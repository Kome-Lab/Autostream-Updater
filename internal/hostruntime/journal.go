package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	journalActiveClearMarkerName    = "journal.clear-active.pending.json"
	journalActiveClearMarkerVersion = 1
	journalActiveClearMarkerMaxSize = 1 << 20
)

type PendingReport struct {
	JobID  string    `json:"job_id"`
	Report JobReport `json:"report"`
}

type journalData struct {
	ActiveJob          *UpdateJob                  `json:"active_job,omitempty"`
	ActivePlan         *MutationPlan               `json:"active_plan,omitempty"`
	ActivePortPlan     *SystemdPortReconfigurePlan `json:"active_port_plan,omitempty"`
	ActiveStageFailure *stageFailureRecord         `json:"active_stage_failure,omitempty"`
	NextSeq            uint64                      `json:"next_sequence"`
	Pending            []PendingReport             `json:"pending_reports,omitempty"`
	DeployedVersions   map[string]string           `json:"deployed_versions,omitempty"`
}

// journalActiveClearMarker is a credential-free durable backup of the exact
// legacy journal state that existed before ActiveJob was cleared. The marker
// is committed and parent-fsynced before journal.json can expose a cleared
// cursor. This lets a fresh v1.9.11 process distinguish the only two safe
// crash states (the exact previous state or that state with only the active
// cursor removed), while v1.9.9/v1.9.10 continue to read the unchanged
// journal.json schema.
type journalActiveClearMarker struct {
	SchemaVersion  int         `json:"schema_version"`
	PreviousSHA256 string      `json:"previous_sha256"`
	Previous       journalData `json:"previous"`
}

type Journal struct {
	mu          sync.Mutex
	path        string
	data        journalData
	leaseTokens map[string]string
	renameFile  func(string, string) error
	syncDir     func(string) error
	poisoned    error
}

func OpenJournal(stateDir string) (*Journal, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	j := &Journal{
		path:        filepath.Join(stateDir, "journal.json"),
		data:        journalData{NextSeq: 1, DeployedVersions: map[string]string{}},
		leaseTokens: map[string]string{},
		renameFile:  os.Rename,
		syncDir:     syncDirectory,
	}
	f, err := os.Open(j.path)
	if errors.Is(err, os.ErrNotExist) {
		if err := j.reconcileActiveClearMarkerLocked(false); err != nil {
			return nil, err
		}
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	decodeErr := json.NewDecoder(f).Decode(&j.data)
	closeErr := f.Close()
	if decodeErr != nil {
		return nil, fmt.Errorf("decode update journal: %w", decodeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close update journal: %w", closeErr)
	}
	if j.data.NextSeq == 0 {
		j.data.NextSeq = 1
	}
	if j.data.DeployedVersions == nil {
		j.data.DeployedVersions = map[string]string{}
	}
	if err := validateJournalData(j.data); err != nil {
		return nil, err
	}
	// Reconcile the clear fence before applying any legacy journal scrubbing.
	// A marker is an exact binding to the bytes represented by the previous
	// journal state, so changing that state first would turn a safe restart into
	// an artificial mismatch.
	if err := j.reconcileActiveClearMarkerLocked(true); err != nil {
		return nil, err
	}
	// Older journals may contain raw lease tokens. Discard them and immediately
	// rewrite the protected journal without credentials; a fresh process must
	// obtain a new recovery lease instead of reusing a short-lived bearer value.
	scrubbed := false
	if j.data.ActiveJob != nil && j.data.ActiveJob.LeaseToken != "" {
		j.data.ActiveJob.LeaseToken = ""
		scrubbed = true
	}
	if j.data.ActiveJob != nil && !j.data.ActiveJob.ReleaseToken.Empty() {
		j.data.ActiveJob.ReleaseToken = ""
		scrubbed = true
	}
	// A restarted process cannot safely reuse an old execution lease. Drop
	// tokenless pending reports and preserve the active cursor so the next poll
	// obtains a fresh recovery claim and report sequence instead of becoming
	// stuck retrying an unauthorised report forever.
	if len(j.data.Pending) > 0 {
		j.data.Pending = nil
		scrubbed = true
	}
	if scrubbed {
		if err := j.saveLocked(); err != nil {
			return nil, err
		}
	}
	return j, nil
}

func validateJournalData(data journalData) error {
	if data.ActiveJob != nil && data.ActiveJob.validateOperationUnion() != nil {
		return errors.New("update journal active job operation is invalid")
	}
	if data.ActivePlan != nil || data.ActivePortPlan != nil {
		if data.ActiveJob == nil ||
			(data.ActivePlan != nil && data.ActivePortPlan != nil) ||
			(data.ActivePlan != nil &&
				(data.ActiveJob.EffectiveOperation() != updateJobOperationSoftwareUpdate ||
					data.ActivePlan.JobID != data.ActiveJob.ID ||
					data.ActivePlan.Validate() != nil)) ||
			(data.ActivePortPlan != nil &&
				(data.ActiveJob.EffectiveOperation() != updateJobOperationPortReconfigure ||
					data.ActivePortPlan.JobID != data.ActiveJob.ID ||
					data.ActivePortPlan.Validate() != nil)) {
			return errors.New("update journal active plan binding is invalid")
		}
	}
	if data.ActiveStageFailure != nil {
		if data.ActiveJob == nil || data.ActiveStageFailure.JobID != data.ActiveJob.ID {
			return errors.New("update journal active stage failure binding is invalid")
		}
		if err := data.ActiveStageFailure.validate(); err != nil {
			return fmt.Errorf("update journal active stage failure is invalid: %w", err)
		}
	}
	return nil
}

func (j *Journal) MarkDeployed(targetID, version string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if j.data.DeployedVersions == nil {
		j.data.DeployedVersions = map[string]string{}
	}
	j.data.DeployedVersions[targetID] = version
	return j.saveLocked()
}

func (j *Journal) DeployedVersions() map[string]string {
	j.mu.Lock()
	defer j.mu.Unlock()
	result := make(map[string]string, len(j.data.DeployedVersions))
	for target, version := range j.data.DeployedVersions {
		result[target] = version
	}
	return result
}

func (j *Journal) SetActive(job *UpdateJob) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if job == nil || job.validateOperationUnion() != nil {
		return errors.New("active update job operation is invalid")
	}
	copy := *job
	if job.PortReconfigure != nil {
		portCopy := *job.PortReconfigure
		portCopy.Docker = cloneDockerPortMutationGrantBinding(job.PortReconfigure.Docker)
		copy.PortReconfigure = &portCopy
	}
	copy.LeaseToken = ""
	copy.ReleaseToken = ""
	if j.data.ActiveJob == nil ||
		j.data.ActiveJob.ID != copy.ID ||
		j.data.ActiveJob.EffectiveOperation() != copy.EffectiveOperation() {
		j.data.ActivePlan = nil
		j.data.ActivePortPlan = nil
		j.data.ActiveStageFailure = nil
	}
	j.data.ActiveJob = &copy
	j.data.NextSeq = job.ReportSequence
	if j.data.NextSeq == 0 {
		j.data.NextSeq = job.Sequence + 1
	}
	if j.data.NextSeq == 0 {
		j.data.NextSeq = 1
	}
	return j.saveLocked()
}

func (j *Journal) SetActivePlan(plan MutationPlan) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if j.data.ActiveJob == nil ||
		j.data.ActiveJob.EffectiveOperation() != updateJobOperationSoftwareUpdate ||
		j.data.ActiveJob.ID != plan.JobID ||
		plan.Validate() != nil {
		return errors.New("active update plan does not match the journal job")
	}
	copy := plan
	j.data.ActivePlan = &copy
	return j.saveLocked()
}

func (j *Journal) SetActivePortPlan(plan SystemdPortReconfigurePlan) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if j.data.ActiveJob == nil ||
		j.data.ActiveJob.EffectiveOperation() != updateJobOperationPortReconfigure ||
		j.data.ActiveJob.ID != plan.JobID ||
		plan.Validate() != nil {
		return errors.New("active port reconfiguration plan does not match the journal job")
	}
	copy := plan
	copy.Docker = cloneDockerPortMutationGrantBinding(plan.Docker)
	j.data.ActivePortPlan = &copy
	return j.saveLocked()
}

func (j *Journal) ActivePlan() *MutationPlan {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.data.ActivePlan == nil {
		return nil
	}
	copy := *j.data.ActivePlan
	return &copy
}

func (j *Journal) ActivePortPlan() *SystemdPortReconfigurePlan {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.data.ActivePortPlan == nil {
		return nil
	}
	copy := *j.data.ActivePortPlan
	copy.Docker = cloneDockerPortMutationGrantBinding(j.data.ActivePortPlan.Docker)
	return &copy
}

func (j *Journal) Active() *UpdateJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.data.ActiveJob == nil {
		return nil
	}
	copy := *j.data.ActiveJob
	if j.data.ActiveJob.PortReconfigure != nil {
		portCopy := *j.data.ActiveJob.PortReconfigure
		portCopy.Docker = cloneDockerPortMutationGrantBinding(j.data.ActiveJob.PortReconfigure.Docker)
		copy.PortReconfigure = &portCopy
	}
	return &copy
}

func (j *Journal) SetActiveStageFailure(failure stageFailureRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if j.data.ActiveJob == nil || failure.JobID != j.data.ActiveJob.ID {
		return errors.New("active stage failure does not match the journal job")
	}
	if err := failure.validate(); err != nil {
		return err
	}
	copy := failure
	j.data.ActiveStageFailure = &copy
	return j.saveLocked()
}

func (j *Journal) ActiveStageFailure() *stageFailureRecord {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.data.ActiveStageFailure == nil {
		return nil
	}
	copy := *j.data.ActiveStageFailure
	return &copy
}

func (j *Journal) Queue(jobID, serviceID, leaseToken string, leaseGeneration uint64, status, code, message string, progress int, artifact, previous string) (JobReport, error) {
	return j.queue(jobID, serviceID, leaseToken, leaseGeneration, status, code, message, progress, artifact, previous, nil)
}

func (j *Journal) QueuePort(
	jobID, serviceID, leaseToken string,
	leaseGeneration uint64,
	status, code, message string,
	progress int,
	result *SystemdPortReconfigureResult,
) (JobReport, error) {
	return j.queue(jobID, serviceID, leaseToken, leaseGeneration, status, code, message, progress, "", "", result)
}

func (j *Journal) queue(
	jobID, serviceID, leaseToken string,
	leaseGeneration uint64,
	status, code, message string,
	progress int,
	artifact, previous string,
	portResult *SystemdPortReconfigureResult,
) (JobReport, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return JobReport{}, err
	}
	var resultCopy *PortReconfigurationJobReport
	if portResult != nil {
		resultCopy = &PortReconfigurationJobReport{Result: portResult.Result}
	}
	report := JobReport{ServiceID: serviceID, LeaseToken: leaseToken, LeaseGeneration: leaseGeneration, Sequence: j.data.NextSeq, Status: status, Progress: progress, Code: code, Message: message, ArtifactDigest: artifact, PreviousDigest: previous, PortReconfigure: resultCopy}
	j.data.NextSeq++
	stored := report
	stored.LeaseToken = ""
	j.data.Pending = append(j.data.Pending, PendingReport{JobID: jobID, Report: stored})
	j.leaseTokens[pendingLeaseKey(jobID, report.Sequence)] = leaseToken
	return report, j.saveLocked()
}

func (j *Journal) DropJobReports(jobID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	kept := j.data.Pending[:0]
	for _, pending := range j.data.Pending {
		if pending.JobID != jobID {
			kept = append(kept, pending)
		} else {
			delete(j.leaseTokens, pendingLeaseKey(pending.JobID, pending.Report.Sequence))
		}
	}
	j.data.Pending = append([]PendingReport(nil), kept...)
	return j.saveLocked()
}

func (j *Journal) Pending() []PendingReport {
	j.mu.Lock()
	defer j.mu.Unlock()
	result := append([]PendingReport(nil), j.data.Pending...)
	for index := range result {
		pending := &result[index]
		pending.Report.LeaseToken = j.leaseTokens[pendingLeaseKey(pending.JobID, pending.Report.Sequence)]
	}
	return result
}

// Ack durably advances only the pending report cursor. A terminal caller must
// clean the exact job directory before separately clearing active recovery
// state, so a cleanup failure cannot be mistaken for completed recovery.
func (j *Journal) Ack(jobID string, sequence uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if len(j.data.Pending) == 0 || j.data.Pending[0].JobID != jobID || j.data.Pending[0].Report.Sequence != sequence {
		return errors.New("journal acknowledgements must be ordered")
	}
	acked := j.data.Pending[0]
	delete(j.leaseTokens, pendingLeaseKey(acked.JobID, acked.Report.Sequence))
	j.data.Pending = append([]PendingReport(nil), j.data.Pending[1:]...)
	return j.saveLocked()
}

func pendingLeaseKey(jobID string, sequence uint64) string {
	return fmt.Sprintf("%s:%d", jobID, sequence)
}

func (j *Journal) ClearActive() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if j.data.ActiveJob == nil {
		return nil
	}

	previous := j.data
	if err := j.installActiveClearMarkerLocked(previous); err != nil {
		return j.poisonLocked(fmt.Errorf("install active journal clear fence: %w", err))
	}

	next := previous
	next.ActiveJob = nil
	next.ActivePlan = nil
	next.ActivePortPlan = nil
	next.ActiveStageFailure = nil
	if err := j.saveDataLocked(next); err != nil {
		// Keep the exact previous state in memory. The durable marker makes a
		// fresh process resolve whether the rename became visible before the
		// error, and the poisoned process may not perform another mutation.
		return j.poisonLocked(fmt.Errorf("persist cleared active journal: %w", err))
	}
	j.data = next
	if err := j.removeActiveClearMarkerLocked(); err != nil {
		return j.poisonLocked(fmt.Errorf("remove active journal clear fence: %w", err))
	}
	return nil
}

func (j *Journal) saveLocked() error {
	if err := j.saveDataLocked(j.data); err != nil {
		// Callers mutate j.data before saving. Once persistence fails, that
		// in-memory state may no longer match journal.json and therefore must
		// never become the Previous side of a later ClearActive fence. Force a
		// fresh process to reload the only state actually visible on disk.
		return j.poisonLocked(fmt.Errorf("persist update journal mutation: %w", err))
	}
	return nil
}

func (j *Journal) saveDataLocked(data journalData) error {
	tmp := j.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encErr := json.NewEncoder(f).Encode(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if encErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write update journal: %w", firstError(encErr, syncErr, closeErr))
	}
	if err := j.renameFile(tmp, j.path); err != nil {
		return fmt.Errorf("install update journal: %w", err)
	}
	if err := j.syncDir(filepath.Dir(j.path)); err != nil {
		return fmt.Errorf("sync update journal parent: %w", err)
	}
	return nil
}

// Err reports a same-process durability poison. Once an active-clear commit
// has an uncertain outcome, all later mutations must fail closed until a fresh
// process reconciles the durable fence with journal.json.
func (j *Journal) Err() error {
	if j == nil {
		return errors.New("update journal is unavailable")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.poisoned
}

func (j *Journal) checkMutableLocked() error {
	if j.poisoned != nil {
		return j.poisoned
	}
	return nil
}

func (j *Journal) poisonLocked(cause error) error {
	if j.poisoned == nil {
		j.poisoned = fmt.Errorf("update journal durability is uncertain; restart required: %w", cause)
	}
	return j.poisoned
}

func journalDataSHA256(data journalData) (string, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}

func validateActiveClearMarker(marker journalActiveClearMarker) error {
	if marker.SchemaVersion != journalActiveClearMarkerVersion ||
		!digestPattern.MatchString(marker.PreviousSHA256) ||
		marker.Previous.ActiveJob == nil {
		return errors.New("active journal clear fence is invalid")
	}
	if err := validateJournalData(marker.Previous); err != nil {
		return fmt.Errorf("active journal clear fence previous state is invalid: %w", err)
	}
	if marker.Previous.ActiveJob.LeaseToken != "" ||
		!marker.Previous.ActiveJob.ReleaseToken.Empty() {
		return errors.New("active journal clear fence contains an execution credential")
	}
	for _, pending := range marker.Previous.Pending {
		if pending.Report.LeaseToken != "" {
			return errors.New("active journal clear fence contains a report credential")
		}
	}
	computed, err := journalDataSHA256(marker.Previous)
	if err != nil || computed != marker.PreviousSHA256 {
		return errors.New("active journal clear fence digest is invalid")
	}
	return nil
}

func (j *Journal) activeClearMarkerPath() string {
	return filepath.Join(filepath.Dir(j.path), journalActiveClearMarkerName)
}

func (j *Journal) activeClearMarkerTempPath() string {
	return j.activeClearMarkerPath() + ".tmp"
}

func (j *Journal) installActiveClearMarkerLocked(previous journalData) error {
	marker := journalActiveClearMarker{
		SchemaVersion: journalActiveClearMarkerVersion,
		Previous:      previous,
	}
	if previous.ActiveJob == nil || previous.ActiveJob.LeaseToken != "" ||
		!previous.ActiveJob.ReleaseToken.Empty() {
		return errors.New("active journal state is not credential-free")
	}
	for _, pending := range previous.Pending {
		if pending.Report.LeaseToken != "" {
			return errors.New("pending journal report is not credential-free")
		}
	}
	var err error
	marker.PreviousSHA256, err = journalDataSHA256(previous)
	if err != nil {
		return errors.New("digest active journal clear fence")
	}
	if err := validateActiveClearMarker(marker); err != nil {
		return err
	}

	if existing, exists, err := j.loadActiveClearMarkerLocked(); err != nil {
		return err
	} else if exists {
		if existing.PreviousSHA256 != marker.PreviousSHA256 {
			return errors.New("active journal clear fence already has another binding")
		}
		// Re-sync an idempotently observed marker before permitting the main
		// journal transition. This closes a prior uncertain parent-fsync result.
		if err := j.syncDir(filepath.Dir(j.path)); err != nil {
			return fmt.Errorf("sync existing active journal clear fence: %w", err)
		}
		return nil
	}
	if err := j.removeActiveClearMarkerTempLocked(); err != nil {
		return err
	}

	encoded, err := json.Marshal(marker)
	if err != nil || len(encoded)+1 > journalActiveClearMarkerMaxSize {
		return errors.New("encode active journal clear fence")
	}
	encoded = append(encoded, '\n')
	tempPath := j.activeClearMarkerTempPath()
	temp, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("create active journal clear fence")
	}
	writeErr := error(nil)
	if err := temp.Chmod(0o600); err != nil {
		writeErr = err
	} else if _, err := io.Copy(temp, bytes.NewReader(encoded)); err != nil {
		writeErr = err
	} else if err := temp.Sync(); err != nil {
		writeErr = err
	}
	closeErr := temp.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("write active journal clear fence: %w", firstError(writeErr, closeErr))
	}
	tempInfo, err := os.Lstat(tempPath)
	if err != nil || !safeActiveClearMarkerFile(tempInfo) {
		_ = os.Remove(tempPath)
		return errors.New("active journal clear fence temporary file is unsafe")
	}
	if err := j.renameFile(tempPath, j.activeClearMarkerPath()); err != nil {
		// A rename error may be reported after the destination became visible.
		// Never continue to journal.json in that ambiguous call; leave a valid
		// installed marker for OpenJournal to reconcile, or clean the untouched
		// temporary file when the destination is still absent.
		if installed, exists, loadErr := j.loadActiveClearMarkerLocked(); loadErr == nil && exists && installed.PreviousSHA256 == marker.PreviousSHA256 {
			_ = j.syncDir(filepath.Dir(j.path))
			return fmt.Errorf("install active journal clear fence reported an error: %w", err)
		}
		_ = j.removeActiveClearMarkerTempLocked()
		return fmt.Errorf("install active journal clear fence: %w", err)
	}
	if err := j.syncDir(filepath.Dir(j.path)); err != nil {
		return fmt.Errorf("sync active journal clear fence parent: %w", err)
	}
	return nil
}

func safeActiveClearMarkerFile(info os.FileInfo) bool {
	return info != nil &&
		info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().IsRegular() &&
		(!snapshotModeEnforced() || info.Mode().Perm() == 0o600) &&
		managedSnapshotOwnedByCurrentUser(info)
}

func (j *Journal) loadActiveClearMarkerLocked() (journalActiveClearMarker, bool, error) {
	path := j.activeClearMarkerPath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return journalActiveClearMarker{}, false, nil
	}
	if err != nil || !safeActiveClearMarkerFile(info) || info.Size() <= 0 ||
		info.Size() > journalActiveClearMarkerMaxSize {
		return journalActiveClearMarker{}, false, errors.New("active journal clear fence is unsafe")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil || !safeActiveClearMarkerFile(openedInfo) {
		if file != nil {
			_ = file.Close()
		}
		return journalActiveClearMarker{}, false, errors.New("open active journal clear fence")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, journalActiveClearMarkerMaxSize+1))
	if err != nil || len(data) == 0 || len(data) > journalActiveClearMarkerMaxSize {
		return journalActiveClearMarker{}, false, errors.New("read active journal clear fence")
	}
	var marker journalActiveClearMarker
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		return journalActiveClearMarker{}, false, errors.New("decode active journal clear fence")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return journalActiveClearMarker{}, false, errors.New("active journal clear fence contains trailing data")
	}
	if err := validateActiveClearMarker(marker); err != nil {
		return journalActiveClearMarker{}, false, err
	}
	return marker, true, nil
}

func (j *Journal) reconcileActiveClearMarkerLocked(mainExists bool) error {
	if err := j.removeActiveClearMarkerTempLocked(); err != nil {
		return err
	}
	marker, exists, err := j.loadActiveClearMarkerLocked()
	if err != nil || !exists {
		return err
	}
	if !mainExists {
		return errors.New("active journal clear fence exists without the main journal")
	}
	currentSHA256, err := journalDataSHA256(j.data)
	if err != nil {
		return errors.New("digest current journal during active clear recovery")
	}
	cleared := marker.Previous
	cleared.ActiveJob = nil
	cleared.ActivePlan = nil
	cleared.ActivePortPlan = nil
	clearedSHA256, err := journalDataSHA256(cleared)
	if err != nil {
		return errors.New("digest cleared journal during active clear recovery")
	}
	if currentSHA256 != marker.PreviousSHA256 && currentSHA256 != clearedSHA256 {
		return errors.New("active journal clear fence does not match the main journal")
	}
	return j.removeActiveClearMarkerLocked()
}

func (j *Journal) removeActiveClearMarkerLocked() error {
	path := j.activeClearMarkerPath()
	info, err := os.Lstat(path)
	if err != nil || !safeActiveClearMarkerFile(info) {
		return errors.New("active journal clear fence changed before cleanup")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("remove active journal clear fence")
	}
	if err := j.syncDir(filepath.Dir(j.path)); err != nil {
		return fmt.Errorf("sync active journal clear fence cleanup: %w", err)
	}
	return nil
}

func (j *Journal) removeActiveClearMarkerTempLocked() error {
	path := j.activeClearMarkerTempPath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !safeActiveClearMarkerFile(info) {
		return errors.New("active journal clear fence temporary file is unsafe")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("remove active journal clear fence temporary file")
	}
	if err := j.syncDir(filepath.Dir(j.path)); err != nil {
		return fmt.Errorf("sync active journal clear fence temporary cleanup: %w", err)
	}
	return nil
}
