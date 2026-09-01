package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalClearActiveMarkerParentSyncFailureRetainsRecoveryState(t *testing.T) {
	stateDir, journal, jobID := newJournalWithActivePlan(t)
	fault := errors.New("marker parent sync failed")
	var syncCalls int
	journal.syncDir = func(path string) error {
		syncCalls++
		if syncCalls == 1 {
			return fault
		}
		return syncDirectory(path)
	}

	err := journal.ClearActive()
	if !errors.Is(err, fault) {
		t.Fatalf("ClearActive error = %v, want marker sync fault", err)
	}
	assertPoisonedJournalRetainsActivePlan(t, journal, jobID)
	assertActiveClearMarkerExists(t, stateDir)

	reopened, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Active(); active == nil || active.ID != jobID {
		t.Fatalf("restart did not retain exact pre-clear cursor: %+v", active)
	}
	if plan := reopened.ActivePlan(); plan == nil || plan.JobID != jobID {
		t.Fatalf("restart did not retain exact pre-clear plan: %+v", plan)
	}
	assertActiveClearMarkerAbsent(t, stateDir)
}

func TestJournalClearActiveRefusesStateAfterEarlierSaveFailure(t *testing.T) {
	stateDir, journal, jobID := newJournalWithActivePlan(t)
	fault := errors.New("ordinary journal rename failed")
	realRename := journal.renameFile
	journal.renameFile = func(string, string) error { return fault }
	if err := journal.MarkDeployed("worker-01", "v1.1.0"); !errors.Is(err, fault) {
		t.Fatalf("MarkDeployed error = %v, want injected save fault", err)
	}
	journal.renameFile = realRename

	if journal.Err() == nil {
		t.Fatal("ordinary save failure did not poison the journal")
	}
	if err := journal.ClearActive(); !errors.Is(err, fault) {
		t.Fatalf("ClearActive after prior save failure = %v, want poison cause", err)
	}
	assertActiveClearMarkerAbsent(t, stateDir)

	reopened, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Active(); active == nil || active.ID != jobID {
		t.Fatalf("restart did not recover the durable active cursor: %+v", active)
	}
	if _, exists := reopened.DeployedVersions()["worker-01"]; exists {
		t.Fatal("failed ordinary mutation appeared in the durable journal")
	}
}

func TestJournalClearActiveMainRenameFailureRetainsRecoveryState(t *testing.T) {
	stateDir, journal, jobID := newJournalWithActivePlan(t)
	fault := errors.New("main journal rename failed")
	realRename := journal.renameFile
	var renameCalls int
	journal.renameFile = func(oldPath, newPath string) error {
		renameCalls++
		if renameCalls == 2 {
			return fault
		}
		return realRename(oldPath, newPath)
	}

	err := journal.ClearActive()
	if !errors.Is(err, fault) {
		t.Fatalf("ClearActive error = %v, want main rename fault", err)
	}
	assertPoisonedJournalRetainsActivePlan(t, journal, jobID)
	assertActiveClearMarkerExists(t, stateDir)

	reopened, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Active(); active == nil || active.ID != jobID {
		t.Fatalf("restart did not retain cursor after failed main rename: %+v", active)
	}
	if plan := reopened.ActivePlan(); plan == nil || plan.JobID != jobID {
		t.Fatalf("restart did not retain plan after failed main rename: %+v", plan)
	}
	assertActiveClearMarkerAbsent(t, stateDir)
}

func TestJournalClearActiveMainParentSyncFailureFreshProcessResolvesClear(t *testing.T) {
	stateDir, journal, jobID := newJournalWithActivePlan(t)
	fault := errors.New("main journal parent sync failed")
	var syncCalls int
	journal.syncDir = func(path string) error {
		syncCalls++
		if syncCalls == 2 {
			return fault
		}
		return syncDirectory(path)
	}

	err := journal.ClearActive()
	if !errors.Is(err, fault) {
		t.Fatalf("ClearActive error = %v, want main parent sync fault", err)
	}
	// The same process must preserve its previous view and stop mutating. The
	// main rename may nevertheless be visible, so only a fresh process may use
	// the durable fence to decide which exact state won.
	assertPoisonedJournalRetainsActivePlan(t, journal, jobID)
	assertActiveClearMarkerExists(t, stateDir)

	reopened, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Active(); active != nil {
		t.Fatalf("fresh process did not accept the exact durable clear: %+v", active)
	}
	if plan := reopened.ActivePlan(); plan != nil {
		t.Fatalf("fresh process retained plan after exact durable clear: %+v", plan)
	}
	assertActiveClearMarkerAbsent(t, stateDir)
}

func TestJournalClearActiveMarkerCleanupSyncFailureReturnsErrorAfterClear(t *testing.T) {
	stateDir, journal, _ := newJournalWithActivePlan(t)
	fault := errors.New("marker cleanup parent sync failed")
	var syncCalls int
	journal.syncDir = func(path string) error {
		syncCalls++
		if syncCalls == 3 {
			return fault
		}
		return syncDirectory(path)
	}

	err := journal.ClearActive()
	if !errors.Is(err, fault) {
		t.Fatalf("ClearActive error = %v, want marker cleanup sync fault", err)
	}
	if journal.Err() == nil {
		t.Fatal("journal was not poisoned after uncertain marker cleanup")
	}
	if active := journal.Active(); active != nil {
		t.Fatalf("same-process journal did not retain its committed clear: %+v", active)
	}
	if err := journal.MarkDeployed("worker-01", "v1.1.0"); err == nil {
		t.Fatal("poisoned journal accepted a later mutation")
	}

	// The main clear was parent-fsynced before marker cleanup began. Whether a
	// crash resurrects the marker or not, a fresh process can only resolve the
	// exact cleared state.
	reopened, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Active(); active != nil {
		t.Fatalf("fresh process did not preserve the committed clear: %+v", active)
	}
	assertActiveClearMarkerAbsent(t, stateDir)
}

func TestJournalClearActiveFenceMismatchFailsClosed(t *testing.T) {
	stateDir, journal, _ := newJournalWithActivePlan(t)
	fault := errors.New("main journal rename failed")
	realRename := journal.renameFile
	var renameCalls int
	journal.renameFile = func(oldPath, newPath string) error {
		renameCalls++
		if renameCalls == 2 {
			return fault
		}
		return realRename(oldPath, newPath)
	}
	if err := journal.ClearActive(); !errors.Is(err, fault) {
		t.Fatalf("ClearActive error = %v, want main rename fault", err)
	}

	journalPath := filepath.Join(stateDir, "journal.json")
	payload, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var data journalData
	if err := json.Unmarshal(payload, &data); err != nil {
		t.Fatal(err)
	}
	data.NextSeq++
	tampered, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenJournal(stateDir); err == nil ||
		!strings.Contains(err.Error(), "does not match the main journal") {
		t.Fatalf("mismatched clear fence error = %v", err)
	}
	assertActiveClearMarkerExists(t, stateDir)
}

func TestJournalClearActiveKeepsLegacyMainSchemaReadable(t *testing.T) {
	stateDir, journal, _ := newJournalWithActivePlan(t)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	assertActiveClearMarkerAbsent(t, stateDir)

	payload, err := os.ReadFile(filepath.Join(stateDir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	// This is the v1.9.9/v1.9.10 main-journal field set. The new crash fence is
	// deliberately a sibling file, so a strict old decoder sees no new field.
	type legacyJournalData struct {
		ActiveJob        *UpdateJob                  `json:"active_job,omitempty"`
		ActivePlan       *MutationPlan               `json:"active_plan,omitempty"`
		ActivePortPlan   *SystemdPortReconfigurePlan `json:"active_port_plan,omitempty"`
		NextSeq          uint64                      `json:"next_sequence"`
		Pending          []PendingReport             `json:"pending_reports,omitempty"`
		DeployedVersions map[string]string           `json:"deployed_versions,omitempty"`
	}
	var legacy legacyJournalData
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacy); err != nil {
		t.Fatalf("legacy journal decoder rejected v1.9.11 main state: %v", err)
	}
	if legacy.ActiveJob != nil || legacy.ActivePlan != nil || legacy.ActivePortPlan != nil {
		t.Fatalf("legacy decoder observed uncleared recovery state: %+v", legacy)
	}
}

func TestRecoveryOnlyReturnsExecuteErrorAfterCursorWasCleared(t *testing.T) {
	agent, originalPanel, _, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *originalPanel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("claim failed after clear")
	base := &hostPullRecoveryLoopPanel{binding: binding, policy: policy}
	panel := &clearThenErrorRecoveryPanel{
		hostPullRecoveryLoopPanel: base,
		journal:                   agent.Journal,
		err:                       fault,
	}
	agent.ControlPlane = recoveryOnlyHostPullControlPlane{
		HostPullControlPlane: agentControlPlane(base),
		execution:            panel,
	}
	agent.RecoveryOnly = true
	agent.ObserveTargets = func(context.Context, HostAgentPolicy) ([]HostTargetObservation, error) {
		return nil, nil
	}
	agent.Logf = func(string, ...any) {}

	err := agent.runRecoveryOnly(context.Background())
	if !errors.Is(err, fault) {
		t.Fatalf("recovery-only result = %v, want execute error", err)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("test panel did not clear active cursor: %+v", active)
	}
}

type clearThenErrorRecoveryPanel struct {
	*hostPullRecoveryLoopPanel
	journal *Journal
	err     error
}

func (p *clearThenErrorRecoveryPanel) ClaimHost(
	context.Context, string, string, string,
) (*UpdateJob, bool, error) {
	if err := p.journal.ClearActive(); err != nil {
		return nil, false, err
	}
	return nil, false, p.err
}

func newJournalWithActivePlan(t *testing.T) (string, *Journal, string) {
	t.Helper()
	stateDir := t.TempDir()
	journal, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	jobID := "job-clear-durability"
	job := &UpdateJob{
		ID: jobID, TargetID: "worker-01", ServiceType: "worker",
		DeploymentMode: ModeSystemd, CurrentVersion: "v1.0.0",
		TargetVersion: "v1.1.0", LeaseToken: strings.Repeat("l", 48),
		LeaseGeneration: 2, ReportSequence: 1,
	}
	if err := journal.SetActive(job); err != nil {
		t.Fatal(err)
	}
	plan := validMutationPlan()
	plan.JobID = jobID
	plan.PlanSHA256 = ""
	plan.PlanSHA256, err = plan.ComputePlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	return stateDir, journal, jobID
}

func assertPoisonedJournalRetainsActivePlan(t *testing.T, journal *Journal, jobID string) {
	t.Helper()
	if journal.Err() == nil {
		t.Fatal("journal was not poisoned after uncertain active clear")
	}
	if active := journal.Active(); active == nil || active.ID != jobID {
		t.Fatalf("same-process journal lost active cursor: %+v", active)
	}
	if plan := journal.ActivePlan(); plan == nil || plan.JobID != jobID {
		t.Fatalf("same-process journal lost active plan: %+v", plan)
	}
	if err := journal.MarkDeployed("worker-01", "v1.1.0"); err == nil {
		t.Fatal("poisoned journal accepted a later mutation")
	}
}

func assertActiveClearMarkerExists(t *testing.T, stateDir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(stateDir, journalActiveClearMarkerName)); err != nil {
		t.Fatalf("active clear marker is not present: %v", err)
	}
}

func assertActiveClearMarkerAbsent(t *testing.T, stateDir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(stateDir, journalActiveClearMarkerName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active clear marker remains after exact reconciliation: %v", err)
	}
}
