package hostruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	softwareClaimRecoveryIntentName     = "software-claim-recovery.json"
	softwareClaimRecoveryLockName       = "software-claim-recovery.lock"
	softwareClaimRecoveryIntentMaxBytes = 32 << 10
	softwareClaimRecoveryMaxAttempts    = 32
)

type softwareClaimRecoveryAttempt struct {
	LeaseGeneration uint64    `json:"lease_generation"`
	StartedAt       time.Time `json:"started_at"`
	ConfirmedReread bool      `json:"confirmed_reread,omitempty"`
}

// This file is an intent and audit trail, never a reconstructed lease. The
// original cursor and every supplied attempt remain available after a CAS.
type softwareClaimRecoveryIntent struct {
	SchemaVersion            int                                        `json:"schema_version"`
	Original                 SoftwareClaimRecoveryRequest               `json:"original_request"`
	Request                  SoftwareClaimRecoveryRequest               `json:"current_request"`
	UpdaterID                string                                     `json:"updater_id"`
	HostID                   string                                     `json:"host_id"`
	SourcePolicyRevision     int64                                      `json:"source_policy_revision"`
	ProjectionRevision       int64                                      `json:"projection_revision"`
	ExecutorPolicyRevision   int64                                      `json:"executor_policy_revision"`
	ExecutorPolicySHA256     string                                     `json:"executor_policy_sha256"`
	Attempts                 []softwareClaimRecoveryAttempt             `json:"attempts"`
	Settled                  bool                                       `json:"settled"`
	SettledAt                time.Time                                  `json:"settled_at,omitzero"`
	TerminalClear            *softwareClaimRecoveryTerminalClearReceipt `json:"terminal_clear_receipt,omitempty"`
	PreviousSettledRawSHA256 string                                     `json:"previous_settled_raw_sha256,omitempty"`
}

func newSoftwareClaimRecoveryIntent(request SoftwareClaimRecoveryRequest, updaterID, hostID string, policy HostAgentPolicy) softwareClaimRecoveryIntent {
	return softwareClaimRecoveryIntent{
		SchemaVersion: 2, Original: request, Request: request, UpdaterID: updaterID, HostID: hostID,
		SourcePolicyRevision: policy.SourcePolicyRevision, ProjectionRevision: policy.Revision,
		ExecutorPolicyRevision: policy.LocalExecutorPolicyRevision, ExecutorPolicySHA256: policy.LocalExecutorPolicySHA256,
	}
}

func (s softwareClaimRecoveryIntent) validate() error {
	if (s.SchemaVersion != 1 && s.SchemaVersion != 2) || s.Original.Validate() != nil || s.Request.Validate() != nil ||
		!s.Original.sameIntent(s.Request) || !identifierPattern.MatchString(s.UpdaterID) || !validExecutionHostID(s.HostID) ||
		s.SourcePolicyRevision < 1 || s.ProjectionRevision < 1 || s.ExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(s.ExecutorPolicySHA256) ||
		len(s.Attempts) == 0 || len(s.Attempts) > softwareClaimRecoveryMaxAttempts ||
		s.Settled != !s.SettledAt.IsZero() {
		return errors.New("software claim recovery durable intent is invalid")
	}
	if s.SchemaVersion == 1 && (s.TerminalClear != nil || s.PreviousSettledRawSHA256 != "") ||
		s.SchemaVersion == 2 && (s.Settled && (s.TerminalClear == nil || s.TerminalClear.validate(s) != nil) ||
			!s.Settled && s.TerminalClear != nil || s.PreviousSettledRawSHA256 != "" && !softwareClaimRecoveryRawDigestValid(s.PreviousSettledRawSHA256)) {
		return errors.New("software claim recovery settled receipt or raw history is invalid")
	}
	seen := make(map[uint64]bool, len(s.Attempts))
	for _, attempt := range s.Attempts {
		if attempt.LeaseGeneration < s.Original.LeaseGeneration || attempt.LeaseGeneration >= 1<<63-1 ||
			attempt.StartedAt.IsZero() || (seen[attempt.LeaseGeneration] && !attempt.ConfirmedReread) {
			return errors.New("software claim recovery durable attempt is invalid")
		}
		seen[attempt.LeaseGeneration] = true
	}
	if s.Attempts[0].LeaseGeneration != s.Original.LeaseGeneration ||
		s.Attempts[len(s.Attempts)-1].LeaseGeneration != s.Request.LeaseGeneration {
		return errors.New("software claim recovery durable attempt cursor is invalid")
	}
	return nil
}

func (s softwareClaimRecoveryIntent) policyMatches(policy HostAgentPolicy) bool {
	return s.HostID == policy.ExecutionHostID && s.UpdaterID == policy.ServiceID &&
		s.Original.OwnershipEpoch == policy.OwnershipEpoch && s.SourcePolicyRevision == policy.SourcePolicyRevision &&
		s.ProjectionRevision == policy.Revision && s.ExecutorPolicyRevision == policy.LocalExecutorPolicyRevision &&
		s.ExecutorPolicySHA256 == policy.LocalExecutorPolicySHA256
}

func (s softwareClaimRecoveryIntent) wasAttempted(generation uint64) bool {
	for _, attempt := range s.Attempts {
		if attempt.LeaseGeneration == generation {
			return true
		}
	}
	return false
}

func softwareClaimRecoveryIntentSHA256(intent softwareClaimRecoveryIntent) string {
	encoded, _ := json.Marshal(intent)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func loadSoftwareClaimRecoveryIntent(stateDir string, owner func(os.FileInfo) bool) (softwareClaimRecoveryIntent, bool, error) {
	snapshot, exists, err := loadSoftwareClaimRecoverySnapshot(stateDir, owner)
	return snapshot.Intent, exists, err
}

func saveSoftwareClaimRecoveryIntent(stateDir, previousSHA256 string, next softwareClaimRecoveryIntent) error {
	if next.validate() != nil || validateManagedDirectoryChain(stateDir) != nil {
		return errors.New("software claim recovery intent or parent is unsafe")
	}
	previous, exists, err := loadSoftwareClaimRecoveryIntent(stateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || (!exists && previousSHA256 != "") ||
		(exists && softwareClaimRecoveryIntentSHA256(previous) != previousSHA256) {
		return errors.New("software claim recovery durable intent compare-and-swap failed")
	}
	if exists && (previous.SchemaVersion != next.SchemaVersion || previous.PreviousSettledRawSHA256 != next.PreviousSettledRawSHA256 ||
		!previous.Original.sameIntent(next.Original) || previous.Original != next.Original ||
		previous.UpdaterID != next.UpdaterID || previous.HostID != next.HostID ||
		previous.SourcePolicyRevision != next.SourcePolicyRevision || previous.ProjectionRevision != next.ProjectionRevision ||
		previous.ExecutorPolicyRevision != next.ExecutorPolicyRevision || previous.ExecutorPolicySHA256 != next.ExecutorPolicySHA256 ||
		previous.Settled || len(next.Attempts) < len(previous.Attempts) || len(next.Attempts) > len(previous.Attempts)+1) {
		return errors.New("software claim recovery CAS cannot replace immutable history")
	}
	if exists {
		for index, attempt := range previous.Attempts {
			if next.Attempts[index] != attempt {
				return errors.New("software claim recovery CAS cannot rewrite previous attempts")
			}
		}
	}
	payload, err := json.Marshal(next)
	if err != nil || len(payload)+1 > softwareClaimRecoveryIntentMaxBytes {
		return errors.New("encode software claim recovery durable intent")
	}
	if err := writeAtomicFile(filepath.Join(stateDir, softwareClaimRecoveryIntentName), append(payload, '\n'), 0o600); err != nil {
		return errors.New("persist software claim recovery durable intent; outcome remains uncertain")
	}
	return nil
}

func readSoftwareClaimRecoveryJournal(stateDir string) (journalData, error) {
	if validateManagedDirectoryChain(stateDir) != nil {
		return journalData{}, errors.New("software claim recovery journal parent is unsafe")
	}
	path := filepath.Join(stateDir, "journal.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return journalData{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		(snapshotModeEnforced() && info.Mode().Perm() != 0o600) || !managedSnapshotOwnedByCurrentUser(info) || info.Size() <= 0 || info.Size() > 4<<20 {
		return journalData{}, errors.New("software claim recovery journal is unsafe")
	}
	file, _, err := openVerifiedConfig(path, info)
	if err != nil {
		return journalData{}, errors.New("software claim recovery journal changed during secure open")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20+1))
	decoder.DisallowUnknownFields()
	var data journalData
	if decoder.Decode(&data) != nil || validateJournalData(data) != nil || data.ActivePlan != nil || data.ActivePortPlan != nil ||
		data.ActivePortPolicy != nil || data.ActiveStageFailure != nil || !softwareClaimRecoveryPendingAllowed(data) {
		return journalData{}, errors.New("software claim recovery journal has a plan, pending report, or unsafe state")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return journalData{}, errors.New("software claim recovery journal contains trailing data")
	}
	return data, nil
}

// Only the first progress acknowledgement can be pending on this terminal-only
// path. Its full immutable software authority remains on the retained cursor;
// a new authenticated lease and root absence proof are required to replace it.
func softwareClaimRecoveryPendingAllowed(data journalData) bool {
	if len(data.Pending) == 0 {
		return true
	}
	active := data.ActiveJob
	if len(data.Pending) != 1 || active == nil || !isV2SoftwareJob(*active) || active.SoftwareClaimRejected ||
		active.SoftwareUpdate == nil || active.SoftwareUpdate.Validate() != nil || validateJournalSoftwareJob(*active) != nil ||
		active.ReportSequence > 1 || active.Sequence != 0 || data.NextSeq != 2 || !identifierPattern.MatchString(active.CommandID) || active.LeaseToken != "" || !active.ReleaseToken.Empty() || active.PortReconfigure != nil ||
		active.Status != "claimed" || active.Progress != 0 || active.Code != "" || active.ArtifactDigest != "" || active.PreviousDigest != "" ||
		data.ActivePlan != nil || data.ActivePortPlan != nil || data.ActivePortPolicy != nil || data.ActiveStageFailure != nil {
		return false
	}
	pending := data.Pending[0]
	report := pending.Report
	return pending.JobID == active.ID && report.ServiceID == active.AgentServiceID && report.LeaseGeneration == active.LeaseGeneration &&
		report.Sequence == 1 && report.Status == "claimed" && report.Progress == 5 &&
		report.Code == "" && report.LeaseToken == "" && report.ArtifactDigest == "" && report.PreviousDigest == "" && report.PortReconfigure == nil
}

func softwareClaimRecoveryJournalFromData(stateDir string, data journalData) *Journal {
	if data.NextSeq == 0 {
		data.NextSeq = 1
	}
	if data.DeployedVersions == nil {
		data.DeployedVersions = make(map[string]string)
	}
	return &Journal{path: filepath.Join(stateDir, "journal.json"), data: data, leaseTokens: make(map[string]string), renameFile: os.Rename, syncDir: syncDirectory}
}
