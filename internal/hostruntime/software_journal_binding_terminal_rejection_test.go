package hostruntime

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSoftwareJournalTerminalRecoveryRejectsChangedOperatorRequest(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*SoftwareClaimRecoveryRequest)
	}{
		{"job", func(r *SoftwareClaimRecoveryRequest) { r.JobID = "job-other" }},
		{"target", func(r *SoftwareClaimRecoveryRequest) { r.TargetID = "worker-other" }},
		{"current_version", func(r *SoftwareClaimRecoveryRequest) { r.CurrentVersion = "v1.0.1" }},
		{"target_version", func(r *SoftwareClaimRecoveryRequest) { r.TargetVersion = "v1.2.0" }},
		{"configuration", func(r *SoftwareClaimRecoveryRequest) { r.ConfigRevision++ }},
		{"epoch", func(r *SoftwareClaimRecoveryRequest) { r.OwnershipEpoch++ }},
		{"older_current_generation", func(r *SoftwareClaimRecoveryRequest) { r.LeaseGeneration-- }},
		{"newer_current_generation", func(r *SoftwareClaimRecoveryRequest) { r.LeaseGeneration++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
			test.mutate(&request)
			fresh.LeaseGeneration = request.LeaseGeneration + 1
			proof.RequestSHA256 = request.sha256()
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
		})
	}
}

func TestSoftwareJournalTerminalRecoveryRejectsChangedDurableMarker(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*softwareClaimRecoveryIntent)
	}{
		{"settled", func(s *softwareClaimRecoveryIntent) { s.Settled = true; s.SettledAt = time.Now().UTC() }},
		{"settled_legacy", func(s *softwareClaimRecoveryIntent) {
			s.SchemaVersion, s.Settled, s.SettledAt = 1, true, time.Now().UTC()
		}},
		{"other_updater", func(s *softwareClaimRecoveryIntent) { s.UpdaterID = "updater-other" }},
		{"other_host", func(s *softwareClaimRecoveryIntent) { s.HostID = "host-other" }},
		{"source", func(s *softwareClaimRecoveryIntent) { s.SourcePolicyRevision++ }},
		{"projection", func(s *softwareClaimRecoveryIntent) { s.ProjectionRevision++ }},
		{"executor", func(s *softwareClaimRecoveryIntent) { s.ExecutorPolicyRevision++ }},
		{"policy_digest", func(s *softwareClaimRecoveryIntent) { s.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64) }},
		{"other_current_request", func(s *softwareClaimRecoveryIntent) { s.Request.LeaseGeneration = 2; s.Attempts = s.Attempts[:2] }},
		{"rewritten_original_intent", func(s *softwareClaimRecoveryIntent) { s.Original.ConfigRevision = 2; s.Request.ConfigRevision = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, _, fresh, request, proof, intent := newSoftwareJournalTerminalFixture(t, false)
			test.mutate(&intent)
			if test.name == "settled" {
				// Reject a structurally valid current-format settled marker, rather
				// than failing fixture setup because its required receipt is absent.
				intent.TerminalClear = &softwareClaimRecoveryTerminalClearReceipt{
					ClaimRequest: HostPullClaimRequest{UpdaterID: intent.UpdaterID, HostID: intent.HostID,
						ActiveJobID: intent.Original.JobID, LeaseGeneration: int64(intent.Request.LeaseGeneration + 1),
						Fence: intent.Original.OwnershipEpoch},
					RootNoMutation: proof, ObservedAt: intent.SettledAt,
				}
			}
			if err := intent.validate(); err != nil {
				t.Fatalf("negative marker must remain structurally valid: %v", err)
			}
			payload, err := json.Marshal(intent)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateDir, softwareClaimRecoveryIntentName), payload, 0o600); err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
		})
	}
}

func TestSoftwareJournalTerminalRecoveryLoadsOnlyStrictFixedMarker(t *testing.T) {
	for _, name := range []string{"missing", "foreign_directory", "unknown_field", "trailing_data", "malformed"} {
		t.Run(name, func(t *testing.T) {
			journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
			markerPath := filepath.Join(stateDir, softwareClaimRecoveryIntentName)
			payload, err := os.ReadFile(markerPath)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing":
				if err := os.Remove(markerPath); err != nil {
					t.Fatal(err)
				}
			case "foreign_directory":
				if err := os.Rename(markerPath, filepath.Join(t.TempDir(), softwareClaimRecoveryIntentName)); err != nil {
					t.Fatal(err)
				}
			case "unknown_field":
				var document map[string]any
				if err := json.Unmarshal(payload, &document); err != nil {
					t.Fatal(err)
				}
				document["apply_authorized"] = true
				payload, err = json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(markerPath, payload, 0o600); err != nil {
					t.Fatal(err)
				}
			case "trailing_data":
				if err := os.WriteFile(markerPath, append(payload, []byte(" {}")...), 0o600); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(markerPath, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
		})
	}
}

func TestSoftwareJournalTerminalRecoveryRejectsExecutionOrDifferentCursorState(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Journal)
	}{
		{"software_plan", func(j *Journal) { plan := validMutationPlan(); j.data.ActivePlan = &plan }},
		{"port_plan", func(j *Journal) { j.data.ActivePortPlan = &SystemdPortReconfigurePlan{} }},
		{"port_policy", func(j *Journal) { j.data.ActivePortPolicy = &portAgentPolicyState{} }},
		{"stage_failure", func(j *Journal) { j.data.ActiveStageFailure = &stageFailureRecord{} }},
		{"pending_report", func(j *Journal) { j.data.Pending = []PendingReport{{JobID: j.data.ActiveJob.ID}} }},
		{"other_job", func(j *Journal) { j.data.ActiveJob.ID = "job-other" }},
		{"later_local_generation", func(j *Journal) { j.data.ActiveJob.LeaseGeneration = 5 }},
		{"zero_local_generation", func(j *Journal) { j.data.ActiveJob.LeaseGeneration = 0 }},
		{"saved_command_digest", func(j *Journal) { j.data.ActiveJob.SoftwareUpdate.CommandSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"saved_configuration_digest", func(j *Journal) { j.data.ActiveJob.SoftwareUpdate.ConfigSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"legacy_wrong_configuration", func(j *Journal) { j.data.ActiveJob.SoftwareUpdate = nil; j.data.ActiveJob.PolicyRevision = 13 }},
		{"retained_credential", func(j *Journal) { j.data.ActiveJob.LeaseToken = "synthetic-credential" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
			test.mutate(journal)
			if err := journal.saveLocked(); err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
		})
	}
}

func TestSoftwareJournalTerminalRecoveryRejectsPoisonedJournal(t *testing.T) {
	journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
	journal.poisoned = errors.New("synthetic persistence failure")
	assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
}

func TestSoftwareJournalTerminalRecoveryRejectsChangedIdempotentCursor(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{"configuration", func(j *UpdateJob) { j.SoftwareUpdate.ConfigRevision++ }},
		{"command_digest", func(j *UpdateJob) { j.SoftwareUpdate.CommandSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"foreign_job", func(j *UpdateJob) { j.ID = "job-other" }},
		{"new_command_for_same_generation", func(j *UpdateJob) { j.CommandID = "command-terminal-other" }},
		{"changed_expiry_for_same_generation", func(j *UpdateJob) { j.LeaseExpiresAt = time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339Nano) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
			if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
				t.Fatal(err)
			}
			changed := cloneV2PanelJob(fresh)
			test.mutate(&changed)
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, changed, request, proof)
		})
	}
}
