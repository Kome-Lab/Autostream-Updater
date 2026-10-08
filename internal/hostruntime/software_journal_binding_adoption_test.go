package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSoftwareJournalAdoptionCommitsFreshCursorAndOldPendingInOneSave(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "bound"
		if legacy {
			name = "trusted_legacy"
		}
		t.Run(name, func(t *testing.T) {
			journal, _, old, fresh, plan := newSoftwareJournalAdoptionFixture(t, legacy)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			expected := journal.data
			copy := cloneV2PanelJob(fresh)
			expected.ActiveJob, expected.NextSeq, expected.Pending = &copy, fresh.ReportSequence, nil
			renames := 0
			journal.renameFile = func(source, destination string) error {
				renames++
				payload, err := os.ReadFile(source)
				if err != nil {
					return err
				}
				var candidate journalData
				if err := json.Unmarshal(payload, &candidate); err != nil {
					return err
				}
				if candidate.ActiveJob == nil || candidate.ActiveJob.LeaseGeneration != fresh.LeaseGeneration || len(candidate.Pending) != 0 || !reflect.DeepEqual(candidate.ActivePlan, &plan) {
					t.Fatal("atomic candidate split pending invalidation from fresh cursor or changed the saved plan")
				}
				current, err := os.ReadFile(destination)
				if err != nil {
					return err
				}
				if !bytes.Equal(before, current) {
					t.Fatal("old pending state was saved away before the fresh cursor")
				}
				return os.Rename(source, destination)
			}
			if err := journal.SetActive(&fresh); err == nil {
				t.Fatal("ordinary SetActive discarded pending reports")
			}
			if err := journal.AdoptRecoveredSoftwareClaim(fresh); err != nil {
				t.Fatal(err)
			}
			if renames != 1 || !reflect.DeepEqual(journal.data, expected) || !reflect.DeepEqual(journal.ActivePlan(), &plan) {
				t.Fatal("recovered claim did not commit only the cursor, report sequence and old pending reports once")
			}
			if len(journal.leaseTokens) != 0 || journal.Active().LeaseGeneration != old.LeaseGeneration+1 {
				t.Fatal("old report lease metadata survived adoption")
			}
			journal.renameFile = os.Rename
			first, err := journal.Queue(fresh.ID, fresh.AgentServiceID, "", fresh.LeaseGeneration, "reconciling", "", "saved target reconciliation", 50, "", "")
			if err != nil || first.Sequence != fresh.ReportSequence {
				t.Fatalf("new lease report cursor differs: %v", err)
			}
			if err := journal.SetActive(&fresh); err != nil {
				t.Fatalf("same adopted cursor could not enter ordinary software recovery: %v", err)
			}
			if journal.data.NextSeq != first.Sequence+1 || len(journal.Pending()) != 1 || !reflect.DeepEqual(journal.ActivePlan(), &plan) {
				t.Fatal("ordinary same-cursor continuation regressed the fresh report or immutable plan")
			}
		})
	}
}

func TestSoftwareJournalAdoptionRejectsChangedAuthorityWithoutDroppingReports(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{"configuration", func(j *UpdateJob) { j.SoftwareUpdate.ConfigRevision++ }},
		{"command_digest", func(j *UpdateJob) { j.SoftwareUpdate.CommandSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"source", func(j *UpdateJob) { j.SoftwareUpdate.SourcePolicyRevision++ }},
		{"projection", func(j *UpdateJob) { j.SoftwareUpdate.ProjectionRevision++; j.PolicyRevision++ }},
		{"executor", func(j *UpdateJob) { j.SoftwareUpdate.ExecutorPolicyRevision++ }},
		{"policy_digest", func(j *UpdateJob) { j.SoftwareUpdate.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64) }},
		{"ownership", func(j *UpdateJob) { j.OwnershipEpoch++ }},
		{"foreign_job", func(j *UpdateJob) { j.ID = "job-other" }},
		{"target", func(j *UpdateJob) { j.TargetID = "worker-other" }},
		{"target_version", func(j *UpdateJob) { j.TargetVersion = "v1.2.0" }},
		{"generation_gap", func(j *UpdateJob) { j.LeaseGeneration++ }},
		{"same_command", func(j *UpdateJob) { j.CommandID = "command-software-journal" }},
		{"invalid_expiry", func(j *UpdateJob) { j.LeaseExpiresAt = "invalid" }},
		{"not_recovery", func(j *UpdateJob) { j.RecoveryRequired = false }},
		{"terminal_marker", func(j *UpdateJob) { j.SoftwareClaimRejected = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, _, _, fresh, _ := newSoftwareJournalAdoptionFixture(t, false)
			test.mutate(&fresh)
			assertSoftwareJournalAdoptionRejected(t, journal, func() error { return journal.AdoptRecoveredSoftwareClaim(fresh) })
		})
	}
}

func TestSoftwareJournalAdoptionRejectsUnrelatedPendingReports(t *testing.T) {
	for _, name := range []string{"job", "generation", "service", "sequence", "credential"} {
		t.Run(name, func(t *testing.T) {
			journal, _, _, fresh, _ := newSoftwareJournalAdoptionFixture(t, false)
			pending := &journal.data.Pending[0]
			switch name {
			case "job":
				pending.JobID = "job-other"
			case "generation":
				pending.Report.LeaseGeneration++
			case "service":
				pending.Report.ServiceID = "updater-other"
			case "sequence":
				pending.Report.Sequence = 0
			case "credential":
				pending.Report.LeaseToken = "synthetic-credential"
			}
			if err := journal.saveLocked(); err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalAdoptionRejected(t, journal, func() error { return journal.AdoptRecoveredSoftwareClaim(fresh) })
		})
	}
}

func TestSoftwareJournalAdoptionSaveFailurePreservesMemoryAndPoisons(t *testing.T) {
	for _, point := range []string{"rename", "directory_sync"} {
		t.Run(point, func(t *testing.T) {
			journal, _, _, fresh, plan := newSoftwareJournalAdoptionFixture(t, false)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := json.Marshal(journal.data)
			if err != nil {
				t.Fatal(err)
			}
			if point == "rename" {
				journal.renameFile = func(string, string) error { return errors.New("synthetic rename failure") }
			} else {
				journal.syncDir = func(string) error { return errors.New("synthetic directory sync failure") }
			}
			if err := journal.AdoptRecoveredSoftwareClaim(fresh); err == nil || journal.poisoned == nil {
				t.Fatal("uncertain adoption did not poison the journal")
			}
			actual, err := json.Marshal(journal.data)
			if err != nil || !bytes.Equal(expected, actual) || len(journal.Pending()) != 2 || len(journal.leaseTokens) != 2 {
				t.Fatal("failed candidate persistence discarded old in-memory pending or active state")
			}
			after, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			if point == "rename" {
				if !bytes.Equal(before, after) {
					t.Fatal("failed rename changed old durable reports")
				}
			} else {
				var durable journalData
				if err := json.Unmarshal(after, &durable); err != nil {
					t.Fatal(err)
				}
				if durable.ActiveJob == nil || durable.ActiveJob.LeaseGeneration != fresh.LeaseGeneration || len(durable.Pending) != 0 || !reflect.DeepEqual(durable.ActivePlan, &plan) {
					t.Fatal("visible uncertain commit contains a split pending/cursor handoff")
				}
			}
			if err := journal.SetActive(&fresh); err == nil {
				t.Fatal("poisoned adoption could continue mutating")
			}
		})
	}
}

func newSoftwareJournalAdoptionFixture(t *testing.T, legacy bool) (*Journal, string, UpdateJob, UpdateJob, MutationPlan) {
	t.Helper()
	journal, stateDir, old, plan := newBoundSoftwareJournalFixture(t, 11, 13, 17)
	if legacy {
		if err := journal.ClearActive(); err != nil {
			t.Fatal(err)
		}
		old.SoftwareUpdate, old.PolicyRevision = nil, 1
		if err := journal.SetActive(&old); err != nil {
			t.Fatal(err)
		}
		if err := journal.SetActivePlan(plan); err != nil {
			t.Fatal(err)
		}
	}
	if err := journal.SetActiveStageFailure(stageFailureRecord{JobID: old.ID, Code: stageFailureCodeSmokeExecution, Message: stageFailureMessageSmokeExecution}); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"claimed", "downloading"} {
		if _, err := journal.Queue(old.ID, old.AgentServiceID, "", old.LeaseGeneration, status, "", "synthetic old lease report", 10, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	fresh := softwareJournalFreshRecovery(old)
	fresh.SoftwareUpdate, fresh.PolicyRevision = softwareJournalFullBinding(plan, 11, 13, 17), 13
	fresh.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	return journal, stateDir, old, fresh, plan
}

func assertSoftwareJournalAdoptionRejected(t *testing.T, journal *Journal, adopt func() error) {
	t.Helper()
	before, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(journal.data)
	if err != nil {
		t.Fatal(err)
	}
	if err := adopt(); err == nil {
		t.Fatal("invalid recovery adoption was accepted")
	}
	after, err := os.ReadFile(journal.path)
	actual, encodeErr := json.Marshal(journal.data)
	if err != nil || encodeErr != nil || !bytes.Equal(before, after) || !bytes.Equal(expected, actual) {
		t.Fatal("invalid recovery adoption changed cursor or pending evidence")
	}
}
