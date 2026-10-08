package hostruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestSoftwareJournalRestartPreservesPendingAndOriginalPlan(t *testing.T) {
	for _, name := range []string{"bound", "trusted_legacy", "bound_terminal"} {
		t.Run(name, func(t *testing.T) {
			journal, stateDir, _, _, plan := newSoftwareJournalAdoptionFixture(t, name == "trusted_legacy")
			if name == "bound_terminal" {
				last := &journal.data.Pending[len(journal.data.Pending)-1].Report
				last.Status, last.Progress, last.ArtifactDigest = "succeeded", 100, plan.ArtifactDigest
				if err := journal.saveLocked(); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := json.Marshal(journal.data)
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := OpenJournal(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(journal.path)
			actual, encodeErr := json.Marshal(reloaded.data)
			if err != nil || encodeErr != nil || !bytes.Equal(before, after) || !bytes.Equal(expected, actual) {
				t.Fatal("restart changed the original software cursor, pending reports, or durable source bytes")
			}
			if reloaded.Active().ReportSequence != 0 || reloaded.data.NextSeq != 3 || len(reloaded.Pending()) != 2 ||
				!reflect.DeepEqual(reloaded.ActivePlan(), &plan) || !reflect.DeepEqual(reloaded.data.ActiveStageFailure, journal.data.ActiveStageFailure) {
				t.Fatal("restart lost the durable sequence or original plan/session/artifact/policy authority")
			}
			if name == "bound_terminal" {
				// The caller must accept exact structured CP terminal proof before
				// dropping this job's reports and then using the normal clear fence.
				if err := reloaded.DropJobReports(reloaded.Active().ID); err != nil {
					t.Fatal(err)
				}
				if err := reloaded.ClearActive(); err != nil {
					t.Fatal(err)
				}
				cleared, err := OpenJournal(stateDir)
				if err != nil || cleared.Active() != nil || len(cleared.Pending()) != 0 {
					t.Fatal("proven terminal clear left an orphaned old software report")
				}
			}
		})
	}
}

func TestSoftwareJournalRestartFailedFreshClaimPreservesPending(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "bound"
		if legacy {
			name = "trusted_legacy"
		}
		t.Run(name, func(t *testing.T) {
			journal, stateDir, _, fresh, plan := newSoftwareJournalAdoptionFixture(t, legacy)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := OpenJournal(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			fresh.OwnershipEpoch++
			assertSoftwareJournalAdoptionRejected(t, reloaded, func() error { return reloaded.AdoptRecoveredSoftwareClaim(fresh) })
			after, err := os.ReadFile(journal.path)
			if err != nil || !bytes.Equal(before, after) || len(reloaded.Pending()) != 2 || !reflect.DeepEqual(reloaded.ActivePlan(), &plan) {
				t.Fatal("failed fresh claim after restart erased the retained pending or plan")
			}
		})
	}
}

func TestSoftwareJournalRestartRejectsAmbiguousPendingWithoutRewriting(t *testing.T) {
	for _, name := range []string{"job", "generation", "service", "zero_sequence", "sequence_at_cursor", "duplicate_sequence", "reversed_sequence", "credential", "port_result", "unknown_status", "invalid_progress", "invalid_digest", "legacy_without_plan", "wire_only_rejected", "raw_active_credential"} {
		t.Run(name, func(t *testing.T) {
			journal, stateDir, _, _, _ := newSoftwareJournalAdoptionFixture(t, false)
			pending := &journal.data.Pending[0]
			switch name {
			case "job":
				pending.JobID = "job-other"
			case "generation":
				pending.Report.LeaseGeneration++
			case "service":
				pending.Report.ServiceID = "updater-other"
			case "zero_sequence":
				pending.Report.Sequence = 0
			case "sequence_at_cursor":
				pending.Report.Sequence = journal.data.NextSeq
			case "duplicate_sequence":
				journal.data.Pending[1].Report.Sequence = pending.Report.Sequence
			case "reversed_sequence":
				pending.Report.Sequence, journal.data.Pending[1].Report.Sequence = 2, 1
			case "credential":
				pending.Report.LeaseToken = "synthetic-credential"
			case "port_result":
				pending.Report.PortReconfigure = &PortReconfigurationJobReport{}
			case "unknown_status":
				pending.Report.Status = "unsupported"
			case "invalid_progress":
				pending.Report.Progress = 101
			case "invalid_digest":
				pending.Report.ArtifactDigest = "invalid"
			case "legacy_without_plan":
				journal.data.ActiveJob.SoftwareUpdate, journal.data.ActiveJob.PolicyRevision, journal.data.ActivePlan = nil, 1, nil
			case "wire_only_rejected":
				journal.data.ActiveJob.SoftwareUpdate = &SoftwareUpdateJobBinding{ConfigRevision: 1, CommandSHA256: journal.data.ActiveJob.SoftwareUpdate.CommandSHA256}
				journal.data.ActiveJob.SoftwareClaimRejected, journal.data.ActiveJob.PolicyRevision, journal.data.ActivePlan = true, 0, nil
			case "raw_active_credential":
				journal.data.ActiveJob.LeaseToken = "synthetic-credential"
			}
			before, err := json.Marshal(journal.data)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(journal.path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenJournal(stateDir); err == nil {
				t.Fatal("ambiguous software pending state was accepted or silently discarded")
			}
			after, err := os.ReadFile(journal.path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed software restart validation rewrote its source bytes")
			}
		})
	}
}

func TestSoftwareJournalRestartRetainsLegacyNonV2PendingScrub(t *testing.T) {
	journal, stateDir, old, _, plan := newSoftwareJournalAdoptionFixture(t, false)
	old.ProtocolVersion, old.SoftwareUpdate, old.PolicyRevision, old.LeaseToken = 0, nil, 8, "synthetic-credential"
	journal.data.ActiveJob = &old
	journal.data.Pending[0].Report.LeaseToken = "synthetic-credential"
	if err := journal.saveLocked(); err != nil {
		t.Fatal(err)
	}
	// Write the historical raw token explicitly; current saves already redact it.
	before, err := json.Marshal(journal.data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal.path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Active() == nil || loaded.Active().LeaseToken != "" || len(loaded.Pending()) != 0 || !reflect.DeepEqual(loaded.ActivePlan(), &plan) {
		t.Fatal("non-v2 software credential and pending compatibility scrub changed")
	}
}
