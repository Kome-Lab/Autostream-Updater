package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSoftwareJournalTerminalRecoveryAtomicallyReplacesFirstProgressPending(t *testing.T) {
	for _, restarted := range []bool{false, true} {
		name := "live"
		if restarted {
			name = "restart"
		}
		t.Run(name, func(t *testing.T) {
			journal, stateDir, fresh, request, proof := newSoftwareJournalTerminalAckFixture(t, restarted)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			markerPath := filepath.Join(stateDir, softwareClaimRecoveryIntentName)
			markerBefore, err := os.ReadFile(markerPath)
			if err != nil {
				t.Fatal(err)
			}
			ordinary := cloneV2PanelJob(*journal.Active())
			ordinary.LeaseGeneration++
			ordinary.CommandID, ordinary.ReportSequence, ordinary.RecoveryRequired = "command-normal-fresh", 1, true
			ordinary.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
			if err := journal.SetActive(&ordinary); err == nil {
				t.Fatal("normal SetActive discarded the first progress pending report")
			}
			expected := journal.data
			copy := cloneV2PanelJob(fresh)
			expected.ActiveJob, expected.NextSeq, expected.Pending = &copy, fresh.ReportSequence, nil
			renames := 0
			journal.renameFile = func(source, destination string) error {
				renames++
				candidateBytes, err := os.ReadFile(source)
				if err != nil {
					return err
				}
				var candidate journalData
				if err := json.Unmarshal(candidateBytes, &candidate); err != nil {
					return err
				}
				if candidate.ActiveJob == nil || candidate.ActiveJob.LeaseGeneration != fresh.LeaseGeneration || candidate.NextSeq != fresh.ReportSequence || len(candidate.Pending) != 0 {
					t.Fatal("terminal adoption split pending invalidation from the fresh cursor")
				}
				previous, err := os.ReadFile(destination)
				if err != nil {
					return err
				}
				if !bytes.Equal(before, previous) {
					t.Fatal("old first progress pending was rewritten before atomic adoption")
				}
				return os.Rename(source, destination)
			}
			if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
				t.Fatal(err)
			}
			if renames != 1 || !reflect.DeepEqual(journal.data, expected) || len(journal.leaseTokens) != 0 {
				t.Fatal("terminal adoption changed more than the active lease, report cursor and exact old pending")
			}
			markerAfter, err := os.ReadFile(markerPath)
			if err != nil || !bytes.Equal(markerBefore, markerAfter) {
				t.Fatal("terminal adoption erased the original attempt history")
			}
		})
	}
}

func TestSoftwareJournalTerminalRecoveryRejectsOtherPendingWithoutErasingEvidence(t *testing.T) {
	for _, name := range []string{"job", "generation", "service", "sequence", "next_sequence", "terminal", "downloading", "progress", "code", "artifact", "previous", "credential", "multiple", "active_status", "active_progress", "active_sequence", "wire_only", "wrong_root_proof"} {
		t.Run(name, func(t *testing.T) {
			journal, stateDir, fresh, request, proof := newSoftwareJournalTerminalAckFixture(t, false)
			report := &journal.data.Pending[0].Report
			switch name {
			case "job":
				journal.data.Pending[0].JobID = "job-other"
			case "generation":
				report.LeaseGeneration++
			case "service":
				report.ServiceID = "updater-other"
			case "sequence":
				report.Sequence++
			case "next_sequence":
				journal.data.NextSeq++
			case "terminal":
				report.Status, report.Progress = "failed", 100
			case "downloading":
				report.Status = "downloading"
			case "progress":
				report.Progress = 6
			case "code":
				report.Code = "synthetic-error"
			case "artifact":
				report.ArtifactDigest = fresh.SoftwareUpdate.ExecutorPolicySHA256
			case "previous":
				report.PreviousDigest = fresh.SoftwareUpdate.ExecutorPolicySHA256
			case "credential":
				report.LeaseToken = "synthetic-credential"
			case "multiple":
				second := journal.data.Pending[0]
				second.Report.Sequence++
				journal.data.Pending, journal.data.NextSeq = append(journal.data.Pending, second), 3
			case "active_status":
				journal.data.ActiveJob.Status = "downloading"
			case "active_progress":
				journal.data.ActiveJob.Progress = 5
			case "active_sequence":
				journal.data.ActiveJob.Sequence = 1
			case "wire_only":
				journal.data.ActiveJob.SoftwareUpdate = &SoftwareUpdateJobBinding{ConfigRevision: 1, CommandSHA256: fresh.SoftwareUpdate.CommandSHA256}
				journal.data.ActiveJob.SoftwareClaimRejected, journal.data.ActiveJob.PolicyRevision = true, 0
			case "wrong_root_proof":
				proof.NoMutation = false
			}
			payload, err := json.Marshal(journal.data)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(journal.path, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
		})
	}
}

func TestSoftwareJournalTerminalPendingSaveFailurePreservesStateAndPoisons(t *testing.T) {
	for _, point := range []string{"rename", "directory_sync"} {
		t.Run(point, func(t *testing.T) {
			journal, stateDir, fresh, request, proof := newSoftwareJournalTerminalAckFixture(t, false)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := json.Marshal(journal.data)
			if err != nil {
				t.Fatal(err)
			}
			markerPath := filepath.Join(stateDir, softwareClaimRecoveryIntentName)
			markerBefore, err := os.ReadFile(markerPath)
			if err != nil {
				t.Fatal(err)
			}
			if point == "rename" {
				journal.renameFile = func(string, string) error { return errors.New("synthetic rename failure") }
			} else {
				journal.syncDir = func(string) error { return errors.New("synthetic directory sync failure") }
			}
			if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err == nil || journal.poisoned == nil {
				t.Fatal("uncertain terminal adoption did not poison the journal")
			}
			actual, err := json.Marshal(journal.data)
			if err != nil || !bytes.Equal(expected, actual) || len(journal.Pending()) != 1 || len(journal.leaseTokens) != 1 {
				t.Fatal("failed terminal save erased the original memory state or pending lease metadata")
			}
			after, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			if point == "rename" {
				if !bytes.Equal(before, after) {
					t.Fatal("failed terminal rename changed the durable pending report")
				}
			} else {
				var durable journalData
				if err := json.Unmarshal(after, &durable); err != nil {
					t.Fatal(err)
				}
				if durable.ActiveJob == nil || durable.ActiveJob.LeaseGeneration != fresh.LeaseGeneration || durable.NextSeq != fresh.ReportSequence || len(durable.Pending) != 0 {
					t.Fatal("uncertain terminal commit contains a partial cursor/pending handoff")
				}
			}
			markerAfter, err := os.ReadFile(markerPath)
			if err != nil || !bytes.Equal(markerBefore, markerAfter) {
				t.Fatal("failed terminal save changed the durable attempt history")
			}
			if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err == nil {
				t.Fatal("poisoned terminal journal resumed mutation")
			}
		})
	}
}

func newSoftwareJournalTerminalAckFixture(t *testing.T, restarted bool) (*Journal, string, UpdateJob, SoftwareClaimRecoveryRequest, SoftwareClaimRecoveryProof) {
	t.Helper()
	journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
	journal.data.ActiveJob.Status, journal.data.ActiveJob.Progress = "claimed", 0
	fresh.Status, fresh.Progress = "claimed", 0
	if _, err := journal.Queue(fresh.ID, fresh.AgentServiceID, "", journal.Active().LeaseGeneration, "claimed", "", "initial claim accepted", 5, "", ""); err != nil {
		t.Fatal(err)
	}
	if restarted {
		var err error
		journal, err = OpenJournal(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		if journal.Active().ReportSequence != 0 || len(journal.Pending()) != 1 {
			t.Fatal("restart did not retain the first pending progress with its durable cursor")
		}
	}
	proof.ObservedAt = time.Now().UTC()
	return journal, stateDir, fresh, request, proof
}
