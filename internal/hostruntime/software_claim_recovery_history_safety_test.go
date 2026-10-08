package hostruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSoftwareClaimRecoveryHistoryRejectsUnboundPriorProofBeforeAndAfterCAS(t *testing.T) {
	for _, kind := range []string{"missing_before", "wrong_before", "wrong_after"} {
		t.Run(kind, func(t *testing.T) {
			agent, panel, inspector, old, next, _ := prepareSoftwareClaimRecoveryHistoryTransition(t)
			claims, reports := len(panel.claims), len(panel.reports)
			pending, err := os.ReadFile(agent.Journal.path)
			if err != nil {
				t.Fatal(err)
			}
			at := inspector.base.calls + 1
			if kind == "wrong_after" {
				at++
			}
			inspector.alter = func(proof *SoftwareClaimRecoveryProof, call int) {
				if call == at {
					proof.PriorSettledRawSHA256 = strings.Repeat("a", 64)
					if kind == "missing_before" {
						proof.PriorSettledRawSHA256 = ""
					}
					if proof.Validate() != nil {
						t.Fatal("negative must use a syntactically valid but unbound root digest")
					}
				}
			}
			if err := agent.RecoverSoftwareClaim(context.Background(), next.Request); err == nil {
				t.Fatal("a merely valid digest authorized a cross-job history transition")
			}
			current, exists, err := loadSoftwareClaimRecoverySnapshot(agent.StateDir, managedSnapshotOwnedByCurrentUser)
			afterPending, pendingErr := os.ReadFile(agent.Journal.path)
			if err != nil || !exists || pendingErr != nil || string(pending) != string(afterPending) ||
				len(panel.claims) != claims || len(panel.reports) != reports {
				t.Fatal("unbound root history issued a claim/report or changed the pending cursor")
			}
			if kind == "wrong_after" {
				if current.Intent.Settled || current.Intent.Original != next.Original || len(current.Archives) != 1 ||
					string(current.Archives[next.PreviousSettledRawSHA256].Raw) != string(old.Raw) {
					t.Fatal("post-CAS refusal lost the complete new marker or preserved original")
				}
			} else if string(current.Raw) != string(old.Raw) || len(current.Archives) != 0 {
				t.Fatal("pre-CAS proof refusal modified or archived the current original")
			}
		})
	}
}

func TestSoftwareClaimRecoveryHistoryRefusesUnsafeMissingOrOversizedArchives(t *testing.T) {
	for _, kind := range []string{"missing", "changed_raw", "unknown_entry", "oversized", "owner", "mode", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			agent, panel, _, _, next, proof := prepareSoftwareClaimRecoveryHistoryTransition(t)
			if err := transitionSoftwareClaimRecoveryIntent(agent.StateDir, next.PreviousSettledRawSHA256, next, proof, defaultSoftwareClaimRecoveryHistoryStoreRuntime()); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(agent.StateDir, softwareClaimRecoveryHistoryName, next.PreviousSettledRawSHA256+".json")
			owner := managedSnapshotOwnedByCurrentUser
			switch kind {
			case "missing":
				if err := os.Remove(archive); err != nil {
					t.Fatal(err)
				}
			case "changed_raw":
				payload, err := os.ReadFile(archive)
				if err != nil || os.WriteFile(archive, append([]byte(" \n"), payload...), 0o600) != nil {
					t.Fatal("persist changed-raw archive fixture")
				}
			case "unknown_entry":
				if err := os.WriteFile(filepath.Join(filepath.Dir(archive), "unknown-state.json"), []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(archive, []byte(strings.Repeat(" ", softwareClaimRecoveryIntentMaxBytes+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			case "owner":
				owner = func(os.FileInfo) bool { return false }
			case "mode", "hardlink":
				if !snapshotModeEnforced() {
					t.Skip("Unix file mode/link protection is exercised by Linux CI")
				}
				if kind == "mode" {
					if err := os.Chmod(archive, 0o644); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Link(archive, filepath.Join(agent.StateDir, "archive-hardlink")); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, owner); err == nil {
				t.Fatal("unsafe raw history passed the shared Agent/root/manual guard reader")
			}
			if kind != "owner" {
				claims := len(panel.claims)
				if err := agent.RecoverSoftwareClaim(context.Background(), next.Request); err == nil || len(panel.claims) != claims {
					t.Fatal("unsafe history reached a new central claim")
				}
				if _, err := agent.HasSoftwareClaimRecoveryIntent(next.Request.JobID); err == nil {
					t.Fatal("unsafe history passed normal Agent processing guard")
				}
			}
		})
	}
}

func TestSoftwareClaimRecoveryHistoryCapacityFailsBeforeCurrentReplacement(t *testing.T) {
	agent, _, _, old, next, proof := prepareSoftwareClaimRecoveryHistoryTransition(t)
	directory := filepath.Join(agent.StateDir, softwareClaimRecoveryHistoryName)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < softwareClaimRecoveryHistoryMaxFiles; index++ {
		archived := old.Intent
		archived.Original.JobID, archived.Request.JobID = "capacity-job-"+strings.Repeat("x", index+1), "capacity-job-"+strings.Repeat("x", index+1)
		receipt := *old.Intent.TerminalClear
		receipt.ClaimRequest.ActiveJobID, receipt.RootNoMutation.RequestSHA256 = archived.Original.JobID, archived.Request.sha256()
		archived.TerminalClear = &receipt
		payload, err := json.Marshal(archived)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, '\n')
		if err := os.WriteFile(filepath.Join(directory, softwareClaimRecoveryRawSHA256(payload)+".json"), payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := transitionSoftwareClaimRecoveryIntent(agent.StateDir, next.PreviousSettledRawSHA256, next, proof, defaultSoftwareClaimRecoveryHistoryStoreRuntime()); err == nil {
		t.Fatal("archive count bound was exceeded")
	}
	current, exists, err := loadSoftwareClaimRecoverySnapshot(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || string(current.Raw) != string(old.Raw) || len(current.Archives) != softwareClaimRecoveryHistoryMaxFiles {
		t.Fatal("archive-capacity refusal modified the current original")
	}
}
