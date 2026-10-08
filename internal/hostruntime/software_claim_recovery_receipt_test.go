package hostruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSoftwareClaimRecoveryTerminalReceiptBindsActualClearAndRootDomains(t *testing.T) {
	agent, _, _, _, request := newSoftwareClaimRecoveryHarness(t)
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	intent, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || intent.SchemaVersion != 2 || intent.TerminalClear == nil {
		t.Fatal("authenticated terminal clear receipt was not persisted")
	}
	receipt := *intent.TerminalClear
	if receipt.ClaimRequest.LeaseGeneration != 2 || receipt.RootNoMutation.RequestSHA256 != request.sha256() ||
		receipt.AcceptedResult == nil || receipt.AcceptedResult.Status != "failed" || receipt.AcceptedResult.Code != "execution_failed" ||
		receipt.validate(intent) != nil {
		t.Fatal("receipt guessed a generation or confused the internal reason with the V2 wire result")
	}
	for _, kind := range []string{"clear_generation", "job", "updater", "host", "fence", "config", "source", "projection", "executor", "digest", "no_mutation", "proof_clear_generation", "wire_code"} {
		t.Run(kind, func(t *testing.T) {
			candidate, changed := intent, receipt
			result := *receipt.AcceptedResult
			changed.AcceptedResult = &result
			switch kind {
			case "clear_generation":
				changed.ClaimRequest.LeaseGeneration++
			case "job":
				changed.ClaimRequest.ActiveJobID = "foreign-job"
			case "updater":
				changed.ClaimRequest.UpdaterID = "foreign-updater"
			case "host":
				changed.ClaimRequest.HostID = "foreign-host"
			case "fence":
				changed.ClaimRequest.Fence++
			case "config":
				candidate.Original.ConfigRevision++
				candidate.Request.ConfigRevision++
			case "source":
				changed.RootNoMutation.SourcePolicyRevision++
			case "projection":
				changed.RootNoMutation.ProjectionRevision++
			case "executor":
				changed.RootNoMutation.ExecutorPolicyRevision++
			case "digest":
				changed.RootNoMutation.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("a", 64)
			case "no_mutation":
				changed.RootNoMutation.NoMutation = false
			case "proof_clear_generation":
				fresh := candidate.Request
				fresh.LeaseGeneration = uint64(changed.ClaimRequest.LeaseGeneration)
				changed.RootNoMutation.RequestSHA256 = fresh.sha256()
			case "wire_code":
				changed.AcceptedResult.Code = "software_claim_orphan_recovered"
			}
			candidate.TerminalClear = &changed
			if changed.validate(candidate) == nil || candidate.validate() == nil {
				t.Fatal("terminal receipt accepted another generation, revision domain or wire result")
			}
		})
	}
}

func TestSoftwareClaimRecoveryTerminalClearOnlyDoesNotInventPublicFailedCode(t *testing.T) {
	agent, panel, _, _, request := newSoftwareClaimRecoveryHarness(t)
	panel.terminal = true
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	intent, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || !intent.Settled || intent.TerminalClear == nil ||
		intent.TerminalClear.ClaimRequest.LeaseGeneration != 1 || intent.TerminalClear.AcceptedResult != nil || len(panel.reports) != 0 {
		t.Fatal("clear-only receipt asserted an unobserved central failed status or code")
	}
}

func TestSoftwareClaimRecoveryLegacySettledKeepsSameJobAndRejectsSuccessor(t *testing.T) {
	agent, panel, _, _, first := newSoftwareClaimRecoveryHarness(t)
	if err := agent.RecoverSoftwareClaim(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	legacy, _, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil {
		t.Fatal(err)
	}
	legacy.SchemaVersion, legacy.TerminalClear = 1, nil
	payload, err := json.Marshal(legacy)
	marker := filepath.Join(agent.StateDir, softwareClaimRecoveryIntentName)
	if err != nil || os.WriteFile(marker, append(payload, '\n'), 0o600) != nil {
		t.Fatal("persist legacy settled fixture")
	}
	before, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	claims, reports := len(panel.claims), len(panel.reports)
	if err := agent.RecoverSoftwareClaim(context.Background(), first); err != nil {
		t.Fatal("legacy same-job settled history is no longer readable")
	}
	second := prepareSoftwareClaimRecoveryHistorySuccessor(t, agent, panel, first)
	pending, err := os.ReadFile(agent.Journal.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.RecoverSoftwareClaim(context.Background(), second); err == nil {
		t.Fatal("a legacy settled flag was elevated into cross-job replacement authority")
	}
	after, markerErr := os.ReadFile(marker)
	afterPending, pendingErr := os.ReadFile(agent.Journal.path)
	if markerErr != nil || pendingErr != nil || string(before) != string(after) || string(pending) != string(afterPending) ||
		len(panel.claims) != claims || len(panel.reports) != reports {
		t.Fatal("legacy refusal changed original bytes, pending state or central jobs")
	}
}
