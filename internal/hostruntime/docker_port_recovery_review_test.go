package hostruntime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/autostream-contracts/pkg/contracts"
)

func TestSTPortDockerReopensInterruptedTargetWithoutRepeatingMutation(t *testing.T) {
	for _, test := range []struct {
		name, phase string
		persistent  bool
	}{
		{"memory_restarted", "after_restart", false},
		{"file_restarted", "after_restart", true},
		{"memory_verified", "after_target_verify", false},
		{"file_verified", "after_target_verify", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newSTDockerPortHarness(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
			stateDir := t.TempDir()
			if test.persistent {
				state, err := newFileDockerPortStateStore(stateDir, false)
				if err != nil {
					t.Fatal(err)
				}
				h.state = state
			}
			h.runtime.crashAt = test.phase
			interrupted := h.run(t, "port_reconfigure")
			if interrupted.Error == nil || interrupted.Error.Code != "reconcile_required" {
				t.Fatal("fixture did not interrupt after the target restart")
			}
			ledger, err := h.state.LoadJob(h.plan.TargetID, h.plan.JobID)
			if err != nil || ledger == nil || ledger.State != systemdPortLedgerRestarted || !ledger.PolicyTransition.Consumed || ledger.Result != nil {
				t.Fatal("interrupted target was not retained without a completion result")
			}
			if test.persistent {
				state, err := newFileDockerPortStateStore(stateDir, false)
				if err != nil {
					t.Fatal(err)
				}
				h.state = state
				policyPath := filepath.Join(t.TempDir(), "executor-policy.json")
				if err := os.WriteFile(policyPath, h.runtime.store.disk, 0o600); err != nil {
					t.Fatal(err)
				}
				reloaded, err := newFilePortPolicyStore(policyPath, false)
				if err != nil || reloaded.Verify(ledger.PolicyTransition.TargetPolicy) != nil {
					t.Fatal("fresh policy store did not retain the interrupted target authority")
				}
			}
			h.runtime.crashAt = ""
			h.plan.LeaseGeneration++
			h.plan.SessionID = "docker-v2-reopened-session-0123456789"
			h.plan.PortPlanSHA256, _ = h.plan.ComputePortPlanSHA256()
			resumed := h.run(t, "port_reconfigure_reconcile")
			if resumed.PortResult == nil || resumed.PortResult.Result != systemdPortResultApplied ||
				h.runtime.consumeCalls != 1 || h.runtime.writeCalls != 1 || h.runtime.recreateCalls != 1 {
				t.Fatalf("verified target recovery changed the mutation count: applied=%t consume=%d write=%d recreate=%d",
					resumed.PortResult != nil && resumed.PortResult.Result == systemdPortResultApplied,
					h.runtime.consumeCalls, h.runtime.writeCalls, h.runtime.recreateCalls)
			}
		})
	}
}

func TestSTPortDockerUnverifiedInterruptedTargetRecoversOnlyToRollback(t *testing.T) {
	h := newSTDockerPortHarness(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	h.runtime.crashAt = "after_restart"
	interrupted := h.run(t, "port_reconfigure")
	if interrupted.Error == nil || interrupted.Error.Code != "reconcile_required" {
		t.Fatal("fixture did not retain an interrupted target")
	}
	// The target sidecar and root policy remain exact, but the target listener
	// is absent. A completed-target response would therefore be false evidence.
	h.runtime.live = nil
	h.runtime.crashAt = ""
	h.plan.LeaseGeneration++
	h.plan.SessionID = "docker-v2-unverified-session-0123456789"
	h.plan.PortPlanSHA256, _ = h.plan.ComputePortPlanSHA256()
	recovered := h.run(t, "port_reconfigure_reconcile")
	if recovered.PortResult == nil || recovered.PortResult.PortResult == nil || recovered.PortResult.Result != systemdPortResultRolledBack ||
		h.runtime.consumeCalls != 2 || h.runtime.writeCalls != 2 || h.runtime.recreateCalls != 2 || h.runtime.restoreCalls != 0 {
		t.Fatal("unverified target did not consume distinct recovery authority and converge to R")
	}
	policy, err := h.runtime.store.Snapshot()
	if err != nil || !portPolicySnapshotMatches(policy, policy.Targets[0], *h.plan.Rollback) ||
		recovered.PortResult.PortResult.ObservedConfigRevision != h.plan.Before.ConfigRevision+2 {
		t.Fatal("recovery did not preserve B functional values with fresh R revisions")
	}
	replayed := h.run(t, "port_reconfigure_reconcile")
	if replayed.PortResult == nil || replayed.PortResult.Result != systemdPortResultRolledBack ||
		h.runtime.consumeCalls != 2 || h.runtime.writeCalls != 2 || h.runtime.recreateCalls != 2 {
		t.Fatal("completed R replay repeated a grant or mutation")
	}
}
