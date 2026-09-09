package hostruntime

import (
	"testing"

	"github.com/example/autostream-contracts/pkg/contracts"
)

func TestSTPortDockerReopensInterruptedTargetWithoutRepeatingMutation(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory_ledger"
		if persistent {
			name = "reopened_file_ledger"
		}
		t.Run(name, func(t *testing.T) {
			h := newSTDockerPortHarness(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
			stateDir := t.TempDir()
			if persistent {
				state, err := newFileDockerPortStateStore(stateDir, false)
				if err != nil {
					t.Fatal(err)
				}
				h.state = state
			}
			h.runtime.crashAt = "after_restart"
			interrupted := h.run(t, "port_reconfigure")
			if interrupted.Error == nil || interrupted.Error.Code != "reconcile_required" {
				t.Fatal("fixture did not interrupt after the target restart")
			}
			ledger, err := h.state.LoadJob(h.plan.TargetID, h.plan.JobID)
			if err != nil || ledger == nil || ledger.State != systemdPortLedgerRestarted || !ledger.PolicyTransition.Consumed || ledger.Result != nil {
				t.Fatal("interrupted target was not retained without a completion result")
			}
			if persistent {
				state, err := newFileDockerPortStateStore(stateDir, false)
				if err != nil {
					t.Fatal(err)
				}
				h.state = state
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
