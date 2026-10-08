package hostruntime

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestSoftwareClaimRecoveryJournalClearInterruptionKeepsUnsettledIntent(t *testing.T) {
	for _, kind := range []string{"before_journal_rename", "after_journal_rename"} {
		t.Run(kind, func(t *testing.T) {
			agent, panel, _, executor, request := newSoftwareClaimRecoveryHarness(t)
			panel.denyReportOnce = true
			if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
				t.Fatal("fixture must retain an unsettled, nonexecuting cursor")
			}
			active := agent.Journal.Active()
			binding := HostAgentBinding{ServiceID: agent.Bootstrap.NodeID, ServiceType: ServiceTypeUpdateAgent,
				TransportMode: HostTransportPullV2, ExecutionHostID: panel.policy.ExecutionHostID, OwnershipEpoch: request.OwnershipEpoch}
			clearRequest := HostPullClaimRequest{UpdaterID: agent.Bootstrap.NodeID, HostID: binding.ExecutionHostID,
				ActiveJobID: active.ID, LeaseGeneration: int64(active.LeaseGeneration), Fence: binding.OwnershipEpoch}
			panel.terminal = true
			terminal, clear, err := panel.ClaimHost(context.Background(), clearRequest)
			if err != nil || !clear {
				t.Fatal("fixture did not obtain an exact authenticated terminal clear")
			}
			journalPath := agent.Journal.path
			agent.Journal.renameFile = func(old, next string) error {
				if next == journalPath {
					if kind == "after_journal_rename" {
						if err := os.Rename(old, next); err != nil {
							return err
						}
					}
					return errors.New("journal clear persistence interrupted")
				}
				return os.Rename(old, next)
			}
			if err := agent.CompleteSoftwareClaimRecoveryClear(context.Background(), binding, panel.policy, terminal, clearRequest); err == nil {
				t.Fatal("interrupted local clear was accepted as settled")
			}
			intent, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
			if err != nil || !exists || intent.Settled || intent.TerminalClear != nil {
				t.Fatal("clear interruption manufactured a settled replacement receipt")
			}
			claims := len(panel.claims)
			foreign := request
			foreign.JobID = "next-job-before-clear-durable"
			if err := agent.RecoverSoftwareClaim(context.Background(), foreign); err == nil || len(panel.claims) != claims {
				t.Fatal("an unfinished journal clear permitted a new job claim")
			}
			// Only the existing journal's durable clear recovery may reconcile
			// its fence. The operator does not delete or rewrite state files.
			journal, err := OpenJournal(agent.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			agent.Journal = journal
			request.LeaseGeneration = panel.generation
			if err := agent.RecoverSoftwareClaim(context.Background(), request); err != nil {
				t.Fatal("same-job exact terminal clear did not finish after normal journal recovery:", err)
			}
			settled, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
			if err != nil || !exists || !settled.Settled || settled.TerminalClear == nil ||
				settled.TerminalClear.ClaimRequest != clearRequest || settled.TerminalClear.AcceptedResult != nil || agent.Journal.Active() != nil ||
				executor.stageCalls+executor.applyCalls+executor.reconcileCalls+executor.v2ApplyCalls+executor.v2ReconCalls != 0 {
				t.Fatal("journal clear recovery lost exact request evidence or executed software")
			}
		})
	}
}
