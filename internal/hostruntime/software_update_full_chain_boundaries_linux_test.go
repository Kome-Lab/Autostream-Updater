//go:build linux

package hostruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/example/autostream-contracts/pkg/contracts"
)

type softwareUpdateChainCalls struct {
	Stage                 int  `json:"stage"`
	Apply                 int  `json:"apply"`
	Reconcile             int  `json:"reconcile"`
	DeliveryLosses        int  `json:"delivery_losses"`
	BlockedReconciles     int  `json:"blocked_reconciles"`
	Inspections           int  `json:"inspections"`
	StageRequiredResponse bool `json:"stage_required_response"`
}
type softwareUpdateChainBoundaryEvidence struct {
	Boundary           string                   `json:"boundary"`
	Job                softwareUpdateChainJob   `json:"terminal_job"`
	OperatorGeneration uint64                   `json:"operator_generation,omitempty"`
	AgentDownloads     int                      `json:"agent_downloads"`
	RootDownloads      int                      `json:"root_downloads"`
	RecoveryCalls      softwareUpdateChainCalls `json:"recovery_socket_calls"`
}

func softwareUpdateChainPreApplyBoundaries(t *testing.T, h *softwareUpdateChainHarness) bool {
	if !t.Run("InitialProgressLossTerminalRecovery", func(t *testing.T) {
		h.startFixedAgent(t)
		job := h.createSoftware(t, "software-initial-progress-loss")
		beforeAuthority := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		beforeWire := softwareUpdateChainDecodeWire(t, beforeAuthority)
		h.armCPFault(t, "progress_claimed_after")
		response := h.agent.call(t, stPortChainCommand{Command: "poll"})
		before := h.readSoftware(t, job.ID)
		if response.OK || response.ActiveJobID != job.ID || response.ActivePlanPresent || response.RootCalls != 0 || before.Status != "claimed" || before.Progress != 5 || before.Sequence != 1 || before.LeaseGeneration != 1 {
			t.Fatal("initial real progress commit/delivery loss did not retain the expected nonexecuting cursor")
		}
		h.agent.stop()
		journal, _ := h.readJournal(t)
		if journal.ActiveJob == nil || journal.ActiveJob.ID != job.ID || journal.ActivePlan != nil || len(journal.Pending) != 1 || journal.Pending[0].JobID != job.ID || journal.Pending[0].Report.Status != "claimed" || journal.Pending[0].Report.Progress != 5 || journal.Pending[0].Report.Sequence != 1 {
			t.Fatal("initial response loss did not preserve the exact pending progress before explicit recovery")
		}
		recovery := h.start(t, "recovery", h.testBinary, "TestSoftwareUpdateFullChainRecoveryProcess", h.uid, h.gid)
		defer recovery.stop()
		settled := recovery.call(t, stPortChainCommand{Command: "recover", JobID: job.ID, LeaseGeneration: before.LeaseGeneration})
		job = h.readSoftware(t, job.ID)
		calls := softwareUpdateChainDecodeCalls(t, settled)
		if !settled.OK || settled.ActiveJobID != "" || settled.ActivePlanPresent || calls.Stage != 0 || calls.Apply != 0 || calls.Reconcile != 0 || calls.Inspections < 1 || calls.StageRequiredResponse || job.Status != "failed" || job.Code != "execution_failed" || job.LeaseGeneration != 2 {
			t.Fatal("exact initial-progress recovery did not terminalize only the nonexecuting original claim")
		}
		h.requireSettledSoftwareClaimIntent(t, job, before.LeaseGeneration)
		afterAuthority := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		afterWire := softwareUpdateChainDecodeWire(t, afterAuthority)
		if afterWire.GrantCount != beforeWire.GrantCount || afterAuthority.ConsumeCount != beforeAuthority.ConsumeCount {
			t.Fatal("terminal-only initial-progress recovery issued or consumed a mutation grant")
		}
		h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
		h.requireUnchangedBaseline(t)
		h.recordBoundary("initial_progress_response_loss", job, before.LeaseGeneration, calls)
	}) {
		return false
	}
	if !t.Run("SavedPlanProgressLossReconcile", func(t *testing.T) {
		h.startFixedAgent(t)
		job := h.createSoftware(t, "software-saved-plan-progress-loss")
		h.armCPFault(t, "progress_verifying_after")
		response := h.agent.call(t, stPortChainCommand{Command: "poll"})
		before := h.readSoftware(t, job.ID)
		original, _ := h.readJournal(t)
		if response.OK || response.ActiveJobID != job.ID || !response.ActivePlanPresent || response.RootCalls != 0 || original.ActivePlan == nil || original.ActivePlan.JobID != job.ID || original.ActiveStageFailure != nil || len(original.Pending) != 1 || original.Pending[0].JobID != job.ID || original.Pending[0].Report.Status != "verifying" || original.Pending[0].Report.Progress != 40 || original.Pending[0].Report.Sequence != uint64(before.Sequence) || before.Status != "downloading" || before.Progress != 40 || before.LeaseGeneration != 1 {
			t.Fatal("real verified download/progress delivery loss did not preserve the pre-Stage plan")
		}
		h.agentDownloads++
		h.restartFixedRuntime(t)
		settled := h.agent.call(t, stPortChainCommand{Command: "poll"})
		job = h.readSoftware(t, job.ID)
		calls := softwareUpdateChainDecodeCalls(t, settled)
		if !settled.OK || settled.ActiveJobID != "" || settled.ActivePlanPresent || calls.Stage != 0 || calls.Apply != 0 || calls.Reconcile != 1 || !calls.StageRequiredResponse || job.Status != "failed" || job.Code != "execution_failed" || job.LeaseGeneration != 2 {
			t.Fatal("saved pre-Stage plan did not reconcile missing root state without downloading, staging or applying")
		}
		h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
		h.requireUnchangedBaseline(t)
		h.recordBoundary("verified_progress_response_loss", job, 0, calls)
	}) {
		return false
	}
	if !t.Run("StageResponseLossRestartReconcile", func(t *testing.T) {
		job, original := h.stageInterrupted(t, "software-stage-response-loss")
		h.restartFixedRuntime(t)
		settled := h.agent.call(t, stPortChainCommand{Command: "poll"})
		job = h.readSoftware(t, job.ID)
		calls := softwareUpdateChainDecodeCalls(t, settled)
		h.requireRolledBackRecovery(t, job, settled, calls, 2)
		h.requirePlanIntent(t, job.ID, original)
		h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
		h.requireUnchangedBaseline(t)
		h.recordBoundary("stage_response_loss", job, 0, calls)
	}) {
		return false
	}
	if !t.Run("LostFreshClaimOperatorGenerationRecovery", func(t *testing.T) {
		job, original := h.stageInterrupted(t, "software-fresh-claim-response-loss")
		h.restartFixedRuntime(t)
		_, journalBefore := h.readJournal(t)
		h.armCPFault(t, "claim_after")
		lost := h.agent.call(t, stPortChainCommand{Command: "poll"})
		central := h.readSoftware(t, job.ID)
		if lost.OK || lost.RootCalls != 0 || lost.ActiveJobID != job.ID || !lost.ActivePlanPresent || central.LeaseGeneration != 2 || central.Status != "reconciling" || central.Sequence != 0 {
			t.Fatal("actual CP fresh claim commit/delivery loss did not preserve the original plan and expose the exact advanced central generation")
		}
		_, journalAfter := h.readJournal(t)
		if journalAfter != journalBefore {
			t.Fatal("lost fresh claim response changed the original journal before authenticated adoption")
		}
		rejected := h.agent.call(t, stPortChainCommand{Command: "poll"})
		_, repeatedJournal := h.readJournal(t)
		if rejected.OK || rejected.FailureHTTPStatus != 409 || rejected.RootCalls != 0 || repeatedJournal != journalBefore || h.readSoftware(t, job.ID) != central {
			t.Fatal("ordinary stale-generation retry changed state instead of retaining the original exact cursor")
		}
		h.agent.stop()
		recovery := h.start(t, "recovery", h.testBinary, "TestSoftwareUpdateFullChainRecoveryProcess", h.uid, h.gid)
		defer recovery.stop()
		settled := recovery.call(t, stPortChainCommand{Command: "recover_plan", JobID: job.ID, LeaseGeneration: central.LeaseGeneration})
		job = h.readSoftware(t, job.ID)
		calls := softwareUpdateChainDecodeCalls(t, settled)
		h.requireRolledBackRecovery(t, job, settled, calls, 3)
		h.requirePlanIntent(t, job.ID, original)
		h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
		h.requireUnchangedBaseline(t)
		h.recordBoundary("fresh_claim_response_loss", job, central.LeaseGeneration, calls)
	}) {
		return false
	}
	return t.Run("ExpiredLeaseRejectedBeforeGrant", func(t *testing.T) {
		job, original := h.stageInterrupted(t, "software-expired-original-lease")
		before := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		beforeWire := softwareUpdateChainDecodeWire(t, before)
		_, journalBefore := h.readJournal(t)
		expired := h.agent.call(t, stPortChainCommand{Command: "expire_grant"})
		after := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		afterWire := softwareUpdateChainDecodeWire(t, after)
		_, journalAfter := h.readJournal(t)
		if expired.OK || expired.FailureCode != "expired_lease_rejected" || expired.RootCalls != 1 || beforeWire.GrantCount != afterWire.GrantCount || before.ConsumeCount != after.ConsumeCount || h.readSoftware(t, job.ID) != job || journalAfter != journalBefore {
			t.Fatal("clock-controlled expired original CP lease reached a grant/root mutation or changed retained authority")
		}
		if !h.cp.call(t, stPortChainCommand{Command: "arm_expiry_probe"}).OK {
			t.Fatal("arm original-expiry MariaDB authorization proof")
		}
		h.restartFixedRuntime(t)
		settled := h.agent.call(t, stPortChainCommand{Command: "poll"})
		job = h.readSoftware(t, job.ID)
		calls := softwareUpdateChainDecodeCalls(t, settled)
		h.requireRolledBackRecovery(t, job, settled, calls, 2)
		wire := softwareUpdateChainDecodeWire(t, h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID}))
		if wire.ExpiredGrantStoreRejections != beforeWire.ExpiredGrantStoreRejections+1 {
			t.Fatal("real MariaDB store did not reject the unmodified grant binding just beyond its persisted lease expiry")
		}
		h.requirePlanIntent(t, job.ID, original)
		h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
		h.requireUnchangedBaseline(t)
		h.recordBoundary("clock_controlled_lease_expiry", job, 0, calls)
	})
}

func (h *softwareUpdateChainHarness) stageInterrupted(t *testing.T, key string) (softwareUpdateChainJob, MutationPlan) {
	t.Helper()
	h.startFixedAgent(t)
	job := h.createSoftware(t, key)
	if !h.agent.call(t, stPortChainCommand{Command: "arm_socket_fault", Fault: "stage_after"}).OK {
		t.Fatal("arm Stage delivery loss")
	}
	response := h.agent.call(t, stPortChainCommand{Command: "poll"})
	job = h.readSoftware(t, job.ID)
	journal, _ := h.readJournal(t)
	calls := softwareUpdateChainDecodeCalls(t, response)
	if response.OK || response.ActiveJobID != job.ID || !response.ActivePlanPresent || journal.ActivePlan == nil || calls.Stage != 1 || calls.Apply != 0 || calls.Reconcile != 0 || calls.DeliveryLosses != 1 || calls.StageRequiredResponse || job.Status != "downloading" || job.Progress != 55 || job.LeaseGeneration != 1 {
		t.Fatal("real successful Stage lost response did not preserve its original plan and durable staged root state")
	}
	h.requireRootLedger(t, job.ID, remoteLedgerStaged)
	h.agentDownloads++
	h.rootDownloads++
	h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
	h.requireUnchangedBaseline(t)
	return job, *journal.ActivePlan
}
func (h *softwareUpdateChainHarness) startFixedAgent(t *testing.T) {
	t.Helper()
	h.agent.stop()
	h.agent = h.start(t, "agent", h.testBinary, "TestSTPortFullChainRuntimeProcess", h.uid, h.gid)
}
func (h *softwareUpdateChainHarness) restartFixedRuntime(t *testing.T) {
	t.Helper()
	h.agent.stop()
	stPortChainRun(t, "/usr/bin/systemctl", "restart", "autostream-local-executor.service")
	h.waitRoot(t)
	h.startFixedAgent(t)
}
func (h *softwareUpdateChainHarness) armCPFault(t *testing.T, fault string) {
	t.Helper()
	if !h.cp.call(t, stPortChainCommand{Command: "arm_fault", Fault: fault}).OK {
		t.Fatal("arm bounded CP commit/delivery boundary")
	}
}
func (h *softwareUpdateChainHarness) readJournal(t *testing.T) (journalData, string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(HostPullAgentStateDir, "journal.json"))
	var data journalData
	if err != nil || len(body) == 0 || len(body) > 4<<20 || json.Unmarshal(body, &data) != nil {
		t.Fatal("read bounded original durable journal without modifying it")
	}
	return data, contracts.ComputeSystemUpdatePortBytesSHA256(body)
}
func softwareUpdateChainDecodeCalls(t *testing.T, response stPortChainResponse) softwareUpdateChainCalls {
	t.Helper()
	var counts softwareUpdateChainCalls
	if json.Unmarshal(response.SoftwareWire, &counts) != nil {
		t.Fatal("actual software socket call counts unavailable")
	}
	t.Logf("SOFTWARE real socket calls: Stage=%d Apply=%d Reconcile=%d Inspect=%d delivery_losses=%d blocked_reconciles=%d stage_required_response=%t", softwareUpdateChainSafeCount(int64(counts.Stage)), softwareUpdateChainSafeCount(int64(counts.Apply)), softwareUpdateChainSafeCount(int64(counts.Reconcile)), softwareUpdateChainSafeCount(int64(counts.Inspections)), softwareUpdateChainSafeCount(int64(counts.DeliveryLosses)), softwareUpdateChainSafeCount(int64(counts.BlockedReconciles)), counts.StageRequiredResponse)
	return counts
}
func (h *softwareUpdateChainHarness) requireRolledBackRecovery(t *testing.T, job softwareUpdateChainJob, response stPortChainResponse, calls softwareUpdateChainCalls, generation uint64) {
	t.Helper()
	if !response.OK || response.ActiveJobID != "" || response.ActivePlanPresent || calls.Stage != 0 || calls.Apply != 0 || calls.Reconcile != 1 || calls.StageRequiredResponse || job.Status != "rolled_back" || job.Code != "" || job.Progress != 100 || job.LeaseGeneration != generation || job.PolicyRevision != h.projection || job.OwnershipEpoch != 3 {
		t.Fatal("fresh-lease recovery did not settle original staged-only intent with one real Reconcile and no Stage/Apply")
	}
}
func (h *softwareUpdateChainHarness) requireSettledSoftwareClaimIntent(t *testing.T, job softwareUpdateChainJob, originalGeneration uint64) {
	t.Helper()
	intent, exists, intentErr := loadSoftwareClaimRecoveryIntent(HostPullAgentStateDir, func(info os.FileInfo) bool {
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && stat.Uid == h.uid && stat.Gid == h.gid && stat.Nlink == 1
	})
	identity, identityErr := LoadManagedBootstrapConfig(HostAgentIdentityPath, true)
	digest, digestErr := h.rootPolicy.SHA256()
	exact := SoftwareClaimRecoveryRequest{JobID: job.ID, LeaseGeneration: originalGeneration, TargetID: "control-panel", CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ConfigRevision: 1, OwnershipEpoch: 3}
	verified := intentErr == nil && exists && intent.Settled && intent.Original == exact && intent.Request == exact &&
		identityErr == nil && intent.UpdaterID == identity.NodeID && intent.HostID == h.rootPolicy.HostID &&
		intent.SourcePolicyRevision == h.source && intent.ProjectionRevision == h.projection && intent.ExecutorPolicyRevision == h.executor &&
		digestErr == nil && intent.ExecutorPolicySHA256 == digest && len(intent.Attempts) == 1 &&
		intent.Attempts[0].LeaseGeneration == originalGeneration && !intent.Attempts[0].ConfirmedReread
	journal, _ := h.readJournal(t)
	empty := journal.ActiveJob == nil && journal.ActivePlan == nil && journal.ActiveStageFailure == nil &&
		journal.ActivePortPlan == nil && journal.ActivePortPolicy == nil && len(journal.Pending) == 0
	t.Logf("SOFTWARE terminal-only reason proof: exact_settled_intent=%t empty_journal=%t source=%d projection=%d executor=%d", verified, empty, softwareUpdateChainSafeCount(intent.SourcePolicyRevision), softwareUpdateChainSafeCount(intent.ProjectionRevision), softwareUpdateChainSafeCount(intent.ExecutorPolicyRevision))
	if !verified || !empty {
		t.Fatal("terminal-only public failure lacks its exact settled recovery intent and fully cleared nonexecuting journal")
	}
}
func (h *softwareUpdateChainHarness) requireRootLedger(t *testing.T, jobID, state string) executorMutationLedger {
	t.Helper()
	cfg, err := h.rootPolicy.mutationHelperConfig("amd64")
	if err != nil {
		t.Fatal("derive actual installed root mutation authority")
	}
	ledger, err := loadExecutorMutationLedger(cfg, "control-panel")
	if err != nil || ledger == nil || ledger.JobID != jobID || ledger.State != state {
		t.Fatal("actual root-owned ledger does not prove the expected job/boundary")
	}
	return *ledger
}
func (h *softwareUpdateChainHarness) requirePlanIntent(t *testing.T, jobID string, original MutationPlan) {
	t.Helper()
	ledger := h.requireRootLedger(t, jobID, remoteLedgerTerminal)
	if ledger.Intent != newRemoteMutationIntent(original) {
		t.Fatal("recovery replaced original verified artifact/version/policy plan intent")
	}
}
func (h *softwareUpdateChainHarness) recordBoundary(name string, job softwareUpdateChainJob, generation uint64, calls softwareUpdateChainCalls) {
	h.boundaries = append(h.boundaries, softwareUpdateChainBoundaryEvidence{Boundary: name, Job: job, OperatorGeneration: generation, AgentDownloads: h.agentDownloads, RootDownloads: h.rootDownloads, RecoveryCalls: calls})
}
