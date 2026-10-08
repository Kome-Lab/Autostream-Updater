//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type softwareUpdateChainJob struct {
	ID              string `json:"id"`
	TargetID        string `json:"target_id"`
	Status          string `json:"status"`
	Code            string `json:"code"`
	PolicyRevision  int64  `json:"policy_revision"`
	OwnershipEpoch  int64  `json:"ownership_epoch"`
	LeaseGeneration uint64 `json:"lease_generation"`
	Sequence        int64  `json:"sequence"`
	Progress        int    `json:"progress"`
	ArtifactDigest  string `json:"artifact_digest"`
}

type softwareUpdateChainWire struct {
	ClaimConfig                 int64  `json:"claim_config"`
	ExpectedConfig              int64  `json:"expected_config"`
	ProgressConfig              int64  `json:"progress_config"`
	ProgressCount               int    `json:"progress_count"`
	GrantConfig                 int64  `json:"grant_config"`
	GrantPolicy                 int64  `json:"grant_policy"`
	GrantCount                  int    `json:"grant_count"`
	TerminalConfig              int64  `json:"terminal_config"`
	TerminalStatus              string `json:"terminal_status"`
	ExpiredGrantStoreRejections int    `json:"expired_grant_store_rejections"`
}

// The matrix runner selects both fixed CPs and both independent revision
// tuples. Every selected entry joins real CP/MariaDB HTTP, the old adapter,
// normal matched-pair installer, fixed Agent and privileged root socket.
func TestSoftwareUpdateFullChain(t *testing.T) {
	h := newSoftwareUpdateChainHarness(t)
	var orphan, fresh softwareUpdateChainJob
	var acceptedSHA string
	if !t.Run("LegacyAgentActualCPClaimRejected", func(t *testing.T) {
		orphan = h.createSoftware(t, "software-chain-orphan")
		old := h.agent.call(t, stPortChainCommand{Command: "poll"})
		orphan = h.readSoftware(t, orphan.ID)
		if old.OK || old.FailureStage != "execute" || old.FailureCode != "claim_revision_mismatch" || old.ActiveJobID != "" || old.RootCalls != 0 || orphan.Status != "claimed" || orphan.Progress != 0 || orphan.Sequence != 0 || orphan.LeaseGeneration != 1 || orphan.OwnershipEpoch != 3 || orphan.PolicyRevision != h.projection {
			t.Fatal("old production adapter did not reproduce the actual CP configuration/policy mismatch before local execution")
		}
		h.requireDownloads(t, 0, 0)
		h.requireUnchangedBaseline(t)
	}) {
		return
	}
	if !t.Run("ClaimedCancelAndSelfUpdateBlocked", func(t *testing.T) {
		guards := h.cp.call(t, stPortChainCommand{Command: "claimed_guards", JobID: orphan.ID})
		if !guards.OK || guards.FailureHTTPStatus != 409 || guards.FailureCode != "system_update_not_cancellable" || guards.ErrorCode != "host_lifecycle_busy" {
			t.Fatal("actual CP claimed cancel or atomic self-update lane guard was bypassed")
		}
		if h.readSoftware(t, orphan.ID) != orphan {
			t.Fatal("guard rejection changed the central claim")
		}
	}) {
		return
	}
	if !t.Run("NewRecoveryOldRootRejected", func(t *testing.T) {
		h.agent.stop()
		recovery := h.start(t, "recovery", h.testBinary, "TestSoftwareUpdateFullChainRecoveryProcess", h.uid, h.gid)
		defer recovery.stop()
		oldRoot := recovery.call(t, stPortChainCommand{Command: "inspect", JobID: orphan.ID, LeaseGeneration: 1})
		oldRootCalls := softwareUpdateChainDecodeCalls(t, oldRoot)
		if oldRoot.OK || oldRoot.RootCalls != 0 || oldRootCalls.Inspections != 1 || h.readSoftware(t, orphan.ID) != orphan {
			t.Fatal("candidate Agent alone recovered through an old root or changed the central job")
		}
		h.requireDownloads(t, 0, 0)
		h.requireUnchangedBaseline(t)
	}) {
		return
	}
	if !t.Run("NormalInstallerUpgradePreservesClaim", func(t *testing.T) {
		h.root.stop()
		softwareUpdateChainRunInstallerHook(t, h)
		if h.readSoftware(t, orphan.ID) != orphan {
			t.Fatal("normal matched-pair upgrade changed the existing central claim")
		}
		h.waitRoot(t)
		h.requireDownloads(t, 0, 0)
		h.requireUnchangedBaseline(t)
	}) {
		return
	}
	if !t.Run("FixedRootOrphanTerminalOnly", func(t *testing.T) {
		recovery := h.start(t, "recovery", h.testBinary, "TestSoftwareUpdateFullChainRecoveryProcess", h.uid, h.gid)
		defer recovery.stop()
		response := recovery.call(t, stPortChainCommand{Command: "recover", JobID: orphan.ID, LeaseGeneration: 1})
		settled := h.readSoftware(t, orphan.ID)
		calls := softwareUpdateChainDecodeCalls(t, response)
		if !response.OK || response.RootCalls != 0 || response.ActiveJobID != "" || response.ActivePlanPresent || calls.Stage != 0 || calls.Apply != 0 || calls.Reconcile != 0 || calls.Inspections < 1 || calls.StageRequiredResponse || settled.ID != orphan.ID || settled.Status != "failed" || settled.Code != "execution_failed" || settled.LeaseGeneration != 2 || settled.PolicyRevision != h.projection || settled.OwnershipEpoch != 3 {
			t.Fatal("explicit real-root absence proof did not settle only the exact orphan job without a software mutation")
		}
		h.requireSettledSoftwareClaimIntent(t, settled, 1)
		h.requireDownloads(t, 0, 0)
		h.requireUnchangedBaseline(t)
		observation := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: orphan.ID})
		wire := softwareUpdateChainDecodeWire(t, observation)
		if observation.ConsumeCount != 0 || wire.GrantCount != 0 || wire.TerminalConfig != 1 || wire.TerminalStatus != "failed" {
			t.Fatal("terminal-only recovery issued or consumed an apply grant or confused C with P")
		}
	}) {
		return
	}
	if !softwareUpdateChainPreApplyBoundaries(t, h) {
		return
	}
	if !t.Run("FreshJobProgressStageGrantApply", func(t *testing.T) {
		h.startFixedAgent(t)
		if baseline := h.agent.call(t, stPortChainCommand{Command: "observe"}); !baseline.OK || !baseline.TargetVerified {
			t.Fatal("fixed Agent could not observe the actual matched root/application baseline")
		}
		fresh = h.createSoftware(t, "software-chain-after-recovery")
		if !h.agent.call(t, stPortChainCommand{Command: "arm_socket_fault", Fault: "apply_after"}).OK {
			t.Fatal("arm delivery loss after a real successful Apply socket call")
		}
		response := h.agent.call(t, stPortChainCommand{Command: "poll"})
		fresh = h.readSoftware(t, fresh.ID)
		if response.OK || response.ActiveJobID != fresh.ID || !response.ActivePlanPresent || fresh.Status != "reconciling" || fresh.Code != "" || fresh.Progress != 99 || fresh.Sequence < 1 || fresh.PolicyRevision != h.projection || fresh.OwnershipEpoch != 3 {
			t.Fatal("lost Apply delivery did not retain the exact plan and uncertain central update")
		}
		observation := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: fresh.ID})
		wire := softwareUpdateChainDecodeWire(t, observation)
		if wire.ClaimConfig != 1 || wire.ExpectedConfig != 1 || wire.ProgressConfig != 1 || wire.ProgressCount < 1 || wire.GrantConfig != 1 || wire.GrantPolicy != h.projection || observation.ConsumeCount != 1 {
			t.Fatal("real CP progress/grant/consume changed independent C/P/F authority")
		}
		calls := softwareUpdateChainDecodeCalls(t, response)
		if calls.Stage != 1 || calls.Apply != 1 || calls.Reconcile != 0 || calls.DeliveryLosses != 1 || calls.BlockedReconciles != 1 {
			t.Fatal("actual socket Stage/Apply or bounded delivery-loss counts differ")
		}
		ledger := h.requireRootLedger(t, fresh.ID, remoteLedgerTerminal)
		if ledger.Result == nil || ledger.Result.Status != "succeeded" || normalizeDigest(ledger.Result.ArtifactDigest) != normalizeDigest(h.artifactDigest) {
			t.Fatal("real root did not durably verify the successful application and health before delivery loss")
		}
		h.agentDownloads++
		h.rootDownloads++
		h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
	}) {
		return
	}
	if !t.Run("ApplyResponseLossRestartReconcile", func(t *testing.T) {
		original, _ := h.readJournal(t)
		if original.ActivePlan == nil || original.ActiveJob == nil || original.ActiveJob.ID != fresh.ID {
			t.Fatal("actual applied response loss lacks the original durable plan")
		}
		h.restartFixedRuntime(t)
		if !h.cp.call(t, stPortChainCommand{Command: "arm_fault", Fault: "terminal_after"}).OK {
			t.Fatal("arm accepted-result response loss after real root restart/reconcile")
		}
		response := h.agent.call(t, stPortChainCommand{Command: "poll"})
		calls := softwareUpdateChainDecodeCalls(t, response)
		fresh = h.readSoftware(t, fresh.ID)
		if response.OK || response.ActiveJobID != fresh.ID || calls.Stage != 0 || calls.Apply != 0 || calls.Reconcile != 1 || calls.StageRequiredResponse || fresh.Status != "succeeded" || fresh.Code != "" || fresh.Progress != 100 || fresh.LeaseGeneration != 2 || fresh.PolicyRevision != h.projection || fresh.OwnershipEpoch != 3 || normalizeDigest(fresh.ArtifactDigest) != normalizeDigest(h.artifactDigest) {
			t.Fatal("actual root/Agent restart did not reconcile and report the original applied result without reapplying")
		}
		observation := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: fresh.ID})
		wire := softwareUpdateChainDecodeWire(t, observation)
		if wire.TerminalConfig != 1 || wire.TerminalStatus != "succeeded" || observation.ConsumeCount != 1 || observation.TerminalBodySHA256 == "" {
			t.Fatal("actual CP did not accept the reconciled result under C1 with exactly one consumed apply grant")
		}
		acceptedSHA = observation.TerminalBodySHA256
		h.requirePlanIntent(t, fresh.ID, *original.ActivePlan)
		h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
	}) {
		return
	}
	if !t.Run("AcceptedResultAckLossRestart", func(t *testing.T) {
		if h.agent.call(t, stPortChainCommand{Command: "metrics"}).ActiveJobID != fresh.ID {
			t.Fatal("acknowledgment loss did not retain the original durable active cursor")
		}
		h.agent.stop()
		stPortChainRun(t, "/usr/bin/systemctl", "restart", "autostream-local-executor.service")
		h.waitRoot(t)
		h.agent = h.start(t, "agent", h.testBinary, "TestSTPortFullChainRuntimeProcess", h.uid, h.gid)
		response := h.agent.call(t, stPortChainCommand{Command: "poll"})
		if !response.OK || response.ActiveJobID != "" || response.RootCalls != 0 || h.readSoftware(t, fresh.ID) != fresh {
			t.Fatal("restart did not accept the exact central terminal proof without reapplying software")
		}
		journal, _ := h.readJournal(t)
		t.Logf("SOFTWARE journal after terminal proof: active_job=%t active_plan=%t pending=%d", journal.ActiveJob != nil, journal.ActivePlan != nil, softwareUpdateChainSafeCount(int64(len(journal.Pending))))
		if journal.ActiveJob != nil || journal.ActivePlan != nil || len(journal.Pending) != 0 {
			t.Fatal("exact terminal proof did not clear the retained active job, plan and pending reports together")
		}
		next := h.agent.call(t, stPortChainCommand{Command: "poll"})
		nextJournal, _ := h.readJournal(t)
		if !next.OK || next.ActiveJobID != "" || next.ActivePlanPresent || next.RootCalls != 0 || nextJournal.ActiveJob != nil || nextJournal.ActivePlan != nil || len(nextJournal.Pending) != 0 || h.readSoftware(t, fresh.ID) != fresh {
			t.Fatal("the poll after terminal cleanup recreated local work or changed the accepted central result")
		}
		observation := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: fresh.ID})
		if observation.TerminalBodySHA256 != acceptedSHA || observation.LastTerminalBodySHA256 != acceptedSHA || observation.ConsumeCount != 1 {
			t.Fatal("restart changed the original terminal result or consumed another grant")
		}
		h.requireDownloads(t, h.agentDownloads, h.rootDownloads)
	}) {
		return
	}
	t.Run("FinalConfigurationAndPolicyPinned", func(t *testing.T) {
		stPortChainSameBytes(t, localExecutorPortPolicyPath, h.initialPolicy)
		stPortChainSameBytes(t, "/opt/autostream/local-executor/ports/control-panel.env", systemdPortSidecarBytes("control_panel", "127.0.0.1", 18080, 1))
		current, err := filepath.EvalSymlinks("/opt/autostream/control-panel/current")
		version, readErr := os.ReadFile(filepath.Join(current, ".version"))
		if err != nil || readErr != nil || strings.TrimSpace(string(version)) != "v2.0.1" || current == h.baselineRelease || verifyManagedReleaseChecksums(current) != nil {
			t.Fatal("installed checked target did not retain C1 and the accepted policy while moving to v2.0.1")
		}
		if baseline := h.agent.call(t, stPortChainCommand{Command: "observe"}); !baseline.OK || !baseline.TargetVerified {
			t.Fatal("final real root PID/listener/HTTP sandwich failed")
		}
		authority := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: fresh.ID})
		frozen := bytes.Equal(authority.RootPolicy, h.initialPolicy)
		t.Logf("SOFTWARE final CP authority: ok=%t phase=%s source=%d projection=%d executor=%d frozen_root_policy=%t", authority.OK, softwareUpdateChainSafeCode(authority.ErrorCode), softwareUpdateChainSafeCount(authority.DBSourcePolicyRevision), softwareUpdateChainSafeCount(authority.DBProjectionRevision), softwareUpdateChainSafeCount(authority.DBExecutorPolicyRevision), frozen)
		if !authority.OK || authority.DBSourcePolicyRevision != h.source || authority.DBProjectionRevision != h.projection || authority.DBExecutorPolicyRevision != h.executor || !frozen {
			t.Fatal("actual final CP authority differs from the independent revision tuple or its original frozen configuration/policy projection")
		}
		h.writeSoftwareEvidence(t, orphan, fresh)
	})
}

func (h *softwareUpdateChainHarness) createSoftware(t *testing.T, key string) softwareUpdateChainJob {
	t.Helper()
	response := h.cp.call(t, stPortChainCommand{Command: "create", IdempotencyKey: key})
	job := softwareUpdateChainDecodeJob(t, response)
	if job.Status != "queued" || job.PolicyRevision != h.projection || job.OwnershipEpoch != 3 {
		t.Fatal("real CP did not create the software job from its current policy/ownership")
	}
	return job
}
func softwareUpdateChainDecodeJob(t *testing.T, response stPortChainResponse) softwareUpdateChainJob {
	t.Helper()
	var job softwareUpdateChainJob
	if !response.OK || json.Unmarshal(response.Job, &job) != nil || job.ID == "" || job.TargetID != "control-panel" {
		status := response.FailureHTTPStatus
		if status < 100 || status > 599 {
			status = 0
		}
		t.Logf("SOFTWARE CP job response: ok=%t phase=%s http_status=%d code=%s source=%d projection=%d executor=%d", response.OK, softwareUpdateChainSafeCode(response.ErrorCode), status, softwareUpdateChainSafeCreateCode(response.FailureCode), softwareUpdateChainSafeCount(response.DBSourcePolicyRevision), softwareUpdateChainSafeCount(response.DBProjectionRevision), softwareUpdateChainSafeCount(response.DBExecutorPolicyRevision))
		t.Fatal("independent actual CP software job observation failed")
	}
	// Keep authority diagnostics usable in failed CI without exposing job bodies,
	// identity YAML, lease tokens, arbitrary server messages or artifact URLs.
	t.Logf("SOFTWARE central job: status=%s code=%s P=%d F=%d generation=%d sequence=%d progress=%d artifact_present=%t", softwareUpdateChainSafeStatus(job.Status), softwareUpdateChainSafeCode(job.Code), softwareUpdateChainSafeCount(job.PolicyRevision), softwareUpdateChainSafeCount(job.OwnershipEpoch), softwareUpdateChainSafeGeneration(job.LeaseGeneration), softwareUpdateChainSafeCount(job.Sequence), softwareUpdateChainSafeCount(int64(job.Progress)), job.ArtifactDigest != "")
	return job
}

// Mirror only immutable CP create/eligibility codes, never server text or its
// target body. Unknown transport/authentication or future codes stay closed.
func softwareUpdateChainSafeCreateCode(code string) string {
	switch code {
	case "system_update_port_contract_required", "idempotency_key_conflict", "system_update_port_idempotency_conflict", "system_update_target_unavailable", "system_update_target_busy", "system_update_target_active", "system_update_ownership_conflict":
		return code
	case "updater_missing", "updater_policy_failed", "updater_policy_pending", "updater_policy_mismatch", "updater_policy_target_type_mismatch", "updater_offline", "target_unreachable", "target_reachability_unknown", "unsupported_deployment_mode", "current_version_unknown":
		return code
	case "release_manifest_unavailable", "release_version_invalid", "update_not_available", "release_manifest_missing", "release_manifest_invalid", "manifest_unverified", "updater_version_incompatible":
		return code
	default:
		return "unknown"
	}
}
func (h *softwareUpdateChainHarness) readSoftware(t *testing.T, id string) softwareUpdateChainJob {
	t.Helper()
	return softwareUpdateChainDecodeJob(t, h.cp.call(t, stPortChainCommand{Command: "observe", JobID: id}))
}
func softwareUpdateChainDecodeWire(t *testing.T, response stPortChainResponse) softwareUpdateChainWire {
	t.Helper()
	var wire softwareUpdateChainWire
	if !response.OK || json.Unmarshal(response.SoftwareWire, &wire) != nil {
		t.Fatal("producer-authored software wire observation unavailable")
	}
	t.Logf("SOFTWARE producer wire: claim_C=%d expected_C=%d progress_C=%d progress_count=%d grant_C=%d grant_P=%d grant_count=%d terminal_C=%d terminal_status=%s expiry_store_rejections=%d", softwareUpdateChainSafeCount(wire.ClaimConfig), softwareUpdateChainSafeCount(wire.ExpectedConfig), softwareUpdateChainSafeCount(wire.ProgressConfig), softwareUpdateChainSafeCount(int64(wire.ProgressCount)), softwareUpdateChainSafeCount(wire.GrantConfig), softwareUpdateChainSafeCount(wire.GrantPolicy), softwareUpdateChainSafeCount(int64(wire.GrantCount)), softwareUpdateChainSafeCount(wire.TerminalConfig), softwareUpdateChainSafeStatus(wire.TerminalStatus), softwareUpdateChainSafeCount(int64(wire.ExpiredGrantStoreRejections)))
	return wire
}
func (h *softwareUpdateChainHarness) requireDownloads(t *testing.T, agent, root int) {
	t.Helper()
	var counts struct {
		Agent   int `json:"agent_downloads"`
		Root    int `json:"root_downloads"`
		Unknown int `json:"unknown_downloads"`
	}
	response := h.provider.call(t, stPortChainCommand{Command: "metrics"})
	decoded := json.Unmarshal(response.SoftwareWire, &counts) == nil
	t.Logf("SOFTWARE archive downloads: decoded=%t Agent=%d root=%d unknown=%d expected_Agent=%d expected_root=%d", decoded, softwareUpdateChainSafeCount(int64(counts.Agent)), softwareUpdateChainSafeCount(int64(counts.Root)), softwareUpdateChainSafeCount(int64(counts.Unknown)), softwareUpdateChainSafeCount(int64(agent)), softwareUpdateChainSafeCount(int64(root)))
	if !response.OK || !decoded || counts.Agent != agent || counts.Root != root || counts.Unknown != 0 {
		t.Fatal("kernel-attributed real Agent/root archive downloads differ from the required no-mutation or one-apply boundary")
	}
}

func softwareUpdateChainSafeCount(value int64) int64 {
	if value < 0 || value > 1000000 {
		return -1
	}
	return value
}
func softwareUpdateChainSafeGeneration(value uint64) uint64 {
	if value > 1000000 {
		return 0
	}
	return value
}
func softwareUpdateChainSafeStatus(value string) string {
	switch value {
	case "queued", "claimed", "downloading", "verifying", "staging", "stopping", "installing", "starting", "health_checking", "rolling_back", "reconciling", "succeeded", "failed", "rolled_back", "canceled":
		return value
	default:
		return "unknown"
	}
}
func softwareUpdateChainSafeCode(value string) string {
	switch value {
	case "":
		return "none"
	case "execution_failed", "system_update_not_cancellable", "host_lifecycle_busy":
		return value
	case "software_profile_policy_unavailable", "software_profile_projection_unavailable", "software_profile_digest_mismatch", "software_profile_identity_unavailable", "software_profile_token_unavailable":
		return value
	case "software_observer_policy_unavailable", "software_observer_owner_unavailable", "software_observer_binding_mismatch", "software_observer_projection_mismatch", "create_rejected":
		return value
	case "software_setup_config", "software_setup_database", "software_setup_authority", "software_setup_policy_read", "software_setup_ownership_read", "software_setup_policy_cas", "software_setup_binding_read", "software_setup_revision_check", "software_setup_restart_check", "software_setup_existing_job", "software_setup_tls", "software_setup_listener", "software_setup_login":
		return value
	default:
		return "other"
	}
}
func (h *softwareUpdateChainHarness) requireUnchangedBaseline(t *testing.T) {
	t.Helper()
	stPortChainSameBytes(t, localExecutorPortPolicyPath, h.initialPolicy)
	current, err := filepath.EvalSymlinks("/opt/autostream/control-panel/current")
	if err != nil || current != h.baselineRelease || verifyManagedReleaseChecksums(current) != nil {
		t.Fatal("orphan/pre-install phase changed the checked baseline application")
	}
}
func softwareUpdateChainRunInstallerHook(t *testing.T, h *softwareUpdateChainHarness) {
	t.Helper()
	hook := os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_INSTALLER_HOOK")
	if !filepath.IsAbs(hook) {
		t.Fatal("normal installer order hook is required")
	}
	ctx, cancel := context.WithTimeout(h.ctx, 5*time.Minute)
	defer cancel()
	log, err := os.OpenFile(filepath.Join(h.evidence, "processes", "normal-installer-upgrade.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal("exclusive private installer output unavailable")
	}
	defer log.Close()
	command := exec.CommandContext(ctx, "/bin/bash", hook, "/opt/software-input/repository", "/opt/software-input/before-production", "b1c94afe2ee2fe8854abb12e2c85565a1bd448dc", "/opt/software-input/candidate-production", os.Getenv("AUTOSTREAM_ST_PORT_UPDATER_SHA"), filepath.Join(h.evidence, "installer"))
	command.Stdout, command.Stderr = log, log
	if command.Run() != nil {
		t.Fatal("normal matched-pair installer upgrade failed; private evidence retains the original failure")
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/systemctl", "stop", "autostream-host-agent.service", "autostream-local-executor.service", "autostream-local-executor.socket").Run()
	})
}
func (h *softwareUpdateChainHarness) writeSoftwareEvidence(t *testing.T, orphan, fresh softwareUpdateChainJob) {
	t.Helper()
	evidence := map[string]any{"schema_version": 1, "control_panel_sha": os.Getenv("AUTOSTREAM_ST_PORT_CONTROL_PANEL_SHA"), "updater_sha": os.Getenv("AUTOSTREAM_ST_PORT_UPDATER_SHA"), "before_updater_sha": "b1c94afe2ee2fe8854abb12e2c85565a1bd448dc", "config_revision": 1, "source_policy_revision": h.source, "projection_revision": h.projection, "executor_policy_revision": h.executor, "ownership_epoch": 3, "old_claim": orphan, "accepted_software_job": fresh, "old_root_inspection": "rejected", "normal_installer": "actual_upgrade", "orphan_download_stage_apply": 0, "agent_archive_downloads": h.agentDownloads, "root_archive_downloads": h.rootDownloads, "target_application": "synthetic_checked_fixture", "executed_arch": "amd64", "boundaries": h.boundaries, "expiry_proof": "existing_adapter_and_store_clock_arguments; no_wall_clock_or_persisted_expiry_change", "apply_response_loss_recovery": "real_root_result_preserved_then_restart_and_reconcile"}
	body, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(h.evidence, "artifacts", "software-full-chain.json"), append(body, '\n'), 0o600) != nil {
		t.Fatal("persist bounded software chain evidence")
	}
}
