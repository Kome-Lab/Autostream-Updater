//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	// The installed runtime pair is shared by all remaining recovery subtests.
	// Stop it only when this outer full-chain test and its children complete.
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/systemctl", "stop", "autostream-host-agent.service", "autostream-local-executor.service", "autostream-local-executor.socket").Run()
	})
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
		h.waitClaimRecoveryServices(t)
		recovery := h.start(t, "recovery", h.testBinary, "TestSoftwareUpdateFullChainRecoveryProcess", h.uid, h.gid)
		defer recovery.stop()
		response := recovery.call(t, stPortChainCommand{Command: "recover", JobID: orphan.ID, LeaseGeneration: 1})
		settled := h.readSoftware(t, orphan.ID)
		calls := softwareUpdateChainDecodeCalls(t, response)
		softwareUpdateChainLogRecoveryInspection(t, response)
		if !response.OK || response.RootCalls != 0 || response.ActiveJobID != "" || response.ActivePlanPresent || calls.Stage != 0 || calls.Apply != 0 || calls.Reconcile != 0 || calls.Inspections < 1 || calls.StageRequiredResponse || settled.ID != orphan.ID || settled.Status != "failed" || settled.Code != "execution_failed" || settled.LeaseGeneration != 2 || settled.PolicyRevision != h.projection || settled.OwnershipEpoch != 3 {
			softwareUpdateChainLogAuxiliaryRootInspection(t, h, SoftwareClaimRecoveryRequest{JobID: orphan.ID, LeaseGeneration: 1, TargetID: "control-panel", CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ConfigRevision: 1, OwnershipEpoch: 3})
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
	if runErr := command.Run(); runErr != nil {
		softwareUpdateChainLogInstallerFailure(t, runErr, ctx.Err() == context.DeadlineExceeded)
		t.Fatal("normal matched-pair installer upgrade failed; private evidence retains the original failure")
	}
}
func softwareUpdateChainLogInstallerFailure(t *testing.T, runErr error, timedOut bool) {
	t.Helper()
	commandExit := "unknown"
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && exitErr.ExitCode() >= 0 && exitErr.ExitCode() <= 255 {
		commandExit = strconv.Itoa(exitErr.ExitCode())
	}
	var diagnostic struct {
		SchemaVersion            int    `json:"schema_version"`
		Phase                    string `json:"phase"`
		Exited                   *bool  `json:"exited"`
		ExitCode                 *int   `json:"exit_code"`
		GetfaclPresent           *bool  `json:"getfacl_present"`
		SetfaclPresent           *bool  `json:"setfacl_present"`
		OtherDependenciesPresent *bool  `json:"other_dependencies_present"`
		SourceInventoryMatched   *bool  `json:"source_inventory_matched"`
		SourceInventoryCount     *int   `json:"source_inventory_count"`
	}
	valid := false
	const statusPath = "/evidence/artifacts/normal-installer-status.json"
	info, statErr := os.Lstat(statusPath)
	if statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Size() > 0 && info.Size() <= 4096 {
		if file, openErr := os.Open(statusPath); openErr == nil {
			opened, openedErr := file.Stat()
			body, readErr := io.ReadAll(io.LimitReader(file, 4097))
			_ = file.Close()
			if openedErr == nil && os.SameFile(info, opened) && readErr == nil && len(body) <= 4096 {
				decoder := json.NewDecoder(bytes.NewReader(body))
				decoder.DisallowUnknownFields()
				if decoder.Decode(&diagnostic) == nil {
					var trailing any
					valid = errors.Is(decoder.Decode(&trailing), io.EOF) && diagnostic.SchemaVersion == 1 &&
						diagnostic.Exited != nil &&
						((!*diagnostic.Exited && diagnostic.ExitCode == nil) ||
							(*diagnostic.Exited && diagnostic.ExitCode != nil && *diagnostic.ExitCode >= 0 && *diagnostic.ExitCode <= 255)) &&
						diagnostic.GetfaclPresent != nil && diagnostic.SetfaclPresent != nil && diagnostic.OtherDependenciesPresent != nil &&
						diagnostic.SourceInventoryMatched != nil && diagnostic.SourceInventoryCount != nil &&
						*diagnostic.SourceInventoryCount >= 0 && *diagnostic.SourceInventoryCount <= 64 &&
						(!*diagnostic.SourceInventoryMatched || *diagnostic.SourceInventoryCount == 37)
				}
			}
		}
	}
	switch diagnostic.Phase {
	case "input_validation", "protected_inputs", "ordinary_dependencies", "binary_pair", "compatibility_floor", "fixture_archive", "legacy_pair_install", "legacy_pair_start", "legacy_pair_probe", "normal_upgrade", "candidate_pair_verify", "identity_policy_preservation", "terminal_state_verify", "agent_stop", "result_record", "complete":
	default:
		valid = false
	}
	if !valid {
		t.Logf("SOFTWARE installer boundary: diagnostic_valid=false command_exit=%s timeout=%t", commandExit, timedOut)
		return
	}
	recordedExit := "unknown"
	if diagnostic.ExitCode != nil {
		recordedExit = strconv.Itoa(*diagnostic.ExitCode)
	}
	t.Logf("SOFTWARE installer boundary: diagnostic_valid=true phase=%s exited=%t exit=%s command_exit=%s timeout=%t getfacl_present=%t setfacl_present=%t other_dependencies_present=%t source_inventory_matched=%t source_inventory_count=%d", diagnostic.Phase, *diagnostic.Exited, recordedExit, commandExit, timedOut, *diagnostic.GetfaclPresent, *diagnostic.SetfaclPresent, *diagnostic.OtherDependenciesPresent, *diagnostic.SourceInventoryMatched, *diagnostic.SourceInventoryCount)
}
func (h *softwareUpdateChainHarness) writeSoftwareEvidence(t *testing.T, orphan, fresh softwareUpdateChainJob) {
	t.Helper()
	evidence := map[string]any{"schema_version": 1, "control_panel_sha": os.Getenv("AUTOSTREAM_ST_PORT_CONTROL_PANEL_SHA"), "updater_sha": os.Getenv("AUTOSTREAM_ST_PORT_UPDATER_SHA"), "before_updater_sha": "b1c94afe2ee2fe8854abb12e2c85565a1bd448dc", "config_revision": 1, "source_policy_revision": h.source, "projection_revision": h.projection, "executor_policy_revision": h.executor, "ownership_epoch": 3, "old_claim": orphan, "accepted_software_job": fresh, "old_root_inspection": "rejected", "normal_installer": "actual_upgrade", "orphan_download_stage_apply": 0, "agent_archive_downloads": h.agentDownloads, "root_archive_downloads": h.rootDownloads, "target_application": "synthetic_checked_fixture", "executed_arch": "amd64", "boundaries": h.boundaries, "expiry_proof": "existing_adapter_and_store_clock_arguments; no_wall_clock_or_persisted_expiry_change", "apply_response_loss_recovery": "real_root_result_preserved_then_restart_and_reconcile"}
	body, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(h.evidence, "artifacts", "software-full-chain.json"), append(body, '\n'), 0o600) != nil {
		t.Fatal("persist bounded software chain evidence")
	}
}

func softwareUpdateChainLogRecoveryInspection(t *testing.T, response stPortChainResponse) {
	t.Helper()
	var wire struct {
		InspectionDiagnostic *softwareUpdateChainInspectionDiagnostic `json:"inspection_diagnostic"`
	}
	if json.Unmarshal(response.SoftwareWire, &wire) != nil || wire.InspectionDiagnostic == nil {
		t.Log("SOFTWARE recovery inspection: diagnostic_present=false")
		return
	}
	d := *wire.InspectionDiagnostic
	code := "transport_other"
	if d.ErrorCode == "none" || validLocalExecutorFailureCode(d.ErrorCode) {
		code = d.ErrorCode
	}
	class := "other"
	switch d.OperationClass {
	case "none", "deadline", "canceled", "agent_proof_binding", "root_response":
		class = d.OperationClass
	}
	policyCode := "other"
	switch d.PolicyErrorCode {
	case "none", "policy_authentication", "host_authentication", "policy_binding":
		policyCode = d.PolicyErrorCode
	}
	t.Logf("SOFTWARE recovery inspection: diagnostic_present=true code=%s operation_class=%s proof_returned=%t policy_observed=%t policy_code=%s policy_matches_fence=%t", code, class, d.ProofReturned, d.PolicyObserved, policyCode, d.PolicyMatchesFence)
	t.Logf("SOFTWARE recovery proof checks: valid=%t request=%t updater=%t host=%t source=%t projection=%t executor=%t digest=%t epoch=%t runtime_matches_agent=%t current_version_matches_build=%t observed_not_future=%t observed_fresh=%t", d.ProofValid, d.RequestMatches, d.UpdaterMatches, d.HostMatches, d.SourceMatches, d.ProjectionMatches, d.ExecutorMatches, d.DigestMatches, d.EpochMatches, d.RuntimeMatchesAgent, d.CurrentVersionMatchesBuild, d.ObservedNotFuture, d.ObservedFresh)
}

// This failure-only observation runs in the parent fixture's process namespace,
// outside the installed Executor unit's sandbox. It cannot replace the real UDS
// proof or any assertion above, and uses only the same fixed read-only runtime.
func softwareUpdateChainLogAuxiliaryRootInspection(t *testing.T, h *softwareUpdateChainHarness, exact SoftwareClaimRecoveryRequest) {
	t.Helper()
	policy, err := LoadLocalExecutorPolicy(DefaultLocalExecutorPolicyPath, true)
	if err != nil {
		t.Log("SOFTWARE auxiliary root inspection: outside_actual_unit=true phase=root_policy_load proof_returned=false")
		return
	}
	digest, digestErr := h.rootPolicy.SHA256()
	canonicalDigest, canonicalErr := policy.SHA256()
	if digestErr != nil || canonicalErr != nil || canonicalDigest != digest {
		t.Log("SOFTWARE auxiliary root inspection: outside_actual_unit=true phase=root_policy_digest proof_returned=false")
		return
	}
	request := LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: localExecutorSoftwareClaimRecoveryOperation,
		ServiceID: exact.TargetID, SoftwareClaimRecovery: &SoftwareClaimRecoveryInspection{Request: exact, ExecutorPolicySHA256: digest},
		SourcePolicyRevision: h.source, OwnershipEpoch: exact.OwnershipEpoch,
		OwnershipPolicyRevision: h.projection, ExecutorPolicyRevision: h.executor,
	}
	runtime := defaultSoftwareClaimRecoveryRootRuntime(nil)
	unlock, err := runtime.acquireLifecycle()
	if err != nil {
		t.Log("SOFTWARE auxiliary root inspection: outside_actual_unit=true phase=lifecycle_lock proof_returned=false")
		return
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(h.ctx, localExecutorHostSelfUpdateTimeout)
	defer cancel()
	proof, err := inspectSoftwareClaimRecoveryRoot(ctx, policy, request, runtime)
	t.Logf("SOFTWARE auxiliary root inspection: outside_actual_unit=true phase=%s proof_returned=%t proof_valid=%t", softwareUpdateChainAuxiliaryRootPhase(err), err == nil, err == nil && proof.Validate() == nil)
}

func softwareUpdateChainAuxiliaryRootPhase(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	// Exact source literals only: unknown errors keep their classification and
	// never expose raw errors, filenames, state bytes, IDs or credentials.
	switch err.Error() {
	case "software claim recovery root policy fence is invalid":
		return "policy_fence"
	case "software claim recovery root policy digest changed":
		return "policy_digest"
	case "software claim recovery canonical root policy changed":
		return "canonical_policy"
	case "software claim recovery root target config binding is invalid":
		return "target_config"
	case "software claim recovery authenticated policy disagrees with root policy", "canonical recovery policy identity is unavailable", "authenticated root recovery policy is unavailable":
		return "authenticated_policy"
	case "software claim recovery ownership fence is invalid":
		return "ownership"
	case "software claim recovery root target differs from authenticated target":
		return "target_snapshot"
	case "Local Executor state root is unsafe", "Host Agent state root is unsafe", "Host Agent state root owner is invalid":
		return "state_roots"
	case "software claim recovery durable intent disagrees with the request", "software claim recovery cannot replace an unsettled or legacy root intent", "software claim recovery previous intent no longer matches current policy", "software claim recovery immutable archive has another identity or policy":
		return "durable_intent"
	case "software claim recovery journal contains execution or pending report state", "software claim recovery journal has another or an executing cursor", "Host Agent journal is unsafe", "Host Agent journal owner is invalid", "Host Agent journal changed during secure open", "decode Host Agent journal", "Host Agent journal contains trailing data":
		return "journal"
	case "software claim recovery is blocked by other durable lifecycle state":
		return "lifecycle_state"
	case "software claim recovery is blocked by runtime credential state":
		return "runtime_credential"
	case "an existing Host self-update grant blocks manual runtime upgrade; wait for the healthy-slot Local Executor to converge it":
		return "self_update_grant"
	case "software claim recovery requires a stable matched installed runtime":
		return "runtime_state"
	case "software claim recovery runtime slot changed":
		return "runtime_slot"
	case "software claim recovery Agent service is not safely active or stopped":
		return "agent_service"
	case "software claim recovery installed runtime pair is unconfirmed":
		return "runtime_pair"
	case "software claim recovery legacy authority is unsafe", "software claim recovery cannot discard a requested-job checkpoint, including a terminal checkpoint", "software claim recovery requested job has a root port record", "software claim recovery cannot discard a requested-job or non-terminal root mutation record", "software claim recovery has unconfirmed root execution residue", "software claim recovery has an orphan or unsafe root stage":
		return "root_records"
	}
	for _, unit := range manualHostRecoveryUnitInstances {
		if err.Error() == unit+" must be inactive and have no MainPID" || err.Error() == "read "+unit+" active state" || err.Error() == "read "+unit+" MainPID" || err.Error() == unit+" MainPID is invalid" {
			return "recovery_service"
		}
	}
	return "unknown"
}
