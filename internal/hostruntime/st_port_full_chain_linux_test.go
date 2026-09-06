//go:build linux

package hostruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

// The ten fixed children are the finite B1-B8 set. This suite is intentionally
// opt-in and runs in the existing privileged CI lane, never on a developer's
// installed runtime. Missing prerequisites fail the selected suite.
func TestSTPortFullChain(t *testing.T) {
	h := newSTPortChainHarness(t)
	t.Run("B1_local_only", func(t *testing.T) {
		before := h.current(t)
		beforePID := h.workerPID(t)
		beforePolicy, beforeSidecar := h.runtimeBytes(t)
		job := h.create(t, "B1-local", "local_only", 18085, 0)
		accepted := h.complete(t, job, contracts.SystemUpdatePortReconfigurationApplied)
		after := h.current(t)
		if after.Snapshot.AdvertisedPort != before.Snapshot.AdvertisedPort || after.Snapshot.LocalListenPort == before.Snapshot.LocalListenPort {
			t.Fatal("local-only conflated advertised and local endpoints")
		}
		afterPolicy, afterSidecar := h.runtimeBytes(t)
		if beforePID == h.workerPID(t) || bytes.Equal(beforePolicy, afterPolicy) || bytes.Equal(beforeSidecar, afterSidecar) {
			t.Fatal("positive change control did not mutate the actual policy/listener/runtime")
		}
		h.captureWeb(t, "B1_local_only", accepted)
	})
	t.Run("B1_local_and_advertised", func(t *testing.T) {
		job := h.create(t, "B1-combined", "local_and_advertised", 18086, 8443)
		h.complete(t, job, contracts.SystemUpdatePortReconfigurationApplied)
		after := h.current(t)
		if after.Snapshot.AdvertisedPort != 8443 || after.Snapshot.LocalListenPort != 18086 {
			t.Fatal("combined endpoints lost their distinct values")
		}
	})
	t.Run("B2_unchanged", func(t *testing.T) {
		before := h.current(t)
		policy, sidecar := h.runtimeBytes(t)
		policyInfo := stPortChainFileInfo(t, localExecutorPortPolicyPath)
		sidecarInfo := stPortChainFileInfo(t, "/opt/autostream/local-executor/ports/worker.json")
		pid := h.workerPID(t)
		job := h.create(t, "B2-unchanged", "local_and_advertised", before.Snapshot.LocalListenPort, before.Snapshot.AdvertisedPort)
		accepted := h.complete(t, job, contracts.SystemUpdatePortReconfigurationUnchanged)
		after := h.current(t)
		stPortChainSameBytes(t, localExecutorPortPolicyPath, policy)
		stPortChainSameBytes(t, "/opt/autostream/local-executor/ports/worker.json", sidecar)
		policyAfter := stPortChainFileInfo(t, localExecutorPortPolicyPath)
		sidecarAfter := stPortChainFileInfo(t, "/opt/autostream/local-executor/ports/worker.json")
		if !os.SameFile(policyInfo, policyAfter) || !os.SameFile(sidecarInfo, sidecarAfter) || h.workerPID(t) != pid || before.Reservations != after.Reservations || !reflect.DeepEqual(before.Snapshot, after.Snapshot) {
			t.Fatal("fresh-B unchanged mutated policy/listener/process/reservation")
		}
		h.captureWeb(t, "B2_unchanged", accepted)
	})
	t.Run("B3_rolled_back", func(t *testing.T) {
		job := h.create(t, "B3-rollback", "local_and_advertised", 18087, 9443)
		h.runtimeFault(t, "exact", job.PortReconfigure.Target.ConfigRevision)
		defer h.clearRuntimeFault(t)
		accepted := h.complete(t, job, contracts.SystemUpdatePortReconfigurationRolledBack)
		if accepted.PortResult.ObservedConfigRevision != job.PortReconfigure.Before.ConfigRevision+2 || accepted.PortResult.ObservedExecutorPolicyRevision != job.PortReconfigure.Before.ExecutorPolicyRevision+2 {
			t.Fatal("rollback reused old revision bytes")
		}
		h.captureWeb(t, "B3_rolled_back", accepted)
		h.writeWebArtifact(t)
	})
	t.Run("B4_recovery_after_rollback_failed", func(t *testing.T) {
		job := h.create(t, "B4-recovery", "local_and_advertised", 18088, 10443)
		h.runtimeFault(t, "at_or_after", job.PortReconfigure.Target.ConfigRevision)
		defer h.clearRuntimeFault(t)
		_ = h.agent.call(t, stPortChainCommand{Command: "poll"})
		failed := h.job(t, job.ID)
		if !failed.RecoveryRequired || failed.PortResult != nil {
			t.Fatal("failed rollback filled accepted slot or released the hold")
		}
		root := h.rootLedger(t, job.ID)
		if root.Result != nil || root.PolicyTransition == nil || !root.PolicyTransition.RecoveryRequired || !root.PolicyTransition.RollbackLatched {
			t.Fatal("root lost durable same-job recovery hold")
		}
		policy, err := LoadLocalExecutorPolicy(localExecutorPortPolicyPath, true)
		if err != nil || policy.PolicyRevision != job.PortReconfigure.Rollback.ExecutorPolicyRevision {
			t.Fatal("R policy was not installed before R runtime recovery")
		}
		h.clearRuntimeFault(t)
		h.agent.stop()
		h.root.stop()
		h.root = h.start(t, "root", h.testBinary, "TestSTPortFullChainRuntimeProcess", 0, 0)
		h.waitRoot(t)
		h.agent = h.start(t, "agent", h.testBinary, "TestSTPortFullChainRuntimeProcess", h.uid, h.gid)
		accepted := h.complete(t, job, contracts.SystemUpdatePortReconfigurationRolledBack)
		if accepted.LeaseGeneration <= failed.LeaseGeneration {
			t.Fatal("same-job recovery reused the old lease")
		}
		for _, command := range []string{"replay_last_failure", "replay_old_applied"} {
			replay := h.cp.call(t, stPortChainCommand{Command: command, JobID: job.ID})
			if !replay.OK || !stPortChainSameResult(accepted.PortResult, h.job(t, job.ID).PortResult) {
				t.Fatal("late old observation replaced accepted R")
			}
		}
	})
	for _, item := range []struct {
		name, fault, key string
		port             int
	}{
		{"B5_create_before_acceptance_loss", "create_before", "B5-before", 18089},
		{"B5_create_after_commit_loss", "create_after", "B5-after", 18090},
	} {
		t.Run(item.name, func(t *testing.T) {
			before := h.current(t)
			h.arm(t, item.fault)
			lost := h.cp.call(t, stPortChainCommand{Command: "create", Mode: "local_only", LocalPort: item.port, IdempotencyKey: item.key})
			if lost.OK {
				t.Fatal("create response-loss fixture did not lose the response")
			}
			lookup := h.cp.call(t, stPortChainCommand{Command: "lookup", IdempotencyKey: item.key})
			if item.fault == "create_before" && len(lookup.Job) != 0 && string(lookup.Job) != "null" {
				t.Fatal("pre-acceptance loss created a job")
			}
			retry := h.cp.call(t, stPortChainCommand{Command: "retry_create", IdempotencyKey: item.key})
			job := stPortChainDecodeJob(t, retry)
			if item.fault == "create_after" && stPortChainDecodeJob(t, lookup).ID != job.ID {
				t.Fatal("same-key reconciliation created a replacement job")
			}
			after := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
			if after.JobsCount != before.JobsCount+1 {
				t.Fatal("same-key acceptance reconciliation duplicated the job")
			}
			repeated := stPortChainDecodeJob(t, h.cp.call(t, stPortChainCommand{Command: "retry_create", IdempotencyKey: item.key}))
			if repeated.ID != job.ID {
				t.Fatal("repeated immutable request changed its job")
			}
			stable := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
			if stable.JobsCount != after.JobsCount || stable.Reservations != after.Reservations {
				t.Fatal("same-key resend duplicated reservations")
			}
			h.complete(t, job, contracts.SystemUpdatePortReconfigurationApplied)
		})
	}
	t.Run("B6_consume_after_commit_loss", func(t *testing.T) {
		job := h.create(t, "B6-consume", "local_only", 18091, 0)
		before := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		h.arm(t, "consume_after")
		ended := make(chan struct{})
		go func() { _, _ = h.agent.exchange(stPortChainCommand{Command: "poll"}); close(ended) }()
		stPortChainWait(t, 60*time.Second, func() bool {
			observed := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
			return observed.ConsumeCount > before.ConsumeCount && observed.DroppedCount > before.DroppedCount && observed.ConsumePhase == "response_dropped" && observed.ConsumeJobID == job.ID
		})
		policy, err := LoadLocalExecutorPolicy(localExecutorPortPolicyPath, true)
		if err != nil || policy.PolicyRevision != job.PortReconfigure.Before.ExecutorPolicyRevision {
			t.Fatal("lost 204 did not retain root B")
		}
		// This is actual elapsed time in the selected CI suite. The restart may
		// not reconstruct a fresh first-write window for a new forward attempt.
		timer := time.NewTimer(31 * time.Second)
		select {
		case <-timer.C:
		case <-h.ctx.Done():
			timer.Stop()
			t.Fatal("full-chain deadline expired")
		}
		h.agent.stop()
		h.root.stop()
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			t.Fatal("interrupted consume transport did not end")
		}
		if !h.cp.call(t, stPortChainCommand{Command: "release"}).OK {
			t.Fatal("release interrupted grant transport")
		}
		cp := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		stillUnaccepted := h.job(t, job.ID)
		policy, err = LoadLocalExecutorPolicy(localExecutorPortPolicyPath, true)
		if err != nil || policy.PolicyRevision != job.PortReconfigure.Before.ExecutorPolicyRevision || !cp.OK || cp.DBSourcePolicyRevision != job.PortReconfigure.Target.SourcePolicyRevision || cp.DBProjectionRevision != job.PortReconfigure.Target.ProjectionRevision || cp.DBExecutorPolicyRevision != job.PortReconfigure.Target.ExecutorPolicyRevision || stillUnaccepted.PolicyRevision != job.PortReconfigure.Before.ProjectionRevision || stillUnaccepted.PortResult != nil {
			t.Fatal("lost consume response did not retain committed CP T and original JP")
		}
		h.root = h.start(t, "root", h.testBinary, "TestSTPortFullChainRuntimeProcess", 0, 0)
		h.waitRoot(t)
		h.agent = h.start(t, "agent", h.testBinary, "TestSTPortFullChainRuntimeProcess", h.uid, h.gid)
		accepted := h.complete(t, job, contracts.SystemUpdatePortReconfigurationRolledBack)
		if h.current(t).Snapshot.SourcePolicyRevision != job.PortReconfigure.Before.SourcePolicyRevision+2 || accepted.PolicyRevision != job.PortReconfigure.Before.ProjectionRevision {
			t.Fatal("reconcile reapplied T or rebound JP")
		}
	})
	t.Run("B7_terminal_response_loss_same_process", func(t *testing.T) {
		job := h.create(t, "B7-terminal", "local_only", 18092, 0)
		h.arm(t, "terminal_after")
		first := h.agent.call(t, stPortChainCommand{Command: "poll"})
		if first.OK {
			t.Fatal("committed terminal response was not dropped")
		}
		accepted := h.job(t, job.ID)
		if accepted.PortResult == nil || !stPortChainSameResult(first.ActiveResult, accepted.PortResult) {
			t.Fatal("DB commit and durable Agent observation differ")
		}
		before := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		pid := h.workerPID(t)
		policy, sidecar := h.runtimeBytes(t)
		retried := h.agent.call(t, stPortChainCommand{Command: "flush"})
		after := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		if !retried.OK || retried.RootCalls != first.RootCalls || before.ClaimCount != after.ClaimCount || before.ConsumeCount != after.ConsumeCount || !stPortChainSameResult(accepted.PortResult, h.job(t, job.ID).PortResult) || before.TerminalBodySHA256 == "" || before.TerminalBodySHA256 != after.LastTerminalBodySHA256 {
			t.Fatal("same-process retry changed result or invoked root/claim/consume")
		}
		if h.workerPID(t) != pid {
			t.Fatal("terminal transport retry restarted runtime")
		}
		stPortChainSameBytes(t, localExecutorPortPolicyPath, policy)
		stPortChainSameBytes(t, "/opt/autostream/local-executor/ports/worker.json", sidecar)
		if !h.agent.call(t, stPortChainCommand{Command: "poll"}).OK {
			t.Fatal("accepted terminal proof did not clear the active cursor")
		}
	})
	t.Run("B8_restart_fresh_lease", func(t *testing.T) {
		job := h.create(t, "B8-restart", "local_only", 18093, 0)
		h.arm(t, "c11_before_commit")
		ended := make(chan struct{})
		go func() { _, _ = h.agent.exchange(stPortChainCommand{Command: "poll"}); close(ended) }()
		firstEnvelopeSHA256 := ""
		stPortChainWait(t, 90*time.Second, func() bool {
			response := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
			if response.C11Phase == "before_commit" && response.C11JobID == job.ID && response.C11BodySHA256 != "" {
				firstEnvelopeSHA256 = response.C11BodySHA256
				return true
			}
			return false
		})
		root := h.rootLedger(t, job.ID)
		if root.Result == nil || root.Result.PortResult == nil {
			t.Fatal("root has no durable immutable result at the stop point")
		}
		firstObservation := clonePortResult(root.Result.PortResult)
		firstObservation.Observation.AgentProjectionVerified = true
		h.kill(t, h.cp)
		h.kill(t, h.agent)
		h.kill(t, h.root)
		select {
		case <-ended:
		case <-time.After(10 * time.Second):
			t.Fatal("interrupted Agent transport did not end")
		}
		h.cp = h.start(t, "cp", h.cpBinary, "TestSTPortFullChainControlPanelProcess", 0, 0)
		if !h.cp.call(t, stPortChainCommand{Command: "init"}).OK {
			t.Fatal("CP restart could not reopen its existing database")
		}
		// Read through a new CP process and database connection only after the
		// interrupted transaction has rolled back. The private stop observation
		// above deliberately does not stand in for committed database evidence.
		uncommitted := h.job(t, job.ID)
		if uncommitted.PortResult != nil {
			t.Fatal("precommit crash exposed a partial accepted result")
		}
		h.root = h.start(t, "root", h.testBinary, "TestSTPortFullChainRuntimeProcess", 0, 0)
		h.waitRoot(t)
		h.agent = h.start(t, "agent", h.testBinary, "TestSTPortFullChainRuntimeProcess", h.uid, h.gid)
		accepted := h.complete(t, job, contracts.SystemUpdatePortReconfigurationApplied)
		last := h.cp.call(t, stPortChainCommand{Command: "observe", JobID: job.ID})
		if accepted.LeaseGeneration <= uncommitted.LeaseGeneration || !stPortChainSameResult(firstObservation, accepted.PortResult) || accepted.PolicyRevision != job.PortReconfigure.Before.ProjectionRevision || last.TerminalBodySHA256 == "" || last.TerminalBodySHA256 == firstEnvelopeSHA256 {
			t.Fatal("restart reused transport state or changed the immutable first result")
		}
	})
}

func (h *stPortChainHarness) current(t *testing.T) stPortChainResponse {
	t.Helper()
	if observation := h.agent.call(t, stPortChainCommand{Command: "observe"}); !observation.OK || !observation.TargetVerified {
		t.Fatal("refresh real Agent baseline")
	}
	response := h.cp.call(t, stPortChainCommand{Command: "observe"})
	if !response.OK || response.Snapshot == nil {
		t.Fatal("read complete current CP snapshot")
	}
	return response
}

func (h *stPortChainHarness) create(t *testing.T, key, mode string, port, advertised int) stPortChainJob {
	t.Helper()
	_ = h.current(t)
	return stPortChainDecodeJob(t, h.cp.call(t, stPortChainCommand{Command: "create", Mode: mode, LocalPort: port, AdvertisedPort: advertised, IdempotencyKey: key}))
}

func stPortChainDecodeJob(t *testing.T, response stPortChainResponse) stPortChainJob {
	t.Helper()
	var job stPortChainJob
	if !response.OK || json.Unmarshal(response.Job, &job) != nil || job.ID == "" || job.PortReconfigure == nil || contracts.ValidateSystemUpdatePortPlan(*job.PortReconfigure) != nil {
		t.Fatal("real CP did not return a valid immutable port job")
	}
	return job
}

func (h *stPortChainHarness) job(t *testing.T, id string) stPortChainJob {
	t.Helper()
	return stPortChainDecodeJob(t, h.cp.call(t, stPortChainCommand{Command: "observe", JobID: id}))
}

func (h *stPortChainHarness) complete(t *testing.T, job stPortChainJob, kind contracts.SystemUpdatePortReconfigurationResult) stPortChainJob {
	t.Helper()
	response := h.agent.call(t, stPortChainCommand{Command: "poll"})
	if !response.OK {
		t.Fatal("real Agent execution did not complete")
	}
	accepted := h.job(t, job.ID)
	if accepted.PortResult == nil || accepted.PortResult.Result != kind || accepted.RecoveryRequired || contracts.ValidateSystemUpdatePortResult(*job.PortReconfigure, *accepted.PortResult) != nil {
		t.Fatal("typed root result did not survive CP database acceptance")
	}
	root := h.rootLedger(t, job.ID)
	if root.Result == nil || root.Result.PortResult == nil {
		t.Fatal("root ledger is missing its accepted result")
	}
	rootResult := clonePortResult(root.Result.PortResult)
	rootResult.Observation.AgentProjectionVerified = true
	if !stPortChainSameResult(rootResult, accepted.PortResult) {
		t.Fatal("CP changed the first root observation")
	}
	policy, err := LoadLocalExecutorPolicy(localExecutorPortPolicyPath, true)
	if err != nil {
		t.Fatal("load accepted installed root policy")
	}
	target, ok := policy.Target("worker-smoke")
	expected := job.PortReconfigure.Target
	if kind == contracts.SystemUpdatePortReconfigurationUnchanged {
		expected = job.PortReconfigure.Before
	}
	if kind == contracts.SystemUpdatePortReconfigurationRolledBack {
		expected = job.PortReconfigure.Rollback
	}
	if err != nil || !ok || !portPolicySnapshotMatches(policy, target, *expected) {
		t.Fatal("accepted DB result differs from the installed root policy")
	}
	if observation := h.agent.call(t, stPortChainCommand{Command: "observe"}); !observation.OK || !observation.TargetVerified {
		t.Fatal("accepted projection could not be re-observed through real IPC")
	}
	return accepted
}

func (h *stPortChainHarness) rootLedger(t *testing.T, jobID string) *systemdPortLedger {
	t.Helper()
	state, err := newFileSystemdPortStateStore(LocalExecutorMutationStateDir, true)
	if err != nil {
		t.Fatal("read root ledger store")
	}
	ledger, err := state.LoadActive("worker-smoke")
	if err != nil || ledger == nil || ledger.Plan.JobID != jobID {
		t.Fatal("read exact durable root job ledger")
	}
	return ledger
}

func (h *stPortChainHarness) runtimeBytes(t *testing.T) ([]byte, []byte) {
	t.Helper()
	policy, err := os.ReadFile(localExecutorPortPolicyPath)
	if err != nil {
		t.Fatal("read installed root policy")
	}
	sidecar, err := os.ReadFile("/opt/autostream/local-executor/ports/worker.json")
	if err != nil {
		t.Fatal("read installed listener projection")
	}
	return policy, sidecar
}

func (h *stPortChainHarness) workerPID(t *testing.T) int {
	t.Helper()
	output, err := exec.CommandContext(h.ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", "autostream-worker.service").Output()
	pid, parseErr := parsePositivePID(string(output))
	if err != nil || parseErr != nil {
		t.Fatal("read actual Worker process identity")
	}
	return pid
}

func (h *stPortChainHarness) runtimeFault(t *testing.T, mode string, revision int64) {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"mode": mode, "revision": revision})
	if mode != "exact" && mode != "at_or_after" || revision < 1 || os.WriteFile(filepath.Join(stPortChainRoot, "runtime-fault.json"), payload, 0o644) != nil {
		t.Fatal("arm isolated real-runtime start failure")
	}
}

func (h *stPortChainHarness) clearRuntimeFault(t *testing.T) {
	t.Helper()
	if err := os.Remove(filepath.Join(stPortChainRoot, "runtime-fault.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal("remove isolated runtime start failure")
	}
}

func (h *stPortChainHarness) arm(t *testing.T, fault string) {
	t.Helper()
	if !h.cp.call(t, stPortChainCommand{Command: "arm_fault", Fault: fault}).OK {
		t.Fatal("arm bounded private CP response fault")
	}
}

func (h *stPortChainHarness) kill(t *testing.T, process *stPortChainProcess) {
	t.Helper()
	if process == nil || process.command == nil || process.command.Process.Signal(syscall.SIGKILL) != nil {
		t.Fatal("stop process at the observed crash boundary")
	}
	select {
	case <-process.done:
	case <-time.After(10 * time.Second):
		t.Fatal("process did not stop at crash boundary")
	}
	_ = process.in.Close()
	_ = process.out.Close()
	process.command = nil
}

type stPortChainWebCase struct {
	ScenarioID    string          `json:"scenario_id"`
	JobID         string          `json:"job_id"`
	Result        string          `json:"result"`
	SystemUpdates json.RawMessage `json:"system_updates"`
}

func (h *stPortChainHarness) captureWeb(t *testing.T, scenario string, job stPortChainJob) {
	t.Helper()
	response := h.cp.call(t, stPortChainCommand{Command: "get", JobID: job.ID})
	var value any
	if !response.OK || json.Unmarshal(response.SystemUpdates, &value) != nil || stPortChainContainsSecretKey(value) {
		t.Fatal("credential-free real GET projection is unavailable")
	}
	if !bytes.Contains(response.SystemUpdates, []byte(job.ID)) {
		t.Fatal("real GET did not contain the accepted job")
	}
	h.webCases = append(h.webCases, stPortChainWebCase{ScenarioID: scenario, JobID: job.ID, Result: string(job.PortResult.Result), SystemUpdates: response.SystemUpdates})
}

func (h *stPortChainHarness) writeWebArtifact(t *testing.T) {
	t.Helper()
	if len(h.webCases) != 3 {
		t.Fatal("three real accepted GET outcomes are required")
	}
	sources := map[string]string{}
	for _, key := range []string{"CONTROL_PANEL", "UPDATER", "CONTRACTS", "WORKER"} {
		value := os.Getenv("AUTOSTREAM_ST_PORT_" + key + "_SHA")
		if len(value) != 40 || strings.Trim(value, "0123456789abcdef") != "" {
			t.Fatal("immutable integration source identity is required")
		}
		sources[strings.ToLower(key)+"_sha"] = value
	}
	artifact := map[string]any{"schema_version": 1, "source_set": sources, "cases": h.webCases}
	payload, err := json.Marshal(artifact)
	if err != nil || os.WriteFile(filepath.Join(h.evidence, "artifacts", "st-port-full-chain-web.json"), payload, 0o600) != nil {
		t.Fatal("persist real GET browser handoff")
	}
}

func stPortChainContainsSecretKey(value any) bool {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			normal := strings.ToLower(key)
			if strings.Contains(normal, "token") || strings.Contains(normal, "credential") || strings.Contains(normal, "nonce") || normal == "cookie" || normal == "headers" || normal == "authorization" || normal == "grant" {
				return true
			}
			if stPortChainContainsSecretKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if stPortChainContainsSecretKey(child) {
				return true
			}
		}
	}
	return false
}
