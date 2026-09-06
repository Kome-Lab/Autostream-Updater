package hostruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

func TestSTPortFirstWriteDeadlineIsCheckedAfterDurableLatch(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
	h.runtime.firstPolicyWriteDelay = 30 * time.Second
	response := h.run(t, "port_reconfigure")
	if response.PortResult != nil || response.Error == nil || h.runtime.consumeCalls != 1 || h.runtime.store.writes != 0 || h.runtime.writeCalls != 0 || h.runtime.restartCalls != 0 {
		t.Fatal("delayed durable latch reset first-write authorization deadline")
	}
	ledger, err := h.state.LoadJob(h.plan.TargetID, h.plan.JobID)
	if err != nil || ledger.Result != nil || !ledger.PolicyTransition.RecoveryRequired {
		t.Fatal("expired first write lost recovery hold")
	}
}

func TestSTPortConsumeTimeRuntimeDriftCannotReachPolicyWrite(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
	h.runtime.consumeHook = func() { h.runtime.live = []byte("external runtime drift") }
	response := h.run(t, "port_reconfigure")
	if response.PortResult != nil || response.Error == nil || h.runtime.consumeCalls != 1 || h.runtime.store.writes != 0 || h.runtime.writeCalls != 0 {
		t.Fatal("runtime drift while authorizing crossed the first policy write boundary")
	}
}

func TestSTPortForwardAndRollbackUseSeparateBoundedBudgets(t *testing.T) {
	for _, rollbackDelay := range []time.Duration{119 * time.Second, 121 * time.Second} {
		t.Run(rollbackDelay.String(), func(t *testing.T) {
			h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
			h.runtime.forwardRestartDelay, h.runtime.rollbackRestartDelay = 121*time.Second, rollbackDelay
			response := h.run(t, "port_reconfigure")
			if rollbackDelay < 120*time.Second {
				if response.PortResult == nil || response.PortResult.Result != systemdPortResultRolledBack {
					t.Fatal("forward timeout consumed independent rollback budget")
				}
			} else {
				if response.PortResult != nil || response.Error == nil {
					t.Fatal("rollback timeout was reported as a verified result")
				}
				ledger, err := h.state.LoadJob(h.plan.TargetID, h.plan.JobID)
				if err != nil || ledger.Result != nil || !ledger.PolicyTransition.RollbackLatched || !ledger.PolicyTransition.RecoveryRequired {
					t.Fatal("unknown rollback deadline cleared the host hold")
				}
				h.plan.LeaseGeneration++
				h.plan.SessionID = "budget-recovery-session-0123456789"
				h.plan.PortPlanSHA256, _ = h.plan.ComputePortPlanSHA256()
				beforeRestarts := h.runtime.restartCalls
				recovered := h.run(t, "port_reconfigure_reconcile")
				if recovered.PortResult == nil || recovered.PortResult.Result != systemdPortResultRolledBack || h.runtime.restartCalls != beforeRestarts {
					t.Fatal("fresh same-job observation did not accept exact R without another restart")
				}
			}
		})
	}
}

func TestSTPortRootRejectsMixedDuplicateAndReboundAuthority(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	encoded, err := json.Marshal(h.plan)
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{
		"mixed-zero":       append([]byte(`{"old_port":0,`), encoded[1:]...),
		"mixed-null":       append([]byte(`{"docker":null,`), encoded[1:]...),
		"duplicate":        append([]byte(`{"mode":"local_only",`), encoded[1:]...),
		"nested-duplicate": bytes.Replace(encoded, []byte(`"config_revision":31`), []byte(`"config_revision":31,"config_revision":31`), 1),
		"unknown-version":  bytes.Replace(encoded, []byte(`"port_contract_version":2`), []byte(`"port_contract_version":3`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			var plan SystemdPortReconfigurePlan
			if json.Unmarshal(payload, &plan) == nil {
				t.Fatal("invalid raw authority accepted")
			}
		})
	}
	binding := h.plan.mutationGrantBinding()
	if !reflect.DeepEqual(binding.sharedPortPlan(), h.plan.SharedPortPlan()) || binding.PortPlanSHA256 == h.plan.PortPlanSHA256 {
		t.Fatal("wire intent and root runtime binding were conflated")
	}
	binding.Before.LocalListenPort++
	if binding.Before.LocalListenPort == h.plan.Before.LocalListenPort {
		t.Fatal("mutation grant aliases immutable plan")
	}
	request := h.request(t, "port_reconfigure")
	request.MutationGrantV2Binding.Lease.Command.MutationAuthorization.Fence++
	if validatePortV2GrantBinding(h.runtime.clock, *request.MutationGrantV2Binding, request.Operation, h.plan,
		LocalExecutorMutationFence{SourcePolicyRevision: h.plan.Before.SourcePolicyRevision, OwnershipEpoch: h.plan.OwnershipEpoch,
			OwnershipPolicyRevision: h.plan.Before.ProjectionRevision, ExecutorPolicyRevision: h.plan.Before.ExecutorPolicyRevision}, &h.policy, &h.policy.Targets[0]) == nil {
		t.Fatal("ownership rebind accepted")
	}
}

func TestSTPortRootRecoveryHoldsWholeHostAndRejectsUnknownPolicy(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
	h.runtime.crashAt = "after_grant_consume"
	if response := h.run(t, "port_reconfigure"); response.Error == nil {
		t.Fatal("fault did not stop execution")
	}
	dockerState := newMemoryDockerPortStateStore()
	request := h.request(t, "port_reconfigure_reconcile")
	if !portV2HostLaneAllows(h.policy, request, h.state, dockerState) {
		t.Fatal("same-job recovery blocked")
	}
	other := request
	other.PortPlan = nil
	other.Operation = "credential_rotate"
	if portV2HostLaneAllows(h.policy, other, h.state, dockerState) {
		t.Fatal("other host mutation bypassed recovery hold")
	}
	other = request
	otherPlan := *request.PortPlan
	otherPlan.JobID = "different-port-job"
	other.PortPlan = &otherPlan
	if portV2HostLaneAllows(h.policy, other, h.state, dockerState) {
		t.Fatal("new job bypassed recovery hold")
	}
	ledger, _ := h.state.LoadJob(h.plan.TargetID, h.plan.JobID)
	for _, payload := range [][]byte{ledger.PolicyTransition.BeforePolicy, ledger.PolicyTransition.TargetPolicy, ledger.PolicyTransition.RollbackPolicy} {
		policy, err := decodePortPolicy(payload)
		if err != nil || validatePortV2Startup(policy, h.state, dockerState) != nil {
			t.Fatal("saved B/T/R restart rejected", err)
		}
		policy.PolicyRevision += 3
		if validatePortV2Startup(policy, h.state, dockerState) == nil {
			t.Fatal("unknown installed policy accepted after restart")
		}
	}
}

func TestSTPortVersionedLedgerBoundsPreserveLegacyLimits(t *testing.T) {
	store, err := newFileSystemdPortStateStore(filepath.Join(t.TempDir(), "state"), false)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.directory(), "test-boundary.json")
	legacy := systemdPortLedger{Checkpoint: newSystemdPortSidecarCheckpoint(true, 0o600, bytes.Repeat([]byte("x"), systemdPortLedgerMaxBytes))}
	if store.writePrivateJSON(path, legacy, "legacy boundary") == nil {
		t.Fatal("legacy write size limit was widened")
	}
	payload, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	var readLegacy systemdPortLedger
	if _, err := store.readPrivateJSON(path, &readLegacy, "legacy boundary"); err == nil {
		t.Fatal("legacy read size limit was widened")
	}
	for _, size := range []int{localExecutorPolicyMaxBytes, localExecutorPolicyMaxBytes + 1} {
		if size > localExecutorPolicyMaxBytes && func() bool { _, err := decodePortPolicy(bytes.Repeat([]byte("x"), size)); return err == nil }() {
			t.Fatal("candidate limit was widened")
		}
	}
	oversized := systemdPortLedger{Plan: SystemdPortReconfigurePlan{PortContractVersion: 2}, TargetBytes: bytes.Repeat([]byte("x"), systemdPortV2LedgerMaxBytes)}
	if store.writePrivateJSON(path, oversized, "v2 boundary") == nil {
		t.Fatal("v2 ledger exceeded the fixed encoded limit")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), systemdPortV2LedgerMaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	var versioned systemdPortLedger
	if _, err := store.readPrivateJSON(path, &versioned, "v2 boundary"); err == nil {
		t.Fatal("v2 oversized read accepted")
	}
}

func TestSTPortLargeVersionedLedgerSurvivesExactRestart(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
	base, _ := json.Marshal(h.policy)
	h.policy.Mutation.PanelURL += "/" + strings.Repeat("x", localExecutorPolicyMaxBytes-len(base)-33)
	root, _ := json.Marshal(h.policy)
	if len(root) > localExecutorPolicyMaxBytes {
		t.Fatal("large fixture exceeds per-policy limit")
	}
	h.plan.Before.ExecutorPolicySHA256 = systemdPortSidecarSHA256(root)
	for _, ref := range []*contracts.SystemUpdatePortSnapshotRef{h.plan.Target, h.plan.Rollback} {
		ref.ExecutorPolicySHA256 = ""
		payload, err := contracts.ApplySystemUpdatePortPolicyDelta(root, h.plan.TargetID, *h.plan.Before, *ref)
		if err != nil {
			t.Fatal("large candidate fixture", err)
		}
		ref.ExecutorPolicySHA256 = systemdPortSidecarSHA256(payload)
	}
	shared := h.plan.SharedPortPlan()
	shared.PortPlanSHA256 = ""
	h.plan.PortIntentSHA256, _ = contracts.ComputeSystemUpdatePortPlanSHA256(shared)
	h.plan.PortPlanSHA256, _ = h.plan.ComputePortPlanSHA256()
	h.runtime.store.disk, h.runtime.store.memory = append([]byte(nil), root...), append([]byte(nil), root...)
	stateDir := filepath.Join(t.TempDir(), "state")
	store, err := newFileSystemdPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	h.state = store
	h.runtime.crashAt = "after_grant_consume"
	if response := h.run(t, "port_reconfigure"); response.Error == nil {
		t.Fatal("crash boundary not reached")
	}
	info, err := os.Stat(store.jobPath(h.plan.TargetID, h.plan.JobID))
	if err != nil || info.Size() <= 4<<20 || info.Size() > systemdPortV2LedgerMaxBytes {
		t.Fatal("fixture does not exercise base64 overhead bound", err)
	}
	restarted, err := newFileSystemdPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := restarted.LoadActive(h.plan.TargetID)
	if err != nil || ledger == nil || !bytes.Equal(ledger.PolicyTransition.BeforePolicy, root) {
		t.Fatal("large durable ledger failed exact restart", err)
	}
	corrupt := cloneSystemdPortLedger(*ledger)
	corrupt.PolicyTransition.RollbackPolicy[0] = '!'
	if restarted.Save(corrupt) == nil {
		t.Fatal("corrupt saved recovery candidate accepted")
	}
	corrupted, _ := json.Marshal(corrupt)
	if err := os.WriteFile(restarted.jobPath(h.plan.TargetID, h.plan.JobID), corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.LoadActive(h.plan.TargetID); err == nil {
		t.Fatal("corrupt persisted recovery candidate accepted after restart")
	}
}
