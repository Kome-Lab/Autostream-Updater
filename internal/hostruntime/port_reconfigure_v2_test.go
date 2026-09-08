package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

type stPortTestPolicyStore struct {
	disk, memory    []byte
	writes, reloads int
	events          *[]string
}

func (s *stPortTestPolicyStore) Snapshot() (LocalExecutorPolicy, error) {
	return decodePortPolicy(s.memory)
}
func (s *stPortTestPolicyStore) Verify(expected []byte) error {
	if !bytes.Equal(s.disk, expected) || !bytes.Equal(s.memory, expected) {
		return errors.New("unverified policy")
	}
	return nil
}
func (s *stPortTestPolicyStore) Write(allowed portPolicyCandidates, next []byte) error {
	match := func(value []byte) bool {
		return bytes.Equal(value, allowed.Before) || bytes.Equal(value, allowed.Target) || bytes.Equal(value, allowed.Rollback)
	}
	if !match(s.disk) || !match(s.memory) || !match(next) {
		return errors.New("unknown policy")
	}
	if !bytes.Equal(s.disk, next) {
		s.writes++
		s.disk = append([]byte(nil), next...)
		*s.events = append(*s.events, "policy_write")
	}
	return nil
}
func (s *stPortTestPolicyStore) Reload(next []byte) error {
	if !bytes.Equal(s.disk, next) {
		return errors.New("reload mismatch")
	}
	if !bytes.Equal(s.memory, next) {
		s.reloads++
		s.memory = append([]byte(nil), next...)
		*s.events = append(*s.events, "policy_reload")
	}
	return nil
}
func (s *stPortTestPolicyStore) Replace(allowed portPolicyCandidates, next []byte) error {
	if err := s.Write(allowed, next); err != nil {
		return err
	}
	return s.Reload(next)
}

type stPortTestRuntime struct {
	*fakeSystemdPortRuntime
	store                                     *stPortTestPolicyStore
	clock                                     time.Time
	live                                      []byte
	events                                    []string
	consumeDelay                              time.Duration
	verifyCalls                               int
	consumeError                              error
	consumeHook                               func()
	failForwardRestart, failRollbackRestart   bool
	forwardRevision, rollbackRevision         int64
	forwardRestartDelay, rollbackRestartDelay time.Duration
	firstPolicyWriteDelay                     time.Duration
}

func (r *stPortTestRuntime) PortPolicyStore() portPolicyStore { return r.store }
func (r *stPortTestRuntime) PortNow() time.Time               { return r.clock }
func (r *stPortTestRuntime) ConsumeGrant(context.Context, SystemdPortReconfigurePlan, string, string, BoundedSecret) error {
	r.consumeCalls++
	r.events = append(r.events, "consume")
	r.clock = r.clock.Add(r.consumeDelay)
	if r.consumeHook != nil {
		r.consumeHook()
	}
	return r.consumeError
}
func (r *stPortTestRuntime) Write(adapter systemdPortAdapter, checkpoint systemdPortSidecarCheckpoint, payload []byte) error {
	policy, err := r.store.Snapshot()
	if err != nil || r.store.Verify(r.store.memory) != nil || policy.Targets[0].ConfigSHA256 != systemdPortSidecarSHA256(payload) {
		return errors.New("runtime write before policy disk and reload")
	}
	r.events = append(r.events, "runtime_write")
	return r.fakeSystemdPortRuntime.Write(adapter, checkpoint, payload)
}
func (r *stPortTestRuntime) Restart(ctx context.Context, target LocalExecutorTarget) error {
	r.restartCalls++
	r.events = append(r.events, "restart")
	if target.ConfigRevision == r.forwardRevision {
		r.clock = r.clock.Add(r.forwardRestartDelay)
	}
	if target.ConfigRevision == r.rollbackRevision {
		r.clock = r.clock.Add(r.rollbackRestartDelay)
	}
	if target.ConfigRevision == r.forwardRevision && r.failForwardRestart || target.ConfigRevision == r.rollbackRevision && r.failRollbackRestart {
		return errors.New("injected restart failure")
	}
	r.live = append([]byte(nil), r.current...)
	return ctx.Err()
}
func (r *stPortTestRuntime) CrashPoint(phase string) error {
	if phase == "before_policy_write" && r.firstPolicyWriteDelay != 0 {
		r.clock = r.clock.Add(r.firstPolicyWriteDelay)
		r.firstPolicyWriteDelay = 0
	}
	return r.fakeSystemdPortRuntime.CrashPoint(phase)
}
func (r *stPortTestRuntime) Verify(ctx context.Context, policy LocalExecutorPolicy, target LocalExecutorTarget) (string, error) {
	r.verifyCalls++
	if ctx.Err() != nil || systemdPortSidecarSHA256(r.live) != target.ConfigSHA256 {
		return "", errors.New("runtime does not match the expected snapshot")
	}
	return "v1.2.3", nil
}

type stPortV2Harness struct {
	policy  LocalExecutorPolicy
	plan    SystemdPortReconfigurePlan
	runtime *stPortTestRuntime
	state   systemdPortStateStore
}

func newSTPortV2Harness(t *testing.T, mode contracts.SystemUpdatePortMode, noop bool) *stPortV2Harness {
	t.Helper()
	legacy := newSystemdPortHarness(t)
	policy := legacy.policy
	policy.SourcePolicyRevision, policy.ProjectionRevision, policy.PolicyRevision = 11, 17, 23
	policy.Targets[0].LocalListen.Port, policy.Targets[0].EndpointRevision, policy.Targets[0].ConfigRevision = 18081, 3, 31
	beforeBytes := systemdPortSidecarBytes("worker", "127.0.0.1", 18081, 31)
	policy.Targets[0].ConfigSHA256 = systemdPortSidecarSHA256(beforeBytes)
	rootBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	rootSHA, _ := policy.SHA256()
	before := contracts.SystemUpdatePortSnapshotRef{SnapshotID: "ps1:" + strings.Repeat("a", 64), SnapshotSHA256: "sha256:" + strings.Repeat("a", 64),
		SourcePolicyRevision: 11, ProjectionRevision: 17, ExecutorPolicyRevision: 23, ExecutorPolicySHA256: rootSHA,
		EndpointRevision: 3, AppliedEndpointRevision: 3, ConfigRevision: 31, ConfigSHA256: policy.Targets[0].ConfigSHA256,
		AdvertisedPort: 443, AdvertisedEndpointSHA256: "sha256:" + strings.Repeat("d", 64), LocalListenPort: 18081}
	target, rollback := before, before
	if !noop {
		target.SnapshotID, target.SnapshotSHA256 = "ps1:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("b", 64)
		rollback.SnapshotID, rollback.SnapshotSHA256 = "ps1:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("c", 64)
		target.SourcePolicyRevision++
		target.ProjectionRevision++
		target.ExecutorPolicyRevision++
		target.ConfigRevision++
		target.LocalListenPort = 18084
		rollback.SourcePolicyRevision += 2
		rollback.ProjectionRevision += 2
		rollback.ExecutorPolicyRevision += 2
		rollback.ConfigRevision += 2
		if mode == contracts.SystemUpdatePortModeLocalAndAdvertised {
			target.EndpointRevision++
			target.AppliedEndpointRevision++
			target.AdvertisedPort = 8443
			target.AdvertisedEndpointSHA256 = "sha256:" + strings.Repeat("e", 64)
			rollback.EndpointRevision += 2
			rollback.AppliedEndpointRevision += 2
		}
		for _, ref := range []*contracts.SystemUpdatePortSnapshotRef{&target, &rollback} {
			ref.ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes("worker", "127.0.0.1", ref.LocalListenPort, ref.ConfigRevision))
			ref.ExecutorPolicySHA256 = ""
			payload, err := contracts.ApplySystemUpdatePortPolicyDelta(rootBytes, "worker-01", before, *ref)
			if err != nil {
				t.Fatal("derive fixed root policy candidate:", err)
			}
			ref.ExecutorPolicySHA256 = systemdPortSidecarSHA256(payload)
		}
	}
	shared := contracts.SystemUpdatePortReconfiguration{PortContractVersion: 2, Mode: mode, NetworkNamespace: "host", Protocol: contracts.SystemUpdatePortProtocolTCP,
		Before: &before, Target: &target, Rollback: &rollback}
	shared.PortPlanSHA256, err = contracts.ComputeSystemUpdatePortPlanSHA256(shared)
	if err != nil {
		t.Fatal(err)
	}
	plan := SystemdPortReconfigurePlan{PortContractVersion: 2, Mode: mode, Before: &before, Target: &target, Rollback: &rollback,
		PortIntentSHA256: shared.PortPlanSHA256, DeploymentMode: ModeSystemd, JobID: "job-port-v2", HostID: policy.HostID,
		TargetID: "worker-01", ServiceType: "worker", NetworkNamespace: "host", Protocol: "tcp", OwnershipEpoch: 9,
		LeaseGeneration: 3, SessionID: "port-v2-session-0123456789abcdef"}
	plan.PortPlanSHA256, err = plan.ComputePortPlanSHA256()
	if err != nil || plan.Validate() != nil {
		t.Fatal("valid versioned port fixture rejected", err)
	}
	runtime := &stPortTestRuntime{fakeSystemdPortRuntime: &fakeSystemdPortRuntime{current: append([]byte(nil), beforeBytes...)}, clock: time.Now(),
		live: append([]byte(nil), beforeBytes...), forwardRevision: target.ConfigRevision, rollbackRevision: rollback.ConfigRevision}
	runtime.store = &stPortTestPolicyStore{disk: append([]byte(nil), rootBytes...), memory: append([]byte(nil), rootBytes...), events: &runtime.events}
	return &stPortV2Harness{policy: policy, plan: plan, runtime: runtime, state: newMemorySystemdPortStateStore()}
}

func (h *stPortV2Harness) request(t *testing.T, operation string) LocalExecutorRequest {
	t.Helper()
	return newSTPortV2Request(t, h.plan, h.runtime.clock, operation)
}

func newSTPortV2Request(t *testing.T, plan SystemdPortReconfigurePlan, now time.Time, operation string) LocalExecutorRequest {
	t.Helper()
	shared := plan.SharedPortPlan()
	desired := contracts.UpdaterDesiredOperation{Operation: contracts.UpdaterDesiredPortReconfigure, PortReconfigure: &shared}
	target := contracts.UpdaterTargetIdentity{TargetKind: contracts.UpdaterTargetApplication, ServiceID: plan.TargetID, ServiceType: contracts.SystemUpdateTargetType(plan.ServiceType),
		DeploymentMode: contracts.SystemUpdateDeploymentMode(plan.DeploymentMode), ExpectedConfigRevision: plan.Before.ConfigRevision}
	lease := v2PanelLease(t, now, desired, target, contracts.UpdaterCapabilityPort)
	auth := &lease.Command.MutationAuthorization
	auth.JobID, auth.HostID, auth.DesiredRevision, auth.Fence = plan.JobID, plan.HostID, plan.Target.ConfigRevision, plan.OwnershipEpoch
	auth.ExpiresAt = now.Add(90 * time.Second)
	lease.LeaseExpiresAt = now.Add(90 * time.Second)
	lease.LeaseGeneration = int64(plan.LeaseGeneration)
	digest, err := contracts.ComputeUpdaterCommandCanonicalDigest(target, auth.DesiredRevision, auth.Fence, desired)
	if err != nil {
		t.Fatal(err)
	}
	auth.CanonicalArgumentDigest, lease.Command.CanonicalPayloadDigest = digest, digest
	binding := &contracts.UpdaterMutationGrantBinding{Lease: lease, Operation: contracts.UpdaterMutationOperation(operation), SessionID: plan.SessionID}
	return LocalExecutorRequest{Version: 2, Operation: operation, ServiceID: plan.TargetID, PortPlan: &plan,
		SourcePolicyRevision: plan.Before.SourcePolicyRevision, OwnershipEpoch: plan.OwnershipEpoch,
		OwnershipPolicyRevision: plan.Before.ProjectionRevision, ExecutorPolicyRevision: plan.Before.ExecutorPolicyRevision,
		MutationGrant: NewBoundedSecret("short-lived-test-grant"), MutationGrantV2Binding: binding}
}

func (h *stPortV2Harness) run(t *testing.T, operation string) LocalExecutorResponse {
	t.Helper()
	policy, err := h.runtime.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return executeSystemdPortRequest(context.Background(), policy, h.request(t, operation), h.runtime, h.state)
}

func TestSTPortRootModesApplyPolicyBeforeRuntime(t *testing.T) {
	for _, mode := range []contracts.SystemUpdatePortMode{contracts.SystemUpdatePortModeLocalOnly, contracts.SystemUpdatePortModeLocalAndAdvertised} {
		t.Run(string(mode), func(t *testing.T) {
			h := newSTPortV2Harness(t, mode, false)
			before := h.runtime.mutationCounts()
			result := h.run(t, "port_reconfigure")
			if result.PortResult == nil || result.PortResult.Result != systemdPortResultApplied {
				t.Fatalf("expected applied result; safe error=%v", result.Error)
			}
			if !reflect.DeepEqual(h.runtime.events, []string{"consume", "policy_write", "policy_reload", "runtime_write", "restart"}) {
				t.Fatalf("wrong policy/runtime order: %v", h.runtime.events)
			}
			after := h.runtime.mutationCounts()
			for i := range after {
				after[i] -= before[i]
			}
			if after != ([5]int{1, 1, 1, 1, 1}) {
				t.Fatal("forward mutation count mismatch")
			}
			if result.PortResult.PortResult.Observation.AgentProjectionVerified {
				t.Fatal("root asserted Agent projection")
			}
			first := clonePortResult(result.PortResult.PortResult)
			beforeReplay := h.runtime.mutationCounts()
			h.plan.LeaseGeneration++
			h.plan.SessionID = "new-lease-session-0123456789abcdef"
			h.plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, h.plan)
			h.runtime.clock = h.runtime.clock.Add(time.Minute)
			replay := h.run(t, "port_reconfigure_reconcile")
			if replay.PortResult == nil || !reflect.DeepEqual(first, replay.PortResult.PortResult) || h.runtime.mutationCounts() != beforeReplay {
				t.Fatal("accepted result or first observation changed on replay")
			}
		})
	}
}

func (r *stPortTestRuntime) mutationCounts() [5]int {
	return [5]int{r.consumeCalls, r.store.writes, r.store.reloads, r.writeCalls, r.restartCalls}
}

func TestSTPortRootNoOpRequiresFreshProofAndHasNoMutation(t *testing.T) {
	for _, mode := range []contracts.SystemUpdatePortMode{contracts.SystemUpdatePortModeLocalOnly, contracts.SystemUpdatePortModeLocalAndAdvertised} {
		for _, operation := range []string{"port_reconfigure", "port_reconfigure_reconcile"} {
			t.Run(string(mode)+"/"+operation, func(t *testing.T) {
				h := newSTPortV2Harness(t, mode, true)
				before, beforeVerify := h.runtime.mutationCounts(), h.runtime.verifyCalls
				request := h.request(t, operation)
				request.MutationGrant = NewBoundedSecret("")
				if validBoundedSecret(request.MutationGrant.Reveal()) {
					t.Fatal("fixture did not expose the former mandatory credential guard")
				}
				t.Log("red_witness=mandatory_credential_guard_rejects_valid_noop")
				var wire bytes.Buffer
				if err := EncodeLocalExecutorRequest(&wire, request); err != nil {
					t.Fatal("encode credential-free exact no-op")
				}
				decoded, err := DecodeLocalExecutorRequest(&wire)
				if err != nil || !decoded.MutationGrant.Empty() || decoded.MutationGrantV2Binding == nil {
					t.Fatal("decode credential-free lease binding")
				}
				result := executeSystemdPortRequest(context.Background(), h.policy, decoded, h.runtime, h.state)
				if result.PortResult == nil || result.PortResult.Result != systemdPortResultUnchanged ||
					result.PortResult.PortResult.ObservedSnapshotID != h.plan.Before.SnapshotID ||
					result.PortResult.PortResult.Observation.AgentProjectionVerified {
					t.Fatal("exact no-op did not return root-only B proof")
				}
				first := clonePortResult(result.PortResult.PortResult)
				h.runtime.clock = h.runtime.clock.Add(time.Second)
				replay := executeSystemdPortRequest(context.Background(), h.policy, decoded, h.runtime, h.state)
				if replay.PortResult == nil || !contracts.EqualSystemUpdatePortResults(*first, *replay.PortResult.PortResult) {
					t.Fatal("no-op replay changed its first accepted observation")
				}
				if h.runtime.mutationCounts() != before || h.runtime.verifyCalls-beforeVerify < 1 {
					t.Fatal("no-op mutated state or omitted fresh runtime verification")
				}
			})
		}
	}
}

func TestSTPortRootNoGrantRejectsNonNoOpAndInvalidProof(t *testing.T) {
	for _, test := range []struct {
		name    string
		changed bool
		mutate  func(*stPortV2Harness, *LocalExecutorRequest)
	}{
		{name: "changed_plan", changed: true},
		{name: "missing_binding", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) { r.MutationGrantV2Binding = nil }},
		{name: "missing_before", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) { r.PortPlan.Before = nil }},
		{name: "missing_target", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) { r.PortPlan.Target = nil }},
		{name: "missing_rollback", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) { r.PortPlan.Rollback = nil }},
		{name: "zero_snapshots", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) {
			r.PortPlan.Before, r.PortPlan.Target, r.PortPlan.Rollback = &contracts.SystemUpdatePortSnapshotRef{}, &contracts.SystemUpdatePortSnapshotRef{}, &contracts.SystemUpdatePortSnapshotRef{}
		}},
		{name: "unequal_snapshot", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) {
			r.PortPlan.Rollback.SnapshotID = "ps1:" + strings.Repeat("f", 64)
		}},
		{name: "wrong_jp", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) { r.OwnershipPolicyRevision++ }},
		{name: "wrong_fence", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) { r.OwnershipEpoch++ }},
		{name: "wrong_job", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) {
			r.MutationGrantV2Binding.Lease.Command.MutationAuthorization.JobID = "other-job"
		}},
		{name: "wrong_host", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) {
			r.MutationGrantV2Binding.Lease.Command.MutationAuthorization.HostID = "other-host"
		}},
		{name: "wrong_target", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) {
			r.MutationGrantV2Binding.Lease.Command.MutationAuthorization.Target.ServiceID = "other-target"
		}},
		{name: "wrong_session", mutate: func(_ *stPortV2Harness, r *LocalExecutorRequest) {
			r.MutationGrantV2Binding.SessionID = "different-session-0123456789abcdef"
		}},
		{name: "expired_lease", mutate: func(h *stPortV2Harness, r *LocalExecutorRequest) {
			r.MutationGrantV2Binding.Lease.LeaseExpiresAt = h.runtime.clock.Add(-time.Second)
		}},
		{name: "stale_policy_disk", mutate: func(h *stPortV2Harness, _ *LocalExecutorRequest) { h.runtime.store.disk = []byte("unverified") }},
		{name: "stale_policy_memory", mutate: func(h *stPortV2Harness, _ *LocalExecutorRequest) { h.runtime.store.memory = []byte("unverified") }},
		{name: "stale_runtime", mutate: func(h *stPortV2Harness, _ *LocalExecutorRequest) { h.runtime.live = []byte("unverified") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, !test.changed)
			before := h.runtime.mutationCounts()
			request := h.request(t, "port_reconfigure")
			request.MutationGrant = NewBoundedSecret("")
			if test.mutate != nil {
				test.mutate(h, &request)
			}
			var wire bytes.Buffer
			if err := EncodeLocalExecutorRequest(&wire, request); err == nil {
				decoded, err := DecodeLocalExecutorRequest(&wire)
				if err != nil {
					t.Fatal("validly encoded fixture did not decode")
				}
				result := executeSystemdPortRequest(context.Background(), h.policy, decoded, h.runtime, h.state)
				if result.Error == nil || result.PortResult != nil {
					t.Fatal("non-no-op or unverified state obtained a credential-free result")
				}
			}
			if h.runtime.mutationCounts() != before {
				t.Fatal("rejected credential-free request reached mutation")
			}
		})
	}
}

func TestSTPortRootRollbackFailureRestartKeepsSameJobRecovery(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	h.runtime.failForwardRestart, h.runtime.failRollbackRestart = true, true
	failed := h.run(t, "port_reconfigure")
	if failed.PortResult == nil || failed.PortResult.Result != systemdPortResultRollbackFailed || !failed.PortResult.RecoveryRequired {
		t.Fatalf("expected recovery hold; safe error=%v", failed.Error)
	}
	ledger, err := h.state.LoadJob(h.plan.TargetID, h.plan.JobID)
	if err != nil || ledger.Result != nil || !ledger.PolicyTransition.RollbackLatched || !ledger.PolicyTransition.RecoveryRequired || ledger.PolicyTransition.LastRecoveryObservation == nil {
		t.Fatal("failed attempt consumed accepted slot or released hold")
	}
	h.runtime.store.memory = append([]byte(nil), h.runtime.store.disk...)
	h.runtime.failRollbackRestart = false
	h.plan.LeaseGeneration++
	h.plan.SessionID = "recovery-session-0123456789abcdef"
	h.plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, h.plan)
	recovered := h.run(t, "port_reconfigure_reconcile")
	if recovered.PortResult == nil || recovered.PortResult.Result != systemdPortResultRolledBack || recovered.PortResult.PortResult.ObservedConfigRevision != 33 {
		t.Fatalf("expected exact R C+2; safe error=%v", recovered.Error)
	}
	if !bytes.Equal(h.runtime.current, systemdPortSidecarBytes("worker", "127.0.0.1", 18081, 33)) {
		t.Fatal("rollback reused B config bytes")
	}
	ledger, _ = h.state.LoadJob(h.plan.TargetID, h.plan.JobID)
	if ledger.Result == nil || ledger.PolicyTransition.RecoveryRequired || ledger.PolicyTransition.LastRecoveryObservation != nil {
		t.Fatal("successful R did not finish recovery")
	}
}

func TestSTPortRootCrashMatrixUsesRecoveryWithoutSecondForward(t *testing.T) {
	for _, phase := range []string{"after_grant_consume", "before_policy_write", "after_policy_write", "after_policy_reload", "after_sidecar_write", "after_restart", "after_result_save"} {
		t.Run(phase, func(t *testing.T) {
			h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
			h.runtime.crashAt = phase
			first := h.run(t, "port_reconfigure")
			if first.Error == nil {
				t.Fatal("fault did not interrupt operation")
			}
			h.runtime.crashAt = ""
			h.runtime.store.memory = append([]byte(nil), h.runtime.store.disk...)
			beforeRestarts := h.runtime.restartCalls
			h.plan.LeaseGeneration++
			h.plan.SessionID = "restart-session-0123456789abcdef"
			h.plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, h.plan)
			result := h.run(t, "port_reconfigure_reconcile")
			if result.PortResult == nil {
				t.Fatalf("same-job recovery did not converge; safe error=%v", result.Error)
			}
			want := systemdPortResultRolledBack
			if phase == "after_restart" || phase == "after_result_save" {
				want = systemdPortResultApplied
			}
			if result.PortResult.Result != want {
				t.Fatalf("result=%s want=%s", result.PortResult.Result, want)
			}
			if want == systemdPortResultApplied && h.runtime.restartCalls != beforeRestarts {
				t.Fatal("replayed forward after restart")
			}
		})
	}
}

func TestSTPortRootConsumeDeadlineStartsBeforeRequestAndCannotReset(t *testing.T) {
	for _, delay := range []time.Duration{29 * time.Second, 30 * time.Second, 31 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
			h.runtime.consumeDelay = delay
			result := h.run(t, "port_reconfigure")
			if delay < 30*time.Second {
				if result.PortResult == nil || result.PortResult.Result != systemdPortResultApplied {
					t.Fatalf("valid deadline rejected: %v", result.Error)
				}
			} else {
				if result.PortResult != nil || result.Error == nil || h.runtime.store.writes != 0 || h.runtime.writeCalls != 0 {
					t.Fatal("204 receipt reset expired start budget")
				}
			}
		})
	}
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
	request := h.request(t, "port_reconfigure")
	m0 := h.runtime.clock
	request.MutationGrantV2Binding.Lease.LeaseExpiresAt = m0.Add(5 * time.Second)
	if got := portStartDeadline(m0, *request.MutationGrantV2Binding); got.Sub(m0) != 5*time.Second {
		t.Fatal("lease expiry was extended")
	}
	// Changing a subsequently read wall clock cannot affect the already
	// captured monotonic deadline; no wall clock is read by the predicate.
	deadline := portStartDeadline(m0, *request.MutationGrantV2Binding)
	for _, wallJump := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		_ = m0.UTC().Add(wallJump)
		if !m0.Add(4*time.Second).Before(deadline) || m0.Add(5*time.Second).Before(deadline) {
			t.Fatal("captured deadline changed with wall time")
		}
	}
}

func TestSTPortRootLostConsumeAcknowledgementRequiresFreshRecovery(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
	h.runtime.consumeError = errors.New("dropped 204")
	response := h.run(t, "port_reconfigure")
	if response.PortResult != nil || response.Error == nil || h.runtime.writeCalls != 0 || h.runtime.store.writes != 0 {
		t.Fatal("lost acknowledgement permitted mutation")
	}
	h.runtime.consumeError = nil
	h.runtime.store.memory = append([]byte(nil), h.runtime.store.disk...)
	h.plan.LeaseGeneration++
	h.plan.SessionID = "lost-ack-session-0123456789abcdef"
	h.plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, h.plan)
	response = h.run(t, "port_reconfigure_reconcile")
	if response.PortResult == nil || response.PortResult.Result != systemdPortResultRolledBack || h.runtime.consumeCalls != 2 {
		t.Fatalf("fresh recovery failed: %v", response.Error)
	}
}

func TestSTPortPolicyFileReplacementRequiresExactDiskAndMemory(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalOnly, false)
	candidates, err := buildSystemUpdatePortPolicyCandidates(h.policy, h.plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "executor-policy.json")
	if err := os.WriteFile(path, candidates.Before, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newFilePortPolicyStore(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(candidates, candidates.Target); err != nil {
		t.Fatal(err)
	}
	if store.Verify(candidates.Target) == nil {
		t.Fatal("disk-only transition appeared loaded")
	}
	if err := store.Reload(candidates.Target); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(candidates.Target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if store.Replace(candidates, candidates.Rollback) == nil {
		t.Fatal("tampered policy was replaced by guessing a recovery state")
	}
}
