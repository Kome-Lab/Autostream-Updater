package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestSystemdPortReconfigurePlanBindsEveryRevisionAndPortBoundary(t *testing.T) {
	for _, testCase := range []struct {
		port  int
		valid bool
	}{
		{port: 1023, valid: false},
		{port: 1024, valid: true},
		{port: 65535, valid: true},
		{port: 65536, valid: false},
	} {
		t.Run(fmt.Sprintf("port_%d", testCase.port), func(t *testing.T) {
			plan := validSystemdPortReconfigurePlan(t)
			plan.NewPort = testCase.port
			if testCase.valid {
				plan.TargetConfigSHA256 = systemdPortSidecarSHA256(
					systemdPortSidecarBytes("worker", "127.0.0.1", plan.NewPort, plan.TargetConfigRevision),
				)
				plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, plan)
			}
			err := plan.Validate()
			if testCase.valid && err != nil {
				t.Fatalf("valid boundary rejected: %v", err)
			}
			if !testCase.valid && err == nil {
				t.Fatal("invalid boundary accepted")
			}
		})
	}

	base := validSystemdPortReconfigurePlan(t)
	for name, mutate := range map[string]func(*SystemdPortReconfigurePlan){
		"same port": func(plan *SystemdPortReconfigurePlan) { plan.NewPort = plan.OldPort },
		"endpoint skips revision": func(plan *SystemdPortReconfigurePlan) {
			plan.TargetEndpointRevision += 1
		},
		"config skips revision": func(plan *SystemdPortReconfigurePlan) {
			plan.TargetConfigRevision += 1
		},
		"foreign namespace": func(plan *SystemdPortReconfigurePlan) {
			plan.NetworkNamespace = "container:attacker"
		},
		"udp": func(plan *SystemdPortReconfigurePlan) { plan.Protocol = "udp" },
		"stale source": func(plan *SystemdPortReconfigurePlan) {
			plan.ExpectedSourcePolicyRevision = 0
		},
		"stale projection": func(plan *SystemdPortReconfigurePlan) {
			plan.ExpectedUpdaterPolicyRevision = 0
		},
		"stale executor": func(plan *SystemdPortReconfigurePlan) {
			plan.ExpectedExecutorPolicyRevision = 0
		},
		"wrong target digest": func(plan *SystemdPortReconfigurePlan) {
			plan.TargetConfigSHA256 = "sha256:" + strings.Repeat("f", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("tampered plan was accepted")
			}
		})
	}
	t.Run("endpoint rollback fence overflow", func(t *testing.T) {
		candidate := base
		candidate.ExpectedEndpointRevision = math.MaxInt64 - 1
		candidate.TargetEndpointRevision = math.MaxInt64
		if _, err := candidate.ComputePortPlanSHA256(); err == nil {
			t.Fatal("overflowing endpoint fence was hashable")
		}
		if err := candidate.Validate(); err == nil {
			t.Fatal("overflowing endpoint fence was accepted")
		}
	})
}

func TestSystemdPortAdapterIsFixedByServiceTypeAndPolicyUnit(t *testing.T) {
	for serviceType, expected := range map[string]systemdPortAdapter{
		"worker": {
			Unit: "autostream-worker.service", SidecarPath: "/opt/autostream/local-executor/ports/worker.json",
			ServiceType: "worker",
		},
		"encoder_recorder": {
			Unit: "autostream-encoder-recorder.service", SidecarPath: "/opt/autostream/local-executor/ports/encoder-recorder.json",
			ServiceType: "encoder_recorder",
		},
		"discord_bot": {
			Unit: "autostream-discord-bot.service", SidecarPath: "/opt/autostream/local-executor/ports/discord-bot.json",
			ServiceType: "discord_bot",
		},
		"observability": {
			Unit: "autostream-observability.service", SidecarPath: "/opt/autostream/local-executor/ports/observability.json",
			ServiceType: "observability",
		},
	} {
		t.Run(serviceType, func(t *testing.T) {
			adapter, err := systemdPortAdapterFor(serviceType, expected.Unit)
			if err != nil {
				t.Fatal(err)
			}
			if adapter != expected {
				t.Fatalf("adapter=%+v expected=%+v", adapter, expected)
			}
			if _, err := systemdPortAdapterFor(serviceType, "attacker.service"); err == nil {
				t.Fatal("request/policy could select an arbitrary unit")
			}
		})
	}
	if _, err := systemdPortAdapterFor("control_panel", "autostream-control-panel.service"); err == nil {
		t.Fatal("non-initial service type was accepted")
	}
}

func TestSystemdPortSidecarIsCanonicalAndDigestBound(t *testing.T) {
	body := systemdPortSidecarBytes("worker", "::1", 18084, 12)
	expected := "{\"schema_version\":2,\"service_type\":\"worker\",\"bind_address\":\"[::1]:18084\",\"config_revision\":12}\n"
	if string(body) != expected {
		t.Fatalf("sidecar=%q", body)
	}
	if got := systemdPortSidecarSHA256(body); !digestPattern.MatchString(got) {
		t.Fatalf("digest=%q", got)
	}
	if systemdPortSidecarSHA256(nil) == systemdPortSidecarSHA256(body) {
		t.Fatal("absent and present checkpoints share a digest")
	}
}

func TestSystemdPortPreviousStateResultContractMatchesPanelFence(t *testing.T) {
	plan := validSystemdPortReconfigurePlan(t)
	for _, resultKind := range []string{
		systemdPortResultRolledBack,
		systemdPortResultUnchanged,
	} {
		result := SystemdPortReconfigureResult{
			Result:           resultKind,
			StateKnown:       true,
			OldPort:          plan.OldPort,
			NewPort:          plan.NewPort,
			AppliedPort:      plan.OldPort,
			EndpointRevision: plan.TargetEndpointRevision + 1,
			ConfigRevision:   plan.ExpectedConfigRevision,
			ConfigSHA256:     plan.ExpectedConfigSHA256,
			Message:          "previous port is verified",
		}
		if resultKind == systemdPortResultUnchanged {
			result.Status = "succeeded"
		} else {
			result.Status = "rolled_back"
		}
		if err := validatePortExecutionResult(plan, result); err != nil {
			t.Fatalf("%s result rejected: %v", resultKind, err)
		}
		stale := result
		stale.EndpointRevision = plan.TargetEndpointRevision
		if err := validatePortExecutionResult(plan, stale); err == nil {
			t.Fatalf("%s reused the consumed pending endpoint fence", resultKind)
		}
	}
	legacyUnchanged := SystemdPortReconfigureResult{
		Status: "rolled_back", Result: systemdPortResultUnchanged,
		StateKnown: true,
		OldPort:    plan.OldPort, NewPort: plan.NewPort, AppliedPort: plan.OldPort,
		EndpointRevision: plan.TargetEndpointRevision + 1,
		ConfigRevision:   plan.ExpectedConfigRevision,
		ConfigSHA256:     plan.ExpectedConfigSHA256,
		Message:          "previous port is verified",
	}
	if err := validatePortExecutionResult(plan, legacyUnchanged); err == nil {
		t.Fatal("legacy rolled_back status for unchanged was accepted")
	}
}

func TestLocalExecutorPortRequestRejectsArbitraryPrivilegedInput(t *testing.T) {
	plan := validSystemdPortReconfigurePlan(t)
	request := LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: "port_reconfigure",
		ServiceID: plan.TargetID, PortPlan: &plan,
		SourcePolicyRevision:    plan.ExpectedSourcePolicyRevision,
		OwnershipEpoch:          plan.OwnershipEpoch,
		OwnershipPolicyRevision: plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision:  plan.ExpectedExecutorPolicyRevision,
		MutationGrant:           NewBoundedSecret("one-time-mutation-grant"),
	}
	var encoded bytes.Buffer
	if err := EncodeLocalExecutorRequest(&encoded, request); err != nil {
		t.Fatalf("EncodeLocalExecutorRequest: %v", err)
	}
	decoded, err := DecodeLocalExecutorRequest(&encoded)
	if err != nil {
		t.Fatalf("DecodeLocalExecutorRequest: %v", err)
	}
	if decoded.PortPlan == nil || decoded.PortPlan.PortPlanSHA256 != plan.PortPlanSHA256 {
		t.Fatalf("decoded=%+v", decoded)
	}
	for name, field := range map[string]string{
		"path": `"path":"/tmp/attacker"`, "unit": `"unit":"attacker.service"`,
		"command": `"command":"/bin/sh"`, "url": `"url":"https://attacker.example"`,
		"image": `"image":"attacker/image"`, "env": `"env_name":"LD_PRELOAD"`,
	} {
		t.Run(name, func(t *testing.T) {
			payload := strings.TrimSpace(encoded.String())
			payload = strings.TrimSuffix(payload, "}") + "," + field + "}\n"
			if _, err := DecodeLocalExecutorRequest(strings.NewReader(payload)); err == nil {
				t.Fatal("arbitrary privileged input was accepted")
			}
		})
	}
}

func TestSystemdPortTransactionAppliesOnlyAfterGrantAndRollsBackLocally(t *testing.T) {
	harness := newSystemdPortHarness(t)
	harness.runtime.verifyNewErr = errors.New("health failed")
	response := executeSystemdPortRequest(
		context.Background(), harness.policy, harness.request("port_reconfigure"),
		harness.runtime, harness.state,
	)
	if response.PortResult == nil || response.PortResult.Result != "rolled_back" {
		t.Fatalf("response=%+v", response)
	}
	if harness.runtime.consumeCalls != 1 {
		t.Fatalf("grant calls=%d", harness.runtime.consumeCalls)
	}
	if harness.runtime.writeCalls != 2 {
		t.Fatalf("expected cutover and rollback writes, got %d", harness.runtime.writeCalls)
	}
	if harness.runtime.restartCalls != 2 {
		t.Fatalf("expected cutover and rollback restarts, got %d", harness.runtime.restartCalls)
	}
	if got := systemdPortSidecarSHA256(harness.runtime.current); got != harness.plan.ExpectedConfigSHA256 {
		t.Fatalf("rollback digest=%q expected=%q", got, harness.plan.ExpectedConfigSHA256)
	}
	if harness.runtime.panelCallsAfterConsume != 0 {
		t.Fatalf("rollback called the Control Panel %d times", harness.runtime.panelCallsAfterConsume)
	}
}

func TestSystemdPortTransactionUncertainApplyReconcilesWithoutReapply(t *testing.T) {
	harness := newSystemdPortHarness(t)
	harness.runtime.crashAt = "after_restart"
	first := executeSystemdPortRequest(
		context.Background(), harness.policy, harness.request("port_reconfigure"),
		harness.runtime, harness.state,
	)
	if first.Error == nil || first.Error.Code != "reconcile_required" {
		t.Fatalf("first=%+v", first)
	}
	writes, restarts := harness.runtime.writeCalls, harness.runtime.restartCalls
	harness.runtime.crashAt = ""
	second := executeSystemdPortRequest(
		context.Background(), harness.policy, harness.request("port_reconfigure_reconcile"),
		harness.runtime, harness.state,
	)
	if second.PortResult == nil || second.PortResult.Result != "applied" {
		t.Fatalf("second=%+v", second)
	}
	if harness.runtime.writeCalls != writes || harness.runtime.restartCalls != restarts {
		t.Fatalf("reconcile reapplied mutation writes=%d/%d restarts=%d/%d",
			writes, harness.runtime.writeCalls, restarts, harness.runtime.restartCalls)
	}
}

func TestSystemdPortReconcileWithoutLedgerClosesAsVerifiedUnchanged(t *testing.T) {
	harness := newSystemdPortHarness(t)
	response := executeSystemdPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure_reconcile"),
		harness.runtime,
		harness.state,
	)
	if response.Error != nil ||
		response.PortResult == nil ||
		response.PortResult.Status != "succeeded" ||
		response.PortResult.Result != systemdPortResultUnchanged ||
		response.PortResult.AppliedPort != harness.plan.OldPort ||
		response.PortResult.EndpointRevision != harness.plan.TargetEndpointRevision+1 {
		t.Fatalf("response=%+v", response)
	}
	if harness.runtime.consumeCalls != 1 ||
		harness.runtime.writeCalls != 0 ||
		harness.runtime.restartCalls != 0 {
		t.Fatalf(
			"unstarted reconcile mutated service: consume=%d writes=%d restarts=%d",
			harness.runtime.consumeCalls,
			harness.runtime.writeCalls,
			harness.runtime.restartCalls,
		)
	}
	ledger, err := harness.state.LoadJob(harness.plan.TargetID, harness.plan.JobID)
	if err != nil ||
		ledger == nil ||
		ledger.State != systemdPortLedgerTerminal ||
		ledger.Result == nil ||
		ledger.Result.Result != systemdPortResultUnchanged {
		t.Fatalf("terminal unchanged ledger=%+v err=%v", ledger, err)
	}
}

func TestSystemdPortTransactionAllowsForwardOnlyEndpointGenerationGap(t *testing.T) {
	harness := newSystemdPortHarness(t)
	harness.plan.ExpectedEndpointRevision += 2
	harness.plan.TargetEndpointRevision = harness.plan.ExpectedEndpointRevision + 1
	harness.plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, harness.plan)

	response := executeSystemdPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if response.Error != nil ||
		response.PortResult == nil ||
		response.PortResult.Result != systemdPortResultApplied ||
		response.PortResult.EndpointRevision != harness.plan.TargetEndpointRevision {
		t.Fatalf("forward endpoint generation gap response=%+v", response)
	}
}

func TestSystemdPortTransactionRejectsRootEndpointAheadOfPlan(t *testing.T) {
	harness := newSystemdPortHarness(t)
	harness.policy.Targets[0].EndpointRevision = harness.plan.ExpectedEndpointRevision + 1
	policySHA, err := harness.policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	harness.plan.ExpectedExecutorPolicySHA256 = policySHA
	harness.plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, harness.plan)

	response := executeSystemdPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if response.Error == nil ||
		response.Error.Code != "config_mismatch" ||
		harness.runtime.consumeCalls != 0 ||
		harness.runtime.writeCalls != 0 ||
		harness.runtime.restartCalls != 0 {
		t.Fatalf("root endpoint regression was not rejected: %+v", response)
	}
}

func TestSystemdPortCommitRepairsCrashAfterAppliedStateSave(t *testing.T) {
	harness := newSystemdPortHarness(t)
	harness.runtime.crashAt = "after_applied_state_save"
	first := executeSystemdPortRequest(
		context.Background(), harness.policy, harness.request("port_reconfigure"),
		harness.runtime, harness.state,
	)
	if first.Error == nil || first.Error.Code != "reconcile_required" {
		t.Fatalf("first=%+v", first)
	}
	ledger, err := harness.state.LoadJob(harness.plan.TargetID, harness.plan.JobID)
	if err != nil || ledger == nil || ledger.State != systemdPortLedgerCommitting ||
		ledger.Result == nil || ledger.Result.Result != systemdPortResultApplied {
		t.Fatalf("commit ledger=%+v err=%v", ledger, err)
	}
	applied, err := harness.state.LoadApplied(harness.plan.TargetID)
	if err != nil || applied == nil ||
		applied.Port != harness.plan.NewPort ||
		applied.EndpointRevision != harness.plan.TargetEndpointRevision {
		t.Fatalf("applied=%+v err=%v", applied, err)
	}
	writes, restarts := harness.runtime.writeCalls, harness.runtime.restartCalls

	// Model an executor restart by constructing a fresh runtime over the
	// already-written sidecar while keeping only the durable state store.
	restartedRuntime := &fakeSystemdPortRuntime{
		current: append([]byte(nil), harness.runtime.current...),
	}
	second := executeSystemdPortRequest(
		context.Background(), harness.policy, harness.request("port_reconfigure_reconcile"),
		restartedRuntime, harness.state,
	)
	if second.PortResult == nil ||
		second.PortResult.Result != systemdPortResultApplied {
		if second.Error != nil {
			t.Fatalf("second error=%s response=%+v", second.Error.Code, second)
		}
		t.Fatalf("second=%+v", second)
	}
	if restartedRuntime.writeCalls != 0 || restartedRuntime.restartCalls != 0 {
		t.Fatalf(
			"commit repair repeated mutation writes=%d restarts=%d (first=%d/%d)",
			restartedRuntime.writeCalls, restartedRuntime.restartCalls, writes, restarts,
		)
	}
	ledger, err = harness.state.LoadJob(harness.plan.TargetID, harness.plan.JobID)
	if err != nil || ledger == nil || ledger.State != systemdPortLedgerTerminal {
		t.Fatalf("repaired ledger=%+v err=%v", ledger, err)
	}
}

func TestSystemdPortRollbackFailedIsTerminalQuarantineNotPermanentBusy(t *testing.T) {
	harness := newSystemdPortHarness(t)
	harness.runtime.restartErr = errors.New("restart unavailable")
	first := executeSystemdPortRequest(
		context.Background(), harness.policy, harness.request("port_reconfigure"),
		harness.runtime, harness.state,
	)
	if first.PortResult == nil ||
		first.PortResult.Result != systemdPortResultRollbackFailed {
		t.Fatalf("first=%+v", first)
	}
	ledger, err := harness.state.LoadJob(harness.plan.TargetID, harness.plan.JobID)
	if err != nil || ledger == nil || ledger.State != systemdPortLedgerTerminal ||
		ledger.Result == nil ||
		ledger.Result.Result != systemdPortResultRollbackFailed {
		t.Fatalf("quarantined ledger=%+v err=%v", ledger, err)
	}

	harness.runtime.restartErr = nil
	harness.plan = nextSystemdPortPlan(
		t, harness.plan, 28084, harness.plan.TargetEndpointRevision,
	)
	// An operator-safe reconciliation refreshes the root policy to the
	// Panel's quarantined endpoint generation while preserving the verified
	// old listener/config tuple. No unverified applied overlay is invented.
	harness.policy.ProjectionRevision++
	harness.policy.PolicyRevision++
	harness.policy.Targets[0].EndpointRevision = harness.plan.ExpectedEndpointRevision
	policySHA, err := harness.policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	harness.plan.ExpectedUpdaterPolicyRevision = harness.policy.ProjectionRevision
	harness.plan.ExpectedExecutorPolicyRevision = harness.policy.PolicyRevision
	harness.plan.ExpectedExecutorPolicySHA256 = policySHA
	harness.plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, harness.plan)
	second := executeSystemdPortRequest(
		context.Background(), harness.policy, harness.request("port_reconfigure"),
		harness.runtime, harness.state,
	)
	if second.Error != nil && second.Error.Code == "target_busy" {
		t.Fatalf("terminal rollback quarantine permanently blocked target: %+v", second)
	}
	if second.PortResult == nil ||
		second.PortResult.Result != systemdPortResultApplied {
		if second.Error != nil {
			t.Fatalf("second error=%s response=%+v", second.Error.Code, second)
		}
		t.Fatalf("second=%+v", second)
	}
}

func TestSystemdPortPreviousStateResultsAdvanceEndpointFenceForNextJob(t *testing.T) {
	for _, resultKind := range []string{
		systemdPortResultRolledBack,
		systemdPortResultUnchanged,
	} {
		t.Run(resultKind, func(t *testing.T) {
			harness := newSystemdPortHarness(t)
			switch resultKind {
			case systemdPortResultRolledBack:
				harness.runtime.verifyNewErr = errors.New("new endpoint failed")
				response := executeSystemdPortRequest(
					context.Background(), harness.policy,
					harness.request("port_reconfigure"),
					harness.runtime, harness.state,
				)
				if response.PortResult == nil ||
					response.PortResult.Result != systemdPortResultRolledBack {
					t.Fatalf("rollback=%+v", response)
				}
				harness.runtime.verifyNewErr = nil
			case systemdPortResultUnchanged:
				harness.runtime.crashAt = "after_grant_consume"
				response := executeSystemdPortRequest(
					context.Background(), harness.policy,
					harness.request("port_reconfigure"),
					harness.runtime, harness.state,
				)
				if response.Error == nil ||
					response.Error.Code != "reconcile_required" {
					t.Fatalf("uncertain=%+v", response)
				}
				harness.runtime.crashAt = ""
				response = executeSystemdPortRequest(
					context.Background(), harness.policy,
					harness.request("port_reconfigure_reconcile"),
					harness.runtime, harness.state,
				)
				if response.PortResult == nil ||
					response.PortResult.Result != systemdPortResultUnchanged ||
					response.PortResult.Status != "succeeded" {
					t.Fatalf("unchanged=%+v", response)
				}
			}
			applied, err := harness.state.LoadApplied(harness.plan.TargetID)
			if err != nil || applied == nil ||
				applied.EndpointRevision != harness.plan.TargetEndpointRevision+1 ||
				applied.Port != harness.plan.OldPort {
				t.Fatalf("previous-state applied fence=%+v err=%v", applied, err)
			}

			harness.plan = nextSystemdPortPlan(
				t, harness.plan, 28084, applied.EndpointRevision,
			)
			next := executeSystemdPortRequest(
				context.Background(), harness.policy,
				harness.request("port_reconfigure"),
				harness.runtime, harness.state,
			)
			if next.PortResult == nil ||
				next.PortResult.Result != systemdPortResultApplied {
				t.Fatalf("next=%+v", next)
			}
		})
	}
}

func nextSystemdPortPlan(
	t *testing.T,
	previous SystemdPortReconfigurePlan,
	newPort int,
	expectedEndpointRevision int64,
) SystemdPortReconfigurePlan {
	t.Helper()
	next := previous
	next.JobID = "job-port-two"
	next.OldPort = previous.OldPort
	next.NewPort = newPort
	next.ExpectedEndpointRevision = expectedEndpointRevision
	next.TargetEndpointRevision = next.ExpectedEndpointRevision + 1
	next.ExpectedConfigRevision = previous.ExpectedConfigRevision
	next.TargetConfigRevision = next.ExpectedConfigRevision + 1
	next.ExpectedConfigSHA256 = previous.ExpectedConfigSHA256
	next.TargetConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		"worker", "127.0.0.1", newPort, next.TargetConfigRevision,
	))
	next.LeaseGeneration++
	next.SessionID = "port-session-two-0123456789"
	next.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, next)
	return next
}

func validSystemdPortReconfigurePlan(t *testing.T) SystemdPortReconfigurePlan {
	t.Helper()
	plan := SystemdPortReconfigurePlan{
		JobID: "job-port-one", HostID: "host-a", TargetID: "worker-01",
		ServiceType: "worker", NetworkNamespace: "host", Protocol: "tcp",
		OldPort: 8084, NewPort: 18084,
		ExpectedEndpointRevision: 4, TargetEndpointRevision: 5,
		ExpectedConfigRevision: 11, TargetConfigRevision: 12,
		ExpectedConfigSHA256: systemdPortSidecarSHA256(
			systemdPortSidecarBytes("worker", "127.0.0.1", 8084, 11),
		),
		TargetConfigSHA256: systemdPortSidecarSHA256(
			systemdPortSidecarBytes("worker", "127.0.0.1", 18084, 12),
		),
		ExpectedSourcePolicyRevision:   6,
		ExpectedUpdaterPolicyRevision:  7,
		ExpectedExecutorPolicyRevision: 8,
		ExpectedExecutorPolicySHA256:   "sha256:" + strings.Repeat("e", 64),
		OwnershipEpoch:                 3,
		LeaseGeneration:                2,
		SessionID:                      "port-session-0123456789abcdef",
	}
	plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, plan)
	return plan
}

func mustSystemdPortPlanSHA256(t *testing.T, plan SystemdPortReconfigurePlan) string {
	t.Helper()
	digest, err := plan.ComputePortPlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type systemdPortHarness struct {
	policy  LocalExecutorPolicy
	plan    SystemdPortReconfigurePlan
	runtime *fakeSystemdPortRuntime
	state   systemdPortStateStore
}

func newSystemdPortHarness(t *testing.T) systemdPortHarness {
	t.Helper()
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 6
	policy.ProjectionRevision = 7
	policy.PolicyRevision = 8
	policy.Targets[0].EndpointRevision = 4
	old := systemdPortSidecarBytes("worker", "127.0.0.1", 8084, 11)
	policy.Targets[0].LocalListen = LocalExecutorEndpoint{Host: "127.0.0.1", Port: 8084}
	policy.Targets[0].ConfigRevision = 11
	policy.Targets[0].ConfigSHA256 = systemdPortSidecarSHA256(old)
	policySHA, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	plan := validSystemdPortReconfigurePlan(t)
	plan.ExpectedExecutorPolicySHA256 = policySHA
	plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, plan)
	runtime := &fakeSystemdPortRuntime{current: append([]byte(nil), old...)}
	return systemdPortHarness{
		policy: policy, plan: plan, runtime: runtime,
		state: newMemorySystemdPortStateStore(),
	}
}

func (h systemdPortHarness) request(operation string) LocalExecutorRequest {
	return LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: operation,
		ServiceID: h.plan.TargetID, PortPlan: &h.plan,
		SourcePolicyRevision:    h.plan.ExpectedSourcePolicyRevision,
		OwnershipEpoch:          h.plan.OwnershipEpoch,
		OwnershipPolicyRevision: h.plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision:  h.plan.ExpectedExecutorPolicyRevision,
		MutationGrant:           NewBoundedSecret("one-time-mutation-grant"),
	}
}

type fakeSystemdPortRuntime struct {
	current                []byte
	consumeCalls           int
	writeCalls             int
	restartCalls           int
	panelCallsAfterConsume int
	verifyNewErr           error
	verifyOldErr           error
	writeErr               error
	restartErr             error
	crashAt                string
}

func (f *fakeSystemdPortRuntime) Checkpoint(_ systemdPortAdapter) (systemdPortSidecarCheckpoint, error) {
	return newSystemdPortSidecarCheckpoint(true, 0o600, f.current), nil
}

func (f *fakeSystemdPortRuntime) EnsurePortAvailable(LocalExecutorEndpoint) error { return nil }

func (f *fakeSystemdPortRuntime) ConsumeGrant(
	context.Context, SystemdPortReconfigurePlan, string, string, BoundedSecret,
) error {
	f.consumeCalls++
	return nil
}

func (f *fakeSystemdPortRuntime) Write(
	_ systemdPortAdapter, _ systemdPortSidecarCheckpoint, body []byte,
) error {
	f.writeCalls++
	if f.writeErr != nil {
		return f.writeErr
	}
	f.current = append([]byte(nil), body...)
	return nil
}

func (f *fakeSystemdPortRuntime) Restore(
	_ systemdPortAdapter, checkpoint systemdPortSidecarCheckpoint, _ []byte,
) error {
	f.writeCalls++
	f.current = append([]byte(nil), checkpoint.Bytes...)
	return nil
}

func (f *fakeSystemdPortRuntime) Restart(context.Context, LocalExecutorTarget) error {
	f.restartCalls++
	return f.restartErr
}

func (f *fakeSystemdPortRuntime) Verify(
	_ context.Context, _ LocalExecutorPolicy, target LocalExecutorTarget,
) (string, error) {
	if target.LocalListen.Port == 18084 {
		return "v1.2.3", f.verifyNewErr
	}
	return "v1.2.3", f.verifyOldErr
}

func (f *fakeSystemdPortRuntime) CrashPoint(name string) error {
	if f.crashAt == name {
		return errSystemdPortSimulatedCrash
	}
	return nil
}
