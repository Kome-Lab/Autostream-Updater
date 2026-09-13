package hostruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePortExecutionResultBindsDockerMappingToImmutablePlan(t *testing.T) {
	plan := newDockerPortHarness(t).plan
	t.Run("deployment_mode_spoof", func(t *testing.T) {
		result := appliedPortExecutionResult(plan)
		if err := result.Validate(); err != nil {
			t.Fatalf("systemd-mode spoof fixture must remain structurally valid: %v", err)
		}
		if err := validatePortExecutionResult(plan, result); err == nil {
			t.Fatal("systemd-mode response for an immutable Docker plan was accepted")
		}
	})
	for _, resultKind := range []string{
		systemdPortResultApplied,
		systemdPortResultRolledBack,
		systemdPortResultUnchanged,
	} {
		t.Run(resultKind+"_exact", func(t *testing.T) {
			result := dockerPortExecutionResultForTest(plan, resultKind)
			if err := validatePortExecutionResult(plan, result); err != nil {
				t.Fatalf("exact Docker result rejected: %v", err)
			}
		})
		t.Run(resultKind+"_container_spoof", func(t *testing.T) {
			result := dockerPortExecutionResultForTest(plan, resultKind)
			result.Docker.AppliedContainerPort++
			if err := result.Validate(); err != nil {
				t.Fatalf("spoof fixture must remain structurally valid: %v", err)
			}
			if err := validatePortExecutionResult(plan, result); err == nil {
				t.Fatal("structurally valid Docker container-port spoof was accepted")
			}
		})
		t.Run(resultKind+"_published_spoof", func(t *testing.T) {
			result := dockerPortExecutionResultForTest(plan, resultKind)
			result.Docker.AppliedPublishedPort++
			result.Docker.AppliedHealthPort++
			if err := result.Validate(); err != nil {
				t.Fatalf("spoof fixture must remain structurally valid: %v", err)
			}
			if err := validatePortExecutionResult(plan, result); err == nil {
				t.Fatal("structurally valid Docker published-port spoof was accepted")
			}
		})
	}
}

func TestHostPullExecutorReadinessAllowsOnlyLegacySystemdObserverBackfill(t *testing.T) {
	agent, _, _, binding, policy := newHostPullExecutionHarness(t, false)
	reportedDigest := "sha256:" + strings.Repeat("c", 64)
	observation := HostTargetObservation{
		ServiceID:      policy.Targets[0].ServiceID,
		Availability:   TargetAvailabilityAvailable,
		PolicyRevision: policy.LocalExecutorPolicyRevision,
		PolicySHA256:   policy.LocalExecutorPolicySHA256,
		ConfigRevision: policy.Targets[0].appliedConfigRevision(),
		ConfigSHA256:   reportedDigest,
	}

	assertCapabilities := func(
		t *testing.T,
		binding HostAgentBinding,
		policy HostAgentPolicy,
		observation HostTargetObservation,
		wantExecutor, wantMutation bool,
	) {
		t.Helper()
		capabilities := agent.capabilities(
			binding, &policy, []HostTargetObservation{observation}, false,
		)
		if capabilities["update_executor"] != wantExecutor ||
			capabilities["mutation_enabled"] != wantMutation ||
			capabilities["observe_only"] != !wantMutation {
			t.Fatalf(
				"capabilities=%+v, want update_executor=%t mutation_enabled=%t observe_only=%t",
				capabilities, wantExecutor, wantMutation, !wantMutation,
			)
		}
	}

	observerBinding := binding
	observerBinding.OwnershipEpoch = 0
	observerPolicy := policy
	observerPolicy.OwnershipEpoch = 0
	observerPolicy.ObserveOnly = true
	observerPolicy.Targets = append(
		[]HostAgentPolicyTarget(nil), policy.Targets...,
	)
	observerPolicy.Targets[0].AppliedConfigSHA256 = ""
	assertCapabilities(
		t, observerBinding, observerPolicy, observation, true, false,
	)

	for name, mutate := range map[string]func(
		*HostAgentBinding, *HostAgentPolicy, *HostTargetObservation,
	){
		"empty reported digest": func(_ *HostAgentBinding, _ *HostAgentPolicy, observation *HostTargetObservation) {
			observation.ConfigSHA256 = ""
		},
		"invalid reported digest": func(_ *HostAgentBinding, _ *HostAgentPolicy, observation *HostTargetObservation) {
			observation.ConfigSHA256 = "sha256:not-a-digest"
		},
		"explicit applied digest mismatch": func(_ *HostAgentBinding, policy *HostAgentPolicy, _ *HostTargetObservation) {
			policy.Targets[0].AppliedConfigSHA256 = "sha256:" + strings.Repeat("d", 64)
		},
		"docker target without applied digest": func(_ *HostAgentBinding, policy *HostAgentPolicy, _ *HostTargetObservation) {
			policy.Targets[0].DeploymentMode = ModeDocker
		},
		"active owner without applied digest": func(binding *HostAgentBinding, policy *HostAgentPolicy, _ *HostTargetObservation) {
			binding.OwnershipEpoch = 1
			policy.OwnershipEpoch = 1
			policy.ObserveOnly = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateBinding := observerBinding
			candidatePolicy := observerPolicy
			candidatePolicy.Targets = append(
				[]HostAgentPolicyTarget(nil), observerPolicy.Targets...,
			)
			candidateObservation := observation
			mutate(
				&candidateBinding, &candidatePolicy, &candidateObservation,
			)
			assertCapabilities(
				t, candidateBinding, candidatePolicy, candidateObservation, false, false,
			)
		})
	}
}

func TestHostPullExecutionClaimsServerOwnedHostAndCompletesThroughLocalExecutor(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if len(panel.claims) != 1 || panel.claims[0] != (HostPullClaimRequest{
		UpdaterID: binding.ServiceID, HostID: binding.ExecutionHostID,
		LeaseGeneration: 1, Fence: binding.OwnershipEpoch,
	}) {
		t.Fatalf("claims=%+v", panel.claims)
	}
	if executor.stageCalls != 1 || executor.applyCalls != 1 || executor.reconcileCalls != 0 {
		t.Fatalf("executor calls stage=%d apply=%d reconcile=%d", executor.stageCalls, executor.applyCalls, executor.reconcileCalls)
	}
	if len(executor.applyFences) != 1 || executor.applyFences[0].SourcePolicyRevision != policy.SourcePolicyRevision {
		t.Fatalf("apply fences=%+v policy source revision=%d", executor.applyFences, policy.SourcePolicyRevision)
	}
	if len(panel.grants) != 1 {
		t.Fatalf("grants=%d", len(panel.grants))
	}
	grant := panel.grants[0]
	if grant.TransportMode != HostTransportPullV2 ||
		grant.OwnershipEpoch != binding.OwnershipEpoch ||
		grant.PolicyRevision != policy.Revision ||
		grant.HostID != binding.ExecutionHostID ||
		grant.ServiceType != panel.job.EffectiveType() ||
		grant.Operation != "apply" {
		t.Fatalf("grant=%+v", grant)
	}
	if len(panel.reports) == 0 || panel.reports[len(panel.reports)-1].Status != "succeeded" {
		t.Fatalf("reports=%+v", panel.reports)
	}
	foundHealthChecking := false
	for _, report := range panel.reports {
		if report.Status == "health_checking" && report.Progress == 90 {
			foundHealthChecking = true
		}
		if report.Status == "reconciling" {
			t.Fatalf("certain apply unexpectedly reconciled: %+v", panel.reports)
		}
	}
	if !foundHealthChecking {
		t.Fatalf("certain apply skipped health_checking/90: %+v", panel.reports)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("terminal report left active job: %+v", active)
	}
	payload, err := os.ReadFile(filepath.Join(agent.StateDir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "ast_mutation_") ||
		strings.Contains(string(payload), strings.Repeat("l", 48)) {
		t.Fatalf("journal persisted a bearer secret: %s", payload)
	}
}
