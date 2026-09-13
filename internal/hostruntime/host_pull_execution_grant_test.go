package hostruntime

import (
	"context"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"strings"
	"testing"
	"time"
)

func TestHostPullClaimRejectsMalformedLeaseCredential(t *testing.T) {
	_, panel, _, binding, policy := newHostPullExecutionHarness(t, false)
	for name, token := range map[string]string{
		"control":  "valid-prefix\nsecret",
		"oversize": strings.Repeat("x", (16<<10)+1),
	} {
		t.Run(name, func(t *testing.T) {
			job := *panel.job
			job.LeaseToken = token
			if err := validateHostPullClaim(job, panel.job.AgentServiceID, binding, policy); err == nil {
				t.Fatal("malformed lease credential was accepted")
			}
		})
	}
}

func TestHostPullV2PortClaimIsAuthoritativelyVersionless(t *testing.T) {
	_, panel, _, binding, policy := newHostPullPortExecutionHarness(t, false)
	legacy := *panel.job
	if err := validateHostPullClaim(legacy, legacy.AgentServiceID, binding, policy); err != nil {
		t.Fatalf("legacy version-bound port claim rejected: %v", err)
	}

	v2 := legacy
	v2.ProtocolVersion = 2
	v2.CommandID = "command-port-one"
	v2.LeaseToken = ""
	v2.CurrentVersion = ""
	v2.TargetVersion = ""
	v2.Version = ""
	if err := validateHostPullClaim(v2, v2.AgentServiceID, binding, policy); err != nil {
		t.Fatalf("versionless v2 port claim rejected: %v", err)
	}

	v2.CurrentVersion = "v0.0.0-port-placeholder"
	v2.TargetVersion = v2.CurrentVersion
	if err := validateHostPullClaim(v2, v2.AgentServiceID, binding, policy); err == nil {
		t.Fatal("v2 port claim accepted a synthetic version sentinel")
	}

	legacy.CurrentVersion = ""
	legacy.TargetVersion = ""
	if err := validateHostPullClaim(legacy, legacy.AgentServiceID, binding, policy); err == nil {
		t.Fatal("legacy port claim lost its canonical version requirement")
	}
}

func TestHostPullV2RecoveryClearUsesDedicatedSyntheticTerminalProof(t *testing.T) {
	agent, panel, _, binding, policy := newHostPullExecutionHarness(t, false)
	active := *panel.job
	active.ProtocolVersion = 2
	active.CommandID = "command-software-one"
	active.LeaseToken = ""
	if err := agent.Journal.SetActive(&active); err != nil {
		t.Fatal(err)
	}
	panel.clearActive = true
	panel.job = &UpdateJob{
		ProtocolVersion: 2,
		ID:              active.ID,
		AgentServiceID:  active.AgentServiceID,
		Status:          "canceled",
		RecoveryClear:   true,
	}
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("v2 recovery clear: %v", err)
	}
	if got := agent.Journal.Active(); got != nil {
		t.Fatalf("v2 recovery clear left active job: %+v", got)
	}
}

func TestValidateV2RecoveryClearRejectsIdentityAndCredentialMutants(t *testing.T) {
	_, panel, _, _, _ := newHostPullExecutionHarness(t, false)
	active := *panel.job
	active.ProtocolVersion = 2
	active.CommandID = "command-software-one"
	active.LeaseToken = ""
	valid := UpdateJob{
		ProtocolVersion: 2,
		ID:              active.ID,
		AgentServiceID:  active.AgentServiceID,
		Status:          "canceled",
		RecoveryClear:   true,
	}
	if err := validateV2RecoveryClear(active, valid, active.AgentServiceID); err != nil {
		t.Fatalf("valid v2 recovery clear rejected: %v", err)
	}
	mutants := map[string]func(*UpdateJob){
		"job":         func(job *UpdateJob) { job.ID = "job-other" },
		"service":     func(job *UpdateJob) { job.AgentServiceID = "updater-other" },
		"protocol":    func(job *UpdateJob) { job.ProtocolVersion = 1 },
		"token":       func(job *UpdateJob) { job.LeaseToken = "unexpected-token" },
		"lease":       func(job *UpdateJob) { job.LeaseGeneration = 1 },
		"nonterminal": func(job *UpdateJob) { job.Status = "claimed" },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateV2RecoveryClear(active, candidate, active.AgentServiceID); err == nil {
				t.Fatal("invalid synthetic recovery clear was accepted")
			}
		})
	}
	legacyActive := active
	legacyActive.ProtocolVersion = 1
	if err := validateV2RecoveryClear(legacyActive, valid, active.AgentServiceID); err == nil {
		t.Fatal("v2 synthetic recovery clear accepted a legacy active job")
	}
}

func TestHostPullSelectsV2SoftwareMutationWithoutLegacyFallback(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	job := *panel.job
	job.ProtocolVersion = 2
	job.CommandID = "command-software-one"
	job.LeaseToken = ""
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, job)
	if err != nil {
		t.Fatal(err)
	}
	grantBinding := hostPullV2SoftwareGrantBinding(t, agent.Bootstrap.NodeID, binding, policy, job, plan, "apply")
	panel.grantResults = []MutationGrant{{
		Token:     "ast_mutation_" + strings.Repeat("v", 43),
		V2Binding: &grantBinding,
	}}
	if _, err := agent.invokeExecutionMutation(
		context.Background(), panel, binding, policy, job, plan, "apply",
	); err != nil {
		t.Fatalf("invoke v2 apply: %v", err)
	}
	if executor.v2ApplyCalls != 1 || executor.applyCalls != 0 || executor.reconcileCalls != 0 {
		t.Fatalf("v2/legacy calls apply_v2=%d apply=%d reconcile=%d", executor.v2ApplyCalls, executor.applyCalls, executor.reconcileCalls)
	}
	if len(executor.v2Grants) != 1 || executor.v2Grants[0].Binding != grantBinding {
		t.Fatal("Local Executor did not receive the exact credential-free v2 binding")
	}
}

func TestHostPullV2GrantFailsClosedOnLegacyOnlyExecutor(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	job := *panel.job
	job.ProtocolVersion = 2
	job.CommandID = "command-software-one"
	job.LeaseToken = ""
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, job)
	if err != nil {
		t.Fatal(err)
	}
	grantBinding := hostPullV2SoftwareGrantBinding(t, agent.Bootstrap.NodeID, binding, policy, job, plan, "apply")
	panel.grantResults = []MutationGrant{{
		Token:     "ast_mutation_" + strings.Repeat("f", 43),
		V2Binding: &grantBinding,
	}}
	agent.Executor = hostPullLegacyOnlyMutationExecutor{inner: executor}
	if _, err := agent.invokeExecutionMutation(
		context.Background(), panel, binding, policy, job, plan, "apply",
	); err == nil {
		t.Fatal("v2 grant downgraded to a legacy-only executor")
	}
	if executor.applyCalls != 0 || executor.reconcileCalls != 0 {
		t.Fatal("legacy executor was invoked for a v2 grant")
	}
	if len(panel.grants) != 0 {
		t.Fatal("v2 grant was issued before executor capability was proven")
	}
}

func TestHostPullSelectsV2PortMutationWithoutSyntheticVersion(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	job := *panel.job
	job.ProtocolVersion = 2
	job.CommandID = "command-port-one"
	job.LeaseToken = ""
	job.CurrentVersion = ""
	job.TargetVersion = ""
	job.Version = ""
	plan, err := agent.preparePortExecutionPlan(policy, job)
	if err != nil {
		t.Fatal(err)
	}
	grantBinding := hostPullV2PortGrantBinding(t, agent.Bootstrap.NodeID, binding, policy, job, plan, "port_reconfigure")
	panel.grantResults = []MutationGrant{{
		Token:     "ast_mutation_" + strings.Repeat("p", 43),
		V2Binding: &grantBinding,
	}}
	if _, err := agent.invokePortExecutionMutation(
		context.Background(), panel, binding, policy, job, plan, "port_reconfigure",
	); err != nil {
		t.Fatalf("invoke v2 port mutation: %v", err)
	}
	if executor.v2PortApplyCalls != 1 || executor.portApplyCalls != 0 || executor.portReconCalls != 0 {
		t.Fatalf("v2/legacy port calls apply_v2=%d apply=%d reconcile=%d", executor.v2PortApplyCalls, executor.portApplyCalls, executor.portReconCalls)
	}
}

func TestHostPullRejectsTamperedV2SoftwareGrantBinding(t *testing.T) {
	agent, panel, _, binding, policy := newHostPullExecutionHarness(t, false)
	job := *panel.job
	job.ProtocolVersion = 2
	job.CommandID = "command-software-one"
	job.LeaseToken = ""
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, job)
	if err != nil {
		t.Fatal(err)
	}
	valid := hostPullV2SoftwareGrantBinding(t, agent.Bootstrap.NodeID, binding, policy, job, plan, "apply")
	tests := map[string]func(*contracts.UpdaterMutationGrantBinding){
		"job": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Lease.Command.MutationAuthorization.JobID = "job-other"
		},
		"updater": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Lease.Command.MutationAuthorization.UpdaterID = "updater-other"
		},
		"host": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Lease.Command.MutationAuthorization.HostID = "host-other"
		},
		"target": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Lease.Command.MutationAuthorization.Target.ServiceID = "worker-other"
		},
		"type": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Lease.Command.MutationAuthorization.Target.ServiceType = contracts.SystemUpdateTargetEncoderRecorder
		},
		"deployment": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Lease.Command.MutationAuthorization.Target.DeploymentMode = contracts.SystemUpdateDeploymentDocker
		},
		"desired revision": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Lease.Command.MutationAuthorization.DesiredRevision++
		},
		"fence": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Lease.Command.MutationAuthorization.Fence++
		},
		"operation": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.Operation = contracts.UpdaterMutationReconcile
		},
		"session": func(candidate *contracts.UpdaterMutationGrantBinding) {
			candidate.SessionID = "session-fedcba9876543210"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			hostPullRefreshV2CommandDigest(t, &candidate.Lease.Command)
			if err := validateV2SoftwareExecutionGrant(
				time.Now().UTC(), agent.Bootstrap.NodeID, binding, policy,
				job, plan, "apply", candidate,
			); err == nil {
				t.Fatal("tampered v2 binding was accepted")
			}
		})
	}
}
