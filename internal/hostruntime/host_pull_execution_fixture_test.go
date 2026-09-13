package hostruntime

import (
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"strings"
	"testing"
	"time"
)

func newHostPullExecutionHarness(t *testing.T, recovery bool) (*HostPullAgent, *hostPullExecutionTestPanel, *hostPullExecutionTestExecutor, HostAgentBinding, HostAgentPolicy) {
	t.Helper()
	bootstrap := managedHostAgentBootstrap("https://panel.example.com")
	binding := HostAgentBinding{
		ServiceID: bootstrap.NodeID, ServiceType: ServiceTypeUpdateAgent,
		TransportMode: HostTransportPullV2, ExecutionHostID: "host-a", OwnershipEpoch: 4,
	}
	policy := HostAgentPolicy{
		ServiceID: bootstrap.NodeID, TransportMode: HostTransportPullV2,
		ExecutionHostID: binding.ExecutionHostID, OwnershipEpoch: binding.OwnershipEpoch,
		Revision: 11, SourcePolicyRevision: 7, LocalExecutorPolicyRevision: 9,
		ObserveOnly:               false,
		LocalExecutorPolicySHA256: "sha256:" + strings.Repeat("b", 64),
		Targets: []HostAgentPolicyTarget{{
			ServiceID: "worker-01", ServiceType: "worker",
			DeploymentMode: ModeSystemd, AppliedConfigRevision: 1,
		}},
	}
	panel := &hostPullExecutionTestPanel{job: &UpdateJob{
		ID: "job-one", AgentServiceID: bootstrap.NodeID,
		HostID: binding.ExecutionHostID, TransportMode: HostTransportPullV2,
		OwnershipEpoch: binding.OwnershipEpoch, PolicyRevision: policy.Revision,
		TargetID: "worker-01", TargetType: "worker", ServiceType: "worker",
		DeploymentMode: ModeSystemd, CurrentVersion: "v1.0.0", TargetVersion: "v1.1.0",
		LeaseToken: strings.Repeat("l", 48), LeaseGeneration: 2, ReportSequence: 1,
		RecoveryRequired: recovery,
	}}
	executor := &hostPullExecutionTestExecutor{}
	agent, err := NewHostPullAgent(bootstrap, HostPullAgentOptions{
		StateDir: t.TempDir(), ControlPlane: panel,
		Executor: executor, Downloader: hostPullExecutionTestDownloader{},
		NewSessionID: func() (string, error) { return "session-0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(agent.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	agent.Journal = journal
	return agent, panel, executor, binding, policy
}

func newHostPullPortExecutionHarness(t *testing.T, recovery bool) (*HostPullAgent, *hostPullExecutionTestPanel, *hostPullExecutionTestExecutor, HostAgentBinding, HostAgentPolicy) {
	t.Helper()
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, recovery)
	expectedConfig := "sha256:" + strings.Repeat("d", 64)
	targetConfig := "sha256:" + strings.Repeat("e", 64)
	policy.Targets[0].AppliedConfigRevision = 3
	policy.Targets[0].AppliedConfigSHA256 = expectedConfig
	policy.Targets[0].LocalListenEndpoint = &HostAgentEndpoint{
		Host: "127.0.0.1", Port: 8084, PublicURL: "http://127.0.0.1:8084",
	}
	policy.Targets[0].DesiredEndpoint = &HostAgentEndpoint{
		Host: "127.0.0.1", Port: 9084, PublicURL: "http://127.0.0.1:9084",
	}
	panel.job.Operation = updateJobOperationPortReconfigure
	panel.job.CurrentVersion = "v1.0.0"
	panel.job.TargetVersion = "v1.0.0"
	panel.job.PortReconfigure = &SystemdPortMutationGrantBinding{
		NetworkNamespace:               systemdPortNetworkNamespaceHost,
		Protocol:                       systemdPortProtocolTCP,
		OldPort:                        8084,
		NewPort:                        9084,
		ExpectedEndpointRevision:       5,
		TargetEndpointRevision:         6,
		ExpectedConfigRevision:         3,
		TargetConfigRevision:           4,
		ExpectedConfigSHA256:           expectedConfig,
		TargetConfigSHA256:             targetConfig,
		ExpectedSourcePolicyRevision:   policy.SourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  policy.Revision,
		ExpectedExecutorPolicyRevision: policy.LocalExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   policy.LocalExecutorPolicySHA256,
		PortPlanSHA256:                 strings.Repeat("c", 64),
	}
	agent.PortExecutor = executor
	return agent, panel, executor, binding, policy
}

func hostPullV2SoftwareGrantBinding(
	t *testing.T,
	updaterID string,
	hostBinding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	plan MutationPlan,
	operation string,
) contracts.UpdaterMutationGrantBinding {
	t.Helper()
	target, ok := hostPullPolicyTarget(policy, job.TargetID)
	if !ok {
		t.Fatal("v2 software fixture target is unavailable")
	}
	command := hostPullV2CommandBase(
		updaterID, hostBinding, policy, job,
		contracts.UpdaterCapabilityUpdate,
		contracts.UpdaterTargetIdentity{
			TargetKind:             contracts.UpdaterTargetApplication,
			ServiceID:              job.TargetID,
			ServiceType:            contracts.SystemUpdateTargetType(target.ServiceType),
			DeploymentMode:         contracts.SystemUpdateDeploymentMode(target.DeploymentMode),
			ExpectedConfigRevision: target.appliedConfigRevision(),
		},
		contracts.UpdaterDesiredOperation{
			Operation: contracts.UpdaterDesiredSoftwareUpdate,
			SoftwareUpdate: &contracts.UpdaterSoftwareUpdateDesiredOperation{
				ExpectedCurrentVersion: plan.CurrentVersion,
				TargetVersion:          plan.TargetVersion,
				Strategy:               contracts.SystemUpdateWhenIdle,
			},
		},
	)
	hostPullRefreshV2CommandDigest(t, &command)
	return contracts.UpdaterMutationGrantBinding{
		Lease: contracts.UpdaterLeaseEnvelope{
			ProtocolVersion: 2,
			LeaseID:         "lease-software-one",
			LeaseGeneration: int64(job.LeaseGeneration),
			LeaseExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
			Command:         command,
		},
		Operation: contracts.UpdaterMutationOperation(operation),
		SessionID: plan.SessionID,
	}
}

func hostPullV2PortGrantBinding(
	t *testing.T,
	updaterID string,
	hostBinding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	plan SystemdPortReconfigurePlan,
	operation string,
) contracts.UpdaterMutationGrantBinding {
	t.Helper()
	target, ok := hostPullPolicyTarget(policy, job.TargetID)
	if !ok || job.PortReconfigure == nil {
		t.Fatal("v2 port fixture target or plan is unavailable")
	}
	desiredPort := &contracts.SystemUpdatePortReconfiguration{
		NetworkNamespace:               plan.NetworkNamespace,
		Protocol:                       contracts.SystemUpdatePortProtocol(plan.Protocol),
		OldPort:                        plan.OldPort,
		NewPort:                        plan.NewPort,
		ExpectedEndpointRevision:       plan.ExpectedEndpointRevision,
		TargetEndpointRevision:         plan.TargetEndpointRevision,
		ExpectedConfigRevision:         plan.ExpectedConfigRevision,
		TargetConfigRevision:           plan.TargetConfigRevision,
		ExpectedConfigSHA256:           plan.ExpectedConfigSHA256,
		TargetConfigSHA256:             plan.TargetConfigSHA256,
		ExpectedSourcePolicyRevision:   plan.ExpectedSourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		ExpectedExecutorPolicyRevision: plan.ExpectedExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   plan.ExpectedExecutorPolicySHA256,
		PortPlanSHA256:                 job.PortReconfigure.PortPlanSHA256,
	}
	command := hostPullV2CommandBase(
		updaterID, hostBinding, policy, job,
		contracts.UpdaterCapabilityPort,
		contracts.UpdaterTargetIdentity{
			TargetKind:             contracts.UpdaterTargetApplication,
			ServiceID:              job.TargetID,
			ServiceType:            contracts.SystemUpdateTargetType(target.ServiceType),
			DeploymentMode:         contracts.SystemUpdateDeploymentMode(target.DeploymentMode),
			ExpectedConfigRevision: target.appliedConfigRevision(),
		},
		contracts.UpdaterDesiredOperation{
			Operation:       contracts.UpdaterDesiredPortReconfigure,
			PortReconfigure: desiredPort,
		},
	)
	hostPullRefreshV2CommandDigest(t, &command)
	return contracts.UpdaterMutationGrantBinding{
		Lease: contracts.UpdaterLeaseEnvelope{
			ProtocolVersion: 2,
			LeaseID:         "lease-port-one",
			LeaseGeneration: int64(job.LeaseGeneration),
			LeaseExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
			Command:         command,
		},
		Operation: contracts.UpdaterMutationOperation(operation),
		SessionID: plan.SessionID,
	}
}

func hostPullV2CommandBase(
	updaterID string,
	hostBinding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	capability contracts.UpdaterCapability,
	target contracts.UpdaterTargetIdentity,
	desired contracts.UpdaterDesiredOperation,
) contracts.UpdaterCommandEnvelope {
	return contracts.UpdaterCommandEnvelope{
		ProtocolVersion: 2,
		CommandID:       job.CommandID,
		Issuer: contracts.UpdaterCommandIssuer{
			ServiceID:      "control-panel-one",
			ServiceType:    "control_panel",
			Authentication: "assignment_bound_rotating_service_identity",
			Permission:     "updates.authorize",
		},
		IdempotencyKey: "idempotency-one",
		MutationAuthorization: contracts.UpdaterMutationAuthorization{
			AuthorizationID:    "authorization-one",
			NonceID:            "nonce-0000000001",
			JobID:              job.ID,
			UpdaterID:          updaterID,
			HostID:             hostBinding.ExecutionHostID,
			ActionType:         capability,
			Target:             target,
			DesiredRevision:    policy.Revision,
			Fence:              hostBinding.OwnershipEpoch,
			ExpiresAt:          time.Now().UTC().Add(time.Hour),
			RequiredCapability: capability,
			OneTime:            true,
		},
		DesiredOperation:   desired,
		AuditCorrelationID: "audit-one",
	}
}

func hostPullRefreshV2CommandDigest(
	t *testing.T,
	command *contracts.UpdaterCommandEnvelope,
) {
	t.Helper()
	digest, err := contracts.ComputeUpdaterCommandCanonicalDigest(
		command.MutationAuthorization.Target,
		command.MutationAuthorization.DesiredRevision,
		command.MutationAuthorization.Fence,
		command.DesiredOperation,
	)
	if err != nil {
		t.Fatalf("compute v2 command digest: %v", err)
	}
	command.CanonicalPayloadDigest = digest
	command.MutationAuthorization.CanonicalArgumentDigest = digest
}
