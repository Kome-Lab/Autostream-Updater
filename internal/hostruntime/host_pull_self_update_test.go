package hostruntime

import (
	"context"
	"strings"
	"testing"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

func TestHostPullRuntimeRequirementGatesClaimAgainstRootExecutorState(t *testing.T) {
	previousVersion := controlversion.Version
	controlversion.Version = "v1.7.8"
	t.Cleanup(func() {
		controlversion.Version = previousVersion
	})

	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	executor := &hostSelfUpdateControllerTestExecutor{
		status: HostSelfUpdateRuntimeStatus{
			State:                   state,
			CurrentSlot:             HostSelfUpdateSlotA,
			ExecutorVersion:         "v1.7.8",
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		},
	}
	controller, err := NewHostSelfUpdateController(
		executor,
		HostSelfUpdateControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	agent := &HostPullAgent{SelfUpdate: controller}
	binding := HostAgentBinding{
		ExecutionHostID: "host-a", OwnershipEpoch: 3,
	}
	policy := HostAgentPolicy{
		Revision: 11, SourcePolicyRevision: 7,
		LocalExecutorPolicyRevision: 9,
		RuntimeRequirement: &HostRuntimeRequirement{
			MinimumAgentVersion:     "v1.7.8",
			MinimumExecutorVersion:  "v1.7.8",
			AgentProtocolVersion:    2,
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
			MutationProtocolVersion: LocalExecutorMutationProtocolVersion,
			RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
		},
	}
	if err := agent.validateRuntimeForClaim(
		context.Background(), binding, policy,
	); err != nil {
		t.Fatalf("compatible root runtime blocked claim: %v", err)
	}
	request := validHostSelfUpdateRequest()
	policy.SelfUpdate = &request
	if err := agent.validateRuntimeForClaim(
		context.Background(), binding, policy,
	); err == nil || !strings.Contains(err.Error(), "target is not active") {
		t.Fatalf("pending runtime generation did not block claim: %v", err)
	}
	policy.SelfUpdate = nil

	executor.status.CurrentSlot = HostSelfUpdateSlotB
	if err := agent.validateRuntimeForClaim(
		context.Background(), binding, policy,
	); err == nil || !strings.Contains(err.Error(), "not stable") {
		t.Fatalf("current-link drift did not block claim: %v", err)
	}
	executor.status.CurrentSlot = HostSelfUpdateSlotA
	executor.status.ExecutorVersion = "v1.7.7"
	if err := agent.validateRuntimeForClaim(
		context.Background(), binding, policy,
	); err == nil || !strings.Contains(err.Error(), "not stable") {
		t.Fatalf("old root executor did not block claim: %v", err)
	}
}

func TestHostAgentPolicySelfUpdateRequiresCompatibleRuntimeContract(t *testing.T) {
	request := validHostSelfUpdateRequest()
	base := HostAgentPolicy{
		ServiceID: "host-agent-a", TransportMode: HostTransportPullV2,
		ExecutionHostID: "host-a", OwnershipEpoch: 3,
		Revision: 11, SourcePolicyRevision: 7,
		LocalExecutorPolicyRevision: 9,
		LocalExecutorPolicySHA256:   "sha256:" + strings.Repeat("a", 64),
		RuntimeRequirement: &HostRuntimeRequirement{
			MinimumAgentVersion:     request.AgentVersion,
			MinimumExecutorVersion:  request.ExecutorVersion,
			AgentProtocolVersion:    request.AgentProtocolVersion,
			ExecutorProtocolVersion: request.ExecutorProtocolVersion,
			MutationProtocolVersion: request.MutationProtocolVersion,
			RecoveryProtocolVersion: request.RecoveryProtocolVersion,
		},
		SelfUpdate:         &request,
		SelfUpdateID:       "self-update-a",
		SelfUpdateRevision: 1,
		SelfUpdateStatus:   "queued",
	}
	if err := base.validateForService("host-agent-a", 0); err != nil {
		t.Fatalf("compatible self-update policy rejected: %v", err)
	}

	withoutRequirement := base
	withoutRequirement.RuntimeRequirement = nil
	if err := withoutRequirement.validateForService(
		"host-agent-a", 0,
	); err == nil {
		t.Fatal("self-update policy without a runtime requirement was accepted")
	}
	incompatible := base
	requirement := *base.RuntimeRequirement
	requirement.MinimumExecutorVersion = "v1.9.0"
	incompatible.RuntimeRequirement = &requirement
	if err := incompatible.validateForService(
		"host-agent-a", 0,
	); err == nil {
		t.Fatal("self-update below the required executor version was accepted")
	}
}
