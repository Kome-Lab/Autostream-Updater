package hostruntime

import (
	"errors"
	"path/filepath"
	"strings"
)

func validateHostSelfUpdateGrantReplayBinding(
	policy LocalExecutorPolicy,
	fence LocalExecutorMutationFence,
	operation string,
	request *HostSelfUpdateRequest,
	proof *HostSelfUpdateAgentProof,
	authorization HostSelfUpdateGrantAuthorization,
) error {
	if err := authorization.validate(); err != nil {
		return err
	}
	binding := authorization.Binding
	if binding.Operation != operation ||
		binding.ExecutionHostID != policy.HostID ||
		binding.ExpectedOwnershipEpoch != fence.OwnershipEpoch ||
		binding.ExpectedSourcePolicyRevision != policy.SourcePolicyRevision ||
		binding.ExpectedSourcePolicyRevision != fence.SourcePolicyRevision ||
		binding.ExpectedProjectionRevision != policy.ProjectionRevision ||
		binding.ExpectedProjectionRevision != fence.OwnershipPolicyRevision ||
		binding.ExpectedLocalExecutorPolicyRevision != policy.PolicyRevision ||
		binding.ExpectedLocalExecutorPolicyRevision != fence.ExecutorPolicyRevision {
		return errors.New("host self-update grant replay policy binding is invalid")
	}
	policySHA256, err := policy.SHA256()
	if err != nil ||
		binding.ExpectedLocalExecutorPolicySHA256 != policySHA256 {
		return errors.New("host self-update grant replay policy digest is invalid")
	}
	expected := hostSelfUpdateRequestForGrantBinding(binding)
	if err := expected.validate(); err != nil {
		return errors.New("host self-update grant replay release binding is invalid")
	}
	expectedPlanSHA256, err := hostSelfUpdateGrantPlanSHA256(
		operation,
		HostAgentPolicy{
			SelfUpdateID:       binding.SelfUpdateID,
			SelfUpdateRevision: binding.ExpectedSelfUpdateRevision,
		},
		expected,
		fence,
	)
	if err != nil || binding.PlanSHA256 != expectedPlanSHA256 {
		return errors.New("host self-update grant replay plan binding is invalid")
	}
	switch operation {
	case "stage":
		if request == nil ||
			proof != nil ||
			!sameHostSelfUpdateRequestIdentity(*request, expected) {
			return errors.New("host self-update stage replay binding is invalid")
		}
	case "reconcile":
		if request != nil || proof == nil || proof.validate() != nil {
			return errors.New("host self-update reconcile replay binding is invalid")
		}
		if proof.HeartbeatGeneration != "" &&
			proof.HeartbeatGeneration != expected.Generation {
			return errors.New("host self-update reconcile generation is invalid")
		}
		if proof.PanelHeartbeatVersion != "" &&
			proof.PanelHeartbeatVersion != expected.AgentVersion {
			return errors.New("host self-update reconcile heartbeat version is invalid")
		}
		if proof.FailureCode == "" &&
			proof.RunningAgentVersion != "" &&
			proof.RunningAgentVersion != expected.AgentVersion {
			return errors.New("host self-update reconcile running version is invalid")
		}
	default:
		return errors.New("host self-update grant replay operation is invalid")
	}
	return nil
}

func hostSelfUpdateRequestForGrantBinding(
	binding HostSelfUpdateGrantBinding,
) HostSelfUpdateRequest {
	return HostSelfUpdateRequest{
		Generation:              binding.AttemptGeneration,
		AgentVersion:            binding.AgentVersion,
		ExecutorVersion:         binding.ExecutorVersion,
		Commit:                  binding.ReleaseCommit,
		ArtifactSHA256:          binding.ArtifactSHA256,
		AgentProtocolVersion:    binding.AgentProtocolVersion,
		ExecutorProtocolVersion: binding.ExecutorProtocolVersion,
		MutationProtocolVersion: binding.MutationProtocolVersion,
		RecoveryProtocolVersion: binding.RecoveryProtocolVersion,
		Release:                 binding.Release,
	}
}

func sameHostSelfUpdateRequestIdentity(
	left HostSelfUpdateRequest,
	right HostSelfUpdateRequest,
) bool {
	return left.Generation == right.Generation &&
		left.AgentVersion == right.AgentVersion &&
		left.ExecutorVersion == right.ExecutorVersion &&
		left.Commit == right.Commit &&
		left.ArtifactSHA256 == right.ArtifactSHA256 &&
		left.AgentProtocolVersion == right.AgentProtocolVersion &&
		left.ExecutorProtocolVersion == right.ExecutorProtocolVersion &&
		left.MutationProtocolVersion == right.MutationProtocolVersion &&
		left.RecoveryProtocolVersion == right.RecoveryProtocolVersion &&
		sameHostSelfUpdateReleaseIdentity(left.Release, right.Release)
}

func (rt hostSelfUpdateExecutorRuntime) hostSelfUpdateStateEffectMatchesGrant(
	state HostSelfUpdateState,
	binding HostSelfUpdateGrantBinding,
) bool {
	if state.Phase == HostSelfUpdatePhaseStable &&
		state.FailedGeneration == binding.AttemptGeneration {
		return true
	}
	request := hostSelfUpdateRequestForGrantBinding(binding)
	if request.validate() != nil {
		return false
	}
	slot := state.PendingSlot
	digests := hostSelfUpdateSlotDigests{
		AgentSHA256:    state.PendingAgentSHA256,
		ExecutorSHA256: state.PendingExecutorSHA256,
	}
	if state.Phase == HostSelfUpdatePhaseStable {
		current, err := rt.readCurrentSlot()
		if err != nil ||
			current != state.ActiveSlot ||
			state.ActiveSlot != state.HealthySlot ||
			state.ActiveAgentVersion != binding.AgentVersion ||
			state.ActiveExecutorVersion != binding.ExecutorVersion {
			return false
		}
		slot = state.ActiveSlot
		digests, err = rt.hostSelfUpdateSlotMarkerDigests(slot)
		if err != nil {
			return false
		}
	} else if !hostSelfUpdatePendingMatchesGrant(state, binding) {
		return false
	}
	ctx, cancel := rt.hostSelfUpdateDetachedVerificationContext()
	defer cancel()
	return rt.verifyHostSelfUpdateSlot(
		ctx,
		slot,
		filepath.Join(rt.slotsRoot, slot),
		request,
		digests,
	) == nil
}

func (rt hostSelfUpdateExecutorRuntime) hostSelfUpdateSlotMarkerDigests(
	slot string,
) (hostSelfUpdateSlotDigests, error) {
	if !validHostSelfUpdateSlot(slot) {
		return hostSelfUpdateSlotDigests{},
			errors.New("host self-update grant slot is invalid")
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	var digests hostSelfUpdateSlotDigests
	for _, marker := range []struct {
		name        string
		destination *string
	}{
		{".agent-sha256", &digests.AgentSHA256},
		{".local-executor-sha256", &digests.ExecutorSHA256},
	} {
		body, err := readHostSelfUpdateSlotMarker(
			filepath.Join(slotRoot, marker.name),
			!rt.allowTestPaths,
		)
		if err != nil {
			return hostSelfUpdateSlotDigests{}, err
		}
		*marker.destination = strings.TrimSuffix(string(body), "\n")
	}
	if err := digests.validate(); err != nil {
		return hostSelfUpdateSlotDigests{}, err
	}
	return digests, nil
}

func validateHostSelfUpdateGrantForOperation(
	policy LocalExecutorPolicy,
	fence LocalExecutorMutationFence,
	operation string,
	request *HostSelfUpdateRequest,
	state HostSelfUpdateState,
	authorization HostSelfUpdateGrantAuthorization,
) error {
	if err := authorization.validate(); err != nil {
		return err
	}
	binding := authorization.Binding
	if binding.Operation != operation ||
		binding.ExecutionHostID != policy.HostID ||
		binding.ExpectedOwnershipEpoch != fence.OwnershipEpoch ||
		binding.ExpectedSourcePolicyRevision != policy.SourcePolicyRevision ||
		binding.ExpectedSourcePolicyRevision != fence.SourcePolicyRevision ||
		binding.ExpectedProjectionRevision != policy.ProjectionRevision ||
		binding.ExpectedProjectionRevision != fence.OwnershipPolicyRevision ||
		binding.ExpectedLocalExecutorPolicyRevision != policy.PolicyRevision ||
		binding.ExpectedLocalExecutorPolicyRevision != fence.ExecutorPolicyRevision {
		return errors.New("host self-update grant policy binding is invalid")
	}
	policySHA256, err := policy.SHA256()
	if err != nil ||
		binding.ExpectedLocalExecutorPolicySHA256 != policySHA256 {
		return errors.New("host self-update grant policy digest is invalid")
	}
	var expected HostSelfUpdateRequest
	switch operation {
	case "stage":
		if request == nil ||
			state.Phase != HostSelfUpdatePhaseStable ||
			request.Generation == state.FailedGeneration {
			return errors.New("host self-update stage grant state is invalid")
		}
		expected = *request
	case "reconcile":
		if request != nil ||
			state.Phase == HostSelfUpdatePhaseStable ||
			state.Phase == HostSelfUpdatePhaseStaged {
			return errors.New("host self-update reconcile grant state is invalid")
		}
		expected = HostSelfUpdateRequest{
			Generation:              state.PendingGeneration,
			AgentVersion:            state.PendingAgentVersion,
			ExecutorVersion:         state.PendingExecutorVersion,
			Commit:                  state.PendingCommit,
			ArtifactSHA256:          state.PendingArtifactSHA256,
			AgentProtocolVersion:    state.PendingAgentProtocol,
			ExecutorProtocolVersion: state.PendingExecutorProtocol,
			MutationProtocolVersion: state.PendingMutationProtocol,
			RecoveryProtocolVersion: state.PendingRecoveryProtocol,
			Release:                 state.PendingRelease,
		}
	default:
		return errors.New("host self-update grant operation is invalid")
	}
	if err := expected.validate(); err != nil ||
		binding.AttemptGeneration != expected.Generation ||
		binding.AgentVersion != expected.AgentVersion ||
		binding.ExecutorVersion != expected.ExecutorVersion ||
		binding.ReleaseCommit != expected.Commit ||
		binding.ArtifactSHA256 != expected.ArtifactSHA256 ||
		binding.AgentProtocolVersion != expected.AgentProtocolVersion ||
		binding.ExecutorProtocolVersion != expected.ExecutorProtocolVersion ||
		binding.MutationProtocolVersion != expected.MutationProtocolVersion ||
		binding.RecoveryProtocolVersion != expected.RecoveryProtocolVersion ||
		!sameHostSelfUpdateReleaseIdentity(
			binding.Release,
			expected.Release,
		) {
		return errors.New("host self-update grant release binding is invalid")
	}
	expectedPlanSHA256, err := hostSelfUpdateGrantPlanSHA256(
		operation,
		HostAgentPolicy{
			SelfUpdateID:       binding.SelfUpdateID,
			SelfUpdateRevision: binding.ExpectedSelfUpdateRevision,
		},
		expected,
		fence,
	)
	if err != nil || binding.PlanSHA256 != expectedPlanSHA256 {
		return errors.New("host self-update grant plan binding is invalid")
	}
	return nil
}

func hostSelfUpdatePendingMatchesGrant(
	state HostSelfUpdateState,
	binding HostSelfUpdateGrantBinding,
) bool {
	return state.PendingGeneration == binding.AttemptGeneration &&
		state.PendingAgentVersion == binding.AgentVersion &&
		state.PendingExecutorVersion == binding.ExecutorVersion &&
		state.PendingCommit == binding.ReleaseCommit &&
		state.PendingArtifactSHA256 == binding.ArtifactSHA256 &&
		state.PendingAgentProtocol == binding.AgentProtocolVersion &&
		state.PendingExecutorProtocol == binding.ExecutorProtocolVersion &&
		state.PendingMutationProtocol == binding.MutationProtocolVersion &&
		state.PendingRecoveryProtocol == binding.RecoveryProtocolVersion &&
		sameHostSelfUpdateReleaseIdentity(
			state.PendingRelease,
			binding.Release,
		)
}
