package hostruntime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func (rt hostSelfUpdateExecutorRuntime) failClosedUncertainStage(
	status HostSelfUpdateRuntimeStatus,
	request HostSelfUpdateRequest,
	authorization HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateRuntimeStatus, error) {
	if err := status.validate(); err != nil ||
		status.State.Phase != HostSelfUpdatePhaseStable ||
		status.CurrentSlot != status.State.ActiveSlot ||
		status.State.ActiveSlot != status.State.HealthySlot ||
		request.validate() != nil ||
		authorization.validate() != nil ||
		authorization.Binding.Operation != "stage" ||
		authorization.Binding.AttemptGeneration != request.Generation ||
		authorization.Binding.AgentVersion != request.AgentVersion ||
		authorization.Binding.ExecutorVersion != request.ExecutorVersion ||
		authorization.Binding.ReleaseCommit != request.Commit ||
		authorization.Binding.ArtifactSHA256 != request.ArtifactSHA256 ||
		authorization.Binding.AgentProtocolVersion != request.AgentProtocolVersion ||
		authorization.Binding.ExecutorProtocolVersion != request.ExecutorProtocolVersion ||
		authorization.Binding.MutationProtocolVersion != request.MutationProtocolVersion ||
		authorization.Binding.RecoveryProtocolVersion != request.RecoveryProtocolVersion ||
		!sameHostSelfUpdateReleaseIdentity(
			authorization.Binding.Release,
			request.Release,
		) {
		return HostSelfUpdateRuntimeStatus{},
			errors.New("uncertain host self-update stage binding is invalid")
	}
	grant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil ||
		grant == nil ||
		grant.Phase != hostSelfUpdateGrantPhasePrepared ||
		!grant.matches(authorization) {
		return HostSelfUpdateRuntimeStatus{},
			errors.New("uncertain host self-update stage fence is unavailable")
	}

	// Persist the generation failure before converting the prepared grant to
	// its receipt-free failed terminal. If the process stops between these
	// operations, status() observes the durable fence and completes the exact,
	// credential-free journal convergence on its next run.
	status.State.FailedGeneration = request.Generation
	if err := rt.saveState(status.State); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := rt.cleanFailedHostSelfUpdateGrant(status.State); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	status.LastAction = HostSelfUpdateActionNone
	return status, nil
}

func (rt *hostSelfUpdateExecutorRuntime) convergeHostSelfUpdateStageAfterError(
	request HostSelfUpdateRequest,
	authorization HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateRuntimeStatus, bool, error) {
	if err := rt.prepare(); err != nil {
		return HostSelfUpdateRuntimeStatus{}, false,
			fmt.Errorf("prepare host self-update stage error recovery: %w", err)
	}
	status, err := rt.status()
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, false,
			fmt.Errorf("recover host self-update stage error: %w", err)
	}
	phase, matches, err := rt.hostSelfUpdateGrantPhase(authorization)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, false, err
	}
	switch {
	case matches &&
		phase == hostSelfUpdateGrantPhaseApplied &&
		rt.hostSelfUpdateStateEffectMatchesGrant(
			status.State,
			authorization.Binding,
		):
		return status, true, nil
	case matches &&
		phase == hostSelfUpdateGrantPhaseFailed &&
		status.State.Phase == HostSelfUpdatePhaseStable &&
		status.State.FailedGeneration == request.Generation:
		return status, false, nil
	default:
		return HostSelfUpdateRuntimeStatus{}, false,
			errors.New("host self-update stage error did not durably converge")
	}
}

func (rt hostSelfUpdateExecutorRuntime) cleanFailedHostSelfUpdateGrant(
	state HostSelfUpdateState,
) error {
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.FailedGeneration == "" {
		return nil
	}
	grant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil || grant == nil {
		return err
	}
	if !failedHostSelfUpdateStateMatchesStageGrant(state, grant) {
		return nil
	}
	if grant.Phase == hostSelfUpdateGrantPhaseFailed {
		return nil
	}
	grant.Phase = hostSelfUpdateGrantPhaseFailed
	grant.Receipt = nil
	return saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		*grant,
		!rt.allowTestPaths,
	)
}

func failedHostSelfUpdateStateMatchesStageGrant(
	state HostSelfUpdateState,
	grant *hostSelfUpdateGrantState,
) bool {
	return grant != nil &&
		state.Phase == HostSelfUpdatePhaseStable &&
		state.FailedGeneration != "" &&
		grant.Binding.Operation == "stage" &&
		grant.Binding.AttemptGeneration == state.FailedGeneration &&
		(grant.Phase == hostSelfUpdateGrantPhasePrepared ||
			grant.Phase == hostSelfUpdateGrantPhaseConsumed ||
			grant.Phase == hostSelfUpdateGrantPhaseApplied ||
			grant.Phase == hostSelfUpdateGrantPhaseFailed)
}

func (rt hostSelfUpdateExecutorRuntime) removeHostSelfUpdateGrantState() error {
	if err := os.Remove(rt.grantStatePath); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return errors.New("remove failed host self-update grant state")
	}
	if err := syncDirectory(filepath.Dir(rt.grantStatePath)); err != nil {
		return errors.New("sync failed host self-update grant cleanup")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) recoverDurableHostSelfUpdateGrant(
	state HostSelfUpdateState,
) (HostSelfUpdateState, error) {
	grant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil || grant == nil {
		return state, err
	}
	if failedHostSelfUpdateStateMatchesStageGrant(state, grant) {
		if err := rt.cleanFailedHostSelfUpdateGrant(state); err != nil {
			return HostSelfUpdateState{}, err
		}
		return state, nil
	}
	if grant.Phase == hostSelfUpdateGrantPhaseApplied {
		if rt.hostSelfUpdateStateEffectMatchesGrant(state, grant.Binding) {
			return state, nil
		}
		return HostSelfUpdateState{},
			errors.New("applied host self-update grant contradicts runtime state")
	}

	switch grant.Binding.Operation {
	case "stage":
		if state.Phase == HostSelfUpdatePhaseStable {
			if grant.Phase == hostSelfUpdateGrantPhaseConsumed &&
				rt.hostSelfUpdateStateEffectMatchesGrant(
					state,
					grant.Binding,
				) {
				if err := rt.markDurableHostSelfUpdateGrantApplied(
					grant,
				); err != nil {
					return HostSelfUpdateState{}, err
				}
				return state, nil
			}
			if state.FailedGeneration != grant.Binding.AttemptGeneration {
				state.FailedGeneration = grant.Binding.AttemptGeneration
				if err := rt.saveState(state); err != nil {
					return HostSelfUpdateState{}, err
				}
			}
			if err := rt.cleanFailedHostSelfUpdateGrant(state); err != nil {
				return HostSelfUpdateState{}, err
			}
			return state, nil
		}
		if grant.Phase == hostSelfUpdateGrantPhaseConsumed &&
			rt.hostSelfUpdateStateEffectMatchesGrant(
				state,
				grant.Binding,
			) {
			if err := rt.markDurableHostSelfUpdateGrantApplied(
				grant,
			); err != nil {
				return HostSelfUpdateState{}, err
			}
			return state, nil
		}
	case "reconcile":
		if grant.Phase == hostSelfUpdateGrantPhasePrepared {
			if err := rt.removeHostSelfUpdateGrantState(); err != nil {
				return HostSelfUpdateState{}, err
			}
			return state, nil
		}
		if grant.Phase == hostSelfUpdateGrantPhaseConsumed &&
			rt.hostSelfUpdateStateEffectMatchesGrant(
				state,
				grant.Binding,
			) {
			if err := rt.markDurableHostSelfUpdateGrantApplied(
				grant,
			); err != nil {
				return HostSelfUpdateState{}, err
			}
			return state, nil
		}
	}
	return HostSelfUpdateState{},
		errors.New("durable host self-update grant contradicts runtime state")
}

func (rt hostSelfUpdateExecutorRuntime) markDurableHostSelfUpdateGrantApplied(
	state *hostSelfUpdateGrantState,
) error {
	if state == nil ||
		state.Phase != hostSelfUpdateGrantPhaseConsumed ||
		state.Receipt == nil {
		return errors.New("durable host self-update grant receipt is unavailable")
	}
	state.Phase = hostSelfUpdateGrantPhaseApplied
	return saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		*state,
		!rt.allowTestPaths,
	)
}
