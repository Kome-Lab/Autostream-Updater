package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

func (rt hostSelfUpdateExecutorRuntime) activate(
	ctx context.Context,
	generation string,
) (HostSelfUpdateRuntimeStatus, error) {
	status, err := rt.status()
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if status.State.Phase != HostSelfUpdatePhaseStaged ||
		status.State.PendingGeneration != generation {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf("%w: generation is not staged", errHostSelfUpdatePrecondition)
	}
	if status.CurrentSlot != status.State.HealthySlot {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf(
				"%w: healthy rollback slot is not current",
				errHostSelfUpdatePrecondition,
			)
	}
	if err := rt.validateHostSelfUpdateSlotTree(
		status.State.HealthySlot,
	); err != nil {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf(
				"%w: healthy rollback slot is unsafe: %v",
				errHostSelfUpdatePrecondition,
				err,
			)
	}
	if err := rt.verifyPendingHostSelfUpdateSlot(ctx, status.State); err != nil {
		failed, failErr := rt.failStagedHostSelfUpdate(status.State)
		if failErr != nil {
			return HostSelfUpdateRuntimeStatus{}, errors.Join(err, failErr)
		}
		status.State = failed
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf(
				"%w: staged slot verification failed: %v",
				errHostSelfUpdatePrecondition,
				err,
			)
	}
	next, err := BeginHostSelfUpdateActivation(
		status.State,
		rt.now().UTC(),
		rt.verificationTimeout,
	)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := rt.saveState(next); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := rt.switchCurrent(next.PendingSlot); err != nil {
		rollback := beginHostSelfUpdateRollback(next)
		if saveErr := rt.saveState(rollback); saveErr != nil {
			return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
				"%w: switch current failed and rollback fence could not be persisted: %v",
				errHostSelfUpdateRollback,
				saveErr,
			)
		}
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
			"%w: switch current failed: %v",
			errHostSelfUpdateRollback,
			err,
		)
	}
	status.State = next
	status.CurrentSlot = next.PendingSlot
	status.LastAction = HostSelfUpdateActionSwitchCurrent
	status.RestartRequested = true
	if err := rt.restartHostAgent(ctx); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	return status, nil
}

func (rt hostSelfUpdateExecutorRuntime) reconcile(
	ctx context.Context,
	proof HostSelfUpdateAgentProof,
) (HostSelfUpdateRuntimeStatus, error) {
	status, err := rt.mutationStatus()
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	observation := HostSelfUpdateObservation{
		CurrentSlot:           status.CurrentSlot,
		RunningAgentVersion:   proof.RunningAgentVersion,
		PanelHeartbeatVersion: proof.PanelHeartbeatVersion,
		HeartbeatGeneration:   proof.HeartbeatGeneration,
		ExecutorVersion:       rt.executorVersion,
		ExecutorProtocol:      LocalExecutorMutationProtocolVersion,
	}
	if status.State.Phase != HostSelfUpdatePhaseStable &&
		(status.State.Phase == HostSelfUpdatePhaseRollingBack ||
			status.CurrentSlot == status.State.PendingSlot) {
		observation.ExecutorProbeGeneration = status.State.PendingGeneration
		expectedExecutor := status.State.PendingExecutorVersion
		if status.State.Phase == HostSelfUpdatePhaseRollingBack {
			expectedExecutor = status.State.ActiveExecutorVersion
		}
		observation.ExecutorHealthy = rt.executorVersion == expectedExecutor
		if !observation.ExecutorHealthy {
			observation.ExecutorFailureCode = "executor_probe_failed"
		}
	}
	if proof.FailureCode != "" {
		observation.ExecutorHealthy = false
		observation.ExecutorFailureCode = proof.FailureCode
	}
	if (status.State.Phase == HostSelfUpdatePhaseActivating ||
		status.State.Phase == HostSelfUpdatePhaseVerifying) &&
		!rt.now().UTC().Before(status.State.ActivationDeadline) {
		observation.ExecutorHealthy = false
		observation.ExecutorFailureCode = "verification_timeout"
	}
	next, action, err := ReconcileHostSelfUpdate(status.State, observation)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	status.State = next
	status.LastAction = action
	switch action {
	case HostSelfUpdateActionSwitchCurrent:
		if err := rt.verifyPendingHostSelfUpdateSlot(ctx, next); err != nil {
			rollback := beginHostSelfUpdateRollback(next)
			if saveErr := rt.saveState(rollback); saveErr != nil {
				return HostSelfUpdateRuntimeStatus{}, errors.Join(
					fmt.Errorf(
						"%w: resumed staged slot verification failed: %v",
						errHostSelfUpdateRollback,
						err,
					),
					saveErr,
				)
			}
			return HostSelfUpdateRuntimeStatus{},
				fmt.Errorf(
					"%w: resumed staged slot verification failed: %v",
					errHostSelfUpdateRollback,
					err,
				)
		}
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		if err := rt.switchCurrent(next.PendingSlot); err != nil {
			rollback := beginHostSelfUpdateRollback(next)
			if saveErr := rt.saveState(rollback); saveErr != nil {
				return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
					"%w: switch current failed and rollback fence could not be persisted: %v",
					errHostSelfUpdateRollback,
					saveErr,
				)
			}
			return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
				"%w: switch current failed: %v",
				errHostSelfUpdateRollback,
				err,
			)
		}
		status.CurrentSlot = next.PendingSlot
		status.RestartRequested = true
		if err := rt.restartHostAgent(ctx); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	case HostSelfUpdateActionRestoreHealthy:
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		if err := rt.switchCurrent(next.HealthySlot); err != nil {
			return HostSelfUpdateRuntimeStatus{},
				fmt.Errorf("%w: restore current slot", errHostSelfUpdateRollback)
		}
		status.CurrentSlot = next.HealthySlot
		status.RollbackRequested = true
		status.RestartRequested = true
		if err := rt.restartHostAgent(ctx); err != nil {
			return HostSelfUpdateRuntimeStatus{},
				fmt.Errorf("%w: restart healthy agent", errHostSelfUpdateRollback)
		}
	case HostSelfUpdateActionRestartAgent:
		if err := rt.verifyPendingHostSelfUpdateSlot(ctx, next); err != nil {
			rollback := beginHostSelfUpdateRollback(next)
			if saveErr := rt.saveState(rollback); saveErr != nil {
				return HostSelfUpdateRuntimeStatus{}, errors.Join(
					fmt.Errorf(
						"%w: resumed pending slot verification failed: %v",
						errHostSelfUpdateRollback,
						err,
					),
					saveErr,
				)
			}
			return HostSelfUpdateRuntimeStatus{},
				fmt.Errorf(
					"%w: resumed pending slot verification failed: %v",
					errHostSelfUpdateRollback,
					err,
				)
		}
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		status.RestartRequested = true
		if err := rt.restartHostAgent(ctx); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	case HostSelfUpdateActionRestartHealthy:
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		status.RestartRequested = true
		if err := rt.restartHostAgent(ctx); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	default:
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	}
	return status, nil
}

func (rt hostSelfUpdateExecutorRuntime) verifyPendingHostSelfUpdateSlot(
	ctx context.Context,
	state HostSelfUpdateState,
) error {
	if err := state.validate(); err != nil ||
		state.Phase == HostSelfUpdatePhaseStable {
		return errors.New("pending host self-update state is invalid")
	}
	request := HostSelfUpdateRequest{
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
	return rt.verifyHostSelfUpdateSlot(
		ctx,
		state.PendingSlot,
		filepath.Join(rt.slotsRoot, state.PendingSlot),
		request,
		hostSelfUpdateSlotDigests{
			AgentSHA256:    state.PendingAgentSHA256,
			ExecutorSHA256: state.PendingExecutorSHA256,
		},
	)
}

func (rt hostSelfUpdateExecutorRuntime) failStagedHostSelfUpdate(
	state HostSelfUpdateState,
) (HostSelfUpdateState, error) {
	if err := state.validate(); err != nil ||
		state.Phase != HostSelfUpdatePhaseStaged {
		return HostSelfUpdateState{},
			errors.New("staged host self-update failure state is invalid")
	}
	failed := clearRolledBackHostSelfUpdate(state)
	if err := rt.saveState(failed); err != nil {
		return HostSelfUpdateState{}, err
	}
	if err := rt.cleanFailedHostSelfUpdateGrant(failed); err != nil {
		return HostSelfUpdateState{}, err
	}
	return failed, nil
}
