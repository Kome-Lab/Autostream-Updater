package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// recoverExpiredHostSelfUpdate is run by the fixed slot-specific recovery
// timers. Only the binary in the root-owned healthy slot may act. The pending
// binary therefore cannot suppress or impersonate rollback if it crash-loops.
func (rt *hostSelfUpdateExecutorRuntime) recoverExpiredHostSelfUpdate(
	ctx context.Context,
	recoverySlot string,
) (HostSelfUpdateRuntimeStatus, error) {
	if !validHostSelfUpdateSlot(recoverySlot) {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update recovery slot is invalid")
	}
	state, err := rt.loadPersistedState()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update recovery state is unavailable")
		}
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if state.ActiveSlot != state.HealthySlot ||
		(state.Phase != HostSelfUpdatePhaseStable &&
			state.PendingSlot != otherHostSelfUpdateSlot(state.HealthySlot)) {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update recovery state slot binding is invalid")
	}
	status := HostSelfUpdateRuntimeStatus{
		State:                   state,
		CurrentSlot:             state.HealthySlot,
		ExecutorVersion:         rt.executorVersion,
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		LastAction:              HostSelfUpdateActionNone,
	}
	if recoverySlot != state.HealthySlot {
		return status, nil
	}
	if rt.executorVersion != state.ActiveExecutorVersion ||
		state.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update recovery binary is incompatible with the healthy slot")
	}
	if err := rt.prepare(); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	preparedState, err := rt.loadPersistedState()
	if err != nil || preparedState != state {
		return HostSelfUpdateRuntimeStatus{},
			errors.New("host self-update recovery state changed during preparation")
	}
	state = preparedState
	status.State = state
	switch state.Phase {
	case HostSelfUpdatePhaseStable, HostSelfUpdatePhaseStaged:
		return status, nil
	case HostSelfUpdatePhaseActivating, HostSelfUpdatePhaseVerifying:
		if rt.now().UTC().Before(state.ActivationDeadline) {
			return status, nil
		}
		status.State = beginHostSelfUpdateRollback(state)
		if err := rt.saveState(status.State); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	case HostSelfUpdatePhaseRollingBack:
		// A previous executor persisted the failure fence before attempting
		// any filesystem or service mutation. Resume that exact rollback.
	default:
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update recovery state is invalid")
	}

	if err := rt.reconstructCurrent(status.State.HealthySlot); err != nil {
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
			"%w: watchdog restore current slot",
			errHostSelfUpdateRollback,
		)
	}
	status.CurrentSlot = status.State.HealthySlot
	status.RollbackRequested = true
	status.RestartRequested = true
	if err := rt.restartLocalExecutor(ctx); err != nil {
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
			"%w: watchdog restart healthy executor",
			errHostSelfUpdateRollback,
		)
	}
	if err := rt.verifyHealthyLocalExecutor(
		ctx,
		status.State.HealthySlot,
		status.State,
	); err != nil {
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
			"%w: watchdog verify healthy executor",
			errHostSelfUpdateRollback,
		)
	}
	if err := rt.restartHostAgent(ctx); err != nil {
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
			"%w: watchdog restart healthy agent",
			errHostSelfUpdateRollback,
		)
	}
	status.State = clearRolledBackHostSelfUpdate(status.State)
	status.LastAction = HostSelfUpdateActionRollbackComplete
	if err := rt.saveState(status.State); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	return status, nil
}
