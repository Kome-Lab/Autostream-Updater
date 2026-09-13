package hostruntime

import (
	"context"
	"errors"
)

func (rt *hostSelfUpdateExecutorRuntime) authorizeHostSelfUpdate(
	ctx context.Context,
	panelURL string,
	authorization HostSelfUpdateGrantAuthorization,
) error {
	next := newHostSelfUpdateGrantState(authorization)
	existing, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil {
		return err
	}
	if existing != nil && existing.matches(authorization) {
		if existing.Phase == hostSelfUpdateGrantPhaseConsumed ||
			existing.Phase == hostSelfUpdateGrantPhaseApplied ||
			existing.Phase == hostSelfUpdateGrantPhaseFailed {
			return nil
		}
		next = *existing
	} else if existing != nil {
		if existing.Phase == hostSelfUpdateGrantPhasePrepared &&
			rt.now().UTC().Before(existing.Binding.ExpiresAt) {
			return errors.New("another host self-update grant consume result is uncertain")
		}
		if existing.Phase == hostSelfUpdateGrantPhaseConsumed {
			return errors.New("a consumed host self-update grant is not durably applied")
		}
	}
	if err := saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		next,
		!rt.allowTestPaths,
	); err != nil {
		return err
	}
	result, err := rt.consumeGrant(ctx, panelURL, authorization)
	if err != nil {
		if ctx.Err() == nil {
			result, err = rt.consumeGrant(ctx, panelURL, authorization)
		}
		if err != nil {
			return errHostSelfUpdateGrantUncertain
		}
	}
	if err := result.Grant.validate(true); err != nil ||
		!sameHostSelfUpdateGrantBinding(
			result.Grant,
			authorization.Binding,
		) {
		return errors.New("host self-update grant consume receipt is invalid")
	}
	next.Phase = hostSelfUpdateGrantPhaseConsumed
	next.Receipt = &result.Grant
	return saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		next,
		!rt.allowTestPaths,
	)
}

func (rt *hostSelfUpdateExecutorRuntime) markHostSelfUpdateGrantApplied(
	authorization HostSelfUpdateGrantAuthorization,
) error {
	state, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil {
		return err
	}
	if state == nil ||
		!state.matches(authorization) {
		return errors.New("host self-update grant apply fence is unavailable")
	}
	if state.Phase == hostSelfUpdateGrantPhaseApplied {
		return nil
	}
	if state.Phase != hostSelfUpdateGrantPhaseConsumed {
		return errors.New("host self-update grant was not consumed")
	}
	state.Phase = hostSelfUpdateGrantPhaseApplied
	return saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		*state,
		!rt.allowTestPaths,
	)
}

func (rt *hostSelfUpdateExecutorRuntime) hostSelfUpdateGrantApplied(
	authorization HostSelfUpdateGrantAuthorization,
) (bool, error) {
	phase, matches, err := rt.hostSelfUpdateGrantPhase(authorization)
	return matches && phase == hostSelfUpdateGrantPhaseApplied, err
}

func (rt *hostSelfUpdateExecutorRuntime) hostSelfUpdateGrantPhase(
	authorization HostSelfUpdateGrantAuthorization,
) (string, bool, error) {
	state, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil {
		return "", false, err
	}
	if state == nil || !state.matches(authorization) {
		return "", false, nil
	}
	return state.Phase, true, nil
}
