package hostruntime

import (
	"context"
	"errors"
	"fmt"
)

func (rt runtimeCredentialExecutorRuntime) activateCredential(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	if !exists {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: staged credential is unavailable", errRuntimeCredentialPrecondition,
		)
	}
	if current.Phase == RuntimeCredentialPhaseActivated {
		return current, nil
	}
	if current.Phase != RuntimeCredentialPhaseProofReady ||
		request.RuntimeCredential.RotationRevision != current.RotationRevision {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: heartbeat proof is required", errRuntimeCredentialPrecondition,
		)
	}
	staged, stagedBytes, _, err := rt.loadIdentity(
		rt.stagedIdentity, policy.AgentGID,
	)
	if err != nil ||
		staged.NodeID != current.ServiceID ||
		staged.PanelURL != policy.Mutation.PanelURL ||
		runtimeCredentialDigest(stagedBytes) != current.StagedIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"staged runtime credential activation input changed",
		)
	}
	if rt.activate == nil {
		return RuntimeCredentialStatus{}, errRuntimeCredentialStateUnavailable
	}
	rotation, err := rt.activate(
		ctx,
		policy.Mutation.PanelURL,
		current.RotationID,
		current.RotationRevision,
		staged.RuntimeToken,
		rt.httpClient,
	)
	if err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := validateRuntimeCredentialPanelTransition(
		rotation, current, "activated", current.RotationRevision+1,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.validateIdentityLayout(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.writeIdentityAtomic(
		rt.activeIdentity, stagedBytes, policy.AgentGID, true,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.validateIdentityLayout(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	_, activeBytes, _, err := rt.loadIdentity(
		rt.activeIdentity, policy.AgentGID,
	)
	if err != nil ||
		runtimeCredentialDigest(activeBytes) != current.StagedIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"activated runtime credential secure reread failed",
		)
	}
	current.Phase = RuntimeCredentialPhaseActivated
	current.RotationRevision = rotation.Revision
	current.ActiveIdentitySHA256 = current.StagedIdentitySHA256
	current.activeRuntimeTokenSHA256 =
		current.stagedRuntimeTokenSHA256
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.wipeAndRemoveIdentity(
		rt.stagedIdentity, policy.AgentGID, current.StagedIdentitySHA256,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) cancel(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	if !exists {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: tracked runtime credential state is unavailable",
			errRuntimeCredentialPrecondition,
		)
	}
	if current.Phase == RuntimeCredentialPhaseActivated {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: activated credential cannot be cancelled", errRuntimeCredentialPrecondition,
		)
	}
	if request.RuntimeCredential.RotationRevision < current.RotationRevision {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: cancel revision is stale", errRuntimeCredentialPrecondition,
		)
	}
	switch current.Phase {
	case RuntimeCredentialPhaseCancelReady:
		switch request.RuntimeCredential.RotationRevision {
		case current.RotationRevision:
			// Idempotent replay after the first cancel response was lost.
			return current, nil
		case current.RotationRevision + 1:
		default:
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: cancel acknowledgement revision is invalid",
				errRuntimeCredentialPrecondition,
			)
		}
		current.Phase = RuntimeCredentialPhaseCancelled
		current.RotationRevision = request.RuntimeCredential.RotationRevision
		if err := rt.removeState(); err != nil {
			return RuntimeCredentialStatus{}, err
		}
		return current, nil
	case RuntimeCredentialPhaseClaimPrepared,
		RuntimeCredentialPhaseStageBound,
		RuntimeCredentialPhaseStaged,
		RuntimeCredentialPhaseLocalStaged,
		RuntimeCredentialPhaseProofReady,
		RuntimeCredentialPhaseExpired:
		if request.RuntimeCredential.RotationRevision !=
			current.RotationRevision+1 {
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: cancel request revision is invalid",
				errRuntimeCredentialPrecondition,
			)
		}
		_, activeBytes, _, err := rt.loadIdentity(
			rt.activeIdentity, policy.AgentGID,
		)
		if err != nil ||
			runtimeCredentialDigest(activeBytes) !=
				current.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, errors.New(
				"previous Host Agent identity changed before cancel",
			)
		}
		current.Phase = RuntimeCredentialPhaseCancelReady
		current.RotationRevision =
			request.RuntimeCredential.RotationRevision
		current.ActiveIdentitySHA256 =
			current.PreviousIdentitySHA256
		current.activeRuntimeTokenSHA256 =
			current.previousRuntimeTokenSHA256
		if err := rt.saveStatus(current); err != nil {
			return RuntimeCredentialStatus{}, err
		}
		// Persist cancel_ready before destroying the staged secret. If this
		// process stops during the wipe, loadAndReconcileStatus completes the
		// exact-digest cleanup before the panel acknowledgement is allowed.
		if err := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity, policy.AgentGID, current.StagedIdentitySHA256,
		); err != nil {
			return RuntimeCredentialStatus{}, err
		}
		return current, nil
	default:
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: rotation cannot be cancelled from this phase",
			errRuntimeCredentialPrecondition,
		)
	}
}

func (rt runtimeCredentialExecutorRuntime) finalize(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	if !exists ||
		(current.Phase != RuntimeCredentialPhaseActivated &&
			current.Phase != RuntimeCredentialPhaseManualRecovered) ||
		request.RuntimeCredential.RotationRevision !=
			current.RotationRevision {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: terminal runtime credential state is unavailable",
			errRuntimeCredentialPrecondition,
		)
	}
	_, activeBytes, _, err := rt.loadIdentity(
		rt.activeIdentity, policy.AgentGID,
	)
	if err != nil ||
		runtimeCredentialDigest(activeBytes) != current.ActiveIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"terminal runtime credential active identity changed",
		)
	}
	if !rt.identityCleanupComplete() {
		return RuntimeCredentialStatus{}, errors.New(
			"terminal runtime credential staged cleanup is incomplete",
		)
	}
	if err := rt.removeState(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}
