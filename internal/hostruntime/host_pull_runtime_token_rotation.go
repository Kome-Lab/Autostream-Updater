package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

type HostRuntimeTokenRotationControlPlane interface {
	ClaimRuntimeTokenRotation(
		context.Context,
		Config,
		HostAgentRuntimeTokenRotation,
		string,
	) (RuntimeTokenRotationClaimResult, error)
	ProveRuntimeTokenRotation(
		context.Context,
		Config,
		HostAgentRuntimeTokenRotation,
		RuntimeTokenRotationHeartbeatProof,
	) (HostAgentRuntimeTokenRotation, error)
	AcknowledgeRuntimeTokenRotationCancel(
		context.Context,
		Config,
		HostAgentRuntimeTokenRotation,
	) (HostAgentRuntimeTokenRotation, error)
}

func (p panelRuntimeTokenRotationControlPlane) AcknowledgeRuntimeTokenRotationCancel(
	ctx context.Context,
	activeIdentity Config,
	rotation HostAgentRuntimeTokenRotation,
) (HostAgentRuntimeTokenRotation, error) {
	return AcknowledgeRuntimeTokenRotationCancel(
		ctx,
		activeIdentity.PanelURL,
		rotation.ID,
		rotation.Revision,
		activeIdentity.RuntimeToken,
		p.HTTPClient,
	)
}

type panelRuntimeTokenRotationControlPlane struct {
	HTTPClient *http.Client
}

func (p panelRuntimeTokenRotationControlPlane) ClaimRuntimeTokenRotation(
	ctx context.Context,
	identity Config,
	rotation HostAgentRuntimeTokenRotation,
	claimID string,
) (RuntimeTokenRotationClaimResult, error) {
	return ClaimRuntimeTokenRotationCredential(
		ctx,
		identity.PanelURL,
		rotation.ID,
		1,
		claimID,
		identity.RuntimeToken,
		p.HTTPClient,
	)
}

func (p panelRuntimeTokenRotationControlPlane) ProveRuntimeTokenRotation(
	ctx context.Context,
	stagedIdentity Config,
	rotation HostAgentRuntimeTokenRotation,
	proof RuntimeTokenRotationHeartbeatProof,
) (HostAgentRuntimeTokenRotation, error) {
	return ProveRuntimeTokenRotationHeartbeat(
		ctx,
		stagedIdentity.PanelURL,
		rotation.ID,
		proof,
		stagedIdentity.RuntimeToken,
		p.HTTPClient,
	)
}

func (a *HostPullAgent) recoverRuntimeTokenRotation(
	ctx context.Context,
) error {
	return a.advanceRuntimeTokenRotation(ctx, nil, false)
}

func (a *HostPullAgent) reconcileRuntimeTokenRotation(
	ctx context.Context,
	policy *HostAgentPolicy,
) error {
	if policy == nil {
		return nil
	}
	if policy.RuntimeTokenRotation == nil {
		// Unlike blind startup recovery, a successfully fetched policy with an
		// explicit nil directive is authoritative evidence that the server no
		// longer has an active rotation. It may retire a pre-claim tombstone
		// only after the Local Executor confirms there is no root state.
		return a.advanceRuntimeTokenRotation(ctx, nil, true)
	}
	copy := *policy.RuntimeTokenRotation
	return a.advanceRuntimeTokenRotation(ctx, &copy, false)
}

func (a *HostPullAgent) advanceRuntimeTokenRotation(
	ctx context.Context,
	directive *HostAgentRuntimeTokenRotation,
	authoritativeNoRotation bool,
) error {
	if a == nil ||
		a.RuntimeCredentialExecutor == nil ||
		a.RuntimeTokenRotationPanel == nil ||
		a.RuntimeTokenClaimState == nil ||
		a.LoadRuntimeIdentity == nil ||
		a.NewRuntimeTokenClaimID == nil {
		return errors.New("runtime token rotation dependencies are incomplete")
	}
	if !a.rotationRunning.CompareAndSwap(false, true) {
		return nil
	}
	defer a.rotationRunning.Store(false)
	if a.executionRunning.Load() {
		return errors.New("host lifecycle mutation is active")
	}
	if a.Journal != nil && a.Journal.Active() != nil {
		return errors.New("host job recovery blocks runtime token rotation")
	}
	blockers := HostLifecycleBlockers{}
	if a.LifecycleBlockers != nil {
		blockers = a.LifecycleBlockers()
	}
	// The active rotation is this operation, not an independent blocker.
	blockers.TokenRotationPending = false
	if blockers.mutationBlocked() {
		return errors.New("host lifecycle mutation blocks runtime token rotation")
	}

	for step := 0; step < 8; step++ {
		identity := a.currentIdentity()
		status, exists, err := a.RuntimeCredentialExecutor.
			RuntimeCredentialStatus(ctx, identity.NodeID)
		if err != nil {
			return err
		}
		a.setRuntimeCredentialStatus(status, exists)
		if exists {
			if status.Phase == RuntimeCredentialPhaseCancelReady &&
				(authoritativeNoRotation ||
					(directive != nil &&
						runtimeCredentialStatusCanBeRetiredForNewDirective(
							status,
							*directive,
						))) {
				if err := a.retirePreparedRuntimeCredential(
					ctx,
					status,
				); err != nil {
					return err
				}
				a.setRuntimeCredentialStatus(
					RuntimeCredentialStatus{},
					false,
				)
				continue
			}
			if status.Phase == RuntimeCredentialPhaseClaimPrepared &&
				(authoritativeNoRotation ||
					(directive != nil &&
						!runtimeCredentialDirectiveMatchesStatus(
							*directive,
							status,
						) &&
						runtimeCredentialStatusCanBeRetiredForNewDirective(
							status,
							*directive,
						))) {
				if err := a.retirePreparedRuntimeCredential(
					ctx,
					status,
				); err != nil {
					return err
				}
				a.setRuntimeCredentialStatus(
					RuntimeCredentialStatus{},
					false,
				)
				continue
			}
			if directive != nil &&
				!runtimeCredentialDirectiveMatchesStatus(*directive, status) &&
				status.Phase != RuntimeCredentialPhaseActivated &&
				status.Phase != RuntimeCredentialPhaseManualRecovered {
				return errors.New(
					"runtime token rotation policy changed during local recovery",
				)
			}
			rotation := runtimeCredentialRotationFromStatus(status)
			if directive != nil &&
				(directive.Status == "cancel_requested" ||
					directive.Status == "canceled") {
				rotation = *directive
			}
			if status.Phase == RuntimeCredentialPhaseCancelReady ||
				rotation.Status == "cancel_requested" ||
				rotation.Status == "canceled" {
				if status.Phase != RuntimeCredentialPhaseCancelReady {
					cancelled, err := a.RuntimeCredentialExecutor.
						CancelRuntimeCredential(ctx, rotation)
					if err != nil {
						return err
					}
					if cancelled.Phase !=
						RuntimeCredentialPhaseCancelReady {
						return errors.New(
							"local executor did not prepare token rotation cancel",
						)
					}
					status = cancelled
					a.setRuntimeCredentialStatus(status, true)
					rotation = runtimeCredentialRotationFromStatus(status)
				}
				active := a.currentIdentity()
				acknowledged, err := a.RuntimeTokenRotationPanel.
					AcknowledgeRuntimeTokenRotationCancel(
						ctx, active, rotation,
					)
				if err != nil {
					return err
				}
				if acknowledged.Status != "canceled" ||
					acknowledged.Revision != status.RotationRevision+1 ||
					!runtimeCredentialDirectiveMatchesStatus(
						acknowledged, status,
					) {
					return errors.New(
						"runtime token rotation cancel acknowledgement is invalid",
					)
				}
				// The panel has revoked the staged token, so claim replay is no
				// longer useful. Delete the unprivileged claim ledger before
				// removing the root cancel_ready ledger; a crash at either
				// boundary then retains one durable recovery source.
				if err := a.deleteRuntimeTokenClaimState(
					acknowledged,
				); err != nil {
					return err
				}
				finalized, err := a.RuntimeCredentialExecutor.
					CancelRuntimeCredential(ctx, acknowledged)
				if err != nil {
					return err
				}
				if finalized.Phase != RuntimeCredentialPhaseCancelled {
					return errors.New(
						"local executor did not finalize token rotation cancel",
					)
				}
				a.setRuntimeCredentialStatus(RuntimeCredentialStatus{}, false)
				return nil
			}
			switch status.Phase {
			case RuntimeCredentialPhaseClaimPrepared:
				if directive == nil {
					// Blind startup cannot distinguish a transient panel outage
					// from break-glass revocation. Preserve the exact root
					// preclaim ledger for retry or explicit local recovery.
					return nil
				}
				if directive.Status != "staged" ||
					(directive.Revision != 1 &&
						directive.Revision != 2) {
					return errors.New(
						"prepared runtime token rotation has no claimable directive",
					)
				}
				next, err := a.claimAndStageRuntimeTokenRotation(
					ctx,
					identity,
					*directive,
				)
				if err != nil {
					return err
				}
				a.setRuntimeCredentialStatus(next, true)
				return nil
			case RuntimeCredentialPhaseExpired:
				if err := a.deleteRuntimeTokenClaimState(rotation); err != nil {
					return err
				}
				return errors.New(
					"runtime token rotation staged credential expired locally",
				)
			case RuntimeCredentialPhaseStageBound,
				RuntimeCredentialPhaseStaged:
				staged, err := a.LoadRuntimeIdentity(
					HostAgentStagedIdentityPath, true,
				)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) &&
						directive != nil &&
						directive.Status == "staged" &&
						directive.Revision == 2 {
						next, stageErr :=
							a.claimAndStageRuntimeTokenRotation(
								ctx,
								identity,
								*directive,
							)
						if stageErr != nil {
							return stageErr
						}
						a.setRuntimeCredentialStatus(
							next,
							true,
						)
						return nil
					}
					return errors.New(
						"load staged runtime identity for local-stage retry",
					)
				}
				next, err := a.RuntimeCredentialExecutor.
					StageRuntimeCredential(
						ctx, rotation,
						NewBoundedSecret(staged.RuntimeToken),
					)
				if err != nil {
					return err
				}
				if next.Phase != RuntimeCredentialPhaseLocalStaged {
					return errors.New(
						"local executor did not acknowledge the staged identity",
					)
				}
				if err := a.deleteRuntimeTokenClaimState(rotation); err != nil {
					return err
				}
				a.setRuntimeCredentialStatus(next, true)
				// Publish the exact staged receipt and executor fences through
				// one successful old-token heartbeat before asking the panel
				// to accept the heartbeat proof.
				return nil
			case RuntimeCredentialPhaseLocalStaged:
				if !a.runtimeTokenRotationHeartbeatPublished(status) {
					return nil
				}
				staged, err := a.LoadRuntimeIdentity(
					HostAgentStagedIdentityPath, true,
				)
				if err != nil {
					return errors.New(
						"load staged runtime identity for heartbeat proof",
					)
				}
				proved, err := a.RuntimeTokenRotationPanel.
					ProveRuntimeTokenRotation(
						ctx,
						staged,
						rotation,
						runtimeTokenHeartbeatProof(
							status,
							a.currentAgentVersion(),
						),
					)
				if err != nil {
					return err
				}
				if err := validateRuntimeCredentialPanelTransition(
					proved, status, "heartbeat_proved",
					status.RotationRevision+1,
				); err != nil {
					return err
				}
				next, err := a.RuntimeCredentialExecutor.
					MarkRuntimeCredentialProofReady(ctx, proved)
				if err != nil {
					return err
				}
				if next.Phase != RuntimeCredentialPhaseProofReady {
					return errors.New(
						"local executor did not persist heartbeat proof",
					)
				}
				a.setRuntimeCredentialStatus(next, true)
			case RuntimeCredentialPhaseProofReady:
				next, err := a.RuntimeCredentialExecutor.
					ActivateRuntimeCredential(ctx, rotation)
				if err != nil {
					return err
				}
				if next.Phase != RuntimeCredentialPhaseActivated {
					return errors.New(
						"local executor did not activate the runtime identity",
					)
				}
				a.setRuntimeCredentialStatus(next, true)
			case RuntimeCredentialPhaseActivated,
				RuntimeCredentialPhaseManualRecovered:
				active, err := a.LoadRuntimeIdentity(
					HostAgentIdentityPath, true,
				)
				if err != nil {
					return errors.New(
						"load activated Host Agent identity",
					)
				}
				if err := a.replaceRuntimeIdentity(active); err != nil {
					return err
				}
				// Retire the unprivileged claim first. A crash before root
				// finalization leaves the exact terminal root ledger available
				// for an idempotent retry. Reversing this order could strand a
				// stale claim after the only authoritative root binding was
				// already removed.
				if err := a.deleteRuntimeTokenClaimState(rotation); err != nil {
					return err
				}
				finalized, err := a.RuntimeCredentialExecutor.
					FinalizeRuntimeCredential(ctx, rotation)
				if err != nil {
					return err
				}
				if finalized.Phase != status.Phase ||
					finalized.RotationRevision !=
						status.RotationRevision {
					return errors.New(
						"local executor did not finalize terminal runtime credential state",
					)
				}
				a.setRuntimeCredentialStatus(RuntimeCredentialStatus{}, false)
				if directive == nil {
					return nil
				}
				continue
			default:
				return errors.New(
					"local runtime token rotation phase is invalid",
				)
			}
			continue
		}
		if directive == nil {
			if authoritativeNoRotation {
				state, claimExists, err :=
					a.RuntimeTokenClaimState.Load()
				if err != nil {
					return err
				}
				if claimExists {
					return a.RuntimeTokenClaimState.Delete(state)
				}
			}
			// An expired claim is no longer valid for credential replay, but it
			// remains the only durable, secret-free binding that lets a later
			// panel cancel request prove which orphaned stage may be wiped.
			// Keep it until an activated/canceled server terminal transition
			// deletes it through deleteRuntimeTokenClaimState.
			return nil
		}
		if directive.Status == "cancel_requested" {
			claimState, claimExists, err :=
				a.RuntimeTokenClaimState.Load()
			if err != nil {
				return err
			}
			if !claimExists || !claimState.matches(*directive) {
				return errors.New(
					"untracked token rotation cancel has no matching durable claim",
				)
			}
			cancelled, err := a.RuntimeCredentialExecutor.
				CancelRuntimeCredential(ctx, *directive)
			if err != nil {
				return err
			}
			if cancelled.Phase != RuntimeCredentialPhaseCancelReady {
				return errors.New(
					"local executor did not verify untracked token rotation cancel",
				)
			}
			a.setRuntimeCredentialStatus(cancelled, true)
			continue
		}
		if directive.Status != "staged" ||
			(directive.Revision != 1 && directive.Revision != 2) {
			return errors.New(
				"runtime token rotation has no recoverable local stage",
			)
		}
		if directive.Revision == 1 {
			claimState, claimExists, err :=
				a.RuntimeTokenClaimState.Load()
			if err != nil {
				return err
			}
			if claimExists &&
				!claimState.matches(*directive) {
				if !runtimeTokenClaimCanBeRetiredForNewDirective(
					claimState,
					*directive,
				) {
					return errors.New(
						"runtime token claim state belongs to another rotation",
					)
				}
				// A newly authenticated revision-1 directive is authoritative
				// single-active-lane evidence that the old, rootless claim is
				// terminal. This closes the emergency-after-claim/before-stage
				// compatibility window without trusting a caller-selected ID.
				if err := a.RuntimeTokenClaimState.Delete(
					claimState,
				); err != nil {
					return err
				}
			}
			prepared, err := a.RuntimeCredentialExecutor.
				PrepareRuntimeCredential(ctx, *directive)
			if err != nil {
				return err
			}
			if prepared.Phase !=
				RuntimeCredentialPhaseClaimPrepared ||
				prepared.RotationRevision !=
					directive.Revision {
				return errors.New(
					"local executor did not prepare the runtime credential claim",
				)
			}
			a.setRuntimeCredentialStatus(prepared, true)
			continue
		}
		next, err := a.claimAndStageRuntimeTokenRotation(
			ctx,
			identity,
			*directive,
		)
		if err != nil {
			return err
		}
		a.setRuntimeCredentialStatus(next, true)
		return nil
	}
	return fmt.Errorf("runtime token rotation exceeded the local transition bound")
}

func (a *HostPullAgent) claimAndStageRuntimeTokenRotation(
	ctx context.Context,
	identity Config,
	directive HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	claimState, claimExists, err := a.RuntimeTokenClaimState.Load()
	if err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if claimExists {
		if !claimState.matches(directive) {
			return RuntimeCredentialStatus{}, errors.New(
				"runtime token claim state belongs to another rotation",
			)
		}
		if !time.Now().UTC().Before(claimState.ExpiresAt) {
			return RuntimeCredentialStatus{}, errors.New(
				"runtime token claim replay expired locally",
			)
		}
	} else {
		if directive.Revision != 1 {
			return RuntimeCredentialStatus{}, errors.New(
				"claimed runtime credential has no durable claim identity",
			)
		}
		claimID, err := a.NewRuntimeTokenClaimID()
		if err != nil {
			return RuntimeCredentialStatus{}, err
		}
		claimState = RuntimeTokenClaimState{
			SchemaVersion:               runtimeTokenClaimStateVersion,
			RotationID:                  directive.ID,
			ServiceID:                   directive.ServiceID,
			ExecutionHostID:             directive.ExecutionHostID,
			PreviousTokenID:             directive.PreviousTokenID,
			StagedTokenID:               directive.StagedTokenID,
			ClaimID:                     claimID,
			InitialRevision:             1,
			OwnershipEpoch:              directive.ExpectedOwnershipEpoch,
			SourcePolicyRevision:        directive.ExpectedSourcePolicyRevision,
			ProjectionRevision:          directive.ExpectedProjectionRevision,
			LocalExecutorPolicyRevision: directive.ExpectedLocalExecutorPolicyRevision,
			ExpiresAt:                   time.Now().UTC().Add(runtimeCredentialStagedMaxAge),
		}
		if err := a.RuntimeTokenClaimState.Save(claimState); err != nil {
			return RuntimeCredentialStatus{}, err
		}
	}
	claimed, err := a.RuntimeTokenRotationPanel.
		ClaimRuntimeTokenRotation(
			ctx, identity, directive, claimState.ClaimID,
		)
	if err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := validateRuntimeCredentialClaimResult(
		claimed, directive,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	next, err := a.RuntimeCredentialExecutor.
		StageRuntimeCredential(
			ctx, claimed.Rotation,
			claimed.Credential.RuntimeToken,
		)
	if err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if next.Phase != RuntimeCredentialPhaseLocalStaged {
		return RuntimeCredentialStatus{}, errors.New(
			"local executor did not complete runtime credential staging",
		)
	}
	if err := a.RuntimeTokenClaimState.Delete(claimState); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return next, nil
}

func runtimeTokenClaimCanBeRetiredForNewDirective(
	claim RuntimeTokenClaimState,
	directive HostAgentRuntimeTokenRotation,
) bool {
	return directive.Revision == 1 &&
		claim.RotationID != directive.ID &&
		claim.ServiceID == directive.ServiceID &&
		claim.ExecutionHostID == directive.ExecutionHostID &&
		claim.PreviousTokenID == directive.PreviousTokenID &&
		claim.OwnershipEpoch ==
			directive.ExpectedOwnershipEpoch &&
		claim.SourcePolicyRevision ==
			directive.ExpectedSourcePolicyRevision &&
		claim.ProjectionRevision ==
			directive.ExpectedProjectionRevision &&
		claim.LocalExecutorPolicyRevision ==
			directive.ExpectedLocalExecutorPolicyRevision
}

func runtimeCredentialStatusCanBeRetiredForNewDirective(
	status RuntimeCredentialStatus,
	directive HostAgentRuntimeTokenRotation,
) bool {
	return (status.Phase == RuntimeCredentialPhaseClaimPrepared ||
		status.Phase == RuntimeCredentialPhaseCancelReady) &&
		directive.Revision == 1 &&
		status.RotationID != directive.ID &&
		status.ServiceID == directive.ServiceID &&
		status.ExecutionHostID == directive.ExecutionHostID &&
		status.PreviousTokenID == directive.PreviousTokenID &&
		status.OwnershipEpoch ==
			directive.ExpectedOwnershipEpoch &&
		status.SourcePolicyRevision ==
			directive.ExpectedSourcePolicyRevision &&
		status.ProjectionRevision ==
			directive.ExpectedProjectionRevision &&
		status.LocalExecutorPolicyRevision ==
			directive.ExpectedLocalExecutorPolicyRevision
}

func (a *HostPullAgent) retirePreparedRuntimeCredential(
	ctx context.Context,
	status RuntimeCredentialStatus,
) error {
	if status.Phase == RuntimeCredentialPhaseClaimPrepared {
		cancel := runtimeCredentialRotationFromStatus(status)
		cancel.Revision = status.RotationRevision + 1
		cancel.Status = "cancel_requested"
		next, err := a.RuntimeCredentialExecutor.
			CancelRuntimeCredential(ctx, cancel)
		if err != nil {
			return err
		}
		if next.Phase != RuntimeCredentialPhaseCancelReady ||
			next.RotationRevision != cancel.Revision {
			return errors.New(
				"local executor did not retire the prepared runtime credential",
			)
		}
		status = next
	}
	if status.Phase != RuntimeCredentialPhaseCancelReady {
		return errors.New(
			"prepared runtime credential retirement state is invalid",
		)
	}
	rotation := runtimeCredentialRotationFromStatus(status)
	if err := a.deleteRuntimeTokenClaimState(rotation); err != nil {
		return err
	}
	rotation.Revision = status.RotationRevision + 1
	rotation.Status = "canceled"
	finalized, err := a.RuntimeCredentialExecutor.
		CancelRuntimeCredential(ctx, rotation)
	if err != nil {
		return err
	}
	if finalized.Phase != RuntimeCredentialPhaseCancelled ||
		finalized.RotationRevision != rotation.Revision {
		return errors.New(
			"local executor did not finalize prepared runtime credential retirement",
		)
	}
	return nil
}

func runtimeTokenHeartbeatProof(
	status RuntimeCredentialStatus,
	agentVersion string,
) RuntimeTokenRotationHeartbeatProof {
	agentProtocolVersion, _ := strconv.Atoi(HostAgentProtocolVersion)
	return RuntimeTokenRotationHeartbeatProof{
		ExpectedRevision:            status.RotationRevision,
		AgentVersion:                agentVersion,
		AgentProtocolVersion:        agentProtocolVersion,
		ExecutorVersion:             status.ExecutorVersion,
		ExecutorProtocolVersion:     status.ExecutorProtocolVersion,
		MutationProtocolVersion:     status.MutationProtocolVersion,
		OwnershipEpoch:              status.OwnershipEpoch,
		SourcePolicyRevision:        status.SourcePolicyRevision,
		ProjectionRevision:          status.ProjectionRevision,
		LocalExecutorPolicyRevision: status.LocalExecutorPolicyRevision,
		LocalExecutorPolicySHA256:   status.LocalExecutorPolicySHA256,
		LocalStageReceiptID:         status.LocalStageReceiptID,
		LocalPhase:                  "staged_token_active",
	}
}

func validateRuntimeCredentialClaimResult(
	result RuntimeTokenRotationClaimResult,
	request HostAgentRuntimeTokenRotation,
) error {
	rotation := result.Rotation
	if err := rotation.Validate(); err != nil ||
		rotation.ID != request.ID ||
		rotation.ServiceID != request.ServiceID ||
		rotation.ExecutionHostID != request.ExecutionHostID ||
		rotation.PreviousTokenID != request.PreviousTokenID ||
		rotation.StagedTokenID != request.StagedTokenID ||
		rotation.ExpectedOwnershipEpoch !=
			request.ExpectedOwnershipEpoch ||
		rotation.ExpectedSourcePolicyRevision !=
			request.ExpectedSourcePolicyRevision ||
		rotation.ExpectedProjectionRevision !=
			request.ExpectedProjectionRevision ||
		rotation.ExpectedLocalExecutorPolicyRevision !=
			request.ExpectedLocalExecutorPolicyRevision ||
		rotation.Status != "staged" ||
		rotation.Revision != 2 ||
		result.Credential.TokenID != rotation.StagedTokenID ||
		!validBoundedSecret(result.Credential.RuntimeToken.Reveal()) {
		return errors.New("runtime token rotation claim binding is invalid")
	}
	return nil
}

func runtimeCredentialRotationFromStatus(
	status RuntimeCredentialStatus,
) HostAgentRuntimeTokenRotation {
	serverStatus := "staged"
	switch status.Phase {
	case RuntimeCredentialPhaseLocalStaged:
		serverStatus = "local_staged"
	case RuntimeCredentialPhaseProofReady:
		serverStatus = "heartbeat_proved"
	case RuntimeCredentialPhaseActivated:
		serverStatus = "activated"
	case RuntimeCredentialPhaseManualRecovered:
		serverStatus = "activated"
	case RuntimeCredentialPhaseCancelReady:
		serverStatus = "cancel_requested"
	case RuntimeCredentialPhaseCancelled:
		serverStatus = "canceled"
	}
	return HostAgentRuntimeTokenRotation{
		ID:                                  status.RotationID,
		ServiceID:                           status.ServiceID,
		ExecutionHostID:                     status.ExecutionHostID,
		Status:                              serverStatus,
		Revision:                            status.RotationRevision,
		ExpectedOwnershipEpoch:              status.OwnershipEpoch,
		ExpectedSourcePolicyRevision:        status.SourcePolicyRevision,
		ExpectedProjectionRevision:          status.ProjectionRevision,
		ExpectedLocalExecutorPolicyRevision: status.LocalExecutorPolicyRevision,
		PreviousTokenID:                     status.PreviousTokenID,
		StagedTokenID:                       status.StagedTokenID,
	}
}

func runtimeCredentialDirectiveMatchesStatus(
	rotation HostAgentRuntimeTokenRotation,
	status RuntimeCredentialStatus,
) bool {
	return rotation.ID == status.RotationID &&
		rotation.ServiceID == status.ServiceID &&
		rotation.ExecutionHostID == status.ExecutionHostID &&
		rotation.PreviousTokenID == status.PreviousTokenID &&
		rotation.StagedTokenID == status.StagedTokenID &&
		rotation.ExpectedOwnershipEpoch == status.OwnershipEpoch &&
		rotation.ExpectedSourcePolicyRevision ==
			status.SourcePolicyRevision &&
		rotation.ExpectedProjectionRevision == status.ProjectionRevision &&
		rotation.ExpectedLocalExecutorPolicyRevision ==
			status.LocalExecutorPolicyRevision
}

func (a *HostPullAgent) deleteRuntimeTokenClaimState(
	rotation HostAgentRuntimeTokenRotation,
) error {
	state, exists, err := a.RuntimeTokenClaimState.Load()
	if err != nil || !exists {
		return err
	}
	if !state.matches(rotation) {
		return errors.New(
			"runtime token claim state changed before cleanup",
		)
	}
	return a.RuntimeTokenClaimState.Delete(state)
}

func (a *HostPullAgent) setRuntimeCredentialStatus(
	status RuntimeCredentialStatus,
	exists bool,
) {
	if a == nil {
		return
	}
	if !exists {
		a.runtimeCredentialStatus.Store(nil)
		a.runtimeCredentialHeartbeat.Store(nil)
		return
	}
	copy := status
	a.runtimeCredentialStatus.Store(&copy)
	published := a.runtimeCredentialHeartbeat.Load()
	if published != nil && *published != status {
		a.runtimeCredentialHeartbeat.Store(nil)
	}
}

func (a *HostPullAgent) runtimeTokenRotationHeartbeatPublished(
	status RuntimeCredentialStatus,
) bool {
	if a == nil {
		return false
	}
	published := a.runtimeCredentialHeartbeat.Load()
	return published != nil &&
		published.Phase == RuntimeCredentialPhaseLocalStaged &&
		*published == status
}
