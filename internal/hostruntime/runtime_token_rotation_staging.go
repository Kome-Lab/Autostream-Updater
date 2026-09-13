package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
)

func (rt runtimeCredentialExecutorRuntime) prepare(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	active Config,
	activeBytes []byte,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	mutation := *request.RuntimeCredential
	if mutation.RotationRevision != 1 {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: initial rotation revision is required",
			errRuntimeCredentialPrecondition,
		)
	}
	if exists {
		if current.Phase ==
			RuntimeCredentialPhaseClaimPrepared &&
			current.RotationRevision ==
				mutation.RotationRevision {
			return current, nil
		}
		return RuntimeCredentialStatus{},
			errRuntimeCredentialBusy
	}
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		if err == nil {
			return RuntimeCredentialStatus{},
				errRuntimeCredentialBusy
		}
		return RuntimeCredentialStatus{}, errors.New(
			"stat staged runtime credential before claim preparation",
		)
	}
	policySHA256, err := policy.SHA256()
	if err != nil {
		return RuntimeCredentialStatus{}, err
	}
	previousDigest := runtimeCredentialDigest(activeBytes)
	current = RuntimeCredentialStatus{
		SchemaVersion:               runtimeCredentialStateSchemaVersion,
		Phase:                       RuntimeCredentialPhaseClaimPrepared,
		RotationID:                  mutation.RotationID,
		ServiceID:                   request.ServiceID,
		ExecutionHostID:             mutation.ExecutionHostID,
		PreviousTokenID:             mutation.PreviousTokenID,
		StagedTokenID:               mutation.StagedTokenID,
		RotationRevision:            mutation.RotationRevision,
		OwnershipEpoch:              request.OwnershipEpoch,
		SourcePolicyRevision:        request.SourcePolicyRevision,
		ProjectionRevision:          request.OwnershipPolicyRevision,
		LocalExecutorPolicyRevision: request.ExecutorPolicyRevision,
		StagedIdentitySHA256:        runtimeCredentialDigest(nil),
		PreviousIdentitySHA256:      previousDigest,
		LocalExecutorPolicySHA256:   policySHA256,
		ExecutorVersion:             rt.currentExecutorVersion(),
		ExecutorProtocolVersion:     LocalExecutorMutationProtocolVersion,
		MutationProtocolVersion:     LocalExecutorMutationProtocolVersion,
		StagedExpiresAt:             rt.currentTime().Add(runtimeCredentialStagedMaxAge),
		previousRuntimeTokenSHA256:  runtimeCredentialTokenDigest(active.RuntimeToken),
		serviceName:                 active.ServiceName,
	}
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) stage(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	active Config,
	activeBytes []byte,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	mutation := *request.RuntimeCredential
	if mutation.RotationRevision != 2 {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: claim revision is required", errRuntimeCredentialPrecondition,
		)
	}
	prepared := exists &&
		current.Phase == RuntimeCredentialPhaseClaimPrepared
	if exists {
		switch current.Phase {
		case RuntimeCredentialPhaseClaimPrepared:
			if current.RotationRevision+1 !=
				mutation.RotationRevision {
				return RuntimeCredentialStatus{}, fmt.Errorf(
					"%w: prepared claim revision changed",
					errRuntimeCredentialPrecondition,
				)
			}
		case RuntimeCredentialPhaseLocalStaged,
			RuntimeCredentialPhaseProofReady,
			RuntimeCredentialPhaseActivated:
			return current, nil
		case RuntimeCredentialPhaseStageBound,
			RuntimeCredentialPhaseStaged:
			if current.RotationRevision != mutation.RotationRevision {
				return RuntimeCredentialStatus{}, fmt.Errorf(
					"%w: staged revision changed", errRuntimeCredentialPrecondition,
				)
			}
		default:
			return RuntimeCredentialStatus{}, errRuntimeCredentialBusy
		}
	}
	if !exists || prepared ||
		current.Phase == RuntimeCredentialPhaseStageBound ||
		current.Phase == RuntimeCredentialPhaseStaged {
		if active.RuntimeToken == mutation.RuntimeToken.Reveal() {
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: staged token equals active token", errRuntimeCredentialPrecondition,
			)
		}
		staged := active
		staged.RuntimeToken = mutation.RuntimeToken.Reveal()
		stagedBytes, err := marshalRuntimeCredentialIdentity(staged)
		if err != nil {
			return RuntimeCredentialStatus{}, err
		}
		if bytes.Equal(stagedBytes, activeBytes) {
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: staged identity is unchanged", errRuntimeCredentialPrecondition,
			)
		}
		stagedDigest := runtimeCredentialDigest(stagedBytes)
		stagedTokenDigest := runtimeCredentialTokenDigest(
			staged.RuntimeToken,
		)
		if current.Phase == RuntimeCredentialPhaseStageBound ||
			current.Phase == RuntimeCredentialPhaseStaged {
			if current.StagedIdentitySHA256 != stagedDigest ||
				current.stagedRuntimeTokenSHA256 !=
					stagedTokenDigest ||
				current.PreviousIdentitySHA256 !=
					runtimeCredentialDigest(activeBytes) ||
				current.previousRuntimeTokenSHA256 !=
					runtimeCredentialTokenDigest(
						active.RuntimeToken,
					) ||
				current.serviceName != active.ServiceName {
				return RuntimeCredentialStatus{}, fmt.Errorf(
					"%w: staged credential replay changed its root binding",
					errRuntimeCredentialPrecondition,
				)
			}
		}
		if _, wipingErr := os.Lstat(
			rt.wipingIdentity,
		); !errors.Is(wipingErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, errors.New(
				"runtime credential cleanup is incomplete before staging",
			)
		}
		stagedExists := false
		if _, stagedErr := os.Lstat(rt.stagedIdentity); stagedErr == nil {
			_, existingStagedBytes, _, loadErr := rt.loadIdentity(
				rt.stagedIdentity, policy.AgentGID,
			)
			if loadErr != nil ||
				!bytes.Equal(existingStagedBytes, stagedBytes) {
				return RuntimeCredentialStatus{}, errors.New(
					"orphaned staged runtime credential does not match claim replay",
				)
			}
			stagedExists = true
		} else if !errors.Is(stagedErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, errors.New(
				"stat staged runtime credential before install",
			)
		}
		if current.Phase != RuntimeCredentialPhaseStageBound &&
			current.Phase != RuntimeCredentialPhaseStaged {
			if prepared {
				current.Phase = RuntimeCredentialPhaseStageBound
				current.RotationRevision =
					mutation.RotationRevision
				current.StagedIdentitySHA256 =
					stagedDigest
				current.stagedRuntimeTokenSHA256 =
					stagedTokenDigest
			} else {
				current = RuntimeCredentialStatus{
					SchemaVersion:               runtimeCredentialStateSchemaVersion,
					Phase:                       RuntimeCredentialPhaseStageBound,
					RotationID:                  mutation.RotationID,
					ServiceID:                   request.ServiceID,
					ExecutionHostID:             mutation.ExecutionHostID,
					PreviousTokenID:             mutation.PreviousTokenID,
					StagedTokenID:               mutation.StagedTokenID,
					RotationRevision:            mutation.RotationRevision,
					OwnershipEpoch:              request.OwnershipEpoch,
					SourcePolicyRevision:        request.SourcePolicyRevision,
					ProjectionRevision:          request.OwnershipPolicyRevision,
					LocalExecutorPolicyRevision: request.ExecutorPolicyRevision,
					StagedIdentitySHA256:        stagedDigest,
					PreviousIdentitySHA256:      runtimeCredentialDigest(activeBytes),
					ExecutorVersion:             rt.currentExecutorVersion(),
					ExecutorProtocolVersion:     LocalExecutorMutationProtocolVersion,
					MutationProtocolVersion:     LocalExecutorMutationProtocolVersion,
					StagedExpiresAt:             rt.currentTime().Add(runtimeCredentialStagedMaxAge),
					previousRuntimeTokenSHA256:  runtimeCredentialTokenDigest(active.RuntimeToken),
					stagedRuntimeTokenSHA256:    stagedTokenDigest,
					serviceName:                 active.ServiceName,
				}
				policySHA256, digestErr := policy.SHA256()
				if digestErr != nil {
					return RuntimeCredentialStatus{}, digestErr
				}
				current.LocalExecutorPolicySHA256 =
					policySHA256
			}
			// Bind the exact claimed identity and token hash in the root-only
			// ledger before creating the staged secret file. A stop on either
			// side of the following write is replayable from this phase.
			if err := rt.saveStatus(current); err != nil {
				return RuntimeCredentialStatus{}, err
			}
		}
		if !stagedExists {
			writeStagedIdentity := rt.writeIdentityAtomic
			if rt.writeStagedIdentity != nil {
				writeStagedIdentity = rt.writeStagedIdentity
			}
			if err := writeStagedIdentity(
				rt.stagedIdentity,
				stagedBytes,
				policy.AgentGID,
				false,
			); err != nil {
				return RuntimeCredentialStatus{}, err
			}
		}
		_, verified, _, err := rt.loadIdentity(
			rt.stagedIdentity, policy.AgentGID,
		)
		if err != nil || !bytes.Equal(verified, stagedBytes) {
			return RuntimeCredentialStatus{}, errors.New(
				"staged runtime credential secure reread failed",
			)
		}
		if current.Phase == RuntimeCredentialPhaseStageBound {
			current.Phase = RuntimeCredentialPhaseStaged
			if err := rt.saveStatus(current); err != nil {
				return RuntimeCredentialStatus{}, err
			}
		}
	}
	_, stagedBytes, _, err := rt.loadIdentity(
		rt.stagedIdentity, policy.AgentGID,
	)
	if err != nil ||
		runtimeCredentialDigest(stagedBytes) != current.StagedIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"staged runtime credential no longer matches durable state",
		)
	}
	if rt.acknowledgeStage == nil {
		return RuntimeCredentialStatus{}, errRuntimeCredentialStateUnavailable
	}
	rotation, err := rt.acknowledgeStage(
		ctx,
		policy.Mutation.PanelURL,
		current.RotationID,
		current.RotationRevision,
		mutation.RuntimeToken.Reveal(),
		rt.httpClient,
	)
	if err != nil {
		// A transport failure can be a lost successful response. Preserve the
		// fixed staged slot and replay the same expected revision.
		return RuntimeCredentialStatus{}, err
	}
	if err := validateRuntimeCredentialPanelTransition(
		rotation, current, "local_staged", current.RotationRevision+1,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	current.Phase = RuntimeCredentialPhaseLocalStaged
	current.RotationRevision = rotation.Revision
	current.LocalStageReceiptID = rotation.LocalStageReceiptID
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) markProofReady(
	request LocalExecutorRequest,
	current RuntimeCredentialStatus,
	exists bool,
	agentGID uint32,
) (RuntimeCredentialStatus, error) {
	if !exists {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: staged credential is unavailable", errRuntimeCredentialPrecondition,
		)
	}
	if current.Phase == RuntimeCredentialPhaseProofReady ||
		current.Phase == RuntimeCredentialPhaseActivated {
		if request.RuntimeCredential.RotationRevision != current.RotationRevision {
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: proof revision changed", errRuntimeCredentialPrecondition,
			)
		}
		return current, nil
	}
	if current.Phase != RuntimeCredentialPhaseLocalStaged ||
		request.RuntimeCredential.RotationRevision != current.RotationRevision+1 {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: heartbeat proof revision is invalid", errRuntimeCredentialPrecondition,
		)
	}
	_, stagedBytes, _, err := rt.loadIdentity(rt.stagedIdentity, agentGID)
	if err != nil ||
		runtimeCredentialDigest(stagedBytes) != current.StagedIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"staged runtime credential proof input changed",
		)
	}
	current.Phase = RuntimeCredentialPhaseProofReady
	current.RotationRevision = request.RuntimeCredential.RotationRevision
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}
