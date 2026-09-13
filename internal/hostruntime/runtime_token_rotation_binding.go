package hostruntime

import (
	"errors"
	"fmt"
	"os"
)

func (rt runtimeCredentialExecutorRuntime) bindClaimPreparedStagedIdentity(
	status RuntimeCredentialStatus,
	agentGID uint32,
	panelURL string,
) (RuntimeCredentialStatus, bool, error) {
	if status.Phase != RuntimeCredentialPhaseClaimPrepared {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential claim binding phase is invalid",
		)
	}
	if _, wipingErr := os.Lstat(
		rt.wipingIdentity,
	); !errors.Is(wipingErr, os.ErrNotExist) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"claim-prepared runtime credential has an unfinished identity wipe",
		)
	}
	if _, stagedErr := os.Lstat(
		rt.stagedIdentity,
	); errors.Is(stagedErr, os.ErrNotExist) {
		return status, false, nil
	} else if stagedErr != nil {
		return RuntimeCredentialStatus{}, false, errors.New(
			"stat claim-prepared staged runtime credential",
		)
	}
	staged, stagedBytes, _, err := rt.loadIdentity(
		rt.stagedIdentity,
		agentGID,
	)
	stagedTokenDigest := runtimeCredentialTokenDigest(
		staged.RuntimeToken,
	)
	if err != nil ||
		staged.PanelURL != panelURL ||
		staged.NodeID != status.ServiceID ||
		staged.ServiceName != status.serviceName ||
		!validBoundedSecret(staged.RuntimeToken) ||
		stagedTokenDigest == status.previousRuntimeTokenSHA256 {
		return RuntimeCredentialStatus{}, false, errors.New(
			"claim-prepared staged runtime credential is unsafe",
		)
	}
	// Compatibility recovery for an older executor that wrote the fixed
	// staged slot before advancing its root ledger. New executors persist this
	// exact digest and token hash before creating the file.
	status.Phase = RuntimeCredentialPhaseStaged
	status.RotationRevision++
	status.StagedIdentitySHA256 =
		runtimeCredentialDigest(stagedBytes)
	status.stagedRuntimeTokenSHA256 = stagedTokenDigest
	if err := rt.saveStatus(status); err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	return status, true, nil
}

func (rt runtimeCredentialExecutorRuntime) bindStageBoundInstalledIdentity(
	status RuntimeCredentialStatus,
	agentGID uint32,
	panelURL string,
) (RuntimeCredentialStatus, bool, error) {
	if status.Phase != RuntimeCredentialPhaseStageBound {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential stage-bound phase is invalid",
		)
	}
	if _, wipingErr := os.Lstat(
		rt.wipingIdentity,
	); !errors.Is(wipingErr, os.ErrNotExist) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"stage-bound runtime credential has an unfinished identity wipe",
		)
	}
	if _, stagedErr := os.Lstat(
		rt.stagedIdentity,
	); errors.Is(stagedErr, os.ErrNotExist) {
		return status, false, nil
	} else if stagedErr != nil {
		return RuntimeCredentialStatus{}, false, errors.New(
			"stat stage-bound runtime credential",
		)
	}
	staged, stagedBytes, _, err := rt.loadIdentity(
		rt.stagedIdentity,
		agentGID,
	)
	if err != nil ||
		staged.NodeID != status.ServiceID ||
		staged.ServiceName != status.serviceName ||
		(panelURL != "" && staged.PanelURL != panelURL) ||
		runtimeCredentialDigest(stagedBytes) !=
			status.StagedIdentitySHA256 ||
		runtimeCredentialTokenDigest(staged.RuntimeToken) !=
			status.stagedRuntimeTokenSHA256 {
		return RuntimeCredentialStatus{}, false, errors.New(
			"stage-bound runtime credential file changed",
		)
	}
	status.Phase = RuntimeCredentialPhaseStaged
	if err := rt.saveStatus(status); err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	return status, true, nil
}

func (rt runtimeCredentialExecutorRuntime) cleanupExpiredOrphanedStagedIdentity(
	agentGID uint32,
) error {
	if _, err := os.Lstat(rt.wipingIdentity); err == nil {
		if wipeErr := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity,
			agentGID,
			"",
		); wipeErr != nil {
			return wipeErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("stat orphaned Host Agent identity wipe")
	}
	if _, err := os.Lstat(rt.stagedIdentity); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("stat orphaned staged Host Agent identity")
	}
	staged, stagedBytes, stagedInfo, err := rt.loadIdentity(
		rt.stagedIdentity, agentGID,
	)
	if err != nil {
		return err
	}
	if rt.currentTime().Before(
		stagedInfo.ModTime().UTC().Add(runtimeCredentialStagedMaxAge),
	) {
		return nil
	}
	active, _, _, err := rt.loadIdentity(rt.activeIdentity, agentGID)
	if err != nil ||
		staged.PanelURL != active.PanelURL ||
		staged.NodeID != active.NodeID ||
		staged.ServiceName != active.ServiceName ||
		staged.RuntimeToken == active.RuntimeToken {
		return errors.New(
			"expired orphaned staged Host Agent identity is unsafe",
		)
	}
	return rt.wipeAndRemoveIdentity(
		rt.stagedIdentity,
		agentGID,
		runtimeCredentialDigest(stagedBytes),
	)
}

func runtimeCredentialRequestMatchesStatus(
	request LocalExecutorRequest,
	status RuntimeCredentialStatus,
) bool {
	mutation := request.RuntimeCredential
	return mutation != nil &&
		request.ServiceID == status.ServiceID &&
		mutation.RotationID == status.RotationID &&
		mutation.ExecutionHostID == status.ExecutionHostID &&
		mutation.PreviousTokenID == status.PreviousTokenID &&
		mutation.StagedTokenID == status.StagedTokenID &&
		request.OwnershipEpoch == status.OwnershipEpoch &&
		request.SourcePolicyRevision == status.SourcePolicyRevision &&
		request.OwnershipPolicyRevision == status.ProjectionRevision &&
		request.ExecutorPolicyRevision == status.LocalExecutorPolicyRevision
}

func validateRuntimeCredentialPanelTransition(
	rotation HostAgentRuntimeTokenRotation,
	current RuntimeCredentialStatus,
	expectedStatus string,
	expectedRevision int64,
) error {
	if err := rotation.Validate(); err != nil ||
		rotation.ID != current.RotationID ||
		rotation.ServiceID != current.ServiceID ||
		rotation.ExecutionHostID != current.ExecutionHostID ||
		rotation.PreviousTokenID != current.PreviousTokenID ||
		rotation.StagedTokenID != current.StagedTokenID ||
		rotation.ExpectedOwnershipEpoch != current.OwnershipEpoch ||
		rotation.ExpectedSourcePolicyRevision != current.SourcePolicyRevision ||
		rotation.ExpectedProjectionRevision != current.ProjectionRevision ||
		rotation.ExpectedLocalExecutorPolicyRevision != current.LocalExecutorPolicyRevision ||
		rotation.Status != expectedStatus ||
		rotation.Revision != expectedRevision {
		return fmt.Errorf(
			"%w: panel transition binding is invalid",
			errRuntimeCredentialPrecondition,
		)
	}
	return nil
}

func runtimeCredentialResponse(
	status RuntimeCredentialStatus,
) LocalExecutorResponse {
	response := LocalExecutorResponse{
		Version:           LocalExecutorMutationProtocolVersion,
		RuntimeCredential: &status,
	}
	if err := response.Validate(); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "internal_error",
		)
	}
	return response
}
