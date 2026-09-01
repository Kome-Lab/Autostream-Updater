package hostruntime

import (
	"errors"
	"strings"
)

// RecoverRuntimeCredentialAfterEmergencyManualReconfigure is the explicit
// root-only break-glass boundary used after the Control Panel has revoked both
// rotation credentials and an operator has installed a replacement managed
// Host Agent identity. It never contacts the Control Panel and accepts no
// caller-selected paths, token values, host IDs, or policy fences.
func RecoverRuntimeCredentialAfterEmergencyManualReconfigure(
	rotationID string,
) error {
	if err := RequireLocalExecutorRoot(); err != nil {
		return errors.New(
			"runtime credential emergency recovery requires root",
		)
	}
	policy, err := LoadLocalExecutorPolicy(
		DefaultLocalExecutorPolicyPath,
		true,
	)
	if err != nil {
		return errors.New(
			"load runtime credential emergency recovery policy",
		)
	}
	unlock, err := acquireHostLifecycleLock()
	if err != nil {
		return errors.New(
			"runtime credential emergency recovery is busy",
		)
	}
	defer unlock()
	_, err = defaultRuntimeCredentialExecutorRuntime().
		recoverAfterEmergencyManualReconfigure(policy, rotationID)
	if err != nil {
		return errors.New(
			"runtime credential emergency recovery rejected",
		)
	}
	return nil
}

func (rt runtimeCredentialExecutorRuntime) recoverAfterEmergencyManualReconfigure(
	policy LocalExecutorPolicy,
	rotationID string,
) (RuntimeCredentialStatus, error) {
	if rotationID != strings.TrimSpace(rotationID) ||
		!identifierPattern.MatchString(rotationID) ||
		rt.validatePaths() != nil ||
		policy.Validate() != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil {
		return RuntimeCredentialStatus{}, errors.New(
			"runtime credential emergency recovery binding is invalid",
		)
	}
	if err := rt.validateIdentityLayout(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	current, exists, err := rt.loadStatus()
	if err != nil || !exists ||
		current.RotationID != rotationID ||
		current.ExecutionHostID != policy.HostID ||
		current.SourcePolicyRevision != policy.SourcePolicyRevision ||
		current.ProjectionRevision != policy.ProjectionRevision ||
		current.LocalExecutorPolicyRevision != policy.PolicyRevision {
		return RuntimeCredentialStatus{}, errors.New(
			"runtime credential emergency recovery state does not match policy",
		)
	}
	policySHA256, err := policy.SHA256()
	if err != nil ||
		current.LocalExecutorPolicySHA256 != policySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"runtime credential emergency recovery policy digest changed",
		)
	}
	if current.Phase == RuntimeCredentialPhaseClaimPrepared {
		current, _, err = rt.bindClaimPreparedStagedIdentity(
			current,
			policy.AgentGID,
			policy.Mutation.PanelURL,
		)
		if err != nil {
			return RuntimeCredentialStatus{}, errors.New(
				"runtime credential emergency recovery staged binding is invalid",
			)
		}
	}
	if current.Phase == RuntimeCredentialPhaseStageBound {
		current, _, err = rt.bindStageBoundInstalledIdentity(
			current,
			policy.AgentGID,
			policy.Mutation.PanelURL,
		)
		if err != nil {
			return RuntimeCredentialStatus{}, errors.New(
				"runtime credential emergency recovery stage-bound file is invalid",
			)
		}
	}
	if err := rt.validateIdentityLayout(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	active, activeBytes, _, err := rt.loadIdentity(
		rt.activeIdentity,
		policy.AgentGID,
	)
	if err != nil ||
		active.NodeID != current.ServiceID ||
		active.PanelURL != policy.Mutation.PanelURL ||
		active.ServiceName != current.serviceName ||
		!validBoundedSecret(active.RuntimeToken) {
		return RuntimeCredentialStatus{}, errors.New(
			"replacement Host Agent identity does not match recovery state",
		)
	}
	activeDigest := runtimeCredentialDigest(activeBytes)
	activeTokenDigest := runtimeCredentialTokenDigest(
		active.RuntimeToken,
	)
	if current.Phase == RuntimeCredentialPhaseManualRecovered {
		if activeDigest != current.ActiveIdentitySHA256 ||
			activeTokenDigest !=
				current.activeRuntimeTokenSHA256 {
			return RuntimeCredentialStatus{}, errors.New(
				"manually recovered Host Agent identity changed",
			)
		}
		if err := rt.finishEmergencyStagedCleanup(
			policy.AgentGID,
			current.StagedIdentitySHA256,
		); err != nil {
			return RuntimeCredentialStatus{}, err
		}
		return current, nil
	}
	switch current.Phase {
	case RuntimeCredentialPhaseClaimPrepared,
		RuntimeCredentialPhaseStageBound,
		RuntimeCredentialPhaseActivated,
		RuntimeCredentialPhaseCancelReady,
		RuntimeCredentialPhaseExpired:
	case RuntimeCredentialPhaseStaged,
		RuntimeCredentialPhaseLocalStaged,
		RuntimeCredentialPhaseProofReady:
		if rt.currentTime().Before(current.StagedExpiresAt) {
			return RuntimeCredentialStatus{}, errors.New(
				"runtime credential emergency recovery TTL has not elapsed",
			)
		}
	default:
		return RuntimeCredentialStatus{}, errors.New(
			"runtime credential state is not emergency-recoverable",
		)
	}
	if activeDigest == current.PreviousIdentitySHA256 ||
		activeDigest == current.StagedIdentitySHA256 ||
		activeTokenDigest ==
			current.previousRuntimeTokenSHA256 ||
		(current.stagedRuntimeTokenSHA256 != "" &&
			activeTokenDigest ==
				current.stagedRuntimeTokenSHA256) {
		return RuntimeCredentialStatus{}, errors.New(
			"replacement Host Agent identity still uses a revoked credential slot",
		)
	}
	current.Phase = RuntimeCredentialPhaseManualRecovered
	current.ActiveIdentitySHA256 = activeDigest
	current.activeRuntimeTokenSHA256 = activeTokenDigest
	// Persist the replacement digest before destroying an old staged slot.
	// A crash after this point re-enters the idempotent branch above, which
	// completes only the exact-digest staged cleanup.
	if err := rt.validateIdentityLayout(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.finishEmergencyStagedCleanup(
		policy.AgentGID,
		current.StagedIdentitySHA256,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) finishEmergencyStagedCleanup(
	agentGID uint32,
	expectedDigest string,
) error {
	if err := rt.validateIdentityLayout(); err != nil {
		return err
	}
	if err := rt.wipeAndRemoveIdentity(
		rt.stagedIdentity,
		agentGID,
		expectedDigest,
	); err != nil {
		return err
	}
	return rt.validateIdentityLayout()
}
