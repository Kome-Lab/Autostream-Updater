package hostruntime

import (
	"errors"
	"os"
)

func (rt runtimeCredentialExecutorRuntime) loadAndReconcileStatus(
	agentGID uint32,
) (RuntimeCredentialStatus, bool, error) {
	status, exists, err := rt.loadStatus()
	if err != nil {
		return status, exists, err
	}
	if !exists {
		if err := rt.cleanupExpiredOrphanedStagedIdentity(agentGID); err != nil {
			return RuntimeCredentialStatus{}, false, err
		}
		return RuntimeCredentialStatus{}, false, nil
	}
	switch status.Phase {
	case RuntimeCredentialPhaseClaimPrepared:
		active, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false,
				errors.New(
					"claim-prepared runtime credential active identity changed",
				)
		}
		if _, wipingErr := os.Lstat(
			rt.wipingIdentity,
		); !errors.Is(wipingErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, false,
				errors.New(
					"claim-prepared runtime credential has an unfinished identity wipe",
				)
		}
		status, stagedExists, err := rt.bindClaimPreparedStagedIdentity(
			status,
			agentGID,
			active.PanelURL,
		)
		if err != nil {
			return RuntimeCredentialStatus{}, false, err
		}
		if !rt.currentTime().Before(status.StagedExpiresAt) {
			status.Phase = RuntimeCredentialPhaseExpired
			status.ActiveIdentitySHA256 =
				status.PreviousIdentitySHA256
			status.activeRuntimeTokenSHA256 =
				status.previousRuntimeTokenSHA256
			if err := rt.saveStatus(status); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
			if stagedExists {
				if err := rt.wipeAndRemoveIdentity(
					rt.stagedIdentity,
					agentGID,
					status.StagedIdentitySHA256,
				); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
			}
		}
	case RuntimeCredentialPhaseStageBound:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity,
			agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"active runtime credential changed before stage-bound replay",
			)
		}
		status, stagedExists, bindErr :=
			rt.bindStageBoundInstalledIdentity(
				status,
				agentGID,
				"",
			)
		if bindErr != nil {
			return RuntimeCredentialStatus{}, false, bindErr
		}
		if !rt.currentTime().Before(status.StagedExpiresAt) {
			status.Phase = RuntimeCredentialPhaseExpired
			status.ActiveIdentitySHA256 =
				status.PreviousIdentitySHA256
			status.activeRuntimeTokenSHA256 =
				status.previousRuntimeTokenSHA256
			if err := rt.saveStatus(status); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
			if stagedExists {
				if err := rt.wipeAndRemoveIdentity(
					rt.stagedIdentity,
					agentGID,
					status.StagedIdentitySHA256,
				); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
			}
		}
	case RuntimeCredentialPhaseStaged:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity,
			agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"active runtime credential changed before staged replay",
			)
		}
		stagedExists := false
		if _, stagedErr := os.Lstat(
			rt.stagedIdentity,
		); stagedErr == nil {
			_, stagedBytes, _, loadErr := rt.loadIdentity(
				rt.stagedIdentity,
				agentGID,
			)
			if loadErr != nil ||
				runtimeCredentialDigest(stagedBytes) !=
					status.StagedIdentitySHA256 {
				return RuntimeCredentialStatus{}, false, errors.New(
					"staged runtime credential state is inconsistent",
				)
			}
			stagedExists = true
		} else if !errors.Is(stagedErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, false, errors.New(
				"stat staged runtime credential during replay",
			)
		}
		if _, wipingErr := os.Lstat(
			rt.wipingIdentity,
		); !errors.Is(wipingErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, false, errors.New(
				"staged runtime credential has an unfinished identity wipe",
			)
		}
		if !rt.currentTime().Before(status.StagedExpiresAt) {
			status.Phase = RuntimeCredentialPhaseExpired
			status.ActiveIdentitySHA256 =
				status.PreviousIdentitySHA256
			status.activeRuntimeTokenSHA256 =
				status.previousRuntimeTokenSHA256
			if err := rt.saveStatus(status); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
			if stagedExists {
				if err := rt.wipeAndRemoveIdentity(
					rt.stagedIdentity,
					agentGID,
					status.StagedIdentitySHA256,
				); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
			}
		}
	case RuntimeCredentialPhaseLocalStaged,
		RuntimeCredentialPhaseProofReady:
		_, stagedBytes, _, stagedErr := rt.loadIdentity(
			rt.stagedIdentity, agentGID,
		)
		if stagedErr != nil ||
			runtimeCredentialDigest(stagedBytes) != status.StagedIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"staged runtime credential state is inconsistent",
			)
		}
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil {
			return RuntimeCredentialStatus{}, false, activeErr
		}
		activeDigest := runtimeCredentialDigest(activeBytes)
		if status.Phase == RuntimeCredentialPhaseProofReady &&
			activeDigest == status.StagedIdentitySHA256 {
			// The server activation and atomic identity replacement completed,
			// but the process stopped before writing its secret-free metadata.
			status.Phase = RuntimeCredentialPhaseActivated
			status.RotationRevision++
			status.ActiveIdentitySHA256 = status.StagedIdentitySHA256
			status.activeRuntimeTokenSHA256 =
				status.stagedRuntimeTokenSHA256
			if err := rt.saveStatus(status); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
			if err := rt.wipeAndRemoveIdentity(
				rt.stagedIdentity, agentGID, status.StagedIdentitySHA256,
			); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
		} else {
			if activeDigest != status.PreviousIdentitySHA256 {
				return RuntimeCredentialStatus{}, false, errors.New(
					"active runtime credential changed before staged expiry",
				)
			}
			if !rt.currentTime().Before(status.StagedExpiresAt) {
				// The control plane is unreachable or the lane was abandoned.
				// Keep the active identity byte-for-byte unchanged, persist a
				// root-owned tombstone, and remove only the staged secret.
				status.Phase = RuntimeCredentialPhaseExpired
				status.ActiveIdentitySHA256 =
					status.PreviousIdentitySHA256
				status.activeRuntimeTokenSHA256 =
					status.previousRuntimeTokenSHA256
				if err := rt.saveStatus(status); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
				if err := rt.wipeAndRemoveIdentity(
					rt.stagedIdentity,
					agentGID,
					status.StagedIdentitySHA256,
				); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
			}
		}
	case RuntimeCredentialPhaseActivated:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) != status.ActiveIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"active runtime credential state is inconsistent",
			)
		}
		if err := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity, agentGID, status.StagedIdentitySHA256,
		); err != nil {
			return RuntimeCredentialStatus{}, false, err
		}
	case RuntimeCredentialPhaseCancelReady:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"cancel-ready runtime credential active identity changed",
			)
		}
		if wipeErr := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity,
			agentGID,
			status.StagedIdentitySHA256,
		); wipeErr != nil {
			return RuntimeCredentialStatus{}, false, wipeErr
		}
		if !rt.identityCleanupComplete() {
			return RuntimeCredentialStatus{}, false, errors.New(
				"cancel-ready runtime credential cleanup is incomplete",
			)
		}
	case RuntimeCredentialPhaseExpired:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"expired runtime credential active identity changed",
			)
		}
		if wipeErr := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity,
			agentGID,
			status.StagedIdentitySHA256,
		); wipeErr != nil {
			return RuntimeCredentialStatus{}, false, wipeErr
		}
	case RuntimeCredentialPhaseManualRecovered:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.ActiveIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"manually recovered runtime credential active identity changed",
			)
		}
		if wipeErr := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity,
			agentGID,
			status.StagedIdentitySHA256,
		); wipeErr != nil {
			return RuntimeCredentialStatus{}, false, wipeErr
		}
	}
	return status, true, nil
}
