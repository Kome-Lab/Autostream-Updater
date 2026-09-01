package hostruntime

import (
	"context"
	"errors"
	"strings"
	"time"
)

const defaultHostSelfUpdateVerificationTimeout = 5 * time.Minute

// HostSelfUpdateAgentProof contains only process identity and proof that the
// Control Panel accepted a heartbeat from that process. Paths, commands,
// systemd units, download origins and credentials are deliberately absent.
type HostSelfUpdateAgentProof struct {
	RunningAgentVersion   string `json:"running_agent_version,omitempty"`
	PanelHeartbeatVersion string `json:"panel_heartbeat_version,omitempty"`
	HeartbeatGeneration   string `json:"heartbeat_generation,omitempty"`
	FailureCode           string `json:"failure_code,omitempty"`
}

func (p HostSelfUpdateAgentProof) validate() error {
	if p.RunningAgentVersion != "" &&
		(!versionPattern.MatchString(p.RunningAgentVersion) ||
			p.RunningAgentVersion != strings.TrimSpace(p.RunningAgentVersion)) {
		return errors.New("host self-update running agent version is invalid")
	}
	if p.PanelHeartbeatVersion != "" &&
		(!versionPattern.MatchString(p.PanelHeartbeatVersion) ||
			p.PanelHeartbeatVersion != strings.TrimSpace(p.PanelHeartbeatVersion)) {
		return errors.New("host self-update heartbeat version is invalid")
	}
	if p.HeartbeatGeneration != "" &&
		(!identifierPattern.MatchString(p.HeartbeatGeneration) ||
			p.HeartbeatGeneration != strings.TrimSpace(p.HeartbeatGeneration)) {
		return errors.New("host self-update heartbeat generation is invalid")
	}
	if p.FailureCode != "" &&
		p.FailureCode != "verification_timeout" &&
		p.FailureCode != "agent_restart_failed" &&
		p.FailureCode != "executor_probe_failed" {
		return errors.New("host self-update failure code is invalid")
	}
	if (p.PanelHeartbeatVersion == "") != (p.HeartbeatGeneration == "") {
		return errors.New("host self-update heartbeat proof is incomplete")
	}
	return nil
}

// HostSelfUpdateRuntimeStatus is the root executor's durable view. The State
// is authoritative; the remaining fields are observations from the fixed A/B
// layout and the currently running executor.
type HostSelfUpdateRuntimeStatus struct {
	State                   HostSelfUpdateState `json:"state"`
	CurrentSlot             string              `json:"current_slot"`
	ExecutorVersion         string              `json:"executor_version"`
	ExecutorProtocolVersion int                 `json:"executor_protocol_version"`
	LastAction              string              `json:"last_action"`
	RollbackRequested       bool                `json:"rollback_requested,omitempty"`
	RestartRequested        bool                `json:"restart_requested,omitempty"`
}

func (s HostSelfUpdateRuntimeStatus) validate() error {
	if err := s.State.validate(); err != nil {
		return err
	}
	if !validHostSelfUpdateSlot(s.CurrentSlot) ||
		!versionPattern.MatchString(s.ExecutorVersion) ||
		s.ExecutorProtocolVersion < 1 {
		return errors.New("host self-update runtime status is invalid")
	}
	switch s.LastAction {
	case "",
		HostSelfUpdateActionNone,
		HostSelfUpdateActionSwitchCurrent,
		HostSelfUpdateActionRestartAgent,
		HostSelfUpdateActionAwaitProof,
		HostSelfUpdateActionProbeExecutor,
		HostSelfUpdateActionCommit,
		HostSelfUpdateActionRestoreHealthy,
		HostSelfUpdateActionRestartHealthy,
		HostSelfUpdateActionRollbackComplete:
	default:
		return errors.New("host self-update runtime action is invalid")
	}
	return nil
}

// HostSelfUpdateExecutor is the only privileged boundary used by the
// unprivileged Host Agent. Each method accepts identities and revision fences,
// never a path, command, unit name, URL or credential.
type HostSelfUpdateExecutor interface {
	HostSelfUpdateStatus(
		context.Context,
		string,
		LocalExecutorMutationFence,
	) (HostSelfUpdateRuntimeStatus, error)
	StageHostSelfUpdate(
		context.Context,
		string,
		HostSelfUpdateRequest,
		HostSelfUpdateGrantAuthorization,
		LocalExecutorMutationFence,
	) (HostSelfUpdateRuntimeStatus, error)
	ActivateHostSelfUpdate(
		context.Context,
		string,
		string,
		LocalExecutorMutationFence,
	) (HostSelfUpdateRuntimeStatus, error)
	ReconcileHostSelfUpdate(
		context.Context,
		string,
		HostSelfUpdateAgentProof,
		*HostSelfUpdateGrantAuthorization,
		LocalExecutorMutationFence,
	) (HostSelfUpdateRuntimeStatus, error)
}

type HostSelfUpdateGrantProvider func(
	context.Context,
	string,
) (HostSelfUpdateGrantAuthorization, error)

type HostSelfUpdateControllerOptions struct{}

// HostSelfUpdateController is restart-safe orchestration only. Artifact
// verification, A/B slot writes, atomic symlink changes and service restarts
// remain inside the root Local Executor.
type HostSelfUpdateController struct {
	executor HostSelfUpdateExecutor
}

func NewHostSelfUpdateController(
	executor HostSelfUpdateExecutor,
	options HostSelfUpdateControllerOptions,
) (*HostSelfUpdateController, error) {
	if executor == nil {
		return nil, errors.New("host self-update executor is unavailable")
	}
	return &HostSelfUpdateController{executor: executor}, nil
}

func (c *HostSelfUpdateController) Reconcile(
	ctx context.Context,
	hostID string,
	desired *HostSelfUpdateRequest,
	proof HostSelfUpdateAgentProof,
	fence LocalExecutorMutationFence,
	blockers HostLifecycleBlockers,
	grantProvider HostSelfUpdateGrantProvider,
) (HostSelfUpdateRuntimeStatus, error) {
	if c == nil || c.executor == nil {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update controller is unavailable")
	}
	hostID = strings.TrimSpace(hostID)
	if !validExecutionHostID(hostID) || !validHostSelfUpdateFence(fence) {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update ownership fence is invalid")
	}
	if desired != nil {
		if err := desired.validate(); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	}

	status, err := c.executor.HostSelfUpdateStatus(ctx, hostID, fence)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := status.validate(); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if status.State.Phase == HostSelfUpdatePhaseStable {
		if status.CurrentSlot != status.State.ActiveSlot {
			if blockers.mutationBlocked() {
				return HostSelfUpdateRuntimeStatus{}, errors.New("host lifecycle mutation is active")
			}
			recovered, reconcileErr := c.executor.ReconcileHostSelfUpdate(
				ctx, hostID, HostSelfUpdateAgentProof{}, nil, fence,
			)
			if reconcileErr != nil {
				return HostSelfUpdateRuntimeStatus{}, reconcileErr
			}
			if err := recovered.validate(); err != nil ||
				recovered.CurrentSlot != recovered.State.ActiveSlot ||
				recovered.LastAction != HostSelfUpdateActionRestoreHealthy {
				return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update stable slot drift was not restored")
			}
			return recovered, nil
		}
		if desired == nil ||
			desired.Generation == status.State.FailedGeneration ||
			(desired.AgentVersion == status.State.ActiveAgentVersion &&
				desired.ExecutorVersion == status.State.ActiveExecutorVersion) {
			return status, nil
		}
		if blockers.mutationBlocked() {
			return HostSelfUpdateRuntimeStatus{}, errors.New("host lifecycle mutation is active")
		}
		if grantProvider == nil {
			return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update stage grant provider is unavailable")
		}
		authorization, grantErr := grantProvider(ctx, "stage")
		if grantErr != nil {
			return HostSelfUpdateRuntimeStatus{}, grantErr
		}
		status, err = c.executor.StageHostSelfUpdate(
			ctx,
			hostID,
			*desired,
			authorization,
			fence,
		)
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		if err := status.validate(); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		if status.State.Phase == HostSelfUpdatePhaseStable &&
			status.State.FailedGeneration == desired.Generation &&
			status.CurrentSlot == status.State.ActiveSlot &&
			status.State.ActiveSlot == status.State.HealthySlot {
			return status, nil
		}
		if status.State.Phase != HostSelfUpdatePhaseStaged ||
			status.State.PendingGeneration != desired.Generation {
			return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update stage did not persist the requested generation")
		}
		return c.activateAndRecover(
			ctx, hostID, desired.Generation, fence,
		)
	}
	if status.State.Phase == HostSelfUpdatePhaseStaged {
		if desired == nil ||
			desired.Generation != status.State.PendingGeneration {
			return HostSelfUpdateRuntimeStatus{}, errors.New("staged host self-update has no matching desired generation")
		}
		if blockers.mutationBlocked() {
			return HostSelfUpdateRuntimeStatus{}, errors.New("host lifecycle mutation is active")
		}
		return c.activateAndRecover(
			ctx, hostID, desired.Generation, fence,
		)
	}
	if err := proof.validate(); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if desired != nil && desired.Generation != status.State.PendingGeneration {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update desired generation changed during an active transition")
	}
	if (status.State.Phase == HostSelfUpdatePhaseActivating ||
		status.State.Phase == HostSelfUpdatePhaseVerifying) &&
		status.CurrentSlot == status.State.PendingSlot &&
		(status.ExecutorVersion != status.State.PendingExecutorVersion ||
			status.ExecutorProtocolVersion != status.State.PendingExecutorProtocol) {
		// The current symlink already points at the pending slot, but a
		// socket-activated request can still be served by the old executor
		// while it drains. Wait for the replacement executor identity before
		// issuing a reconcile grant; treating the transient observation as a
		// failed probe would incorrectly roll back a healthy activation.
		return status, nil
	}
	if blockers.ActiveJob || blockers.MutationInProgress ||
		blockers.RecoveryPending || blockers.TokenRotationPending {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host lifecycle mutation is active")
	}
	if grantProvider == nil {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update reconcile grant provider is unavailable")
	}
	authorization, grantErr := grantProvider(ctx, "reconcile")
	if grantErr != nil {
		return HostSelfUpdateRuntimeStatus{}, grantErr
	}
	status, err = c.executor.ReconcileHostSelfUpdate(
		ctx,
		hostID,
		proof,
		&authorization,
		fence,
	)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := status.validate(); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	return status, nil
}

func (c *HostSelfUpdateController) activateAndRecover(
	ctx context.Context,
	hostID, generation string,
	fence LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	activated, activateErr := c.executor.ActivateHostSelfUpdate(
		ctx, hostID, generation, fence,
	)
	if activateErr == nil {
		if err := activated.validate(); err != nil ||
			activated.State.PendingGeneration != generation ||
			(activated.State.Phase != HostSelfUpdatePhaseActivating &&
				activated.State.Phase != HostSelfUpdatePhaseVerifying &&
				activated.State.Phase != HostSelfUpdatePhaseRollingBack) {
			return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update activation returned an invalid transition")
		}
		return activated, nil
	}
	// Activation intentionally restarts both caller and executor. A lost
	// response is therefore reconciled from root-owned durable state and
	// never interpreted as permission to stage or apply a second time.
	recovered, statusErr := c.executor.HostSelfUpdateStatus(ctx, hostID, fence)
	if statusErr != nil {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update activation result is uncertain")
	}
	if err := recovered.validate(); err != nil ||
		recovered.State.PendingGeneration != generation ||
		(recovered.State.Phase != HostSelfUpdatePhaseActivating &&
			recovered.State.Phase != HostSelfUpdatePhaseVerifying &&
			recovered.State.Phase != HostSelfUpdatePhaseRollingBack) {
		return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update activation could not be reconciled")
	}
	return recovered, nil
}

func validHostSelfUpdateFence(fence LocalExecutorMutationFence) bool {
	return fence.SourcePolicyRevision > 0 &&
		fence.OwnershipEpoch > 0 &&
		fence.OwnershipPolicyRevision > 0 &&
		fence.ExecutorPolicyRevision > 0
}
