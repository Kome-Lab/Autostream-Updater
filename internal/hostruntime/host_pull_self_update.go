package hostruntime

import (
	"context"
	"errors"
	"time"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

func (a *HostPullAgent) startSelfUpdate(
	ctx context.Context,
	binding HostAgentBinding,
	policy *HostAgentPolicy,
) {
	if a == nil || a.SelfUpdate == nil || policy == nil ||
		policy.RuntimeTokenRotation != nil ||
		binding.TransportMode != HostTransportPullV2 ||
		binding.OwnershipEpoch < 1 ||
		policy.TransportMode != HostTransportPullV2 ||
		policy.ExecutionHostID != binding.ExecutionHostID ||
		policy.OwnershipEpoch != binding.OwnershipEpoch {
		return
	}
	cached := a.selfUpdateStatus.Load()
	if cached != nil &&
		cached.State.Phase == HostSelfUpdatePhaseStable &&
		(policy.SelfUpdate == nil ||
			policy.SelfUpdate.Generation == cached.State.FailedGeneration ||
			(policy.SelfUpdate.AgentVersion == cached.State.ActiveAgentVersion &&
				policy.SelfUpdate.ExecutorVersion == cached.State.ActiveExecutorVersion)) &&
		a.selfUpdateStatusIsFresh() {
		return
	}
	if !a.executionRunning.CompareAndSwap(false, true) {
		return
	}
	policySnapshot := *policy
	if policy.SelfUpdate != nil {
		copy := *policy.SelfUpdate
		policySnapshot.SelfUpdate = &copy
	}
	go func() {
		defer a.executionRunning.Store(false)
		blockers := HostLifecycleBlockers{}
		if a.LifecycleBlockers != nil {
			blockers = a.LifecycleBlockers()
		}
		if a.Journal != nil {
			active := a.Journal.Active()
			blockers.ActiveJob = blockers.ActiveJob || active != nil
			blockers.RecoveryPending = blockers.RecoveryPending || active != nil
		}
		proof := HostSelfUpdateAgentProof{
			RunningAgentVersion: controlversion.Current(),
		}
		if accepted := a.selfUpdateProof.Load(); accepted != nil {
			proof = *accepted
		}
		fence := LocalExecutorMutationFence{
			SourcePolicyRevision:    policySnapshot.SourcePolicyRevision,
			OwnershipEpoch:          binding.OwnershipEpoch,
			OwnershipPolicyRevision: policySnapshot.Revision,
			ExecutorPolicyRevision:  policySnapshot.LocalExecutorPolicyRevision,
		}
		grantProvider := HostSelfUpdateGrantProvider(nil)
		if policySnapshot.SelfUpdate != nil &&
			a.SelfUpdateGrantIssuer != nil &&
			a.NewSessionID != nil {
			grantProvider = func(
				grantCtx context.Context,
				operation string,
			) (HostSelfUpdateGrantAuthorization, error) {
				sessionID, sessionErr := a.NewSessionID()
				if sessionErr != nil {
					return HostSelfUpdateGrantAuthorization{}, errors.New("create host self-update grant session")
				}
				planSHA256, planErr := hostSelfUpdateGrantPlanSHA256(
					operation,
					policySnapshot,
					*policySnapshot.SelfUpdate,
					fence,
				)
				if planErr != nil {
					return HostSelfUpdateGrantAuthorization{}, planErr
				}
				return a.SelfUpdateGrantIssuer.IssueHostSelfUpdateGrant(
					grantCtx,
					HostSelfUpdateGrantIssueRequest{
						SelfUpdateID:     policySnapshot.SelfUpdateID,
						ExpectedRevision: policySnapshot.SelfUpdateRevision,
						Operation:        operation,
						PlanSHA256:       planSHA256,
						SessionID:        sessionID,
					},
				)
			}
		}
		status, err := a.SelfUpdate.Reconcile(
			ctx,
			binding.ExecutionHostID,
			policySnapshot.SelfUpdate,
			proof,
			fence,
			blockers,
			grantProvider,
		)
		if err != nil {
			if ctx.Err() == nil {
				a.Logf("host self-update reconcile failed: %v", err)
			}
			return
		}
		a.selfUpdateStatus.Store(&status)
		a.selfUpdateChecked.Store(time.Now().UnixNano())
	}()
}

func (a *HostPullAgent) selfUpdateStatusIsFresh() bool {
	if a == nil {
		return false
	}
	checked := a.selfUpdateChecked.Load()
	if checked <= 0 {
		return false
	}
	refreshInterval := a.HeartbeatInterval
	if refreshInterval <= 0 {
		refreshInterval = 30 * time.Second
	}
	return time.Since(time.Unix(0, checked)) < refreshInterval
}

func (a *HostPullAgent) recordSelfUpdateHeartbeat(
	policy *HostAgentPolicy,
) {
	if a == nil || policy == nil || policy.SelfUpdate == nil ||
		controlversion.Current() != policy.SelfUpdate.AgentVersion {
		return
	}
	proof := &HostSelfUpdateAgentProof{
		RunningAgentVersion:   controlversion.Current(),
		PanelHeartbeatVersion: controlversion.Current(),
		HeartbeatGeneration:   policy.SelfUpdate.Generation,
	}
	a.selfUpdateProof.Store(proof)
}

func (a *HostPullAgent) validateRuntimeForClaim(
	ctx context.Context,
	binding HostAgentBinding,
	policy HostAgentPolicy,
) error {
	if a != nil {
		if cached := a.selfUpdateStatus.Load(); cached != nil &&
			cached.State.Phase != HostSelfUpdatePhaseStable {
			return errors.New("host runtime self-update is not stable")
		}
	}
	if policy.RuntimeRequirement == nil {
		return nil
	}
	if a == nil || a.SelfUpdate == nil ||
		binding.ExecutionHostID == "" ||
		binding.OwnershipEpoch < 1 {
		return errors.New("host runtime compatibility cannot be established")
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          binding.OwnershipEpoch,
		OwnershipPolicyRevision: policy.Revision,
		ExecutorPolicyRevision:  policy.LocalExecutorPolicyRevision,
	}
	status, err := a.SelfUpdate.executor.HostSelfUpdateStatus(
		ctx, binding.ExecutionHostID, fence,
	)
	if err != nil {
		return errors.New("host runtime compatibility probe failed")
	}
	if err := status.validate(); err != nil ||
		status.State.Phase != HostSelfUpdatePhaseStable ||
		status.CurrentSlot != status.State.ActiveSlot ||
		status.ExecutorVersion != status.State.ActiveExecutorVersion {
		return errors.New("host runtime self-update is not stable")
	}
	if policy.SelfUpdate != nil &&
		(status.State.ActiveAgentVersion != policy.SelfUpdate.AgentVersion ||
			status.State.ActiveExecutorVersion != policy.SelfUpdate.ExecutorVersion) {
		return errors.New("host runtime self-update target is not active")
	}
	current := currentHostRuntimeCompatibility(status.ExecutorVersion)
	if err := ValidateHostRuntimeCompatibility(
		current, *policy.RuntimeRequirement,
	); err != nil {
		return err
	}
	a.selfUpdateStatus.Store(&status)
	a.selfUpdateChecked.Store(time.Now().UnixNano())
	return nil
}
