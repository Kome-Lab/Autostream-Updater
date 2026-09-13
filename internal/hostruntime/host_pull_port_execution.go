package hostruntime

import (
	"context"
	"errors"
)

func (a *HostPullAgent) processPortReconfigurationJob(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	binding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
) error {
	if a.PortExecutor == nil {
		return errors.New("host pull port executor is unavailable")
	}
	if err := a.Journal.SetActive(&job); err != nil {
		return err
	}
	if job.RecoveryRequired {
		plan, err := a.recoverPortExecutionPlan(policy, job)
		if err != nil {
			// A port terminal report must carry a locally verified applied,
			// unchanged, rolled-back, or rollback-failed result. Never invent
			// one merely because the durable plan cannot yet be recovered.
			return err
		}
		progress := 99
		if isPortContractV2(job) {
			// A fresh lease omits CP progress. A previous recovery observation
			// or legal progress report may already have reached the ceiling.
			progress = 100
		}
		if _, err := a.emitPortExecutionReport(
			ctx, panel, job, "reconciling", "",
			"inspecting interrupted port change without reapplying", progress, nil,
		); err != nil {
			return err
		}
		result, err := a.invokePortExecutionMutation(
			ctx, panel, binding, policy, job, plan, "port_reconfigure_reconcile",
		)
		if err != nil {
			return err
		}
		return a.finishPortExecutionResult(ctx, panel, job, plan, result, true)
	}

	if _, err := a.emitPortExecutionReport(
		ctx, panel, job, "claimed", "",
		"port reconfiguration job claimed and immutable intent validated", 5, nil,
	); err != nil {
		return err
	}
	plan, err := a.preparePortExecutionPlan(policy, job)
	if err != nil {
		// The claim remains durable and will be reclaimed in recovery mode.
		// Reporting a terminal port failure without a verified local result
		// would violate the server contract and strand pending endpoint state.
		return err
	}
	if err := a.Journal.SetActivePortPlan(plan); err != nil {
		return err
	}
	if isPortContractV2(job) {
		if err := a.Journal.StagePortPolicy(policy, job, plan); err != nil {
			return err
		}
	}
	if _, err := a.emitPortExecutionReport(
		ctx, panel, job, "installing", "",
		"root executor is applying the fixed port transition", 65, nil,
	); err != nil {
		return err
	}
	reconciling := false
	result, err := a.invokePortExecutionMutation(
		ctx, panel, binding, policy, job, plan, "port_reconfigure",
	)
	if err != nil {
		code := ""
		if isPortContractV2(job) {
			code = "outcome_ambiguous"
		}
		if _, reportErr := a.emitPortExecutionReport(
			ctx, panel, job, "reconciling", code,
			"port mutation result is uncertain; reconciling without reapplying", 99, nil,
		); reportErr != nil {
			return reportErr
		}
		reconciling = true
		result, err = a.invokePortExecutionMutation(
			ctx, panel, binding, policy, job, plan, "port_reconfigure_reconcile",
		)
		if err != nil {
			return err
		}
	}
	return a.finishPortExecutionResult(ctx, panel, job, plan, result, reconciling)
}

func (a *HostPullAgent) preparePortExecutionPlan(
	policy HostAgentPolicy,
	job UpdateJob,
) (SystemdPortReconfigurePlan, error) {
	sessionID, err := a.NewSessionID()
	if err != nil {
		return SystemdPortReconfigurePlan{}, err
	}
	return portExecutionPlanFromJob(policy, job, sessionID)
}

func portExecutionPlanFromJob(
	policy HostAgentPolicy,
	job UpdateJob,
	sessionID string,
) (SystemdPortReconfigurePlan, error) {
	if job.PortReconfigure == nil {
		return SystemdPortReconfigurePlan{}, errors.New("port job contract is unavailable")
	}
	port := *job.PortReconfigure
	plan := SystemdPortReconfigurePlan{
		PortContractVersion: port.PortContractVersion,
		Mode:                port.Mode, Before: clonePortSnapshotRef(port.Before),
		Target: clonePortSnapshotRef(port.Target), Rollback: clonePortSnapshotRef(port.Rollback),
		DockerBaseline: clonePortDockerBaseline(port.DockerBaseline),
		DeploymentMode: job.DeploymentMode,
		JobID:          job.ID, HostID: job.HostID, TargetID: job.TargetID,
		ServiceType:      job.EffectiveType(),
		NetworkNamespace: port.NetworkNamespace, Protocol: port.Protocol,
		OldPort: port.OldPort, NewPort: port.NewPort,
		ExpectedEndpointRevision:       port.ExpectedEndpointRevision,
		TargetEndpointRevision:         port.TargetEndpointRevision,
		ExpectedConfigRevision:         port.ExpectedConfigRevision,
		TargetConfigRevision:           port.TargetConfigRevision,
		ExpectedConfigSHA256:           port.ExpectedConfigSHA256,
		TargetConfigSHA256:             port.TargetConfigSHA256,
		ExpectedSourcePolicyRevision:   port.ExpectedSourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  port.ExpectedUpdaterPolicyRevision,
		ExpectedExecutorPolicyRevision: port.ExpectedExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   port.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:                 job.OwnershipEpoch,
		LeaseGeneration:                job.LeaseGeneration,
		SessionID:                      sessionID,
		Docker:                         cloneDockerPortMutationGrantBinding(port.Docker),
	}
	if isPortContractV2(job) {
		plan.PortIntentSHA256 = port.PortPlanSHA256
		target, ok := hostPullPolicyTarget(policy, job.TargetID)
		if !ok || !portClaimPolicyMatches(job, policy, target) {
			return SystemdPortReconfigurePlan{}, errors.New("port v2 job policy fence is stale")
		}
	} else if plan.ExpectedSourcePolicyRevision != policy.SourcePolicyRevision ||
		plan.ExpectedUpdaterPolicyRevision != policy.Revision ||
		plan.ExpectedExecutorPolicyRevision != policy.LocalExecutorPolicyRevision ||
		plan.ExpectedExecutorPolicySHA256 != policy.LocalExecutorPolicySHA256 {
		return SystemdPortReconfigurePlan{}, errors.New("port job policy fence is stale")
	}
	runtimeHash, err := plan.ComputePortPlanSHA256()
	if err != nil {
		return SystemdPortReconfigurePlan{}, err
	}
	// The nested job hash authenticates the server/store intent. The local
	// executor hash additionally binds this claim's lease generation and the
	// fresh durable session, so it must always be computed locally.
	plan.PortPlanSHA256 = runtimeHash
	if err := plan.Validate(); err != nil {
		return SystemdPortReconfigurePlan{}, err
	}
	return plan, nil
}

func (a *HostPullAgent) recoverPortExecutionPlan(
	policy HostAgentPolicy,
	job UpdateJob,
) (SystemdPortReconfigurePlan, error) {
	stored := a.Journal.ActivePortPlan()
	if stored == nil {
		// SetActive is persisted before the runtime plan. A crash in that
		// narrow window cannot have reached the Local Executor, so reconstruct
		// a fresh session and use reconcile. If a root ledger somehow exists,
		// its different session/plan binding will fail closed.
		fresh, err := a.preparePortExecutionPlan(policy, job)
		if err != nil {
			return SystemdPortReconfigurePlan{}, errors.New("durable port recovery plan is unavailable")
		}
		if err := a.Journal.SetActivePortPlan(fresh); err != nil {
			return SystemdPortReconfigurePlan{}, err
		}
		if isPortContractV2(job) {
			if err := a.Journal.StagePortPolicy(policy, job, fresh); err != nil {
				return SystemdPortReconfigurePlan{}, err
			}
		}
		return fresh, nil
	}
	if stored.Validate() != nil {
		return SystemdPortReconfigurePlan{}, errors.New("durable port recovery plan is unavailable")
	}
	rebound, err := portExecutionPlanFromJob(policy, job, stored.SessionID)
	if err != nil || !sameSystemdPortIntent(*stored, rebound) {
		return SystemdPortReconfigurePlan{}, errors.New("durable port recovery plan does not match the recovered job")
	}
	if err := a.Journal.SetActivePortPlan(rebound); err != nil {
		return SystemdPortReconfigurePlan{}, err
	}
	if isPortContractV2(job) {
		if err := a.Journal.StagePortPolicy(policy, job, rebound); err != nil {
			return SystemdPortReconfigurePlan{}, err
		}
	}
	return rebound, nil
}

func (a *HostPullAgent) invokePortExecutionMutation(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	binding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	plan SystemdPortReconfigurePlan,
	operation string,
) (SystemdPortReconfigureResult, error) {
	if operation != "port_reconfigure" && operation != "port_reconfigure_reconcile" {
		return SystemdPortReconfigureResult{}, errors.New("port mutation operation is invalid")
	}
	var requiredV2Executor LocalExecutorV2PortMutationClient
	if job.ProtocolVersion == 2 {
		var ok bool
		requiredV2Executor, ok = a.PortExecutor.(LocalExecutorV2PortMutationClient)
		if !ok {
			return SystemdPortReconfigureResult{}, errors.New("local executor does not support v2 port mutation grants")
		}
	}
	grant, err := panel.IssueMutationGrant(ctx, job.ID, MutationGrantRequest{
		ServiceID: a.Bootstrap.NodeID, LeaseToken: job.LeaseToken,
		MutationGrantBinding: MutationGrantBinding{
			LeaseGeneration: job.LeaseGeneration,
			HostID:          binding.ExecutionHostID, TransportMode: HostTransportPullV2,
			OwnershipEpoch: binding.OwnershipEpoch, PolicyRevision: job.PolicyRevision,
			TargetID: job.TargetID, TargetVersion: job.EffectiveVersion(),
			ServiceType:    job.EffectiveType(),
			DeploymentMode: job.DeploymentMode,
			JobOperation:   updateJobOperationPortReconfigure,
			Operation:      operation,
			PlanSHA256:     plan.PortPlanSHA256, SessionID: plan.SessionID,
			PortReconfigure: plan.mutationGrantBinding(),
		},
	})
	if err != nil {
		return SystemdPortReconfigureResult{}, err
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          binding.OwnershipEpoch,
		OwnershipPolicyRevision: job.PolicyRevision,
		ExecutorPolicyRevision:  policy.LocalExecutorPolicyRevision,
	}
	if isPortContractV2(job) {
		fence.SourcePolicyRevision = plan.Before.SourcePolicyRevision
		fence.ExecutorPolicyRevision = plan.Before.ExecutorPolicyRevision
	}
	if grant.V2Binding != nil {
		v2Executor := requiredV2Executor
		if v2Executor == nil {
			var ok bool
			v2Executor, ok = a.PortExecutor.(LocalExecutorV2PortMutationClient)
			if !ok {
				return SystemdPortReconfigureResult{}, errors.New("local executor does not support v2 port mutation grants")
			}
		}
		if err := validateV2PortExecutionGrant(
			hostPullExecutionNow(panel), a.Bootstrap.NodeID, binding, policy,
			job, plan, operation, *grant.V2Binding,
		); err != nil {
			return SystemdPortReconfigureResult{}, err
		}
		v2Grant := V2MutationGrant{
			Token: NewBoundedSecret(grant.Token), Binding: *grant.V2Binding,
		}
		if operation == "port_reconfigure" {
			return v2Executor.PortReconfigureV2(ctx, plan, fence, v2Grant)
		}
		return v2Executor.PortReconfigureReconcileV2(ctx, plan, fence, v2Grant)
	}
	if job.ProtocolVersion == 2 {
		return SystemdPortReconfigureResult{}, errors.New("v2 port mutation grant binding is unavailable")
	}
	if operation == "port_reconfigure" {
		return a.PortExecutor.PortReconfigure(ctx, plan, fence, NewBoundedSecret(grant.Token))
	}
	return a.PortExecutor.PortReconfigureReconcile(ctx, plan, fence, NewBoundedSecret(grant.Token))
}

func (a *HostPullAgent) finishPortExecutionResult(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	job UpdateJob,
	plan SystemdPortReconfigurePlan,
	result SystemdPortReconfigureResult,
	reconciling bool,
) error {
	if err := validatePortExecutionResult(plan, result); err != nil {
		return err
	}
	if plan.PortContractVersion == 2 {
		var err error
		result, err = a.verifyPortResultProjection(ctx, job, plan, result)
		if err != nil {
			return err
		}
	}
	switch result.Status {
	case "succeeded":
		return a.emitPortExecutionTerminal(
			ctx, panel, job, "succeeded", "",
			"requested port is running and verified", &result,
		)
	case "rolled_back":
		// A direct forward result follows installing. Recovery already reported
		// reconciling, whose next report must remain terminal.
		if isPortContractV2(job) && !reconciling {
			if _, err := a.emitPortExecutionReport(ctx, panel, job, "rolling_back", "",
				"previous port was restored and verified", 95, nil); err != nil {
				return err
			}
		}
		return a.emitPortExecutionTerminal(
			ctx, panel, job, "rolled_back", "post_update_verification_failed",
			"previous port is running and verified", &result,
		)
	case "failed":
		return a.emitPortExecutionTerminal(
			ctx, panel, job, "failed", "port_rollback_failed",
			"port rollback could not determine a verified effective port", &result,
		)
	default:
		return errors.New("local executor returned a non-terminal port result")
	}
}
