package hostruntime

import (
	"context"
)

func repairDockerPortCommit(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	policyTarget LocalExecutorTarget,
	ledger dockerPortLedger,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	if ledger.Result == nil ||
		ledger.Result.Validate() != nil ||
		ledger.Result.Result == systemdPortResultRollbackFailed {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_invalid",
		)
	}
	plan := *request.PortPlan
	result := *ledger.Result
	effective := policyTarget
	effective.LocalListen.Port = result.Docker.AppliedHealthPort
	effective.EndpointRevision = result.EndpointRevision
	effective.ConfigRevision = result.ConfigRevision
	effective.ConfigSHA256 = result.ConfigSHA256
	docker := *effective.Docker
	docker.ComposeConfigSHA256 = result.Docker.ComposeConfigSHA256
	effective.Docker = &docker
	observation, err := runtime.Observe(ctx, policy, effective)
	targetSide := result.Result == systemdPortResultApplied
	if err != nil ||
		!dockerPortObservationMatchesTarget(
			observation, plan, ledger, targetSide,
		) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	if err := runtime.ConsumeGrant(
		ctx,
		plan,
		request.Operation,
		observation.Runtime.CurrentVersion,
		request.MutationGrant,
	); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	applied := dockerPortAppliedState{
		SchemaVersion: 1, TargetID: plan.TargetID,
		ServiceType:            plan.ServiceType,
		PublishedPort:          result.Docker.AppliedPublishedPort,
		ContainerPort:          result.Docker.AppliedContainerPort,
		HealthPort:             result.Docker.AppliedHealthPort,
		EndpointRevision:       result.EndpointRevision,
		ConfigRevision:         result.ConfigRevision,
		ConfigSHA256:           result.ConfigSHA256,
		ComposeConfigSHA256:    result.Docker.ComposeConfigSHA256,
		SourcePolicyRevision:   plan.ExpectedSourcePolicyRevision,
		UpdaterPolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision: plan.ExpectedExecutorPolicyRevision,
		ExecutorPolicySHA256:   plan.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:         plan.OwnershipEpoch,
	}
	if err := state.SaveApplied(applied); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	ledger.Plan = plan
	ledger.State = dockerPortLedgerTerminal
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}

func rollbackDockerPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	oldTarget LocalExecutorTarget,
	ledger dockerPortLedger,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	plan := ledger.Plan
	// A post-grant recheck can fail before the mapping sidecar is written. In
	// that case the verified old state is already the safe terminal outcome;
	// attempting Restore would incorrectly require the not-yet-written target
	// bytes and turn a known unchanged state into rollback_failed.
	if observation, err := runtime.Observe(ctx, policy, oldTarget); err == nil &&
		dockerPortObservationMatchesTarget(observation, plan, ledger, false) {
		return commitDockerPortResult(
			plan, ledger, systemdPortResultUnchanged,
			observation.ComposeConfigSHA256, runtime, state,
		)
	}
	if err := runtime.Restore(ledger.Checkpoint, ledger.TargetBytes); err == nil {
		oldModel := dockerPortPreparedModel{
			ComposePolicySHA256: plan.Docker.ApprovedComposeConfigSHA256,
			ComposeConfigSHA256: ledger.OldComposeSHA256,
			PublishedHostIP:     plan.Docker.PublishedHostIP,
			PublishedPort:       plan.Docker.OldPublishedPort,
			ContainerPort:       plan.Docker.OldContainerPort,
			HealthPort:          plan.Docker.OldHealthPort,
		}
		if recreateErr := runtime.Recreate(ctx, oldTarget, oldModel); recreateErr == nil {
			if observation, observeErr := runtime.Observe(ctx, policy, oldTarget); observeErr == nil &&
				dockerPortObservationMatchesTarget(observation, plan, ledger, false) {
				return commitDockerPortResult(
					plan, ledger, systemdPortResultRolledBack,
					observation.ComposeConfigSHA256, runtime, state,
				)
			}
		}
	}
	return terminalDockerPortRollbackFailed(plan, ledger, state)
}

func reconcileDockerPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	target LocalExecutorTarget,
	adapter dockerPortAdapter,
	ledger *dockerPortLedger,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	plan := *request.PortPlan
	if ledger == nil {
		staged, err := stageDockerPortLedger(ctx, policy, target, adapter, plan, runtime)
		if err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "mutation_precondition_failed",
			)
		}
		if err := state.Stage(staged); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "state_unavailable",
			)
		}
		if err := runtime.ConsumeGrant(
			ctx, plan, request.Operation, staged.Baseline.CurrentVersion,
			request.MutationGrant,
		); err != nil {
			staged.State = dockerPortLedgerAmbiguous
			_ = state.Save(staged)
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "reconcile_required",
			)
		}
		return commitDockerPortResult(
			plan, staged, systemdPortResultUnchanged,
			staged.OldComposeSHA256, runtime, state,
		)
	}
	working := cloneDockerPortLedger(*ledger)
	observation, observeErr := runtime.Observe(ctx, policy, target)
	if observeErr == nil &&
		dockerPortObservationMatchesTarget(observation, plan, working, false) {
		return commitDockerPortResult(
			plan, working, systemdPortResultRolledBack,
			observation.ComposeConfigSHA256, runtime, state,
		)
	}
	newTarget := dockerPortTargetAfter(target, plan, working.TargetComposeSHA256)
	targetObservation, targetErr := runtime.Observe(ctx, policy, newTarget)
	if targetErr == nil &&
		dockerPortObservationMatchesTarget(targetObservation, plan, working, true) {
		return commitDockerPortResult(
			plan, working, systemdPortResultApplied,
			targetObservation.ComposeConfigSHA256, runtime, state,
		)
	}
	return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
}
