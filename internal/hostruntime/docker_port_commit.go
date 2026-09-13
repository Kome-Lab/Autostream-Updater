package hostruntime

import (
	"context"
	"runtime"
)

func commitDockerPortResult(
	plan SystemdPortReconfigurePlan,
	ledger dockerPortLedger,
	resultKind, composeSHA256 string,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	result := SystemdPortReconfigureResult{
		DeploymentMode: ModeDocker,
		OldPort:        plan.OldPort, NewPort: plan.NewPort,
	}
	var publishedPort, containerPort, healthPort int
	switch resultKind {
	case systemdPortResultApplied:
		result.Status, result.Result = "succeeded", systemdPortResultApplied
		result.StateKnown, result.AppliedPort = true, plan.NewPort
		result.EndpointRevision = plan.TargetEndpointRevision
		result.ConfigRevision = plan.TargetConfigRevision
		result.ConfigSHA256 = plan.TargetConfigSHA256
		result.Message = "requested Docker port mapping is running and verified"
		publishedPort, containerPort, healthPort =
			plan.Docker.NewPublishedPort,
			plan.Docker.NewContainerPort,
			plan.Docker.NewHealthPort
	case systemdPortResultRolledBack:
		result.Status, result.Result = "rolled_back", systemdPortResultRolledBack
		result.StateKnown, result.AppliedPort = true, plan.OldPort
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "previous Docker port mapping was restored and verified"
		publishedPort, containerPort, healthPort =
			plan.Docker.OldPublishedPort,
			plan.Docker.OldContainerPort,
			plan.Docker.OldHealthPort
	case systemdPortResultUnchanged:
		result.Status, result.Result = "succeeded", systemdPortResultUnchanged
		result.StateKnown, result.AppliedPort = true, plan.OldPort
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "Docker port mutation had not changed the verified previous mapping"
		publishedPort, containerPort, healthPort =
			plan.Docker.OldPublishedPort,
			plan.Docker.OldContainerPort,
			plan.Docker.OldHealthPort
	default:
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "internal_error",
		)
	}
	result.Docker = &DockerPortReconfigureResultState{
		AppliedPublishedPort: publishedPort,
		AppliedContainerPort: containerPort,
		AppliedHealthPort:    healthPort,
		ComposeConfigSHA256:  composeSHA256,
	}
	if result.Validate() != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "internal_error",
		)
	}
	applied := dockerPortAppliedState{
		SchemaVersion: 1, TargetID: plan.TargetID, ServiceType: plan.ServiceType,
		PublishedPort: publishedPort, ContainerPort: containerPort,
		HealthPort: healthPort, EndpointRevision: result.EndpointRevision,
		ConfigRevision: result.ConfigRevision, ConfigSHA256: result.ConfigSHA256,
		ComposeConfigSHA256:    composeSHA256,
		SourcePolicyRevision:   plan.ExpectedSourcePolicyRevision,
		UpdaterPolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision: plan.ExpectedExecutorPolicyRevision,
		ExecutorPolicySHA256:   plan.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:         plan.OwnershipEpoch,
	}
	ledger.Plan = plan
	ledger.State = dockerPortLedgerCommitting
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	if err := state.SaveApplied(applied); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	if runtime != nil {
		if err := runtime.CrashPoint("after_applied_state_save"); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "reconcile_required",
			)
		}
	}
	ledger.State = dockerPortLedgerTerminal
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}

func terminalDockerPortRollbackFailed(
	plan SystemdPortReconfigurePlan,
	ledger dockerPortLedger,
	state dockerPortStateStore,
) LocalExecutorResponse {
	result := SystemdPortReconfigureResult{
		DeploymentMode: ModeDocker,
		Status:         "failed", Result: systemdPortResultRollbackFailed,
		StateKnown: false, OldPort: plan.OldPort, NewPort: plan.NewPort,
		EndpointRevision: plan.TargetEndpointRevision,
		Message:          "local rollback could not determine a verified Docker port mapping",
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

func handleLocalExecutorDockerPortMutation(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	remoteRuntime executorMutationRuntime,
) LocalExecutorResponse {
	if remoteRuntime.platformOS == "" {
		remoteRuntime.platformOS = runtime.GOOS
	}
	if remoteRuntime.platformOS != "linux" || request.PortPlan == nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "target_unavailable",
		)
	}
	target, ok := policy.Target(request.ServiceID)
	if !ok {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "target_not_found",
		)
	}
	if target.DeploymentMode != ModeDocker || target.Docker == nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "config_mismatch",
		)
	}
	secured, err := securePrivilegedTarget(target.runtimeTarget(policy.HostID))
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "target_unavailable",
		)
	}
	unlock, err := acquireTargetLock(secured)
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "target_busy",
		)
	}
	defer unlock()
	portRuntime, state, err := newPlatformDockerPortExecution(
		policy, target, secured, remoteRuntime,
	)
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return executeDockerPortRequest(ctx, policy, request, portRuntime, state)
}
