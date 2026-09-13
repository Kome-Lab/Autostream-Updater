package hostruntime

import (
	"context"
	"reflect"
	"runtime"
)

func commitSystemdPortResult(
	plan SystemdPortReconfigurePlan,
	ledger systemdPortLedger,
	resultKind string,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	result := SystemdPortReconfigureResult{
		OldPort: plan.OldPort, NewPort: plan.NewPort,
	}
	switch resultKind {
	case systemdPortResultApplied:
		result.Status, result.Result = "succeeded", systemdPortResultApplied
		result.StateKnown = true
		result.AppliedPort = plan.NewPort
		result.EndpointRevision = plan.TargetEndpointRevision
		result.ConfigRevision = plan.TargetConfigRevision
		result.ConfigSHA256 = plan.TargetConfigSHA256
		result.Message = "requested systemd port is running and verified"
	case systemdPortResultRolledBack:
		result.Status, result.Result = "rolled_back", systemdPortResultRolledBack
		result.StateKnown = true
		result.AppliedPort = plan.OldPort
		// The Panel already consumed target_endpoint_revision for the pending
		// generation. Closing it without promoting the requested endpoint
		// advances once more so a later job cannot reuse the aborted fence.
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "previous systemd port was restored and verified"
	case systemdPortResultUnchanged:
		result.Status, result.Result = "succeeded", systemdPortResultUnchanged
		result.StateKnown = true
		result.AppliedPort = plan.OldPort
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "systemd port mutation had not changed the verified previous state"
	default:
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "internal_error")
	}
	applied := systemdPortAppliedStateForResult(plan, result)
	ledger.Plan = plan
	ledger.State = systemdPortLedgerCommitting
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	if err := state.SaveApplied(applied); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	if runtime != nil {
		if err := runtime.CrashPoint("after_applied_state_save"); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "reconcile_required",
			)
		}
	}
	ledger.State = systemdPortLedgerTerminal
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	return localExecutorPortResponse(plan, result)
}

func systemdPortAppliedStateForResult(
	plan SystemdPortReconfigurePlan,
	result SystemdPortReconfigureResult,
) systemdPortAppliedState {
	if plan.PortContractVersion == 2 {
		ref := portV2ResultSnapshot(plan, result.Result)
		if ref == nil {
			return systemdPortAppliedState{}
		}
		return systemdPortAppliedState{SchemaVersion: systemdPortPlanSchemaVersion, TargetID: plan.TargetID, ServiceType: plan.ServiceType,
			Port: ref.LocalListenPort, EndpointRevision: ref.AppliedEndpointRevision, ConfigRevision: ref.ConfigRevision, ConfigSHA256: ref.ConfigSHA256,
			SourcePolicyRevision: ref.SourcePolicyRevision, UpdaterPolicyRevision: ref.ProjectionRevision, ExecutorPolicyRevision: ref.ExecutorPolicyRevision,
			ExecutorPolicySHA256: ref.ExecutorPolicySHA256, OwnershipEpoch: plan.OwnershipEpoch}
	}
	return systemdPortAppliedState{
		SchemaVersion: systemdPortPlanSchemaVersion,
		TargetID:      plan.TargetID, ServiceType: plan.ServiceType,
		Port: result.AppliedPort, EndpointRevision: result.EndpointRevision,
		ConfigRevision: result.ConfigRevision, ConfigSHA256: result.ConfigSHA256,
		SourcePolicyRevision:   plan.ExpectedSourcePolicyRevision,
		UpdaterPolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision: plan.ExpectedExecutorPolicyRevision,
		ExecutorPolicySHA256:   plan.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:         plan.OwnershipEpoch,
	}
}

func localExecutorPortResponse(
	plan SystemdPortReconfigurePlan,
	result SystemdPortReconfigureResult,
) LocalExecutorResponse {
	response := LocalExecutorResponse{
		Version:    LocalExecutorMutationProtocolVersion,
		PortResult: &result, SessionID: plan.SessionID, PlanSHA256: plan.PortPlanSHA256,
	}
	if err := response.Validate(); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "internal_error")
	}
	return response
}

func systemdPortTargetAfter(
	target LocalExecutorTarget,
	plan SystemdPortReconfigurePlan,
) LocalExecutorTarget {
	updated := target
	updated.LocalListen.Port = plan.NewPort
	updated.EndpointRevision = plan.TargetEndpointRevision
	updated.ConfigRevision = plan.TargetConfigRevision
	updated.ConfigSHA256 = plan.TargetConfigSHA256
	return updated
}

func sameSystemdPortCheckpoint(left, right systemdPortSidecarCheckpoint) bool {
	return left.Existed == right.Existed &&
		left.Mode == right.Mode &&
		left.SHA256 == right.SHA256 &&
		string(left.Bytes) == string(right.Bytes)
}

func sameSystemdPortIntent(left, right SystemdPortReconfigurePlan) bool {
	left.LeaseGeneration = 0
	left.PortPlanSHA256 = ""
	right.LeaseGeneration = 0
	right.PortPlanSHA256 = ""
	if left.PortContractVersion == 2 && right.PortContractVersion == 2 {
		left.SessionID, right.SessionID = "", ""
	}
	return reflect.DeepEqual(left, right)
}

func (p SystemdPortReconfigurePlan) mutationGrantBinding() *SystemdPortMutationGrantBinding {
	if p.PortContractVersion == 2 {
		return &SystemdPortMutationGrantBinding{PortContractVersion: 2, Mode: p.Mode,
			Before: clonePortSnapshotRef(p.Before), Target: clonePortSnapshotRef(p.Target), Rollback: clonePortSnapshotRef(p.Rollback),
			DockerBaseline: clonePortDockerBaseline(p.DockerBaseline), NetworkNamespace: p.NetworkNamespace,
			Protocol: p.Protocol, PortPlanSHA256: p.PortIntentSHA256}
	}
	return &SystemdPortMutationGrantBinding{
		NetworkNamespace: p.NetworkNamespace, Protocol: p.Protocol,
		OldPort: p.OldPort, NewPort: p.NewPort,
		ExpectedEndpointRevision:       p.ExpectedEndpointRevision,
		TargetEndpointRevision:         p.TargetEndpointRevision,
		ExpectedConfigRevision:         p.ExpectedConfigRevision,
		TargetConfigRevision:           p.TargetConfigRevision,
		ExpectedConfigSHA256:           p.ExpectedConfigSHA256,
		TargetConfigSHA256:             p.TargetConfigSHA256,
		ExpectedSourcePolicyRevision:   p.ExpectedSourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  p.ExpectedUpdaterPolicyRevision,
		ExpectedExecutorPolicyRevision: p.ExpectedExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   p.ExpectedExecutorPolicySHA256,
		PortPlanSHA256:                 p.PortPlanSHA256,
		Docker:                         cloneDockerPortMutationGrantBinding(p.Docker),
	}
}

func cloneDockerPortMutationGrantBinding(
	input *DockerPortMutationGrantBinding,
) *DockerPortMutationGrantBinding {
	if input == nil {
		return nil
	}
	copy := *input
	return &copy
}

func handleLocalExecutorSystemdPortMutation(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	remoteRuntime executorMutationRuntime,
) LocalExecutorResponse {
	if remoteRuntime.platformOS == "" {
		remoteRuntime.platformOS = runtime.GOOS
	}
	if remoteRuntime.platformOS != "linux" || request.PortPlan == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_unavailable")
	}
	target, ok := policy.Target(request.ServiceID)
	if !ok {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_not_found")
	}
	if target.DeploymentMode != ModeSystemd || target.Systemd == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}
	secured, err := securePrivilegedTarget(target.runtimeTarget(policy.HostID))
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_unavailable")
	}
	unlock, err := acquireTargetLock(secured)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_busy")
	}
	defer unlock()
	portRuntime, state, err := newPlatformSystemdPortExecution(policy, target, secured, remoteRuntime)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	return executeSystemdPortRequest(ctx, policy, request, portRuntime, state)
}
