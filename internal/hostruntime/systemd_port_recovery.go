package hostruntime

import (
	"context"
)

// reconcileUnstartedSystemdPortRequest closes the response-loss window before
// the first request reaches the Local Executor. A fresh reconcile grant can
// prove that the exact previous sidecar and service are still active, persist a
// terminal unchanged ledger, and release the Panel's pending endpoint without
// writing configuration or restarting the service.
func reconcileUnstartedSystemdPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	target LocalExecutorTarget,
	adapter systemdPortAdapter,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	plan := *request.PortPlan
	checkpoint, err := runtime.Checkpoint(adapter)
	expectedOldBytes := systemdPortSidecarBytes(
		adapter.ServiceType,
		target.LocalListen.Host,
		plan.OldPort,
		plan.ExpectedConfigRevision,
	)
	if err != nil ||
		checkpoint.validate() != nil ||
		!checkpoint.Existed ||
		checkpoint.Mode != 0o600 ||
		checkpoint.SHA256 != plan.ExpectedConfigSHA256 ||
		string(checkpoint.Bytes) != string(expectedOldBytes) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "mutation_precondition_failed",
		)
	}
	currentVersion, err := runtime.Verify(ctx, policy, target)
	if err != nil || !versionPattern.MatchString(currentVersion) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "mutation_precondition_failed",
		)
	}
	targetBytes := systemdPortSidecarBytes(
		adapter.ServiceType,
		target.LocalListen.Host,
		plan.NewPort,
		plan.TargetConfigRevision,
	)
	if systemdPortSidecarSHA256(targetBytes) != plan.TargetConfigSHA256 {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "config_mismatch",
		)
	}
	working := systemdPortLedger{
		SchemaVersion:  systemdPortPlanSchemaVersion,
		Plan:           plan,
		State:          systemdPortLedgerStaged,
		Checkpoint:     checkpoint,
		TargetBytes:    targetBytes,
		CurrentVersion: currentVersion,
	}
	if err := state.Stage(working); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	working.State = systemdPortLedgerGrantConsuming
	if err := state.Save(working); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	if err := runtime.ConsumeGrant(
		ctx, plan, request.Operation, working.CurrentVersion, request.MutationGrant,
	); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	working.State = systemdPortLedgerGrantConsumed
	if err := state.Save(working); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	return commitSystemdPortResult(
		plan, working, systemdPortResultUnchanged, runtime, state,
	)
}

func reconcileSystemdPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	target LocalExecutorTarget,
	adapter systemdPortAdapter,
	ledger systemdPortLedger,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	plan := *request.PortPlan
	working := ledger
	working.Plan = plan
	working.State = systemdPortLedgerGrantConsuming
	working.Result = nil
	if err := state.Save(working); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	if err := runtime.ConsumeGrant(ctx, plan, request.Operation, working.CurrentVersion, request.MutationGrant); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "reconcile_required")
	}
	working.State = systemdPortLedgerGrantConsumed
	if err := state.Save(working); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "reconcile_required")
	}
	current, checkpointErr := runtime.Checkpoint(adapter)
	newTarget := systemdPortTargetAfter(target, plan)
	if checkpointErr == nil &&
		current.SHA256 == plan.TargetConfigSHA256 &&
		func() bool {
			_, err := runtime.Verify(ctx, policy, newTarget)
			return err == nil
		}() {
		return commitSystemdPortResult(
			plan, working, systemdPortResultApplied, runtime, state,
		)
	}
	if checkpointErr == nil &&
		sameSystemdPortCheckpoint(current, working.Checkpoint) &&
		func() bool {
			_, err := runtime.Verify(ctx, policy, target)
			return err == nil
		}() {
		return commitSystemdPortResult(
			plan, working, systemdPortResultUnchanged, runtime, state,
		)
	}
	return rollbackSystemdPortRequest(ctx, policy, plan, target, adapter, working, runtime, state)
}

func repairSystemdPortCommit(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	policyTarget LocalExecutorTarget,
	adapter systemdPortAdapter,
	ledger systemdPortLedger,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	plan := *request.PortPlan
	if ledger.State != systemdPortLedgerCommitting ||
		ledger.Result == nil ||
		ledger.Result.Validate() != nil ||
		ledger.Result.Result == systemdPortResultRollbackFailed {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_invalid",
		)
	}
	if err := runtime.ConsumeGrant(
		ctx, plan, request.Operation, ledger.CurrentVersion, request.MutationGrant,
	); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	result := *ledger.Result
	effective := policyTarget
	effective.LocalListen.Port = result.AppliedPort
	effective.EndpointRevision = result.EndpointRevision
	effective.ConfigRevision = result.ConfigRevision
	effective.ConfigSHA256 = result.ConfigSHA256
	expectedBytes := systemdPortSidecarBytes(
		adapter.ServiceType,
		effective.LocalListen.Host,
		effective.LocalListen.Port,
		effective.ConfigRevision,
	)
	current, err := runtime.Checkpoint(adapter)
	if err != nil ||
		!current.Existed ||
		current.Mode != 0o600 ||
		current.SHA256 != result.ConfigSHA256 ||
		systemdPortSidecarSHA256(expectedBytes) != result.ConfigSHA256 ||
		string(current.Bytes) != string(expectedBytes) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_invalid",
		)
	}
	if _, err := runtime.Verify(ctx, policy, effective); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	applied := systemdPortAppliedStateForResult(plan, result)
	if err := state.SaveApplied(applied); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	ledger.Plan = plan
	ledger.State = systemdPortLedgerTerminal
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}

func rollbackSystemdPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	plan SystemdPortReconfigurePlan,
	oldTarget LocalExecutorTarget,
	adapter systemdPortAdapter,
	ledger systemdPortLedger,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	if err := runtime.Restore(adapter, ledger.Checkpoint, ledger.TargetBytes); err == nil {
		if restartErr := runtime.Restart(ctx, oldTarget); restartErr == nil {
			if _, verifyErr := runtime.Verify(ctx, policy, oldTarget); verifyErr == nil {
				return commitSystemdPortResult(
					plan, ledger, systemdPortResultRolledBack, runtime, state,
				)
			}
		}
	}
	result := SystemdPortReconfigureResult{
		Status: "failed", Result: systemdPortResultRollbackFailed,
		StateKnown: false,
		OldPort:    plan.OldPort, NewPort: plan.NewPort, AppliedPort: 0,
		EndpointRevision: plan.TargetEndpointRevision,
		ConfigRevision:   0, ConfigSHA256: "",
		Message: "local rollback could not determine a verified effective port",
	}
	// The result is terminal but quarantined: no applied overlay is recorded,
	// and every later job must prove its own exact old-sidecar and endpoint
	// preconditions. Keeping rollback_failed non-terminal would leave the
	// active pointer permanently returning target_busy after the Panel closes
	// the failed job.
	ledger.Plan = plan
	ledger.State = systemdPortLedgerTerminal
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}
