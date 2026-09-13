package hostruntime

import (
	"context"
	"errors"
)

type systemdPortRuntime interface {
	Checkpoint(systemdPortAdapter) (systemdPortSidecarCheckpoint, error)
	EnsurePortAvailable(LocalExecutorEndpoint) error
	ConsumeGrant(context.Context, SystemdPortReconfigurePlan, string, string, BoundedSecret) error
	Write(systemdPortAdapter, systemdPortSidecarCheckpoint, []byte) error
	Restore(systemdPortAdapter, systemdPortSidecarCheckpoint, []byte) error
	Restart(context.Context, LocalExecutorTarget) error
	Verify(context.Context, LocalExecutorPolicy, LocalExecutorTarget) (string, error)
	CrashPoint(string) error
}

func executeSystemdPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	if request.PortPlan != nil && request.PortPlan.PortContractVersion == 2 {
		return executeSystemdPortV2Request(ctx, policy, request, runtime, state)
	}
	failure := func(code string) LocalExecutorResponse {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, code)
	}
	if runtime == nil || state == nil || request.PortPlan == nil {
		return failure("internal_error")
	}
	plan := *request.PortPlan
	policyTarget, adapter, err := validateSystemdPortPolicyBinding(policy, request, plan)
	if err != nil {
		return failure("config_mismatch")
	}
	historical, err := state.LoadJob(plan.TargetID, plan.JobID)
	if err != nil {
		return failure("state_invalid")
	}
	if historical != nil {
		if err := historical.validate(plan.TargetID); err != nil {
			return failure("state_invalid")
		}
		if !sameSystemdPortIntent(historical.Plan, plan) {
			return failure("plan_conflict")
		}
		if historical.State == systemdPortLedgerTerminal {
			return localExecutorPortResponse(plan, *historical.Result)
		}
	}
	active, err := state.LoadActive(plan.TargetID)
	if err != nil {
		return failure("state_invalid")
	}
	if active != nil && active.Plan.JobID != plan.JobID &&
		active.State != systemdPortLedgerTerminal {
		return failure("target_busy")
	}
	ledger := historical
	if ledger == nil && active != nil && active.Plan.JobID == plan.JobID {
		ledger = active
	}
	if ledger != nil && ledger.State == systemdPortLedgerCommitting {
		if request.Operation != "port_reconfigure_reconcile" {
			return failure("reconcile_required")
		}
		return repairSystemdPortCommit(
			ctx, policy, request, policyTarget, adapter, *ledger, runtime, state,
		)
	}
	target, err := resolveSystemdPortAppliedTarget(policy, policyTarget, state)
	if err != nil || !systemdPortTargetMatchesExpected(target, plan) {
		return failure("config_mismatch")
	}
	if request.Operation == "port_reconfigure_reconcile" {
		if ledger == nil {
			return reconcileUnstartedSystemdPortRequest(
				ctx, policy, request, target, adapter, runtime, state,
			)
		}
		return reconcileSystemdPortRequest(ctx, policy, request, target, adapter, *ledger, runtime, state)
	}
	if request.Operation != "port_reconfigure" {
		return failure("invalid_request")
	}
	if ledger == nil {
		checkpoint, err := runtime.Checkpoint(adapter)
		if err != nil || checkpoint.validate() != nil ||
			checkpoint.SHA256 != plan.ExpectedConfigSHA256 {
			return failure("mutation_precondition_failed")
		}
		expectedOldBytes := systemdPortSidecarBytes(
			adapter.ServiceType, target.LocalListen.Host, plan.OldPort, plan.ExpectedConfigRevision,
		)
		if checkpoint.Existed && string(checkpoint.Bytes) != string(expectedOldBytes) {
			return failure("mutation_precondition_failed")
		}
		if !checkpoint.Existed && checkpoint.SHA256 != systemdPortSidecarSHA256(nil) {
			return failure("mutation_precondition_failed")
		}
		currentVersion, err := runtime.Verify(ctx, policy, target)
		if err != nil || !versionPattern.MatchString(currentVersion) {
			return failure("mutation_precondition_failed")
		}
		newEndpoint := target.LocalListen
		newEndpoint.Port = plan.NewPort
		if err := runtime.EnsurePortAvailable(newEndpoint); err != nil {
			return failure("mutation_precondition_failed")
		}
		targetBytes := systemdPortSidecarBytes(
			adapter.ServiceType, target.LocalListen.Host, plan.NewPort, plan.TargetConfigRevision,
		)
		if systemdPortSidecarSHA256(targetBytes) != plan.TargetConfigSHA256 {
			return failure("config_mismatch")
		}
		record := systemdPortLedger{
			SchemaVersion: systemdPortPlanSchemaVersion, Plan: plan,
			State: systemdPortLedgerStaged, Checkpoint: checkpoint,
			TargetBytes: targetBytes, CurrentVersion: currentVersion,
		}
		if err := state.Stage(record); err != nil {
			return failure("state_unavailable")
		}
		ledger = &record
	}
	if ledger.State != systemdPortLedgerStaged {
		return failure("reconcile_required")
	}
	current, err := runtime.Checkpoint(adapter)
	if err != nil || !sameSystemdPortCheckpoint(current, ledger.Checkpoint) {
		return failure("reconcile_required")
	}
	newEndpoint := target.LocalListen
	newEndpoint.Port = plan.NewPort
	if err := runtime.EnsurePortAvailable(newEndpoint); err != nil {
		return failure("mutation_precondition_failed")
	}
	working := *ledger
	working.Plan = plan
	working.State = systemdPortLedgerGrantConsuming
	if err := state.Save(working); err != nil {
		return failure("state_unavailable")
	}
	if err := runtime.ConsumeGrant(ctx, plan, request.Operation, working.CurrentVersion, request.MutationGrant); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	working.State = systemdPortLedgerGrantConsumed
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_grant_consume"); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	if err := runtime.Write(adapter, working.Checkpoint, working.TargetBytes); err != nil {
		return rollbackSystemdPortRequest(ctx, policy, plan, target, adapter, working, runtime, state)
	}
	working.State = systemdPortLedgerSidecarWritten
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_sidecar_write"); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	newTarget := systemdPortTargetAfter(target, plan)
	if err := runtime.Restart(ctx, newTarget); err != nil {
		return rollbackSystemdPortRequest(ctx, policy, plan, target, adapter, working, runtime, state)
	}
	working.State = systemdPortLedgerRestarted
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_restart"); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	if _, err := runtime.Verify(ctx, policy, newTarget); err != nil {
		return rollbackSystemdPortRequest(ctx, policy, plan, target, adapter, working, runtime, state)
	}
	return commitSystemdPortResult(
		plan, working, systemdPortResultApplied, runtime, state,
	)
}

func validateSystemdPortPolicyBinding(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	plan SystemdPortReconfigurePlan,
) (LocalExecutorTarget, systemdPortAdapter, error) {
	if request.Validate() != nil || plan.Validate() != nil ||
		request.Operation != "port_reconfigure" && request.Operation != "port_reconfigure_reconcile" ||
		request.ServiceID != plan.TargetID ||
		request.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		request.OwnershipEpoch != plan.OwnershipEpoch ||
		request.OwnershipPolicyRevision != plan.ExpectedUpdaterPolicyRevision ||
		request.ExecutorPolicyRevision != plan.ExpectedExecutorPolicyRevision {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("request fence does not match the port plan")
	}
	if policy.Validate() != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil ||
		policy.HostID != plan.HostID ||
		policy.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		policy.ProjectionRevision != plan.ExpectedUpdaterPolicyRevision ||
		policy.PolicyRevision != plan.ExpectedExecutorPolicyRevision {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("root policy revision does not match the port plan")
	}
	policySHA, err := policy.SHA256()
	if err != nil || policySHA != plan.ExpectedExecutorPolicySHA256 {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("root policy digest does not match the port plan")
	}
	target, ok := policy.Target(plan.TargetID)
	if !ok || target.DeploymentMode != ModeSystemd || target.Systemd == nil ||
		target.ServiceType != plan.ServiceType {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("root target identity does not match the port plan")
	}
	adapter, err := systemdPortAdapterFor(target.ServiceType, target.Systemd.Unit)
	if err != nil {
		return LocalExecutorTarget{}, systemdPortAdapter{}, err
	}
	expectedTarget := systemdPortSidecarBytes(
		adapter.ServiceType, target.LocalListen.Host, plan.NewPort, plan.TargetConfigRevision,
	)
	if systemdPortSidecarSHA256(expectedTarget) != plan.TargetConfigSHA256 {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("target sidecar digest does not match the fixed adapter")
	}
	return target, adapter, nil
}

func resolveSystemdPortAppliedTarget(
	policy LocalExecutorPolicy,
	policyTarget LocalExecutorTarget,
	state systemdPortAppliedStateReader,
) (LocalExecutorTarget, error) {
	applied, err := state.LoadApplied(policyTarget.ServiceID)
	if err != nil {
		return LocalExecutorTarget{}, err
	}
	if applied == nil {
		return policyTarget, nil
	}
	useOverlay, err := applied.validateForPolicy(policy, policyTarget)
	if err != nil {
		return LocalExecutorTarget{}, err
	}
	if verifier, ok := state.(systemdPortAppliedSidecarVerifier); ok {
		if err := verifier.VerifyAppliedSidecar(policyTarget, *applied); err != nil {
			return LocalExecutorTarget{}, err
		}
	}
	if !useOverlay {
		return policyTarget, nil
	}
	target := policyTarget
	target.LocalListen.Port = applied.Port
	target.EndpointRevision = applied.EndpointRevision
	target.ConfigRevision = applied.ConfigRevision
	target.ConfigSHA256 = applied.ConfigSHA256
	return target, nil
}

func systemdPortTargetMatchesExpected(
	target LocalExecutorTarget,
	plan SystemdPortReconfigurePlan,
) bool {
	return target.LocalListen.Port == plan.OldPort &&
		// Queued cancellations consume server-side endpoint generations
		// without reaching this root-owned runtime. A forward-only gap is safe
		// when the actual port and complete config identity still match and the
		// surrounding policy/ownership/grant fences have already been checked.
		target.EndpointRevision > 0 &&
		target.EndpointRevision <= plan.ExpectedEndpointRevision &&
		target.ConfigRevision == plan.ExpectedConfigRevision &&
		target.ConfigSHA256 == plan.ExpectedConfigSHA256
}
