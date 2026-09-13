package hostruntime

import (
	"context"
	"errors"
)

type dockerPortRuntime interface {
	Observe(context.Context, LocalExecutorPolicy, LocalExecutorTarget) (dockerPortObservation, error)
	Prepare(context.Context, LocalExecutorTarget, []byte) (dockerPortPreparedModel, error)
	EnsureAvailable(context.Context, LocalExecutorTarget, dockerPortPreparedModel, string) error
	ConsumeGrant(context.Context, SystemdPortReconfigurePlan, string, string, BoundedSecret) error
	Write(dockerPortMappingCheckpoint, []byte) error
	Restore(dockerPortMappingCheckpoint, []byte) error
	Recreate(context.Context, LocalExecutorTarget, dockerPortPreparedModel) error
	CrashPoint(string) error
}

func executeDockerPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	if request.PortPlan != nil && request.PortPlan.PortContractVersion == 2 {
		return executeDockerPortV2Request(ctx, policy, request, runtime, state)
	}
	failure := func(code string) LocalExecutorResponse {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, code)
	}
	if runtime == nil || state == nil || request.PortPlan == nil {
		return failure("internal_error")
	}
	plan := *request.PortPlan
	target, adapter, err := validateDockerPortPolicyBinding(policy, request, plan)
	if err != nil {
		return failure("config_mismatch")
	}
	historical, err := state.LoadJob(plan.TargetID, plan.JobID)
	if err != nil {
		return failure("state_invalid")
	}
	if historical != nil {
		if historical.validate(plan.TargetID) != nil ||
			!sameSystemdPortIntent(historical.Plan, plan) {
			return failure("plan_conflict")
		}
		if historical.State == dockerPortLedgerTerminal {
			return localExecutorPortResponse(plan, *historical.Result)
		}
	}
	active, err := state.LoadActive(plan.TargetID)
	if err != nil {
		return failure("state_invalid")
	}
	if active != nil && active.Plan.JobID != plan.JobID &&
		active.State != dockerPortLedgerTerminal {
		return failure("target_busy")
	}
	ledger := historical
	if ledger == nil && active != nil && active.Plan.JobID == plan.JobID {
		ledger = active
	}
	if ledger != nil && ledger.State == dockerPortLedgerCommitting {
		if request.Operation != "port_reconfigure_reconcile" {
			return failure("reconcile_required")
		}
		return repairDockerPortCommit(
			ctx, policy, request, target, *ledger, runtime, state,
		)
	}
	target, err = resolveDockerPortAppliedTargetForTransaction(
		policy, target, state, ledger,
	)
	if err != nil || !dockerPortTargetMatchesExpected(target, plan) {
		return failure("config_mismatch")
	}
	if request.Operation == "port_reconfigure_reconcile" {
		return reconcileDockerPortRequest(
			ctx, policy, request, target, adapter, ledger, runtime, state,
		)
	}
	if request.Operation != "port_reconfigure" {
		return failure("invalid_request")
	}
	if ledger == nil {
		created, err := stageDockerPortLedger(ctx, policy, target, adapter, plan, runtime)
		if err != nil {
			return failure("mutation_precondition_failed")
		}
		if err := state.Stage(created); err != nil {
			return failure("state_unavailable")
		}
		ledger = &created
	}
	if ledger.State != dockerPortLedgerStaged {
		return failure("reconcile_required")
	}
	if err := recheckDockerPortStagedInputs(ctx, policy, target, *ledger, runtime); err != nil {
		return failure("mutation_precondition_failed")
	}
	working := cloneDockerPortLedger(*ledger)
	working.Plan = plan
	working.State = dockerPortLedgerGrantConsuming
	if err := state.Save(working); err != nil {
		return failure("state_unavailable")
	}
	if err := runtime.ConsumeGrant(
		ctx, plan, request.Operation, working.Baseline.CurrentVersion,
		request.MutationGrant,
	); err != nil {
		working.State = dockerPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	working.State = dockerPortLedgerGrantConsumed
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_grant_consume"); err != nil {
		working.State = dockerPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	if err := recheckDockerPortStagedInputs(ctx, policy, target, working, runtime); err != nil {
		return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
	}
	if err := runtime.Write(working.Checkpoint, working.TargetBytes); err != nil {
		return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
	}
	working.State = dockerPortLedgerEnvWritten
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_port_env_write"); err != nil {
		working.State = dockerPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	prepared := dockerPortPreparedModel{
		ComposePolicySHA256: plan.Docker.ApprovedComposeConfigSHA256,
		ComposeConfigSHA256: working.TargetComposeSHA256,
		PublishedHostIP:     plan.Docker.PublishedHostIP,
		PublishedPort:       plan.Docker.NewPublishedPort,
		ContainerPort:       plan.Docker.NewContainerPort,
		HealthPort:          plan.Docker.NewHealthPort,
	}
	newTarget := dockerPortTargetAfter(target, plan, working.TargetComposeSHA256)
	if err := runtime.Recreate(ctx, newTarget, prepared); err != nil {
		return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
	}
	working.State = dockerPortLedgerRecreated
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_docker_recreate"); err != nil {
		working.State = dockerPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	observation, err := runtime.Observe(ctx, policy, newTarget)
	if err != nil || !dockerPortObservationMatchesTarget(
		observation, plan, working, true,
	) {
		return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
	}
	return commitDockerPortResult(
		plan, working, systemdPortResultApplied, observation.ComposeConfigSHA256,
		runtime, state,
	)
}

func validateDockerPortPolicyBinding(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	plan SystemdPortReconfigurePlan,
) (LocalExecutorTarget, dockerPortAdapter, error) {
	if request.Validate() != nil ||
		plan.Validate() != nil ||
		plan.effectiveDeploymentMode() != ModeDocker ||
		request.ServiceID != plan.TargetID ||
		request.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		request.OwnershipEpoch != plan.OwnershipEpoch ||
		request.OwnershipPolicyRevision != plan.ExpectedUpdaterPolicyRevision ||
		request.ExecutorPolicyRevision != plan.ExpectedExecutorPolicyRevision {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port request fence is invalid")
	}
	if policy.Validate() != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil ||
		policy.HostID != plan.HostID ||
		policy.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		policy.ProjectionRevision != plan.ExpectedUpdaterPolicyRevision ||
		policy.PolicyRevision != plan.ExpectedExecutorPolicyRevision {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port root policy revision is stale")
	}
	policySHA256, err := policy.SHA256()
	if err != nil || policySHA256 != plan.ExpectedExecutorPolicySHA256 {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port root policy digest is stale")
	}
	target, ok := policy.Target(plan.TargetID)
	if !ok || target.DeploymentMode != ModeDocker ||
		target.Docker == nil ||
		target.ServiceType != plan.ServiceType ||
		target.LocalListen.Host != plan.Docker.PublishedHostIP ||
		target.Docker.PortComposePolicySHA256 != plan.Docker.ApprovedComposeConfigSHA256 ||
		target.Docker.PortComposeRevision != plan.Docker.ApprovedComposeRevision {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port root target does not match the plan")
	}
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil {
		return LocalExecutorTarget{}, dockerPortAdapter{}, err
	}
	targetBytes, err := dockerPortEnvBytes(
		adapter, plan.Docker.NewPublishedPort,
		plan.Docker.NewContainerPort, plan.TargetConfigRevision,
	)
	if err != nil || dockerPortEnvSHA256(targetBytes) != plan.TargetConfigSHA256 {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port target env digest is invalid")
	}
	return target, adapter, nil
}

func resolveDockerPortAppliedTarget(
	policy LocalExecutorPolicy,
	policyTarget LocalExecutorTarget,
	state dockerPortAppliedStateReader,
) (LocalExecutorTarget, error) {
	return resolveDockerPortAppliedTargetBound(
		policy, policyTarget, state, true,
	)
}

func resolveDockerPortAppliedTargetForTransaction(
	policy LocalExecutorPolicy,
	policyTarget LocalExecutorTarget,
	state dockerPortAppliedStateReader,
	ledger *dockerPortLedger,
) (LocalExecutorTarget, error) {
	// Once a durable transaction has crossed the staged boundary, the mapping
	// sidecar may legitimately contain either the checkpoint or target bytes.
	// Requiring it to still match the preceding applied overlay would make a
	// process restart after Write or Recreate impossible to reconcile. The
	// ledger remains root-bound and reconciliation immediately observes both
	// exact old and target models before committing either outcome.
	verifySidecar := ledger == nil || ledger.State == dockerPortLedgerStaged
	return resolveDockerPortAppliedTargetBound(
		policy, policyTarget, state, verifySidecar,
	)
}

func resolveDockerPortAppliedTargetBound(
	policy LocalExecutorPolicy,
	policyTarget LocalExecutorTarget,
	state dockerPortAppliedStateReader,
	verifySidecar bool,
) (LocalExecutorTarget, error) {
	applied, err := state.LoadDockerApplied(policyTarget.ServiceID)
	if err != nil {
		return LocalExecutorTarget{}, err
	}
	if applied == nil {
		return policyTarget, nil
	}
	var useOverlay bool
	if applied.PortContractVersion == 2 {
		useOverlay, err = validateDockerPortV2AppliedAuthority(policy, policyTarget, *applied, state)
	} else {
		useOverlay, err = applied.validateForPolicy(policy, policyTarget)
	}
	if err != nil {
		return LocalExecutorTarget{}, err
	}
	if verifier, ok := state.(dockerPortAppliedSidecarVerifier); ok &&
		verifySidecar {
		if err := verifier.VerifyAppliedDockerSidecar(
			policyTarget, *applied,
		); err != nil {
			return LocalExecutorTarget{}, err
		}
	}
	if !useOverlay {
		return policyTarget, nil
	}
	target := policyTarget
	target.LocalListen.Port = applied.HealthPort
	target.EndpointRevision = applied.EndpointRevision
	target.ConfigRevision = applied.ConfigRevision
	target.ConfigSHA256 = applied.ConfigSHA256
	docker := *target.Docker
	docker.ComposeConfigSHA256 = applied.ComposeConfigSHA256
	target.Docker = &docker
	return target, nil
}

func dockerPortTargetMatchesExpected(
	target LocalExecutorTarget,
	plan SystemdPortReconfigurePlan,
) bool {
	return target.Docker != nil &&
		target.LocalListen.Port == plan.Docker.OldHealthPort &&
		target.EndpointRevision > 0 &&
		target.EndpointRevision <= plan.ExpectedEndpointRevision &&
		target.ConfigRevision == plan.ExpectedConfigRevision &&
		target.ConfigSHA256 == plan.ExpectedConfigSHA256 &&
		target.Docker.PortComposePolicySHA256 ==
			plan.Docker.ApprovedComposeConfigSHA256 &&
		target.Docker.PortComposeRevision ==
			plan.Docker.ApprovedComposeRevision
}
