package hostruntime

import (
	"context"
	"runtime"
	"strings"
)

// handleLocalExecutorMutation is the root-side software-update boundary. The
// Host Agent can select only a service ID already present in the root-owned
// policy and can supply only a digest-bound plan plus a one-time grant.
func handleLocalExecutorMutation(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	rt executorMutationRuntime,
) LocalExecutorResponse {
	if err := request.Validate(); err != nil || request.Operation == "probe" {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "invalid_request")
	}
	unlockLifecycle, err := acquireHostLifecycleLock()
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_busy")
	}
	defer unlockLifecycle()
	if strings.HasPrefix(request.Operation, "runtime_credential_") {
		return handleLocalExecutorRuntimeCredential(
			ctx, policy, request, defaultRuntimeCredentialExecutorRuntime(),
		)
	}
	if strings.HasPrefix(request.Operation, "host_self_update_") {
		return handleLocalExecutorHostSelfUpdate(
			ctx, policy, request, defaultHostSelfUpdateExecutorRuntime(),
		)
	}
	if request.Operation == "port_reconfigure" ||
		request.Operation == "port_reconfigure_reconcile" {
		if err := policy.Validate(); err != nil {
			return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "policy_invalid")
		}
		target, ok := policy.Target(request.ServiceID)
		if !ok {
			return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_not_found")
		}
		switch target.DeploymentMode {
		case ModeSystemd:
			return handleLocalExecutorSystemdPortMutation(ctx, policy, request, rt)
		case ModeDocker:
			return handleLocalExecutorDockerPortMutation(ctx, policy, request, rt)
		default:
			return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
		}
	}
	if err := policy.Validate(); err != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "policy_invalid")
	}
	if request.SourcePolicyRevision != policy.SourcePolicyRevision ||
		request.OwnershipPolicyRevision != policy.ProjectionRevision ||
		request.ExecutorPolicyRevision != policy.PolicyRevision {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}
	policyDigest, err := policy.SHA256()
	if err != nil || request.Plan == nil ||
		request.Plan.ConfigSHA256 != policyDigest ||
		request.Plan.HostID != policy.HostID ||
		request.Plan.TargetID != request.ServiceID {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}
	localTarget, ok := policy.Target(request.ServiceID)
	if !ok {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_not_found")
	}
	if localTarget.ServiceType != request.Plan.ServiceType ||
		localTarget.DeploymentMode != request.Plan.DeploymentMode {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}

	arch := rt.platformArch
	if arch == "" {
		arch = runtime.GOARCH
	}
	cfg, err := policy.mutationHelperConfig(arch)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "policy_invalid")
	}
	if rt.localStateDir != "" {
		cfg.StateDir = rt.localStateDir
	}
	target, ok := cfg.Target(request.ServiceID)
	if !ok {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_not_found")
	}
	if rt.runner == nil {
		rt.runner = OSCommandRunner{NewProcessGroup: true}
	}
	if rt.consumeGrant == nil {
		rt.consumeGrant = ConsumeMutationGrant
	}
	if rt.platformOS == "" {
		rt.platformOS = runtime.GOOS
	}
	rt.platformArch = arch
	rt.ownershipEpoch = request.OwnershipEpoch
	rt.policyRevision = request.OwnershipPolicyRevision
	rt.transportMode = HostTransportPullV2
	rt.publicArtifactsOnly = true

	if err := ensureExecutorStateDirectories(cfg); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	secured, err := securePrivilegedTarget(target)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_unavailable")
	}
	unlock, err := acquireTargetLock(secured)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_busy")
	}
	defer unlock()

	ledger, err := loadExecutorMutationLedger(cfg, request.ServiceID)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_invalid")
	}
	var remote executorMutationOutcome
	switch request.Operation {
	case "stage":
		// Public Kome-Lab release repositories are fetched anonymously. The
		// downloader pins owner/repository/API origins and verifies immutable
		// release/tag identity, manifest commit and checksums before staging.
		remote = executorStageRequest(ctx, cfg, secured, *request.Plan, "", ledger, rt)
	case "apply", "reconcile":
		remote = executorMutationRequest(ctx, cfg, secured, *request.Plan, request.Operation, request.MutationGrant, ledger, rt)
	default:
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "invalid_request")
	}
	return localExecutorResponseFromOutcome(remote)
}

func localExecutorResponseFromOutcome(remote executorMutationOutcome) LocalExecutorResponse {
	if remote.Error != nil {
		response := localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, remote.Error.Code)
		if response.Error != nil && response.Error.Code == remote.Error.Code && safeExecutorMessage(remote.Error.Message) {
			response.Error.Message = remote.Error.Message
		}
		return response
	}
	response := LocalExecutorResponse{
		Version: LocalExecutorMutationProtocolVersion,
		Stage:   remote.Stage, Result: remote.Result,
		SessionID: remote.SessionID, PlanSHA256: remote.PlanSHA256,
	}
	if err := response.Validate(); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "internal_error")
	}
	return response
}
