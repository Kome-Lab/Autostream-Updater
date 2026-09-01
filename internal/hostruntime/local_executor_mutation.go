package hostruntime

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/controlplane"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
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
		if request.MutationGrantV2Binding != nil {
			if rt.now == nil {
				rt.now = time.Now
			}
			if err := validateV2PortMutationGrantBinding(
				rt.now().UTC(), *request.MutationGrantV2Binding,
				request.Operation, *request.PortPlan,
				LocalExecutorMutationFence{
					SourcePolicyRevision:    request.SourcePolicyRevision,
					OwnershipEpoch:          request.OwnershipEpoch,
					OwnershipPolicyRevision: request.OwnershipPolicyRevision,
					ExecutorPolicyRevision:  request.ExecutorPolicyRevision,
				},
				&policy, &target,
			); err != nil {
				return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
			}
		}
		rt.v2GrantBinding = request.MutationGrantV2Binding
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
	if request.MutationGrantV2Binding != nil {
		if rt.now == nil {
			rt.now = time.Now
		}
		if err := validateV2SoftwareMutationGrantBinding(
			rt.now().UTC(), *request.MutationGrantV2Binding,
			request.Operation, *request.Plan,
			LocalExecutorMutationFence{
				SourcePolicyRevision:    request.SourcePolicyRevision,
				OwnershipEpoch:          request.OwnershipEpoch,
				OwnershipPolicyRevision: request.OwnershipPolicyRevision,
				ExecutorPolicyRevision:  request.ExecutorPolicyRevision,
			},
			&policy, &localTarget,
		); err != nil {
			return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
		}
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
	if rt.consumeV2Grant == nil {
		rt.consumeV2Grant = controlplane.ConsumeMutationGrant
	}
	if rt.now == nil {
		rt.now = time.Now
	}
	if rt.platformOS == "" {
		rt.platformOS = runtime.GOOS
	}
	rt.platformArch = arch
	rt.ownershipEpoch = request.OwnershipEpoch
	rt.policyRevision = request.OwnershipPolicyRevision
	rt.transportMode = HostTransportPullV2
	rt.publicArtifactsOnly = true
	rt.v2GrantBinding = request.MutationGrantV2Binding

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

func validateV2SoftwareMutationGrantBinding(
	now time.Time,
	binding contracts.UpdaterMutationGrantBinding,
	operation string,
	plan MutationPlan,
	fence LocalExecutorMutationFence,
	policy *LocalExecutorPolicy,
	rootTarget *LocalExecutorTarget,
) error {
	if contracts.ValidateUpdaterMutationGrantBinding(now, binding) != nil ||
		plan.Validate() != nil ||
		binding.Operation != contracts.UpdaterMutationOperation(operation) ||
		binding.SessionID != plan.SessionID ||
		(operation != "apply" && operation != "reconcile") {
		return errors.New("v2 software mutation grant is invalid")
	}
	lease := binding.Lease
	command := lease.Command
	authorization := command.MutationAuthorization
	target := authorization.Target
	desired := command.DesiredOperation
	if desired.Operation != contracts.UpdaterDesiredSoftwareUpdate ||
		desired.SoftwareUpdate == nil ||
		desired.SoftwareUpdate.ExpectedCurrentVersion != plan.CurrentVersion ||
		desired.SoftwareUpdate.TargetVersion != plan.TargetVersion ||
		authorization.JobID != plan.JobID ||
		authorization.HostID != plan.HostID ||
		authorization.DesiredRevision != fence.OwnershipPolicyRevision ||
		authorization.Fence != fence.OwnershipEpoch ||
		lease.LeaseGeneration != int64(plan.LeaseGeneration) ||
		target.TargetKind != contracts.UpdaterTargetApplication ||
		target.ServiceID != plan.TargetID ||
		string(target.ServiceType) != plan.ServiceType ||
		string(target.DeploymentMode) != plan.DeploymentMode {
		return errors.New("v2 software mutation grant does not match the plan")
	}
	if policy == nil && rootTarget == nil {
		return nil
	}
	if policy == nil || rootTarget == nil || policy.Validate() != nil ||
		policy.HostID != authorization.HostID ||
		policy.SourcePolicyRevision != fence.SourcePolicyRevision ||
		policy.ProjectionRevision != authorization.DesiredRevision ||
		policy.PolicyRevision != fence.ExecutorPolicyRevision ||
		rootTarget.ServiceID != target.ServiceID ||
		rootTarget.ServiceType != string(target.ServiceType) ||
		rootTarget.DeploymentMode != string(target.DeploymentMode) ||
		rootTarget.ConfigRevision != target.ExpectedConfigRevision {
		return errors.New("v2 software mutation grant does not match root policy")
	}
	policySHA256, err := policy.SHA256()
	if err != nil || policySHA256 != plan.ConfigSHA256 {
		return errors.New("v2 software mutation plan does not match root policy digest")
	}
	return nil
}

func validateV2PortMutationGrantBinding(
	now time.Time,
	binding contracts.UpdaterMutationGrantBinding,
	operation string,
	plan SystemdPortReconfigurePlan,
	fence LocalExecutorMutationFence,
	policy *LocalExecutorPolicy,
	rootTarget *LocalExecutorTarget,
) error {
	if contracts.ValidateUpdaterMutationGrantBinding(now, binding) != nil ||
		plan.Validate() != nil ||
		binding.Operation != contracts.UpdaterMutationOperation(operation) ||
		binding.SessionID != plan.SessionID ||
		(operation != "port_reconfigure" && operation != "port_reconfigure_reconcile") {
		return errors.New("v2 port mutation grant is invalid")
	}
	lease := binding.Lease
	command := lease.Command
	authorization := command.MutationAuthorization
	target := authorization.Target
	desired := command.DesiredOperation
	if desired.Operation != contracts.UpdaterDesiredPortReconfigure ||
		!v2PortDesiredMatchesPlan(desired.PortReconfigure, plan) ||
		authorization.JobID != plan.JobID ||
		authorization.HostID != plan.HostID ||
		authorization.DesiredRevision != plan.ExpectedUpdaterPolicyRevision ||
		authorization.DesiredRevision != fence.OwnershipPolicyRevision ||
		authorization.Fence != plan.OwnershipEpoch ||
		authorization.Fence != fence.OwnershipEpoch ||
		lease.LeaseGeneration != int64(plan.LeaseGeneration) ||
		target.TargetKind != contracts.UpdaterTargetApplication ||
		target.ServiceID != plan.TargetID ||
		string(target.ServiceType) != plan.ServiceType ||
		string(target.DeploymentMode) != plan.effectiveDeploymentMode() ||
		target.ExpectedConfigRevision != plan.ExpectedConfigRevision {
		return errors.New("v2 port mutation grant does not match the plan")
	}
	if policy == nil && rootTarget == nil {
		return nil
	}
	if policy == nil || rootTarget == nil || policy.Validate() != nil ||
		policy.HostID != authorization.HostID ||
		policy.SourcePolicyRevision != fence.SourcePolicyRevision ||
		policy.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		policy.ProjectionRevision != authorization.DesiredRevision ||
		policy.PolicyRevision != fence.ExecutorPolicyRevision ||
		policy.PolicyRevision != plan.ExpectedExecutorPolicyRevision ||
		rootTarget.ServiceID != target.ServiceID ||
		rootTarget.ServiceType != string(target.ServiceType) ||
		rootTarget.DeploymentMode != string(target.DeploymentMode) ||
		rootTarget.ConfigRevision != target.ExpectedConfigRevision ||
		rootTarget.ConfigSHA256 != plan.ExpectedConfigSHA256 {
		return errors.New("v2 port mutation grant does not match root policy")
	}
	policySHA256, err := policy.SHA256()
	if err != nil || policySHA256 != plan.ExpectedExecutorPolicySHA256 {
		return errors.New("v2 port mutation plan does not match root policy digest")
	}
	return nil
}

func v2PortDesiredMatchesPlan(
	desired *contracts.SystemUpdatePortReconfiguration,
	plan SystemdPortReconfigurePlan,
) bool {
	if desired == nil || desired.Result != "" ||
		desired.NetworkNamespace != plan.NetworkNamespace ||
		string(desired.Protocol) != plan.Protocol ||
		desired.OldPort != plan.OldPort ||
		desired.NewPort != plan.NewPort ||
		desired.ExpectedEndpointRevision != plan.ExpectedEndpointRevision ||
		desired.TargetEndpointRevision != plan.TargetEndpointRevision ||
		desired.ExpectedConfigRevision != plan.ExpectedConfigRevision ||
		desired.TargetConfigRevision != plan.TargetConfigRevision ||
		desired.ExpectedConfigSHA256 != plan.ExpectedConfigSHA256 ||
		desired.TargetConfigSHA256 != plan.TargetConfigSHA256 ||
		desired.ExpectedSourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		desired.ExpectedUpdaterPolicyRevision != plan.ExpectedUpdaterPolicyRevision ||
		desired.ExpectedExecutorPolicyRevision != plan.ExpectedExecutorPolicyRevision ||
		desired.ExpectedExecutorPolicySHA256 != plan.ExpectedExecutorPolicySHA256 {
		return false
	}
	if plan.Docker == nil || desired.Docker == nil {
		return plan.Docker == nil && desired.Docker == nil
	}
	return desired.Docker.PublishedHostIP == plan.Docker.PublishedHostIP &&
		desired.Docker.OldPublishedPort == plan.Docker.OldPublishedPort &&
		desired.Docker.NewPublishedPort == plan.Docker.NewPublishedPort &&
		desired.Docker.OldContainerPort == plan.Docker.OldContainerPort &&
		desired.Docker.NewContainerPort == plan.Docker.NewContainerPort &&
		desired.Docker.OldHealthPort == plan.Docker.OldHealthPort &&
		desired.Docker.NewHealthPort == plan.Docker.NewHealthPort &&
		desired.Docker.ApprovedComposeConfigSHA256 == plan.Docker.ApprovedComposeConfigSHA256 &&
		desired.Docker.ApprovedComposeRevision == plan.Docker.ApprovedComposeRevision &&
		desired.Docker.ExpectedVersionEnvSHA256 == plan.Docker.ExpectedVersionEnvSHA256 &&
		desired.Docker.ExpectedContainerID == plan.Docker.ExpectedContainerID &&
		desired.Docker.ExpectedImageID == plan.Docker.ExpectedImageID &&
		desired.Docker.ExpectedRepositoryDigest == plan.Docker.ExpectedRepositoryDigest
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
