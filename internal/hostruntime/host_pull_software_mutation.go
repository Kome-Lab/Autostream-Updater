package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func (a *HostPullAgent) recoverExecutionPlan(policy HostAgentPolicy, job UpdateJob) (MutationPlan, error) {
	stored := a.Journal.ActivePlan()
	if stored == nil || stored.Validate() != nil ||
		stored.JobID != job.ID ||
		stored.HostID != job.HostID ||
		stored.TargetID != job.TargetID ||
		stored.ServiceType != job.EffectiveType() ||
		stored.DeploymentMode != job.DeploymentMode ||
		stored.CurrentVersion != strings.TrimSpace(job.CurrentVersion) ||
		stored.TargetVersion != job.EffectiveVersion() ||
		stored.ConfigSHA256 != policy.LocalExecutorPolicySHA256 {
		return MutationPlan{}, errors.New("durable recovery plan does not match the recovered job")
	}
	rebound := *stored
	rebound.LeaseGeneration = job.LeaseGeneration
	digest, err := rebound.ComputePlanSHA256()
	if err != nil {
		return MutationPlan{}, err
	}
	rebound.PlanSHA256 = digest
	if err := rebound.Validate(); err != nil {
		return MutationPlan{}, err
	}
	if err := a.Journal.SetActivePlan(rebound); err != nil {
		return MutationPlan{}, err
	}
	return rebound, nil
}

func (a *HostPullAgent) finishExecutionResult(
	terminal func(string, string, string, ApplyResult) error,
	result ApplyResult,
) error {
	if result.Status == "rolled_back" || result.RolledBack {
		return terminal("rolled_back", "post_update_verification_failed", "previous target state was restored and verified", result)
	}
	return terminal("succeeded", "", "target updated and verified", result)
}

func (a *HostPullAgent) prepareExecutionPlan(ctx context.Context, policy HostAgentPolicy, job UpdateJob) (MutationPlan, error) {
	target, ok := hostPullPolicyTarget(policy, job.TargetID)
	if !ok {
		return MutationPlan{}, errors.New("host pull policy target is unavailable")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return MutationPlan{}, errors.New("host pull execution architecture is unsupported")
	}
	jobDir, err := ensurePrivateJobDirectory(a.StateDir, job.ID)
	if err != nil {
		return MutationPlan{}, err
	}
	verificationDir := filepath.Join(jobDir, fmt.Sprintf("verification-%d", job.LeaseGeneration))
	if err := os.RemoveAll(verificationDir); err != nil {
		return MutationPlan{}, errors.New("clear incomplete host release verification")
	}
	applyPlan := ApplyPlan{
		JobID: job.ID, HostID: job.HostID, TargetID: job.TargetID,
		ServiceType: target.ServiceType, DeploymentMode: target.DeploymentMode,
		TargetVersion: job.EffectiveVersion(), CurrentVersion: strings.TrimSpace(job.CurrentVersion),
		ConfigSHA256: policy.LocalExecutorPolicySHA256, LeaseGeneration: job.LeaseGeneration,
	}
	switch target.DeploymentMode {
	case ModeSystemd:
		artifact, err := a.Downloader.Download(ctx, target.ServiceType, applyPlan.TargetVersion, runtime.GOARCH, filepath.Join(verificationDir, "artifact"))
		if err != nil {
			return MutationPlan{}, err
		}
		applyPlan.ArtifactDigest = artifact.SHA256
		applyPlan.ExpectedVersion = applyPlan.TargetVersion
	case ModeDocker:
		imageRepo, err := dockerImageRepoForService(target.ServiceType)
		if err != nil {
			return MutationPlan{}, err
		}
		resolved, err := a.Downloader.ResolveDockerReleaseForArch(
			ctx, applyPlan.TargetVersion, target.ServiceType, imageRepo, "docker",
			runtime.GOARCH, filepath.Join(verificationDir, "docker"),
		)
		if err != nil {
			return MutationPlan{}, err
		}
		applyPlan.ArtifactDigest = strings.TrimPrefix(normalizeDigest(resolved.ManifestSHA256), "sha256:")
		applyPlan.ExpectedVersion = resolved.SourceVersion
		applyPlan.ExpectedImageDigest = resolved.ManifestDigest
		applyPlan.ExpectedPlatformDigest = resolved.PlatformDigest
	default:
		return MutationPlan{}, errors.New("host pull target deployment mode is unsupported")
	}
	planSHA256, err := MutationPlanSHA256(applyPlan)
	if err != nil {
		return MutationPlan{}, err
	}
	sessionID, err := a.NewSessionID()
	if err != nil {
		return MutationPlan{}, err
	}
	plan := MutationPlan{
		JobID: applyPlan.JobID, HostID: applyPlan.HostID, TargetID: applyPlan.TargetID,
		ServiceType: applyPlan.ServiceType, DeploymentMode: applyPlan.DeploymentMode,
		CurrentVersion: applyPlan.CurrentVersion, ConfigSHA256: applyPlan.ConfigSHA256,
		TargetVersion: applyPlan.TargetVersion, LeaseGeneration: applyPlan.LeaseGeneration,
		ArtifactDigest: applyPlan.ArtifactDigest, ExpectedVersion: applyPlan.ExpectedVersion,
		ExpectedImageDigest: applyPlan.ExpectedImageDigest, ExpectedPlatformDigest: applyPlan.ExpectedPlatformDigest,
		SessionID: sessionID, PlanSHA256: planSHA256,
	}
	if err := plan.Validate(); err != nil {
		return MutationPlan{}, err
	}
	return plan, nil
}

func (a *HostPullAgent) invokeExecutionMutation(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	binding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	plan MutationPlan,
	operation string,
) (ApplyResult, error) {
	var requiredV2Executor LocalExecutorV2MutationClient
	if job.ProtocolVersion == 2 {
		var ok bool
		requiredV2Executor, ok = a.Executor.(LocalExecutorV2MutationClient)
		if !ok {
			return ApplyResult{}, errors.New("local executor does not support v2 mutation grants")
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
			DeploymentMode: job.DeploymentMode, Operation: operation,
			PlanSHA256: plan.PlanSHA256, SessionID: plan.SessionID,
		},
	})
	if err != nil {
		return ApplyResult{}, err
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          binding.OwnershipEpoch,
		OwnershipPolicyRevision: job.PolicyRevision,
		ExecutorPolicyRevision:  policy.LocalExecutorPolicyRevision,
	}
	if grant.V2Binding != nil {
		v2Executor := requiredV2Executor
		if v2Executor == nil {
			var ok bool
			v2Executor, ok = a.Executor.(LocalExecutorV2MutationClient)
			if !ok {
				return ApplyResult{}, errors.New("local executor does not support v2 mutation grants")
			}
		}
		if err := validateV2SoftwareExecutionGrant(
			hostPullExecutionNow(panel), a.Bootstrap.NodeID, binding, policy,
			job, plan, operation, *grant.V2Binding,
		); err != nil {
			return ApplyResult{}, err
		}
		v2Grant := V2MutationGrant{
			Token: NewBoundedSecret(grant.Token), Binding: *grant.V2Binding,
		}
		if operation == "apply" {
			return v2Executor.ApplyV2(ctx, plan, fence, v2Grant)
		}
		return v2Executor.ReconcileV2(ctx, plan, fence, v2Grant)
	}
	if job.ProtocolVersion == 2 {
		return ApplyResult{}, errors.New("v2 mutation grant binding is unavailable")
	}
	if operation == "apply" {
		return a.Executor.Apply(ctx, plan, fence, NewBoundedSecret(grant.Token))
	}
	return a.Executor.Reconcile(ctx, plan, fence, NewBoundedSecret(grant.Token))
}

func hostPullExecutionNow(panel HostPullExecutionControlPlane) time.Time {
	if clock, ok := panel.(interface{ now() time.Time }); ok {
		return clock.now().UTC()
	}
	return time.Now().UTC()
}
