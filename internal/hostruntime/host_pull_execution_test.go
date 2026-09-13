package hostruntime

import (
	"context"
	"errors"
	"strings"
)

type hostPullExecutionTestPanel struct {
	job          *UpdateJob
	clearActive  bool
	claims       []HostPullClaimRequest
	reports      []JobReport
	reportErrors []error
	grants       []MutationGrantRequest
	grantErrors  []error
	grantResults []MutationGrant
}

func (*hostPullExecutionTestPanel) RegisterHostAgent(context.Context, Config, map[string]any) (HostAgentBinding, error) {
	return HostAgentBinding{}, errors.New("not used")
}
func (*hostPullExecutionTestPanel) HeartbeatHostAgent(context.Context, Config, string, map[string]any) error {
	return errors.New("not used")
}
func (*hostPullExecutionTestPanel) FetchHostAgentPolicy(context.Context, string, int64) (*HostAgentPolicy, bool, error) {
	return nil, false, errors.New("not used")
}
func (p *hostPullExecutionTestPanel) ClaimHost(_ context.Context, request HostPullClaimRequest) (*UpdateJob, bool, error) {
	p.claims = append(p.claims, request)
	if p.job == nil {
		return nil, false, nil
	}
	copy := *p.job
	return &copy, p.clearActive, nil
}
func (p *hostPullExecutionTestPanel) Report(_ context.Context, _ string, report JobReport) error {
	if len(p.reportErrors) > 0 {
		err := p.reportErrors[0]
		p.reportErrors = p.reportErrors[1:]
		if err != nil {
			return err
		}
	}
	p.reports = append(p.reports, report)
	return nil
}
func (p *hostPullExecutionTestPanel) IssueMutationGrant(_ context.Context, _ string, request MutationGrantRequest) (MutationGrant, error) {
	p.grants = append(p.grants, request)
	if len(p.grantErrors) > 0 {
		err := p.grantErrors[0]
		p.grantErrors = p.grantErrors[1:]
		if err != nil {
			return MutationGrant{}, err
		}
	}
	if len(p.grantResults) > 0 {
		grant := p.grantResults[0]
		p.grantResults = p.grantResults[1:]
		return grant, nil
	}
	return MutationGrant{Token: "ast_mutation_" + strings.Repeat("a", 43), ExpiresAt: "2099-01-01T00:00:00Z"}, nil
}

type hostPullExecutionTestDownloader struct{}

func (hostPullExecutionTestDownloader) Download(context.Context, string, string, string, string) (DownloadedArtifact, error) {
	return DownloadedArtifact{SHA256: strings.Repeat("a", 64)}, nil
}

type hostPullFailingDownloader struct{}

func (hostPullFailingDownloader) Download(context.Context, string, string, string, string) (DownloadedArtifact, error) {
	return DownloadedArtifact{}, errors.New("release provider unavailable")
}
func (hostPullFailingDownloader) ResolveDockerReleaseForArch(context.Context, string, string, string, string, string, string) (ResolvedDockerRelease, error) {
	return ResolvedDockerRelease{}, errors.New("release provider unavailable")
}
func (hostPullExecutionTestDownloader) ResolveDockerReleaseForArch(context.Context, string, string, string, string, string, string) (ResolvedDockerRelease, error) {
	return ResolvedDockerRelease{}, errors.New("not used")
}

type hostPullExecutionTestExecutor struct {
	stageCalls       int
	applyCalls       int
	reconcileCalls   int
	portApplyCalls   int
	portReconCalls   int
	v2ApplyCalls     int
	v2ReconCalls     int
	v2PortApplyCalls int
	v2PortReconCalls int
	v2Grants         []V2MutationGrant
	reconcilePlans   []MutationPlan
	portApplyPlans   []SystemdPortReconfigurePlan
	portReconPlans   []SystemdPortReconfigurePlan
	applyFences      []LocalExecutorMutationFence
	reconcileFences  []LocalExecutorMutationFence
	portFences       []LocalExecutorMutationFence
	stageErr         error
	applyErr         error
	applyResult      *ApplyResult
	reconcileErr     error
	reconcileResult  *ApplyResult
	portApplyErr     error
	portReconResult  *SystemdPortReconfigureResult
}

type hostPullLegacyOnlyMutationExecutor struct {
	inner *hostPullExecutionTestExecutor
}

func (e hostPullLegacyOnlyMutationExecutor) Stage(ctx context.Context, plan MutationPlan, fence LocalExecutorMutationFence) (MutationStageResult, error) {
	return e.inner.Stage(ctx, plan, fence)
}

func (e hostPullLegacyOnlyMutationExecutor) Apply(ctx context.Context, plan MutationPlan, fence LocalExecutorMutationFence, grant BoundedSecret) (ApplyResult, error) {
	return e.inner.Apply(ctx, plan, fence, grant)
}

func (e hostPullLegacyOnlyMutationExecutor) Reconcile(ctx context.Context, plan MutationPlan, fence LocalExecutorMutationFence, grant BoundedSecret) (ApplyResult, error) {
	return e.inner.Reconcile(ctx, plan, fence, grant)
}

func (e *hostPullExecutionTestExecutor) ApplyV2(_ context.Context, plan MutationPlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (ApplyResult, error) {
	e.v2ApplyCalls++
	e.v2Grants = append(e.v2Grants, grant)
	e.applyFences = append(e.applyFences, fence)
	if e.applyErr != nil {
		return ApplyResult{}, e.applyErr
	}
	return ApplyResult{Status: "succeeded", ArtifactDigest: plan.ResultArtifactDigest()}, nil
}

func (e *hostPullExecutionTestExecutor) ReconcileV2(_ context.Context, plan MutationPlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (ApplyResult, error) {
	e.v2ReconCalls++
	e.v2Grants = append(e.v2Grants, grant)
	e.reconcileFences = append(e.reconcileFences, fence)
	if e.reconcileErr != nil {
		return ApplyResult{}, e.reconcileErr
	}
	return ApplyResult{Status: "succeeded", ArtifactDigest: plan.ResultArtifactDigest()}, nil
}

func (e *hostPullExecutionTestExecutor) Stage(_ context.Context, plan MutationPlan, _ LocalExecutorMutationFence) (MutationStageResult, error) {
	e.stageCalls++
	if e.stageErr != nil {
		return MutationStageResult{}, e.stageErr
	}
	return MutationStageResult{Status: "staged", SessionID: plan.SessionID, PlanSHA256: plan.PlanSHA256, ArtifactDigest: plan.ArtifactDigest}, nil
}
func (e *hostPullExecutionTestExecutor) Apply(_ context.Context, plan MutationPlan, fence LocalExecutorMutationFence, _ BoundedSecret) (ApplyResult, error) {
	e.applyCalls++
	e.applyFences = append(e.applyFences, fence)
	if e.applyErr != nil {
		return ApplyResult{}, e.applyErr
	}
	if e.applyResult != nil {
		result := *e.applyResult
		if result.ArtifactDigest == "" {
			result.ArtifactDigest = plan.ResultArtifactDigest()
		}
		return result, nil
	}
	return ApplyResult{Status: "succeeded", ArtifactDigest: plan.ResultArtifactDigest()}, nil
}
func (e *hostPullExecutionTestExecutor) Reconcile(_ context.Context, plan MutationPlan, fence LocalExecutorMutationFence, _ BoundedSecret) (ApplyResult, error) {
	e.reconcileCalls++
	e.reconcilePlans = append(e.reconcilePlans, plan)
	e.reconcileFences = append(e.reconcileFences, fence)
	if e.reconcileErr != nil {
		return ApplyResult{}, e.reconcileErr
	}
	if e.reconcileResult != nil {
		result := *e.reconcileResult
		if result.ArtifactDigest == "" {
			result.ArtifactDigest = plan.ResultArtifactDigest()
		}
		return result, nil
	}
	return ApplyResult{Status: "succeeded", ArtifactDigest: plan.ResultArtifactDigest()}, nil
}

func (e *hostPullExecutionTestExecutor) PortReconfigure(_ context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, _ BoundedSecret) (SystemdPortReconfigureResult, error) {
	e.portApplyCalls++
	e.portApplyPlans = append(e.portApplyPlans, plan)
	e.portFences = append(e.portFences, fence)
	if e.portApplyErr != nil {
		return SystemdPortReconfigureResult{}, e.portApplyErr
	}
	return appliedPortExecutionResult(plan), nil
}

func (e *hostPullExecutionTestExecutor) PortReconfigureReconcile(_ context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, _ BoundedSecret) (SystemdPortReconfigureResult, error) {
	e.portReconCalls++
	e.portReconPlans = append(e.portReconPlans, plan)
	e.portFences = append(e.portFences, fence)
	if e.portReconResult != nil {
		return *e.portReconResult, nil
	}
	return appliedPortExecutionResult(plan), nil
}

func (e *hostPullExecutionTestExecutor) PortReconfigureV2(_ context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (SystemdPortReconfigureResult, error) {
	e.v2PortApplyCalls++
	e.v2Grants = append(e.v2Grants, grant)
	e.portFences = append(e.portFences, fence)
	if e.portApplyErr != nil {
		return SystemdPortReconfigureResult{}, e.portApplyErr
	}
	return appliedPortExecutionResult(plan), nil
}

func (e *hostPullExecutionTestExecutor) PortReconfigureReconcileV2(_ context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (SystemdPortReconfigureResult, error) {
	e.v2PortReconCalls++
	e.v2Grants = append(e.v2Grants, grant)
	e.portFences = append(e.portFences, fence)
	if e.portReconResult != nil {
		return *e.portReconResult, nil
	}
	return appliedPortExecutionResult(plan), nil
}

func appliedPortExecutionResult(plan SystemdPortReconfigurePlan) SystemdPortReconfigureResult {
	return SystemdPortReconfigureResult{
		Status: "succeeded", Result: systemdPortResultApplied, StateKnown: true,
		OldPort: plan.OldPort, NewPort: plan.NewPort, AppliedPort: plan.NewPort,
		EndpointRevision: plan.TargetEndpointRevision,
		ConfigRevision:   plan.TargetConfigRevision,
		ConfigSHA256:     plan.TargetConfigSHA256,
		Message:          "requested systemd port is running and verified",
	}
}

func unchangedPortExecutionResult(plan SystemdPortReconfigurePlan) SystemdPortReconfigureResult {
	return SystemdPortReconfigureResult{
		Status: "succeeded", Result: systemdPortResultUnchanged, StateKnown: true,
		OldPort: plan.OldPort, NewPort: plan.NewPort, AppliedPort: plan.OldPort,
		EndpointRevision: plan.TargetEndpointRevision + 1,
		ConfigRevision:   plan.ExpectedConfigRevision,
		ConfigSHA256:     plan.ExpectedConfigSHA256,
		Message:          "systemd port mutation had not changed the verified previous state",
	}
}

func dockerPortExecutionResultForTest(
	plan SystemdPortReconfigurePlan,
	resultKind string,
) SystemdPortReconfigureResult {
	result := SystemdPortReconfigureResult{
		DeploymentMode: ModeDocker,
		OldPort:        plan.OldPort,
		NewPort:        plan.NewPort,
	}
	var publishedPort, containerPort, healthPort int
	switch resultKind {
	case systemdPortResultApplied:
		result.Status = "succeeded"
		result.Result = systemdPortResultApplied
		result.StateKnown = true
		result.AppliedPort = plan.NewPort
		result.EndpointRevision = plan.TargetEndpointRevision
		result.ConfigRevision = plan.TargetConfigRevision
		result.ConfigSHA256 = plan.TargetConfigSHA256
		result.Message = "requested Docker port mapping is running and verified"
		publishedPort = plan.Docker.NewPublishedPort
		containerPort = plan.Docker.NewContainerPort
		healthPort = plan.Docker.NewHealthPort
	case systemdPortResultRolledBack:
		result.Status = "rolled_back"
		result.Result = systemdPortResultRolledBack
		result.StateKnown = true
		result.AppliedPort = plan.OldPort
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "previous Docker port mapping was restored and verified"
		publishedPort = plan.Docker.OldPublishedPort
		containerPort = plan.Docker.OldContainerPort
		healthPort = plan.Docker.OldHealthPort
	case systemdPortResultUnchanged:
		result.Status = "succeeded"
		result.Result = systemdPortResultUnchanged
		result.StateKnown = true
		result.AppliedPort = plan.OldPort
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "Docker port mutation did not change the verified mapping"
		publishedPort = plan.Docker.OldPublishedPort
		containerPort = plan.Docker.OldContainerPort
		healthPort = plan.Docker.OldHealthPort
	default:
		panic("unsupported Docker port result kind")
	}
	result.Docker = &DockerPortReconfigureResultState{
		AppliedPublishedPort: publishedPort,
		AppliedContainerPort: containerPort,
		AppliedHealthPort:    healthPort,
		ComposeConfigSHA256:  strings.Repeat("c", 64),
	}
	return result
}
