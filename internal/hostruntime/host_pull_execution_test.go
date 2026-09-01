package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hostPullExecutionTestPanel struct {
	job          *UpdateJob
	claimHostIDs []string
	reports      []JobReport
	reportErrors []error
	grants       []MutationGrantRequest
	grantErrors  []error
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
func (p *hostPullExecutionTestPanel) ClaimHost(_ context.Context, _, hostID, _ string) (*UpdateJob, bool, error) {
	p.claimHostIDs = append(p.claimHostIDs, hostID)
	if p.job == nil {
		return nil, false, nil
	}
	copy := *p.job
	return &copy, false, nil
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
	stageCalls      int
	applyCalls      int
	reconcileCalls  int
	portApplyCalls  int
	portReconCalls  int
	reconcilePlans  []MutationPlan
	portApplyPlans  []SystemdPortReconfigurePlan
	portReconPlans  []SystemdPortReconfigurePlan
	applyFences     []LocalExecutorMutationFence
	reconcileFences []LocalExecutorMutationFence
	portFences      []LocalExecutorMutationFence
	stageErr        error
	applyErr        error
	applyResult     *ApplyResult
	reconcileErr    error
	reconcileResult *ApplyResult
	portApplyErr    error
	portReconResult *SystemdPortReconfigureResult
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

func TestValidatePortExecutionResultBindsDockerMappingToImmutablePlan(t *testing.T) {
	plan := newDockerPortHarness(t).plan
	t.Run("deployment_mode_spoof", func(t *testing.T) {
		result := appliedPortExecutionResult(plan)
		if err := result.Validate(); err != nil {
			t.Fatalf("systemd-mode spoof fixture must remain structurally valid: %v", err)
		}
		if err := validatePortExecutionResult(plan, result); err == nil {
			t.Fatal("systemd-mode response for an immutable Docker plan was accepted")
		}
	})
	for _, resultKind := range []string{
		systemdPortResultApplied,
		systemdPortResultRolledBack,
		systemdPortResultUnchanged,
	} {
		t.Run(resultKind+"_exact", func(t *testing.T) {
			result := dockerPortExecutionResultForTest(plan, resultKind)
			if err := validatePortExecutionResult(plan, result); err != nil {
				t.Fatalf("exact Docker result rejected: %v", err)
			}
		})
		t.Run(resultKind+"_container_spoof", func(t *testing.T) {
			result := dockerPortExecutionResultForTest(plan, resultKind)
			result.Docker.AppliedContainerPort++
			if err := result.Validate(); err != nil {
				t.Fatalf("spoof fixture must remain structurally valid: %v", err)
			}
			if err := validatePortExecutionResult(plan, result); err == nil {
				t.Fatal("structurally valid Docker container-port spoof was accepted")
			}
		})
		t.Run(resultKind+"_published_spoof", func(t *testing.T) {
			result := dockerPortExecutionResultForTest(plan, resultKind)
			result.Docker.AppliedPublishedPort++
			result.Docker.AppliedHealthPort++
			if err := result.Validate(); err != nil {
				t.Fatalf("spoof fixture must remain structurally valid: %v", err)
			}
			if err := validatePortExecutionResult(plan, result); err == nil {
				t.Fatal("structurally valid Docker published-port spoof was accepted")
			}
		})
	}
}

func TestHostPullExecutorReadinessAllowsOnlyLegacySystemdObserverBackfill(t *testing.T) {
	agent, _, _, binding, policy := newHostPullExecutionHarness(t, false)
	reportedDigest := "sha256:" + strings.Repeat("c", 64)
	observation := HostTargetObservation{
		ServiceID:      policy.Targets[0].ServiceID,
		Availability:   TargetAvailabilityAvailable,
		PolicyRevision: policy.LocalExecutorPolicyRevision,
		PolicySHA256:   policy.LocalExecutorPolicySHA256,
		ConfigRevision: policy.Targets[0].appliedConfigRevision(),
		ConfigSHA256:   reportedDigest,
	}

	assertCapabilities := func(
		t *testing.T,
		binding HostAgentBinding,
		policy HostAgentPolicy,
		observation HostTargetObservation,
		wantExecutor, wantMutation bool,
	) {
		t.Helper()
		capabilities := agent.capabilities(
			binding, &policy, []HostTargetObservation{observation}, false,
		)
		if capabilities["update_executor"] != wantExecutor ||
			capabilities["mutation_enabled"] != wantMutation ||
			capabilities["observe_only"] != !wantMutation {
			t.Fatalf(
				"capabilities=%+v, want update_executor=%t mutation_enabled=%t observe_only=%t",
				capabilities, wantExecutor, wantMutation, !wantMutation,
			)
		}
	}

	observerBinding := binding
	observerBinding.OwnershipEpoch = 0
	observerPolicy := policy
	observerPolicy.OwnershipEpoch = 0
	observerPolicy.ObserveOnly = true
	observerPolicy.Targets = append(
		[]HostAgentPolicyTarget(nil), policy.Targets...,
	)
	observerPolicy.Targets[0].AppliedConfigSHA256 = ""
	assertCapabilities(
		t, observerBinding, observerPolicy, observation, true, false,
	)

	for name, mutate := range map[string]func(
		*HostAgentBinding, *HostAgentPolicy, *HostTargetObservation,
	){
		"empty reported digest": func(_ *HostAgentBinding, _ *HostAgentPolicy, observation *HostTargetObservation) {
			observation.ConfigSHA256 = ""
		},
		"invalid reported digest": func(_ *HostAgentBinding, _ *HostAgentPolicy, observation *HostTargetObservation) {
			observation.ConfigSHA256 = "sha256:not-a-digest"
		},
		"explicit applied digest mismatch": func(_ *HostAgentBinding, policy *HostAgentPolicy, _ *HostTargetObservation) {
			policy.Targets[0].AppliedConfigSHA256 = "sha256:" + strings.Repeat("d", 64)
		},
		"docker target without applied digest": func(_ *HostAgentBinding, policy *HostAgentPolicy, _ *HostTargetObservation) {
			policy.Targets[0].DeploymentMode = ModeDocker
		},
		"active owner without applied digest": func(binding *HostAgentBinding, policy *HostAgentPolicy, _ *HostTargetObservation) {
			binding.OwnershipEpoch = 1
			policy.OwnershipEpoch = 1
			policy.ObserveOnly = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateBinding := observerBinding
			candidatePolicy := observerPolicy
			candidatePolicy.Targets = append(
				[]HostAgentPolicyTarget(nil), observerPolicy.Targets...,
			)
			candidateObservation := observation
			mutate(
				&candidateBinding, &candidatePolicy, &candidateObservation,
			)
			assertCapabilities(
				t, candidateBinding, candidatePolicy, candidateObservation, false, false,
			)
		})
	}
}

func TestHostPullExecutionClaimsServerOwnedHostAndCompletesThroughLocalExecutor(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if len(panel.claimHostIDs) != 1 || panel.claimHostIDs[0] != "" {
		t.Fatalf("claim host ids=%v", panel.claimHostIDs)
	}
	if executor.stageCalls != 1 || executor.applyCalls != 1 || executor.reconcileCalls != 0 {
		t.Fatalf("executor calls stage=%d apply=%d reconcile=%d", executor.stageCalls, executor.applyCalls, executor.reconcileCalls)
	}
	if len(executor.applyFences) != 1 || executor.applyFences[0].SourcePolicyRevision != policy.SourcePolicyRevision {
		t.Fatalf("apply fences=%+v policy source revision=%d", executor.applyFences, policy.SourcePolicyRevision)
	}
	if len(panel.grants) != 1 {
		t.Fatalf("grants=%d", len(panel.grants))
	}
	grant := panel.grants[0]
	if grant.TransportMode != HostTransportPullV2 ||
		grant.OwnershipEpoch != binding.OwnershipEpoch ||
		grant.PolicyRevision != policy.Revision ||
		grant.HostID != binding.ExecutionHostID ||
		grant.ServiceType != panel.job.EffectiveType() ||
		grant.Operation != "apply" {
		t.Fatalf("grant=%+v", grant)
	}
	if len(panel.reports) == 0 || panel.reports[len(panel.reports)-1].Status != "succeeded" {
		t.Fatalf("reports=%+v", panel.reports)
	}
	foundHealthChecking := false
	for _, report := range panel.reports {
		if report.Status == "health_checking" && report.Progress == 90 {
			foundHealthChecking = true
		}
		if report.Status == "reconciling" {
			t.Fatalf("certain apply unexpectedly reconciled: %+v", panel.reports)
		}
	}
	if !foundHealthChecking {
		t.Fatalf("certain apply skipped health_checking/90: %+v", panel.reports)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("terminal report left active job: %+v", active)
	}
	payload, err := os.ReadFile(filepath.Join(agent.StateDir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "ast_mutation_") ||
		strings.Contains(string(payload), strings.Repeat("l", 48)) {
		t.Fatalf("journal persisted a bearer secret: %s", payload)
	}
}

func TestHostPullExecutionPostUpdateRollbackReportsRollingBackBeforeTerminal(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	executor.applyResult = &ApplyResult{
		Status:     "rolled_back",
		RolledBack: true,
		Message:    "expected worker version was not healthy",
	}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}

	wantStatuses := []string{
		"claimed", "downloading", "verifying", "staging", "installing",
		"health_checking", "rolling_back", "rolled_back",
	}
	if len(panel.reports) != len(wantStatuses) {
		t.Fatalf("reports=%+v, want statuses=%v", panel.reports, wantStatuses)
	}
	for i, want := range wantStatuses {
		if got := panel.reports[i].Status; got != want {
			t.Fatalf("report[%d]=%+v, want status=%q", i, panel.reports[i], want)
		}
	}
	rollingBack := panel.reports[len(panel.reports)-2]
	if rollingBack.Progress != 95 || rollingBack.Code != "" {
		t.Fatalf("rolling_back report=%+v", rollingBack)
	}
	terminal := panel.reports[len(panel.reports)-1]
	if terminal.Progress != 100 || terminal.Code != "post_update_verification_failed" {
		t.Fatalf("terminal report=%+v", terminal)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("rolled-back job left active: %+v", active)
	}
}

func TestHostPullExecutionExplicitStageFailurePreservesPlanForRecovery(t *testing.T) {
	for _, code := range []string{"stage_failed", "state_unavailable"} {
		t.Run(code, func(t *testing.T) {
			agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
			executor.stageErr = &LocalExecutorClientError{Code: code}

			if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
				t.Fatal("explicit stage failure unexpectedly became terminal")
			}
			if executor.stageCalls != 1 || executor.applyCalls != 0 || executor.reconcileCalls != 0 {
				t.Fatalf(
					"executor calls stage=%d apply=%d reconcile=%d",
					executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
				)
			}
			if len(panel.grants) != 0 {
				t.Fatalf("stage failure issued grants before recovery: %+v", panel.grants)
			}
			if len(panel.reports) == 0 {
				t.Fatal("stage failure emitted no reports")
			}
			last := panel.reports[len(panel.reports)-1]
			if last.Status != "staging" || last.Progress != 55 {
				t.Fatalf("last report=%+v", last)
			}
			for _, report := range panel.reports {
				if isTerminalUpdateStatus(report.Status) {
					t.Fatalf("stage failure emitted terminal report before reconcile: %+v", report)
				}
			}
			if active := agent.Journal.Active(); active == nil || active.ID != panel.job.ID {
				t.Fatalf("stage failure active job=%+v", active)
			}
			if plan := agent.Journal.ActivePlan(); plan == nil || plan.JobID != panel.job.ID {
				t.Fatalf("stage failure active plan=%+v", plan)
			}
		})
	}
}

func TestHostPullExecutionRecordsPreciseStageFailureForRecovery(t *testing.T) {
	for _, test := range []struct {
		name    string
		message string
		code    string
	}{
		{
			name:    "smoke execution",
			message: stageFailureMessageSmokeExecution,
			code:    stageFailureCodeSmokeExecution,
		},
		{
			name:    "version mismatch",
			message: stageFailureMessageVersionMismatch,
			code:    stageFailureCodeVersionMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
			executor.stageErr = &LocalExecutorClientError{Code: "stage_failed", Message: test.message}

			if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
				t.Fatal("stage failure unexpectedly completed")
			}
			failure := agent.Journal.ActiveStageFailure()
			if failure == nil || failure.JobID != panel.job.ID || failure.Code != test.code || failure.Message != test.message {
				t.Fatalf("recorded failure=%+v", failure)
			}
			if active := agent.Journal.Active(); active == nil || active.ID != panel.job.ID {
				t.Fatalf("active job=%+v", active)
			}
		})
	}
}

func TestHostPullJournalRejectsTamperedDurablePlan(t *testing.T) {
	agent, panel, _, _, policy := newHostPullExecutionHarness(t, false)
	job := *panel.job
	if err := agent.Journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(agent.StateDir, "journal.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var data journalData
	if err := json.Unmarshal(payload, &data); err != nil {
		t.Fatal(err)
	}
	data.ActivePlan.TargetID = "different-target"
	tampered, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(agent.StateDir); err == nil ||
		!strings.Contains(err.Error(), "active plan binding") {
		t.Fatalf("tampered journal error=%v", err)
	}
}

func TestHostPullExecutionUncertainApplyReconcilesWithoutReapplying(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	executor.applyErr = errors.New("UDS result lost")
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.applyCalls != 1 || executor.reconcileCalls != 1 {
		t.Fatalf("apply=%d reconcile=%d", executor.applyCalls, executor.reconcileCalls)
	}
	if len(executor.reconcileFences) != 1 || executor.reconcileFences[0].SourcePolicyRevision != policy.SourcePolicyRevision {
		t.Fatalf("reconcile fences=%+v policy source revision=%d", executor.reconcileFences, policy.SourcePolicyRevision)
	}
	if len(panel.grants) != 2 ||
		panel.grants[0].Operation != "apply" ||
		panel.grants[1].Operation != "reconcile" {
		t.Fatalf("grants=%+v", panel.grants)
	}
	reconcilingIndex := -1
	previousProgress := -1
	for index, report := range panel.reports {
		if report.Progress < previousProgress {
			t.Errorf(
				"report progress decreased at index %d: previous=%d report=%+v",
				index, previousProgress, report,
			)
		}
		previousProgress = report.Progress
		if report.Status == "health_checking" {
			t.Errorf("uncertain apply emitted post-reconcile health_checking report: %+v", report)
		}
		if report.Status == "reconciling" {
			reconcilingIndex = index
		}
	}
	if reconcilingIndex < 0 {
		t.Fatalf("reports=%+v", panel.reports)
	}
	if reconcilingIndex+1 >= len(panel.reports) {
		t.Fatalf("reconciling report was not followed by a terminal report: %+v", panel.reports)
	}
	reconciling := panel.reports[reconcilingIndex]
	terminal := panel.reports[reconcilingIndex+1]
	if reconciling.Progress != 99 || terminal.Status != "succeeded" || terminal.Progress != 100 {
		t.Fatalf("reconciling=%+v terminal=%+v", reconciling, terminal)
	}
}

func TestHostPullExecutionUncertainStagePreservesPlanAndRecoversWithoutRestaging(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	executor.stageErr = errors.New("read local executor mutation response")

	if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
		t.Fatal("uncertain stage result unexpectedly became terminal")
	}
	if executor.stageCalls != 1 || executor.applyCalls != 0 || executor.reconcileCalls != 0 {
		t.Fatalf(
			"first executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if len(panel.grants) != 0 {
		t.Fatalf("uncertain stage issued grants before recovery: %+v", panel.grants)
	}
	if len(panel.reports) == 0 {
		t.Fatal("uncertain stage emitted no reports")
	}
	lastInitial := panel.reports[len(panel.reports)-1]
	if lastInitial.Status != "staging" || lastInitial.Progress != 55 {
		t.Fatalf("last initial report=%+v", lastInitial)
	}
	for _, report := range panel.reports {
		if isTerminalUpdateStatus(report.Status) {
			t.Fatalf("uncertain stage emitted terminal report: %+v", report)
		}
	}
	if active := agent.Journal.Active(); active == nil || active.ID != panel.job.ID {
		t.Fatalf("uncertain stage active job=%+v", active)
	}
	if plan := agent.Journal.ActivePlan(); plan == nil || plan.JobID != panel.job.ID {
		t.Fatalf("uncertain stage active plan=%+v", plan)
	}
	executor.stageErr = nil
	panel.job.RecoveryRequired = true
	panel.job.LeaseGeneration++
	panel.job.Status = "staging"
	panel.job.Progress = 55
	panel.job.Sequence = uint64(len(panel.reports))
	panel.job.ReportSequence = panel.job.Sequence + 1
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("recovery executeOnce: %v", err)
	}
	if executor.stageCalls != 1 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf(
			"recovered executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if len(panel.grants) != 1 || panel.grants[0].Operation != "reconcile" {
		t.Fatalf("recovery grants=%+v", panel.grants)
	}
	if len(panel.reports) < 2 {
		t.Fatalf("recovery reports=%+v", panel.reports)
	}
	reconciling := panel.reports[len(panel.reports)-2]
	terminal := panel.reports[len(panel.reports)-1]
	if reconciling.Status != "reconciling" ||
		reconciling.Progress != 99 ||
		terminal.Status != "succeeded" ||
		terminal.Progress != 100 {
		t.Fatalf("reconciling=%+v terminal=%+v", reconciling, terminal)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("recovered uncertain stage left active job: %+v", active)
	}
}

func TestHostPullPermanentStaleReportPreservesPlanForFreshRecovery(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		status    string
		code      string
		message   string
		progress  int
		errorCode string
	}{
		{
			name: "reconciling", status: "reconciling",
			message:  "inspecting interrupted host update state without reapplying",
			progress: 99, errorCode: "system_update_lease_invalid",
		},
		{
			name: "terminal", status: "failed", code: "remote_stage_missing",
			message:  "interrupted job has no durable mutation state to reconcile",
			progress: 100, errorCode: "system_update_sequence_stale",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
			interrupted := *panel.job
			interrupted.RecoveryRequired = false
			if err := agent.Journal.SetActive(&interrupted); err != nil {
				t.Fatal(err)
			}
			plan, err := agent.prepareExecutionPlan(context.Background(), policy, interrupted)
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.Journal.SetActivePlan(plan); err != nil {
				t.Fatal(err)
			}
			if _, err := agent.Journal.Queue(
				interrupted.ID, agent.Bootstrap.NodeID, interrupted.LeaseToken,
				interrupted.LeaseGeneration, testCase.status, testCase.code,
				testCase.message, testCase.progress, "", "",
			); err != nil {
				t.Fatal(err)
			}
			panel.reportErrors = []error{&PanelHTTPError{
				Status: 409,
				Code:   testCase.errorCode,
			}}

			if err := agent.flushExecutionReports(context.Background(), panel); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("stale report error=%v", err)
			}
			if pending := agent.Journal.Pending(); len(pending) != 0 {
				t.Fatalf("stale reports were not dropped: %+v", pending)
			}
			if active := agent.Journal.Active(); active == nil || active.ID != interrupted.ID {
				t.Fatalf("stale report cleared active job: %+v", active)
			}
			if activePlan := agent.Journal.ActivePlan(); activePlan == nil ||
				activePlan.JobID != interrupted.ID || activePlan.PlanSHA256 != plan.PlanSHA256 {
				t.Fatalf("stale report cleared or changed active plan: %+v", activePlan)
			}

			panel.job.RecoveryRequired = true
			panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
			panel.job.LeaseToken = strings.Repeat("r", 48)
			panel.job.Status = testCase.status
			panel.job.Progress = testCase.progress
			panel.job.Sequence = 7
			panel.job.ReportSequence = 8
			agent.Downloader = hostPullFailingDownloader{}

			if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
				t.Fatalf("fresh recovery executeOnce: %v", err)
			}
			if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
				t.Fatalf(
					"fresh recovery calls stage=%d apply=%d reconcile=%d",
					executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
				)
			}
			if len(panel.reports) != 2 ||
				panel.reports[0].Status != "reconciling" || panel.reports[0].Progress != 99 ||
				panel.reports[1].Status != "succeeded" || panel.reports[1].Progress != 100 {
				t.Fatalf("fresh recovery reports=%+v", panel.reports)
			}
			if active := agent.Journal.Active(); active != nil {
				t.Fatalf("fresh recovery left active job: %+v", active)
			}
			if activePlan := agent.Journal.ActivePlan(); activePlan != nil {
				t.Fatalf("fresh recovery left active plan: %+v", activePlan)
			}
			if pending := agent.Journal.Pending(); len(pending) != 0 {
				t.Fatalf("fresh recovery left pending reports: %+v", pending)
			}
		})
	}
}

func TestHostPullClaimRejectsMalformedLeaseCredential(t *testing.T) {
	_, panel, _, binding, policy := newHostPullExecutionHarness(t, false)
	for name, token := range map[string]string{
		"control":  "valid-prefix\nsecret",
		"oversize": strings.Repeat("x", (16<<10)+1),
	} {
		t.Run(name, func(t *testing.T) {
			job := *panel.job
			job.LeaseToken = token
			if err := validateHostPullClaim(job, panel.job.AgentServiceID, binding, policy); err == nil {
				t.Fatal("malformed lease credential was accepted")
			}
		})
	}
}

func TestHostPullRecoveryOnlyReconcilesDurableExecutorState(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
	agent.Downloader = hostPullFailingDownloader{}
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf("executor calls stage=%d apply=%d reconcile=%d", executor.stageCalls, executor.applyCalls, executor.reconcileCalls)
	}
	if len(executor.reconcileFences) != 1 || executor.reconcileFences[0].SourcePolicyRevision != policy.SourcePolicyRevision {
		t.Fatalf("recovery reconcile fences=%+v policy source revision=%d", executor.reconcileFences, policy.SourcePolicyRevision)
	}
	if len(panel.grants) != 1 || panel.grants[0].Operation != "reconcile" {
		t.Fatalf("grants=%+v", panel.grants)
	}
	if len(executor.reconcilePlans) != 1 ||
		executor.reconcilePlans[0].LeaseGeneration != panel.job.LeaseGeneration ||
		panel.grants[0].LeaseGeneration != panel.job.LeaseGeneration {
		t.Fatalf("plan=%+v grant=%+v", executor.reconcilePlans, panel.grants)
	}
}

func TestHostPullRecoveryWithoutExecutorStageTerminates(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
	agent.Downloader = hostPullFailingDownloader{}
	executor.reconcileErr = &LocalExecutorClientError{Code: "stage_required"}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Errorf("executeOnce: %v", err)
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf(
			"executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if len(panel.grants) != 1 || panel.grants[0].Operation != "reconcile" {
		t.Fatalf("grants=%+v", panel.grants)
	}
	if len(executor.reconcilePlans) != 1 ||
		executor.reconcilePlans[0].LeaseGeneration != panel.job.LeaseGeneration ||
		panel.grants[0].LeaseGeneration != panel.job.LeaseGeneration {
		t.Fatalf("plan=%+v grant=%+v", executor.reconcilePlans, panel.grants)
	}
	if len(panel.reports) != 2 {
		t.Fatalf("reports=%+v", panel.reports)
	}
	reconciling := panel.reports[0]
	terminal := panel.reports[1]
	if reconciling.Status != "reconciling" ||
		reconciling.Progress != 99 ||
		reconciling.Message != "inspecting interrupted host update state without reapplying" {
		t.Fatalf("reconciling report=%+v", reconciling)
	}
	if terminal.Status != "failed" ||
		terminal.Progress != 100 ||
		terminal.Code != "remote_stage_missing" ||
		terminal.Message != "interrupted job has no durable mutation state to reconcile" {
		t.Fatalf("terminal report=%+v", terminal)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("stage-required recovery left active job: %+v", active)
	}
	if plan := agent.Journal.ActivePlan(); plan != nil {
		t.Fatalf("stage-required recovery left active plan: %+v", plan)
	}
	if pending := agent.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("stage-required recovery left pending reports: %+v", pending)
	}
}

func TestHostPullRecoveryReportsRecordedStageFailureCategory(t *testing.T) {
	for _, test := range []struct {
		name       string
		failure    stageFailureRecord
		reportCode string
	}{
		{
			name: "smoke execution",
			failure: stageFailureRecord{
				Code:    stageFailureCodeSmokeExecution,
				Message: stageFailureMessageSmokeExecution,
			},
			reportCode: stageFailureReportCodeSmokeExecution,
		},
		{
			name: "version mismatch",
			failure: stageFailureRecord{
				Code:    stageFailureCodeVersionMismatch,
				Message: stageFailureMessageVersionMismatch,
			},
			reportCode: stageFailureReportCodeVersionMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
			interrupted := *panel.job
			interrupted.RecoveryRequired = false
			if err := agent.Journal.SetActive(&interrupted); err != nil {
				t.Fatal(err)
			}
			plan, err := agent.prepareExecutionPlan(context.Background(), policy, interrupted)
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.Journal.SetActivePlan(plan); err != nil {
				t.Fatal(err)
			}
			test.failure.JobID = interrupted.ID
			if err := agent.Journal.SetActiveStageFailure(test.failure); err != nil {
				t.Fatal(err)
			}
			panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
			agent.Downloader = hostPullFailingDownloader{}
			executor.reconcileErr = &LocalExecutorClientError{Code: "stage_required"}

			if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
				t.Fatalf("executeOnce: %v", err)
			}
			if len(panel.reports) != 2 {
				t.Fatalf("reports=%+v", panel.reports)
			}
			terminal := panel.reports[1]
			if terminal.Status != "failed" || terminal.Progress != 100 || terminal.Code != test.reportCode || terminal.Message != test.failure.Message {
				t.Fatalf("terminal report=%+v", terminal)
			}
			if active := agent.Journal.Active(); active != nil {
				t.Fatalf("active job survived precise stage failure terminalization: %+v", active)
			}
			if failure := agent.Journal.ActiveStageFailure(); failure != nil {
				t.Fatalf("stage failure survived precise terminalization: %+v", failure)
			}
		})
	}
}

func TestHostPullRecoveryReconcileResponseLossPreservesPlan(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
	agent.Downloader = hostPullFailingDownloader{}
	executor.reconcileErr = errors.New("read local executor mutation response")

	if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
		t.Fatal("lost reconcile response unexpectedly became terminal")
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf(
			"executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if len(panel.reports) != 1 || panel.reports[0].Status != "reconciling" || panel.reports[0].Progress != 99 {
		t.Fatalf("reports=%+v", panel.reports)
	}
	if active := agent.Journal.Active(); active == nil || active.ID != panel.job.ID {
		t.Fatalf("lost reconcile response active job=%+v", active)
	}
	if activePlan := agent.Journal.ActivePlan(); activePlan == nil || activePlan.JobID != panel.job.ID {
		t.Fatalf("lost reconcile response active plan=%+v", activePlan)
	}
}

func TestHostPullRecoveryRolledBackTerminatesAtOneHundred(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
	agent.Downloader = hostPullFailingDownloader{}
	executor.reconcileResult = &ApplyResult{Status: "rolled_back", RolledBack: true}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if len(panel.reports) != 2 {
		t.Fatalf("reports=%+v", panel.reports)
	}
	reconciling := panel.reports[0]
	terminal := panel.reports[1]
	if reconciling.Status != "reconciling" ||
		reconciling.Progress != 99 ||
		terminal.Status != "rolled_back" ||
		terminal.Progress != 100 ||
		terminal.Code != "post_update_verification_failed" {
		t.Fatalf("reconciling=%+v terminal=%+v", reconciling, terminal)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("rolled-back recovery left active job: %+v", active)
	}
}

func TestHostPullPortReconfigureSkipsReleaseAndStagesNoSoftware(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	agent.Downloader = hostPullFailingDownloader{}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 0 {
		t.Fatalf("software executor calls stage=%d apply=%d reconcile=%d", executor.stageCalls, executor.applyCalls, executor.reconcileCalls)
	}
	if executor.portApplyCalls != 1 || executor.portReconCalls != 0 {
		t.Fatalf("port executor calls apply=%d reconcile=%d", executor.portApplyCalls, executor.portReconCalls)
	}
	if len(panel.grants) != 1 {
		t.Fatalf("grants=%+v", panel.grants)
	}
	grant := panel.grants[0]
	intentHash := panel.job.PortReconfigure.PortPlanSHA256
	if grant.JobOperation != updateJobOperationPortReconfigure ||
		grant.Operation != "port_reconfigure" ||
		grant.ServiceType != panel.job.EffectiveType() ||
		grant.PortReconfigure == nil ||
		grant.PlanSHA256 == intentHash ||
		grant.PortReconfigure.PortPlanSHA256 != grant.PlanSHA256 ||
		grant.PlanSHA256 != executor.portApplyPlans[0].PortPlanSHA256 {
		t.Fatalf("grant=%+v intent_hash=%q plan=%+v", grant, intentHash, executor.portApplyPlans)
	}
	if len(executor.portFences) != 1 ||
		executor.portFences[0].SourcePolicyRevision != policy.SourcePolicyRevision ||
		executor.portFences[0].OwnershipPolicyRevision != policy.Revision ||
		executor.portFences[0].ExecutorPolicyRevision != policy.LocalExecutorPolicyRevision {
		t.Fatalf("port fences=%+v", executor.portFences)
	}
	for index, report := range panel.reports {
		terminal := index == len(panel.reports)-1
		if terminal {
			if report.Status != "succeeded" ||
				report.PortReconfigure == nil ||
				report.PortReconfigure.Result != systemdPortResultApplied {
				t.Fatalf("terminal report=%+v", report)
			}
		} else if report.PortReconfigure != nil {
			t.Fatalf("non-terminal report leaked a result: %+v", report)
		}
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("terminal port report left active job: %+v", active)
	}
	payload, err := os.ReadFile(filepath.Join(agent.StateDir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "ast_mutation_") ||
		strings.Contains(string(payload), strings.Repeat("l", 48)) {
		t.Fatalf("journal persisted a bearer secret: %s", payload)
	}
}

func TestHostPullPortReconfigureUncertainResultReconcilesWithoutReapply(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	executor.portApplyErr = errors.New("UDS result lost")

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.portApplyCalls != 1 || executor.portReconCalls != 1 {
		t.Fatalf("port calls apply=%d reconcile=%d", executor.portApplyCalls, executor.portReconCalls)
	}
	if len(panel.grants) != 2 ||
		panel.grants[0].Operation != "port_reconfigure" ||
		panel.grants[1].Operation != "port_reconfigure_reconcile" {
		t.Fatalf("grants=%+v", panel.grants)
	}
	if panel.grants[0].PlanSHA256 != panel.grants[1].PlanSHA256 ||
		panel.grants[0].SessionID != panel.grants[1].SessionID {
		t.Fatalf("apply and reconcile grants changed runtime intent: %+v", panel.grants)
	}
	foundReconciling := false
	for _, report := range panel.reports {
		if report.Status == "reconciling" {
			foundReconciling = true
		}
	}
	if !foundReconciling {
		t.Fatalf("reports=%+v", panel.reports)
	}
}

func TestHostPullPortGrantResponseFailureReconcilesUnstartedMutationAsUnchanged(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	panel.grantErrors = []error{errors.New("grant response lost")}
	plan, err := agent.preparePortExecutionPlan(policy, *panel.job)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := unchangedPortExecutionResult(plan)
	executor.portReconResult = &unchanged

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.portApplyCalls != 0 || executor.portReconCalls != 1 {
		t.Fatalf(
			"grant failure reached apply or skipped reconcile: apply=%d reconcile=%d",
			executor.portApplyCalls,
			executor.portReconCalls,
		)
	}
	if len(panel.grants) != 2 ||
		panel.grants[0].Operation != "port_reconfigure" ||
		panel.grants[1].Operation != "port_reconfigure_reconcile" ||
		panel.grants[0].PlanSHA256 != panel.grants[1].PlanSHA256 ||
		panel.grants[0].SessionID != panel.grants[1].SessionID {
		t.Fatalf("grants=%+v", panel.grants)
	}
	terminal := panel.reports[len(panel.reports)-1]
	if terminal.Status != "succeeded" ||
		terminal.PortReconfigure == nil ||
		terminal.PortReconfigure.Result != systemdPortResultUnchanged {
		t.Fatalf("terminal report=%+v", terminal)
	}
}

func TestHostPullPortRecoveryRebindsLeaseAndPreservesSessionAndIntent(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	original, err := agent.preparePortExecutionPlan(policy, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePortPlan(original); err != nil {
		t.Fatal(err)
	}
	panel.job.LeaseGeneration++
	agent.Downloader = hostPullFailingDownloader{}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.portApplyCalls != 0 || executor.portReconCalls != 1 {
		t.Fatalf("port calls apply=%d reconcile=%d", executor.portApplyCalls, executor.portReconCalls)
	}
	rebound := executor.portReconPlans[0]
	if rebound.LeaseGeneration != panel.job.LeaseGeneration ||
		rebound.SessionID != original.SessionID ||
		rebound.PortPlanSHA256 == original.PortPlanSHA256 ||
		panel.job.PortReconfigure.PortPlanSHA256 != interrupted.PortReconfigure.PortPlanSHA256 {
		t.Fatalf("original=%+v rebound=%+v recovered_job=%+v", original, rebound, panel.job)
	}
	if len(panel.grants) != 1 ||
		panel.grants[0].Operation != "port_reconfigure_reconcile" ||
		panel.grants[0].PlanSHA256 != rebound.PortPlanSHA256 {
		t.Fatalf("grants=%+v", panel.grants)
	}
}

func TestHostPullPortRecoveryReconstructsMissingPreMutationPlanAndReconciles(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	reconstructed, err := agent.preparePortExecutionPlan(policy, *panel.job)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := unchangedPortExecutionResult(reconstructed)
	executor.portReconResult = &unchanged

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.portApplyCalls != 0 || executor.portReconCalls != 1 ||
		len(panel.grants) != 1 ||
		panel.grants[0].Operation != "port_reconfigure_reconcile" {
		t.Fatalf(
			"recovery calls apply=%d reconcile=%d grants=%+v",
			executor.portApplyCalls,
			executor.portReconCalls,
			panel.grants,
		)
	}
	terminal := panel.reports[len(panel.reports)-1]
	if terminal.Status != "succeeded" ||
		terminal.PortReconfigure == nil ||
		terminal.PortReconfigure.Result != systemdPortResultUnchanged {
		t.Fatalf("terminal=%+v", terminal)
	}
}

func TestHostPullPortPlanGenerationFailureNeverSendsInvalidTerminalResult(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	agent.NewSessionID = func() (string, error) {
		return "", errors.New("entropy unavailable")
	}
	if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
		t.Fatal("plan generation failure was hidden")
	}
	for _, report := range panel.reports {
		if isTerminalUpdateStatus(report.Status) {
			t.Fatalf("unverified terminal report was emitted: %+v", report)
		}
	}
	if agent.Journal.Active() == nil || agent.Journal.ActivePortPlan() != nil ||
		executor.portApplyCalls != 0 || executor.portReconCalls != 0 {
		t.Fatalf(
			"failed plan state active=%+v plan=%+v apply=%d reconcile=%d",
			agent.Journal.Active(),
			agent.Journal.ActivePortPlan(),
			executor.portApplyCalls,
			executor.portReconCalls,
		)
	}

	agent.NewSessionID = func() (string, error) {
		return "recovered-session-0123456789", nil
	}
	panel.job.RecoveryRequired = true
	panel.job.LeaseGeneration++
	reconstructed, err := agent.preparePortExecutionPlan(policy, *panel.job)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := unchangedPortExecutionResult(reconstructed)
	executor.portReconResult = &unchanged
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("recovery executeOnce: %v", err)
	}
	terminal := panel.reports[len(panel.reports)-1]
	if terminal.PortReconfigure == nil ||
		terminal.PortReconfigure.Result != systemdPortResultUnchanged {
		t.Fatalf("recovery terminal=%+v", terminal)
	}
}

func TestHostPullPortClaimRejectsUnionAndPolicyDrift(t *testing.T) {
	_, panel, _, binding, policy := newHostPullPortExecutionHarness(t, false)
	for name, mutate := range map[string]func(*UpdateJob){
		"software with port plan": func(job *UpdateJob) {
			job.Operation = updateJobOperationSoftwareUpdate
		},
		"port without nested plan": func(job *UpdateJob) {
			job.PortReconfigure = nil
		},
		"intent hash missing": func(job *UpdateJob) {
			job.PortReconfigure.PortPlanSHA256 = ""
		},
		"source policy stale": func(job *UpdateJob) {
			job.PortReconfigure.ExpectedSourcePolicyRevision--
		},
		"executor digest stale": func(job *UpdateJob) {
			job.PortReconfigure.ExpectedExecutorPolicySHA256 = "sha256:" + strings.Repeat("f", 64)
		},
		"old port mismatch": func(job *UpdateJob) {
			job.PortReconfigure.OldPort++
		},
		"new port mismatch": func(job *UpdateJob) {
			job.PortReconfigure.NewPort++
		},
		"software version mixed in": func(job *UpdateJob) {
			job.TargetVersion = "v1.1.0"
		},
	} {
		t.Run(name, func(t *testing.T) {
			job := *panel.job
			nested := *panel.job.PortReconfigure
			job.PortReconfigure = &nested
			mutate(&job)
			if err := validateHostPullClaim(job, panel.job.AgentServiceID, binding, policy); err == nil {
				t.Fatalf("invalid port claim was accepted: %+v", job)
			}
		})
	}
}

func TestHostPullPortJournalRejectsTamperedRuntimePlan(t *testing.T) {
	agent, panel, _, _, policy := newHostPullPortExecutionHarness(t, false)
	job := *panel.job
	if err := agent.Journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.preparePortExecutionPlan(policy, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePortPlan(plan); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(agent.StateDir, "journal.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var data journalData
	if err := json.Unmarshal(payload, &data); err != nil {
		t.Fatal(err)
	}
	data.ActivePortPlan.NewPort++
	tampered, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(agent.StateDir); err == nil ||
		!strings.Contains(err.Error(), "active plan binding") {
		t.Fatalf("tampered port journal error=%v", err)
	}
}

func newHostPullExecutionHarness(t *testing.T, recovery bool) (*HostPullAgent, *hostPullExecutionTestPanel, *hostPullExecutionTestExecutor, HostAgentBinding, HostAgentPolicy) {
	t.Helper()
	bootstrap := managedHostAgentBootstrap("https://panel.example.com")
	binding := HostAgentBinding{
		ServiceID: bootstrap.NodeID, ServiceType: ServiceTypeUpdateAgent,
		TransportMode: HostTransportPullV2, ExecutionHostID: "host-a", OwnershipEpoch: 4,
	}
	policy := HostAgentPolicy{
		ServiceID: bootstrap.NodeID, TransportMode: HostTransportPullV2,
		ExecutionHostID: binding.ExecutionHostID, OwnershipEpoch: binding.OwnershipEpoch,
		Revision: 11, SourcePolicyRevision: 7, LocalExecutorPolicyRevision: 9,
		ObserveOnly:               false,
		LocalExecutorPolicySHA256: "sha256:" + strings.Repeat("b", 64),
		Targets: []HostAgentPolicyTarget{{
			ServiceID: "worker-01", ServiceType: "worker",
			DeploymentMode: ModeSystemd, AppliedConfigRevision: 1,
		}},
	}
	panel := &hostPullExecutionTestPanel{job: &UpdateJob{
		ID: "job-one", AgentServiceID: bootstrap.NodeID,
		HostID: binding.ExecutionHostID, TransportMode: HostTransportPullV2,
		OwnershipEpoch: binding.OwnershipEpoch, PolicyRevision: policy.Revision,
		TargetID: "worker-01", TargetType: "worker", ServiceType: "worker",
		DeploymentMode: ModeSystemd, CurrentVersion: "v1.0.0", TargetVersion: "v1.1.0",
		LeaseToken: strings.Repeat("l", 48), LeaseGeneration: 2, ReportSequence: 1,
		RecoveryRequired: recovery,
	}}
	executor := &hostPullExecutionTestExecutor{}
	agent, err := NewHostPullAgent(bootstrap, HostPullAgentOptions{
		StateDir: t.TempDir(), ControlPlane: panel,
		Executor: executor, Downloader: hostPullExecutionTestDownloader{},
		NewSessionID: func() (string, error) { return "session-0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(agent.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	agent.Journal = journal
	return agent, panel, executor, binding, policy
}

func newHostPullPortExecutionHarness(t *testing.T, recovery bool) (*HostPullAgent, *hostPullExecutionTestPanel, *hostPullExecutionTestExecutor, HostAgentBinding, HostAgentPolicy) {
	t.Helper()
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, recovery)
	expectedConfig := "sha256:" + strings.Repeat("d", 64)
	targetConfig := "sha256:" + strings.Repeat("e", 64)
	policy.Targets[0].AppliedConfigRevision = 3
	policy.Targets[0].AppliedConfigSHA256 = expectedConfig
	policy.Targets[0].LocalListenEndpoint = &HostAgentEndpoint{
		Host: "127.0.0.1", Port: 8084, PublicURL: "http://127.0.0.1:8084",
	}
	policy.Targets[0].DesiredEndpoint = &HostAgentEndpoint{
		Host: "127.0.0.1", Port: 9084, PublicURL: "http://127.0.0.1:9084",
	}
	panel.job.Operation = updateJobOperationPortReconfigure
	panel.job.CurrentVersion = "v1.0.0"
	panel.job.TargetVersion = "v1.0.0"
	panel.job.PortReconfigure = &SystemdPortMutationGrantBinding{
		NetworkNamespace:               systemdPortNetworkNamespaceHost,
		Protocol:                       systemdPortProtocolTCP,
		OldPort:                        8084,
		NewPort:                        9084,
		ExpectedEndpointRevision:       5,
		TargetEndpointRevision:         6,
		ExpectedConfigRevision:         3,
		TargetConfigRevision:           4,
		ExpectedConfigSHA256:           expectedConfig,
		TargetConfigSHA256:             targetConfig,
		ExpectedSourcePolicyRevision:   policy.SourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  policy.Revision,
		ExpectedExecutorPolicyRevision: policy.LocalExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   policy.LocalExecutorPolicySHA256,
		PortPlanSHA256:                 strings.Repeat("c", 64),
	}
	agent.PortExecutor = executor
	return agent, panel, executor, binding, policy
}
