package hostruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

type HostPullExecutionControlPlane interface {
	ClaimHost(context.Context, HostPullClaimRequest) (*UpdateJob, bool, error)
	Report(context.Context, string, JobReport) error
	IssueMutationGrant(context.Context, string, MutationGrantRequest) (MutationGrant, error)
}

type HostPullClaimRequest struct {
	UpdaterID       string
	HostID          string
	LeaseGeneration int64
	Fence           int64
	ActiveJobID     string
}

func newHostPullSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "session-" + hex.EncodeToString(value[:]), nil
}

func (a *HostPullAgent) mutationReady(
	binding HostAgentBinding,
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) bool {
	return a.mutationCapabilityReady(
		binding, policy, observations, observationFailed,
	) &&
		policy.RuntimeTokenRotation == nil
}

func (a *HostPullAgent) mutationCapabilityReady(
	binding HostAgentBinding,
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) bool {
	return a.executorReady(policy, observations, observationFailed) &&
		!policy.ObserveOnly &&
		binding.TransportMode == HostTransportPullV2 &&
		binding.OwnershipEpoch > 0 &&
		policy.TransportMode == HostTransportPullV2 &&
		policy.ExecutionHostID == binding.ExecutionHostID &&
		policy.OwnershipEpoch == binding.OwnershipEpoch
}

func (a *HostPullAgent) executorReady(
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) bool {
	if a == nil || policy == nil || observationFailed ||
		a.Executor == nil || a.Downloader == nil || a.NewSessionID == nil ||
		policy.TransportMode != HostTransportPullV2 ||
		policy.Revision < 1 ||
		policy.SourcePolicyRevision < 1 ||
		policy.LocalExecutorPolicyRevision < 1 ||
		policy.LocalExecutorPolicySHA256 == "" {
		return false
	}
	if _, ok := a.ControlPlane.(HostPullExecutionControlPlane); !ok {
		return false
	}
	observed := make(map[string]HostTargetObservation, len(observations))
	for _, observation := range observations {
		observed[observation.ServiceID] = observation
	}
	for _, target := range policy.Targets {
		observation, ok := observed[target.ServiceID]
		if !ok ||
			observation.Availability != TargetAvailabilityAvailable ||
			observation.PolicyRevision != policy.LocalExecutorPolicyRevision ||
			observation.PolicySHA256 != policy.LocalExecutorPolicySHA256 ||
			observation.ConfigRevision != target.appliedConfigRevision() ||
			!localExecutorConfigDigestMatchesTarget(
				*policy, target, observation.ConfigSHA256,
			) {
			return false
		}
	}
	return len(policy.Targets) > 0
}

func (a *HostPullAgent) startExecution(
	ctx context.Context,
	binding HostAgentBinding,
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) {
	if !a.mutationReady(binding, policy, observations, observationFailed) ||
		!a.executionRunning.CompareAndSwap(false, true) {
		return
	}
	policySnapshot := *policy
	policySnapshot.Targets = append([]HostAgentPolicyTarget(nil), policy.Targets...)
	go func() {
		defer a.executionRunning.Store(false)
		if err := a.executeOnce(ctx, binding, policySnapshot); err != nil &&
			ctx.Err() == nil {
			a.Logf("host pull agent execution poll failed: %v", err)
		}
	}()
}

func (a *HostPullAgent) executeOnce(ctx context.Context, binding HostAgentBinding, policy HostAgentPolicy) error {
	panel, ok := a.ControlPlane.(HostPullExecutionControlPlane)
	if !ok || a.Journal == nil {
		return errors.New("host pull execution dependencies are incomplete")
	}
	if err := a.validateRuntimeForClaim(ctx, binding, policy); err != nil {
		return err
	}
	if err := a.flushExecutionReports(ctx, panel); err != nil {
		return err
	}
	active := a.Journal.Active()
	activeID := ""
	leaseGeneration := int64(1)
	if active != nil {
		activeID = active.ID
		if active.LeaseGeneration == 0 || active.LeaseGeneration > math.MaxInt64 {
			return errors.New("active pull_v2 lease generation is invalid")
		}
		leaseGeneration = int64(active.LeaseGeneration)
	}
	job, clearActive, err := panel.ClaimHost(ctx, HostPullClaimRequest{
		UpdaterID:       a.Bootstrap.NodeID,
		HostID:          binding.ExecutionHostID,
		LeaseGeneration: leaseGeneration,
		Fence:           binding.OwnershipEpoch,
		ActiveJobID:     activeID,
	})
	if err != nil {
		return err
	}
	if clearActive {
		if active == nil || job == nil {
			return errors.New("terminal pull recovery proof does not match the active job")
		}
		if job.RecoveryClear {
			if err := validateV2RecoveryClear(*active, *job, a.Bootstrap.NodeID); err != nil {
				return err
			}
		} else if !sameRecoveredJobIntent(*active, *job) ||
			!isTerminalUpdateStatus(job.Status) {
			return errors.New("terminal pull recovery proof does not match the active job")
		}
		if err := cleanupJobDirectory(a.StateDir, active.ID); err != nil {
			return fmt.Errorf("clean terminal pull recovery job state: %w", err)
		}
		return a.Journal.ClearActive()
	}
	if job == nil {
		return nil
	}
	if err := validateHostPullClaim(*job, a.Bootstrap.NodeID, binding, policy); err != nil {
		return err
	}
	if active != nil && (active.ID != job.ID || !job.RecoveryRequired) {
		return fmt.Errorf("refusing claim %s while interrupted job %s awaits recovery", job.ID, active.ID)
	}
	if active != nil && !sameRecoveredJobIntent(*active, *job) {
		return fmt.Errorf("refusing recovered claim %s because its immutable intent changed", job.ID)
	}
	return a.processExecutionJob(ctx, panel, binding, policy, *job)
}

func validateV2RecoveryClear(active, terminal UpdateJob, updaterID string) error {
	if active.ProtocolVersion != 2 ||
		!terminal.RecoveryClear || terminal.ProtocolVersion != 2 ||
		terminal.ID != active.ID ||
		active.AgentServiceID != updaterID ||
		terminal.AgentServiceID != updaterID ||
		!terminal.ReleaseToken.Empty() ||
		terminal.LeaseToken != "" ||
		terminal.LeaseExpiresAt != "" ||
		terminal.LeaseGeneration != 0 ||
		!isV2RecoveryClearStatus(terminal.Status) {
		return errors.New("v2 recovery clear does not match the active job")
	}
	return nil
}

func isV2RecoveryClearStatus(status string) bool {
	return status == "canceled"
}

func validateHostPullClaim(job UpdateJob, serviceID string, binding HostAgentBinding, policy HostAgentPolicy) error {
	if !job.ReleaseToken.Empty() {
		return errors.New("pull_v2 claim unexpectedly contained a release credential")
	}
	if err := job.validateOperationUnion(); err != nil {
		return err
	}
	if !identifierPattern.MatchString(job.ID) ||
		job.AgentServiceID != serviceID ||
		job.HostID != binding.ExecutionHostID ||
		job.TransportMode != HostTransportPullV2 ||
		job.OwnershipEpoch != binding.OwnershipEpoch ||
		job.PolicyRevision != policy.Revision ||
		job.LeaseGeneration == 0 ||
		job.ReportSequence == 0 {
		return errors.New("pull_v2 claim ownership or lease binding is invalid")
	}
	if job.ProtocolVersion == 2 {
		if job.LeaseToken != "" || !identifierPattern.MatchString(job.CommandID) {
			return errors.New("pull_v2 v2 claim credential or command binding is invalid")
		}
	} else if !validBoundedSecret(job.LeaseToken) {
		return errors.New("pull_v2 legacy claim lease credential is invalid")
	}
	target, ok := hostPullPolicyTarget(policy, job.TargetID)
	if !ok ||
		target.ServiceType != job.EffectiveType() ||
		target.DeploymentMode != job.DeploymentMode {
		return errors.New("pull_v2 claim target does not match the active policy")
	}
	if job.EffectiveOperation() == updateJobOperationPortReconfigure {
		port := job.PortReconfigure
		if port == nil ||
			port.ExpectedSourcePolicyRevision != policy.SourcePolicyRevision ||
			port.ExpectedUpdaterPolicyRevision != policy.Revision ||
			port.ExpectedUpdaterPolicyRevision != job.PolicyRevision ||
			port.ExpectedExecutorPolicyRevision != policy.LocalExecutorPolicyRevision ||
			port.ExpectedExecutorPolicySHA256 != policy.LocalExecutorPolicySHA256 ||
			port.ExpectedConfigRevision != target.appliedConfigRevision() ||
			port.ExpectedConfigSHA256 != target.AppliedConfigSHA256 ||
			target.DesiredEndpoint == nil ||
			target.DesiredEndpoint.Port != port.NewPort {
			return errors.New("pull_v2 port claim does not match the active policy")
		}
		if job.ProtocolVersion == 2 {
			if job.CurrentVersion != "" || job.TargetVersion != "" || job.Version != "" {
				return errors.New("pull_v2 v2 port claim must remain versionless")
			}
		} else if !versionPattern.MatchString(job.CurrentVersion) ||
			!versionPattern.MatchString(job.TargetVersion) ||
			job.CurrentVersion != strings.TrimSpace(job.CurrentVersion) ||
			job.TargetVersion != strings.TrimSpace(job.TargetVersion) ||
			job.Version != "" ||
			job.TargetVersion != job.CurrentVersion {
			return errors.New("pull_v2 legacy port claim version binding is invalid")
		}
		switch job.DeploymentMode {
		case ModeSystemd:
			if port.Docker != nil ||
				target.LocalListenEndpoint == nil ||
				target.LocalListenEndpoint.Port != port.OldPort {
				return errors.New("pull_v2 systemd port claim does not match the active policy")
			}
		case ModeDocker:
			if port.Docker == nil ||
				target.AppliedEndpoint == nil ||
				target.AppliedEndpoint.Port != port.OldPort ||
				target.LocalHealthEndpoint == nil ||
				target.LocalHealthEndpoint.Host != port.Docker.PublishedHostIP ||
				target.LocalHealthEndpoint.Port != port.Docker.OldHealthPort {
				return errors.New("pull_v2 Docker port claim does not match the active policy")
			}
		default:
			return errors.New("pull_v2 port claim deployment mode is unsupported")
		}
	} else if !versionPattern.MatchString(job.CurrentVersion) ||
		!versionPattern.MatchString(job.EffectiveVersion()) ||
		job.CurrentVersion != strings.TrimSpace(job.CurrentVersion) {
		return errors.New("pull_v2 claim version binding is invalid")
	}
	return nil
}

func sameRecoveredJobIntent(active, recovered UpdateJob) bool {
	if active.ProtocolVersion != recovered.ProtocolVersion ||
		active.CommandID != recovered.CommandID ||
		active.ID != recovered.ID ||
		active.Operation != recovered.Operation ||
		active.AgentServiceID != recovered.AgentServiceID ||
		active.HostID != recovered.HostID ||
		active.TransportMode != recovered.TransportMode ||
		active.OwnershipEpoch != recovered.OwnershipEpoch ||
		active.PolicyRevision != recovered.PolicyRevision ||
		active.TargetID != recovered.TargetID ||
		active.TargetType != recovered.TargetType ||
		active.ServiceType != recovered.ServiceType ||
		active.DeploymentMode != recovered.DeploymentMode ||
		active.CurrentVersion != recovered.CurrentVersion ||
		active.TargetVersion != recovered.TargetVersion ||
		active.Version != recovered.Version {
		return false
	}
	if active.EffectiveOperation() == updateJobOperationSoftwareUpdate {
		return active.PortReconfigure == nil && recovered.PortReconfigure == nil
	}
	return samePortMutationGrantBinding(
		active.PortReconfigure,
		recovered.PortReconfigure,
	)
}

func samePortMutationGrantBinding(
	left, right *SystemdPortMutationGrantBinding,
) bool {
	if left == nil || right == nil {
		return left == right
	}
	leftCopy := *left
	rightCopy := *right
	leftDocker := leftCopy.Docker
	rightDocker := rightCopy.Docker
	leftCopy.Docker = nil
	rightCopy.Docker = nil
	if leftCopy != rightCopy {
		return false
	}
	if leftDocker == nil || rightDocker == nil {
		return leftDocker == rightDocker
	}
	return *leftDocker == *rightDocker
}

func hostPullPolicyTarget(policy HostAgentPolicy, serviceID string) (HostAgentPolicyTarget, bool) {
	for _, target := range policy.Targets {
		if target.ServiceID == serviceID {
			return target, true
		}
	}
	return HostAgentPolicyTarget{}, false
}

func (a *HostPullAgent) processExecutionJob(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	binding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
) error {
	if job.EffectiveOperation() == updateJobOperationPortReconfigure {
		return a.processPortReconfigurationJob(ctx, panel, binding, policy, job)
	}
	if err := a.Journal.SetActive(&job); err != nil {
		return err
	}
	terminal := func(status, code, message string, result ApplyResult) error {
		_, err := a.emitExecutionReport(ctx, panel, job, status, code, message, 100, result.ArtifactDigest, result.PreviousDigest)
		return err
	}
	if job.RecoveryRequired {
		plan, err := a.recoverExecutionPlan(policy, job)
		if err != nil {
			return terminal("failed", "recovery_plan_unavailable", "interrupted job has no trusted durable plan to reconcile", ApplyResult{})
		}
		if _, err := a.emitExecutionReport(ctx, panel, job, "reconciling", "", "inspecting interrupted host update state without reapplying", 99, "", ""); err != nil {
			return err
		}
		result, err := a.invokeExecutionMutation(ctx, panel, binding, policy, job, plan, "reconcile")
		if err != nil {
			if localExecutorErrorCode(err) == "stage_required" {
				if failure := a.Journal.ActiveStageFailure(); failure != nil && failure.JobID == job.ID {
					return terminal(
						"failed", failure.reportCode(), failure.Message,
						ApplyResult{},
					)
				}
				return terminal(
					"failed", "remote_stage_missing",
					"interrupted job has no durable mutation state to reconcile",
					ApplyResult{},
				)
			}
			return err
		}
		return a.finishExecutionResult(terminal, result)
	}

	if _, err := a.emitExecutionReport(ctx, panel, job, "claimed", "", "update job claimed and fixed target validated", 5, "", ""); err != nil {
		return err
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "downloading", "", "resolving immutable public release metadata", 20, "", ""); err != nil {
		return err
	}
	plan, err := a.prepareExecutionPlan(ctx, policy, job)
	if err != nil {
		return terminal("failed", "artifact_verification_failed", "immutable public release metadata could not be verified", ApplyResult{})
	}
	if err := a.Journal.SetActivePlan(plan); err != nil {
		return err
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "verifying", "", "release tag, manifest and artifact identity verified", 40, normalizeDigest(plan.ArtifactDigest), ""); err != nil {
		return err
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "staging", "", "root executor is staging the immutable release", 55, normalizeDigest(plan.ArtifactDigest), ""); err != nil {
		return err
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          binding.OwnershipEpoch,
		OwnershipPolicyRevision: job.PolicyRevision,
		ExecutorPolicyRevision:  policy.LocalExecutorPolicyRevision,
	}
	if _, err := a.Executor.Stage(ctx, plan, fence); err != nil {
		if failure, ok := stageFailureFromLocalExecutorError(job.ID, err); ok {
			if journalErr := a.Journal.SetActiveStageFailure(failure); journalErr != nil {
				return journalErr
			}
		}
		// Stage is non-mutating. Preserve the active cursor because a lost UDS
		// result or an explicit failure after an uncertain ledger commit may have
		// left durable state, so recovery must prove and settle it.
		return err
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "installing", "", "root executor is applying the fixed target", 65, normalizeDigest(plan.ArtifactDigest), ""); err != nil {
		return err
	}
	result, err := a.invokeExecutionMutation(ctx, panel, binding, policy, job, plan, "apply")
	if err != nil {
		if _, reportErr := a.emitExecutionReport(ctx, panel, job, "reconciling", "", "apply result is uncertain; reconciling without reapplying", 99, "", ""); reportErr != nil {
			return reportErr
		}
		result, err = a.invokeExecutionMutation(ctx, panel, binding, policy, job, plan, "reconcile")
		if err != nil {
			return err
		}
		// Reconciling is reported at 99%, and the server accepts only a terminal
		// transition from that state. Do not regress to health_checking/90 after
		// the executor has already returned its durable verified result.
		return a.finishExecutionResult(terminal, result)
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "health_checking", "", "root executor completed bounded health and version checks", 90, result.ArtifactDigest, result.PreviousDigest); err != nil {
		return err
	}
	if result.Status == "rolled_back" || result.RolledBack {
		if _, err := a.emitExecutionReport(
			ctx, panel, job, "rolling_back", "",
			"post-update checks failed; previous release was restored", 95,
			result.ArtifactDigest, result.PreviousDigest,
		); err != nil {
			return err
		}
	}
	return a.finishExecutionResult(terminal, result)
}

func localExecutorErrorCode(err error) string {
	var executorErr *LocalExecutorClientError
	if errors.As(err, &executorErr) {
		return strings.TrimSpace(executorErr.Code)
	}
	return ""
}

func (a *HostPullAgent) processPortReconfigurationJob(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	binding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
) error {
	if a.PortExecutor == nil {
		return errors.New("host pull port executor is unavailable")
	}
	if err := a.Journal.SetActive(&job); err != nil {
		return err
	}
	if job.RecoveryRequired {
		plan, err := a.recoverPortExecutionPlan(policy, job)
		if err != nil {
			// A port terminal report must carry a locally verified applied,
			// unchanged, rolled-back, or rollback-failed result. Never invent
			// one merely because the durable plan cannot yet be recovered.
			return err
		}
		if _, err := a.emitPortExecutionReport(
			ctx, panel, job, "reconciling", "",
			"inspecting interrupted port change without reapplying", 99, nil,
		); err != nil {
			return err
		}
		result, err := a.invokePortExecutionMutation(
			ctx, panel, binding, policy, job, plan, "port_reconfigure_reconcile",
		)
		if err != nil {
			return err
		}
		return a.finishPortExecutionResult(ctx, panel, job, plan, result)
	}

	if _, err := a.emitPortExecutionReport(
		ctx, panel, job, "claimed", "",
		"port reconfiguration job claimed and immutable intent validated", 5, nil,
	); err != nil {
		return err
	}
	plan, err := a.preparePortExecutionPlan(policy, job)
	if err != nil {
		// The claim remains durable and will be reclaimed in recovery mode.
		// Reporting a terminal port failure without a verified local result
		// would violate the server contract and strand pending endpoint state.
		return err
	}
	if err := a.Journal.SetActivePortPlan(plan); err != nil {
		return err
	}
	if _, err := a.emitPortExecutionReport(
		ctx, panel, job, "installing", "",
		"root executor is applying the fixed port transition", 65, nil,
	); err != nil {
		return err
	}
	result, err := a.invokePortExecutionMutation(
		ctx, panel, binding, policy, job, plan, "port_reconfigure",
	)
	if err != nil {
		if _, reportErr := a.emitPortExecutionReport(
			ctx, panel, job, "reconciling", "",
			"port mutation result is uncertain; reconciling without reapplying", 99, nil,
		); reportErr != nil {
			return reportErr
		}
		result, err = a.invokePortExecutionMutation(
			ctx, panel, binding, policy, job, plan, "port_reconfigure_reconcile",
		)
		if err != nil {
			return err
		}
	}
	return a.finishPortExecutionResult(ctx, panel, job, plan, result)
}

func (a *HostPullAgent) preparePortExecutionPlan(
	policy HostAgentPolicy,
	job UpdateJob,
) (SystemdPortReconfigurePlan, error) {
	sessionID, err := a.NewSessionID()
	if err != nil {
		return SystemdPortReconfigurePlan{}, err
	}
	return portExecutionPlanFromJob(policy, job, sessionID)
}

func portExecutionPlanFromJob(
	policy HostAgentPolicy,
	job UpdateJob,
	sessionID string,
) (SystemdPortReconfigurePlan, error) {
	if job.PortReconfigure == nil {
		return SystemdPortReconfigurePlan{}, errors.New("port job contract is unavailable")
	}
	port := *job.PortReconfigure
	plan := SystemdPortReconfigurePlan{
		DeploymentMode: job.DeploymentMode,
		JobID:          job.ID, HostID: job.HostID, TargetID: job.TargetID,
		ServiceType:      job.EffectiveType(),
		NetworkNamespace: port.NetworkNamespace, Protocol: port.Protocol,
		OldPort: port.OldPort, NewPort: port.NewPort,
		ExpectedEndpointRevision:       port.ExpectedEndpointRevision,
		TargetEndpointRevision:         port.TargetEndpointRevision,
		ExpectedConfigRevision:         port.ExpectedConfigRevision,
		TargetConfigRevision:           port.TargetConfigRevision,
		ExpectedConfigSHA256:           port.ExpectedConfigSHA256,
		TargetConfigSHA256:             port.TargetConfigSHA256,
		ExpectedSourcePolicyRevision:   port.ExpectedSourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  port.ExpectedUpdaterPolicyRevision,
		ExpectedExecutorPolicyRevision: port.ExpectedExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   port.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:                 job.OwnershipEpoch,
		LeaseGeneration:                job.LeaseGeneration,
		SessionID:                      sessionID,
		Docker:                         cloneDockerPortMutationGrantBinding(port.Docker),
	}
	if plan.ExpectedSourcePolicyRevision != policy.SourcePolicyRevision ||
		plan.ExpectedUpdaterPolicyRevision != policy.Revision ||
		plan.ExpectedExecutorPolicyRevision != policy.LocalExecutorPolicyRevision ||
		plan.ExpectedExecutorPolicySHA256 != policy.LocalExecutorPolicySHA256 {
		return SystemdPortReconfigurePlan{}, errors.New("port job policy fence is stale")
	}
	runtimeHash, err := plan.ComputePortPlanSHA256()
	if err != nil {
		return SystemdPortReconfigurePlan{}, err
	}
	// The nested job hash authenticates the server/store intent. The local
	// executor hash additionally binds this claim's lease generation and the
	// fresh durable session, so it must always be computed locally.
	plan.PortPlanSHA256 = runtimeHash
	if err := plan.Validate(); err != nil {
		return SystemdPortReconfigurePlan{}, err
	}
	return plan, nil
}

func (a *HostPullAgent) recoverPortExecutionPlan(
	policy HostAgentPolicy,
	job UpdateJob,
) (SystemdPortReconfigurePlan, error) {
	stored := a.Journal.ActivePortPlan()
	if stored == nil {
		// SetActive is persisted before the runtime plan. A crash in that
		// narrow window cannot have reached the Local Executor, so reconstruct
		// a fresh session and use reconcile. If a root ledger somehow exists,
		// its different session/plan binding will fail closed.
		fresh, err := a.preparePortExecutionPlan(policy, job)
		if err != nil {
			return SystemdPortReconfigurePlan{}, errors.New("durable port recovery plan is unavailable")
		}
		if err := a.Journal.SetActivePortPlan(fresh); err != nil {
			return SystemdPortReconfigurePlan{}, err
		}
		return fresh, nil
	}
	if stored.Validate() != nil {
		return SystemdPortReconfigurePlan{}, errors.New("durable port recovery plan is unavailable")
	}
	rebound, err := portExecutionPlanFromJob(policy, job, stored.SessionID)
	if err != nil || !sameSystemdPortIntent(*stored, rebound) {
		return SystemdPortReconfigurePlan{}, errors.New("durable port recovery plan does not match the recovered job")
	}
	if err := a.Journal.SetActivePortPlan(rebound); err != nil {
		return SystemdPortReconfigurePlan{}, err
	}
	return rebound, nil
}

func (a *HostPullAgent) invokePortExecutionMutation(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	binding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	plan SystemdPortReconfigurePlan,
	operation string,
) (SystemdPortReconfigureResult, error) {
	if operation != "port_reconfigure" && operation != "port_reconfigure_reconcile" {
		return SystemdPortReconfigureResult{}, errors.New("port mutation operation is invalid")
	}
	var requiredV2Executor LocalExecutorV2PortMutationClient
	if job.ProtocolVersion == 2 {
		var ok bool
		requiredV2Executor, ok = a.PortExecutor.(LocalExecutorV2PortMutationClient)
		if !ok {
			return SystemdPortReconfigureResult{}, errors.New("local executor does not support v2 port mutation grants")
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
			DeploymentMode: job.DeploymentMode,
			JobOperation:   updateJobOperationPortReconfigure,
			Operation:      operation,
			PlanSHA256:     plan.PortPlanSHA256, SessionID: plan.SessionID,
			PortReconfigure: plan.mutationGrantBinding(),
		},
	})
	if err != nil {
		return SystemdPortReconfigureResult{}, err
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
			v2Executor, ok = a.PortExecutor.(LocalExecutorV2PortMutationClient)
			if !ok {
				return SystemdPortReconfigureResult{}, errors.New("local executor does not support v2 port mutation grants")
			}
		}
		if err := validateV2PortExecutionGrant(
			hostPullExecutionNow(panel), a.Bootstrap.NodeID, binding, policy,
			job, plan, operation, *grant.V2Binding,
		); err != nil {
			return SystemdPortReconfigureResult{}, err
		}
		v2Grant := V2MutationGrant{
			Token: NewBoundedSecret(grant.Token), Binding: *grant.V2Binding,
		}
		if operation == "port_reconfigure" {
			return v2Executor.PortReconfigureV2(ctx, plan, fence, v2Grant)
		}
		return v2Executor.PortReconfigureReconcileV2(ctx, plan, fence, v2Grant)
	}
	if job.ProtocolVersion == 2 {
		return SystemdPortReconfigureResult{}, errors.New("v2 port mutation grant binding is unavailable")
	}
	if operation == "port_reconfigure" {
		return a.PortExecutor.PortReconfigure(ctx, plan, fence, NewBoundedSecret(grant.Token))
	}
	return a.PortExecutor.PortReconfigureReconcile(ctx, plan, fence, NewBoundedSecret(grant.Token))
}

func (a *HostPullAgent) finishPortExecutionResult(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	job UpdateJob,
	plan SystemdPortReconfigurePlan,
	result SystemdPortReconfigureResult,
) error {
	if err := validatePortExecutionResult(plan, result); err != nil {
		return err
	}
	switch result.Status {
	case "succeeded":
		return a.emitPortExecutionTerminal(
			ctx, panel, job, "succeeded", "",
			"requested port is running and verified", &result,
		)
	case "rolled_back":
		return a.emitPortExecutionTerminal(
			ctx, panel, job, "rolled_back", "post_update_verification_failed",
			"previous port is running and verified", &result,
		)
	case "failed":
		return a.emitPortExecutionTerminal(
			ctx, panel, job, "failed", "port_rollback_failed",
			"port rollback could not determine a verified effective port", &result,
		)
	default:
		return errors.New("local executor returned a non-terminal port result")
	}
}

func validatePortExecutionResult(
	plan SystemdPortReconfigurePlan,
	result SystemdPortReconfigureResult,
) error {
	resultMode := strings.TrimSpace(result.DeploymentMode)
	if resultMode == "" {
		resultMode = ModeSystemd
	}
	if err := result.Validate(); err != nil ||
		resultMode != plan.effectiveDeploymentMode() ||
		result.OldPort != plan.OldPort ||
		result.NewPort != plan.NewPort {
		return errors.New("local executor returned a port result outside the immutable plan")
	}
	switch result.Result {
	case systemdPortResultApplied:
		if result.EndpointRevision != plan.TargetEndpointRevision ||
			result.ConfigRevision != plan.TargetConfigRevision ||
			result.ConfigSHA256 != plan.TargetConfigSHA256 {
			return errors.New("local executor applied port result does not match the target config")
		}
		if resultMode == ModeDocker &&
			!dockerPortExecutionResultMatchesPlan(
				result.Docker,
				plan.Docker.NewPublishedPort,
				plan.Docker.NewContainerPort,
				plan.Docker.NewHealthPort,
			) {
			return errors.New("local executor applied Docker mapping does not match the immutable plan")
		}
	case systemdPortResultRolledBack, systemdPortResultUnchanged:
		if plan.TargetEndpointRevision >= math.MaxInt64 ||
			result.EndpointRevision != plan.TargetEndpointRevision+1 ||
			result.ConfigRevision != plan.ExpectedConfigRevision ||
			result.ConfigSHA256 != plan.ExpectedConfigSHA256 {
			return errors.New("local executor rollback port result does not match the previous config")
		}
		if resultMode == ModeDocker &&
			!dockerPortExecutionResultMatchesPlan(
				result.Docker,
				plan.Docker.OldPublishedPort,
				plan.Docker.OldContainerPort,
				plan.Docker.OldHealthPort,
			) {
			return errors.New("local executor rollback Docker mapping does not match the immutable plan")
		}
	case systemdPortResultRollbackFailed:
		if result.EndpointRevision != plan.TargetEndpointRevision {
			return errors.New("local executor failed rollback result does not match the pending endpoint fence")
		}
	default:
		return errors.New("local executor port result kind is invalid")
	}
	return nil
}

func dockerPortExecutionResultMatchesPlan(
	result *DockerPortReconfigureResultState,
	publishedPort, containerPort, healthPort int,
) bool {
	return result != nil &&
		result.AppliedPublishedPort == publishedPort &&
		result.AppliedContainerPort == containerPort &&
		result.AppliedHealthPort == healthPort
}

func (a *HostPullAgent) emitPortExecutionTerminal(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	job UpdateJob,
	status, code, message string,
	result *SystemdPortReconfigureResult,
) error {
	_, err := a.emitPortExecutionReport(ctx, panel, job, status, code, message, 100, result)
	return err
}

func (a *HostPullAgent) emitPortExecutionReport(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	job UpdateJob,
	status, code, message string,
	progress int,
	result *SystemdPortReconfigureResult,
) (JobReport, error) {
	if result != nil && !isTerminalUpdateStatus(status) {
		return JobReport{}, errors.New("port result is only valid on a terminal report")
	}
	report, err := a.Journal.QueuePort(
		job.ID, a.Bootstrap.NodeID, job.LeaseToken, job.LeaseGeneration,
		status, code, message, progress, result,
	)
	if err != nil {
		return JobReport{}, err
	}
	if err := a.flushExecutionReports(ctx, panel); err != nil {
		return report, err
	}
	return report, nil
}

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

func validateV2SoftwareExecutionGrant(
	now time.Time,
	updaterID string,
	hostBinding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	plan MutationPlan,
	operation string,
	grantBinding contracts.UpdaterMutationGrantBinding,
) error {
	desired, err := validateV2ExecutionGrantCommon(
		now, updaterID, hostBinding, policy, job,
		operation, plan.SessionID, grantBinding,
	)
	if err != nil {
		return err
	}
	if desired.Operation != contracts.UpdaterDesiredSoftwareUpdate ||
		desired.SoftwareUpdate == nil ||
		desired.SoftwareUpdate.ExpectedCurrentVersion != plan.CurrentVersion ||
		desired.SoftwareUpdate.TargetVersion != plan.TargetVersion ||
		plan.JobID != job.ID ||
		plan.HostID != job.HostID ||
		plan.TargetID != job.TargetID ||
		plan.ServiceType != job.EffectiveType() ||
		plan.DeploymentMode != job.DeploymentMode ||
		plan.CurrentVersion != job.CurrentVersion ||
		plan.TargetVersion != job.EffectiveVersion() ||
		plan.LeaseGeneration != job.LeaseGeneration ||
		plan.ConfigSHA256 != policy.LocalExecutorPolicySHA256 {
		return errors.New("v2 mutation grant does not match the software update plan")
	}
	return nil
}

func validateV2PortExecutionGrant(
	now time.Time,
	updaterID string,
	hostBinding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	plan SystemdPortReconfigurePlan,
	operation string,
	grantBinding contracts.UpdaterMutationGrantBinding,
) error {
	desired, err := validateV2ExecutionGrantCommon(
		now, updaterID, hostBinding, policy, job,
		operation, plan.SessionID, grantBinding,
	)
	if err != nil {
		return err
	}
	if desired.Operation != contracts.UpdaterDesiredPortReconfigure ||
		desired.PortReconfigure == nil ||
		job.PortReconfigure == nil ||
		desired.PortReconfigure.PortPlanSHA256 != job.PortReconfigure.PortPlanSHA256 ||
		!v2PortDesiredMatchesPlan(desired.PortReconfigure, plan) ||
		plan.JobID != job.ID ||
		plan.HostID != job.HostID ||
		plan.TargetID != job.TargetID ||
		plan.ServiceType != job.EffectiveType() ||
		plan.effectiveDeploymentMode() != job.DeploymentMode ||
		plan.ExpectedUpdaterPolicyRevision != job.PolicyRevision ||
		plan.OwnershipEpoch != job.OwnershipEpoch ||
		plan.LeaseGeneration != job.LeaseGeneration {
		return errors.New("v2 mutation grant does not match the port reconfiguration plan")
	}
	return nil
}

func validateV2ExecutionGrantCommon(
	now time.Time,
	updaterID string,
	hostBinding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
	operation string,
	sessionID string,
	grantBinding contracts.UpdaterMutationGrantBinding,
) (contracts.UpdaterDesiredOperation, error) {
	if job.ProtocolVersion != 2 || job.LeaseToken != "" ||
		contracts.ValidateUpdaterMutationGrantBinding(now, grantBinding) != nil ||
		grantBinding.Operation != contracts.UpdaterMutationOperation(operation) ||
		grantBinding.SessionID != sessionID {
		return contracts.UpdaterDesiredOperation{}, errors.New("v2 mutation grant binding is invalid")
	}
	lease := grantBinding.Lease
	command := lease.Command
	authorization := command.MutationAuthorization
	target := authorization.Target
	policyTarget, ok := hostPullPolicyTarget(policy, job.TargetID)
	if !ok ||
		command.CommandID != job.CommandID ||
		authorization.JobID != job.ID ||
		authorization.UpdaterID != updaterID ||
		authorization.UpdaterID != job.AgentServiceID ||
		authorization.HostID != hostBinding.ExecutionHostID ||
		authorization.HostID != job.HostID ||
		authorization.DesiredRevision != policy.Revision ||
		authorization.DesiredRevision != job.PolicyRevision ||
		authorization.Fence != hostBinding.OwnershipEpoch ||
		authorization.Fence != job.OwnershipEpoch ||
		lease.LeaseGeneration != int64(job.LeaseGeneration) ||
		target.TargetKind != contracts.UpdaterTargetApplication ||
		target.ServiceID != job.TargetID ||
		string(target.ServiceType) != job.EffectiveType() ||
		string(target.DeploymentMode) != job.DeploymentMode ||
		target.ExpectedConfigRevision != policyTarget.appliedConfigRevision() {
		return contracts.UpdaterDesiredOperation{}, errors.New("v2 mutation grant does not match the claimed job and active policy")
	}
	return command.DesiredOperation, nil
}

func (a *HostPullAgent) emitExecutionReport(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	job UpdateJob,
	status, code, message string,
	progress int,
	artifact, previous string,
) (JobReport, error) {
	report, err := a.Journal.Queue(
		job.ID, a.Bootstrap.NodeID, job.LeaseToken, job.LeaseGeneration,
		status, code, message, progress,
		canonicalReportDigest(artifact), canonicalReportDigest(previous),
	)
	if err != nil {
		return JobReport{}, err
	}
	if err := a.flushExecutionReports(ctx, panel); err != nil {
		return report, err
	}
	return report, nil
}

func (a *HostPullAgent) flushExecutionReports(ctx context.Context, panel HostPullExecutionControlPlane) error {
	for {
		pending := a.Journal.Pending()
		if len(pending) == 0 {
			return nil
		}
		item := pending[0]
		if err := panel.Report(ctx, item.JobID, item.Report); err != nil {
			if IsPermanentReportError(err) {
				// A stale lease or sequence says only that this report cursor is no
				// longer usable. Drop that cursor without running terminal cleanup or
				// clearing the durable job and plan needed by the next recovery lease.
				if dropErr := a.Journal.DropJobReports(item.JobID); dropErr != nil {
					return dropErr
				}
				return ErrLeaseLost
			}
			return err
		}
		if err := a.Journal.Ack(item.JobID, item.Report.Sequence); err != nil {
			return err
		}
		if isTerminalUpdateStatus(item.Report.Status) {
			if err := cleanupJobDirectory(a.StateDir, item.JobID); err != nil {
				return err
			}
			if err := a.Journal.ClearActive(); err != nil {
				return err
			}
		}
	}
}
