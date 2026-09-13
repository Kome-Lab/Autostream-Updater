package hostruntime

import (
	"context"
	"errors"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"math"
	"strings"
)

func validatePortExecutionResult(
	plan SystemdPortReconfigurePlan,
	result SystemdPortReconfigureResult,
) error {
	if plan.PortContractVersion == 2 {
		if result.PortContractVersion != 2 || result.PortResult == nil || result.Validate() != nil ||
			string(result.PortResult.Result) != result.Result {
			return errors.New("local executor returned an invalid port v2 result")
		}
		// This validates root evidence without claiming that the Agent adopted
		// a projection. Actual projection verification happens before queueing.
		checked := *clonePortResult(result.PortResult)
		if contracts.IsAcceptedSystemUpdatePortResult(checked) {
			checked.Observation.AgentProjectionVerified = true
		}
		if contracts.ValidateSystemUpdatePortResult(plan.SharedPortPlan(), checked) != nil {
			return errors.New("local executor port v2 result is outside the immutable plan")
		}
		return nil
	}
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
