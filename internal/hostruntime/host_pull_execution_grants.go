package hostruntime

import (
	"context"
	"errors"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"time"
)

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
		(plan.PortContractVersion != 2 && plan.ExpectedUpdaterPolicyRevision != job.PolicyRevision) ||
		(plan.PortContractVersion == 2 && plan.Before.ProjectionRevision != job.PolicyRevision) ||
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
	portV2 := isPortContractV2(job)
	revisionMatches := authorization.DesiredRevision == policy.Revision && authorization.DesiredRevision == job.PolicyRevision
	configMatches := target.ExpectedConfigRevision == policyTarget.appliedConfigRevision()
	if portV2 {
		revisionMatches = authorization.DesiredRevision == job.PortReconfigure.Target.ConfigRevision &&
			job.PolicyRevision == job.PortReconfigure.Before.ProjectionRevision && portClaimPolicyMatches(job, policy, policyTarget)
		configMatches = target.ExpectedConfigRevision == job.PortReconfigure.Before.ConfigRevision
	}
	if !ok ||
		command.CommandID != job.CommandID ||
		authorization.JobID != job.ID ||
		authorization.UpdaterID != updaterID ||
		authorization.UpdaterID != job.AgentServiceID ||
		authorization.HostID != hostBinding.ExecutionHostID ||
		authorization.HostID != job.HostID ||
		!revisionMatches ||
		authorization.Fence != hostBinding.OwnershipEpoch ||
		authorization.Fence != job.OwnershipEpoch ||
		lease.LeaseGeneration != int64(job.LeaseGeneration) ||
		target.TargetKind != contracts.UpdaterTargetApplication ||
		target.ServiceID != job.TargetID ||
		string(target.ServiceType) != job.EffectiveType() ||
		string(target.DeploymentMode) != job.DeploymentMode ||
		!configMatches {
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
		if isTerminalUpdateStatus(item.Report.Status) && !isPortRecoveryObservation(item.Report) {
			if err := cleanupJobDirectory(a.StateDir, item.JobID); err != nil {
				return err
			}
			if err := a.Journal.ClearActive(); err != nil {
				return err
			}
		}
	}
}
