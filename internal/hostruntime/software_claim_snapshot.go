package hostruntime

import "errors"

// bindSoftwareClaim authorizes a fresh lease against the authenticated policy.
// Recovery retains its saved authority; it does not approve an old command
// using whatever policy happens to be latest.
func (a *HostPullAgent) bindSoftwareClaim(panel HostPullExecutionControlPlane, binding HostAgentBinding, policy HostAgentPolicy, active *UpdateJob, job *UpdateJob) error {
	if job == nil || !isV2SoftwareJob(*job) {
		return nil
	}
	if !softwareClaimIdentityMatches(*job, a.Bootstrap.NodeID, binding, policy) || job.SoftwareUpdate == nil || job.SoftwareUpdate.validateIntent() != nil {
		return errors.New("software claim identity or original intent is invalid")
	}
	target, _ := hostPullPolicyTarget(policy, job.TargetID)
	wire := *job.SoftwareUpdate
	if wire.ConfigRevision != target.appliedConfigRevision() {
		return errors.New("software claim configuration differs from authenticated policy")
	}
	snapshot := SoftwareUpdateJobBinding{ConfigRevision: wire.ConfigRevision, ConfigSHA256: target.AppliedConfigSHA256, CommandSHA256: wire.CommandSHA256,
		SourcePolicyRevision: policy.SourcePolicyRevision, ProjectionRevision: policy.Revision, ExecutorPolicyRevision: policy.LocalExecutorPolicyRevision,
		ExecutorPolicySHA256: policy.LocalExecutorPolicySHA256}
	if snapshot.Validate() != nil {
		return errors.New("software claim authenticated policy is incomplete")
	}
	if (wire.ProjectionRevision != 0 && wire != snapshot) ||
		(wire.ProjectionRevision == 0 && job.PolicyRevision != 0) || (wire.ProjectionRevision != 0 && job.PolicyRevision != snapshot.ProjectionRevision) {
		return errors.New("software claim policy projection was replaced before binding")
	}
	if active != nil {
		if !sameSoftwareJobIdentity(*active, *job) || !sameRecoveredJobLease(*active, *job) {
			return errors.New("recovered software claim changed its immutable identity")
		}
		if active.SoftwareUpdate != nil {
			if *active.SoftwareUpdate != snapshot {
				return errors.New("recovered software claim changed its saved policy authority")
			}
			snapshot = *active.SoftwareUpdate
		} else {
			// Pre-fix journals stored C in PolicyRevision. Their existing plan D
			// binds all host policy revisions. Only that exact authenticated D,
			// a fresh same-job lease and the fixed target intent permit migration.
			plan := a.Journal.ActivePlan()
			if active.PolicyRevision != wire.ConfigRevision || plan == nil || plan.Validate() != nil ||
				plan.JobID != job.ID || plan.TargetID != job.TargetID || plan.HostID != job.HostID ||
				plan.CurrentVersion != job.CurrentVersion || plan.TargetVersion != job.EffectiveVersion() || plan.ConfigSHA256 != snapshot.ExecutorPolicySHA256 {
				return errors.New("legacy software cursor lacks its original trusted policy plan")
			}
			active.SoftwareUpdate = &snapshot
			active.PolicyRevision = snapshot.ProjectionRevision
		}
		job.SoftwareClaimRejected = active.SoftwareClaimRejected
	}
	job.SoftwareUpdate = &snapshot
	job.PolicyRevision = snapshot.ProjectionRevision
	if binder, ok := panel.(interface{ BindSoftwareUpdateClaim(UpdateJob) error }); ok {
		if err := binder.BindSoftwareUpdateClaim(*job); err != nil {
			return err
		}
	}
	return nil
}

func softwareClaimIdentityMatches(job UpdateJob, updaterID string, binding HostAgentBinding, policy HostAgentPolicy) bool {
	target, ok := hostPullPolicyTarget(policy, job.TargetID)
	return isV2SoftwareJob(job) && job.ID != "" && job.AgentServiceID == updaterID && job.HostID == binding.ExecutionHostID &&
		binding.ServiceID == updaterID && binding.ServiceType == ServiceTypeUpdateAgent && policy.ServiceID == updaterID &&
		job.TransportMode == HostTransportPullV2 && job.OwnershipEpoch == binding.OwnershipEpoch && policy.ExecutionHostID == binding.ExecutionHostID &&
		policy.TransportMode == HostTransportPullV2 && policy.OwnershipEpoch == binding.OwnershipEpoch && ok &&
		target.ServiceType == job.EffectiveType() && target.DeploymentMode == job.DeploymentMode
}

func sameSoftwareJobIdentity(left, right UpdateJob) bool {
	return isV2SoftwareJob(left) && isV2SoftwareJob(right) && left.ID == right.ID && left.Operation == right.Operation &&
		left.AgentServiceID == right.AgentServiceID && left.HostID == right.HostID && left.TransportMode == right.TransportMode &&
		left.OwnershipEpoch == right.OwnershipEpoch && left.TargetID == right.TargetID && left.TargetType == right.TargetType &&
		left.ServiceType == right.ServiceType && left.DeploymentMode == right.DeploymentMode && left.CurrentVersion == right.CurrentVersion &&
		left.TargetVersion == right.TargetVersion && left.Version == right.Version && left.PortReconfigure == nil && right.PortReconfigure == nil
}
