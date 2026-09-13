package hostruntime

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"time"
)

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
		(!isPortContractV2(job) && job.PolicyRevision != policy.Revision) ||
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
		if isPortContractV2(job) {
			if job.CurrentVersion != "" || job.TargetVersion != "" || job.Version != "" ||
				job.PolicyRevision != port.Before.ProjectionRevision ||
				!portClaimPolicyMatches(job, policy, target) {
				return errors.New("pull_v2 port claim does not match its original snapshot and policy")
			}
			return nil
		}
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
		!sameRecoveredJobLease(active, recovered) ||
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

// ClaimHost validates the complete fresh lease and authorization before this
// comparison. Only a v2 port recovery may replace its transport identity; the
// caller still compares every immutable job and port-intent field separately.
func sameRecoveredJobLease(active, recovered UpdateJob) bool {
	if active.ProtocolVersion != 2 || recovered.ProtocolVersion != 2 ||
		!isPortContractV2(active) || !isPortContractV2(recovered) {
		return active.CommandID == recovered.CommandID
	}
	if active.LeaseGeneration == recovered.LeaseGeneration {
		return active.CommandID == recovered.CommandID && active.LeaseExpiresAt == recovered.LeaseExpiresAt
	}
	if !recovered.RecoveryRequired || active.LeaseGeneration == 0 || active.LeaseGeneration >= math.MaxInt64 ||
		recovered.LeaseGeneration != active.LeaseGeneration+1 || active.CommandID == recovered.CommandID ||
		!identifierPattern.MatchString(active.CommandID) || !identifierPattern.MatchString(recovered.CommandID) {
		return false
	}
	activeExpiry, activeErr := time.Parse(time.RFC3339Nano, active.LeaseExpiresAt)
	recoveredExpiry, recoveredErr := time.Parse(time.RFC3339Nano, recovered.LeaseExpiresAt)
	return activeErr == nil && recoveredErr == nil && !activeExpiry.IsZero() && !recoveredExpiry.IsZero()
}

func samePortMutationGrantBinding(
	left, right *SystemdPortMutationGrantBinding,
) bool {
	if left != nil && right != nil && (left.PortContractVersion != 0 || right.PortContractVersion != 0) {
		return reflect.DeepEqual(left, right)
	}
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
