package hostruntime

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"
)

const localExecutorClientTimeout = 5 * time.Second
const localExecutorMutationClientTimeout = 30 * time.Minute

type LocalExecutorProbeClient interface {
	Probe(context.Context, string) (LocalExecutorProbe, error)
}

type LocalExecutorMutationFence struct {
	SourcePolicyRevision    int64
	OwnershipEpoch          int64
	OwnershipPolicyRevision int64
	ExecutorPolicyRevision  int64
}

type LocalExecutorMutationClient interface {
	Stage(context.Context, MutationPlan, LocalExecutorMutationFence) (MutationStageResult, error)
	Apply(context.Context, MutationPlan, LocalExecutorMutationFence, BoundedSecret) (ApplyResult, error)
	Reconcile(context.Context, MutationPlan, LocalExecutorMutationFence, BoundedSecret) (ApplyResult, error)
}

type LocalExecutorPortMutationClient interface {
	PortReconfigure(context.Context, SystemdPortReconfigurePlan, LocalExecutorMutationFence, BoundedSecret) (SystemdPortReconfigureResult, error)
	PortReconfigureReconcile(context.Context, SystemdPortReconfigurePlan, LocalExecutorMutationFence, BoundedSecret) (SystemdPortReconfigureResult, error)
}

type LocalExecutorRuntimeCredentialClient interface {
	RuntimeCredentialStatus(context.Context, string) (RuntimeCredentialStatus, bool, error)
	PrepareRuntimeCredential(context.Context, HostAgentRuntimeTokenRotation) (RuntimeCredentialStatus, error)
	StageRuntimeCredential(context.Context, HostAgentRuntimeTokenRotation, BoundedSecret) (RuntimeCredentialStatus, error)
	MarkRuntimeCredentialProofReady(context.Context, HostAgentRuntimeTokenRotation) (RuntimeCredentialStatus, error)
	ActivateRuntimeCredential(context.Context, HostAgentRuntimeTokenRotation) (RuntimeCredentialStatus, error)
	CancelRuntimeCredential(context.Context, HostAgentRuntimeTokenRotation) (RuntimeCredentialStatus, error)
	FinalizeRuntimeCredential(context.Context, HostAgentRuntimeTokenRotation) (RuntimeCredentialStatus, error)
}

type LocalExecutorClient struct {
	SocketPath      string
	Timeout         time.Duration
	MutationTimeout time.Duration
}

type LocalExecutorClientError struct {
	Code    string
	Message string
}

func (e *LocalExecutorClientError) Error() string {
	code := strings.TrimSpace(e.Code)
	if !validLocalExecutorFailureCode(code) {
		code = "internal_error"
	}
	message := strings.TrimSpace(e.Message)
	if safeExecutorMessage(message) {
		return "local executor request failed: " + code + ": " + message
	}
	return "local executor request failed: " + code
}

func NewLocalExecutorTargetObserver(client LocalExecutorProbeClient) HostTargetObserver {
	return func(ctx context.Context, policy HostAgentPolicy) ([]HostTargetObservation, error) {
		if client == nil {
			return nil, errors.New("local executor client is unavailable")
		}
		observations := make([]HostTargetObservation, 0, len(policy.Targets))
		for _, target := range policy.Targets {
			observation := HostTargetObservation{
				ServiceID:    target.ServiceID,
				Availability: TargetAvailabilityUnknown,
			}
			if policy.LocalExecutorPolicySHA256 == "" {
				observation.AvailabilityCode = "executor_policy_unpinned"
				observations = append(observations, observation)
				continue
			}
			if !digestPattern.MatchString(policy.LocalExecutorPolicySHA256) ||
				policy.LocalExecutorPolicyRevision < 1 ||
				target.appliedConfigRevision() < 1 ||
				!hostAgentTargetHasProbeAuthority(target) {
				observation.AvailabilityCode = "executor_policy_incomplete"
				observations = append(observations, observation)
				continue
			}
			probe, err := client.Probe(ctx, target.ServiceID)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				observation.Availability = TargetAvailabilityUnavailable
				observation.AvailabilityCode = "executor_unavailable"
				observations = append(observations, observation)
				continue
			}
			if err := probe.Validate(); err != nil {
				observation.Availability = TargetAvailabilityUnavailable
				observation.AvailabilityCode = "executor_probe_mismatch"
				observations = append(observations, observation)
				continue
			}
			if probe.PolicyRevision != policy.LocalExecutorPolicyRevision ||
				probe.PolicySHA256 != policy.LocalExecutorPolicySHA256 {
				observation.Availability = TargetAvailabilityUnavailable
				observation.AvailabilityCode = "executor_policy_mismatch"
				observations = append(observations, observation)
				continue
			}
			if probe.ServiceID != target.ServiceID ||
				probe.ServiceType != target.ServiceType ||
				probe.DeploymentMode != target.DeploymentMode ||
				probe.ConfigRevision != target.appliedConfigRevision() ||
				!localExecutorConfigDigestMatchesTarget(
					policy, target, probe.ConfigSHA256,
				) {
				observation.Availability = TargetAvailabilityUnavailable
				observation.AvailabilityCode = "executor_probe_mismatch"
				observations = append(observations, observation)
				continue
			}
			reportedLocalPort := 0
			if target.DeploymentMode == ModeSystemd {
				if target.LocalListenEndpoint == nil ||
					!localExecutorListenerMatchesEndpoint(
						probe.ListenerAddress, *target.LocalListenEndpoint,
					) {
					observation.Availability = TargetAvailabilityUnavailable
					observation.AvailabilityCode = "executor_probe_mismatch"
					observations = append(observations, observation)
					continue
				}
				reportedLocalPort = target.LocalListenEndpoint.Port
			} else if probe.Docker == nil ||
				!localExecutorListenerMatchesPort(
					probe.ListenerAddress, probe.Docker.HealthPort,
				) {
				observation.Availability = TargetAvailabilityUnavailable
				observation.AvailabilityCode = "executor_probe_mismatch"
				observations = append(observations, observation)
				continue
			} else {
				reportedLocalPort = probe.Docker.HealthPort
			}
			observation.Availability = TargetAvailabilityAvailable
			observation.AvailabilityCode = "executor_verified"
			observation.ReportedPort = reportedLocalPort
			observation.ReportedServiceType = probe.ServiceType
			observation.ReportedDeploymentMode = probe.DeploymentMode
			observation.PolicyRevision = probe.PolicyRevision
			observation.PolicySHA256 = probe.PolicySHA256
			observation.ConfigRevision = probe.ConfigRevision
			observation.ConfigSHA256 = probe.ConfigSHA256
			if probe.Docker != nil {
				if target.DeploymentMode != ModeDocker ||
					target.AppliedEndpoint == nil ||
					target.AppliedEndpoint.Port < 1 ||
					target.AppliedEndpoint.Port > 65535 ||
					probe.Docker.HealthPort != reportedLocalPort {
					observation.Availability = TargetAvailabilityUnavailable
					observation.AvailabilityCode = "executor_probe_mismatch"
					observations = append(observations, observation)
					continue
				}
				observation.Docker = &HostDockerPortObservation{
					CapabilityVersion:   probe.Docker.CapabilityVersion,
					AdvertisedPort:      target.AppliedEndpoint.Port,
					PublishedPort:       probe.Docker.PublishedPort,
					ContainerPort:       probe.Docker.ContainerPort,
					HealthPort:          probe.Docker.HealthPort,
					ComposePolicySHA256: probe.Docker.ComposePolicySHA256,
					ComposeRevision:     probe.Docker.ComposeRevision,
					VersionEnvSHA256:    probe.Docker.VersionEnvSHA256,
					ContainerID:         probe.Docker.ContainerID,
					ImageID:             probe.Docker.ImageID,
					RepositoryDigest:    probe.Docker.RepositoryDigest,
				}
			}
			observations = append(observations, observation)
		}
		return observations, nil
	}
}

func localExecutorConfigDigestMatchesTarget(
	policy HostAgentPolicy,
	target HostAgentPolicyTarget,
	reportedDigest string,
) bool {
	if !digestPattern.MatchString(reportedDigest) {
		return false
	}
	if target.AppliedConfigSHA256 != "" {
		return digestPattern.MatchString(target.AppliedConfigSHA256) &&
			reportedDigest == target.AppliedConfigSHA256
	}
	return policy.TransportMode == HostTransportPullV2 &&
		policy.ObserveOnly &&
		policy.OwnershipEpoch == 0 &&
		target.DeploymentMode == ModeSystemd
}

func hostAgentTargetHasProbeAuthority(target HostAgentPolicyTarget) bool {
	switch target.DeploymentMode {
	case ModeSystemd:
		return target.LocalListenEndpoint != nil &&
			validLocalExecutorLoopback(target.LocalListenEndpoint.Host) &&
			target.LocalListenEndpoint.Port >= 1024 &&
			target.LocalListenEndpoint.Port <= 65535
	case ModeDocker:
		return digestPattern.MatchString(target.AppliedConfigSHA256) &&
			target.AppliedEndpoint != nil &&
			target.AppliedEndpoint.Port >= 1 &&
			target.AppliedEndpoint.Port <= 65535
	default:
		return false
	}
}

func localExecutorListenerMatchesEndpoint(listener string, expected HostAgentEndpoint) bool {
	address, err := netip.ParseAddrPort(listener)
	if err != nil || !address.Addr().IsLoopback() {
		return false
	}
	expectedAddress, err := netip.ParseAddr(expected.Host)
	if err != nil || !expectedAddress.IsLoopback() || expected.Port < 1024 || expected.Port > 65535 {
		return false
	}
	return address.Addr() == expectedAddress && int(address.Port()) == expected.Port
}

func localExecutorListenerMatchesPort(listener string, expectedPort int) bool {
	address, err := netip.ParseAddrPort(listener)
	return err == nil &&
		address.Addr().IsLoopback() &&
		expectedPort >= 1024 &&
		expectedPort <= 65535 &&
		int(address.Port()) == expectedPort
}
