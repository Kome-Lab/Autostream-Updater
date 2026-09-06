package hostruntime

import (
	"sort"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

// Baseline metadata is derived from verified root probes. Neither a desired
// policy candidate nor an Agent version string is evidence of root support.
func portPolicyBaseline(policy HostAgentPolicy, observations []HostTargetObservation) *contracts.UpdaterPortPolicyBaseline {
	if len(policy.Targets) == 0 || len(observations) != len(policy.Targets) {
		return nil
	}
	baseline := &contracts.UpdaterPortPolicyBaseline{PortContractVersion: 2, PolicyTransitionVersion: 1}
	seen := map[string]bool{}
	for _, observation := range observations {
		target, ok := hostPullPolicyTarget(policy, observation.ServiceID)
		if !ok || seen[target.ServiceID] || observation.Availability != TargetAvailabilityAvailable ||
			observation.PortContractVersion != 2 || observation.PolicyTransitionVersion != 1 ||
			observation.SourcePolicyRevision != policy.SourcePolicyRevision || observation.ProjectionRevision != policy.Revision ||
			observation.PolicyRevision != policy.LocalExecutorPolicyRevision || observation.PolicySHA256 != policy.LocalExecutorPolicySHA256 ||
			observation.ReportedServiceType != target.ServiceType || observation.ReportedDeploymentMode != target.DeploymentMode ||
			observation.EndpointRevision != target.AppliedEndpointRevision ||
			observation.ConfigRevision != target.AppliedConfigRevision || observation.ConfigSHA256 != target.AppliedConfigSHA256 ||
			observation.AgentUID == 0 || observation.AgentGID == 0 || observation.ObservedAt.IsZero() {
			return nil
		}
		seen[target.ServiceID] = true
		if len(baseline.Targets) == 0 {
			baseline.AgentUID, baseline.AgentGID = observation.AgentUID, observation.AgentGID
			baseline.SourcePolicyRevision, baseline.ProjectionRevision = observation.SourcePolicyRevision, observation.ProjectionRevision
			baseline.ExecutorPolicyRevision, baseline.ExecutorPolicySHA256 = observation.PolicyRevision, observation.PolicySHA256
			baseline.ObservedAt = observation.ObservedAt
		} else if baseline.AgentUID != observation.AgentUID || baseline.AgentGID != observation.AgentGID {
			return nil
		}
		if observation.ObservedAt.Before(baseline.ObservedAt) {
			baseline.ObservedAt = observation.ObservedAt
		}
		item := contracts.UpdaterPortPolicyBaselineTarget{
			ServiceID: target.ServiceID, ServiceType: contracts.SystemUpdateTargetType(target.ServiceType),
			DeploymentMode:   contracts.SystemUpdateDeploymentMode(target.DeploymentMode),
			EndpointRevision: observation.EndpointRevision, ConfigRevision: observation.ConfigRevision,
			ConfigSHA256: observation.ConfigSHA256, LocalListenPort: observation.ReportedPort,
		}
		if observation.Docker != nil {
			docker := observation.Docker
			if observation.DockerRoot == nil {
				return nil
			}
			root := *observation.DockerRoot
			item.DockerRoot = &root
			item.Docker = &contracts.SystemUpdatePortDockerSnapshot{
				PublishedHostIP: "127.0.0.1", PublishedPort: docker.PublishedPort, ContainerPort: docker.ContainerPort,
				HealthPort: docker.HealthPort, ComposePolicySHA256: normalizeDigest(docker.ComposePolicySHA256),
				ComposeRevision: docker.ComposeRevision, VersionEnvSHA256: docker.VersionEnvSHA256,
				ImageID: docker.ImageID, RepositoryDigest: docker.RepositoryDigest,
			}
			item.LocalListenPort = docker.PublishedPort
		}
		baseline.Targets = append(baseline.Targets, item)
	}
	sort.Slice(baseline.Targets, func(i, j int) bool { return baseline.Targets[i].ServiceID < baseline.Targets[j].ServiceID })
	if contracts.ValidateUpdaterPortPolicyBaseline(*baseline) != nil {
		return nil
	}
	return baseline
}
