package hostruntime

import (
	"context"
	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
	"runtime"
	"strings"
)

func (a *HostPullAgent) observe(ctx context.Context, policy HostAgentPolicy) ([]HostTargetObservation, bool) {
	if effective, err := a.portRecoveryPolicy(policy); err != nil {
		return nil, true
	} else {
		policy = effective
	}
	if a.ObserveTargets == nil {
		observations := make([]HostTargetObservation, 0, len(policy.Targets))
		for _, target := range policy.Targets {
			observations = append(observations, HostTargetObservation{
				ServiceID: target.ServiceID, Availability: TargetAvailabilityUnknown,
			})
		}
		return observations, false
	}
	observations, err := a.ObserveTargets(ctx, policy)
	if err != nil {
		if ctx.Err() == nil {
			a.Logf("host pull agent target observation failed")
		}
		return nil, true
	}
	allowedTargets := make(map[string]struct{}, len(policy.Targets))
	for _, target := range policy.Targets {
		allowedTargets[target.ServiceID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(observations))
	filtered := make([]HostTargetObservation, 0, len(observations))
	for _, observation := range observations {
		observation.ServiceID = strings.TrimSpace(observation.ServiceID)
		if _, allowed := allowedTargets[observation.ServiceID]; !allowed {
			continue
		}
		if _, duplicate := seen[observation.ServiceID]; duplicate {
			continue
		}
		switch observation.Availability {
		case TargetAvailabilityAvailable, TargetAvailabilityUnavailable, TargetAvailabilityUnknown:
		default:
			observation.Availability = TargetAvailabilityUnknown
		}
		if observation.ReportedPort < 0 || observation.ReportedPort > 65535 {
			observation.ReportedPort = 0
		}
		if observation.ReportedServiceType != "" && !validLocalExecutorServiceType(observation.ReportedServiceType) {
			observation.ReportedServiceType = ""
		}
		if observation.ReportedDeploymentMode != "" &&
			observation.ReportedDeploymentMode != ModeSystemd &&
			observation.ReportedDeploymentMode != ModeDocker {
			observation.ReportedDeploymentMode = ""
		}
		if observation.PolicyRevision < 0 {
			observation.PolicyRevision = 0
		}
		if observation.PolicySHA256 != "" && !digestPattern.MatchString(observation.PolicySHA256) {
			observation.PolicySHA256 = ""
		}
		if observation.ConfigRevision < 0 {
			observation.ConfigRevision = 0
		}
		if observation.ConfigSHA256 != "" && !digestPattern.MatchString(observation.ConfigSHA256) {
			observation.ConfigSHA256 = ""
		}
		if observation.Docker != nil &&
			!validHostDockerPortObservation(*observation.Docker) {
			observation.Docker = nil
		}
		if !identifierPattern.MatchString(strings.TrimSpace(observation.AvailabilityCode)) {
			observation.AvailabilityCode = ""
		}
		seen[observation.ServiceID] = struct{}{}
		filtered = append(filtered, observation)
	}
	return filtered, false
}

func (a *HostPullAgent) capabilities(binding HostAgentBinding, policy *HostAgentPolicy, observations []HostTargetObservation, observationFailed bool) map[string]any {
	if policy != nil {
		if effective, err := a.portRecoveryPolicy(*policy); err == nil {
			policy = &effective
		} else {
			observationFailed = true
		}
	}
	executorReady := a.executorReady(policy, observations, observationFailed)
	mutationReady := a.mutationCapabilityReady(
		binding, policy, observations, observationFailed,
	)
	hostCapabilities := []string{
		"outbound_control",
		"policy_refresh",
		"target_availability",
		"port_drift",
	}
	if executorReady {
		hostCapabilities = append(hostCapabilities, "software_update_v1", "durable_reconcile_v1")
	}
	capabilities := map[string]any{
		"host_agent":                true,
		"observe_only":              !mutationReady,
		"update_executor":           executorReady,
		"mutation_enabled":          mutationReady,
		"transport_mode":            HostTransportPullV2,
		"agent_version":             a.currentAgentVersion(),
		"agent_protocol_version":    HostAgentProtocolVersion,
		"host_capabilities":         hostCapabilities,
		"os":                        runtime.GOOS,
		"arch":                      runtime.GOARCH,
		"executor_version":          controlversion.Current(),
		"executor_protocol_version": LocalExecutorMutationProtocolVersion,
		"mutation_protocol_version": LocalExecutorMutationProtocolVersion,
		"recovery_protocol_version": HostSelfUpdateRecoveryProtocolVersion,
	}
	if !observationFailed && policy != nil {
		if baseline := portPolicyBaseline(*policy, observations); baseline != nil {
			capabilities["port_contract_version"] = baseline.PortContractVersion
			capabilities["policy_transition_version"] = baseline.PolicyTransitionVersion
			capabilities["port_policy_baseline"] = baseline
		}
	}
	if a.Journal != nil && a.Journal.Active() != nil {
		capabilities["recovery_pending"] = true
	} else {
		capabilities["recovery_pending"] = false
	}
	if selfUpdate := a.selfUpdateStatus.Load(); selfUpdate != nil {
		capabilities["self_update_phase"] = selfUpdate.State.Phase
		capabilities["self_update_active_agent_version"] = selfUpdate.State.ActiveAgentVersion
		capabilities["self_update_active_executor_version"] = selfUpdate.State.ActiveExecutorVersion
		capabilities["self_update_pending_generation"] = selfUpdate.State.PendingGeneration
		capabilities["self_update_failed_generation"] = selfUpdate.State.FailedGeneration
		capabilities["self_update_current_slot"] = selfUpdate.CurrentSlot
		capabilities["executor_version"] = selfUpdate.ExecutorVersion
		capabilities["executor_protocol_version"] = selfUpdate.ExecutorProtocolVersion
		capabilities["self_update_ready"] = selfUpdate.State.Phase == HostSelfUpdatePhaseStable
	}
	if a.rotationRunning.Load() {
		capabilities["runtime_token_rotation_phase"] = "reconciling"
	}
	if policy != nil && policy.SelfUpdate != nil &&
		controlversion.Current() == policy.SelfUpdate.AgentVersion {
		capabilities["self_update_heartbeat_generation"] = policy.SelfUpdate.Generation
	}
	if binding.ExecutionHostID != "" {
		capabilities["execution_host_id"] = binding.ExecutionHostID
		capabilities["ownership_epoch"] = binding.OwnershipEpoch
	}
	if policy == nil {
		capabilities["policy_revision"] = int64(0)
		capabilities["source_policy_revision"] = int64(0)
		capabilities["local_executor_policy_revision"] = int64(0)
		capabilities["target_availability"] = map[string]string{}
		capabilities["target_availability_codes"] = map[string]string{}
		capabilities["reported_ports"] = map[string]int{}
		capabilities["port_drift"] = map[string]bool{}
		capabilities["reported_service_types"] = map[string]string{}
		capabilities["reported_deployment_modes"] = map[string]string{}
		capabilities["reported_executor_policy_revisions"] = map[string]int64{}
		capabilities["reported_executor_policy_sha256"] = map[string]string{}
		capabilities["reported_config_revisions"] = map[string]int64{}
		capabilities["reported_config_sha256"] = map[string]string{}
		capabilities["reported_docker_port_capabilities"] = map[string]string{}
		capabilities["reported_docker_published_ports"] = map[string]int{}
		capabilities["reported_docker_container_ports"] = map[string]int{}
		capabilities["reported_docker_health_ports"] = map[string]int{}
		capabilities["reported_docker_compose_sha256"] = map[string]string{}
		capabilities["reported_docker_compose_config_sha256"] = map[string]string{}
		capabilities["reported_docker_compose_revisions"] = map[string]int64{}
		capabilities["reported_docker_version_env_sha256"] = map[string]string{}
		capabilities["reported_docker_container_ids"] = map[string]string{}
		capabilities["reported_docker_image_ids"] = map[string]string{}
		capabilities["reported_docker_repository_digests"] = map[string]string{}
		a.addRuntimeTokenRotationCapabilities(capabilities)
		return capabilities
	}
	capabilities["policy_revision"] = policy.Revision
	capabilities["source_policy_revision"] = policy.SourcePolicyRevision
	capabilities["local_executor_policy_revision"] = policy.LocalExecutorPolicyRevision
	capabilities["policy_status"] = PolicyStatusApplied
	availability := make(map[string]string, len(policy.Targets))
	availabilityCodes := make(map[string]string, len(policy.Targets))
	reportedPorts := make(map[string]int, len(policy.Targets))
	portDrift := make(map[string]bool, len(policy.Targets))
	reportedServiceTypes := make(map[string]string, len(policy.Targets))
	reportedDeploymentModes := make(map[string]string, len(policy.Targets))
	reportedPolicyRevisions := make(map[string]int64, len(policy.Targets))
	reportedPolicyDigests := make(map[string]string, len(policy.Targets))
	reportedConfigRevisions := make(map[string]int64, len(policy.Targets))
	reportedConfigDigests := make(map[string]string, len(policy.Targets))
	reportedDockerCapabilities := make(map[string]string, len(policy.Targets))
	reportedDockerPublishedPorts := make(map[string]int, len(policy.Targets))
	reportedDockerContainerPorts := make(map[string]int, len(policy.Targets))
	reportedDockerHealthPorts := make(map[string]int, len(policy.Targets))
	reportedDockerComposeDigests := make(map[string]string, len(policy.Targets))
	reportedDockerComposeConfigDigests := make(map[string]string, len(policy.Targets))
	reportedDockerComposeRevisions := make(map[string]int64, len(policy.Targets))
	reportedDockerVersionEnvDigests := make(map[string]string, len(policy.Targets))
	reportedDockerContainerIDs := make(map[string]string, len(policy.Targets))
	reportedDockerImageIDs := make(map[string]string, len(policy.Targets))
	reportedDockerRepositoryDigests := make(map[string]string, len(policy.Targets))
	observed := make(map[string]HostTargetObservation, len(observations))
	for _, observation := range observations {
		observed[observation.ServiceID] = observation
	}
	for _, target := range policy.Targets {
		observation, exists := observed[target.ServiceID]
		if !exists {
			observation = HostTargetObservation{ServiceID: target.ServiceID, Availability: TargetAvailabilityUnknown}
		}
		if observationFailed {
			observation.Availability = TargetAvailabilityUnknown
			observation.AvailabilityCode = "observation_failed"
			observation.Docker = nil
		}
		availability[target.ServiceID] = observation.Availability
		if observation.AvailabilityCode != "" {
			availabilityCodes[target.ServiceID] = observation.AvailabilityCode
		}
		if observation.Docker != nil {
			reportedPorts[target.ServiceID] = observation.Docker.AdvertisedPort
			reportedDockerCapabilities[target.ServiceID] = observation.Docker.CapabilityVersion
			reportedDockerPublishedPorts[target.ServiceID] = observation.Docker.PublishedPort
			reportedDockerContainerPorts[target.ServiceID] = observation.Docker.ContainerPort
			reportedDockerHealthPorts[target.ServiceID] = observation.Docker.HealthPort
			reportedDockerComposeDigests[target.ServiceID] = observation.Docker.ComposePolicySHA256
			// The resolved runtime model differs from the installed policy profile
			// after a port transition. Publish only a verified available observation.
			if observation.Availability == TargetAvailabilityAvailable && mutationPlanHashPattern.MatchString(observation.Docker.ComposeConfigSHA256) {
				reportedDockerComposeConfigDigests[target.ServiceID] = observation.Docker.ComposeConfigSHA256
			}
			reportedDockerComposeRevisions[target.ServiceID] = observation.Docker.ComposeRevision
			reportedDockerVersionEnvDigests[target.ServiceID] = observation.Docker.VersionEnvSHA256
			reportedDockerContainerIDs[target.ServiceID] = observation.Docker.ContainerID
			reportedDockerImageIDs[target.ServiceID] = observation.Docker.ImageID
			reportedDockerRepositoryDigests[target.ServiceID] = observation.Docker.RepositoryDigest
		} else if observation.ReportedPort > 0 {
			reportedPorts[target.ServiceID] = observation.ReportedPort
		}
		if observation.ReportedServiceType != "" {
			reportedServiceTypes[target.ServiceID] = observation.ReportedServiceType
		}
		if observation.ReportedDeploymentMode != "" {
			reportedDeploymentModes[target.ServiceID] = observation.ReportedDeploymentMode
		}
		if observation.PolicyRevision > 0 {
			reportedPolicyRevisions[target.ServiceID] = observation.PolicyRevision
		}
		if observation.PolicySHA256 != "" {
			reportedPolicyDigests[target.ServiceID] = observation.PolicySHA256
		}
		if observation.ConfigRevision > 0 {
			reportedConfigRevisions[target.ServiceID] = observation.ConfigRevision
		}
		if observation.ConfigSHA256 != "" {
			reportedConfigDigests[target.ServiceID] = observation.ConfigSHA256
		}
		if observation.Docker != nil {
			portDrift[target.ServiceID] = false
		} else if target.LocalListenEndpoint != nil && observation.ReportedPort > 0 {
			portDrift[target.ServiceID] = target.LocalListenEndpoint.Port != observation.ReportedPort
		}
	}
	capabilities["target_availability"] = availability
	capabilities["target_availability_codes"] = availabilityCodes
	capabilities["reported_ports"] = reportedPorts
	capabilities["port_drift"] = portDrift
	capabilities["reported_service_types"] = reportedServiceTypes
	capabilities["reported_deployment_modes"] = reportedDeploymentModes
	capabilities["reported_executor_policy_revisions"] = reportedPolicyRevisions
	capabilities["reported_executor_policy_sha256"] = reportedPolicyDigests
	capabilities["reported_config_revisions"] = reportedConfigRevisions
	capabilities["reported_config_sha256"] = reportedConfigDigests
	capabilities["reported_docker_port_capabilities"] = reportedDockerCapabilities
	capabilities["reported_docker_published_ports"] = reportedDockerPublishedPorts
	capabilities["reported_docker_container_ports"] = reportedDockerContainerPorts
	capabilities["reported_docker_health_ports"] = reportedDockerHealthPorts
	capabilities["reported_docker_compose_sha256"] = reportedDockerComposeDigests
	capabilities["reported_docker_compose_config_sha256"] = reportedDockerComposeConfigDigests
	capabilities["reported_docker_compose_revisions"] = reportedDockerComposeRevisions
	capabilities["reported_docker_version_env_sha256"] = reportedDockerVersionEnvDigests
	capabilities["reported_docker_container_ids"] = reportedDockerContainerIDs
	capabilities["reported_docker_image_ids"] = reportedDockerImageIDs
	capabilities["reported_docker_repository_digests"] = reportedDockerRepositoryDigests
	a.addRuntimeTokenRotationCapabilities(capabilities)
	return capabilities
}

func validHostDockerPortObservation(observation HostDockerPortObservation) bool {
	return observation.CapabilityVersion == dockerPortCapabilityVersion &&
		observation.AdvertisedPort >= 1 &&
		observation.AdvertisedPort <= 65535 &&
		validSystemdPort(observation.PublishedPort) &&
		validSystemdPort(observation.ContainerPort) &&
		observation.HealthPort == observation.PublishedPort &&
		mutationPlanHashPattern.MatchString(observation.ComposePolicySHA256) &&
		observation.ComposeRevision >= 1 &&
		digestPattern.MatchString(observation.VersionEnvSHA256) &&
		len(observation.ContainerID) == 64 &&
		dockerContainerIDPattern.MatchString(observation.ContainerID) &&
		digestPattern.MatchString(observation.ImageID) &&
		digestPattern.MatchString(observation.RepositoryDigest)
}
