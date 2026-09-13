package hostruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/example/autostream-contracts/pkg/contracts"
	"math"
	"strings"
)

const (
	systemdPortPlanSchemaVersion = 1

	systemdPortLedgerStaged         = "staged"
	systemdPortLedgerGrantConsuming = "grant_consuming"
	systemdPortLedgerGrantConsumed  = "grant_consumed"
	systemdPortLedgerSidecarWritten = "sidecar_written"
	systemdPortLedgerRestarted      = "restarted"
	systemdPortLedgerAmbiguous      = "ambiguous"
	systemdPortLedgerCommitting     = "committing"
	systemdPortLedgerTerminal       = "terminal"
	systemdPortNetworkNamespaceHost = "host"
	systemdPortProtocolTCP          = "tcp"
	systemdPortResultApplied        = "applied"
	systemdPortResultRolledBack     = "rolled_back"
	systemdPortResultUnchanged      = "unchanged"
	systemdPortResultRollbackFailed = "rollback_failed"
)

var errSystemdPortSimulatedCrash = errors.New("simulated systemd port transaction crash")

// SystemdPortReconfigurePlan is a server-derived, secret-free description of
// one direct-systemd port change. It intentionally contains no path, unit,
// environment-variable name, command, URL, image, or caller-selected host
// address. Those privileged values are resolved from the root policy and the
// fixed service adapter.
type SystemdPortReconfigurePlan struct {
	PortContractVersion            int                                       `json:"port_contract_version,omitempty"`
	Mode                           contracts.SystemUpdatePortMode            `json:"mode,omitempty"`
	Before                         *contracts.SystemUpdatePortSnapshotRef    `json:"before,omitempty"`
	Target                         *contracts.SystemUpdatePortSnapshotRef    `json:"target,omitempty"`
	Rollback                       *contracts.SystemUpdatePortSnapshotRef    `json:"rollback,omitempty"`
	DockerBaseline                 *contracts.SystemUpdatePortDockerBaseline `json:"docker_baseline,omitempty"`
	PortIntentSHA256               string                                    `json:"port_intent_sha256,omitempty"`
	DeploymentMode                 string                                    `json:"deployment_mode,omitempty"`
	JobID                          string                                    `json:"job_id"`
	HostID                         string                                    `json:"host_id"`
	TargetID                       string                                    `json:"target_id"`
	ServiceType                    string                                    `json:"service_type"`
	NetworkNamespace               string                                    `json:"network_namespace"`
	Protocol                       string                                    `json:"protocol"`
	OldPort                        int                                       `json:"old_port,omitempty"`
	NewPort                        int                                       `json:"new_port,omitempty"`
	ExpectedEndpointRevision       int64                                     `json:"expected_endpoint_revision,omitempty"`
	TargetEndpointRevision         int64                                     `json:"target_endpoint_revision,omitempty"`
	ExpectedConfigRevision         int64                                     `json:"expected_config_revision,omitempty"`
	TargetConfigRevision           int64                                     `json:"target_config_revision,omitempty"`
	ExpectedConfigSHA256           string                                    `json:"expected_config_sha256,omitempty"`
	TargetConfigSHA256             string                                    `json:"target_config_sha256,omitempty"`
	ExpectedSourcePolicyRevision   int64                                     `json:"expected_source_policy_revision,omitempty"`
	ExpectedUpdaterPolicyRevision  int64                                     `json:"expected_updater_policy_revision,omitempty"`
	ExpectedExecutorPolicyRevision int64                                     `json:"expected_executor_policy_revision,omitempty"`
	ExpectedExecutorPolicySHA256   string                                    `json:"expected_executor_policy_sha256,omitempty"`
	OwnershipEpoch                 int64                                     `json:"ownership_epoch"`
	LeaseGeneration                uint64                                    `json:"lease_generation"`
	SessionID                      string                                    `json:"session_id"`
	PortPlanSHA256                 string                                    `json:"port_plan_sha256"`
	Docker                         *DockerPortMutationGrantBinding           `json:"docker,omitempty"`
}

func (p SystemdPortReconfigurePlan) Validate() error {
	if p.PortContractVersion != 0 {
		return p.validatePortV2()
	}
	if p.Before != nil || p.Target != nil || p.Rollback != nil || p.DockerBaseline != nil || p.Mode != "" || p.PortIntentSHA256 != "" {
		return errors.New("legacy port plan contains versioned fields")
	}
	if !identifierPattern.MatchString(p.JobID) ||
		!validExecutionHostID(p.HostID) ||
		!identifierPattern.MatchString(p.TargetID) ||
		!validSystemdPortServiceType(p.ServiceType) {
		return errors.New("systemd port plan identity is invalid")
	}
	if p.NetworkNamespace != systemdPortNetworkNamespaceHost ||
		p.Protocol != systemdPortProtocolTCP {
		return errors.New("systemd port plan network binding is invalid")
	}
	if p.OldPort < 1 || p.OldPort > 65535 ||
		p.NewPort < 1 || p.NewPort > 65535 {
		return errors.New("systemd port plan port range is invalid")
	}
	if p.ExpectedEndpointRevision < 1 ||
		p.ExpectedEndpointRevision >= math.MaxInt64-1 ||
		p.TargetEndpointRevision != p.ExpectedEndpointRevision+1 ||
		p.ExpectedConfigRevision < 1 ||
		p.TargetConfigRevision != p.ExpectedConfigRevision+1 {
		return errors.New("systemd port plan revision transition is invalid")
	}
	if !digestPattern.MatchString(p.ExpectedConfigSHA256) ||
		!digestPattern.MatchString(p.TargetConfigSHA256) ||
		p.ExpectedConfigSHA256 == p.TargetConfigSHA256 {
		return errors.New("systemd port plan config digest is invalid")
	}
	if p.ExpectedSourcePolicyRevision < 1 ||
		p.ExpectedUpdaterPolicyRevision < 1 ||
		p.ExpectedExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(p.ExpectedExecutorPolicySHA256) ||
		p.OwnershipEpoch < 1 ||
		p.LeaseGeneration == 0 {
		return errors.New("systemd port plan policy fence is invalid")
	}
	if !mutationSessionPattern.MatchString(p.SessionID) ||
		!mutationPlanHashPattern.MatchString(p.PortPlanSHA256) {
		return errors.New("systemd port plan authorization binding is invalid")
	}
	switch p.effectiveDeploymentMode() {
	case ModeSystemd:
		if p.Docker != nil ||
			!validSystemdPort(p.OldPort) ||
			!validSystemdPort(p.NewPort) ||
			p.OldPort == p.NewPort {
			return errors.New("systemd port plan contains Docker-only fields")
		}
	case ModeDocker:
		if p.DeploymentMode != ModeDocker ||
			p.Docker.validate(p.ExpectedExecutorPolicyRevision) != nil {
			return errors.New("Docker port plan runtime baseline is invalid")
		}
		if p.OldPort == p.NewPort &&
			p.Docker.OldPublishedPort == p.Docker.NewPublishedPort &&
			p.Docker.OldContainerPort == p.Docker.NewContainerPort {
			return errors.New("Docker port plan is a no-op")
		}
	default:
		return errors.New("port plan deployment mode is invalid")
	}
	computed, err := p.ComputePortPlanSHA256()
	if err != nil || computed != p.PortPlanSHA256 {
		return errors.New("systemd port plan digest does not match its immutable fields")
	}
	return nil
}

func (p SystemdPortReconfigurePlan) effectiveDeploymentMode() string {
	if strings.TrimSpace(p.DeploymentMode) == "" && p.Docker == nil {
		return ModeSystemd
	}
	return strings.TrimSpace(p.DeploymentMode)
}

func (p SystemdPortReconfigurePlan) ComputePortPlanSHA256() (string, error) {
	if p.PortContractVersion == 2 {
		return contracts.ComputeSystemUpdatePortRuntimePlanSHA256(p.SharedPortPlan(), p.JobID, p.HostID, p.TargetID, p.ServiceType, p.OwnershipEpoch, p.LeaseGeneration, p.SessionID)
	}
	if !identifierPattern.MatchString(p.JobID) ||
		!validExecutionHostID(p.HostID) ||
		!identifierPattern.MatchString(p.TargetID) ||
		!validSystemdPortServiceType(p.ServiceType) ||
		p.NetworkNamespace != systemdPortNetworkNamespaceHost ||
		p.Protocol != systemdPortProtocolTCP ||
		p.OldPort < 1 || p.OldPort > 65535 ||
		p.NewPort < 1 || p.NewPort > 65535 ||
		p.ExpectedEndpointRevision < 1 ||
		p.ExpectedEndpointRevision >= math.MaxInt64-1 ||
		p.TargetEndpointRevision != p.ExpectedEndpointRevision+1 ||
		p.ExpectedConfigRevision < 1 ||
		p.TargetConfigRevision != p.ExpectedConfigRevision+1 ||
		!digestPattern.MatchString(p.ExpectedConfigSHA256) ||
		!digestPattern.MatchString(p.TargetConfigSHA256) ||
		p.ExpectedSourcePolicyRevision < 1 ||
		p.ExpectedUpdaterPolicyRevision < 1 ||
		p.ExpectedExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(p.ExpectedExecutorPolicySHA256) ||
		p.OwnershipEpoch < 1 ||
		p.LeaseGeneration == 0 ||
		!mutationSessionPattern.MatchString(p.SessionID) {
		return "", errors.New("systemd port plan is incomplete")
	}
	if p.effectiveDeploymentMode() == ModeDocker {
		if p.DeploymentMode != ModeDocker ||
			p.Docker.validate(p.ExpectedExecutorPolicyRevision) != nil {
			return "", errors.New("Docker port plan is incomplete")
		}
		if p.OldPort == p.NewPort &&
			p.Docker.OldPublishedPort == p.Docker.NewPublishedPort &&
			p.Docker.OldContainerPort == p.Docker.NewContainerPort {
			return "", errors.New("Docker port plan is a no-op")
		}
		docker := p.Docker
		payload := struct {
			SchemaVersion                  int    `json:"schema_version"`
			JobID                          string `json:"job_id"`
			HostID                         string `json:"host_id"`
			TargetID                       string `json:"target_id"`
			ServiceType                    string `json:"service_type"`
			NetworkNamespace               string `json:"network_namespace"`
			Protocol                       string `json:"protocol"`
			OldAdvertisedPort              int    `json:"old_advertised_port"`
			NewAdvertisedPort              int    `json:"new_advertised_port"`
			PublishedHostIP                string `json:"published_host_ip"`
			OldPublishedPort               int    `json:"old_published_port"`
			NewPublishedPort               int    `json:"new_published_port"`
			OldContainerPort               int    `json:"old_container_port"`
			NewContainerPort               int    `json:"new_container_port"`
			OldHealthPort                  int    `json:"old_health_port"`
			NewHealthPort                  int    `json:"new_health_port"`
			ExpectedEndpointRevision       int64  `json:"expected_endpoint_revision"`
			TargetEndpointRevision         int64  `json:"target_endpoint_revision"`
			ExpectedConfigRevision         int64  `json:"expected_config_revision"`
			TargetConfigRevision           int64  `json:"target_config_revision"`
			ExpectedConfigSHA256           string `json:"expected_config_sha256"`
			TargetConfigSHA256             string `json:"target_config_sha256"`
			ApprovedComposeConfigSHA256    string `json:"approved_compose_config_sha256"`
			ApprovedComposeRevision        int64  `json:"approved_compose_revision"`
			ExpectedVersionEnvSHA256       string `json:"expected_version_env_sha256"`
			ExpectedContainerID            string `json:"expected_container_id"`
			ExpectedImageID                string `json:"expected_image_id"`
			ExpectedRepositoryDigest       string `json:"expected_repository_digest"`
			ExpectedSourcePolicyRevision   int64  `json:"expected_source_policy_revision"`
			ExpectedUpdaterPolicyRevision  int64  `json:"expected_updater_policy_revision"`
			ExpectedExecutorPolicyRevision int64  `json:"expected_executor_policy_revision"`
			ExpectedExecutorPolicySHA256   string `json:"expected_executor_policy_sha256"`
			OwnershipEpoch                 int64  `json:"ownership_epoch"`
			LeaseGeneration                uint64 `json:"lease_generation"`
			SessionID                      string `json:"session_id"`
		}{
			SchemaVersion: 2,
			JobID:         p.JobID, HostID: p.HostID, TargetID: p.TargetID,
			ServiceType: p.ServiceType, NetworkNamespace: p.NetworkNamespace,
			Protocol: p.Protocol, OldAdvertisedPort: p.OldPort,
			NewAdvertisedPort: p.NewPort, PublishedHostIP: docker.PublishedHostIP,
			OldPublishedPort: docker.OldPublishedPort,
			NewPublishedPort: docker.NewPublishedPort,
			OldContainerPort: docker.OldContainerPort,
			NewContainerPort: docker.NewContainerPort,
			OldHealthPort:    docker.OldHealthPort, NewHealthPort: docker.NewHealthPort,
			ExpectedEndpointRevision:       p.ExpectedEndpointRevision,
			TargetEndpointRevision:         p.TargetEndpointRevision,
			ExpectedConfigRevision:         p.ExpectedConfigRevision,
			TargetConfigRevision:           p.TargetConfigRevision,
			ExpectedConfigSHA256:           p.ExpectedConfigSHA256,
			TargetConfigSHA256:             p.TargetConfigSHA256,
			ApprovedComposeConfigSHA256:    docker.ApprovedComposeConfigSHA256,
			ApprovedComposeRevision:        docker.ApprovedComposeRevision,
			ExpectedVersionEnvSHA256:       docker.ExpectedVersionEnvSHA256,
			ExpectedContainerID:            docker.ExpectedContainerID,
			ExpectedImageID:                docker.ExpectedImageID,
			ExpectedRepositoryDigest:       docker.ExpectedRepositoryDigest,
			ExpectedSourcePolicyRevision:   p.ExpectedSourcePolicyRevision,
			ExpectedUpdaterPolicyRevision:  p.ExpectedUpdaterPolicyRevision,
			ExpectedExecutorPolicyRevision: p.ExpectedExecutorPolicyRevision,
			ExpectedExecutorPolicySHA256:   p.ExpectedExecutorPolicySHA256,
			OwnershipEpoch:                 p.OwnershipEpoch, LeaseGeneration: p.LeaseGeneration,
			SessionID: p.SessionID,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(encoded)
		return hex.EncodeToString(digest[:]), nil
	}
	if p.effectiveDeploymentMode() != ModeSystemd ||
		p.Docker != nil ||
		!validSystemdPort(p.OldPort) ||
		!validSystemdPort(p.NewPort) ||
		p.OldPort == p.NewPort {
		return "", errors.New("systemd port plan deployment mode is invalid")
	}
	payload := struct {
		SchemaVersion                  int    `json:"schema_version"`
		JobID                          string `json:"job_id"`
		HostID                         string `json:"host_id"`
		TargetID                       string `json:"target_id"`
		ServiceType                    string `json:"service_type"`
		NetworkNamespace               string `json:"network_namespace"`
		Protocol                       string `json:"protocol"`
		OldPort                        int    `json:"old_port"`
		NewPort                        int    `json:"new_port"`
		ExpectedEndpointRevision       int64  `json:"expected_endpoint_revision"`
		TargetEndpointRevision         int64  `json:"target_endpoint_revision"`
		ExpectedConfigRevision         int64  `json:"expected_config_revision"`
		TargetConfigRevision           int64  `json:"target_config_revision"`
		ExpectedConfigSHA256           string `json:"expected_config_sha256"`
		TargetConfigSHA256             string `json:"target_config_sha256"`
		ExpectedSourcePolicyRevision   int64  `json:"expected_source_policy_revision"`
		ExpectedUpdaterPolicyRevision  int64  `json:"expected_updater_policy_revision"`
		ExpectedExecutorPolicyRevision int64  `json:"expected_executor_policy_revision"`
		ExpectedExecutorPolicySHA256   string `json:"expected_executor_policy_sha256"`
		OwnershipEpoch                 int64  `json:"ownership_epoch"`
		LeaseGeneration                uint64 `json:"lease_generation"`
		SessionID                      string `json:"session_id"`
	}{
		SchemaVersion: systemdPortPlanSchemaVersion,
		JobID:         p.JobID, HostID: p.HostID, TargetID: p.TargetID,
		ServiceType: p.ServiceType, NetworkNamespace: p.NetworkNamespace,
		Protocol: p.Protocol, OldPort: p.OldPort, NewPort: p.NewPort,
		ExpectedEndpointRevision:       p.ExpectedEndpointRevision,
		TargetEndpointRevision:         p.TargetEndpointRevision,
		ExpectedConfigRevision:         p.ExpectedConfigRevision,
		TargetConfigRevision:           p.TargetConfigRevision,
		ExpectedConfigSHA256:           p.ExpectedConfigSHA256,
		TargetConfigSHA256:             p.TargetConfigSHA256,
		ExpectedSourcePolicyRevision:   p.ExpectedSourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  p.ExpectedUpdaterPolicyRevision,
		ExpectedExecutorPolicyRevision: p.ExpectedExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   p.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:                 p.OwnershipEpoch, LeaseGeneration: p.LeaseGeneration,
		SessionID: p.SessionID,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
