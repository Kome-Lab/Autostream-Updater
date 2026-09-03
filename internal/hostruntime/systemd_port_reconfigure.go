package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/example/autostream-contracts/pkg/contracts"
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
	DeploymentMode                 string                          `json:"deployment_mode,omitempty"`
	JobID                          string                          `json:"job_id"`
	HostID                         string                          `json:"host_id"`
	TargetID                       string                          `json:"target_id"`
	ServiceType                    string                          `json:"service_type"`
	NetworkNamespace               string                          `json:"network_namespace"`
	Protocol                       string                          `json:"protocol"`
	OldPort                        int                             `json:"old_port"`
	NewPort                        int                             `json:"new_port"`
	ExpectedEndpointRevision       int64                           `json:"expected_endpoint_revision"`
	TargetEndpointRevision         int64                           `json:"target_endpoint_revision"`
	ExpectedConfigRevision         int64                           `json:"expected_config_revision"`
	TargetConfigRevision           int64                           `json:"target_config_revision"`
	ExpectedConfigSHA256           string                          `json:"expected_config_sha256"`
	TargetConfigSHA256             string                          `json:"target_config_sha256"`
	ExpectedSourcePolicyRevision   int64                           `json:"expected_source_policy_revision"`
	ExpectedUpdaterPolicyRevision  int64                           `json:"expected_updater_policy_revision"`
	ExpectedExecutorPolicyRevision int64                           `json:"expected_executor_policy_revision"`
	ExpectedExecutorPolicySHA256   string                          `json:"expected_executor_policy_sha256"`
	OwnershipEpoch                 int64                           `json:"ownership_epoch"`
	LeaseGeneration                uint64                          `json:"lease_generation"`
	SessionID                      string                          `json:"session_id"`
	PortPlanSHA256                 string                          `json:"port_plan_sha256"`
	Docker                         *DockerPortMutationGrantBinding `json:"docker,omitempty"`
}

func (p SystemdPortReconfigurePlan) Validate() error {
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

type SystemdPortReconfigureResult struct {
	DeploymentMode   string                            `json:"deployment_mode,omitempty"`
	Status           string                            `json:"status"`
	Result           string                            `json:"result"`
	StateKnown       bool                              `json:"state_known"`
	OldPort          int                               `json:"old_port"`
	NewPort          int                               `json:"new_port"`
	AppliedPort      int                               `json:"applied_port"`
	EndpointRevision int64                             `json:"endpoint_revision"`
	ConfigRevision   int64                             `json:"config_revision"`
	ConfigSHA256     string                            `json:"config_sha256"`
	Message          string                            `json:"message"`
	Docker           *DockerPortReconfigureResultState `json:"docker,omitempty"`
}

type DockerPortReconfigureResultState struct {
	AppliedPublishedPort int    `json:"applied_published_port"`
	AppliedContainerPort int    `json:"applied_container_port"`
	AppliedHealthPort    int    `json:"applied_health_port"`
	ComposeConfigSHA256  string `json:"compose_config_sha256"`
}

func (r SystemdPortReconfigureResult) Validate() error {
	mode := strings.TrimSpace(r.DeploymentMode)
	if mode == "" {
		mode = ModeSystemd
	}
	if r.OldPort < 1 || r.OldPort > 65535 ||
		r.NewPort < 1 || r.NewPort > 65535 ||
		!safeExecutorMessage(r.Message) {
		return errors.New("systemd port result is invalid")
	}
	if mode == ModeSystemd {
		if r.Docker != nil ||
			!validSystemdPort(r.OldPort) ||
			!validSystemdPort(r.NewPort) ||
			r.OldPort == r.NewPort {
			return errors.New("systemd port result is invalid")
		}
	} else if mode == ModeDocker {
		if r.DeploymentMode != ModeDocker {
			return errors.New("Docker port result mode is invalid")
		}
		if r.Result == systemdPortResultRollbackFailed {
			if r.Docker != nil {
				return errors.New("unknown Docker port result contains applied mapping")
			}
		} else if r.Docker == nil ||
			!validSystemdPort(r.Docker.AppliedPublishedPort) ||
			!validSystemdPort(r.Docker.AppliedContainerPort) ||
			r.Docker.AppliedHealthPort != r.Docker.AppliedPublishedPort ||
			!mutationPlanHashPattern.MatchString(r.Docker.ComposeConfigSHA256) {
			return errors.New("Docker port result mapping is invalid")
		}
	} else {
		return errors.New("port result deployment mode is invalid")
	}
	switch r.Result {
	case systemdPortResultApplied:
		if r.Status != "succeeded" || !r.StateKnown ||
			r.AppliedPort != r.NewPort ||
			r.EndpointRevision < 1 || r.ConfigRevision < 1 ||
			!digestPattern.MatchString(r.ConfigSHA256) {
			return errors.New("applied systemd port result is invalid")
		}
	case systemdPortResultRolledBack:
		if r.Status != "rolled_back" || !r.StateKnown ||
			r.AppliedPort != r.OldPort ||
			r.EndpointRevision < 1 || r.ConfigRevision < 1 ||
			!digestPattern.MatchString(r.ConfigSHA256) {
			return errors.New("rolled back systemd port result is invalid")
		}
	case systemdPortResultUnchanged:
		if r.Status != "succeeded" || !r.StateKnown ||
			r.AppliedPort != r.OldPort ||
			r.EndpointRevision < 1 || r.ConfigRevision < 1 ||
			!digestPattern.MatchString(r.ConfigSHA256) {
			return errors.New("unchanged systemd port result is invalid")
		}
	case systemdPortResultRollbackFailed:
		if r.Status != "failed" || r.StateKnown ||
			r.AppliedPort != 0 || r.EndpointRevision < 1 ||
			r.ConfigRevision != 0 || r.ConfigSHA256 != "" {
			return errors.New("failed systemd port rollback result is invalid")
		}
	default:
		return errors.New("systemd port result kind is invalid")
	}
	return nil
}

type systemdPortAdapter struct {
	Unit        string
	SidecarPath string
	ServiceType string
}

func systemdPortAdapterFor(serviceType, policyUnit string) (systemdPortAdapter, error) {
	var adapter systemdPortAdapter
	switch serviceType {
	case "worker":
		adapter = systemdPortAdapter{
			Unit: "autostream-worker.service", SidecarPath: "/opt/autostream/local-executor/ports/worker.json",
			ServiceType: "worker",
		}
	case "encoder_recorder":
		adapter = systemdPortAdapter{
			Unit: "autostream-encoder-recorder.service", SidecarPath: "/opt/autostream/local-executor/ports/encoder-recorder.json",
			ServiceType: "encoder_recorder",
		}
	case "discord_bot":
		adapter = systemdPortAdapter{
			Unit: "autostream-discord-bot.service", SidecarPath: "/opt/autostream/local-executor/ports/discord-bot.json",
			ServiceType: "discord_bot",
		}
	case "observability":
		adapter = systemdPortAdapter{
			Unit: "autostream-observability.service", SidecarPath: "/opt/autostream/local-executor/ports/observability.json",
			ServiceType: "observability",
		}
	default:
		return systemdPortAdapter{}, errors.New("service type does not support systemd port reconfiguration")
	}
	if policyUnit != adapter.Unit {
		return systemdPortAdapter{}, errors.New("root policy unit does not match the fixed service adapter")
	}
	return adapter, nil
}

func validSystemdPortServiceType(value string) bool {
	switch value {
	case "worker", "encoder_recorder", "discord_bot", "observability":
		return true
	default:
		return false
	}
}

func validSystemdPort(value int) bool {
	return value >= 1024 && value <= 65535
}

func systemdPortSidecarBytes(serviceType, host string, port int, configRevision int64) []byte {
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	if serviceType == "control_panel" {
		return []byte(fmt.Sprintf("AUTOSTREAM_BIND_ADDR=%s\nAUTOSTREAM_CONFIG_REVISION=%d\n", address, configRevision))
	}
	body, err := contracts.MarshalNodeListenerConfig(contracts.NodeListenerConfig{
		SchemaVersion: 2, ServiceType: serviceType, BindAddress: address, ConfigRevision: configRevision,
	})
	if err != nil {
		return nil
	}
	return body
}

func systemdPortSidecarSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}

type systemdPortSidecarCheckpoint struct {
	Existed bool   `json:"existed"`
	Mode    uint32 `json:"mode"`
	Bytes   []byte `json:"bytes,omitempty"`
	SHA256  string `json:"sha256"`
}

func newSystemdPortSidecarCheckpoint(existed bool, mode uint32, body []byte) systemdPortSidecarCheckpoint {
	if !existed {
		body = nil
		mode = 0
	}
	return systemdPortSidecarCheckpoint{
		Existed: existed, Mode: mode, Bytes: append([]byte(nil), body...),
		SHA256: systemdPortSidecarSHA256(body),
	}
}

func (c systemdPortSidecarCheckpoint) validate() error {
	if c.SHA256 != systemdPortSidecarSHA256(c.Bytes) {
		return errors.New("systemd port sidecar checkpoint digest is invalid")
	}
	if !c.Existed {
		if c.Mode != 0 || len(c.Bytes) != 0 {
			return errors.New("absent systemd port sidecar checkpoint is invalid")
		}
		return nil
	}
	if c.Mode == 0 || c.Mode&0o022 != 0 || len(c.Bytes) == 0 || len(c.Bytes) > 64<<10 {
		return errors.New("present systemd port sidecar checkpoint is invalid")
	}
	return nil
}

type systemdPortLedger struct {
	SchemaVersion  int                           `json:"schema_version"`
	Plan           SystemdPortReconfigurePlan    `json:"plan"`
	State          string                        `json:"state"`
	Checkpoint     systemdPortSidecarCheckpoint  `json:"checkpoint"`
	TargetBytes    []byte                        `json:"target_bytes"`
	CurrentVersion string                        `json:"current_version"`
	Result         *SystemdPortReconfigureResult `json:"result,omitempty"`
}

type systemdPortAppliedState struct {
	SchemaVersion          int    `json:"schema_version"`
	TargetID               string `json:"target_id"`
	ServiceType            string `json:"service_type"`
	Port                   int    `json:"port"`
	EndpointRevision       int64  `json:"endpoint_revision"`
	ConfigRevision         int64  `json:"config_revision"`
	ConfigSHA256           string `json:"config_sha256"`
	SourcePolicyRevision   int64  `json:"source_policy_revision"`
	UpdaterPolicyRevision  int64  `json:"updater_policy_revision"`
	ExecutorPolicyRevision int64  `json:"executor_policy_revision"`
	ExecutorPolicySHA256   string `json:"executor_policy_sha256"`
	OwnershipEpoch         int64  `json:"ownership_epoch"`
}

func (s systemdPortAppliedState) validateRecord(target LocalExecutorTarget) error {
	if s.SchemaVersion != systemdPortPlanSchemaVersion ||
		s.TargetID != target.ServiceID ||
		s.ServiceType != target.ServiceType ||
		target.DeploymentMode != ModeSystemd ||
		target.Systemd == nil ||
		!validSystemdPort(s.Port) ||
		s.EndpointRevision < 1 ||
		s.ConfigRevision < 1 ||
		!digestPattern.MatchString(s.ConfigSHA256) ||
		s.SourcePolicyRevision < 1 ||
		s.UpdaterPolicyRevision < 1 ||
		s.ExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(s.ExecutorPolicySHA256) ||
		s.OwnershipEpoch < 1 ||
		!digestPattern.MatchString(target.ConfigSHA256) {
		return errors.New("systemd applied port state is invalid")
	}
	adapter, err := systemdPortAdapterFor(target.ServiceType, target.Systemd.Unit)
	if err != nil {
		return errors.New("systemd applied port state adapter is invalid")
	}
	expectedDigest := systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.ServiceType,
		target.LocalListen.Host,
		s.Port,
		s.ConfigRevision,
	))
	if s.ConfigSHA256 != expectedDigest {
		return errors.New("systemd applied port state digest is invalid")
	}
	return nil
}

func (s systemdPortAppliedState) validateForPolicy(
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
) (bool, error) {
	if err := s.validateRecord(target); err != nil {
		return false, err
	}
	policySHA, err := policy.SHA256()
	if err != nil {
		return false, errors.New("systemd applied port policy digest is unavailable")
	}
	lineageMatches := s.SourcePolicyRevision == policy.SourcePolicyRevision &&
		s.UpdaterPolicyRevision == policy.ProjectionRevision &&
		s.ExecutorPolicyRevision == policy.PolicyRevision &&
		s.ExecutorPolicySHA256 == policySHA
	if !lineageMatches {
		// A newly installed root policy may already contain the exact applied
		// endpoint. In that case the overlay is redundant and can be ignored
		// safely. Any other lineage mismatch is quarantined fail-closed.
		if s.matchesTarget(target) {
			return false, nil
		}
		return false, errors.New("systemd applied port state policy lineage is stale")
	}
	if s.EndpointRevision < target.EndpointRevision ||
		s.ConfigRevision < target.ConfigRevision {
		return false, errors.New("systemd applied port state revision regresses")
	}
	if s.EndpointRevision == target.EndpointRevision &&
		(s.Port != target.LocalListen.Port ||
			s.ConfigRevision != target.ConfigRevision ||
			s.ConfigSHA256 != target.ConfigSHA256) {
		return false, errors.New("systemd applied port state reuses an endpoint revision")
	}
	if s.ConfigRevision == target.ConfigRevision &&
		(s.Port != target.LocalListen.Port ||
			s.ConfigSHA256 != target.ConfigSHA256) {
		return false, errors.New("systemd applied port state reuses a config revision")
	}
	return true, nil
}

func (s systemdPortAppliedState) matchesTarget(target LocalExecutorTarget) bool {
	return s.TargetID == target.ServiceID &&
		s.ServiceType == target.ServiceType &&
		s.Port == target.LocalListen.Port &&
		s.EndpointRevision == target.EndpointRevision &&
		s.ConfigRevision == target.ConfigRevision &&
		s.ConfigSHA256 == target.ConfigSHA256
}

func (l systemdPortLedger) validate(targetID string) error {
	if l.SchemaVersion != systemdPortPlanSchemaVersion ||
		l.Plan.TargetID != targetID ||
		l.Plan.Validate() != nil ||
		l.Checkpoint.validate() != nil ||
		l.Plan.ExpectedConfigSHA256 != l.Checkpoint.SHA256 ||
		systemdPortSidecarSHA256(l.TargetBytes) != l.Plan.TargetConfigSHA256 {
		return errors.New("systemd port ledger binding is invalid")
	}
	if !versionPattern.MatchString(l.CurrentVersion) {
		return errors.New("systemd port ledger current version is invalid")
	}
	switch l.State {
	case systemdPortLedgerStaged, systemdPortLedgerGrantConsuming,
		systemdPortLedgerGrantConsumed, systemdPortLedgerSidecarWritten,
		systemdPortLedgerRestarted, systemdPortLedgerAmbiguous:
		if l.Result != nil {
			return errors.New("non-terminal systemd port ledger contains a result")
		}
	case systemdPortLedgerCommitting:
		if l.Result == nil || l.Result.Validate() != nil ||
			l.Result.Result == systemdPortResultRollbackFailed {
			return errors.New("committing systemd port ledger result is invalid")
		}
	case systemdPortLedgerTerminal:
		if l.Result == nil || l.Result.Validate() != nil {
			return errors.New("terminal systemd port ledger result is invalid")
		}
	default:
		return errors.New("systemd port ledger state is invalid")
	}
	return nil
}

type systemdPortStateStore interface {
	LoadActive(string) (*systemdPortLedger, error)
	LoadJob(string, string) (*systemdPortLedger, error)
	Stage(systemdPortLedger) error
	Save(systemdPortLedger) error
	LoadApplied(string) (*systemdPortAppliedState, error)
	SaveApplied(systemdPortAppliedState) error
}

type memorySystemdPortStateStore struct {
	mu      sync.Mutex
	ledgers map[string]map[string]systemdPortLedger
	active  map[string]string
	applied map[string]systemdPortAppliedState
}

func newMemorySystemdPortStateStore() *memorySystemdPortStateStore {
	return &memorySystemdPortStateStore{
		ledgers: make(map[string]map[string]systemdPortLedger),
		active:  make(map[string]string), applied: make(map[string]systemdPortAppliedState),
	}
}

func (s *memorySystemdPortStateStore) LoadActive(targetID string) (*systemdPortLedger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobID := s.active[targetID]
	ledger, ok := s.ledgers[targetID][jobID]
	if !ok {
		return nil, nil
	}
	copy := cloneSystemdPortLedger(ledger)
	return &copy, nil
}

func (s *memorySystemdPortStateStore) LoadJob(targetID, jobID string) (*systemdPortLedger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, ok := s.ledgers[targetID][jobID]
	if !ok {
		return nil, nil
	}
	copy := cloneSystemdPortLedger(ledger)
	return &copy, nil
}

func (s *memorySystemdPortStateStore) Stage(ledger systemdPortLedger) error {
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	targetID := ledger.Plan.TargetID
	if activeID := s.active[targetID]; activeID != "" && activeID != ledger.Plan.JobID {
		if active, ok := s.ledgers[targetID][activeID]; ok &&
			active.State != systemdPortLedgerTerminal {
			return errors.New("systemd port target already has a non-terminal transaction")
		}
	}
	if s.ledgers[targetID] == nil {
		s.ledgers[targetID] = make(map[string]systemdPortLedger)
	}
	s.ledgers[targetID][ledger.Plan.JobID] = cloneSystemdPortLedger(ledger)
	s.active[targetID] = ledger.Plan.JobID
	return nil
}

func (s *memorySystemdPortStateStore) Save(ledger systemdPortLedger) error {
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ledgers[ledger.Plan.TargetID] == nil {
		s.ledgers[ledger.Plan.TargetID] = make(map[string]systemdPortLedger)
	}
	s.ledgers[ledger.Plan.TargetID][ledger.Plan.JobID] = cloneSystemdPortLedger(ledger)
	if s.active[ledger.Plan.TargetID] == "" {
		s.active[ledger.Plan.TargetID] = ledger.Plan.JobID
	}
	return nil
}

func (s *memorySystemdPortStateStore) LoadApplied(targetID string) (*systemdPortAppliedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	applied, ok := s.applied[targetID]
	if !ok {
		return nil, nil
	}
	copy := applied
	return &copy, nil
}

func (s *memorySystemdPortStateStore) SaveApplied(applied systemdPortAppliedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied[applied.TargetID] = applied
	return nil
}

func cloneSystemdPortLedger(ledger systemdPortLedger) systemdPortLedger {
	copy := ledger
	copy.Checkpoint.Bytes = append([]byte(nil), ledger.Checkpoint.Bytes...)
	copy.TargetBytes = append([]byte(nil), ledger.TargetBytes...)
	if ledger.Result != nil {
		result := *ledger.Result
		copy.Result = &result
	}
	return copy
}

type systemdPortRuntime interface {
	Checkpoint(systemdPortAdapter) (systemdPortSidecarCheckpoint, error)
	EnsurePortAvailable(LocalExecutorEndpoint) error
	ConsumeGrant(context.Context, SystemdPortReconfigurePlan, string, string, BoundedSecret) error
	Write(systemdPortAdapter, systemdPortSidecarCheckpoint, []byte) error
	Restore(systemdPortAdapter, systemdPortSidecarCheckpoint, []byte) error
	Restart(context.Context, LocalExecutorTarget) error
	Verify(context.Context, LocalExecutorPolicy, LocalExecutorTarget) (string, error)
	CrashPoint(string) error
}

func executeSystemdPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	failure := func(code string) LocalExecutorResponse {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, code)
	}
	if runtime == nil || state == nil || request.PortPlan == nil {
		return failure("internal_error")
	}
	plan := *request.PortPlan
	policyTarget, adapter, err := validateSystemdPortPolicyBinding(policy, request, plan)
	if err != nil {
		return failure("config_mismatch")
	}
	historical, err := state.LoadJob(plan.TargetID, plan.JobID)
	if err != nil {
		return failure("state_invalid")
	}
	if historical != nil {
		if err := historical.validate(plan.TargetID); err != nil {
			return failure("state_invalid")
		}
		if !sameSystemdPortIntent(historical.Plan, plan) {
			return failure("plan_conflict")
		}
		if historical.State == systemdPortLedgerTerminal {
			return localExecutorPortResponse(plan, *historical.Result)
		}
	}
	active, err := state.LoadActive(plan.TargetID)
	if err != nil {
		return failure("state_invalid")
	}
	if active != nil && active.Plan.JobID != plan.JobID &&
		active.State != systemdPortLedgerTerminal {
		return failure("target_busy")
	}
	ledger := historical
	if ledger == nil && active != nil && active.Plan.JobID == plan.JobID {
		ledger = active
	}
	if ledger != nil && ledger.State == systemdPortLedgerCommitting {
		if request.Operation != "port_reconfigure_reconcile" {
			return failure("reconcile_required")
		}
		return repairSystemdPortCommit(
			ctx, policy, request, policyTarget, adapter, *ledger, runtime, state,
		)
	}
	target, err := resolveSystemdPortAppliedTarget(policy, policyTarget, state)
	if err != nil || !systemdPortTargetMatchesExpected(target, plan) {
		return failure("config_mismatch")
	}
	if request.Operation == "port_reconfigure_reconcile" {
		if ledger == nil {
			return reconcileUnstartedSystemdPortRequest(
				ctx, policy, request, target, adapter, runtime, state,
			)
		}
		return reconcileSystemdPortRequest(ctx, policy, request, target, adapter, *ledger, runtime, state)
	}
	if request.Operation != "port_reconfigure" {
		return failure("invalid_request")
	}
	if ledger == nil {
		checkpoint, err := runtime.Checkpoint(adapter)
		if err != nil || checkpoint.validate() != nil ||
			checkpoint.SHA256 != plan.ExpectedConfigSHA256 {
			return failure("mutation_precondition_failed")
		}
		expectedOldBytes := systemdPortSidecarBytes(
			adapter.ServiceType, target.LocalListen.Host, plan.OldPort, plan.ExpectedConfigRevision,
		)
		if checkpoint.Existed && string(checkpoint.Bytes) != string(expectedOldBytes) {
			return failure("mutation_precondition_failed")
		}
		if !checkpoint.Existed && checkpoint.SHA256 != systemdPortSidecarSHA256(nil) {
			return failure("mutation_precondition_failed")
		}
		currentVersion, err := runtime.Verify(ctx, policy, target)
		if err != nil || !versionPattern.MatchString(currentVersion) {
			return failure("mutation_precondition_failed")
		}
		newEndpoint := target.LocalListen
		newEndpoint.Port = plan.NewPort
		if err := runtime.EnsurePortAvailable(newEndpoint); err != nil {
			return failure("mutation_precondition_failed")
		}
		targetBytes := systemdPortSidecarBytes(
			adapter.ServiceType, target.LocalListen.Host, plan.NewPort, plan.TargetConfigRevision,
		)
		if systemdPortSidecarSHA256(targetBytes) != plan.TargetConfigSHA256 {
			return failure("config_mismatch")
		}
		record := systemdPortLedger{
			SchemaVersion: systemdPortPlanSchemaVersion, Plan: plan,
			State: systemdPortLedgerStaged, Checkpoint: checkpoint,
			TargetBytes: targetBytes, CurrentVersion: currentVersion,
		}
		if err := state.Stage(record); err != nil {
			return failure("state_unavailable")
		}
		ledger = &record
	}
	if ledger.State != systemdPortLedgerStaged {
		return failure("reconcile_required")
	}
	current, err := runtime.Checkpoint(adapter)
	if err != nil || !sameSystemdPortCheckpoint(current, ledger.Checkpoint) {
		return failure("reconcile_required")
	}
	newEndpoint := target.LocalListen
	newEndpoint.Port = plan.NewPort
	if err := runtime.EnsurePortAvailable(newEndpoint); err != nil {
		return failure("mutation_precondition_failed")
	}
	working := *ledger
	working.Plan = plan
	working.State = systemdPortLedgerGrantConsuming
	if err := state.Save(working); err != nil {
		return failure("state_unavailable")
	}
	if err := runtime.ConsumeGrant(ctx, plan, request.Operation, working.CurrentVersion, request.MutationGrant); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	working.State = systemdPortLedgerGrantConsumed
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_grant_consume"); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	if err := runtime.Write(adapter, working.Checkpoint, working.TargetBytes); err != nil {
		return rollbackSystemdPortRequest(ctx, policy, plan, target, adapter, working, runtime, state)
	}
	working.State = systemdPortLedgerSidecarWritten
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_sidecar_write"); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	newTarget := systemdPortTargetAfter(target, plan)
	if err := runtime.Restart(ctx, newTarget); err != nil {
		return rollbackSystemdPortRequest(ctx, policy, plan, target, adapter, working, runtime, state)
	}
	working.State = systemdPortLedgerRestarted
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_restart"); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	if _, err := runtime.Verify(ctx, policy, newTarget); err != nil {
		return rollbackSystemdPortRequest(ctx, policy, plan, target, adapter, working, runtime, state)
	}
	return commitSystemdPortResult(
		plan, working, systemdPortResultApplied, runtime, state,
	)
}

func validateSystemdPortPolicyBinding(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	plan SystemdPortReconfigurePlan,
) (LocalExecutorTarget, systemdPortAdapter, error) {
	if request.Validate() != nil || plan.Validate() != nil ||
		request.Operation != "port_reconfigure" && request.Operation != "port_reconfigure_reconcile" ||
		request.ServiceID != plan.TargetID ||
		request.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		request.OwnershipEpoch != plan.OwnershipEpoch ||
		request.OwnershipPolicyRevision != plan.ExpectedUpdaterPolicyRevision ||
		request.ExecutorPolicyRevision != plan.ExpectedExecutorPolicyRevision {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("request fence does not match the port plan")
	}
	if policy.Validate() != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil ||
		policy.HostID != plan.HostID ||
		policy.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		policy.ProjectionRevision != plan.ExpectedUpdaterPolicyRevision ||
		policy.PolicyRevision != plan.ExpectedExecutorPolicyRevision {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("root policy revision does not match the port plan")
	}
	policySHA, err := policy.SHA256()
	if err != nil || policySHA != plan.ExpectedExecutorPolicySHA256 {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("root policy digest does not match the port plan")
	}
	target, ok := policy.Target(plan.TargetID)
	if !ok || target.DeploymentMode != ModeSystemd || target.Systemd == nil ||
		target.ServiceType != plan.ServiceType {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("root target identity does not match the port plan")
	}
	adapter, err := systemdPortAdapterFor(target.ServiceType, target.Systemd.Unit)
	if err != nil {
		return LocalExecutorTarget{}, systemdPortAdapter{}, err
	}
	expectedTarget := systemdPortSidecarBytes(
		adapter.ServiceType, target.LocalListen.Host, plan.NewPort, plan.TargetConfigRevision,
	)
	if systemdPortSidecarSHA256(expectedTarget) != plan.TargetConfigSHA256 {
		return LocalExecutorTarget{}, systemdPortAdapter{}, errors.New("target sidecar digest does not match the fixed adapter")
	}
	return target, adapter, nil
}

func resolveSystemdPortAppliedTarget(
	policy LocalExecutorPolicy,
	policyTarget LocalExecutorTarget,
	state systemdPortAppliedStateReader,
) (LocalExecutorTarget, error) {
	applied, err := state.LoadApplied(policyTarget.ServiceID)
	if err != nil {
		return LocalExecutorTarget{}, err
	}
	if applied == nil {
		return policyTarget, nil
	}
	useOverlay, err := applied.validateForPolicy(policy, policyTarget)
	if err != nil {
		return LocalExecutorTarget{}, err
	}
	if verifier, ok := state.(systemdPortAppliedSidecarVerifier); ok {
		if err := verifier.VerifyAppliedSidecar(policyTarget, *applied); err != nil {
			return LocalExecutorTarget{}, err
		}
	}
	if !useOverlay {
		return policyTarget, nil
	}
	target := policyTarget
	target.LocalListen.Port = applied.Port
	target.EndpointRevision = applied.EndpointRevision
	target.ConfigRevision = applied.ConfigRevision
	target.ConfigSHA256 = applied.ConfigSHA256
	return target, nil
}

func systemdPortTargetMatchesExpected(
	target LocalExecutorTarget,
	plan SystemdPortReconfigurePlan,
) bool {
	return target.LocalListen.Port == plan.OldPort &&
		// Queued cancellations consume server-side endpoint generations
		// without reaching this root-owned runtime. A forward-only gap is safe
		// when the actual port and complete config identity still match and the
		// surrounding policy/ownership/grant fences have already been checked.
		target.EndpointRevision > 0 &&
		target.EndpointRevision <= plan.ExpectedEndpointRevision &&
		target.ConfigRevision == plan.ExpectedConfigRevision &&
		target.ConfigSHA256 == plan.ExpectedConfigSHA256
}

// reconcileUnstartedSystemdPortRequest closes the response-loss window before
// the first request reaches the Local Executor. A fresh reconcile grant can
// prove that the exact previous sidecar and service are still active, persist a
// terminal unchanged ledger, and release the Panel's pending endpoint without
// writing configuration or restarting the service.
func reconcileUnstartedSystemdPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	target LocalExecutorTarget,
	adapter systemdPortAdapter,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	plan := *request.PortPlan
	checkpoint, err := runtime.Checkpoint(adapter)
	expectedOldBytes := systemdPortSidecarBytes(
		adapter.ServiceType,
		target.LocalListen.Host,
		plan.OldPort,
		plan.ExpectedConfigRevision,
	)
	if err != nil ||
		checkpoint.validate() != nil ||
		!checkpoint.Existed ||
		checkpoint.Mode != 0o600 ||
		checkpoint.SHA256 != plan.ExpectedConfigSHA256 ||
		string(checkpoint.Bytes) != string(expectedOldBytes) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "mutation_precondition_failed",
		)
	}
	currentVersion, err := runtime.Verify(ctx, policy, target)
	if err != nil || !versionPattern.MatchString(currentVersion) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "mutation_precondition_failed",
		)
	}
	targetBytes := systemdPortSidecarBytes(
		adapter.ServiceType,
		target.LocalListen.Host,
		plan.NewPort,
		plan.TargetConfigRevision,
	)
	if systemdPortSidecarSHA256(targetBytes) != plan.TargetConfigSHA256 {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "config_mismatch",
		)
	}
	working := systemdPortLedger{
		SchemaVersion:  systemdPortPlanSchemaVersion,
		Plan:           plan,
		State:          systemdPortLedgerStaged,
		Checkpoint:     checkpoint,
		TargetBytes:    targetBytes,
		CurrentVersion: currentVersion,
	}
	if err := state.Stage(working); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	working.State = systemdPortLedgerGrantConsuming
	if err := state.Save(working); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	if err := runtime.ConsumeGrant(
		ctx, plan, request.Operation, working.CurrentVersion, request.MutationGrant,
	); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	working.State = systemdPortLedgerGrantConsumed
	if err := state.Save(working); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	return commitSystemdPortResult(
		plan, working, systemdPortResultUnchanged, runtime, state,
	)
}

func reconcileSystemdPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	target LocalExecutorTarget,
	adapter systemdPortAdapter,
	ledger systemdPortLedger,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	plan := *request.PortPlan
	working := ledger
	working.Plan = plan
	working.State = systemdPortLedgerGrantConsuming
	working.Result = nil
	if err := state.Save(working); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	if err := runtime.ConsumeGrant(ctx, plan, request.Operation, working.CurrentVersion, request.MutationGrant); err != nil {
		working.State = systemdPortLedgerAmbiguous
		_ = state.Save(working)
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "reconcile_required")
	}
	working.State = systemdPortLedgerGrantConsumed
	if err := state.Save(working); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "reconcile_required")
	}
	current, checkpointErr := runtime.Checkpoint(adapter)
	newTarget := systemdPortTargetAfter(target, plan)
	if checkpointErr == nil &&
		current.SHA256 == plan.TargetConfigSHA256 &&
		func() bool {
			_, err := runtime.Verify(ctx, policy, newTarget)
			return err == nil
		}() {
		return commitSystemdPortResult(
			plan, working, systemdPortResultApplied, runtime, state,
		)
	}
	if checkpointErr == nil &&
		sameSystemdPortCheckpoint(current, working.Checkpoint) &&
		func() bool {
			_, err := runtime.Verify(ctx, policy, target)
			return err == nil
		}() {
		return commitSystemdPortResult(
			plan, working, systemdPortResultUnchanged, runtime, state,
		)
	}
	return rollbackSystemdPortRequest(ctx, policy, plan, target, adapter, working, runtime, state)
}

func repairSystemdPortCommit(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	policyTarget LocalExecutorTarget,
	adapter systemdPortAdapter,
	ledger systemdPortLedger,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	plan := *request.PortPlan
	if ledger.State != systemdPortLedgerCommitting ||
		ledger.Result == nil ||
		ledger.Result.Validate() != nil ||
		ledger.Result.Result == systemdPortResultRollbackFailed {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_invalid",
		)
	}
	if err := runtime.ConsumeGrant(
		ctx, plan, request.Operation, ledger.CurrentVersion, request.MutationGrant,
	); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	result := *ledger.Result
	effective := policyTarget
	effective.LocalListen.Port = result.AppliedPort
	effective.EndpointRevision = result.EndpointRevision
	effective.ConfigRevision = result.ConfigRevision
	effective.ConfigSHA256 = result.ConfigSHA256
	expectedBytes := systemdPortSidecarBytes(
		adapter.ServiceType,
		effective.LocalListen.Host,
		effective.LocalListen.Port,
		effective.ConfigRevision,
	)
	current, err := runtime.Checkpoint(adapter)
	if err != nil ||
		!current.Existed ||
		current.Mode != 0o600 ||
		current.SHA256 != result.ConfigSHA256 ||
		systemdPortSidecarSHA256(expectedBytes) != result.ConfigSHA256 ||
		string(current.Bytes) != string(expectedBytes) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_invalid",
		)
	}
	if _, err := runtime.Verify(ctx, policy, effective); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	applied := systemdPortAppliedStateForResult(plan, result)
	if err := state.SaveApplied(applied); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	ledger.Plan = plan
	ledger.State = systemdPortLedgerTerminal
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}

func rollbackSystemdPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	plan SystemdPortReconfigurePlan,
	oldTarget LocalExecutorTarget,
	adapter systemdPortAdapter,
	ledger systemdPortLedger,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	if err := runtime.Restore(adapter, ledger.Checkpoint, ledger.TargetBytes); err == nil {
		if restartErr := runtime.Restart(ctx, oldTarget); restartErr == nil {
			if _, verifyErr := runtime.Verify(ctx, policy, oldTarget); verifyErr == nil {
				return commitSystemdPortResult(
					plan, ledger, systemdPortResultRolledBack, runtime, state,
				)
			}
		}
	}
	result := SystemdPortReconfigureResult{
		Status: "failed", Result: systemdPortResultRollbackFailed,
		StateKnown: false,
		OldPort:    plan.OldPort, NewPort: plan.NewPort, AppliedPort: 0,
		EndpointRevision: plan.TargetEndpointRevision,
		ConfigRevision:   0, ConfigSHA256: "",
		Message: "local rollback could not determine a verified effective port",
	}
	// The result is terminal but quarantined: no applied overlay is recorded,
	// and every later job must prove its own exact old-sidecar and endpoint
	// preconditions. Keeping rollback_failed non-terminal would leave the
	// active pointer permanently returning target_busy after the Panel closes
	// the failed job.
	ledger.Plan = plan
	ledger.State = systemdPortLedgerTerminal
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}

func commitSystemdPortResult(
	plan SystemdPortReconfigurePlan,
	ledger systemdPortLedger,
	resultKind string,
	runtime systemdPortRuntime,
	state systemdPortStateStore,
) LocalExecutorResponse {
	result := SystemdPortReconfigureResult{
		OldPort: plan.OldPort, NewPort: plan.NewPort,
	}
	switch resultKind {
	case systemdPortResultApplied:
		result.Status, result.Result = "succeeded", systemdPortResultApplied
		result.StateKnown = true
		result.AppliedPort = plan.NewPort
		result.EndpointRevision = plan.TargetEndpointRevision
		result.ConfigRevision = plan.TargetConfigRevision
		result.ConfigSHA256 = plan.TargetConfigSHA256
		result.Message = "requested systemd port is running and verified"
	case systemdPortResultRolledBack:
		result.Status, result.Result = "rolled_back", systemdPortResultRolledBack
		result.StateKnown = true
		result.AppliedPort = plan.OldPort
		// The Panel already consumed target_endpoint_revision for the pending
		// generation. Closing it without promoting the requested endpoint
		// advances once more so a later job cannot reuse the aborted fence.
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "previous systemd port was restored and verified"
	case systemdPortResultUnchanged:
		result.Status, result.Result = "succeeded", systemdPortResultUnchanged
		result.StateKnown = true
		result.AppliedPort = plan.OldPort
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "systemd port mutation had not changed the verified previous state"
	default:
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "internal_error")
	}
	applied := systemdPortAppliedStateForResult(plan, result)
	ledger.Plan = plan
	ledger.State = systemdPortLedgerCommitting
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	if err := state.SaveApplied(applied); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	if runtime != nil {
		if err := runtime.CrashPoint("after_applied_state_save"); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "reconcile_required",
			)
		}
	}
	ledger.State = systemdPortLedgerTerminal
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	return localExecutorPortResponse(plan, result)
}

func systemdPortAppliedStateForResult(
	plan SystemdPortReconfigurePlan,
	result SystemdPortReconfigureResult,
) systemdPortAppliedState {
	return systemdPortAppliedState{
		SchemaVersion: systemdPortPlanSchemaVersion,
		TargetID:      plan.TargetID, ServiceType: plan.ServiceType,
		Port: result.AppliedPort, EndpointRevision: result.EndpointRevision,
		ConfigRevision: result.ConfigRevision, ConfigSHA256: result.ConfigSHA256,
		SourcePolicyRevision:   plan.ExpectedSourcePolicyRevision,
		UpdaterPolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision: plan.ExpectedExecutorPolicyRevision,
		ExecutorPolicySHA256:   plan.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:         plan.OwnershipEpoch,
	}
}

func localExecutorPortResponse(
	plan SystemdPortReconfigurePlan,
	result SystemdPortReconfigureResult,
) LocalExecutorResponse {
	response := LocalExecutorResponse{
		Version:    LocalExecutorMutationProtocolVersion,
		PortResult: &result, SessionID: plan.SessionID, PlanSHA256: plan.PortPlanSHA256,
	}
	if err := response.Validate(); err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "internal_error")
	}
	return response
}

func systemdPortTargetAfter(
	target LocalExecutorTarget,
	plan SystemdPortReconfigurePlan,
) LocalExecutorTarget {
	updated := target
	updated.LocalListen.Port = plan.NewPort
	updated.EndpointRevision = plan.TargetEndpointRevision
	updated.ConfigRevision = plan.TargetConfigRevision
	updated.ConfigSHA256 = plan.TargetConfigSHA256
	return updated
}

func sameSystemdPortCheckpoint(left, right systemdPortSidecarCheckpoint) bool {
	return left.Existed == right.Existed &&
		left.Mode == right.Mode &&
		left.SHA256 == right.SHA256 &&
		string(left.Bytes) == string(right.Bytes)
}

func sameSystemdPortIntent(left, right SystemdPortReconfigurePlan) bool {
	left.LeaseGeneration = 0
	left.PortPlanSHA256 = ""
	right.LeaseGeneration = 0
	right.PortPlanSHA256 = ""
	return reflect.DeepEqual(left, right)
}

func (p SystemdPortReconfigurePlan) mutationGrantBinding() *SystemdPortMutationGrantBinding {
	return &SystemdPortMutationGrantBinding{
		NetworkNamespace: p.NetworkNamespace, Protocol: p.Protocol,
		OldPort: p.OldPort, NewPort: p.NewPort,
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
		PortPlanSHA256:                 p.PortPlanSHA256,
		Docker:                         cloneDockerPortMutationGrantBinding(p.Docker),
	}
}

func cloneDockerPortMutationGrantBinding(
	input *DockerPortMutationGrantBinding,
) *DockerPortMutationGrantBinding {
	if input == nil {
		return nil
	}
	copy := *input
	return &copy
}

func handleLocalExecutorSystemdPortMutation(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	remoteRuntime executorMutationRuntime,
) LocalExecutorResponse {
	if remoteRuntime.platformOS == "" {
		remoteRuntime.platformOS = runtime.GOOS
	}
	if remoteRuntime.platformOS != "linux" || request.PortPlan == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_unavailable")
	}
	target, ok := policy.Target(request.ServiceID)
	if !ok {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_not_found")
	}
	if target.DeploymentMode != ModeSystemd || target.Systemd == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}
	secured, err := securePrivilegedTarget(target.runtimeTarget(policy.HostID))
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_unavailable")
	}
	unlock, err := acquireTargetLock(secured)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "target_busy")
	}
	defer unlock()
	portRuntime, state, err := newPlatformSystemdPortExecution(policy, target, secured, remoteRuntime)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	return executeSystemdPortRequest(ctx, policy, request, portRuntime, state)
}
