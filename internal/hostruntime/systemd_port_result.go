package hostruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/example/autostream-contracts/pkg/contracts"
	"net"
	"strings"
)

type SystemdPortReconfigureResult struct {
	PortContractVersion int                                 `json:"port_contract_version,omitempty"`
	PortResult          *contracts.SystemUpdatePortResultV2 `json:"port_result,omitempty"`
	RecoveryRequired    bool                                `json:"recovery_required,omitempty"`
	DeploymentMode      string                              `json:"deployment_mode,omitempty"`
	Status              string                              `json:"status"`
	Result              string                              `json:"result"`
	StateKnown          bool                                `json:"state_known"`
	OldPort             int                                 `json:"old_port"`
	NewPort             int                                 `json:"new_port"`
	AppliedPort         int                                 `json:"applied_port"`
	EndpointRevision    int64                               `json:"endpoint_revision"`
	ConfigRevision      int64                               `json:"config_revision"`
	ConfigSHA256        string                              `json:"config_sha256"`
	Message             string                              `json:"message"`
	Docker              *DockerPortReconfigureResultState   `json:"docker,omitempty"`
}

type DockerPortReconfigureResultState struct {
	AppliedPublishedPort int    `json:"applied_published_port"`
	AppliedContainerPort int    `json:"applied_container_port"`
	AppliedHealthPort    int    `json:"applied_health_port"`
	ComposeConfigSHA256  string `json:"compose_config_sha256"`
}

func (r SystemdPortReconfigureResult) Validate() error {
	if r.PortContractVersion != 0 {
		return r.validatePortV2()
	}
	if r.PortResult != nil || r.RecoveryRequired {
		return errors.New("legacy port result contains versioned fields")
	}
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
