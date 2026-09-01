package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const (
	LocalExecutorPolicySchemaVersion         = 1
	LocalExecutorMutationPolicySchemaVersion = 2
	LocalExecutorSocketPath                  = "/run/autostream-local-executor/executor.sock"
	LocalExecutorMutationStateDir            = "/var/lib/autostream-local-executor"
	localExecutorPolicyMaxBytes              = 1 << 20
)

// LocalExecutorPolicy is the only authority for privileged service
// identities and paths. It must be installed as a root-owned policy and must
// never be populated from a local IPC request.
type LocalExecutorPolicy struct {
	SchemaVersion        int                          `json:"schema_version"`
	ProtocolVersion      int                          `json:"protocol_version"`
	HostID               string                       `json:"host_id"`
	AgentUID             uint32                       `json:"agent_uid"`
	AgentGID             uint32                       `json:"agent_gid"`
	SocketPath           string                       `json:"socket_path"`
	SourcePolicyRevision int64                        `json:"source_policy_revision,omitempty"`
	ProjectionRevision   int64                        `json:"projection_revision,omitempty"`
	PolicyRevision       int64                        `json:"policy_revision"`
	Mutation             *LocalExecutorMutationPolicy `json:"mutation,omitempty"`
	Targets              []LocalExecutorTarget        `json:"targets"`
}

// LocalExecutorMutationPolicy contains the root-owned authority needed at the
// final grant-consumption boundary. Neither the Panel origin nor the durable
// state path can be supplied by the unprivileged Host Agent request.
type LocalExecutorMutationPolicy struct {
	PanelURL string `json:"panel_url"`
}

type LocalExecutorTarget struct {
	ServiceID        string                `json:"service_id"`
	ServiceType      string                `json:"service_type"`
	DeploymentMode   string                `json:"deployment_mode"`
	DatabaseName     string                `json:"database_name,omitempty"`
	EndpointRevision int64                 `json:"endpoint_revision,omitempty"`
	ConfigRevision   int64                 `json:"config_revision"`
	ConfigSHA256     string                `json:"config_sha256,omitempty"`
	LocalListen      LocalExecutorEndpoint `json:"local_listen_endpoint"`
	Systemd          *SystemdTarget        `json:"systemd,omitempty"`
	Docker           *DockerTarget         `json:"docker,omitempty"`
}

type LocalExecutorEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type localExecutorDockerProfile struct {
	service        string
	imageRepo      string
	versionEnvFile string
	portEnvFile    string
}

func LoadLocalExecutorPolicy(path string, requireRootOwned bool) (LocalExecutorPolicy, error) {
	if !filepath.IsAbs(path) {
		return LocalExecutorPolicy{}, errors.New("local executor policy path must be absolute")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return LocalExecutorPolicy{}, fmt.Errorf("stat local executor policy: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() ||
		pathInfo.Size() <= 0 || pathInfo.Size() > localExecutorPolicyMaxBytes {
		return LocalExecutorPolicy{}, errors.New("local executor policy must be a bounded regular non-symlink file")
	}
	file, openedInfo, err := openVerifiedConfig(path, pathInfo)
	if err != nil {
		return LocalExecutorPolicy{}, errors.New("local executor policy changed during secure open")
	}
	defer file.Close()
	if requireRootOwned {
		if openedInfo.Mode().Perm()&0o007 != 0 || openedInfo.Mode().Perm()&0o022 != 0 {
			return LocalExecutorPolicy{}, errors.New("local executor policy must be root-owned, not writable by group, and inaccessible to other users")
		}
		if err := validateRootOwnedFileAndParents(path, openedInfo, "local executor policy"); err != nil {
			return LocalExecutorPolicy{}, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, localExecutorPolicyMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > localExecutorPolicyMaxBytes {
		return LocalExecutorPolicy{}, errors.New("read local executor policy")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy LocalExecutorPolicy
	if err := decoder.Decode(&policy); err != nil {
		return LocalExecutorPolicy{}, errors.New("decode local executor policy")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return LocalExecutorPolicy{}, errors.New("local executor policy contains trailing data")
	}
	if err := policy.Validate(); err != nil {
		return LocalExecutorPolicy{}, err
	}
	return policy, nil
}

func (p LocalExecutorPolicy) Validate() error {
	if p.SchemaVersion != LocalExecutorPolicySchemaVersion &&
		p.SchemaVersion != LocalExecutorMutationPolicySchemaVersion {
		return errors.New("unsupported local executor policy schema_version")
	}
	if p.SchemaVersion == LocalExecutorPolicySchemaVersion &&
		(p.ProtocolVersion != LocalExecutorProtocolVersion || p.Mutation != nil) {
		return errors.New("unsupported local executor policy protocol_version")
	}
	if p.SchemaVersion == LocalExecutorMutationPolicySchemaVersion {
		if p.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
			p.Mutation == nil ||
			validatePanelURL(strings.TrimSpace(p.Mutation.PanelURL)) != nil ||
			p.Mutation.PanelURL != strings.TrimSpace(p.Mutation.PanelURL) {
			return errors.New("local executor mutation policy is invalid")
		}
	}
	if p.HostID != strings.TrimSpace(p.HostID) || !identifierPattern.MatchString(p.HostID) {
		return errors.New("local executor policy host_id is invalid")
	}
	if p.AgentUID == 0 || p.AgentGID == 0 {
		return errors.New("local executor policy agent identity must be non-root")
	}
	if p.SocketPath != LocalExecutorSocketPath {
		return errors.New("local executor policy socket_path must use the fixed executor socket")
	}
	if p.PolicyRevision < 1 || len(p.Targets) == 0 {
		return errors.New("local executor policy revision and targets are required")
	}
	if (p.SourcePolicyRevision != 0 || p.ProjectionRevision != 0) &&
		(p.SourcePolicyRevision < 1 || p.ProjectionRevision < 1) {
		return errors.New("local executor policy source and projection revisions must be complete")
	}
	seen := make(map[string]struct{}, len(p.Targets))
	seenPrivilegedTarget := make(map[string]struct{}, len(p.Targets))
	for index := range p.Targets {
		target := &p.Targets[index]
		if err := target.validate(); err != nil {
			return fmt.Errorf("targets[%d]: %w", index, err)
		}
		if _, exists := seen[target.ServiceID]; exists {
			return fmt.Errorf("duplicate local executor service_id %q", target.ServiceID)
		}
		seen[target.ServiceID] = struct{}{}
		privilegedKey := target.DeploymentMode + "\x00" + target.ServiceType
		if _, exists := seenPrivilegedTarget[privilegedKey]; exists {
			return fmt.Errorf("duplicate local executor privileged target for %s %s", target.DeploymentMode, target.ServiceType)
		}
		seenPrivilegedTarget[privilegedKey] = struct{}{}
	}
	return nil
}

func (p LocalExecutorPolicy) mutationHelperConfig(arch string) (HelperConfig, error) {
	if p.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		p.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		p.Mutation == nil {
		return HelperConfig{}, errors.New("local executor mutation policy is disabled")
	}
	targets := make([]Target, 0, len(p.Targets))
	for _, target := range p.Targets {
		targets = append(targets, target.runtimeTarget(p.HostID))
	}
	cfg := HelperConfig{
		SchemaVersion: HelperConfigSchemaVersion,
		HostID:        p.HostID,
		PanelURL:      p.Mutation.PanelURL,
		Arch:          arch,
		StateDir:      LocalExecutorMutationStateDir,
		Targets:       targets,
	}
	if arch != "amd64" && arch != "arm64" {
		return HelperConfig{}, errors.New("local executor mutation architecture is unsupported")
	}
	if !deploymentAbsolutePath(cfg.StateDir) {
		return HelperConfig{}, errors.New("local executor mutation state directory is invalid")
	}
	for _, target := range cfg.Targets {
		if err := target.Validate(); err != nil {
			return HelperConfig{}, err
		}
	}
	return cfg, nil
}

func (p LocalExecutorPolicy) Target(serviceID string) (LocalExecutorTarget, bool) {
	for _, target := range p.Targets {
		if target.ServiceID == serviceID {
			return target, true
		}
	}
	return LocalExecutorTarget{}, false
}

func (p LocalExecutorPolicy) SHA256() (string, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return "", errors.New("encode local executor policy digest")
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (t LocalExecutorTarget) validate() error {
	if t.ServiceID != strings.TrimSpace(t.ServiceID) || !identifierPattern.MatchString(t.ServiceID) {
		return errors.New("service_id is invalid")
	}
	if t.ServiceType != strings.TrimSpace(t.ServiceType) || !validLocalExecutorServiceType(t.ServiceType) {
		return errors.New("service_type is invalid")
	}
	if t.ConfigRevision < 1 {
		return errors.New("config_revision is required")
	}
	if t.EndpointRevision < 0 ||
		(t.ConfigSHA256 != "" && !digestPattern.MatchString(t.ConfigSHA256)) {
		return errors.New("endpoint revision or config digest is invalid")
	}
	if !validLocalExecutorLoopback(t.LocalListen.Host) || t.LocalListen.Port < 1024 || t.LocalListen.Port > 65535 {
		return errors.New("local_listen_endpoint must be a canonical loopback IP and unprivileged port")
	}
	switch t.DeploymentMode {
	case ModeSystemd:
		if t.Systemd == nil || t.Docker != nil {
			return errors.New("systemd target must define only systemd configuration")
		}
		if err := t.Systemd.Validate(); err != nil {
			return err
		}
		if err := validateLocalExecutorSystemdTarget(t); err != nil {
			return err
		}
	case ModeDocker:
		if t.Docker == nil || t.Systemd != nil || t.DatabaseName != "" {
			return errors.New("Docker target must define only Docker configuration")
		}
		if err := t.Docker.Validate(); err != nil {
			return err
		}
		if err := validateLocalExecutorDockerTarget(t); err != nil {
			return err
		}
	default:
		return errors.New("deployment_mode is invalid")
	}
	return nil
}

func (t LocalExecutorTarget) runtimeTarget(hostID string) Target {
	base := "http://" + t.LocalListen.address()
	target := Target{
		TargetID:       t.ServiceID,
		HostID:         hostID,
		ServiceType:    t.ServiceType,
		DeploymentMode: t.DeploymentMode,
		HealthURL:      base + "/health",
		VersionURL:     base + "/updater/version",
		Systemd:        t.Systemd,
	}
	if t.Systemd != nil {
		if profile, ok := standardSystemdProfileFor(t.ServiceType); ok && profile.backupExecutable != "" {
			target.BackupArgv = []string{profile.backupExecutable, t.DatabaseName}
		}
	} else if profile, ok := localExecutorDockerProfileFor(t.ServiceType); ok {
		target.Docker = &DockerTarget{
			DockerPath:              "/usr/bin/docker",
			ComposeProject:          "autostream",
			ProjectDir:              "/opt/autostream",
			ComposeFiles:            []string{"/opt/autostream/compose.yml"},
			Service:                 profile.service,
			ImageRepo:               profile.imageRepo,
			ImageVariable:           "AUTOSTREAM_DOCKER_VERSION",
			BaseEnvFile:             "/opt/autostream/.env",
			VersionEnvFile:          profile.versionEnvFile,
			PortEnvFile:             t.Docker.PortEnvFile,
			ComposeConfigSHA256:     t.Docker.ComposeConfigSHA256,
			PortComposePolicySHA256: t.Docker.PortComposePolicySHA256,
			PortComposeRevision:     t.Docker.PortComposeRevision,
			CurrentVersion:          t.Docker.CurrentVersion,
			Channel:                 "docker",
		}
	}
	return target
}

func validateLocalExecutorSystemdTarget(target LocalExecutorTarget) error {
	profile, ok := standardSystemdProfileFor(target.ServiceType)
	if !ok {
		return errors.New("systemd target service_type is unsupported")
	}
	systemd := target.Systemd
	if systemd.SystemctlPath != "/usr/bin/systemctl" ||
		systemd.RunuserPath != "/usr/sbin/runuser" ||
		systemd.SmokeUser != "autostream" ||
		systemd.Unit != profile.unit ||
		systemd.ReleaseRoot != profile.releaseRoot ||
		systemd.CurrentLink != profile.currentLink ||
		systemd.BinaryPath != profile.binaryPath ||
		len(systemd.RequiredPaths) != len(profile.requiredPaths) {
		return errors.New("systemd target does not match the fixed privileged service profile")
	}
	for index := range profile.requiredPaths {
		if systemd.RequiredPaths[index] != profile.requiredPaths[index] {
			return errors.New("systemd target does not match the fixed privileged service profile")
		}
	}
	if profile.backupExecutable == "" {
		if target.DatabaseName != "" {
			return errors.New("database_name is not allowed for this systemd service")
		}
		return nil
	}
	if !databaseNamePattern.MatchString(target.DatabaseName) {
		return errors.New("database_name is required for this systemd service")
	}
	return nil
}

func validateLocalExecutorDockerTarget(target LocalExecutorTarget) error {
	if _, ok := localExecutorDockerProfileFor(target.ServiceType); !ok {
		return errors.New("Docker target service_type is unsupported")
	}
	if !matchesLocalExecutorDockerProfile(target.ServiceType, target.Docker) {
		return errors.New("Docker target does not match the fixed privileged service profile")
	}
	return nil
}

func matchesLocalExecutorDockerProfile(serviceType string, docker *DockerTarget) bool {
	profile, ok := localExecutorDockerProfileFor(serviceType)
	if !ok || docker == nil {
		return false
	}
	if docker.DockerPath != "/usr/bin/docker" ||
		docker.ComposeProject != "autostream" ||
		docker.ProjectDir != "/opt/autostream" ||
		len(docker.ComposeFiles) != 1 ||
		docker.ComposeFiles[0] != "/opt/autostream/compose.yml" ||
		docker.Service != profile.service ||
		docker.ImageRepo != profile.imageRepo ||
		docker.ImageVariable != "AUTOSTREAM_DOCKER_VERSION" ||
		docker.BaseEnvFile != "/opt/autostream/.env" ||
		docker.VersionEnvFile != profile.versionEnvFile ||
		docker.Channel != "docker" {
		return false
	}
	if docker.PortEnvFile != "" &&
		docker.PortEnvFile != profile.portEnvFile {
		return false
	}
	return true
}

func localExecutorDockerProfileFor(serviceType string) (localExecutorDockerProfile, bool) {
	var service string
	switch serviceType {
	case "control_panel":
		service = "control-panel"
	case "encoder_recorder":
		service = "encoder-recorder"
	case "observability":
		service = "observability"
	case "discord_bot":
		service = "discord-bot"
	case "worker":
		service = "worker"
	default:
		return localExecutorDockerProfile{}, false
	}
	return localExecutorDockerProfile{
		service:        service,
		imageRepo:      "ghcr.io/kome-lab/autostream-docker/" + service,
		versionEnvFile: "/opt/autostream/local-executor/docker/" + service + ".env",
		portEnvFile:    "/opt/autostream/local-executor/docker/ports/" + service + ".env",
	}, true
}

func (e LocalExecutorEndpoint) address() string {
	return netip.AddrPortFrom(netip.MustParseAddr(e.Host), uint16(e.Port)).String()
}

func validLocalExecutorLoopback(value string) bool {
	if value != strings.TrimSpace(value) {
		return false
	}
	address, err := netip.ParseAddr(value)
	return err == nil && address.IsLoopback() && value == address.String()
}

func validLocalExecutorServiceType(value string) bool {
	switch value {
	case "control_panel", "worker", "encoder_recorder", "discord_bot", "observability":
		return true
	default:
		return false
	}
}
