package hostruntime

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	unitPattern       = regexp.MustCompile(`^[A-Za-z0-9_.@-]+\.service$`)
	imagePattern      = regexp.MustCompile(`^ghcr\.io/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+$`)
	envNamePattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// Target and its deployment profiles are derived only from the root-owned
// Local Executor policy. They are never accepted from the Control Panel wire.
type Target struct {
	TargetID       string         `json:"target_id"`
	HostID         string         `json:"host_id,omitempty"`
	ServiceType    string         `json:"service_type"`
	DeploymentMode string         `json:"deployment_mode"`
	HealthURL      string         `json:"health_url,omitempty"`
	VersionURL     string         `json:"version_url,omitempty"`
	BackupArgv     []string       `json:"backup_argv,omitempty"`
	Systemd        *SystemdTarget `json:"systemd,omitempty"`
	Docker         *DockerTarget  `json:"docker,omitempty"`
}

type SystemdTarget struct {
	SystemctlPath string   `json:"systemctl_path"`
	RunuserPath   string   `json:"runuser_path"`
	SmokeUser     string   `json:"smoke_user"`
	Unit          string   `json:"unit"`
	ReleaseRoot   string   `json:"release_root"`
	CurrentLink   string   `json:"current_link"`
	BinaryPath    string   `json:"binary_path"`
	RequiredPaths []string `json:"required_paths,omitempty"`
}

type DockerTarget struct {
	DockerPath              string   `json:"docker_path"`
	ComposeProject          string   `json:"compose_project"`
	ProjectDir              string   `json:"project_dir"`
	ComposeFiles            []string `json:"compose_files"`
	Service                 string   `json:"service"`
	ImageRepo               string   `json:"image_repo"`
	ImageVariable           string   `json:"image_variable"`
	BaseEnvFile             string   `json:"base_env_file,omitempty"`
	VersionEnvFile          string   `json:"version_env_file"`
	PortEnvFile             string   `json:"port_env_file,omitempty"`
	ComposeConfigSHA256     string   `json:"compose_config_sha256"`
	PortComposePolicySHA256 string   `json:"port_compose_policy_sha256,omitempty"`
	PortComposeRevision     int64    `json:"port_compose_revision,omitempty"`
	CurrentVersion          string   `json:"current_version,omitempty"`
	Channel                 string   `json:"channel,omitempty"`
}

func (t Target) Validate() error {
	if !identifierPattern.MatchString(t.TargetID) {
		return errors.New("target_id is invalid")
	}
	switch t.ServiceType {
	case "control_panel", "worker", "encoder_recorder", "discord_bot", "observability":
	default:
		return fmt.Errorf("unsupported service_type %q", t.ServiceType)
	}
	if err := validateLoopbackEndpoint(t.HealthURL, "health_url"); err != nil {
		return err
	}
	if err := validateLoopbackEndpoint(t.VersionURL, "version_url"); err != nil {
		return err
	}
	if (t.ServiceType == "control_panel" || t.ServiceType == "observability") && len(t.BackupArgv) == 0 {
		return errors.New("backup_argv is required for database-owning services")
	}
	if len(t.BackupArgv) > 0 {
		if !filepath.IsAbs(t.BackupArgv[0]) {
			return errors.New("backup_argv must begin with an absolute executable path")
		}
		for _, arg := range t.BackupArgv {
			if strings.TrimSpace(arg) == "" || strings.ContainsRune(arg, '\x00') {
				return errors.New("backup_argv contains an invalid argument")
			}
		}
	}
	switch t.DeploymentMode {
	case ModeSystemd:
		if t.Systemd == nil || t.Docker != nil {
			return errors.New("systemd target must define only systemd configuration")
		}
		return t.Systemd.Validate()
	case ModeDocker:
		if t.Docker == nil || t.Systemd != nil {
			return errors.New("Docker target must define only Docker configuration")
		}
		return t.Docker.Validate()
	default:
		return errors.New("deployment_mode is invalid")
	}
}

func (t SystemdTarget) Validate() error {
	if !deploymentAbsolutePath(t.SystemctlPath) || !deploymentAbsolutePath(t.RunuserPath) ||
		!regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`).MatchString(t.SmokeUser) ||
		t.SmokeUser == "root" || !unitPattern.MatchString(t.Unit) {
		return errors.New("systemd target profile is invalid")
	}
	for _, value := range []string{t.ReleaseRoot, t.CurrentLink} {
		if !deploymentAbsolutePath(value) || filepath.Clean(value) == string(filepath.Separator) {
			return errors.New("systemd target path is invalid")
		}
	}
	if filepath.Clean(t.ReleaseRoot) == filepath.Clean(t.CurrentLink) {
		return errors.New("release_root and current_link must differ")
	}
	for _, value := range append([]string{t.BinaryPath}, t.RequiredPaths...) {
		if !safeRelativePath(value) {
			return errors.New("systemd artifact path is unsafe")
		}
	}
	return nil
}

func (t DockerTarget) Validate() error {
	if !deploymentAbsolutePath(t.DockerPath) || !identifierPattern.MatchString(t.ComposeProject) ||
		!identifierPattern.MatchString(t.Service) || !deploymentAbsolutePath(t.ProjectDir) ||
		len(t.ComposeFiles) == 0 || !imagePattern.MatchString(t.ImageRepo) ||
		!envNamePattern.MatchString(t.ImageVariable) || t.ImageVariable != "AUTOSTREAM_DOCKER_VERSION" {
		return errors.New("Docker target profile is invalid")
	}
	for _, file := range t.ComposeFiles {
		if !deploymentAbsolutePath(file) {
			return errors.New("compose_files entries must be absolute")
		}
	}
	for _, file := range []string{t.BaseEnvFile, t.VersionEnvFile} {
		if file != "" && (!deploymentAbsolutePath(file) || filepath.Clean(file) == string(filepath.Separator)) {
			return errors.New("Docker environment file is invalid")
		}
	}
	portFields := 0
	if t.PortEnvFile != "" {
		portFields++
	}
	if t.PortComposePolicySHA256 != "" {
		portFields++
	}
	if t.PortComposeRevision != 0 {
		portFields++
	}
	if portFields != 0 {
		if portFields != 3 || !deploymentAbsolutePath(t.PortEnvFile) ||
			filepath.Clean(t.PortEnvFile) == string(filepath.Separator) ||
			len(t.PortComposePolicySHA256) != 64 ||
			strings.ToLower(t.PortComposePolicySHA256) != t.PortComposePolicySHA256 ||
			t.PortComposeRevision < 1 {
			return errors.New("Docker port authority is invalid")
		}
		if _, err := hex.DecodeString(t.PortComposePolicySHA256); err != nil {
			return errors.New("Docker port authority digest is invalid")
		}
	}
	if t.Channel != "" && t.Channel != "docker" {
		return errors.New("docker channel must be docker")
	}
	if !versionPattern.MatchString(strings.TrimSpace(t.CurrentVersion)) ||
		len(t.ComposeConfigSHA256) != 64 ||
		strings.ToLower(t.ComposeConfigSHA256) != t.ComposeConfigSHA256 {
		return errors.New("Docker version or compose digest is invalid")
	}
	if _, err := hex.DecodeString(t.ComposeConfigSHA256); err != nil {
		return errors.New("compose_config_sha256 is invalid")
	}
	return nil
}

func validateLoopbackEndpoint(raw, name string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") ||
		u.User != nil || !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("%s must use an absolute loopback HTTP(S) URL", name)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func safeRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, `\`) || strings.ContainsRune(value, '\x00') {
		return false
	}
	clean := filepath.Clean(value)
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}
