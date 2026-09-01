package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type dockerPortAdapter struct {
	Service           string
	PublishedVariable string
	ContainerVariable string
	PortEnvFile       string
}

func dockerPortAdapterFor(
	serviceType string,
	target *DockerTarget,
) (dockerPortAdapter, error) {
	profile, ok := localExecutorDockerProfileFor(serviceType)
	if !ok || target == nil || target.Service != profile.service ||
		target.PortEnvFile != profile.portEnvFile ||
		target.PortComposeRevision < 1 ||
		!mutationPlanHashPattern.MatchString(target.PortComposePolicySHA256) {
		return dockerPortAdapter{}, errors.New("Docker port root authority is unavailable")
	}
	var publishedVariable, containerVariable string
	switch serviceType {
	case "worker":
		publishedVariable = "AUTOSTREAM_WORKER_PORT"
		containerVariable = "AUTOSTREAM_WORKER_CONTAINER_PORT"
	case "encoder_recorder":
		publishedVariable = "AUTOSTREAM_ENCODER_RECORDER_PORT"
		containerVariable = "AUTOSTREAM_ENCODER_RECORDER_CONTAINER_PORT"
	case "discord_bot":
		publishedVariable = "AUTOSTREAM_DISCORD_BOT_PORT"
		containerVariable = "AUTOSTREAM_DISCORD_BOT_CONTAINER_PORT"
	case "observability":
		publishedVariable = "AUTOSTREAM_OBSERVABILITY_PORT"
		containerVariable = "AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT"
	default:
		return dockerPortAdapter{}, errors.New("Docker port service type is unsupported")
	}
	return dockerPortAdapter{
		Service: profile.service, PublishedVariable: publishedVariable,
		ContainerVariable: containerVariable, PortEnvFile: profile.portEnvFile,
	}, nil
}

func dockerPortEnvBytes(
	adapter dockerPortAdapter,
	publishedPort, containerPort int,
	configRevision int64,
) ([]byte, error) {
	if !envNamePattern.MatchString(adapter.PublishedVariable) ||
		!envNamePattern.MatchString(adapter.ContainerVariable) ||
		!validSystemdPort(publishedPort) ||
		!validSystemdPort(containerPort) ||
		configRevision < 1 {
		return nil, errors.New("Docker port environment is invalid")
	}
	return []byte(fmt.Sprintf(
		"%s=%d\n%s=%d\nAUTOSTREAM_CONFIG_REVISION=%d\n",
		adapter.PublishedVariable,
		publishedPort,
		adapter.ContainerVariable,
		containerPort,
		configRevision,
	)), nil
}

func dockerPortEnvSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func parseDockerPortEnv(
	adapter dockerPortAdapter,
	body []byte,
) (int, int, int64, error) {
	if len(body) == 0 || len(body) > 64<<10 {
		return 0, 0, 0, errors.New("Docker port mapping is empty or oversized")
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return 0, 0, 0, errors.New("Docker port mapping must contain exactly three assignments")
	}
	publishedPort, err := parseCanonicalDockerPortAssignment(
		lines[0], adapter.PublishedVariable,
	)
	if err != nil {
		return 0, 0, 0, err
	}
	containerPort, err := parseCanonicalDockerPortAssignment(
		lines[1], adapter.ContainerVariable,
	)
	if err != nil {
		return 0, 0, 0, err
	}
	revisionText, ok := strings.CutPrefix(
		lines[2], "AUTOSTREAM_CONFIG_REVISION=",
	)
	if !ok || revisionText == "" || strings.HasPrefix(revisionText, "0") {
		return 0, 0, 0, errors.New("Docker port mapping config revision is invalid")
	}
	configRevision, err := strconv.ParseInt(revisionText, 10, 64)
	if err != nil || configRevision < 1 ||
		strconv.FormatInt(configRevision, 10) != revisionText {
		return 0, 0, 0, errors.New("Docker port mapping config revision is invalid")
	}
	expected, err := dockerPortEnvBytes(
		adapter, publishedPort, containerPort, configRevision,
	)
	if err != nil || !bytes.Equal(expected, body) {
		return 0, 0, 0, errors.New("Docker port mapping is not canonical")
	}
	return publishedPort, containerPort, configRevision, nil
}

func parseCanonicalDockerPortAssignment(line, variable string) (int, error) {
	value, ok := strings.CutPrefix(line, variable+"=")
	if !ok || value == "" || strings.HasPrefix(value, "0") {
		return 0, errors.New("Docker port mapping assignment is invalid")
	}
	port, err := strconv.Atoi(value)
	if err != nil || !validSystemdPort(port) || strconv.Itoa(port) != value {
		return 0, errors.New("Docker port mapping assignment is invalid")
	}
	return port, nil
}

// dockerPortComposePolicyHash binds every resolved Compose field except the
// four values this transaction is explicitly allowed to change: the managed
// published port, container target, bind address port and config revision.
// Image tags are normalized exactly like composeModelHash so a software update
// does not silently revoke otherwise identical port authority.
func dockerPortComposePolicyHash(
	raw []byte,
	target *DockerTarget,
) (string, error) {
	if target == nil || !isCanonicalNodeDockerPortTarget(target) {
		return "", errors.New("Docker port policy target is invalid")
	}
	if err := validateComposeModelSecurity(raw, target); err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model map[string]any
	if err := decoder.Decode(&model); err != nil {
		return "", errors.New("Docker port policy model is invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", errors.New("Docker port policy model contains trailing JSON")
	}
	services, ok := model["services"].(map[string]any)
	if !ok {
		return "", errors.New("Docker port policy model has no services")
	}
	canonicalRepos := map[string]bool{
		"ghcr.io/kome-lab/autostream-docker/control-panel":    true,
		"ghcr.io/kome-lab/autostream-docker/worker":           true,
		"ghcr.io/kome-lab/autostream-docker/encoder-recorder": true,
		"ghcr.io/kome-lab/autostream-docker/discord-bot":      true,
		"ghcr.io/kome-lab/autostream-docker/observability":    true,
	}
	for name, rawService := range services {
		service, ok := rawService.(map[string]any)
		if !ok {
			return "", errors.New("Docker port policy service is invalid")
		}
		image, _ := service["image"].(string)
		if name == target.Service {
			if image == "" {
				return "", errors.New("managed Docker port service has no image")
			}
			service["image"] = "__AUTOSTREAM_MANAGED_IMAGE__"
		} else if repo := strings.ToLower(dockerImageBase(image)); strings.HasPrefix(repo, "ghcr.io/kome-lab/autostream-docker/") {
			if !canonicalRepos[repo] {
				return "", errors.New("Docker port policy contains a noncanonical AutoStream image")
			}
			service["image"] = repo + ":__AUTOSTREAM_BUNDLE__"
		}
	}
	managed, ok := services[target.Service].(map[string]any)
	if !ok {
		return "", errors.New("Docker port policy has no managed service")
	}
	ports, ok := managed["ports"].([]any)
	if !ok || len(ports) != 1 {
		return "", errors.New("managed Docker port policy must contain one mapping")
	}
	port, ok := ports[0].(map[string]any)
	if !ok {
		return "", errors.New("managed Docker port policy mapping is invalid")
	}
	port["published"] = "__AUTOSTREAM_PUBLISHED_PORT__"
	port["target"] = "__AUTOSTREAM_CONTAINER_PORT__"
	environment, ok := managed["environment"].(map[string]any)
	if !ok {
		return "", errors.New("managed Docker port policy environment is invalid")
	}
	bindVariable, ok := dockerContainerBindVariable(target.Service)
	if !ok {
		return "", errors.New("managed Docker port policy bind contract is unavailable")
	}
	if _, ok := environment[bindVariable].(string); !ok {
		return "", errors.New("managed Docker port policy bind address is unavailable")
	}
	revision, ok := environment["AUTOSTREAM_CONFIG_REVISION"]
	if !ok {
		return "", errors.New("managed Docker port policy config revision is unavailable")
	}
	revisionText := fmt.Sprint(revision)
	revisionNumber, err := strconv.ParseInt(revisionText, 10, 64)
	if err != nil || revisionNumber < 1 || strconv.FormatInt(revisionNumber, 10) != revisionText {
		return "", errors.New("managed Docker port policy config revision is invalid")
	}
	environment[bindVariable] = "0.0.0.0:__AUTOSTREAM_CONTAINER_PORT__"
	environment["AUTOSTREAM_CONFIG_REVISION"] = "__AUTOSTREAM_CONFIG_REVISION__"
	canonical, err := json.Marshal(model)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
