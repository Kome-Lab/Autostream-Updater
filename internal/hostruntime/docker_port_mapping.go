package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var dockerContainerIDPattern = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

type dockerPortMapping struct {
	HostIP        string
	PublishedPort int
	ContainerPort int
	Protocol      string
}

type dockerComposePort struct {
	HostIP    string `json:"host_ip"`
	Target    any    `json:"target"`
	Published any    `json:"published"`
	Protocol  string `json:"protocol"`
	Mode      string `json:"mode"`
}

type dockerComposePortService struct {
	Environment map[string]any      `json:"environment"`
	Ports       []dockerComposePort `json:"ports"`
}

type dockerPublishedBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// validateDockerComposePortMappings extracts the managed service's resolved
// mapping from the canonical Compose JSON. Published host ports and container
// listen ports remain separate facts, while the complete project is checked
// for mappings that can collide before Docker performs any mutation.
func validateDockerComposePortMappings(raw []byte, target *DockerTarget) ([]dockerPortMapping, error) {
	if target == nil || !identifierPattern.MatchString(target.Service) {
		return nil, errors.New("Docker port mapping target is invalid")
	}
	// Only the four canonical Node images have an explicit, non-secret
	// container-bind contract today. Control Panel bind changes are deferred to
	// its final canary, and legacy/custom Docker targets retain their bridge
	// software-update behavior instead of being forced into a contract they
	// never declared.
	if !isCanonicalNodeDockerPortTarget(target) {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model struct {
		Services map[string]dockerComposePortService `json:"services"`
	}
	if err := decoder.Decode(&model); err != nil {
		return nil, errors.New("Docker port mapping model is invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("Docker port mapping model contains trailing JSON")
	}
	_, ok := model.Services[target.Service]
	if !ok {
		return nil, errors.New("Docker port mapping model has no managed service")
	}

	type observedMapping struct {
		service  string
		hostIP   string
		port     int
		protocol string
	}
	var observed []observedMapping
	var managedMappings []dockerPortMapping
	for serviceName, service := range model.Services {
		for _, rawPort := range service.Ports {
			containerPort, err := dockerComposePortNumber(rawPort.Target)
			if err != nil {
				return nil, fmt.Errorf("Docker service %q has an invalid container port", serviceName)
			}
			publishedPort, err := dockerComposePortNumber(rawPort.Published)
			if err != nil {
				return nil, fmt.Errorf("Docker service %q has an invalid published port", serviceName)
			}
			protocol := strings.ToLower(strings.TrimSpace(rawPort.Protocol))
			if protocol == "" {
				protocol = "tcp"
			}
			if protocol != "tcp" && protocol != "udp" {
				return nil, fmt.Errorf("Docker service %q has an unsupported published protocol", serviceName)
			}
			hostIP, err := canonicalDockerHostIP(rawPort.HostIP)
			if err != nil {
				return nil, fmt.Errorf("Docker service %q has an invalid published host address", serviceName)
			}
			for _, prior := range observed {
				if prior.port == publishedPort &&
					prior.protocol == protocol &&
					dockerHostBindingsConflict(prior.hostIP, hostIP) {
					return nil, fmt.Errorf("Docker published port %d/%s is assigned more than once in the Compose project", publishedPort, protocol)
				}
			}
			observed = append(observed, observedMapping{
				service: serviceName, hostIP: hostIP, port: publishedPort, protocol: protocol,
			})
			if serviceName != target.Service {
				continue
			}
			if containerPort < 1024 || publishedPort < 1024 ||
				containerPort > 65535 || publishedPort > 65535 ||
				protocol != "tcp" ||
				(rawPort.Mode != "" && rawPort.Mode != "ingress") {
				return nil, errors.New("managed Docker ports must be unprivileged TCP ingress ports")
			}
			managedMappings = append(managedMappings, dockerPortMapping{
				HostIP: hostIP, PublishedPort: publishedPort,
				ContainerPort: containerPort, Protocol: protocol,
			})
		}
	}
	if len(managedMappings) == 0 {
		return nil, nil
	}
	if len(managedMappings) != 1 {
		return nil, errors.New("managed Docker service must have exactly one published API port")
	}
	listener, _, err := dockerNodeListenerFromCompose(raw, target.Service)
	if err != nil {
		return nil, err
	}
	bindPort, err := dockerListenPort(listener.BindAddress)
	if err != nil || bindPort != managedMappings[0].ContainerPort {
		return nil, errors.New("managed Docker container bind port differs from its published target port")
	}
	return managedMappings, nil
}

func dockerComposePortNumber(value any) (int, error) {
	text := ""
	switch typed := value.(type) {
	case json.Number:
		text = typed.String()
	case string:
		text = typed
	default:
		return 0, errors.New("port is not an integer")
	}
	if text != strings.TrimSpace(text) || strings.HasPrefix(text, "+") {
		return 0, errors.New("port is not canonical")
	}
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != text {
		return 0, errors.New("port is outside the valid range")
	}
	return port, nil
}

func canonicalDockerHostIP(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if value != strings.TrimSpace(value) {
		return "", errors.New("host address is not canonical")
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Is4In6() {
		return "", errors.New("host address is not an IP literal")
	}
	return address.String(), nil
}

func dockerHostBindingsConflict(left, right string) bool {
	if left == "" || right == "" || left == right {
		return true
	}
	leftAddress, leftErr := netip.ParseAddr(left)
	rightAddress, rightErr := netip.ParseAddr(right)
	if leftErr != nil || rightErr != nil {
		return true
	}
	if leftAddress.IsUnspecified() || rightAddress.IsUnspecified() {
		return true
	}
	return false
}

func isCanonicalNodeDockerPortTarget(target *DockerTarget) bool {
	if target == nil {
		return false
	}
	service := dockerManifestService(target.Service)
	switch service {
	case "worker", "encoder-recorder", "discord-bot", "observability":
		return target.Service == service &&
			target.ImageRepo == "ghcr.io/kome-lab/autostream-docker/"+service
	default:
		return false
	}
}

func dockerListenPort(value string) (int, error) {
	if value != strings.TrimSpace(value) {
		return 0, errors.New("container bind address is not canonical")
	}
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsUnspecified() || address.Port() < 1024 {
		return 0, errors.New("container bind address is invalid")
	}
	return int(address.Port()), nil
}

func preflightDockerPublishedPortOwnership(
	ctx context.Context,
	runner CommandRunner,
	target *DockerTarget,
	mappings []dockerPortMapping,
	currentContainerID string,
) error {
	currentContainerID = strings.ToLower(strings.TrimSpace(currentContainerID))
	if runner == nil || target == nil ||
		!dockerContainerIDPattern.MatchString(currentContainerID) {
		return errors.New("Docker published-port ownership baseline is invalid")
	}
	output, err := runner.Run(
		ctx,
		target.ProjectDir,
		dockerCommandEnv(),
		target.DockerPath,
		"container", "ls", "--quiet", "--no-trunc",
	)
	if err != nil {
		return errors.New("could not verify Docker published-port ownership by enumerating running containers")
	}
	owners := strings.Fields(strings.ToLower(output))
	if len(owners) == 0 {
		return errors.New("Docker published ports are not owned by the managed container")
	}
	if len(owners) > 256 {
		return errors.New("could not verify Docker published-port ownership for an unbounded container set")
	}
	seenOwners := make(map[string]bool, len(owners))
	foundCurrent := make([]bool, len(mappings))
	for _, owner := range owners {
		if !dockerContainerIDPattern.MatchString(owner) || seenOwners[owner] {
			return errors.New("could not verify running Docker container identities")
		}
		seenOwners[owner] = true
	}
	inspectArgs := append(
		[]string{"container", "inspect", "--format={{json .NetworkSettings.Ports}}"},
		owners...,
	)
	rawBindings, err := runner.Run(
		ctx,
		target.ProjectDir,
		dockerCommandEnv(),
		target.DockerPath,
		inspectArgs...,
	)
	if err != nil {
		return errors.New("could not inspect Docker published-port ownership")
	}
	ownerBindings, err := decodeDockerPublishedBindings([]byte(rawBindings), len(owners))
	if err != nil {
		return err
	}
	for ownerIndex, bindings := range ownerBindings {
		owner := owners[ownerIndex]
		for endpoint, hostBindings := range bindings {
			parts := strings.Split(endpoint, "/")
			if len(parts) != 2 {
				return errors.New("Docker container port binding is invalid")
			}
			boundContainerPort, err := dockerComposePortNumber(parts[0])
			if err != nil ||
				(parts[1] != "tcp" && parts[1] != "udp") {
				return errors.New("Docker container port binding is invalid")
			}
			for _, hostBinding := range hostBindings {
				hostPort, err := dockerComposePortNumber(hostBinding.HostPort)
				if err != nil {
					return errors.New("Docker published host port binding is invalid")
				}
				hostIP, err := canonicalDockerHostIP(hostBinding.HostIP)
				if err != nil {
					return errors.New("Docker published host address binding is invalid")
				}
				currentOwner := dockerContainerIDsMatch(owner, currentContainerID)
				matchedCurrent := false
				for index, mapping := range mappings {
					if currentOwner {
						if mapping.PublishedPort == hostPort &&
							mapping.ContainerPort == boundContainerPort &&
							mapping.Protocol == parts[1] &&
							dockerCurrentHostBindingMatches(mapping.HostIP, hostIP) {
							foundCurrent[index] = true
							matchedCurrent = true
						}
						continue
					}
					if mapping.PublishedPort == hostPort &&
						mapping.Protocol == parts[1] &&
						dockerHostBindingsConflict(mapping.HostIP, hostIP) {
						return fmt.Errorf(
							"Docker published port %d/%s is already owned by another container",
							mapping.PublishedPort,
							mapping.Protocol,
						)
					}
				}
				if currentOwner && !matchedCurrent {
					return errors.New("managed Docker container published binding does not match the trusted Compose model")
				}
			}
		}
	}
	for index, mapping := range mappings {
		if !foundCurrent[index] {
			return fmt.Errorf(
				"Docker published port %d/%s is not owned by the managed container",
				mapping.PublishedPort,
				mapping.Protocol,
			)
		}
	}
	return nil
}

// preflightDockerProposedPortAvailability verifies that a candidate loopback
// binding is not owned by another running container. The currently managed
// container is ignored by identity because its old bindings are released by
// the later Compose recreate; no binding is treated as managed merely because
// it resembles the candidate mapping.
func preflightDockerProposedPortAvailability(
	ctx context.Context,
	runner CommandRunner,
	target *DockerTarget,
	mapping dockerPortMapping,
	currentContainerID string,
) error {
	if runner == nil || target == nil ||
		mapping.HostIP != "127.0.0.1" ||
		mapping.PublishedPort < 1024 || mapping.PublishedPort > 65535 ||
		mapping.ContainerPort < 1024 || mapping.ContainerPort > 65535 ||
		mapping.Protocol != "tcp" ||
		len(currentContainerID) != 64 ||
		!dockerContainerIDPattern.MatchString(currentContainerID) {
		return errors.New("Docker proposed published-port baseline is invalid")
	}
	output, err := runner.Run(
		ctx,
		target.ProjectDir,
		dockerCommandEnv(),
		target.DockerPath,
		"container", "ls", "--quiet", "--no-trunc",
	)
	if err != nil {
		return errors.New("could not verify Docker proposed published-port availability by enumerating running containers")
	}
	owners := strings.Fields(output)
	if len(owners) > 256 {
		return errors.New("could not verify Docker proposed published-port availability for an unbounded container set")
	}

	seenOwners := make(map[string]bool, len(owners))
	currentOwnerIndex := -1
	for ownerIndex, owner := range owners {
		if len(owner) != 64 ||
			!dockerContainerIDPattern.MatchString(owner) ||
			seenOwners[owner] {
			return errors.New("could not verify running Docker container identities")
		}
		seenOwners[owner] = true
		if owner != currentContainerID {
			continue
		}
		currentOwnerIndex = ownerIndex
	}
	if currentOwnerIndex < 0 {
		return errors.New("could not identify the managed Docker container among running container identities")
	}

	foreignOwners := make([]string, 0, len(owners)-1)
	for ownerIndex, owner := range owners {
		if ownerIndex != currentOwnerIndex {
			foreignOwners = append(foreignOwners, owner)
		}
	}
	if len(foreignOwners) == 0 {
		return nil
	}

	inspectArgs := append(
		[]string{"container", "inspect", "--format={{json .NetworkSettings.Ports}}"},
		foreignOwners...,
	)
	rawBindings, err := runner.Run(
		ctx,
		target.ProjectDir,
		dockerCommandEnv(),
		target.DockerPath,
		inspectArgs...,
	)
	if err != nil {
		return errors.New("could not inspect Docker proposed published-port availability")
	}
	ownerBindings, err := decodeDockerPublishedBindings([]byte(rawBindings), len(foreignOwners))
	if err != nil {
		return err
	}
	for _, bindings := range ownerBindings {
		for endpoint, hostBindings := range bindings {
			parts := strings.Split(endpoint, "/")
			if len(parts) != 2 {
				return errors.New("Docker container port binding is invalid")
			}
			if _, err := dockerComposePortNumber(parts[0]); err != nil ||
				(parts[1] != "tcp" && parts[1] != "udp") {
				return errors.New("Docker container port binding is invalid")
			}
			for _, hostBinding := range hostBindings {
				hostPort, err := dockerComposePortNumber(hostBinding.HostPort)
				if err != nil {
					return errors.New("Docker published host port binding is invalid")
				}
				hostIP, err := canonicalDockerHostIP(hostBinding.HostIP)
				if err != nil {
					return errors.New("Docker published host address binding is invalid")
				}
				if mapping.PublishedPort == hostPort &&
					mapping.Protocol == parts[1] &&
					dockerHostBindingsConflict(mapping.HostIP, hostIP) {
					return fmt.Errorf(
						"Docker proposed published port %d/%s is already owned by another container",
						mapping.PublishedPort,
						mapping.Protocol,
					)
				}
			}
		}
	}
	return nil
}

func dockerCurrentHostBindingMatches(expected, actual string) bool {
	if expected == "" {
		if actual == "" {
			return true
		}
		address, err := netip.ParseAddr(actual)
		return err == nil && address.IsUnspecified()
	}
	return expected == actual
}

func decodeDockerPublishedBindings(raw []byte, expected int) ([]map[string][]dockerPublishedBinding, error) {
	if expected < 1 || expected > 256 {
		return nil, errors.New("Docker published-port ownership response count is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	results := make([]map[string][]dockerPublishedBinding, 0, expected)
	for range expected {
		var bindings map[string][]dockerPublishedBinding
		if err := decoder.Decode(&bindings); err != nil || bindings == nil {
			return nil, errors.New("Docker published-port ownership response is invalid")
		}
		results = append(results, bindings)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("Docker published-port ownership response contains trailing data")
	}
	return results, nil
}

func dockerContainerIDsMatch(left, right string) bool {
	if !dockerContainerIDPattern.MatchString(left) ||
		!dockerContainerIDPattern.MatchString(right) {
		return false
	}
	return strings.HasPrefix(left, right) || strings.HasPrefix(right, left)
}

func preflightTrustedDockerComposePorts(
	ctx context.Context,
	runner CommandRunner,
	target *DockerTarget,
	frozenPath string,
	currentContainerID string,
) error {
	raw, err := os.ReadFile(frozenPath)
	if err != nil {
		return errors.New("trusted frozen compose port mapping is unavailable")
	}
	mappings, err := validateDockerComposePortMappings(raw, target)
	if err != nil {
		return err
	}
	if len(mappings) == 0 {
		return nil
	}
	return preflightDockerPublishedPortOwnership(ctx, runner, target, mappings, currentContainerID)
}
