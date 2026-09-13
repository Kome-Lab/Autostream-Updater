//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func dockerPortSmokeContainerID(
	t *testing.T,
	runner OSCommandRunner,
) string {
	t.Helper()
	shortID := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, dockerPortSmokeProjectDir, "/usr/bin/docker",
		"ps", "-q",
		"--filter", "label=com.docker.compose.project=autostream",
		"--filter", "label=com.docker.compose.service=worker",
	))
	fullID := strings.ToLower(strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, dockerPortSmokeProjectDir, "/usr/bin/docker",
		"inspect", "--format={{.Id}}", shortID,
	)))
	if len(fullID) != 64 || !dockerContainerIDPattern.MatchString(fullID) {
		t.Fatalf("managed container ID=%q", fullID)
	}
	return fullID
}

func assertDockerPortFixtureBoundary(
	t *testing.T,
	runner OSCommandRunner,
	containerID string,
	publishedPort, containerPort int,
	listenerRoot string,
) {
	t.Helper()
	mounts := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"inspect", "--format={{json .Mounts}}", containerID,
	))
	privileged := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"inspect", "--format={{.HostConfig.Privileged}}", containerID,
	))
	mapping := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"port", containerID, fmt.Sprintf("%d/tcp", containerPort),
	))
	var mounted []struct {
		Type, Source, Destination string
		RW                        bool
	}
	if json.Unmarshal([]byte(mounts), &mounted) != nil || len(mounted) != 1 ||
		mounted[0].Type != "bind" || mounted[0].RW ||
		mounted[0].Destination != "/run/autostream-credentials/node-listener.json" ||
		filepath.Dir(mounted[0].Source) != filepath.Join(listenerRoot, "worker") || privileged != "false" ||
		mapping != fmt.Sprintf("127.0.0.1:%d", publishedPort) {
		t.Fatal("Docker fixture mount, privilege or loopback boundary mismatch")
	}
	var hostConfig struct {
		ReadonlyRootfs       bool
		CapDrop, SecurityOpt []string
	}
	hostRaw := mustDockerPortSmokeRun(t, runner, "", "/usr/bin/docker", "inspect", "--format={{json .HostConfig}}", containerID)
	if json.Unmarshal([]byte(hostRaw), &hostConfig) != nil || !hostConfig.ReadonlyRootfs ||
		!reflect.DeepEqual(hostConfig.CapDrop, []string{"ALL"}) ||
		!(reflect.DeepEqual(hostConfig.SecurityOpt, []string{"no-new-privileges:true"}) || reflect.DeepEqual(hostConfig.SecurityOpt, []string{"no-new-privileges"})) {
		t.Fatal("Docker fixture confinement changed")
	}
	if err := verifyDockerPortSmokeListenerFile(mounted[0].Source, publishedPort); err != nil {
		t.Fatal(err)
	}
}

func waitForDockerPortFixture(
	t *testing.T,
	publishedPort, advertisedPort, containerPort int,
	configRevision int64,
	unhealthy bool,
) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastError error
	for time.Now().Before(deadline) {
		lastError = verifyDockerPortFixture(
			publishedPort, advertisedPort, containerPort,
			configRevision, unhealthy,
		)
		if lastError == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("fixture verification failed: %v", lastError)
}

func verifyDockerPortFixture(
	publishedPort, advertisedPort, containerPort int,
	configRevision int64,
	unhealthy bool,
) error {
	client := &http.Client{Timeout: time.Second}
	base := fmt.Sprintf("http://127.0.0.1:%d", publishedPort)
	healthResponse, err := client.Get(base + "/health")
	if err != nil {
		return err
	}
	defer healthResponse.Body.Close()
	expectedStatus := http.StatusOK
	if unhealthy {
		expectedStatus = http.StatusServiceUnavailable
	}
	if healthResponse.StatusCode != expectedStatus {
		return fmt.Errorf(
			"health status=%d want=%d",
			healthResponse.StatusCode, expectedStatus,
		)
	}
	var version struct {
		Version        string `json:"version"`
		ServiceID      string `json:"service_id"`
		ServiceType    string `json:"service_type"`
		ConfigRevision int64  `json:"config_revision"`
	}
	if err := getDockerPortFixtureJSON(
		client, base+"/updater/version", &version,
	); err != nil {
		return err
	}
	if version.Version != "v1.0.0" ||
		version.ServiceID != "worker-smoke" ||
		version.ServiceType != "worker" ||
		version.ConfigRevision != configRevision {
		return fmt.Errorf("version identity=%+v", version)
	}
	var config struct {
		AdvertisedPort int   `json:"advertised_port"`
		ContainerPort  int   `json:"container_port"`
		ConfigRevision int64 `json:"config_revision"`
	}
	if err := getDockerPortFixtureJSON(
		client, base+"/config", &config,
	); err != nil {
		return err
	}
	if config.AdvertisedPort != advertisedPort ||
		config.ContainerPort != containerPort ||
		config.ConfigRevision != configRevision {
		return fmt.Errorf("config identity=%+v", config)
	}
	return nil
}

func getDockerPortFixtureJSON(
	client *http.Client,
	endpoint string,
	out any,
) error {
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d", endpoint, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func buildDockerPortFixtureImage(t *testing.T, image string) {
	t.Helper()
	contextDir := t.TempDir()
	fixtureBinary := filepath.Join(contextDir, "docker-port-fixture")
	if prebuilt := os.Getenv(dockerPortDaemonSmokeFixtureEnv); prebuilt != "" {
		body, err := os.ReadFile(prebuilt)
		if err != nil || len(body) == 0 {
			t.Fatalf("read prebuilt Docker port fixture: %v", err)
		}
		if err := os.WriteFile(fixtureBinary, body, 0o555); err != nil {
			t.Fatal(err)
		}
	} else {
		command := exec.Command(
			"go", "build", "-trimpath", "-ldflags=-s -w",
			"-o", fixtureBinary,
			"./testdata/docker-port-fixture",
		)
		command.Env = append(
			os.Environ(),
			"CGO_ENABLED=0",
			"GOOS=linux",
			"GOARCH="+dockerPortSmokeServerGoArch(t),
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build Docker port fixture: %v\n%s", err, output)
		}
	}
	dockerfile := []byte(
		"FROM scratch\n" +
			"COPY --chmod=0555 docker-port-fixture /docker-port-fixture\n" +
			"USER 65532:65532\n" +
			"ENTRYPOINT [\"/docker-port-fixture\"]\n",
	)
	if err := os.WriteFile(
		filepath.Join(contextDir, "Dockerfile"), dockerfile, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	baseRunner := OSCommandRunner{NewProcessGroup: true}
	fixtureDockerConfig := t.TempDir()
	if err := os.Chmod(fixtureDockerConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := baseRunner.Run(
		context.Background(),
		"",
		[]string{"HOME=/", "DOCKER_CONFIG=" + fixtureDockerConfig},
		"/usr/bin/docker",
		"build", "--pull=false", "--network=none",
		"--label", "com.kome-lab.autostream.test=docker-port-smoke",
		"--tag", image, contextDir,
	)
	if err != nil {
		t.Fatalf("build isolated Docker port fixture: %v\n%s", err, output)
	}
}

func dockerPortSmokeServerGoArch(t *testing.T) string {
	t.Helper()
	baseRunner := OSCommandRunner{NewProcessGroup: true}
	architecture := strings.TrimSpace(mustDockerPortSmokeRun(
		t, baseRunner, "", "/usr/bin/docker",
		"version", "--format", "{{.Server.Arch}}",
	))
	switch architecture {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		t.Fatalf("unsupported Docker server architecture %q", architecture)
		return ""
	}
}
