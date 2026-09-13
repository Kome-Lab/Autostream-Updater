//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func proveDockerAutoConfigureFailsClosed(t *testing.T) {
	t.Helper()
	_, err := BuildHostAgentConfigurePolicy(HostAgentConfigurePolicySource{
		PanelURL:                    "https://panel.example.com",
		ExecutionHostID:             "host-smoke",
		AgentUID:                    1001,
		AgentGID:                    1001,
		SourcePolicyRevision:        1,
		ProjectionRevision:          1,
		LocalExecutorPolicyRevision: 1,
		Targets: []HostAgentConfigurePolicyTarget{{
			ServiceID:             "worker-smoke",
			ServiceType:           "worker",
			DeploymentMode:        ModeDocker,
			EndpointRevision:      1,
			AppliedConfigRevision: 1,
			AppliedEndpointPort:   443,
		}},
	})
	if err == nil {
		t.Fatal("Auto Configure synthesized privileged Docker authority")
	}
}

func proveDockerTransientCleanup(t *testing.T) {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(base, dockerPortRecreatePrefix+"daemon-smoke")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := []byte(`{"services":{"worker":{"environment":{"TOKEN":"wipe-me"}}}}`)
	frozen := filepath.Join(orphan, "compose-frozen.json")
	if err := os.WriteFile(frozen, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	captured := filepath.Join(base, "captured")
	if err := os.Link(frozen, captured); err != nil {
		t.Fatal(err)
	}
	if err := cleanupDockerPortTransientOrphans(base, false); err != nil {
		t.Fatal(err)
	}
	wiped, err := os.ReadFile(captured)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wiped, make([]byte, len(secret))) {
		t.Fatal("frozen Compose model was not zeroed before unlink")
	}
}

func requireDockerPortSmokePortAvailable(t *testing.T, port int) {
	t.Helper()
	listener, err := net.Listen(
		"tcp", fmt.Sprintf("127.0.0.1:%d", port),
	)
	if err != nil {
		t.Fatalf("required smoke port %d is in use: %v", port, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func requireDockerPortSmokeHostClean(
	t *testing.T,
	runner OSCommandRunner,
) {
	t.Helper()
	for _, path := range []string{
		dockerPortSmokeProjectDir,
		"/etc/autostream-local-executor",
		"/etc/autostream",
		filepath.Join(
			privilegedLockDir(), ".autostream-host-lifecycle.lock",
		),
		filepath.Join(
			privilegedLockDir(),
			".autostream-updater-"+
				shortID(filepath.Clean(dockerPortSmokeProjectDir)+"\x00autostream")+
				".lock",
		),
	} {
		if pathExists(path) {
			t.Fatalf("Docker port smoke refuses existing host path %s", path)
		}
	}
	projectContainers := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"ps", "-aq",
		"--filter", "label=com.docker.compose.project=autostream",
	))
	if projectContainers != "" {
		t.Fatalf(
			"Docker port smoke refuses existing project containers %s",
			projectContainers,
		)
	}
	labelledContainers := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"ps", "-aq",
		"--filter", "label=com.kome-lab.autostream.test=docker-port-smoke",
	))
	if labelledContainers != "" {
		t.Fatalf(
			"Docker port smoke refuses existing labelled containers %s",
			labelledContainers,
		)
	}
	if dockerPortSmokeCommand(
		runner, "", "/usr/bin/docker",
		"network", "inspect", "autostream_default",
	) == nil {
		t.Fatal("Docker port smoke refuses existing autostream_default network")
	}
}

func cleanupDockerPortSmokeEnvironment(
	t *testing.T,
	runner OSCommandRunner,
	image, foreignContainer string,
	runDirExisted bool,
) {
	t.Helper()
	_ = dockerPortSmokeCommand(
		runner, "", "/usr/bin/docker", "rm", "-f", foreignContainer,
	)
	if output, err := runner.Run(
		context.Background(), "", dockerCommandEnv(), "/usr/bin/docker",
		"ps", "-aq",
		"--filter", "label=com.docker.compose.project=autostream",
	); err == nil {
		for _, containerID := range strings.Fields(output) {
			_ = dockerPortSmokeCommand(
				runner, "", "/usr/bin/docker", "rm", "-f", containerID,
			)
		}
	}
	_ = dockerPortSmokeCommand(
		runner, "", "/usr/bin/docker",
		"network", "rm", "autostream_default",
	)
	_ = dockerPortSmokeCommand(
		runner, "", "/usr/bin/docker", "image", "rm", "-f", image,
	)

	for _, path := range []string{
		"/opt/autostream/local-executor/docker/ports/worker.env",
		"/opt/autostream/local-executor/docker/worker.env",
		"/opt/autostream/compose.yml",
		"/opt/autostream/.env",
		"/opt/autostream/.docker-port-smoke-owner",
		"/etc/autostream-local-executor/docker/config.json",
		"/etc/autostream/updater/executor-policy.json",
		"/etc/autostream-local-executor/.docker-port-smoke-owner",
		filepath.Join(
			privilegedLockDir(), ".autostream-host-lifecycle.lock",
		),
		filepath.Join(
			privilegedLockDir(),
			".autostream-updater-"+
				shortID(filepath.Clean(dockerPortSmokeProjectDir)+"\x00autostream")+
				".lock",
		),
	} {
		if err := os.Remove(path); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove %s: %v", path, err)
		}
	}
	for _, path := range []string{
		"/opt/autostream/local-executor/docker/ports",
		"/opt/autostream/local-executor/docker",
		"/opt/autostream/local-executor",
		"/opt/autostream",
		"/etc/autostream-local-executor/docker",
		"/etc/autostream-local-executor",
		"/etc/autostream/updater",
		"/etc/autostream",
	} {
		if err := os.Remove(path); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove empty %s: %v", path, err)
		}
	}
	if !runDirExisted {
		if err := os.Remove(privilegedLockDir()); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove empty %s: %v", privilegedLockDir(), err)
		}
	}
}

func mustDockerPortSmokeRun(
	t *testing.T,
	runner OSCommandRunner,
	dir, name string,
	args ...string,
) string {
	t.Helper()
	output, err := runner.Run(
		context.Background(), dir, dockerCommandEnv(), name, args...,
	)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return output
}

func dockerPortSmokeCommand(
	runner OSCommandRunner,
	dir, name string,
	args ...string,
) error {
	_, err := runner.Run(
		context.Background(), dir, dockerCommandEnv(), name, args...,
	)
	return err
}

func dockerPortSmokeSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
