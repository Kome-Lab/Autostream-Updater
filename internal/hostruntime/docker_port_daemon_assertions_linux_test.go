//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"fmt"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"os"
	"path/filepath"
	"testing"
)

func assertDockerPortSmokeApplied(
	t *testing.T,
	response LocalExecutorResponse,
	plan SystemdPortReconfigurePlan,
) {
	t.Helper()
	if err := response.Validate(); err != nil ||
		response.PortResult == nil ||
		response.PortResult.Result != systemdPortResultApplied ||
		response.PortResult.Docker == nil ||
		response.PortResult.AppliedPort != plan.NewPort ||
		response.PortResult.Docker.AppliedPublishedPort !=
			plan.Docker.NewPublishedPort ||
		response.PortResult.Docker.AppliedContainerPort !=
			plan.Docker.NewContainerPort ||
		response.PortResult.Docker.AppliedHealthPort !=
			plan.Docker.NewHealthPort {
		portResultPresent := response.PortResult != nil
		dockerResultPresent := portResultPresent && response.PortResult.Docker != nil
		resultClass := "missing"
		if portResultPresent {
			switch response.PortResult.Result {
			case systemdPortResultApplied:
				resultClass = "applied"
			case systemdPortResultRolledBack:
				resultClass = "rolled_back"
			case systemdPortResultRollbackFailed:
				resultClass = "rollback_failed"
			default:
				resultClass = "other"
			}
		}
		t.Fatalf(
			"applied response mismatch: result=%s validation_error_present=%t error_present=%t port_result_present=%t docker_result_present=%t "+
				"advertised_match=%t published_match=%t container_match=%t health_match=%t",
			resultClass, err != nil, response.Error != nil, portResultPresent, dockerResultPresent,
			portResultPresent && response.PortResult.AppliedPort == plan.NewPort,
			dockerResultPresent && plan.Docker != nil && response.PortResult.Docker.AppliedPublishedPort == plan.Docker.NewPublishedPort,
			dockerResultPresent && plan.Docker != nil && response.PortResult.Docker.AppliedContainerPort == plan.Docker.NewContainerPort,
			dockerResultPresent && plan.Docker != nil && response.PortResult.Docker.AppliedHealthPort == plan.Docker.NewHealthPort,
		)
	}
}

func assertDockerPortSmokeRolledBack(
	t interface {
		Helper()
		Fatalf(string, ...any)
	},
	response LocalExecutorResponse,
	plan SystemdPortReconfigurePlan,
) {
	t.Helper()
	if err := response.Validate(); err != nil ||
		response.PortResult == nil ||
		response.PortResult.Result != systemdPortResultRolledBack ||
		response.PortResult.Docker == nil ||
		response.PortResult.AppliedPort != plan.OldPort ||
		response.PortResult.Docker.AppliedPublishedPort !=
			plan.Docker.OldPublishedPort ||
		response.PortResult.Docker.AppliedContainerPort !=
			plan.Docker.OldContainerPort ||
		response.PortResult.Docker.AppliedHealthPort !=
			plan.Docker.OldHealthPort {
		t.Fatalf("rollback response mismatch: %s", dockerPortSmokeRollbackSummary(response, plan))
	}
}

func assertDockerPortSmokeDurableState(
	t *testing.T,
	stateDir string,
	adapter dockerPortAdapter,
	state dockerPortSmokeState,
	plan SystemdPortReconfigurePlan,
) {
	t.Helper()
	assertDockerPortSmokeSidecar(t, adapter, state)
	store, err := newFileDockerPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := store.LoadDockerApplied(plan.TargetID)
	if err != nil || applied == nil ||
		applied.PublishedPort != state.publishedPort ||
		applied.ContainerPort != state.containerPort ||
		applied.HealthPort != state.publishedPort ||
		applied.EndpointRevision != state.endpointRevision ||
		applied.ConfigRevision != state.configRevision ||
		applied.ConfigSHA256 != state.configSHA256 {
		t.Fatalf("durable applied=%+v err=%v", applied, err)
	}
	assertDockerPortSmokeWorkDirEmpty(t, stateDir)
}

func assertDockerPortSmokeSidecar(
	t *testing.T,
	adapter dockerPortAdapter,
	state dockerPortSmokeState,
) {
	t.Helper()
	want, err := dockerPortEnvBytes(
		adapter, state.publishedPort, state.containerPort,
		state.configRevision,
	)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(adapter.PortEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(adapter.PortEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 ||
		!bytes.Equal(got, want) ||
		dockerPortEnvSHA256(got) != state.configSHA256 {
		t.Fatalf("Docker port sidecar mode=%o body=%q", info.Mode().Perm(), got)
	}
}

func assertDockerPortSmokeWorkDirEmpty(t *testing.T, stateDir string) {
	t.Helper()
	workDir := filepath.Join(stateDir, "docker-work")
	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Docker transient work survived: %+v", entries)
	}
}

func assertDockerPortSmokeFrozenCaptures(
	t *testing.T,
	captureDir string,
) {
	t.Helper()
	entries, err := os.ReadDir(captureDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 12 || len(entries)%2 != 0 {
		t.Fatalf("captured frozen Compose count=%d", len(entries))
	}
	for _, entry := range entries {
		path := filepath.Join(captureDir, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 ||
			!bytes.Equal(body, make([]byte, len(body))) {
			t.Fatalf("frozen Compose inode was not zeroed: %s", path)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

func startDockerPortSmokeForeignContainer(
	t *testing.T,
	runner OSCommandRunner,
	image, name, stateDir string,
	publishedPort, containerPort int,
) {
	t.Helper()
	credentialDir := filepath.Join(stateDir, "foreign-listener")
	if err := os.Mkdir(credentialDir, 0o700); err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(credentialDir, "node-listener.json")
	credential, err := contracts.MarshalNodeListenerConfig(contracts.NodeListenerConfig{
		SchemaVersion:  2,
		ServiceType:    "worker",
		BindAddress:    fmt.Sprintf("0.0.0.0:%d", containerPort),
		ConfigRevision: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialPath, credential, 0o444); err != nil {
		t.Fatal(err)
	}
	mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"run", "-d",
		"--name", name,
		"--label", "com.kome-lab.autostream.test=docker-port-smoke",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "64",
		"--mount", fmt.Sprintf(
			"type=bind,src=%s,dst=/run/autostream-credentials/node-listener.json,readonly",
			credentialPath,
		),
		"-p", fmt.Sprintf(
			"127.0.0.1:%d:%d/tcp", publishedPort, containerPort,
		),
		"-e", "CREDENTIALS_DIRECTORY=/run/autostream-credentials",
		"-e", "AUTOSTREAM_FIXTURE_ADVERTISED_PORT=443",
		"-e", "AUTOSTREAM_FIXTURE_VERSION=v1.0.0",
		image,
	)
	if err := waitForDockerPortTCP(
		context.Background(), publishedPort,
	); err != nil {
		t.Fatal(err)
	}
}
