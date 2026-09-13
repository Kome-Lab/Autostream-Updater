package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type fakeLocalTargetVerifier struct {
	observations    []LocalProcessObservation
	calls           int
	err             error
	observedTargets []LocalExecutorTarget
	dockerProbe     *LocalExecutorDockerPortProbe
	dockerErr       error
}

type fakeLocalExecutorProbeClient struct {
	probes map[string]LocalExecutorProbe
	err    error
	calls  int
}

func (f *fakeLocalExecutorProbeClient) Probe(_ context.Context, serviceID string) (LocalExecutorProbe, error) {
	f.calls++
	if f.err != nil {
		return LocalExecutorProbe{}, f.err
	}
	probe, ok := f.probes[serviceID]
	if !ok {
		return LocalExecutorProbe{}, errors.New("not found")
	}
	return probe, nil
}

func (f *fakeLocalTargetVerifier) Observe(
	_ context.Context,
	_ LocalExecutorPolicy,
	target LocalExecutorTarget,
) (LocalProcessObservation, error) {
	f.calls++
	f.observedTargets = append(f.observedTargets, target)
	if f.err != nil {
		return LocalProcessObservation{}, f.err
	}
	if len(f.observations) == 0 {
		return LocalProcessObservation{}, errors.New("no observation")
	}
	index := f.calls - 1
	if index >= len(f.observations) {
		index = len(f.observations) - 1
	}
	return f.observations[index], nil
}

func (f *fakeLocalTargetVerifier) ObserveDockerPort(
	context.Context,
	LocalExecutorPolicy,
	LocalExecutorTarget,
	*http.Client,
) (LocalExecutorDockerPortProbe, error) {
	if f.dockerErr != nil {
		return LocalExecutorDockerPortProbe{}, f.dockerErr
	}
	if f.dockerProbe == nil {
		return LocalExecutorDockerPortProbe{}, errors.New("no Docker port observation")
	}
	return *f.dockerProbe, nil
}

func validLocalProcessObservation(target LocalExecutorTarget, version string) LocalProcessObservation {
	return LocalProcessObservation{
		ServiceID:            target.ServiceID,
		ServiceType:          target.ServiceType,
		DeploymentMode:       target.DeploymentMode,
		CurrentVersion:       version,
		MainPID:              101,
		ListenerPID:          102,
		ControlGroup:         "/system.slice/autostream-worker.service",
		ListenerControlGroup: "/system.slice/autostream-worker.service",
	}
}

func validLocalExecutorPolicy(t *testing.T) LocalExecutorPolicy {
	t.Helper()
	systemd := validLocalSystemdTarget(t)
	return LocalExecutorPolicy{
		SchemaVersion:   LocalExecutorPolicySchemaVersion,
		ProtocolVersion: LocalExecutorProtocolVersion,
		HostID:          "host-a",
		AgentUID:        1001,
		AgentGID:        1001,
		SocketPath:      LocalExecutorSocketPath,
		PolicyRevision:  7,
		Targets: []LocalExecutorTarget{{
			ServiceID:      "worker-01",
			ServiceType:    "worker",
			DeploymentMode: ModeSystemd,
			ConfigRevision: 11,
			LocalListen:    LocalExecutorEndpoint{Host: "127.0.0.1", Port: 18084},
			Systemd:        &systemd,
		}},
	}
}

func validLocalSystemdTarget(t *testing.T) SystemdTarget {
	t.Helper()
	return SystemdTarget{
		SystemctlPath: "/usr/bin/systemctl",
		RunuserPath:   "/usr/sbin/runuser",
		SmokeUser:     "autostream",
		Unit:          "autostream-worker.service",
		ReleaseRoot:   "/opt/autostream/worker/releases",
		CurrentLink:   "/opt/autostream/worker/current",
		BinaryPath:    "bin/autostream-worker",
	}
}

func validLocalDockerTarget(t *testing.T) DockerTarget {
	t.Helper()
	return DockerTarget{
		DockerPath:          "/usr/bin/docker",
		ComposeProject:      "autostream",
		ProjectDir:          "/opt/autostream",
		ComposeFiles:        []string{"/opt/autostream/compose.yml"},
		Service:             "worker",
		ImageRepo:           "ghcr.io/kome-lab/autostream-docker/worker",
		ImageVariable:       "AUTOSTREAM_DOCKER_VERSION",
		BaseEnvFile:         "/opt/autostream/.env",
		VersionEnvFile:      "/opt/autostream/local-executor/docker/worker.env",
		ComposeConfigSHA256: strings.Repeat("a", 64),
		CurrentVersion:      "v1.2.3",
		Channel:             "docker",
	}
}

func newLocalExecutorProbeServer(t *testing.T, target LocalExecutorTarget, version string, revision int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /updater/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":         version,
			"service_id":      target.ServiceID,
			"service_type":    target.ServiceType,
			"config_revision": revision,
		})
	})
	return httptest.NewServer(mux)
}

func endpointFromServer(t *testing.T, server *httptest.Server) LocalExecutorEndpoint {
	t.Helper()
	hostPort := strings.TrimPrefix(server.URL, "http://")
	host, portText, ok := strings.Cut(hostPort, ":")
	if !ok {
		t.Fatalf("server URL=%q", server.URL)
	}
	var port int
	if _, err := fmt.Sscan(portText, &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return LocalExecutorEndpoint{Host: host, Port: port}
}

func cloneLocalExecutorPolicy(t *testing.T, policy LocalExecutorPolicy) LocalExecutorPolicy {
	t.Helper()
	var clone LocalExecutorPolicy
	if err := json.Unmarshal([]byte(mustJSON(t, policy)), &clone); err != nil {
		t.Fatalf("clone policy: %v", err)
	}
	return clone
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func writeTestFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
