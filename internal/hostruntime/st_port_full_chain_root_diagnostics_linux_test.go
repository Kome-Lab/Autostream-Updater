//go:build linux

package hostruntime

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

var stPortChainRootPhases = [...]string{
	"policy_select", "policy_save", "policy_write", "policy_reload", "policy_verify",
	"forward_budget", "forward_write", "forward_restart", "forward_probe",
	"probe_projection", "probe_before", "probe_http", "probe_docker_mapping",
	"probe_after", "probe_baseline", "probe_response", "docker_container",
	"docker_pid", "docker_cgroup", "docker_version", "docker_listener",
	"systemd_release", "systemd_process", "systemd_pid", "systemd_cgroup", "systemd_listener",
	"http_health", "http_version",
	"docker_prepare_target", "docker_prepare_applied", "docker_prepare_observe",
	"docker_prepare_observation", "docker_prepare_snapshot", "docker_prepare_container",
	"docker_prepare_image", "docker_prepare_repository", "docker_prepare_version_env",
	"docker_prepare_compose", "docker_prepare_target_payload", "docker_prepare_rollback_payload",
	"docker_prepare_target_model", "docker_prepare_rollback_model", "docker_prepare_availability",
}

var stPortChainRootClasses = [...]string{"validation", "operation", "deadline", "canceled"}

func stPortChainRootFailureContext(ctx context.Context) context.Context {
	var count atomic.Uint32
	return context.WithValue(ctx, localExecutionFailureContextKey{}, func(phase localExecutionFailurePhase, class localExecutionFailureClass) {
		if int(phase) >= len(stPortChainRootPhases) || int(class) >= len(stPortChainRootClasses) || count.Add(1) > 32 {
			return
		}
		_, _ = fmt.Fprintf(os.Stderr, "ST-PORT root failure: phase=%s class=%s\n", stPortChainRootPhases[phase], stPortChainRootClasses[class])
	})
}

// Child stderr is private. Only this exact closed marker crosses into the
// parent test artifact; unrelated bytes and incomplete lines are never emitted.
func stPortChainLogRootFailures(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return
	}
	allowed := make(map[string]bool)
	for _, phase := range stPortChainRootPhases {
		for _, class := range stPortChainRootClasses {
			allowed["ST-PORT root failure: phase="+phase+" class="+class] = true
		}
	}
	count := 0
	lines := strings.Split(string(body), "\n")
	for _, line := range lines[:len(lines)-1] {
		line = strings.TrimSuffix(line, "\r")
		if allowed[line] && count < 32 {
			t.Log(line)
			count++
		}
	}
}
