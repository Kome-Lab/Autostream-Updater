package hostruntime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type ApplyPlan struct {
	JobID                  string `json:"job_id"`
	HostID                 string `json:"host_id,omitempty"`
	TargetID               string `json:"target_id"`
	ServiceType            string `json:"service_type"`
	DeploymentMode         string `json:"deployment_mode"`
	TargetVersion          string `json:"target_version"`
	CurrentVersion         string `json:"current_version,omitempty"`
	ConfigSHA256           string `json:"config_sha256,omitempty"`
	LeaseToken             string `json:"lease_token"`
	LeaseGeneration        uint64 `json:"lease_generation"`
	StageDir               string `json:"stage_dir,omitempty"`
	ArtifactDigest         string `json:"artifact_digest,omitempty"`
	ExpectedVersion        string `json:"expected_version,omitempty"`
	ExpectedImageDigest    string `json:"expected_image_digest,omitempty"`
	ExpectedPlatformDigest string `json:"expected_platform_digest,omitempty"`
}

type ApplyResult struct {
	Status         string `json:"status"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	RolledBack     bool   `json:"rolled_back,omitempty"`
	Message        string `json:"message,omitempty"`
}

type CommandRunner interface {
	Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error)
}

type OSCommandRunner struct {
	NewProcessGroup bool
}

func (r OSCommandRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	output, _, err := r.runWithOutputMetadata(ctx, dir, env, name, args...)
	return output, err
}

// runWithOutputMetadata preserves Run's command and error behavior. The extra
// bit reports bytes actually discarded, not merely a buffer at its limit.
func (r OSCommandRunner) runWithOutputMetadata(ctx context.Context, dir string, env []string, name string, args ...string) (string, bool, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	processDone := configureProcessGroup(cmd, r.NewProcessGroup)
	cmd.Dir = dir
	cmd.Env = sanitizedCommandEnv(env)
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	processDone()
	if err != nil {
		return output.String(), output.truncated, fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return output.String(), output.truncated, nil
}

func sanitizedCommandEnv(extra []string) []string {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	if runtime.GOOS == "windows" {
		env = nil
		for _, key := range []string{"SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"} {
			if value, ok := os.LookupEnv(key); ok {
				env = append(env, key+"="+value)
			}
		}
	}
	for _, value := range extra {
		if strings.ContainsRune(value, '\x00') || !strings.Contains(value, "=") {
			continue
		}
		env = append(env, value)
	}
	return env
}

func dockerCommandEnv() []string {
	return []string{"HOME=/", "DOCKER_CONFIG=" + localExecutorDockerConfigDir}
}

type limitedBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	const max = 1 << 20
	if n > max-b.Len() {
		b.truncated = true
	}
	if b.Len() < max {
		remaining := max - b.Len()
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}
