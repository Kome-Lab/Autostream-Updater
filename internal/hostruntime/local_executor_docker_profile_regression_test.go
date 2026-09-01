package hostruntime

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestLocalExecutorComposeArgsApplyVersionPinAfterBaseEnvironment(t *testing.T) {
	target := localExecutorDockerRegressionTarget()
	overridePath := "/var/lib/autostream-local-executor/stages/job-1/compose-override.json"

	got := composeArgs(&target, overridePath)
	want := []string{
		"compose",
		"--env-file", "/opt/autostream/.env",
		"--env-file", "/opt/autostream/local-executor/docker/worker.env",
		"--project-directory", "/opt/autostream",
		"-p", "autostream",
		"-f", "/opt/autostream/compose.yml",
		"-f", overridePath,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compose args=%q want=%q", got, want)
	}

	frozenPath := "/var/lib/autostream-local-executor/stages/job-1/compose-frozen.json"
	got = composeFrozenArgs(&target, frozenPath)
	want = []string{
		"compose",
		"--env-file", "/opt/autostream/.env",
		"--env-file", "/opt/autostream/local-executor/docker/worker.env",
		"--project-directory", "/opt/autostream",
		"-p", "autostream",
		"-f", frozenPath,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("frozen compose args=%q want=%q", got, want)
	}
}

func TestLocalExecutorDockerCheckpointUsesExecutorStateAndTargetIdentity(t *testing.T) {
	dockerTarget := localExecutorDockerRegressionTarget()
	first := Target{
		TargetID:       "worker-01",
		ServiceType:    "worker",
		DeploymentMode: ModeDocker,
		Docker:         &dockerTarget,
	}
	second := first
	second.TargetID = "worker-02"

	firstPath := checkpointPath(first)
	secondPath := checkpointPath(second)
	if filepath.Dir(firstPath) != filepath.Clean(LocalExecutorMutationStateDir) {
		t.Fatalf("checkpoint escaped Local Executor state: %q", firstPath)
	}
	if firstPath == secondPath {
		t.Fatalf("distinct target identities share a checkpoint: %q", firstPath)
	}

	legacy := first
	legacyDocker := *first.Docker
	legacy.Docker = &legacyDocker
	legacy.Docker.BaseEnvFile = ""
	legacy.Docker.VersionEnvFile = "/opt/autostream/worker-version.env"
	if got := checkpointPath(legacy); filepath.Dir(got) != filepath.Clean(legacy.Docker.ProjectDir) {
		t.Fatalf("non-Local-Executor Docker checkpoint compatibility changed: %q", got)
	}
}

func localExecutorDockerRegressionTarget() DockerTarget {
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
		ComposeConfigSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CurrentVersion:      "v1.2.3",
		Channel:             "docker",
	}
}
