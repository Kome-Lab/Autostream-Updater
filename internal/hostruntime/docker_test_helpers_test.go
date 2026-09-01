package hostruntime

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type executorDockerBaselineRunner struct {
	calls       []commandCall
	afterGate   bool
	mutation    string
	containerID string
	imageID     string
	repoDigest  string
	targetImage string
	targetRepo  string
}

func (r *executorDockerBaselineRunner) Run(
	_ context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (string, error) {
	r.calls = append(r.calls, commandCall{
		dir: dir, env: append([]string(nil), env...), name: name,
		args: append([]string(nil), args...),
	})
	joined := strings.Join(args, " ")
	switch {
	case len(args) > 0 && args[0] == "ps":
		if r.afterGate && r.mutation == "container" {
			return r.containerID + "-changed\n", nil
		}
		return r.containerID + "\n", nil
	case len(args) > 0 && args[0] == "inspect":
		if r.afterGate && r.mutation == "image" {
			return "sha256:" + strings.Repeat("f", 64) + "\n", nil
		}
		return r.imageID + "\n", nil
	case len(args) > 2 && args[0] == "image" && args[1] == "inspect" && strings.Contains(joined, "RepoDigests"):
		if strings.Contains(args[len(args)-1], "@sha256:") {
			repo := r.targetRepo
			if r.afterGate && r.mutation == "target_repo" {
				repo = "sha256:" + strings.Repeat("7", 64)
			}
			return `["ghcr.io/kome-lab/autostream-docker/worker@` + repo + `"]`, nil
		}
		repo := r.repoDigest
		if r.afterGate && r.mutation == "repo" {
			repo = "sha256:" + strings.Repeat("9", 64)
		}
		return `["ghcr.io/kome-lab/autostream-docker/worker@` + repo + `"]`, nil
	case len(args) > 1 && args[0] == "image" && args[1] == "inspect":
		imageID := r.targetImage
		if r.afterGate && r.mutation == "target_image" {
			imageID = "sha256:" + strings.Repeat("6", 64)
		}
		return imageID + "\n", nil
	default:
		return "", nil
	}
}

func executorDockerMutationFixture(t *testing.T) (Target, ApplyPlan, *executorDockerBaselineRunner, dockerMutationBaseline) {
	t.Helper()
	oldSource, newSource := "v1.5.0", "v1.6.0"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/version") {
			_, _ = fmt.Fprintf(w, `{"version":%q}`, oldSource)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	root := t.TempDir()
	stageDir := filepath.Join(root, "stage")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := "ghcr.io/kome-lab/autostream-docker/worker"
	targetPlatform := "sha256:" + strings.Repeat("e", 64)
	frozen := []byte(`{"services":{"worker":{"image":"` + repository + `@` + targetPlatform + `"}}}`)
	modelDigest, err := composeModelHash(frozen, "worker")
	if err != nil {
		t.Fatal(err)
	}
	versionEnv := filepath.Join(root, "worker.env")
	currentManifest := "sha256:" + strings.Repeat("b", 64)
	if err := os.WriteFile(versionEnv, []byte("AUTOSTREAM_DOCKER_VERSION=v1.0.0@"+currentManifest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := Target{
		TargetID: "worker-01", HostID: "edge-01", ServiceType: "worker", DeploymentMode: ModeDocker,
		HealthURL: server.URL + "/health", VersionURL: server.URL + "/version",
		Docker: &DockerTarget{
			DockerPath: filepath.Join(root, "docker"), ComposeProject: "autostream", ProjectDir: root,
			ComposeFiles: []string{filepath.Join(root, "compose.yml")}, Service: "worker", ImageRepo: repository,
			ImageVariable: "AUTOSTREAM_DOCKER_VERSION", VersionEnvFile: versionEnv,
			CurrentVersion: "v1.0.0", ComposeConfigSHA256: modelDigest,
		},
	}
	if err := os.WriteFile(filepath.Join(stageDir, "compose-frozen.json"), frozen, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &executorDockerBaselineRunner{
		containerID: "container-stable", imageID: "sha256:" + strings.Repeat("a", 64),
		repoDigest: "sha256:" + strings.Repeat("c", 64), targetImage: "sha256:" + strings.Repeat("d", 64),
		targetRepo: targetPlatform,
	}
	observation, err := observeDockerMutationBaseline(context.Background(), target, runner)
	if err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	plan := ApplyPlan{
		JobID: "job-01", TargetID: target.TargetID, ServiceType: target.ServiceType,
		DeploymentMode: ModeDocker, CurrentVersion: "v1.0.0", TargetVersion: "v2.0.0",
		StageDir: stageDir, ExpectedVersion: newSource,
		ExpectedImageDigest:    "sha256:" + strings.Repeat("8", 64),
		ExpectedPlatformDigest: targetPlatform,
	}
	return target, plan, runner, observation.Baseline
}

func acceptTestFixtureOwner(os.FileInfo) bool { return true }
