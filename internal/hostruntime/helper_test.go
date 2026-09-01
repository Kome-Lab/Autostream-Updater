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

type commandCall struct {
	dir  string
	env  []string
	name string
	args []string
}

type fakeRunner struct {
	calls   []commandCall
	psCount int
}

const (
	testOldImage = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testNewImage = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testPlatform = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func (f *fakeRunner) Run(_ context.Context, dir string, env []string, name string, args ...string) (string, error) {
	f.calls = append(f.calls, commandCall{dir: dir, env: append([]string(nil), env...), name: name, args: append([]string(nil), args...)})
	joined := strings.Join(args, " ")
	switch {
	case len(args) > 0 && args[0] == "ps":
		f.psCount++
		return fmt.Sprintf("container-%d\n", f.psCount), nil
	case strings.Contains(joined, "config --format json"):
		return `{"services":{"worker":{"image":"ghcr.io/kome-lab/autostream-docker/worker@` + testPlatform + `"}}}`, nil
	case len(args) > 0 && args[0] == "inspect":
		if strings.Contains(joined, "container-2") {
			return testNewImage + "\n", nil
		}
		return testOldImage + "\n", nil
	case len(args) > 2 && args[0] == "image" && args[1] == "inspect" && strings.Contains(joined, "RepoDigests"):
		if strings.Contains(joined, testOldImage) {
			return `["ghcr.io/kome-lab/autostream-docker/worker@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]`, nil
		}
		return `["ghcr.io/kome-lab/autostream-docker/worker@` + testPlatform + `"]`, nil
	case len(args) > 1 && args[0] == "image" && args[1] == "inspect":
		return testNewImage + "\n", nil
	default:
		return "", nil
	}
}

func TestDockerApplyUsesFixedComposeArgumentsAndBundleVersion(t *testing.T) {
	version := "v2.0.0"
	sourceVersion := "v1.0.16"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/version") {
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprintf(w, `{"version":%q,"service_id":"worker","service_type":"worker","config_revision":1}`, sourceVersion)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	versionEnv := filepath.Join(root, "worker.env")
	model := []byte(`{"services":{"worker":{"image":"ignored"}}}`)
	modelDigest, err := composeModelHash(model, "worker")
	if err != nil {
		t.Fatal(err)
	}
	target := Target{TargetID: "worker", ServiceType: "worker", DeploymentMode: ModeDocker, ConfigRevision: 1, HealthURL: server.URL + "/health", VersionURL: server.URL + "/updater/version", Docker: &DockerTarget{
		DockerPath: filepath.Join(root, "docker"), ComposeProject: "autostream", ProjectDir: root, ComposeFiles: []string{filepath.Join(root, "compose.yml")}, Service: "worker", ImageRepo: "ghcr.io/kome-lab/autostream-docker/worker", ImageVariable: "AUTOSTREAM_DOCKER_VERSION", VersionEnvFile: versionEnv, CurrentVersion: "v1.9.0", ComposeConfigSHA256: modelDigest,
	}}
	runner := &fakeRunner{}
	result, err := applyDocker(context.Background(), target, ApplyPlan{JobID: "job-1", TargetVersion: version, StageDir: stage, ExpectedVersion: sourceVersion, ExpectedImageDigest: testPlatform, ExpectedPlatformDigest: testPlatform}, runner)
	if err != nil {
		t.Fatal(err)
	}
	if result.ArtifactDigest != testPlatform || result.PreviousDigest != testOldImage {
		t.Fatalf("unexpected result: %+v", result)
	}
	foundPull, foundUp, foundConfig := false, false, false
	for _, call := range runner.calls {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, " pull worker") {
			foundPull = true
			if strings.Contains(joined, "compose.yml") || !strings.Contains(joined, "compose-frozen.json") {
				t.Fatalf("pull did not use only the frozen compose model: %s", joined)
			}
		}
		if strings.Contains(joined, "up -d --no-deps --no-build --pull never worker") {
			foundUp = true
		}
		if strings.Contains(joined, "config --format json") && strings.Contains(joined, "--env-file "+versionEnv) {
			foundConfig = true
		}
	}
	if !foundPull || !foundUp || !foundConfig {
		t.Fatalf("expected fixed pull/up calls, got %+v", runner.calls)
	}
	for _, call := range runner.calls {
		if call.name != target.Docker.DockerPath {
			continue
		}
		joinedEnv := strings.Join(call.env, "\n")
		if !strings.Contains(joinedEnv, "HOME=/") || !strings.Contains(joinedEnv, "DOCKER_CONFIG=/etc/autostream-local-executor/docker") {
			t.Fatalf("Docker command inherited a non-root credential environment: %+v", call.env)
		}
	}
	persisted, err := os.ReadFile(versionEnv)
	if err != nil || string(persisted) != "AUTOSTREAM_DOCKER_VERSION="+version+"@"+testPlatform+"\n" {
		t.Fatalf("durable version pin = %q err=%v", persisted, err)
	}
}

func TestReadHealthyTargetVersionRequiresFreshApplicationIdentity(t *testing.T) {
	tests := []struct {
		name       string
		versionURL string
		cache      string
		serviceID  string
		revision   int
		wantOK     bool
	}{
		{name: "exact identity", versionURL: "/updater/version", cache: "no-store", serviceID: "worker-01", revision: 7, wantOK: true},
		{name: "cacheable identity", versionURL: "/updater/version", cache: "private", serviceID: "worker-01", revision: 7},
		{name: "wrong service identity", versionURL: "/updater/version", cache: "no-store", serviceID: "worker-02", revision: 7},
		{name: "wrong config revision", versionURL: "/updater/version", cache: "no-store", serviceID: "worker-01", revision: 8},
		{name: "updater health substitution", versionURL: "/health", cache: "no-store", serviceID: "worker-01", revision: 7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				w.Header().Set("Cache-Control", test.cache)
				if request.URL.Path == "/health" {
					_, _ = w.Write([]byte(`{"status":"ok","revision":7}`))
					return
				}
				_, _ = fmt.Fprintf(
					w,
					`{"version":"v1.2.3","service_id":%q,"service_type":"worker","config_revision":%d}`,
					test.serviceID,
					test.revision,
				)
			}))
			defer server.Close()

			target := Target{
				TargetID:       "worker-01",
				ServiceType:    "worker",
				DeploymentMode: ModeSystemd,
				ConfigRevision: 7,
				HealthURL:      server.URL + "/health",
				VersionURL:     server.URL + test.versionURL,
			}
			version, err := readHealthyTargetVersionWithClient(t.Context(), target, server.Client())
			if test.wantOK {
				if err != nil || version != "v1.2.3" {
					t.Fatalf("version=%q err=%v", version, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("unsafe identity was accepted: version=%q", version)
			}
		})
	}
}

func TestDockerCommandEnvironmentIsFixed(t *testing.T) {
	env := sanitizedCommandEnv(dockerCommandEnv())
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "HOME=/") || !strings.Contains(joined, "DOCKER_CONFIG=/etc/autostream-local-executor/docker") {
		t.Fatalf("fixed Docker environment missing: %v", env)
	}
}

func TestComposeModelHashNormalizesAllCanonicalBundleImages(t *testing.T) {
	first := []byte(`{"services":{"worker":{"image":"ghcr.io/kome-lab/autostream-docker/worker:v1.0.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"observability":{"image":"ghcr.io/kome-lab/autostream-docker/observability:v1.0.0@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}`)
	second := []byte(`{"services":{"worker":{"image":"ghcr.io/kome-lab/autostream-docker/worker:v2.0.0@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"observability":{"image":"ghcr.io/kome-lab/autostream-docker/observability:v2.0.0@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}}`)
	a, err := composeModelHash(first, "worker")
	if err != nil {
		t.Fatal(err)
	}
	b, err := composeModelHash(second, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("bundle-only image changes altered canonical model hash: %s != %s", a, b)
	}
}

func TestComposeModelSecurityRejectsPrivilegeAndDockerSocket(t *testing.T) {
	d := &DockerTarget{Service: "worker", ImageRepo: "ghcr.io/kome-lab/autostream-docker/worker"}
	for name, model := range map[string]string{
		"privileged": `{"services":{"worker":{"image":"ghcr.io/kome-lab/autostream-docker/worker:v1.0.0","privileged":true}}}`,
		"socket":     `{"services":{"worker":{"image":"ghcr.io/kome-lab/autostream-docker/worker:v1.0.0","volumes":[{"type":"bind","source":"/var/run/docker.sock","target":"/var/run/docker.sock","read_only":true}]}}}`,
		"writable":   `{"services":{"worker":{"image":"ghcr.io/kome-lab/autostream-docker/worker:v1.0.0","volumes":[{"type":"bind","source":"/tmp","target":"/data","read_only":false}]}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateComposeModelSecurity([]byte(model), d); err == nil {
				t.Fatal("expected unsafe compose model rejection")
			}
		})
	}
}

func TestValidateTrustedFrozenComposeRejectsNonRootOwnedFile(t *testing.T) {
	if RequireLocalExecutorRoot() == nil {
		t.Skip("requires a non-root Unix test process")
	}
	repo := "ghcr.io/kome-lab/autostream-docker/worker"
	platform := "sha256:" + strings.Repeat("e", 64)
	raw := []byte(`{"services":{"worker":{"image":"` + repo + `@` + platform + `"}}}`)
	modelHash, err := composeModelHash(raw, "worker")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "compose-frozen.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if isRootOwner(info) {
		t.Fatal("non-root fixture is unexpectedly root-owned")
	}
	docker := &DockerTarget{Service: "worker", ImageRepo: repo, ComposeConfigSHA256: modelHash}
	err = validateTrustedFrozenCompose(path, docker, repo+"@"+platform)
	if err == nil || err.Error() != "trusted frozen compose model is unavailable" {
		t.Fatalf("non-root-owned frozen compose result = %v", err)
	}
}
