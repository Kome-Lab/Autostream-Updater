package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

func TestResolveDockerReleaseAcceptsCanonicalManifest(t *testing.T) {
	got, err := resolveDockerReleaseForTest(t, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceVersion != "v1.0.0" {
		t.Fatalf("SourceVersion = %q", got.SourceVersion)
	}
	if got.ManifestDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("ManifestDigest = %q", got.ManifestDigest)
	}
	if got.PlatformDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("PlatformDigest = %q", got.PlatformDigest)
	}
	if !digestPattern.MatchString(got.ManifestSHA256) {
		t.Fatalf("ManifestSHA256 = %q", got.ManifestSHA256)
	}
}

func TestResolveDockerReleaseRejectsIncompatibleMinimumAgentVersion(t *testing.T) {
	for name, minimum := range map[string]string{
		"missing": "",
		"too new": "v9.0.0",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := resolveDockerReleaseForTest(t, func(manifest *DockerReleaseManifest) {
				manifest.MinimumAgentVersion = minimum
			}, false)
			if err == nil {
				t.Fatal("expected minimum_agent_version rejection")
			}
		})
	}
}

func TestResolveDockerReleaseRequiresExactlyFiveCanonicalComponents(t *testing.T) {
	tests := map[string]func(*DockerReleaseManifest){
		"missing": func(manifest *DockerReleaseManifest) {
			manifest.Components = manifest.Components[:len(manifest.Components)-1]
		},
		"duplicate": func(manifest *DockerReleaseManifest) {
			manifest.Components[len(manifest.Components)-1] = manifest.Components[0]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := resolveDockerReleaseForTest(t, mutate, false)
			if err == nil {
				t.Fatal("expected component set rejection")
			}
		})
	}
}

func TestResolveDockerReleaseRejectsMismatchedSidecar(t *testing.T) {
	if _, err := resolveDockerReleaseForTest(t, nil, true); err == nil {
		t.Fatal("expected SHA256 sidecar rejection")
	}
}

func TestResolveDockerReleaseRequiresIdenticalPublishedAndGeneratedTimestamps(t *testing.T) {
	_, err := resolveDockerReleaseForTest(t, func(manifest *DockerReleaseManifest) {
		manifest.GeneratedAt = "2026-07-17T19:00:00-05:00"
	}, false)
	if err == nil {
		t.Fatal("expected generated_at string identity rejection")
	}
}

func resolveDockerReleaseForTest(t *testing.T, mutate func(*DockerReleaseManifest), mismatchedSidecar bool, rawMutate ...func(map[string]any)) (ResolvedDockerRelease, error) {
	t.Helper()

	oldVersion := controlversion.Version
	controlversion.Version = "v1.6.8"
	t.Cleanup(func() { controlversion.Version = oldVersion })

	const bundleVersion = "v1.2.3"
	services := []string{"control-panel", "worker", "encoder-recorder", "discord-bot", "observability"}
	components := make([]DockerReleaseComponent, 0, len(services))
	for _, service := range services {
		databaseSchema := "none"
		if service == "control-panel" || service == "observability" {
			databaseSchema = "backward_compatible"
		}
		components = append(components, DockerReleaseComponent{
			Service:        service,
			SourceVersion:  "v1.0.0",
			Image:          "ghcr.io/kome-lab/autostream-docker/" + service + ":" + bundleVersion,
			ManifestDigest: "sha256:" + strings.Repeat("b", 64),
			PlatformDigests: map[string]string{
				"linux/amd64": "sha256:" + strings.Repeat("a", 64),
				"linux/arm64": "sha256:" + strings.Repeat("c", 64),
			},
			RollbackCompatible: true,
			DatabaseSchema:     databaseSchema,
		})
	}
	manifest := DockerReleaseManifest{
		SchemaVersion:       1,
		ReleaseID:           bundleVersion,
		Channel:             "docker",
		PublishedAt:         "2026-07-18T00:00:00Z",
		BundleVersion:       bundleVersion,
		GeneratedAt:         "2026-07-18T00:00:00Z",
		MinimumAgentVersion: "v1.0.0",
		Components:          components,
	}
	if mutate != nil {
		mutate(&manifest)
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawMutate) > 0 {
		var raw map[string]any
		if err := json.Unmarshal(manifestJSON, &raw); err != nil {
			t.Fatal(err)
		}
		rawMutate[0](raw)
		manifestJSON, err = json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	manifestSum := sha256.Sum256(manifestJSON)
	sidecarSum := hex.EncodeToString(manifestSum[:])
	if mismatchedSidecar {
		sidecarSum = strings.Repeat("d", 64)
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/Kome-Lab/Autostream-Docker/releases/tags/" + bundleVersion:
			fmt.Fprintf(w, `{"assets":[{"name":"release-manifest.json","url":%q},{"name":"release-manifest.json.sha256","url":%q}]}`, server.URL+"/manifest", server.URL+"/manifest-sidecar")
		case "/manifest":
			_, _ = w.Write(manifestJSON)
		case "/manifest-sidecar":
			fmt.Fprintf(w, "%s  release-manifest.json\n", sidecarSum)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	downloader := ReleaseDownloader{APIBase: server.URL, Client: server.Client(), AllowHTTPForTest: true}
	return downloader.ResolveDockerRelease(context.Background(), bundleVersion, "worker", "ghcr.io/kome-lab/autostream-docker/worker", "docker", t.TempDir())
}

func TestResolveDockerReleaseRejectsMissingRollbackFields(t *testing.T) {
	for _, field := range []string{"rollback_compatible", "database_schema"} {
		t.Run(field, func(t *testing.T) {
			_, err := resolveDockerReleaseForTest(t, nil, false, func(raw map[string]any) {
				components := raw["components"].([]any)
				delete(components[0].(map[string]any), field)
			})
			if err == nil {
				t.Fatalf("expected missing %s rejection", field)
			}
		})
	}
}

func TestResolveDockerReleaseRejectsUnsafeRollbackPolicy(t *testing.T) {
	for name, mutate := range map[string]func(*DockerReleaseManifest){
		"rollback false":  func(manifest *DockerReleaseManifest) { manifest.Components[1].RollbackCompatible = false },
		"database policy": func(manifest *DockerReleaseManifest) { manifest.Components[0].DatabaseSchema = "none" },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveDockerReleaseForTest(t, mutate, false); err == nil {
				t.Fatal("expected unsafe rollback policy rejection")
			}
		})
	}
}
