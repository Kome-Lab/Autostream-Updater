package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type DockerReleaseManifest struct {
	SchemaVersion       int                      `json:"schema_version"`
	ReleaseID           string                   `json:"release_id"`
	Channel             string                   `json:"channel"`
	PublishedAt         string                   `json:"published_at"`
	BundleVersion       string                   `json:"bundle_version"`
	GeneratedAt         string                   `json:"generated_at"`
	MinimumAgentVersion string                   `json:"minimum_agent_version"`
	Components          []DockerReleaseComponent `json:"components"`
}

type DockerReleaseComponent struct {
	Service            string            `json:"service"`
	SourceVersion      string            `json:"source_version"`
	Image              string            `json:"image"`
	ManifestDigest     string            `json:"manifest_digest"`
	PlatformDigests    map[string]string `json:"platform_digests"`
	RollbackCompatible bool              `json:"rollback_compatible"`
	DatabaseSchema     string            `json:"database_schema"`
}

type ResolvedDockerRelease struct {
	SourceVersion  string
	ManifestDigest string
	ManifestSHA256 string
	PlatformDigest string
}

func (d ReleaseDownloader) ResolveDockerRelease(ctx context.Context, bundleVersion, serviceType, imageRepo, channel, destDir string) (ResolvedDockerRelease, error) {
	return d.ResolveDockerReleaseForArch(ctx, bundleVersion, serviceType, imageRepo, channel, runtime.GOARCH, destDir)
}

// ResolveDockerReleaseForArch resolves the immutable platform digest for the
// managed host, rather than for the process resolving the release.
// The wrapper above is retained for the host-local helper and existing callers.
func (d ReleaseDownloader) ResolveDockerReleaseForArch(ctx context.Context, bundleVersion, serviceType, imageRepo, channel, arch, destDir string) (ResolvedDockerRelease, error) {
	if !versionPattern.MatchString(bundleVersion) {
		return ResolvedDockerRelease{}, errors.New("Docker bundle version is invalid")
	}
	arch = strings.ToLower(strings.TrimSpace(arch))
	if arch != "amd64" && arch != "arm64" {
		return ResolvedDockerRelease{}, errors.New("Docker release architecture must be amd64 or arm64")
	}
	if channel == "" {
		channel = "docker"
	}
	spec := RepoSpec{Owner: "Kome-Lab", Repo: "Autostream-Docker", Prefix: "autostream-docker"}
	base := strings.TrimRight(d.APIBase, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	assets, err := d.releaseAssets(ctx, base, spec, bundleVersion)
	if err != nil {
		return ResolvedDockerRelease{}, err
	}
	manifestURL, okManifest := assets["release-manifest.json"]
	sidecarURL, okSidecar := assets["release-manifest.json.sha256"]
	if !okManifest || !okSidecar {
		return ResolvedDockerRelease{}, errors.New("Docker release is missing the manifest or its SHA256 sidecar")
	}
	if err := firstError(d.validateAssetURL(manifestURL, base), d.validateAssetURL(sidecarURL, base)); err != nil {
		return ResolvedDockerRelease{}, err
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return ResolvedDockerRelease{}, err
	}
	manifestPath := filepath.Join(destDir, "release-manifest.json")
	digest, err := d.downloadFile(ctx, manifestURL, manifestPath, 4<<20)
	if err != nil {
		return ResolvedDockerRelease{}, err
	}
	sidecarPath := filepath.Join(destDir, "release-manifest.json.sha256")
	if _, err := d.downloadFile(ctx, sidecarURL, sidecarPath, 64<<10); err != nil {
		return ResolvedDockerRelease{}, err
	}
	expectedDigest, err := readSHA256File(sidecarPath, "release-manifest.json")
	if err != nil || !strings.EqualFold(expectedDigest, digest) {
		return ResolvedDockerRelease{}, errors.New("Docker release manifest SHA256 sidecar does not match")
	}
	f, err := os.Open(manifestPath)
	if err != nil {
		return ResolvedDockerRelease{}, err
	}
	defer f.Close()
	var manifest DockerReleaseManifest
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return ResolvedDockerRelease{}, errors.New("Docker release manifest is invalid JSON")
	}
	published, publishedErr := time.Parse(time.RFC3339, manifest.PublishedAt)
	generated, generatedErr := time.Parse(time.RFC3339, manifest.GeneratedAt)
	if manifest.SchemaVersion != 1 || manifest.ReleaseID != bundleVersion || manifest.BundleVersion != bundleVersion || manifest.Channel != channel || publishedErr != nil || generatedErr != nil || manifest.PublishedAt != manifest.GeneratedAt || !published.Equal(generated) || !semverAtLeast(controlversion.Current(), manifest.MinimumAgentVersion) {
		return ResolvedDockerRelease{}, errors.New("Docker release manifest identity does not match the requested bundle")
	}
	expectedRepos := map[string]string{
		"control-panel":    "ghcr.io/kome-lab/autostream-docker/control-panel",
		"worker":           "ghcr.io/kome-lab/autostream-docker/worker",
		"encoder-recorder": "ghcr.io/kome-lab/autostream-docker/encoder-recorder",
		"discord-bot":      "ghcr.io/kome-lab/autostream-docker/discord-bot",
		"observability":    "ghcr.io/kome-lab/autostream-docker/observability",
	}
	if len(manifest.Components) != len(expectedRepos) {
		return ResolvedDockerRelease{}, errors.New("Docker release manifest must contain exactly all five services")
	}
	components := map[string]*DockerReleaseComponent{}
	for i := range manifest.Components {
		component := &manifest.Components[i]
		repo, known := expectedRepos[component.Service]
		if !known || components[component.Service] != nil {
			return ResolvedDockerRelease{}, errors.New("Docker release manifest contains an unknown or duplicate service component")
		}
		if !versionPattern.MatchString(component.SourceVersion) || component.Image != repo+":"+bundleVersion {
			return ResolvedDockerRelease{}, errors.New("Docker component source_version or image identity is invalid")
		}
		expectedSchema := "none"
		if component.Service == "control-panel" || component.Service == "observability" {
			expectedSchema = "backward_compatible"
		}
		if !component.RollbackCompatible || component.DatabaseSchema != expectedSchema {
			return ResolvedDockerRelease{}, errors.New("Docker component rollback or database schema policy is invalid")
		}
		component.ManifestDigest = strings.ToLower(strings.TrimSpace(component.ManifestDigest))
		if !digestPattern.MatchString(component.ManifestDigest) || len(component.PlatformDigests) != 2 {
			return ResolvedDockerRelease{}, errors.New("Docker component manifest digest metadata is invalid")
		}
		for _, required := range []string{"linux/amd64", "linux/arm64"} {
			if !digestPattern.MatchString(strings.ToLower(strings.TrimSpace(component.PlatformDigests[required]))) {
				return ResolvedDockerRelease{}, errors.New("Docker component platform_digests is incomplete or invalid")
			}
		}
		components[component.Service] = component
	}
	wantedService := dockerManifestService(serviceType)
	matched := components[wantedService]
	if matched == nil || expectedRepos[wantedService] != imageRepo {
		return ResolvedDockerRelease{}, errors.New("Docker release manifest does not match the configured service repository")
	}
	platform := "linux/" + arch
	platformDigest := strings.ToLower(strings.TrimSpace(matched.PlatformDigests[platform]))
	if !digestPattern.MatchString(platformDigest) {
		return ResolvedDockerRelease{}, errors.New("Docker component platform_digests is incomplete or invalid")
	}
	return ResolvedDockerRelease{SourceVersion: matched.SourceVersion, ManifestDigest: matched.ManifestDigest, ManifestSHA256: "sha256:" + digest, PlatformDigest: platformDigest}, nil
}

func (d ReleaseDownloader) releaseAssets(ctx context.Context, base string, spec RepoSpec, version string) (map[string]string, error) {
	if err := d.validateTrustedPublicRepository(base, spec); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", base, spec.Owner, spec.Repo, version)
	var release githubRelease
	if err := d.getJSON(ctx, endpoint, &release); err != nil {
		return nil, err
	}
	if d.TrustedPublicOnly {
		if err := validateTrustedPublicReleaseMetadata(release, version); err != nil {
			return nil, err
		}
	}
	assets, err := uniqueReleaseAssetURLs(release)
	if err != nil {
		return nil, err
	}
	for _, asset := range release.Assets {
		if d.TrustedPublicOnly {
			if asset.ID <= 0 || asset.State != "uploaded" ||
				!immutableReleaseAssetDigestPattern.MatchString(asset.Digest) ||
				d.validateTrustedPublicAssetURL(asset.URL, base, spec, asset.ID) != nil {
				return nil, fmt.Errorf("Docker release asset %q has invalid immutable metadata", asset.Name)
			}
		}
	}
	if d.TrustedPublicOnly {
		if _, err := d.resolveTrustedReleaseTagCommit(ctx, base, spec, version); err != nil {
			return nil, err
		}
	}
	return assets, nil
}

func dockerManifestService(serviceType string) string {
	switch serviceType {
	case "control_panel":
		return "control-panel"
	case "encoder_recorder":
		return "encoder-recorder"
	case "discord_bot":
		return "discord-bot"
	default:
		return serviceType
	}
}

func dockerImageBase(image string) string {
	image = strings.TrimSpace(image)
	if at := strings.IndexByte(image, '@'); at >= 0 {
		image = image[:at]
	}
	lastSlash := strings.LastIndexByte(image, '/')
	if colon := strings.LastIndexByte(image, ':'); colon > lastSlash {
		image = image[:colon]
	}
	return image
}
