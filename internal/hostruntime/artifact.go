package hostruntime

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

const (
	defaultMaxArtifactBytes = int64(256 << 20)
	defaultMaxExtractBytes  = int64(1 << 30)
	defaultMaxEntries       = 10000
)

var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$`)

type RepoSpec struct {
	Owner  string
	Repo   string
	Prefix string
}

var repositoryByServiceType = map[string]RepoSpec{
	"control_panel":    {Owner: "Kome-Lab", Repo: "Autostream-ControlPanel", Prefix: "autostream-control-panel"},
	"worker":           {Owner: "Kome-Lab", Repo: "Autostream-Worker", Prefix: "autostream-worker"},
	"encoder_recorder": {Owner: "Kome-Lab", Repo: "Autostream-Encoder-Recorder", Prefix: "autostream-encoder-recorder"},
	"discord_bot":      {Owner: "Kome-Lab", Repo: "Autostream-DiscordBot", Prefix: "autostream-discord-bot"},
	"observability":    {Owner: "Kome-Lab", Repo: "Autostream-Observability", Prefix: "autostream-observability"},
}

type DownloadedArtifact struct {
	ArchivePath string
	RootDir     string
	SHA256      string
	AssetName   string
}

type ReleaseDownloader struct {
	Client  *http.Client
	APIBase string
	Token   string
	// TrustedPublicOnly enables the credential-free pull_v2 release policy.
	// It permits only the built-in Kome-Lab repositories on GitHub's production
	// API and requires immutable release/tag provenance before any artifact is
	// staged by the root local executor.
	TrustedPublicOnly bool
	MaxArtifactBytes  int64
	MaxExtractBytes   int64
	MaxEntries        int
	AllowHTTPForTest  bool

	hostAgentProvenanceVerifier releaseProvenanceVerifier
}

type githubRelease struct {
	TagName    string               `json:"tag_name"`
	Draft      bool                 `json:"draft"`
	Prerelease bool                 `json:"prerelease"`
	Immutable  bool                 `json:"immutable"`
	Assets     []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Digest string `json:"digest"`
	State  string `json:"state"`
}

type resolvedReleaseAssets struct {
	Archive          githubReleaseAsset
	ArchiveChecksum  githubReleaseAsset
	Manifest         githubReleaseAsset
	ManifestChecksum githubReleaseAsset
	TagCommit        string
}

type HostReleaseManifest struct {
	SchemaVersion       int                    `json:"schema_version"`
	ReleaseID           string                 `json:"release_id"`
	Channel             string                 `json:"channel"`
	PublishedAt         string                 `json:"published_at"`
	MinimumAgentVersion string                 `json:"minimum_agent_version"`
	Components          []HostReleaseComponent `json:"components"`
}

type HostReleaseComponent struct {
	Service            string                `json:"service"`
	SourceVersion      string                `json:"source_version"`
	Commit             string                `json:"commit"`
	Artifacts          []HostReleaseArtifact `json:"artifacts"`
	RollbackCompatible bool                  `json:"rollback_compatible"`
	DatabaseSchema     string                `json:"database_schema"`
}

type HostReleaseArtifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func (d ReleaseDownloader) Download(ctx context.Context, serviceType, version, arch, destDir string) (DownloadedArtifact, error) {
	spec, ok := repositoryByServiceType[serviceType]
	if !ok {
		return DownloadedArtifact{}, errors.New("service type has no release repository")
	}
	if !versionPattern.MatchString(version) {
		return DownloadedArtifact{}, errors.New("target version is invalid")
	}
	if arch != "amd64" && arch != "arm64" {
		return DownloadedArtifact{}, errors.New("only amd64 and arm64 host artifacts are supported")
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return DownloadedArtifact{}, fmt.Errorf("create artifact directory: %w", err)
	}
	assetName := fmt.Sprintf("%s_%s_linux_%s.tar.gz", spec.Prefix, version, arch)
	assets, err := d.resolveAssets(ctx, spec, version, assetName)
	if err != nil {
		return DownloadedArtifact{}, err
	}
	manifestPath := filepath.Join(destDir, "release-manifest.json")
	manifestDigest, err := d.downloadResolvedReleaseAsset(ctx, assets.Manifest, manifestPath, 4<<20)
	if err != nil {
		return DownloadedArtifact{}, fmt.Errorf("download host release manifest: %w", err)
	}
	manifestChecksumPath := manifestPath + ".sha256"
	if _, err := d.downloadResolvedReleaseAsset(ctx, assets.ManifestChecksum, manifestChecksumPath, 64<<10); err != nil {
		return DownloadedArtifact{}, fmt.Errorf("download host release manifest checksum: %w", err)
	}
	expectedManifestDigest, err := readSHA256File(manifestChecksumPath, "release-manifest.json")
	if err != nil || !strings.EqualFold(expectedManifestDigest, manifestDigest) {
		return DownloadedArtifact{}, errors.New("host release manifest SHA256 sidecar does not match")
	}
	manifestArtifact, err := validateHostReleaseManifest(manifestPath, serviceType, spec, version, arch, assetName, assets.TagCommit)
	if err != nil {
		return DownloadedArtifact{}, err
	}
	archivePath := filepath.Join(destDir, assetName)
	maxArtifact := d.MaxArtifactBytes
	if maxArtifact <= 0 {
		maxArtifact = defaultMaxArtifactBytes
	}
	digest, err := d.downloadResolvedReleaseAsset(ctx, assets.Archive, archivePath, maxArtifact)
	if err != nil {
		return DownloadedArtifact{}, fmt.Errorf("download release artifact: %w", err)
	}
	checksumPath := archivePath + ".sha256"
	if _, err := d.downloadResolvedReleaseAsset(ctx, assets.ArchiveChecksum, checksumPath, 1<<20); err != nil {
		return DownloadedArtifact{}, fmt.Errorf("download release checksum: %w", err)
	}
	expected, err := readSHA256File(checksumPath, assetName)
	if err != nil {
		return DownloadedArtifact{}, err
	}
	if !strings.EqualFold(expected, digest) {
		return DownloadedArtifact{}, errors.New("release artifact SHA256 does not match sidecar")
	}
	archiveInfo, statErr := os.Stat(archivePath)
	if statErr != nil || archiveInfo.Size() != manifestArtifact.Size || !strings.EqualFold(digest, manifestArtifact.SHA256) {
		return DownloadedArtifact{}, errors.New("release artifact does not match the host release manifest")
	}
	extractDir := filepath.Join(destDir, "extracted")
	maxExtract := d.MaxExtractBytes
	if maxExtract <= 0 {
		maxExtract = defaultMaxExtractBytes
	}
	maxEntries := d.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	root, err := ExtractTarGz(archivePath, extractDir, maxExtract, maxEntries)
	if err != nil {
		return DownloadedArtifact{}, err
	}
	if err := VerifyInnerChecksums(root); err != nil {
		return DownloadedArtifact{}, err
	}
	return DownloadedArtifact{ArchivePath: archivePath, RootDir: root, SHA256: digest, AssetName: assetName}, nil
}

func (d ReleaseDownloader) resolveAssets(ctx context.Context, spec RepoSpec, version, assetName string) (resolvedReleaseAssets, error) {
	base := strings.TrimRight(d.APIBase, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	if err := d.validateTrustedPublicRepository(base, spec); err != nil {
		return resolvedReleaseAssets{}, err
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases/tags/%s", base, url.PathEscape(spec.Owner), url.PathEscape(spec.Repo), url.PathEscape(version))
	var release githubRelease
	if err := d.getJSON(ctx, endpoint, &release); err != nil {
		return resolvedReleaseAssets{}, fmt.Errorf("resolve GitHub release: %w", err)
	}
	if d.TrustedPublicOnly {
		if err := validateTrustedPublicReleaseMetadata(release, version); err != nil {
			return resolvedReleaseAssets{}, err
		}
	}
	assets, err := uniqueReleaseAssets(release)
	if err != nil {
		return resolvedReleaseAssets{}, err
	}
	for _, asset := range release.Assets {
		if d.TrustedPublicOnly {
			if asset.ID <= 0 || asset.State != "uploaded" ||
				!immutableReleaseAssetDigestPattern.MatchString(asset.Digest) ||
				d.validateTrustedPublicAssetURL(asset.URL, base, spec, asset.ID) != nil {
				return resolvedReleaseAssets{}, fmt.Errorf("release asset %q has invalid immutable metadata", asset.Name)
			}
		}
	}
	archive, archiveOK := assets[assetName]
	checksum, checksumOK := assets[assetName+".sha256"]
	manifest, manifestOK := assets["release-manifest.json"]
	manifestChecksum, manifestChecksumOK := assets["release-manifest.json.sha256"]
	if !archiveOK || !checksumOK || !manifestOK || !manifestChecksumOK {
		return resolvedReleaseAssets{}, fmt.Errorf("release is missing %s, its checksum, or the host manifest checksums", assetName)
	}
	for _, asset := range []githubReleaseAsset{archive, checksum, manifest, manifestChecksum} {
		if err := d.validateAssetURL(asset.URL, base); err != nil {
			return resolvedReleaseAssets{}, err
		}
	}
	tagCommit := ""
	if d.TrustedPublicOnly {
		var err error
		tagCommit, err = d.resolveTrustedReleaseTagCommit(ctx, base, spec, version)
		if err != nil {
			return resolvedReleaseAssets{}, err
		}
	}
	return resolvedReleaseAssets{
		Archive:          archive,
		ArchiveChecksum:  checksum,
		Manifest:         manifest,
		ManifestChecksum: manifestChecksum,
		TagCommit:        tagCommit,
	}, nil
}

func validateTrustedPublicReleaseMetadata(release githubRelease, version string) error {
	if release.TagName != version || release.Draft || release.Prerelease || !release.Immutable {
		return errors.New("public release is not an immutable stable release for the requested tag")
	}
	return nil
}

func uniqueReleaseAssetURLs(release githubRelease) (map[string]string, error) {
	resolved, err := uniqueReleaseAssets(release)
	if err != nil {
		return nil, err
	}
	assets := make(map[string]string, len(resolved))
	for name, asset := range resolved {
		assets[name] = asset.URL
	}
	return assets, nil
}

func uniqueReleaseAssets(release githubRelease) (map[string]githubReleaseAsset, error) {
	assets := make(map[string]githubReleaseAsset, len(release.Assets))
	for _, asset := range release.Assets {
		if _, exists := assets[asset.Name]; exists {
			return nil, fmt.Errorf("release contains duplicate asset %q", asset.Name)
		}
		assets[asset.Name] = asset
	}
	return assets, nil
}

func validateHostReleaseManifest(path, serviceType string, spec RepoSpec, releaseVersion, arch, assetName, tagCommit string) (HostReleaseArtifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return HostReleaseArtifact{}, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 4<<20))
	decoder.DisallowUnknownFields()
	var manifest HostReleaseManifest
	if err := decoder.Decode(&manifest); err != nil {
		return HostReleaseArtifact{}, errors.New("host release manifest is invalid JSON")
	}
	if manifest.SchemaVersion != 1 || manifest.ReleaseID != releaseVersion || manifest.Channel != "host" || len(manifest.Components) != 1 {
		return HostReleaseArtifact{}, errors.New("host release manifest identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339, manifest.PublishedAt); err != nil {
		return HostReleaseArtifact{}, errors.New("host release manifest published_at is invalid")
	}
	if !versionPattern.MatchString(manifest.MinimumAgentVersion) || !semverAtLeast(controlversion.Current(), manifest.MinimumAgentVersion) {
		return HostReleaseArtifact{}, fmt.Errorf("host release requires updater %s or newer", manifest.MinimumAgentVersion)
	}
	component := manifest.Components[0]
	expectedService := dockerManifestService(serviceType)
	if component.Service != expectedService || component.SourceVersion != releaseVersion || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(strings.ToLower(component.Commit)) || !component.RollbackCompatible {
		return HostReleaseArtifact{}, errors.New("host release component identity or rollback policy is invalid")
	}
	if tagCommit != "" && component.Commit != tagCommit {
		return HostReleaseArtifact{}, errors.New("host release component commit does not match the immutable release tag")
	}
	expectedSchema := "none"
	if serviceType == "control_panel" || serviceType == "observability" {
		expectedSchema = "backward_compatible"
	}
	if component.DatabaseSchema != expectedSchema {
		return HostReleaseArtifact{}, errors.New("host release database_schema policy is invalid")
	}
	if len(component.Artifacts) != 2 {
		return HostReleaseArtifact{}, errors.New("host release manifest must contain amd64 and arm64 artifacts")
	}
	seen := map[string]bool{}
	var selected HostReleaseArtifact
	for _, artifact := range component.Artifacts {
		expectedName := fmt.Sprintf("%s_%s_linux_%s.tar.gz", spec.Prefix, releaseVersion, artifact.Arch)
		if artifact.OS != "linux" || (artifact.Arch != "amd64" && artifact.Arch != "arm64") || seen[artifact.Arch] || artifact.Name != expectedName || artifact.Size <= 0 || artifact.Size > defaultMaxArtifactBytes || len(artifact.SHA256) != 64 {
			return HostReleaseArtifact{}, errors.New("host release manifest contains invalid artifact metadata")
		}
		if _, err := hex.DecodeString(artifact.SHA256); err != nil {
			return HostReleaseArtifact{}, errors.New("host release manifest contains an invalid artifact SHA256")
		}
		seen[artifact.Arch] = true
		if artifact.Arch == arch && artifact.Name == assetName {
			selected = artifact
		}
	}
	if !seen["amd64"] || !seen["arm64"] || selected.Name == "" {
		return HostReleaseArtifact{}, errors.New("host release manifest is missing the requested architecture")
	}
	return selected, nil
}

func semverAtLeast(current, minimum string) bool {
	parse := func(value string) ([3]int, bool) {
		var out [3]int
		value = strings.TrimPrefix(strings.TrimSpace(value), "v")
		if _, err := fmt.Sscanf(strings.SplitN(value, "-", 2)[0], "%d.%d.%d", &out[0], &out[1], &out[2]); err != nil {
			return out, false
		}
		return out, true
	}
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(minimum) {
		return false
	}
	actual, actualOK := parse(current)
	required, requiredOK := parse(minimum)
	if !actualOK || !requiredOK {
		return false
	}
	for i := range actual {
		if actual[i] != required[i] {
			return actual[i] > required[i]
		}
	}
	return !strings.Contains(strings.TrimPrefix(strings.TrimSpace(current), "v"), "-")
}

func (d ReleaseDownloader) validateAssetURL(raw, apiBase string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("GitHub returned an invalid asset URL")
	}
	base, _ := url.Parse(apiBase)
	if u.Scheme != "https" && !d.AllowHTTPForTest {
		return errors.New("release asset URL must use HTTPS")
	}
	if !strings.EqualFold(u.Host, base.Host) {
		return errors.New("release asset URL must use the configured GitHub API host")
	}
	return nil
}

func (d ReleaseDownloader) validateTrustedPublicRepository(base string, spec RepoSpec) error {
	if !d.TrustedPublicOnly {
		return nil
	}
	if strings.TrimSpace(d.Token) != "" {
		return errors.New("credentialed release access is unavailable in public pull mode")
	}
	parsed, err := url.Parse(base)
	if err != nil ||
		parsed.Scheme != "https" ||
		!strings.EqualFold(parsed.Host, "api.github.com") ||
		parsed.EscapedPath() != "" ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		parsed.User != nil {
		return errors.New("public pull mode requires GitHub's production API origin")
	}
	trusted := false
	for _, candidate := range repositoryByServiceType {
		if candidate == spec {
			trusted = true
			break
		}
	}
	if spec == (RepoSpec{Owner: "Kome-Lab", Repo: "Autostream-Docker", Prefix: "autostream-docker"}) {
		trusted = true
	}
	if !trusted {
		return errors.New("public pull mode does not permit a custom release repository")
	}
	return nil
}

func (d ReleaseDownloader) validateTrustedPublicAssetURL(raw, base string, spec RepoSpec, assetID int64) error {
	if err := d.validateAssetURL(raw, base); err != nil {
		return err
	}
	assetURL, assetErr := url.Parse(raw)
	baseURL, baseErr := url.Parse(base)
	if assetErr != nil || baseErr != nil || assetID <= 0 {
		return errors.New("GitHub returned an invalid release asset API URL")
	}
	expectedPath := strings.TrimRight(baseURL.EscapedPath(), "/") + fmt.Sprintf(
		"/repos/%s/%s/releases/assets/%d",
		url.PathEscape(spec.Owner), url.PathEscape(spec.Repo), assetID,
	)
	if assetURL.EscapedPath() != expectedPath ||
		assetURL.RawQuery != "" ||
		assetURL.Fragment != "" ||
		assetURL.User != nil {
		return errors.New("release asset does not use its canonical GitHub asset API URL")
	}
	return nil
}

func (d ReleaseDownloader) resolveTrustedReleaseTagCommit(ctx context.Context, base string, spec RepoSpec, version string) (string, error) {
	endpoint := fmt.Sprintf(
		"%s/repos/%s/%s/git/ref/tags/%s",
		base, url.PathEscape(spec.Owner), url.PathEscape(spec.Repo), url.PathEscape(version),
	)
	var ref gitRef
	if err := d.getJSON(ctx, endpoint, &ref); err != nil {
		return "", fmt.Errorf("resolve immutable release tag: %w", err)
	}
	object := ref.Object
	seenTags := make(map[string]struct{}, 8)
	for depth := 0; object.Type == "tag"; depth++ {
		if depth >= 8 {
			return "", errors.New("immutable release tag exceeds the dereference limit")
		}
		if !updaterReleaseCommitPattern.MatchString(object.SHA) {
			return "", errors.New("immutable release tag object is invalid")
		}
		if _, seen := seenTags[object.SHA]; seen {
			return "", errors.New("immutable release tag contains a cycle")
		}
		seenTags[object.SHA] = struct{}{}
		tagEndpoint := fmt.Sprintf(
			"%s/repos/%s/%s/git/tags/%s",
			base, url.PathEscape(spec.Owner), url.PathEscape(spec.Repo), url.PathEscape(object.SHA),
		)
		var tag gitTag
		if err := d.getJSON(ctx, tagEndpoint, &tag); err != nil {
			return "", fmt.Errorf("dereference immutable release tag: %w", err)
		}
		object = tag.Object
	}
	if object.Type != "commit" || !updaterReleaseCommitPattern.MatchString(object.SHA) {
		return "", errors.New("immutable release tag does not resolve to a valid commit")
	}
	return object.SHA, nil
}

func (d ReleaseDownloader) httpClient() *http.Client {
	base := d.Client
	if base == nil {
		base = &http.Client{Timeout: 2 * time.Minute}
	}
	clone := *base
	if clone.Timeout == 0 || clone.Timeout > 2*time.Minute {
		clone.Timeout = 2 * time.Minute
	}
	prior := clone.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many release download redirects")
		}
		if req.URL.Scheme != "https" && !d.AllowHTTPForTest {
			return errors.New("release download redirect must use HTTPS")
		}
		if d.TrustedPublicOnly && !trustedGitHubReleaseRedirectHost(req.URL.Hostname()) {
			return errors.New("public release download redirected outside trusted GitHub storage")
		}
		if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			req.Header.Del("Authorization")
		}
		if prior != nil {
			return prior(req, via)
		}
		return nil
	}
	return &clone
}

func trustedGitHubReleaseRedirectHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com":
		return true
	default:
		return false
	}
}

func (d ReleaseDownloader) newRequest(ctx context.Context, raw string) (*http.Request, error) {
	if d.TrustedPublicOnly && strings.TrimSpace(d.Token) != "" {
		return nil, errors.New("public pull mode does not accept a release credential")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "autostream-updater")
	if strings.TrimSpace(d.Token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(d.Token))
	}
	return req, nil
}

func (d ReleaseDownloader) getJSON(ctx context.Context, raw string, out any) error {
	req, err := d.newRequest(ctx, raw)
	if err != nil {
		return err
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

func (d ReleaseDownloader) downloadFile(ctx context.Context, raw, dest string, max int64) (string, error) {
	req, err := d.newRequest(ctx, raw)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("asset endpoint returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > max {
		return "", errors.New("release asset exceeds size limit")
	}
	tmp := dest + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	remove := true
	defer func() {
		_ = f.Close()
		if remove {
			_ = os.Remove(tmp)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, max+1))
	if err != nil {
		return "", err
	}
	if n > max {
		return "", errors.New("release asset exceeds size limit")
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	remove = false
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d ReleaseDownloader) downloadResolvedReleaseAsset(ctx context.Context, asset githubReleaseAsset, dest string, max int64) (string, error) {
	digest, err := d.downloadFile(ctx, asset.URL, dest, max)
	if err != nil {
		return "", err
	}
	if d.TrustedPublicOnly && asset.Digest != "sha256:"+strings.ToLower(digest) {
		_ = os.Remove(dest)
		return "", fmt.Errorf("release asset %q does not match the GitHub API digest", asset.Name)
	}
	return digest, nil
}

func readSHA256File(path, expectedName string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
	if !scanner.Scan() {
		return "", errors.New("SHA256 sidecar is empty")
	}
	line := scanner.Text()
	if len(line) < 67 || line[64:66] != "  " {
		return "", errors.New("SHA256 sidecar has an invalid format or filename")
	}
	digest, checksumName := line[:64], line[66:]
	if checksumName != expectedName || strings.ToLower(digest) != digest || len(checksumName) == 0 {
		return "", errors.New("SHA256 sidecar has an invalid format or filename")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", errors.New("SHA256 sidecar contains an invalid digest")
	}
	if scanner.Scan() || scanner.Err() != nil {
		return "", errors.New("SHA256 sidecar must contain exactly one line")
	}
	return digest, nil
}

func ExtractTarGz(archivePath, dest string, maxBytes int64, maxEntries int) (string, error) {
	if err := os.Mkdir(dest, 0o700); err != nil {
		return "", fmt.Errorf("create extraction directory: %w", err)
	}
	// Extraction can run inside the transient helper's UMask=0077 sandbox.
	// Keep the wrapper private, but make its mode deterministic instead of
	// relying on the caller's process umask.
	if err := os.Chmod(dest, 0o700); err != nil {
		return "", fmt.Errorf("secure extraction directory: %w", err)
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	top := ""
	var total int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar: %w", err)
		}
		entries++
		if entries > maxEntries {
			return "", errors.New("archive contains too many entries")
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if !safeArchivePath(name) {
			return "", fmt.Errorf("archive contains unsafe path %q", hdr.Name)
		}
		if seen[name] {
			return "", fmt.Errorf("archive contains duplicate path %q", hdr.Name)
		}
		seen[name] = true
		part := strings.Split(name, "/")[0]
		if top == "" {
			top = part
		} else if top != part {
			return "", errors.New("archive must contain exactly one top-level directory")
		}
		out := filepath.Join(dest, filepath.FromSlash(name))
		if !pathWithin(dest, out) {
			return "", errors.New("archive path escaped extraction directory")
		}
		if hdr.Mode < 0 || hdr.Mode&^int64(0o777) != 0 {
			return "", fmt.Errorf("archive entry %q has forbidden mode bits", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(out, 0o755); err != nil {
				return "", err
			}
			if err := chmodExtractedDirectories(dest, out); err != nil {
				return "", err
			}
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size < 0 || total > maxBytes-hdr.Size {
				return "", errors.New("archive exceeds extraction size limit")
			}
			total += hdr.Size
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return "", err
			}
			if err := chmodExtractedDirectories(dest, filepath.Dir(out)); err != nil {
				return "", err
			}
			mode := os.FileMode(0o644)
			if os.FileMode(hdr.Mode)&0o111 != 0 {
				// Normalize every archive executable to the fixed release mode so
				// the configured smoke user can run it even when its producer used
				// an owner-only mode. Special bits were rejected above.
				mode = 0o755
			}
			outFile, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return "", err
			}
			n, copyErr := io.Copy(outFile, io.LimitReader(tr, hdr.Size+1))
			chmodErr := outFile.Chmod(mode)
			closeErr := outFile.Close()
			if copyErr != nil || chmodErr != nil || closeErr != nil || n != hdr.Size {
				return "", errors.New("archive entry could not be extracted completely")
			}
		default:
			return "", fmt.Errorf("archive entry %q has forbidden type %d", hdr.Name, hdr.Typeflag)
		}
	}
	if top == "" {
		return "", errors.New("archive is empty")
	}
	root := filepath.Join(dest, top)
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "", errors.New("archive top-level directory is missing")
	}
	return root, nil
}

// chmodExtractedDirectories restores the extraction policy after MkdirAll.
// MkdirAll applies the process umask, so a transient UMask=0077 would otherwise
// turn archive directories into 0700 and prevent the configured smoke user
// from traversing the verified artifact. Only descendants of the private
// extraction wrapper are made root-owned release-readable directories; the
// wrapper itself and the surrounding updater state remain 0700.
func chmodExtractedDirectories(root, leaf string) error {
	root = filepath.Clean(root)
	leaf = filepath.Clean(leaf)
	if !pathWithin(root, leaf) {
		return errors.New("extracted directory escaped extraction root")
	}
	rel, err := filepath.Rel(root, leaf)
	if err != nil {
		return errors.New("resolve extracted directory")
	}
	if rel == "." {
		return nil
	}
	current := root
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("extracted directory path is invalid")
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("extracted directory is unsafe")
		}
		if err := os.Chmod(current, 0o755); err != nil {
			return errors.New("restore extracted directory mode")
		}
	}
	return nil
}

func safeArchivePath(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, '\x00') {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(name)))
	return clean == name && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func VerifyInnerChecksums(root string) error {
	return verifyInnerChecksums(root, nil)
}

func verifyManagedReleaseChecksums(root string) error {
	return verifyInnerChecksums(root, map[string]bool{
		filepath.Clean(filepath.Join(root, ".artifact-sha256")): true,
		filepath.Clean(filepath.Join(root, ".version")):         true,
	})
}

func verifyInnerChecksums(root string, allowedExtra map[string]bool) error {
	manifestPath := filepath.Join(root, "checksums.txt")
	f, err := os.Open(manifestPath)
	if err != nil {
		return errors.New("artifact is missing checksums.txt")
	}
	defer f.Close()
	listed := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(f, 4<<20))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || len(fields[0]) != sha256.Size*2 {
			return errors.New("checksums.txt contains an invalid line")
		}
		name := strings.TrimPrefix(strings.TrimPrefix(fields[len(fields)-1], "*"), "./")
		if name == "checksums.txt" { // current release workflows include the newly-created manifest itself
			continue
		}
		if !safeArchivePath(name) || listed[name] != "" {
			return errors.New("checksums.txt contains an unsafe or duplicate path")
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return errors.New("checksums.txt contains an invalid digest")
		}
		listed[name] = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(listed) == 0 {
		return errors.New("checksums.txt contains no files")
	}
	seen := map[string]bool{}
	for name, expected := range listed {
		path := filepath.Join(root, filepath.FromSlash(name))
		if !pathWithin(root, path) {
			return errors.New("checksum path escaped artifact root")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("checksummed file %q is missing or not regular", name)
		}
		digest, err := hashFile(path)
		if err != nil || !strings.EqualFold(digest, expected) {
			return fmt.Errorf("inner checksum mismatch for %q", name)
		}
		seen[filepath.Clean(path)] = true
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("artifact contains a symlink")
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return errors.New("artifact contains a non-regular file")
		}
		if entry.Type().IsRegular() && filepath.Clean(path) != filepath.Clean(manifestPath) && !seen[filepath.Clean(path)] && !allowedExtra[filepath.Clean(path)] {
			return fmt.Errorf("artifact file %q is not listed in checksums.txt", path)
		}
		return nil
	})
	return err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
