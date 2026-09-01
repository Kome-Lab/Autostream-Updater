package hostruntime

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

var hostAgentReleaseRepository = RepoSpec{
	Owner: "Kome-Lab", Repo: "Autostream-Updater", Prefix: "autostream-host-agent",
}

type hostAgentReleaseManifest struct {
	SchemaVersion                           int                   `json:"schema_version"`
	ReleaseID                               string                `json:"release_id"`
	Channel                                 string                `json:"channel"`
	PublishedAt                             string                `json:"published_at"`
	Commit                                  string                `json:"commit"`
	AgentVersion                            string                `json:"agent_version"`
	ProtocolVersion                         int                   `json:"protocol_version"`
	ObserveOnly                             bool                  `json:"observe_only"`
	LocalExecutorProtocolVersion            int                   `json:"local_executor_protocol_version"`
	LocalExecutorProbeOnly                  bool                  `json:"local_executor_probe_only"`
	LocalExecutorProtocolMinVersion         int                   `json:"local_executor_protocol_min_version"`
	LocalExecutorProtocolMaxVersion         int                   `json:"local_executor_protocol_max_version"`
	LocalExecutorProbeCompatible            bool                  `json:"local_executor_probe_compatible"`
	LocalExecutorMutationProtocolVersion    int                   `json:"local_executor_mutation_protocol_version"`
	LocalExecutorMutationEnabled            bool                  `json:"local_executor_mutation_enabled"`
	LocalExecutorMutationRequiresRootPolicy bool                  `json:"local_executor_mutation_requires_root_policy"`
	RecoveryProtocolVersion                 int                   `json:"recovery_protocol_version"`
	MinimumPanelVersion                     string                `json:"minimum_panel_version"`
	Artifacts                               []HostReleaseArtifact `json:"artifacts"`
}

type HostAgentRelease struct {
	Artifact            DownloadedArtifact
	Request             HostSelfUpdateRequest
	PublishedAt         time.Time
	MinimumPanelVersion string
}

// HostAgentReleaseMetadata is the Control Plane-safe immutable release view.
// It deliberately contains no URL, credential, local path, or raw artifact.
type HostAgentReleaseMetadata struct {
	Tag                     string
	Commit                  string
	PublishedAt             time.Time
	ManifestAssetID         int64
	ManifestAssetName       string
	ManifestSHA256          string
	ManifestChecksumAssetID int64
	ManifestChecksumSHA256  string
	ArchiveAssetID          int64
	ArchiveAssetName        string
	ArchiveSize             int64
	ArchiveSHA256           string
	ArchiveChecksumAssetID  int64
	ArchiveChecksumSHA256   string
	Arch                    string
	AgentProtocolVersion    int
	ExecutorProtocolVersion int
	MutationProtocolVersion int
	RecoveryProtocolVersion int
	MinimumPanelVersion     string
	AttestationVerifiedAt   time.Time
}

// ResolveHostAgentReleaseMetadata verifies the fixed public Kome-Lab release
// without downloading or retaining the archive itself. The Host Agent and
// Local Executor independently download and verify the archive before use.
func (d ReleaseDownloader) ResolveHostAgentReleaseMetadata(
	ctx context.Context,
	version, arch string,
) (HostAgentReleaseMetadata, error) {
	if !versionPattern.MatchString(version) ||
		(arch != "amd64" && arch != "arm64") {
		return HostAgentReleaseMetadata{},
			errors.New("host agent release identity is invalid")
	}
	if !d.TrustedPublicOnly && !d.AllowHTTPForTest {
		return HostAgentReleaseMetadata{},
			errors.New("host self-update requires public immutable release mode")
	}
	if strings.TrimSpace(d.Token) != "" {
		return HostAgentReleaseMetadata{},
			errors.New("host self-update does not accept a release credential")
	}
	root, err := os.MkdirTemp("", "autostream-host-release-metadata-")
	if err != nil {
		return HostAgentReleaseMetadata{}, err
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		return HostAgentReleaseMetadata{}, err
	}
	assetName := hostAgentReleaseAssetName(version, arch)
	release, err := d.resolveHostAgentRelease(ctx, version, assetName)
	if err != nil {
		return HostAgentReleaseMetadata{}, err
	}
	manifestPath := filepath.Join(root, hostAgentManifestName)
	manifestDigest, err := d.downloadUpdaterReleaseAsset(
		ctx, release.Manifest, manifestPath, 4<<20,
	)
	if err != nil {
		return HostAgentReleaseMetadata{}, err
	}
	manifestChecksumPath := manifestPath + ".sha256"
	manifestChecksumDigest, err := d.downloadUpdaterReleaseAsset(
		ctx, release.ManifestChecksum, manifestChecksumPath, 64<<10,
	)
	if err != nil {
		return HostAgentReleaseMetadata{}, err
	}
	expectedManifestDigest, err := readSHA256File(
		manifestChecksumPath, hostAgentManifestName,
	)
	if err != nil || expectedManifestDigest != manifestDigest {
		return HostAgentReleaseMetadata{},
			errors.New("host agent manifest SHA256 sidecar does not match")
	}
	if err := d.verifyHostAgentReleaseProvenance(
		ctx, version, manifestDigest, release.TagCommit,
	); err != nil {
		return HostAgentReleaseMetadata{}, err
	}
	manifest, artifact, publishedAt, err :=
		validateHostAgentReleaseManifest(
			manifestPath, version, arch, assetName, release.TagCommit,
		)
	if err != nil {
		return HostAgentReleaseMetadata{}, err
	}
	if !updaterReleaseSemverAtLeast(
		controlversion.Current(), manifest.MinimumPanelVersion,
	) {
		return HostAgentReleaseMetadata{},
			errors.New("Control Panel is older than the host release minimum")
	}
	archiveChecksumPath := filepath.Join(root, assetName+".sha256")
	archiveChecksumDigest, err := d.downloadUpdaterReleaseAsset(
		ctx, release.ArchiveChecksum, archiveChecksumPath, 64<<10,
	)
	if err != nil {
		return HostAgentReleaseMetadata{}, err
	}
	expectedArchiveDigest, err := readSHA256File(
		archiveChecksumPath, assetName,
	)
	if err != nil ||
		expectedArchiveDigest != artifact.SHA256 ||
		release.Archive.Digest != "sha256:"+artifact.SHA256 {
		return HostAgentReleaseMetadata{},
			errors.New("host agent archive metadata does not match")
	}
	return HostAgentReleaseMetadata{
		Tag:                     version,
		Commit:                  release.TagCommit,
		PublishedAt:             publishedAt,
		ManifestAssetID:         release.Manifest.ID,
		ManifestAssetName:       release.Manifest.Name,
		ManifestSHA256:          manifestDigest,
		ManifestChecksumAssetID: release.ManifestChecksum.ID,
		ManifestChecksumSHA256:  manifestChecksumDigest,
		ArchiveAssetID:          release.Archive.ID,
		ArchiveAssetName:        release.Archive.Name,
		ArchiveSize:             artifact.Size,
		ArchiveSHA256:           artifact.SHA256,
		ArchiveChecksumAssetID:  release.ArchiveChecksum.ID,
		ArchiveChecksumSHA256:   archiveChecksumDigest,
		Arch:                    arch,
		AgentProtocolVersion:    manifest.ProtocolVersion,
		ExecutorProtocolVersion: manifest.LocalExecutorProtocolVersion,
		MutationProtocolVersion: manifest.LocalExecutorMutationProtocolVersion,
		RecoveryProtocolVersion: manifest.RecoveryProtocolVersion,
		MinimumPanelVersion:     manifest.MinimumPanelVersion,
		AttestationVerifiedAt:   time.Now().UTC(),
	}, nil
}

// DownloadHostAgentRelease verifies the public immutable Updater repository
// release, exact tag commit, checksums and Actions attestation before exposing
// the paired Host Agent / Local Executor artifact to the root staging code.
func (d ReleaseDownloader) DownloadHostAgentRelease(
	ctx context.Context,
	version, arch, destDir string,
) (HostAgentRelease, error) {
	if !versionPattern.MatchString(version) {
		return HostAgentRelease{}, errors.New("host agent release version is invalid")
	}
	if arch != "amd64" && arch != "arm64" {
		return HostAgentRelease{}, errors.New("only amd64 and arm64 host agent releases are supported")
	}
	if !d.TrustedPublicOnly && !d.AllowHTTPForTest {
		return HostAgentRelease{}, errors.New("host self-update requires public immutable release mode")
	}
	if strings.TrimSpace(d.Token) != "" {
		return HostAgentRelease{}, errors.New("host self-update does not accept a release credential")
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return HostAgentRelease{}, fmt.Errorf("create host self-update artifact directory: %w", err)
	}
	if err := os.Chmod(destDir, 0o700); err != nil {
		return HostAgentRelease{}, errors.New("secure host self-update artifact directory")
	}

	assetName := hostAgentReleaseAssetName(version, arch)
	release, err := d.resolveHostAgentRelease(ctx, version, assetName)
	if err != nil {
		return HostAgentRelease{}, err
	}
	manifestPath := filepath.Join(destDir, hostAgentManifestName)
	manifestDigest, err := d.downloadUpdaterReleaseAsset(
		ctx, release.Manifest, manifestPath, 4<<20,
	)
	if err != nil {
		return HostAgentRelease{}, fmt.Errorf("download host agent manifest: %w", err)
	}
	checksumPath := manifestPath + ".sha256"
	manifestChecksumDigest, err := d.downloadUpdaterReleaseAsset(
		ctx, release.ManifestChecksum, checksumPath, 64<<10,
	)
	if err != nil {
		return HostAgentRelease{}, fmt.Errorf("download host agent manifest checksum: %w", err)
	}
	expectedManifestDigest, err := readSHA256File(checksumPath, hostAgentManifestName)
	if err != nil || expectedManifestDigest != manifestDigest {
		return HostAgentRelease{}, errors.New("host agent manifest SHA256 sidecar does not match")
	}
	if err := d.verifyHostAgentReleaseProvenance(
		ctx, version, manifestDigest, release.TagCommit,
	); err != nil {
		return HostAgentRelease{}, err
	}
	manifest, artifactMetadata, publishedAt, err := validateHostAgentReleaseManifest(
		manifestPath, version, arch, assetName, release.TagCommit,
	)
	if err != nil {
		return HostAgentRelease{}, err
	}

	archivePath := filepath.Join(destDir, assetName)
	maxArtifact := d.MaxArtifactBytes
	if maxArtifact <= 0 {
		maxArtifact = defaultMaxArtifactBytes
	}
	artifactDigest, err := d.downloadUpdaterReleaseAsset(
		ctx, release.Archive, archivePath, maxArtifact,
	)
	if err != nil {
		return HostAgentRelease{}, fmt.Errorf("download host agent artifact: %w", err)
	}
	archiveChecksumPath := archivePath + ".sha256"
	archiveChecksumDigest, err := d.downloadUpdaterReleaseAsset(
		ctx, release.ArchiveChecksum, archiveChecksumPath, 64<<10,
	)
	if err != nil {
		return HostAgentRelease{}, fmt.Errorf("download host agent artifact checksum: %w", err)
	}
	expectedArtifactDigest, err := readSHA256File(archiveChecksumPath, assetName)
	if err != nil || expectedArtifactDigest != artifactDigest {
		return HostAgentRelease{}, errors.New("host agent artifact SHA256 sidecar does not match")
	}
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() != artifactMetadata.Size ||
		artifactDigest != artifactMetadata.SHA256 {
		return HostAgentRelease{}, errors.New("host agent artifact does not match the trusted manifest")
	}

	maxExtract := d.MaxExtractBytes
	if maxExtract <= 0 {
		maxExtract = defaultMaxExtractBytes
	}
	maxEntries := d.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultMaxEntries
	}
	root, err := ExtractTarGz(
		archivePath, filepath.Join(destDir, "extracted"), maxExtract, maxEntries,
	)
	if err != nil {
		return HostAgentRelease{}, err
	}
	if err := VerifyInnerChecksums(root); err != nil {
		return HostAgentRelease{}, err
	}
	for _, name := range []string{
		"autostream-host-agent", "autostream-local-executor",
	} {
		binaryPath := filepath.Join(root, "bin", name)
		binary, err := os.Lstat(binaryPath)
		if err != nil || !binary.Mode().IsRegular() ||
			binary.Mode()&os.ModeSymlink != 0 ||
			(runtime.GOOS != "windows" && binary.Mode().Perm()&0o111 == 0) {
			return HostAgentRelease{}, fmt.Errorf(
				"host agent artifact is missing executable %s (stat=%v mode=%v)",
				name, err, func() os.FileMode {
					if binary == nil {
						return 0
					}
					return binary.Mode()
				}(),
			)
		}
	}

	return HostAgentRelease{
		Artifact: DownloadedArtifact{
			ArchivePath: archivePath, RootDir: root,
			SHA256: artifactDigest, AssetName: assetName,
		},
		Request: HostSelfUpdateRequest{
			Generation:              "release-" + version,
			AgentVersion:            manifest.AgentVersion,
			ExecutorVersion:         manifest.AgentVersion,
			Commit:                  manifest.Commit,
			ArtifactSHA256:          "sha256:" + artifactDigest,
			AgentProtocolVersion:    manifest.ProtocolVersion,
			ExecutorProtocolVersion: manifest.LocalExecutorProtocolVersion,
			MutationProtocolVersion: manifest.LocalExecutorMutationProtocolVersion,
			RecoveryProtocolVersion: manifest.RecoveryProtocolVersion,
			Release: HostSelfUpdateReleaseIdentity{
				Tag:                     version,
				Commit:                  release.TagCommit,
				PublishedAt:             publishedAt,
				ManifestAssetID:         release.Manifest.ID,
				ManifestAssetName:       release.Manifest.Name,
				ManifestSHA256:          manifestDigest,
				ManifestChecksumAssetID: release.ManifestChecksum.ID,
				ManifestChecksumSHA256:  manifestChecksumDigest,
				ArchiveAssetID:          release.Archive.ID,
				ArchiveAssetName:        release.Archive.Name,
				ArchiveSize:             artifactMetadata.Size,
				ArchiveSHA256:           artifactDigest,
				ArchiveChecksumAssetID:  release.ArchiveChecksum.ID,
				ArchiveChecksumSHA256:   archiveChecksumDigest,
				Arch:                    arch,
				AgentProtocolVersion:    manifest.ProtocolVersion,
				ExecutorProtocolVersion: manifest.LocalExecutorProtocolVersion,
				MutationProtocolVersion: manifest.LocalExecutorMutationProtocolVersion,
				RecoveryProtocolVersion: manifest.RecoveryProtocolVersion,
				MinimumPanelVersion:     manifest.MinimumPanelVersion,
			},
		},
		PublishedAt:         publishedAt,
		MinimumPanelVersion: manifest.MinimumPanelVersion,
	}, nil
}

func (d ReleaseDownloader) resolveHostAgentRelease(
	ctx context.Context,
	version, assetName string,
) (resolvedImmutableRelease, error) {
	base := strings.TrimRight(strings.TrimSpace(d.APIBase), "/")
	if base == "" {
		base = "https://api.github.com"
	}
	if !d.AllowHTTPForTest {
		parsed, err := url.Parse(base)
		if err != nil || parsed.Scheme != "https" ||
			!strings.EqualFold(parsed.Host, "api.github.com") ||
			parsed.EscapedPath() != "" || parsed.RawQuery != "" ||
			parsed.Fragment != "" || parsed.User != nil {
			return resolvedImmutableRelease{}, errors.New("host self-update requires GitHub's production API origin")
		}
	}
	endpoint := fmt.Sprintf(
		"%s/repos/%s/%s/releases/tags/%s",
		base,
		url.PathEscape(hostAgentReleaseRepository.Owner),
		url.PathEscape(hostAgentReleaseRepository.Repo),
		url.PathEscape(version),
	)
	var release githubRelease
	if err := d.getJSON(ctx, endpoint, &release); err != nil {
		return resolvedImmutableRelease{}, fmt.Errorf("resolve host agent release: %w", err)
	}
	if err := validateTrustedPublicReleaseMetadata(release, version); err != nil {
		return resolvedImmutableRelease{}, err
	}
	assets, err := uniqueReleaseAssets(release)
	if err != nil {
		return resolvedImmutableRelease{}, err
	}
	archive, archiveOK := assets[assetName]
	archiveChecksum, checksumOK := assets[assetName+".sha256"]
	manifest, manifestOK := assets[hostAgentManifestName]
	manifestChecksum, manifestChecksumOK := assets[hostAgentManifestName+".sha256"]
	if !archiveOK || !checksumOK || !manifestOK || !manifestChecksumOK {
		return resolvedImmutableRelease{}, errors.New("host agent release is incomplete")
	}
	convert := func(asset githubReleaseAsset) (immutableReleaseAsset, error) {
		converted := immutableReleaseAsset{
			ID: asset.ID, Name: asset.Name, URL: asset.URL,
			Digest: asset.Digest, State: asset.State,
		}
		if converted.State != "uploaded" ||
			!immutableReleaseAssetDigestPattern.MatchString(converted.Digest) {
			return immutableReleaseAsset{}, fmt.Errorf("host agent release asset %q has invalid immutable metadata", converted.Name)
		}
		if err := d.validateUpdaterReleaseAssetURL(converted, base); err != nil {
			return immutableReleaseAsset{}, err
		}
		return converted, nil
	}
	converted := make([]immutableReleaseAsset, 0, 4)
	for _, asset := range []githubReleaseAsset{
		archive, archiveChecksum, manifest, manifestChecksum,
	} {
		item, err := convert(asset)
		if err != nil {
			return resolvedImmutableRelease{}, err
		}
		converted = append(converted, item)
	}
	tagCommit, err := d.resolveUpdaterReleaseTagCommit(ctx, base, version)
	if err != nil {
		return resolvedImmutableRelease{}, err
	}
	return resolvedImmutableRelease{
		Archive: converted[0], ArchiveChecksum: converted[1],
		Manifest: converted[2], ManifestChecksum: converted[3],
		TagCommit: tagCommit,
	}, nil
}

func (d ReleaseDownloader) verifyHostAgentReleaseProvenance(
	ctx context.Context,
	version, manifestDigest, tagCommit string,
) error {
	verifier := d.hostAgentProvenanceVerifier
	if verifier == nil {
		verifier = sigstoreHostAgentProvenanceVerifier{}
	}
	if err := verifier.Verify(ctx, d, version, manifestDigest, tagCommit); err != nil {
		return fmt.Errorf("host agent manifest has no trusted Actions provenance: %w", err)
	}
	return nil
}

func validateHostAgentReleaseManifest(
	path, releaseVersion, arch, assetName, tagCommit string,
) (hostAgentReleaseManifest, HostReleaseArtifact, time.Time, error) {
	file, err := os.Open(path)
	if err != nil {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	decoder.DisallowUnknownFields()
	var manifest hostAgentReleaseManifest
	if err := decoder.Decode(&manifest); err != nil {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
			errors.New("host agent manifest is invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
			errors.New("host agent manifest contains trailing data")
	}
	publishedAt, err := time.Parse(time.RFC3339, manifest.PublishedAt)
	if err != nil || publishedAt.Location() != time.UTC {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
			errors.New("host agent manifest published_at is invalid")
	}
	if manifest.SchemaVersion != 1 ||
		manifest.ReleaseID != releaseVersion ||
		manifest.Channel != "host-agent" ||
		manifest.AgentVersion != releaseVersion ||
		manifest.Commit != tagCommit ||
		!updaterReleaseCommitPattern.MatchString(manifest.Commit) {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
			errors.New("host agent manifest identity is invalid")
	}
	if manifest.ProtocolVersion != 2 ||
		manifest.ObserveOnly ||
		manifest.LocalExecutorProtocolVersion != LocalExecutorMutationProtocolVersion ||
		manifest.LocalExecutorProbeOnly ||
		manifest.LocalExecutorProtocolMinVersion != LocalExecutorProtocolVersion ||
		manifest.LocalExecutorProtocolMaxVersion != LocalExecutorMutationProtocolVersion ||
		!manifest.LocalExecutorProbeCompatible ||
		manifest.LocalExecutorMutationProtocolVersion != LocalExecutorMutationProtocolVersion ||
		!manifest.LocalExecutorMutationEnabled ||
		!manifest.LocalExecutorMutationRequiresRootPolicy ||
		manifest.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
			errors.New("host agent manifest protocol compatibility is invalid")
	}
	if !versionPattern.MatchString(manifest.MinimumPanelVersion) {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
			errors.New("host agent manifest minimum panel version is invalid")
	}
	if len(manifest.Artifacts) != 2 {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
			errors.New("host agent manifest must contain amd64 and arm64 artifacts")
	}
	seen := make(map[string]bool, 2)
	var selected HostReleaseArtifact
	for _, artifact := range manifest.Artifacts {
		expectedName := hostAgentReleaseAssetName(releaseVersion, artifact.Arch)
		if artifact.OS != "linux" ||
			(artifact.Arch != "amd64" && artifact.Arch != "arm64") ||
			seen[artifact.Arch] ||
			artifact.Name != expectedName ||
			artifact.Size <= 0 || artifact.Size > defaultMaxArtifactBytes ||
			len(artifact.SHA256) != 64 ||
			artifact.SHA256 != strings.ToLower(artifact.SHA256) {
			return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
				errors.New("host agent manifest contains invalid artifact metadata")
		}
		if _, err := hex.DecodeString(artifact.SHA256); err != nil {
			return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
				errors.New("host agent manifest contains an invalid artifact SHA256")
		}
		seen[artifact.Arch] = true
		if artifact.Arch == arch && artifact.Name == assetName {
			selected = artifact
		}
	}
	if !seen["amd64"] || !seen["arm64"] || selected.Name == "" {
		return hostAgentReleaseManifest{}, HostReleaseArtifact{}, time.Time{},
			errors.New("host agent manifest is missing the requested architecture")
	}
	return manifest, selected, publishedAt, nil
}

func hostAgentReleaseAssetName(version, arch string) string {
	return hostAgentReleaseRepository.Prefix + "_" + version + "_linux_" + arch + ".tar.gz"
}

func currentHostRuntimeCompatibility(executorVersion string) HostRuntimeCompatibility {
	return HostRuntimeCompatibility{
		AgentVersion:            controlversion.Current(),
		ExecutorVersion:         executorVersion,
		AgentProtocolVersion:    2,
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		MutationProtocolVersion: LocalExecutorMutationProtocolVersion,
		RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
	}
}
