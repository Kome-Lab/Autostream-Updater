package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	hostSelfUpdateArtifactTestVersion = "v1.8.0"
	hostSelfUpdateArtifactTestCommit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestHostReleaseScriptsRecoveryProtocolMatchesRuntime(t *testing.T) {
	protocol := strconv.Itoa(HostSelfUpdateRecoveryProtocolVersion)
	checks := []struct {
		path   string
		marker string
	}{
		{
			path:   filepath.Join("..", "..", "scripts", "ci", "build-release-bundles.sh"),
			marker: "recovery_protocol_version: " + protocol + ",",
		},
		{
			path:   filepath.Join("..", "..", "scripts", "ci", "verify-release-bundles.sh"),
			marker: ".recovery_protocol_version == " + protocol + " and",
		},
	}
	for _, check := range checks {
		payload, err := os.ReadFile(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(payload), check.marker) {
			t.Fatalf(
				"host release script recovery protocol does not match runtime: %s missing %q",
				check.path,
				check.marker,
			)
		}
	}
}

func TestDownloadHostAgentReleaseBindsImmutableManifestAndBothBinaries(t *testing.T) {
	root := strings.TrimSuffix(
		hostAgentReleaseAssetName(hostSelfUpdateArtifactTestVersion, "amd64"),
		".tar.gz",
	)
	agent := []byte("host-agent-v1.8.0")
	executor := []byte("local-executor-v1.8.0")
	agentSum := sha256.Sum256(agent)
	executorSum := sha256.Sum256(executor)
	archive := makeBootstrapTarGz(t, []bootstrapTarEntry{
		{name: root + "/bin/autostream-host-agent", body: agent},
		{name: root + "/bin/autostream-local-executor", body: executor},
		{name: root + "/checksums.txt", body: []byte(fmt.Sprintf(
			"%x  ./bin/autostream-host-agent\n%x  ./bin/autostream-local-executor\n",
			agentSum,
			executorSum,
		))},
	})
	archiveSum := sha256.Sum256(archive)
	assetName := root + ".tar.gz"
	manifest := hostAgentReleaseManifest{
		SchemaVersion:                           1,
		ReleaseID:                               hostSelfUpdateArtifactTestVersion,
		Channel:                                 "host-agent",
		PublishedAt:                             "2026-07-28T00:00:00Z",
		Commit:                                  hostSelfUpdateArtifactTestCommit,
		AgentVersion:                            hostSelfUpdateArtifactTestVersion,
		ProtocolVersion:                         2,
		ObserveOnly:                             false,
		LocalExecutorProtocolVersion:            2,
		LocalExecutorProbeOnly:                  false,
		LocalExecutorProtocolMinVersion:         1,
		LocalExecutorProtocolMaxVersion:         2,
		LocalExecutorProbeCompatible:            true,
		LocalExecutorMutationProtocolVersion:    2,
		LocalExecutorMutationEnabled:            true,
		LocalExecutorMutationRequiresRootPolicy: true,
		RecoveryProtocolVersion:                 HostSelfUpdateRecoveryProtocolVersion,
		MinimumPanelVersion:                     "v1.8.0",
		Artifacts: []HostReleaseArtifact{
			{OS: "linux", Arch: "amd64", Name: assetName, Size: int64(len(archive)), SHA256: hex.EncodeToString(archiveSum[:])},
			{OS: "linux", Arch: "arm64", Name: hostAgentReleaseAssetName(hostSelfUpdateArtifactTestVersion, "arm64"), Size: 1, SHA256: strings.Repeat("b", 64)},
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifestJSON)
	archiveSidecar := fmt.Sprintf("%x  %s\n", archiveSum, assetName)
	manifestSidecar := fmt.Sprintf("%x  %s\n", manifestSum, hostAgentManifestName)
	payloads := map[string][]byte{
		assetName:                         archive,
		assetName + ".sha256":             []byte(archiveSidecar),
		hostAgentManifestName:             manifestJSON,
		hostAgentManifestName + ".sha256": []byte(manifestSidecar),
	}

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/Kome-Lab/Autostream-Updater/releases/tags/" + hostSelfUpdateArtifactTestVersion:
			names := []string{assetName, assetName + ".sha256", hostAgentManifestName, hostAgentManifestName + ".sha256"}
			assets := make([]immutableReleaseAsset, 0, len(names))
			for index, name := range names {
				sum := sha256.Sum256(payloads[name])
				assets = append(assets, immutableReleaseAsset{
					ID: int64(index + 1), Name: name,
					URL:    server.URL + "/repos/Kome-Lab/Autostream-Updater/releases/assets/" + fmt.Sprint(index+1),
					Digest: "sha256:" + hex.EncodeToString(sum[:]), State: "uploaded",
				})
			}
			_ = json.NewEncoder(w).Encode(updaterReleaseGitHubRelease{
				TagName: hostSelfUpdateArtifactTestVersion, Immutable: true, Assets: assets,
			})
		case "/repos/Kome-Lab/Autostream-Updater/git/ref/tags/" + hostSelfUpdateArtifactTestVersion:
			fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, hostSelfUpdateArtifactTestCommit)
		default:
			const prefix = "/repos/Kome-Lab/Autostream-Updater/releases/assets/"
			if strings.HasPrefix(r.URL.Path, prefix) {
				var index int
				if _, err := fmt.Sscanf(strings.TrimPrefix(r.URL.Path, prefix), "%d", &index); err == nil && index >= 1 && index <= 4 {
					names := []string{assetName, assetName + ".sha256", hostAgentManifestName, hostAgentManifestName + ".sha256"}
					_, _ = w.Write(payloads[names[index-1]])
					return
				}
			}
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	downloader := ReleaseDownloader{
		APIBase: server.URL, Client: server.Client(), AllowHTTPForTest: true,
		hostAgentProvenanceVerifier: bootstrapProvenanceVerifierFunc(func(
			_ context.Context,
			_ ReleaseDownloader,
			version, manifestDigest, commit string,
		) error {
			if version != hostSelfUpdateArtifactTestVersion ||
				manifestDigest != hex.EncodeToString(manifestSum[:]) ||
				commit != hostSelfUpdateArtifactTestCommit {
				return fmt.Errorf("unexpected provenance binding")
			}
			return nil
		}),
	}
	release, err := downloader.DownloadHostAgentRelease(
		context.Background(),
		hostSelfUpdateArtifactTestVersion,
		"amd64",
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("download host agent release: %v", err)
	}
	if release.Request.AgentVersion != hostSelfUpdateArtifactTestVersion ||
		release.Request.ExecutorVersion != hostSelfUpdateArtifactTestVersion ||
		release.Request.Commit != hostSelfUpdateArtifactTestCommit ||
		release.Request.ArtifactSHA256 != "sha256:"+hex.EncodeToString(archiveSum[:]) ||
		release.Request.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion ||
		release.PublishedAt.Format("2006-01-02T15:04:05Z07:00") != "2026-07-28T00:00:00Z" ||
		release.Artifact.RootDir == "" {
		t.Fatalf("unexpected host self-update release: %#v", release)
	}
	archiveSidecarSum := sha256.Sum256([]byte(archiveSidecar))
	manifestSidecarSum := sha256.Sum256([]byte(manifestSidecar))
	identity := release.Request.Release
	if identity.Tag != hostSelfUpdateArtifactTestVersion ||
		identity.Commit != hostSelfUpdateArtifactTestCommit ||
		identity.ManifestAssetID != 3 ||
		identity.ManifestAssetName != hostAgentManifestName ||
		identity.ManifestSHA256 != hex.EncodeToString(manifestSum[:]) ||
		identity.ManifestChecksumAssetID != 4 ||
		identity.ManifestChecksumSHA256 !=
			hex.EncodeToString(manifestSidecarSum[:]) ||
		identity.ArchiveAssetID != 1 ||
		identity.ArchiveAssetName != assetName ||
		identity.ArchiveSize != int64(len(archive)) ||
		identity.ArchiveSHA256 != hex.EncodeToString(archiveSum[:]) ||
		identity.ArchiveChecksumAssetID != 2 ||
		identity.ArchiveChecksumSHA256 !=
			hex.EncodeToString(archiveSidecarSum[:]) ||
		identity.MinimumPanelVersion != "v1.8.0" ||
		!identity.PublishedAt.Equal(release.PublishedAt) {
		t.Fatalf("root download lost immutable release metadata: %#v", identity)
	}
}

func TestValidateHostAgentReleaseManifestRejectsProtocolDrift(t *testing.T) {
	path := t.TempDir() + "/host-agent-manifest.json"
	manifest := hostAgentReleaseManifest{
		SchemaVersion: 1, ReleaseID: "v1.8.0", Channel: "host-agent",
		PublishedAt: "2026-07-28T00:00:00Z",
		Commit:      strings.Repeat("a", 40), AgentVersion: "v1.8.0",
		ProtocolVersion: 2, LocalExecutorProtocolVersion: 2,
		LocalExecutorProtocolMinVersion: 1, LocalExecutorProtocolMaxVersion: 2,
		LocalExecutorProbeCompatible:            true,
		LocalExecutorMutationProtocolVersion:    3,
		LocalExecutorMutationEnabled:            true,
		LocalExecutorMutationRequiresRootPolicy: true,
		RecoveryProtocolVersion:                 HostSelfUpdateRecoveryProtocolVersion,
		MinimumPanelVersion:                     "v1.8.0",
		Artifacts: []HostReleaseArtifact{
			{OS: "linux", Arch: "amd64", Name: "autostream-host-agent_v1.8.0_linux_amd64.tar.gz", Size: 1, SHA256: strings.Repeat("a", 64)},
			{OS: "linux", Arch: "arm64", Name: "autostream-host-agent_v1.8.0_linux_arm64.tar.gz", Size: 1, SHA256: strings.Repeat("b", 64)},
		},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := validateHostAgentReleaseManifest(
		path, "v1.8.0", "amd64",
		"autostream-host-agent_v1.8.0_linux_amd64.tar.gz",
		strings.Repeat("a", 40),
	); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("protocol drift accepted: %v", err)
	}
}

func TestHostSelfUpdateReleaseMatcherIgnoresOnlyAttemptGeneration(t *testing.T) {
	request := validHostSelfUpdateRequest()
	release := HostAgentRelease{
		Request:             request,
		PublishedAt:         request.Release.PublishedAt,
		MinimumPanelVersion: request.Release.MinimumPanelVersion,
	}
	release.Request.Generation = "release-v1.8.0"
	directive := release.Request
	directive.Generation = "11111111-1111-4111-8111-111111111111"

	if !hostSelfUpdateReleaseMatchesRequest(release, directive) {
		t.Fatal("immutable release identity was coupled to attempt generation")
	}
	incomplete := release
	incomplete.PublishedAt = time.Time{}
	if hostSelfUpdateReleaseMatchesRequest(incomplete, directive) {
		t.Fatal("missing immutable publication time was ignored")
	}
	incomplete = release
	incomplete.MinimumPanelVersion = ""
	if hostSelfUpdateReleaseMatchesRequest(incomplete, directive) {
		t.Fatal("missing minimum panel version was ignored")
	}
	directive.ArtifactSHA256 = "sha256:" + strings.Repeat("c", 64)
	if hostSelfUpdateReleaseMatchesRequest(release, directive) {
		t.Fatal("immutable artifact digest mismatch was ignored")
	}
}

func TestHostSelfUpdateReleaseMatcherRejectsEveryServerResolvedMetadataDrift(
	t *testing.T,
) {
	request := validHostSelfUpdateRequest()
	release := HostAgentRelease{
		Request:             request,
		PublishedAt:         request.Release.PublishedAt,
		MinimumPanelVersion: request.Release.MinimumPanelVersion,
	}
	release.Request.Generation = "release-" + request.AgentVersion
	tests := map[string]func(*HostSelfUpdateRequest){
		"commit": func(value *HostSelfUpdateRequest) {
			value.Commit = strings.Repeat("c", 40)
			value.Release.Commit = value.Commit
		},
		"published_at": func(value *HostSelfUpdateRequest) {
			value.Release.PublishedAt =
				value.Release.PublishedAt.Add(time.Second)
		},
		"manifest_asset_id": func(value *HostSelfUpdateRequest) {
			value.Release.ManifestAssetID += 10
		},
		"manifest_sha256": func(value *HostSelfUpdateRequest) {
			value.Release.ManifestSHA256 = strings.Repeat("5", 64)
		},
		"manifest_checksum_asset_id": func(value *HostSelfUpdateRequest) {
			value.Release.ManifestChecksumAssetID += 10
		},
		"manifest_checksum_sha256": func(value *HostSelfUpdateRequest) {
			value.Release.ManifestChecksumSHA256 = strings.Repeat("6", 64)
		},
		"archive_asset_id": func(value *HostSelfUpdateRequest) {
			value.Release.ArchiveAssetID += 10
		},
		"archive_asset_name": func(value *HostSelfUpdateRequest) {
			value.Release.ArchiveAssetName =
				hostAgentReleaseAssetName(value.AgentVersion, "arm64")
			value.Release.Arch = "arm64"
		},
		"archive_size": func(value *HostSelfUpdateRequest) {
			value.Release.ArchiveSize++
		},
		"archive_sha256": func(value *HostSelfUpdateRequest) {
			value.ArtifactSHA256 = "sha256:" + strings.Repeat("7", 64)
			value.Release.ArchiveSHA256 =
				strings.TrimPrefix(value.ArtifactSHA256, "sha256:")
		},
		"archive_checksum_asset_id": func(value *HostSelfUpdateRequest) {
			value.Release.ArchiveChecksumAssetID += 10
		},
		"archive_checksum_sha256": func(value *HostSelfUpdateRequest) {
			value.Release.ArchiveChecksumSHA256 = strings.Repeat("8", 64)
		},
		"minimum_panel_version": func(value *HostSelfUpdateRequest) {
			value.Release.MinimumPanelVersion = "v1.8.1"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			drifted := request
			mutate(&drifted)
			if hostSelfUpdateReleaseMatchesRequest(release, drifted) {
				t.Fatal("server/root metadata drift was ignored")
			}
		})
	}
}
