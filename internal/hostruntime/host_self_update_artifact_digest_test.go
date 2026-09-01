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
	"strings"
	"testing"
)

func TestDownloadHostAgentReleaseRejectsEveryGitHubAssetDigestMismatch(t *testing.T) {
	const repositoryPath = "/repos/Kome-Lab/Autostream-Updater"

	version := hostSelfUpdateArtifactTestVersion
	assetName := hostAgentReleaseAssetName(version, "amd64")
	root := strings.TrimSuffix(assetName, ".tar.gz")
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
	manifest, err := json.Marshal(hostAgentReleaseManifest{
		SchemaVersion:                           1,
		ReleaseID:                               version,
		Channel:                                 "host-agent",
		PublishedAt:                             "2026-07-28T00:00:00Z",
		Commit:                                  hostSelfUpdateArtifactTestCommit,
		AgentVersion:                            version,
		ProtocolVersion:                         2,
		LocalExecutorProtocolVersion:            2,
		LocalExecutorProtocolMinVersion:         1,
		LocalExecutorProtocolMaxVersion:         2,
		LocalExecutorProbeCompatible:            true,
		LocalExecutorMutationProtocolVersion:    2,
		LocalExecutorMutationEnabled:            true,
		LocalExecutorMutationRequiresRootPolicy: true,
		RecoveryProtocolVersion:                 HostSelfUpdateRecoveryProtocolVersion,
		MinimumPanelVersion:                     version,
		Artifacts: []HostReleaseArtifact{
			{
				OS: "linux", Arch: "amd64", Name: assetName,
				Size: int64(len(archive)), SHA256: hex.EncodeToString(archiveSum[:]),
			},
			{
				OS: "linux", Arch: "arm64",
				Name: hostAgentReleaseAssetName(version, "arm64"),
				Size: 1, SHA256: strings.Repeat("b", 64),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifest)
	payloads := map[string][]byte{
		hostAgentManifestName:             manifest,
		hostAgentManifestName + ".sha256": []byte(fmt.Sprintf("%x  %s\n", manifestSum, hostAgentManifestName)),
		assetName:                         archive,
		assetName + ".sha256":             []byte(fmt.Sprintf("%x  %s\n", archiveSum, assetName)),
	}
	downloadOrder := []string{
		hostAgentManifestName,
		hostAgentManifestName + ".sha256",
		assetName,
		assetName + ".sha256",
	}

	for _, mismatchedAsset := range downloadOrder {
		t.Run(mismatchedAsset, func(t *testing.T) {
			var requested []string
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requested = append(requested, r.URL.Path)
				switch r.URL.Path {
				case repositoryPath + "/releases/tags/" + version:
					assets := make([]immutableReleaseAsset, 0, len(downloadOrder))
					for index, name := range downloadOrder {
						sum := sha256.Sum256(payloads[name])
						digest := "sha256:" + hex.EncodeToString(sum[:])
						if name == mismatchedAsset {
							digest = "sha256:" + strings.Repeat("f", 64)
						}
						assets = append(assets, immutableReleaseAsset{
							ID:     int64(index + 1),
							Name:   name,
							URL:    server.URL + repositoryPath + "/releases/assets/" + fmt.Sprint(index+1),
							Digest: digest,
							State:  "uploaded",
						})
					}
					_ = json.NewEncoder(w).Encode(updaterReleaseGitHubRelease{
						TagName: version, Immutable: true, Assets: assets,
					})
				case repositoryPath + "/git/ref/tags/" + version:
					fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, hostSelfUpdateArtifactTestCommit)
				default:
					const assetPathPrefix = repositoryPath + "/releases/assets/"
					if strings.HasPrefix(r.URL.Path, assetPathPrefix) {
						var index int
						if _, scanErr := fmt.Sscanf(
							strings.TrimPrefix(r.URL.Path, assetPathPrefix),
							"%d",
							&index,
						); scanErr == nil && index >= 1 && index <= len(downloadOrder) {
							_, _ = w.Write(payloads[downloadOrder[index-1]])
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
					context.Context,
					ReleaseDownloader,
					string,
					string,
					string,
				) error {
					return nil
				}),
			}
			destDir := t.TempDir()
			_, downloadErr := downloader.DownloadHostAgentRelease(
				context.Background(), version, "amd64", destDir,
			)
			if downloadErr == nil ||
				!strings.Contains(downloadErr.Error(), mismatchedAsset) ||
				!strings.Contains(downloadErr.Error(), "GitHub API digest") {
				t.Fatalf(
					"GitHub digest mismatch for %q was not rejected: %v",
					mismatchedAsset,
					downloadErr,
				)
			}
			if _, statErr := os.Stat(filepath.Join(destDir, mismatchedAsset)); !os.IsNotExist(statErr) {
				t.Fatalf("mismatched asset %q was not removed: %v", mismatchedAsset, statErr)
			}

			mismatchIndex := 0
			for index, name := range downloadOrder {
				if name == mismatchedAsset {
					mismatchIndex = index
					break
				}
			}
			for _, later := range downloadOrder[mismatchIndex+1:] {
				laterPath := repositoryPath + "/releases/assets/" +
					fmt.Sprint(indexOfHostSelfUpdateAsset(downloadOrder, later)+1)
				for _, path := range requested {
					if path == laterPath {
						t.Fatalf(
							"download continued to %q after %q digest mismatch",
							later,
							mismatchedAsset,
						)
					}
				}
			}
		})
	}
}

func indexOfHostSelfUpdateAsset(names []string, target string) int {
	for index, name := range names {
		if name == target {
			return index
		}
	}
	return -1
}
