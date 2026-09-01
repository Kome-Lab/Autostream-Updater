package hostruntime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

func TestCanonicalVersionPattern(t *testing.T) {
	for _, version := range []string{"v0.0.0", "v1.2.3", "v1.2.3-rc.1", "v1.2.3-alpha-2"} {
		if !versionPattern.MatchString(version) {
			t.Fatalf("canonical version %q was rejected", version)
		}
	}
	for _, version := range []string{"1.2.3", "v1.2.3+build.1", "v1.2.3.rc1", "v1.2.3-", "v1.2.3-rc..1", " v1.2.3"} {
		if versionPattern.MatchString(version) {
			t.Fatalf("noncanonical version %q was accepted", version)
		}
	}
}

type tarEntry struct {
	name     string
	typeflag byte
	body     []byte
	mode     int64
}

func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0o755
		}
		h := &tar.Header{Name: entry.name, Typeflag: typeflag, Mode: mode, Size: int64(len(entry.body))}
		if typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write(entry.body)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return out.Bytes()
}

func TestExtractTarGzRejectsTraversalAndLinks(t *testing.T) {
	for name, entries := range map[string][]tarEntry{
		"traversal":         {{name: "root/../../escape", body: []byte("x")}},
		"symlink":           {{name: "root/link", typeflag: tar.TypeSymlink}},
		"device":            {{name: "root/device", typeflag: tar.TypeChar}},
		"setuid executable": {{name: "root/worker", body: []byte("x"), mode: 0o4755}},
		"setgid executable": {{name: "root/worker", body: []byte("x"), mode: 0o2755}},
		"sticky directory":  {{name: "root", typeflag: tar.TypeDir, mode: 0o1755}},
	} {
		t.Run(name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "bad.tar.gz")
			if err := os.WriteFile(archive, makeTarGz(t, entries), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ExtractTarGz(archive, filepath.Join(t.TempDir(), "out"), 1<<20, 10); err == nil {
				t.Fatal("expected unsafe archive rejection")
			}
		})
	}
}

func TestVerifyInnerChecksumsAndUnlistedFile(t *testing.T) {
	root := t.TempDir()
	data := []byte("binary")
	if err := os.WriteFile(filepath.Join(root, "worker"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	manifest := fmt.Sprintf("%x  ./worker\n", sum)
	if err := os.WriteFile(filepath.Join(root, "checksums.txt"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInnerChecksums(root); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "unlisted"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyInnerChecksums(root); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("expected unlisted file rejection, got %v", err)
	}
}

func TestReleaseDownloaderVerifiesOuterAndInnerSHA256(t *testing.T) {
	binary := []byte("worker-v1.2.3")
	inner := sha256.Sum256(binary)
	manifest := []byte(fmt.Sprintf("%x  ./bin/worker\n", inner))
	archive := makeTarGz(t, []tarEntry{{name: "autostream-worker_v1.2.3_linux_amd64/bin/worker", body: binary}, {name: "autostream-worker_v1.2.3_linux_amd64/checksums.txt", body: manifest}})
	outer := sha256.Sum256(archive)
	hostManifest, err := json.Marshal(HostReleaseManifest{SchemaVersion: 1, ReleaseID: "v1.2.3", Channel: "host", PublishedAt: "2026-07-18T00:00:00Z", MinimumAgentVersion: "v1.0.0", Components: []HostReleaseComponent{{Service: "worker", SourceVersion: "v1.2.3", Commit: strings.Repeat("a", 40), RollbackCompatible: true, DatabaseSchema: "none", Artifacts: []HostReleaseArtifact{{OS: "linux", Arch: "amd64", Name: "autostream-worker_v1.2.3_linux_amd64.tar.gz", Size: int64(len(archive)), SHA256: hex.EncodeToString(outer[:])}, {OS: "linux", Arch: "arm64", Name: "autostream-worker_v1.2.3_linux_arm64.tar.gz", Size: 1, SHA256: strings.Repeat("b", 64)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	hostManifestSum := sha256.Sum256(hostManifest)
	oldVersion := controlversion.Version
	controlversion.Version = "v1.0.0"
	defer func() { controlversion.Version = oldVersion }()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/Kome-Lab/Autostream-Worker/releases/tags/v1.2.3":
			fmt.Fprintf(w, `{"assets":[{"name":"autostream-worker_v1.2.3_linux_amd64.tar.gz","url":%q},{"name":"autostream-worker_v1.2.3_linux_amd64.tar.gz.sha256","url":%q},{"name":"release-manifest.json","url":%q},{"name":"release-manifest.json.sha256","url":%q}]}`, server.URL+"/archive", server.URL+"/checksum", server.URL+"/manifest", server.URL+"/manifest-checksum")
		case "/archive":
			_, _ = w.Write(archive)
		case "/checksum":
			fmt.Fprintf(w, "%x  autostream-worker_v1.2.3_linux_amd64.tar.gz\n", outer)
		case "/manifest":
			_, _ = w.Write(hostManifest)
		case "/manifest-checksum":
			fmt.Fprintf(w, "%x  release-manifest.json\n", hostManifestSum)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	d := ReleaseDownloader{APIBase: server.URL, Client: server.Client(), AllowHTTPForTest: true}
	got, err := d.Download(context.Background(), "worker", "v1.2.3", "amd64", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA256 != hex.EncodeToString(outer[:]) {
		t.Fatalf("digest = %s", got.SHA256)
	}
}

func TestReadSHA256FileRequiresCanonicalSingleLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset.sha256")
	valid := strings.Repeat("a", 64) + "  asset.tar.gz\n"
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSHA256File(path, "asset.tar.gz"); err != nil || got != strings.Repeat("a", 64) {
		t.Fatalf("canonical sidecar rejected: %q %v", got, err)
	}
	for name, value := range map[string]string{
		"extra line": valid + valid,
		"upper":      strings.Repeat("A", 64) + "  asset.tar.gz\n",
		"path":       strings.Repeat("a", 64) + "  artifacts/asset.tar.gz\n",
		"field":      strings.Repeat("a", 64) + "  asset.tar.gz extra\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSHA256File(path, "asset.tar.gz"); err == nil {
				t.Fatal("expected noncanonical sidecar rejection")
			}
		})
	}
}

func TestHostManifestRejectsMinimumAgentAndRollbackPolicy(t *testing.T) {
	oldVersion := controlversion.Version
	controlversion.Version = "v1.2.0"
	defer func() { controlversion.Version = oldVersion }()
	base := HostReleaseManifest{SchemaVersion: 1, ReleaseID: "v1.2.3", Channel: "host", PublishedAt: "2026-07-18T00:00:00Z", MinimumAgentVersion: "v1.0.0", Components: []HostReleaseComponent{{Service: "worker", SourceVersion: "v1.2.3", Commit: strings.Repeat("a", 40), RollbackCompatible: true, DatabaseSchema: "none", Artifacts: []HostReleaseArtifact{{OS: "linux", Arch: "amd64", Name: "autostream-worker_v1.2.3_linux_amd64.tar.gz", Size: 10, SHA256: strings.Repeat("b", 64)}, {OS: "linux", Arch: "arm64", Name: "autostream-worker_v1.2.3_linux_arm64.tar.gz", Size: 10, SHA256: strings.Repeat("c", 64)}}}}}
	for name, mutate := range map[string]func(*HostReleaseManifest){
		"missing minimum": func(manifest *HostReleaseManifest) { manifest.MinimumAgentVersion = "" },
		"new minimum":     func(manifest *HostReleaseManifest) { manifest.MinimumAgentVersion = "v9.0.0" },
		"rollback false":  func(manifest *HostReleaseManifest) { manifest.Components[0].RollbackCompatible = false },
		"schema mismatch": func(manifest *HostReleaseManifest) { manifest.Components[0].DatabaseSchema = "backward_compatible" },
	} {
		t.Run(name, func(t *testing.T) {
			manifest := base
			manifest.Components = append([]HostReleaseComponent(nil), base.Components...)
			mutate(&manifest)
			payload, _ := json.Marshal(manifest)
			path := filepath.Join(t.TempDir(), "release-manifest.json")
			if err := os.WriteFile(path, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := validateHostReleaseManifest(path, "worker", repositoryByServiceType["worker"], "v1.2.3", "amd64", "autostream-worker_v1.2.3_linux_amd64.tar.gz", ""); err == nil {
				t.Fatal("expected unsafe host manifest rejection")
			}
		})
	}
}

func TestReleaseRedirectDoesNotLeakAuthorization(t *testing.T) {
	seenAuth := "unset"
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("asset"))
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	d := ReleaseDownloader{Token: "top-secret", AllowHTTPForTest: true}
	_, err := d.downloadFile(context.Background(), source.URL, filepath.Join(t.TempDir(), "asset"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if seenAuth != "" {
		t.Fatalf("authorization leaked to redirect host: %q", seenAuth)
	}
}

func TestTrustedPublicReleaseRequiresImmutableExactStableTagAndUniqueAssets(t *testing.T) {
	base := githubRelease{TagName: "v1.2.3", Immutable: true}
	for name, mutate := range map[string]func(*githubRelease){
		"mutable":    func(release *githubRelease) { release.Immutable = false },
		"wrong tag":  func(release *githubRelease) { release.TagName = "v1.2.4" },
		"draft":      func(release *githubRelease) { release.Draft = true },
		"prerelease": func(release *githubRelease) { release.Prerelease = true },
	} {
		t.Run(name, func(t *testing.T) {
			release := base
			mutate(&release)
			if err := validateTrustedPublicReleaseMetadata(release, "v1.2.3"); err == nil {
				t.Fatal("unsafe public release metadata was accepted")
			}
		})
	}
	if err := validateTrustedPublicReleaseMetadata(base, "v1.2.3"); err != nil {
		t.Fatalf("valid immutable release rejected: %v", err)
	}

	var duplicate githubRelease
	if err := json.Unmarshal([]byte(`{"assets":[{"name":"asset","url":"https://api.github.com/a"},{"name":"asset","url":"https://api.github.com/b"}]}`), &duplicate); err != nil {
		t.Fatal(err)
	}
	if _, err := uniqueReleaseAssetURLs(duplicate); err == nil {
		t.Fatal("duplicate GitHub release asset was accepted")
	}
}

func TestTrustedPublicReleaseRejectsCustomAPIAndRedirectHosts(t *testing.T) {
	downloader := ReleaseDownloader{TrustedPublicOnly: true}
	if err := downloader.validateTrustedPublicRepository(
		"https://api.github.com",
		repositoryByServiceType["worker"],
	); err != nil {
		t.Fatalf("trusted production repository rejected: %v", err)
	}
	for name, base := range map[string]string{
		"custom host": "https://github.example.com",
		"http":        "http://api.github.com",
		"path":        "https://api.github.com/custom",
	} {
		t.Run(name, func(t *testing.T) {
			if err := downloader.validateTrustedPublicRepository(base, repositoryByServiceType["worker"]); err == nil {
				t.Fatal("custom public API origin was accepted")
			}
		})
	}
	if trustedGitHubReleaseRedirectHost("attacker.example") {
		t.Fatal("untrusted redirect host was accepted")
	}
	for _, host := range []string{"api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"} {
		if !trustedGitHubReleaseRedirectHost(host) {
			t.Fatalf("trusted GitHub redirect host %q was rejected", host)
		}
	}
}

func TestHostManifestCommitMustMatchImmutableReleaseTag(t *testing.T) {
	oldVersion := controlversion.Version
	controlversion.Version = "v1.2.0"
	defer func() { controlversion.Version = oldVersion }()
	manifest := HostReleaseManifest{
		SchemaVersion: 1, ReleaseID: "v1.2.3", Channel: "host",
		PublishedAt: "2026-07-18T00:00:00Z", MinimumAgentVersion: "v1.0.0",
		Components: []HostReleaseComponent{{
			Service: "worker", SourceVersion: "v1.2.3", Commit: strings.Repeat("a", 40),
			RollbackCompatible: true, DatabaseSchema: "none",
			Artifacts: []HostReleaseArtifact{
				{OS: "linux", Arch: "amd64", Name: "autostream-worker_v1.2.3_linux_amd64.tar.gz", Size: 10, SHA256: strings.Repeat("b", 64)},
				{OS: "linux", Arch: "arm64", Name: "autostream-worker_v1.2.3_linux_arm64.tar.gz", Size: 10, SHA256: strings.Repeat("c", 64)},
			},
		}},
	}
	path := filepath.Join(t.TempDir(), "release-manifest.json")
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateHostReleaseManifest(
		path, "worker", repositoryByServiceType["worker"], "v1.2.3", "amd64",
		"autostream-worker_v1.2.3_linux_amd64.tar.gz", strings.Repeat("d", 40),
	); err == nil || !strings.Contains(err.Error(), "immutable release tag") {
		t.Fatalf("commit mismatch error=%v", err)
	}
}

func TestTrustedPublicTagResolutionHandlesLightweightAnnotatedAndUnsafeChains(t *testing.T) {
	spec := repositoryByServiceType["worker"]
	commit := strings.Repeat("a", 40)
	tagOne := strings.Repeat("b", 40)
	tagTwo := strings.Repeat("c", 40)

	t.Run("lightweight", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/git/ref/tags/") {
				fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, commit)
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()
		got, err := (ReleaseDownloader{Client: server.Client(), AllowHTTPForTest: true}).resolveTrustedReleaseTagCommit(context.Background(), server.URL, spec, "v1.2.3")
		if err != nil || got != commit {
			t.Fatalf("commit=%q err=%v", got, err)
		}
	})

	t.Run("annotated chain", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/git/ref/tags/"):
				fmt.Fprintf(w, `{"object":{"type":"tag","sha":%q}}`, tagOne)
			case strings.HasSuffix(r.URL.Path, "/git/tags/"+tagOne):
				fmt.Fprintf(w, `{"object":{"type":"tag","sha":%q}}`, tagTwo)
			case strings.HasSuffix(r.URL.Path, "/git/tags/"+tagTwo):
				fmt.Fprintf(w, `{"object":{"type":"commit","sha":%q}}`, commit)
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()
		got, err := (ReleaseDownloader{Client: server.Client(), AllowHTTPForTest: true}).resolveTrustedReleaseTagCommit(context.Background(), server.URL, spec, "v1.2.3")
		if err != nil || got != commit {
			t.Fatalf("commit=%q err=%v", got, err)
		}
	})

	for name, test := range map[string]struct {
		first gitObject
		next  gitObject
	}{
		"invalid commit": {
			first: gitObject{Type: "commit", SHA: "not-a-commit"},
		},
		"cycle": {
			first: gitObject{Type: "tag", SHA: tagOne},
			next:  gitObject{Type: "tag", SHA: tagOne},
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				object := test.first
				if strings.Contains(r.URL.Path, "/git/tags/") {
					object = test.next
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"object": object})
			}))
			defer server.Close()
			if _, err := (ReleaseDownloader{Client: server.Client(), AllowHTTPForTest: true}).resolveTrustedReleaseTagCommit(context.Background(), server.URL, spec, "v1.2.3"); err == nil {
				t.Fatal("unsafe tag chain was accepted")
			}
		})
	}

	t.Run("depth", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, `{"object":{"type":"tag","sha":%q}}`, tagOne)
		}))
		defer server.Close()
		if _, err := (ReleaseDownloader{Client: server.Client(), AllowHTTPForTest: true}).resolveTrustedReleaseTagCommit(context.Background(), server.URL, spec, "v1.2.3"); err == nil {
			t.Fatal("unbounded annotated tag chain was accepted")
		}
	})
}

func TestTrustedPublicAssetURLRequiresCanonicalRepositoryAndID(t *testing.T) {
	downloader := ReleaseDownloader{TrustedPublicOnly: true}
	spec := repositoryByServiceType["worker"]
	valid := "https://api.github.com/repos/Kome-Lab/Autostream-Worker/releases/assets/42"
	if err := downloader.validateTrustedPublicAssetURL(valid, "https://api.github.com", spec, 42); err != nil {
		t.Fatalf("canonical asset URL rejected: %v", err)
	}
	if err := downloader.validateTrustedPublicAssetURL(valid, "https://api.github.com", spec, 0); err == nil {
		t.Fatal("missing asset id was accepted")
	}
	for _, raw := range []string{
		"https://api.github.com/repos/Kome-Lab/Autostream-Worker/releases/assets/41",
		"https://api.github.com/repos/Kome-Lab/Other/releases/assets/42",
		valid + "?download=1",
	} {
		if err := downloader.validateTrustedPublicAssetURL(raw, "https://api.github.com", spec, 42); err == nil {
			t.Fatalf("noncanonical asset URL accepted: %s", raw)
		}
	}
}

type artifactRoundTripFunc func(*http.Request) (*http.Response, error)

func (f artifactRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestTrustedPublicReleaseVerifiesEveryGitHubAssetDigest(t *testing.T) {
	const (
		version     = "v1.2.3"
		commit      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		archiveName = "autostream-worker_v1.2.3_linux_amd64.tar.gz"
		repository  = "/repos/Kome-Lab/Autostream-Worker"
	)
	binary := []byte("worker-v1.2.3")
	inner := sha256.Sum256(binary)
	innerManifest := []byte(fmt.Sprintf("%x  ./bin/worker\n", inner))
	archive := makeTarGz(t, []tarEntry{
		{name: "autostream-worker_v1.2.3_linux_amd64/bin/worker", body: binary},
		{name: "autostream-worker_v1.2.3_linux_amd64/checksums.txt", body: innerManifest},
	})
	archiveSum := sha256.Sum256(archive)
	hostManifest, err := json.Marshal(HostReleaseManifest{
		SchemaVersion: 1, ReleaseID: version, Channel: "host",
		PublishedAt: "2026-07-18T00:00:00Z", MinimumAgentVersion: "v1.0.0",
		Components: []HostReleaseComponent{{
			Service: "worker", SourceVersion: version, Commit: commit,
			RollbackCompatible: true, DatabaseSchema: "none",
			Artifacts: []HostReleaseArtifact{
				{OS: "linux", Arch: "amd64", Name: archiveName, Size: int64(len(archive)), SHA256: hex.EncodeToString(archiveSum[:])},
				{OS: "linux", Arch: "arm64", Name: "autostream-worker_v1.2.3_linux_arm64.tar.gz", Size: 1, SHA256: strings.Repeat("b", 64)},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hostManifestSum := sha256.Sum256(hostManifest)
	contents := map[string][]byte{
		archiveName:                    archive,
		archiveName + ".sha256":        []byte(fmt.Sprintf("%x  %s\n", archiveSum, archiveName)),
		"release-manifest.json":        hostManifest,
		"release-manifest.json.sha256": []byte(fmt.Sprintf("%x  release-manifest.json\n", hostManifestSum)),
	}
	assetIDs := map[string]int64{
		archiveName:                    101,
		archiveName + ".sha256":        102,
		"release-manifest.json":        103,
		"release-manifest.json.sha256": 104,
	}
	downloadOrder := []string{
		"release-manifest.json",
		"release-manifest.json.sha256",
		archiveName,
		archiveName + ".sha256",
	}
	oldVersion := controlversion.Version
	controlversion.Version = "v1.0.0"
	defer func() { controlversion.Version = oldVersion }()

	for _, mismatchedAsset := range append([]string{""}, downloadOrder...) {
		testName := mismatchedAsset
		if testName == "" {
			testName = "all digests match"
		}
		t.Run(testName, func(t *testing.T) {
			assets := make([]map[string]any, 0, len(assetIDs))
			contentByAssetPath := make(map[string][]byte, len(assetIDs))
			pathByName := make(map[string]string, len(assetIDs))
			for _, name := range []string{archiveName, archiveName + ".sha256", "release-manifest.json", "release-manifest.json.sha256"} {
				sum := sha256.Sum256(contents[name])
				digest := "sha256:" + hex.EncodeToString(sum[:])
				if name == mismatchedAsset {
					digest = "sha256:" + strings.Repeat("f", 64)
				}
				path := fmt.Sprintf("%s/releases/assets/%d", repository, assetIDs[name])
				pathByName[name] = path
				contentByAssetPath[path] = contents[name]
				assets = append(assets, map[string]any{
					"id": assetIDs[name], "name": name,
					"url":    "https://api.github.com" + path,
					"digest": digest, "state": "uploaded",
				})
			}
			releaseJSON, marshalErr := json.Marshal(map[string]any{
				"tag_name": version, "draft": false, "prerelease": false,
				"immutable": true, "assets": assets,
			})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var requested []string
			client := &http.Client{Transport: artifactRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				requested = append(requested, request.URL.Path)
				var body []byte
				status := http.StatusOK
				switch request.URL.Path {
				case repository + "/releases/tags/" + version:
					body = releaseJSON
				case repository + "/git/ref/tags/" + version:
					body = []byte(fmt.Sprintf(`{"object":{"type":"commit","sha":%q}}`, commit))
				default:
					var ok bool
					body, ok = contentByAssetPath[request.URL.Path]
					if !ok {
						status = http.StatusNotFound
					}
				}
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(body)),
					Request:    request,
				}, nil
			})}
			downloader := ReleaseDownloader{Client: client, TrustedPublicOnly: true}
			destDir := t.TempDir()
			_, downloadErr := downloader.Download(context.Background(), "worker", version, "amd64", destDir)
			if mismatchedAsset == "" {
				if downloadErr != nil {
					t.Fatalf("matching GitHub asset digests were rejected: %v", downloadErr)
				}
				return
			}
			if downloadErr == nil ||
				!strings.Contains(downloadErr.Error(), mismatchedAsset) ||
				!strings.Contains(downloadErr.Error(), "GitHub API digest") {
				t.Fatalf("GitHub digest mismatch for %q was not rejected: %v", mismatchedAsset, downloadErr)
			}
			if _, statErr := os.Stat(filepath.Join(destDir, mismatchedAsset)); !os.IsNotExist(statErr) {
				t.Fatalf("mismatched asset %q was not removed: %v", mismatchedAsset, statErr)
			}
			targetIndex := -1
			for index, name := range downloadOrder {
				if name == mismatchedAsset {
					targetIndex = index
					break
				}
			}
			for _, later := range downloadOrder[targetIndex+1:] {
				for _, path := range requested {
					if path == pathByName[later] {
						t.Fatalf("download continued to %q after %q digest mismatch", later, mismatchedAsset)
					}
				}
			}
		})
	}
}
