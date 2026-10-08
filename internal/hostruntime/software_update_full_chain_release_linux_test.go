//go:build linux

package hostruntime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const softwareUpdateChainRepo = "/repos/Kome-Lab/Autostream-ControlPanel"

type softwareUpdateChainProvider struct {
	Commit string   `json:"commit"`
	Names  []string `json:"names"`
}

// Real downloaders use their fixed api.github.com origin, immutable-release
// check, tag commit, manifest, sidecars, archive digest and inner checksums.
// The only provider substitution is TLS/DNS inside a network-none container.
func TestSoftwareUpdateFullChainReleaseProcess(t *testing.T) {
	if os.Getenv("AUTOSTREAM_ST_PORT_CHAIN_CHILD") != "release" || os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_FULL_CHAIN") != "1" || os.Geteuid() != 0 {
		t.Skip("isolated immutable release provider is not selected")
	}
	dir := filepath.Join(stPortChainRoot, "release-private")
	body, err := os.ReadFile(filepath.Join(dir, "provider.json"))
	var fixture softwareUpdateChainProvider
	if err != nil || len(body) > 4096 || json.Unmarshal(body, &fixture) != nil || len(fixture.Names) != 7 || (fixture.Commit != "0315845e3af01eff6b97c6164db3ddc3109b55af" && fixture.Commit != "9c75188147daf8435d005651a8266ae31ce39653") {
		t.Fatal("bounded immutable release input unavailable")
	}
	assets := make(map[int64][]byte, 7)
	release := githubRelease{TagName: "v2.0.1", Immutable: true}
	var agentDownloads, rootDownloads, unknownDownloads atomic.Int64
	for i, name := range fixture.Names {
		if filepath.Base(name) != name || strings.ContainsAny(name, "\r\n") {
			t.Fatal("fixture asset name is invalid")
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(data) == 0 || len(data) > 256<<20 {
			t.Fatal("bounded release asset unavailable")
		}
		id := int64(i + 1)
		assets[id] = data
		release.Assets = append(release.Assets, githubReleaseAsset{ID: id, Name: name, URL: "https://api.github.com" + softwareUpdateChainRepo + "/releases/assets/" + strconv.FormatInt(id, 10), Digest: "sha256:" + stPortChainDigest(data), State: "uploaded"})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+softwareUpdateChainRepo+"/releases/tags/v2.0.1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(release)
	})
	mux.HandleFunc("GET "+softwareUpdateChainRepo+"/git/ref/tags/v2.0.1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ref": "refs/tags/v2.0.1", "object": map[string]string{"type": "commit", "sha": fixture.Commit}})
	})
	mux.HandleFunc("GET "+softwareUpdateChainRepo+"/releases/assets/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		data, ok := assets[id]
		if err != nil || !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(fixture.Names[id-1], "_linux_amd64.tar.gz") {
			switch softwareUpdateChainClientUID(r.RemoteAddr) {
			case 0:
				rootDownloads.Add(1)
			case 16531:
				agentDownloads.Add(1)
			default:
				unknownDownloads.Add(1)
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(data)
	})
	cert, err := tls.LoadX509KeyPair(filepath.Join(stPortChainRoot, "tls.crt"), filepath.Join(stPortChainRoot, "tls.key"))
	if err != nil {
		t.Fatal("provider verified TLS unavailable")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal("isolated provider bind failed")
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	defer server.Close()
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	in, out := os.NewFile(3, "provider-command"), os.NewFile(4, "provider-observation")
	defer in.Close()
	defer out.Close()
	decoder, encoder := json.NewDecoder(io.LimitReader(in, 1<<20)), json.NewEncoder(out)
	for {
		var command stPortChainCommand
		if decoder.Decode(&command) != nil {
			return
		}
		if command.Command != "init" && command.Command != "metrics" {
			t.Fatal("unknown bounded provider command")
		}
		counts, _ := json.Marshal(map[string]int64{"agent_downloads": agentDownloads.Load(), "root_downloads": rootDownloads.Load(), "unknown_downloads": unknownDownloads.Load()})
		if encoder.Encode(stPortChainResponse{OK: true, SoftwareWire: counts}) != nil {
			return
		}
	}
}

// Observe the established loopback client socket's kernel UID. This does not
// trust a caller-supplied header and never exports a PID, address or token.
func softwareUpdateChainClientUID(remote string) int64 {
	host, rawPort, err := net.SplitHostPort(remote)
	if err != nil || host != "127.0.0.1" {
		return -1
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return -1
	}
	body, err := os.ReadFile("/proc/net/tcp")
	if err != nil || len(body) > 256<<10 {
		return -1
	}
	local := fmt.Sprintf("0100007F:%04X", port)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 8 && fields[1] == local && fields[2] == "0100007F:01BB" {
			uid, err := strconv.ParseInt(fields[7], 10, 64)
			if err == nil {
				return uid
			}
		}
	}
	return -1
}

func softwareUpdateChainPrepareRelease(t *testing.T, h *stPortChainHarness, commit string) string {
	t.Helper()
	dir := filepath.Join(stPortChainRoot, "release-private")
	if os.Mkdir(dir, 0o700) != nil {
		t.Fatal("exclusive provider setup refused existing data")
	}
	newArchive := softwareUpdateChainArchive(t, h.testBinary, "v2.0.1", commit)
	armArchive := []byte("software-update isolated arm64 metadata fixture; execution is amd64 only\n")
	amdName := "autostream-control-panel_v2.0.1_linux_amd64.tar.gz"
	armName := "autostream-control-panel_v2.0.1_linux_arm64.tar.gz"
	manifest := HostReleaseManifest{SchemaVersion: 1, ReleaseID: "v2.0.1", Channel: "host", PublishedAt: "2026-10-08T00:00:00Z", MinimumAgentVersion: "v1.7.0",
		Components: []HostReleaseComponent{{Service: "control-panel", SourceVersion: "v2.0.1", Commit: commit, RollbackCompatible: true, DatabaseSchema: "backward_compatible", Artifacts: []HostReleaseArtifact{
			{OS: "linux", Arch: "amd64", Name: amdName, Size: int64(len(newArchive)), SHA256: stPortChainDigest(newArchive)},
			{OS: "linux", Arch: "arm64", Name: armName, Size: int64(len(armArchive)), SHA256: stPortChainDigest(armArchive)},
		}}}}
	manifestBytes, _ := json.Marshal(manifest)
	assetBytes := map[string][]byte{amdName: newArchive, armName: armArchive, "release-manifest.json": append(manifestBytes, '\n')}
	for _, name := range []string{amdName, armName, "release-manifest.json"} {
		assetBytes[name+".sha256"] = []byte(stPortChainDigest(assetBytes[name]) + "  " + name + "\n")
	}
	names := make([]string, 0, 7)
	for name := range assetBytes {
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		fmt.Fprintf(&sums, "%s  %s\n", stPortChainDigest(assetBytes[name]), name)
	}
	assetBytes["SHA256SUMS"] = []byte(sums.String())
	names = append(names, "SHA256SUMS")
	sort.Strings(names)
	for name, data := range assetBytes {
		if os.WriteFile(filepath.Join(dir, name), data, 0o600) != nil {
			t.Fatal("persist immutable provider asset")
		}
	}
	index, _ := json.Marshal(softwareUpdateChainProvider{Commit: commit, Names: names})
	if os.WriteFile(filepath.Join(dir, "provider.json"), index, 0o600) != nil {
		t.Fatal("persist provider identity")
	}
	// The baseline is another fully checksummed synthetic application release.
	oldArchive := softwareUpdateChainArchive(t, h.testBinary, "v2.0.0", commit)
	oldArchivePath := filepath.Join(dir, "baseline.tar.gz")
	if os.WriteFile(oldArchivePath, oldArchive, 0o600) != nil {
		t.Fatal("persist isolated baseline")
	}
	oldRoot, err := ExtractTarGz(oldArchivePath, "/opt/autostream/control-panel/releases", 256<<20, 64)
	if err != nil || VerifyInnerChecksums(oldRoot) != nil {
		t.Fatal("baseline extraction/checksum failed")
	}
	for name, data := range map[string][]byte{".version": []byte("v2.0.0\n"), ".artifact-sha256": []byte(stPortChainDigest(oldArchive) + "\n")} {
		if os.WriteFile(filepath.Join(oldRoot, name), data, 0o444) != nil {
			t.Fatal("install baseline markers")
		}
	}
	if os.Symlink(oldRoot, "/opt/autostream/control-panel/current") != nil {
		t.Fatal("exclusive current link creation failed")
	}
	return "sha256:" + stPortChainDigest(newArchive)
}

func softwareUpdateChainArchive(t *testing.T, binary, version, commit string) []byte {
	t.Helper()
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("read synthetic application binary")
	}
	identity, _ := json.Marshal(map[string]string{"version": version, "service": "control-panel", "source_commit": commit, "fixture": "synthetic_application_not_cp_binary"})
	files := map[string][]byte{"bin/control-panel": binaryBytes, "artifact-manifest.json": append(identity, '\n'), "share/autostream-control-panel/index.html": []byte("isolated software-update fixture\n")}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var inner strings.Builder
	for _, name := range names {
		fmt.Fprintf(&inner, "%s  %s\n", stPortChainDigest(files[name]), name)
	}
	files["checksums.txt"] = []byte(inner.String())
	names = append(names, "checksums.txt")
	sort.Strings(names)
	var buffer bytes.Buffer
	gzipWriter, _ := gzip.NewWriterLevel(&buffer, gzip.BestSpeed)
	writer := tar.NewWriter(gzipWriter)
	prefix := "autostream-control-panel_" + version + "_linux_amd64/"
	for _, name := range names {
		mode := int64(0o644)
		if name == "bin/control-panel" {
			mode = 0o755
		}
		data := files[name]
		if writer.WriteHeader(&tar.Header{Name: prefix + name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}) != nil {
			t.Fatal("archive header")
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal("archive bytes")
		}
	}
	if writer.Close() != nil || gzipWriter.Close() != nil {
		t.Fatal("archive close")
	}
	return buffer.Bytes()
}
