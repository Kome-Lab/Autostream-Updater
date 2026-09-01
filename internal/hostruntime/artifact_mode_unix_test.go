//go:build !windows

package hostruntime

import (
	"archive/tar"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestExtractTarGzRestoresSafeModesUnderRestrictiveUmask(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "release.tar.gz")
	entries := []tarEntry{
		{name: "release", typeflag: tar.TypeDir, mode: 0o755},
		{name: "release/bin", typeflag: tar.TypeDir, mode: 0o755},
		{name: "release/bin/worker", body: []byte("verified executable"), mode: 0o700},
		{name: "release/bin/tool", body: []byte("second executable"), mode: 0o744},
		{name: "release/config.json", body: []byte("{}"), mode: 0o644},
	}
	if err := os.WriteFile(archive, makeTarGz(t, entries), 0o600); err != nil {
		t.Fatal(err)
	}

	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)
	dest := filepath.Join(t.TempDir(), "extracted")
	root, err := ExtractTarGz(archive, dest, 1<<20, 16)
	if err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]os.FileMode{
		dest:                                 0o700,
		root:                                 0o755,
		filepath.Join(root, "bin"):           0o755,
		filepath.Join(root, "bin", "worker"): 0o755,
		filepath.Join(root, "bin", "tool"):   0o755,
		filepath.Join(root, "config.json"):   0o644,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("mode %s = %04o, want %04o", path, got, want)
		}
	}
}

func TestInstallReleaseTreeRestoresSafeModesUnderRestrictiveUmask(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	for _, dir := range []string{source, filepath.Join(source, "bin"), filepath.Join(source, "meta")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, fixture := range map[string]struct {
		mode os.FileMode
		body string
	}{
		filepath.Join(source, "bin", "worker"):            {mode: 0o700, body: "worker"},
		filepath.Join(source, "bin", "tool"):              {mode: 0o744, body: "tool"},
		filepath.Join(source, "config.json"):              {mode: 0o600, body: "{}"},
		filepath.Join(source, "meta", ".version"):         {mode: 0o700, body: "artifact data"},
		filepath.Join(source, "meta", ".artifact-sha256"): {mode: 0o600, body: "artifact data"},
	} {
		if err := os.WriteFile(path, []byte(fixture.body), fixture.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, fixture.mode); err != nil {
			t.Fatal(err)
		}
	}
	var checksums strings.Builder
	for _, rel := range []string{"bin/worker", "bin/tool", "config.json", "meta/.version", "meta/.artifact-sha256"} {
		body, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		fmt.Fprintf(&checksums, "%x  %s\n", sum, rel)
	}
	checksumsPath := filepath.Join(source, "checksums.txt")
	if err := os.WriteFile(checksumsPath, []byte(checksums.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(checksumsPath, 0o600); err != nil {
		t.Fatal(err)
	}

	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)
	dest := filepath.Join(t.TempDir(), "releases", "v1.2.3-aaaaaaaaaaaa")
	if err := installReleaseTree(source, dest, strings.Repeat("a", 64), "v1.2.3"); err != nil {
		t.Fatal(err)
	}

	wantModes := map[string]os.FileMode{
		dest:                                            0o755,
		filepath.Join(dest, "bin"):                      0o755,
		filepath.Join(dest, "bin", "worker"):            0o755,
		filepath.Join(dest, "bin", "tool"):              0o755,
		filepath.Join(dest, "meta"):                     0o755,
		filepath.Join(dest, "meta", ".version"):         0o755,
		filepath.Join(dest, "meta", ".artifact-sha256"): 0o644,
		filepath.Join(dest, "config.json"):              0o644,
		filepath.Join(dest, "checksums.txt"):            0o644,
		filepath.Join(dest, ".artifact-sha256"):         0o444,
		filepath.Join(dest, ".version"):                 0o444,
	}
	assertModes := func() {
		t.Helper()
		for path, want := range wantModes {
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", path, err)
			}
			if got := info.Mode().Perm(); got != want {
				t.Fatalf("mode %s = %04o, want %04o", path, got, want)
			}
		}
	}
	assertModes()

	// Reproduce the tree left by the old UMask-dependent installer. A retry of
	// the same checksum-bound release must repair it without operator deletion.
	for path, mode := range map[string]os.FileMode{
		dest:                                            0o700,
		filepath.Join(dest, "bin"):                      0o700,
		filepath.Join(dest, "bin", "worker"):            0o700,
		filepath.Join(dest, "bin", "tool"):              0o700,
		filepath.Join(dest, "meta"):                     0o700,
		filepath.Join(dest, "meta", ".version"):         0o700,
		filepath.Join(dest, "meta", ".artifact-sha256"): 0o600,
		filepath.Join(dest, "config.json"):              0o600,
		filepath.Join(dest, "checksums.txt"):            0o600,
		filepath.Join(dest, ".artifact-sha256"):         0o400,
		filepath.Join(dest, ".version"):                 0o400,
	} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := installReleaseTree(source, dest, strings.Repeat("a", 64), "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	assertModes()
}

func TestInstallReleaseTreeRemovesValidatedStalePartial(t *testing.T) {
	if RequireLocalExecutorRoot() != nil {
		t.Skip("root-owned release partial policy")
	}
	source := writeMinimalChecksummedRelease(t)
	digest := strings.Repeat("b", 64)
	version := "v2.0.0"
	dest := filepath.Join(t.TempDir(), "releases", "v2.0.0-bbbbbbbbbbbb")
	partial := dest + ".partial-" + shortID(digest+version)
	if err := os.MkdirAll(filepath.Join(partial, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(partial, "nested", "stale"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := installReleaseTree(source, dest, digest, version); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("validated stale partial survived: %v", err)
	}
	if err := verifyManagedReleaseChecksums(dest); err != nil {
		t.Fatalf("replacement release is invalid: %v", err)
	}
}

func TestInstallReleaseTreeRejectsUnsafeStalePartial(t *testing.T) {
	source := writeMinimalChecksummedRelease(t)
	digest := strings.Repeat("c", 64)
	version := "v2.0.1"
	root := t.TempDir()
	dest := filepath.Join(root, "releases", "v2.0.1-cccccccccccc")
	partial := dest + ".partial-" + shortID(digest+version)
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(filepath.Dir(partial), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "sentinel"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, partial); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}

	if err := installReleaseTree(source, dest, digest, version); err == nil {
		t.Fatal("unsafe stale partial was accepted")
	}
	if info, err := os.Lstat(partial); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("unsafe partial was followed or removed: %v", err)
	}
	if body, err := os.ReadFile(filepath.Join(outside, "sentinel")); err != nil || string(body) != "keep" {
		t.Fatalf("outside sentinel changed: body=%q err=%v", body, err)
	}
}

func TestInstallReleaseTreeDoesNotPublishInvalidCopiedTree(t *testing.T) {
	source := writeMinimalChecksummedRelease(t)
	if err := os.WriteFile(filepath.Join(source, "unlisted"), []byte("must fail"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("d", 64)
	version := "v2.0.2"
	dest := filepath.Join(t.TempDir(), "releases", "v2.0.2-dddddddddddd")
	partial := dest + ".partial-" + shortID(digest+version)

	if err := installReleaseTree(source, dest, digest, version); err == nil {
		t.Fatal("invalid copied release was published")
	}
	for _, path := range []string{dest, partial} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed install stranded %s: %v", path, err)
		}
	}
}

func writeMinimalChecksummedRelease(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	worker := []byte("worker")
	workerPath := filepath.Join(root, "bin", "worker")
	if err := os.WriteFile(workerPath, worker, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(workerPath, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(worker)
	manifest := fmt.Sprintf("%x  bin/worker\n", sum)
	if err := os.WriteFile(filepath.Join(root, "checksums.txt"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}
