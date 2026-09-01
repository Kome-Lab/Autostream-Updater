package hostruntime

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDockerPortStartupCleanupWipesOrphanedFrozenComposeInode(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(base, dockerPortRecreatePrefix+"crashed")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := []byte(`{"services":{"worker":{"environment":{"TOKEN":"must-not-survive"}}}}`)
	frozen := filepath.Join(orphan, "compose-frozen.json")
	if err := os.WriteFile(frozen, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	capturedInode := filepath.Join(base, "captured-inode")
	if err := os.Link(frozen, capturedInode); err != nil {
		t.Fatal(err)
	}

	if err := cleanupDockerPortTransientOrphans(base, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned transient directory survived cleanup: %v", err)
	}
	wiped, err := os.ReadFile(capturedInode)
	if err != nil {
		t.Fatal(err)
	}
	if len(wiped) != len(secret) ||
		bytes.Contains(wiped, []byte("must-not-survive")) ||
		!bytes.Equal(wiped, make([]byte, len(secret))) {
		t.Fatalf("captured frozen Compose inode was not fully wiped: %q", wiped)
	}
}

func TestDockerPortTransientCleanupRejectsReparseEntries(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	link := filepath.Join(base, dockerPortRecreatePrefix+"link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := cleanupDockerPortTransientOrphans(base, false); err == nil {
		t.Fatal("reparse-backed Docker port transient directory was accepted")
	}
}
