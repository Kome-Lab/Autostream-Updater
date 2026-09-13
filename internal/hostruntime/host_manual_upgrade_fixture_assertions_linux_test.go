//go:build linux

package hostruntime

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type manualHostUpgradeLinuxProtectedSnapshot struct {
	info    os.FileInfo
	payload []byte
	mode    fs.FileMode
	uid     uint32
	gid     uint32
}

func snapshotManualHostUpgradeLinuxProtectedFile(
	t *testing.T,
	path string,
) manualHostUpgradeLinuxProtectedSnapshot {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("protected file has no Linux stat identity")
	}
	return manualHostUpgradeLinuxProtectedSnapshot{
		info: info, payload: payload, mode: info.Mode(), uid: stat.Uid, gid: stat.Gid,
	}
}

func assertManualHostUpgradeLinuxProtectedFileUnchanged(
	t *testing.T,
	path string,
	before manualHostUpgradeLinuxProtectedSnapshot,
) {
	t.Helper()
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(before.info, after) || before.mode != after.Mode() ||
		before.uid != stat.Uid || before.gid != stat.Gid ||
		!bytes.Equal(before.payload, payload) {
		t.Fatalf("protected file changed during upgrade: %s", path)
	}
}

func assertManualHostUpgradeLinuxPublicLinks(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	for path, want := range map[string]string{
		fixture.publicAgentPath: filepath.Join(
			fixture.runtime.selfUpdate.currentLink,
			"bin",
			"autostream-host-agent",
		),
		fixture.publicExecutorPath: filepath.Join(
			fixture.runtime.selfUpdate.currentLink,
			"bin",
			"autostream-local-executor",
		),
	} {
		got, err := os.Readlink(path)
		if err != nil || got != want {
			t.Fatalf("public link %s=%q want=%q err=%v", path, got, want, err)
		}
	}
}

func assertManualHostUpgradeLinuxSlotBinding(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
	slot string,
) {
	t.Helper()
	request, digests, err := readManualHostUpdateSlotBinding(
		slot, fixture.runtime.selfUpdate,
	)
	if err != nil {
		t.Fatalf("read slot %s binding: %v", slot, err)
	}
	if !sameManualHostUpgradeArchiveContent(request, fixture.targetRequest) {
		t.Fatalf("slot %s request=%+v want=%+v", slot, request, fixture.targetRequest)
	}
	wantDigests, err := hostSelfUpdateArtifactBinaryDigests(fixture.artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	if digests != wantDigests {
		t.Fatalf("slot %s digests=%+v want=%+v", slot, digests, wantDigests)
	}
	for name, wantMode := range map[string]fs.FileMode{
		".generation":                   0o444,
		".release-binding.json":         0o444,
		"bin/autostream-host-agent":     0o755,
		"bin/autostream-local-executor": 0o755,
	} {
		info, err := os.Lstat(filepath.Join(
			fixture.runtime.selfUpdate.slotsRoot,
			slot,
			filepath.FromSlash(name),
		))
		if err != nil || info.Mode().Perm() != wantMode {
			t.Fatalf("slot %s path %s mode=%v err=%v", slot, name, infoMode(info), err)
		}
	}
}

func assertManualHostUpgradeLinuxNoTransitionResidue(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	entries, err := os.ReadDir(fixture.runtime.selfUpdate.slotsRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Fatalf("slot transition residue remains: %s", entry.Name())
		}
	}
	entries, err = os.ReadDir(fixture.runtime.selfUpdate.installRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".current-") {
			t.Fatalf("current-link transition residue remains: %s", entry.Name())
		}
	}
}

func infoMode(info os.FileInfo) fs.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}
