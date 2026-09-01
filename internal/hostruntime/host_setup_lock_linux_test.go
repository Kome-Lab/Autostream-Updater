//go:build linux

package hostruntime

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestHostRuntimeSetupAndLifecycleLocksUsePermanentStrongInodes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("privileged Host lock validation requires root")
	}

	unlock, err := AcquireHostRuntimeSetupAndLifecycleLocks()
	if err != nil {
		t.Fatalf("acquire combined Host runtime locks: %v", err)
	}
	directory := privilegedLockDir()
	setupPath := filepath.Join(directory, ".autostream-runtime-host-setup.lock")
	lifecyclePath := filepath.Join(directory, ".autostream-host-lifecycle.lock")
	setupBefore := requireStrongPermanentHostLock(t, setupPath)
	lifecycleBefore := requireStrongPermanentHostLock(t, lifecyclePath)

	contendedUnlock, err := acquireHostLifecycleLock()
	if err == nil {
		contendedUnlock()
		unlock()
		t.Fatal("Host lifecycle lock was acquired while the combined transaction held it")
	}
	if !strings.Contains(err.Error(), "another privileged Host lifecycle operation is active") {
		unlock()
		t.Fatalf("unexpected Host lifecycle contention error: %v", err)
	}
	unlock()

	secondUnlock, err := AcquireHostRuntimeSetupAndLifecycleLocks()
	if err != nil {
		t.Fatalf("reacquire combined Host runtime locks: %v", err)
	}
	defer secondUnlock()
	setupAfter := requireStrongPermanentHostLock(t, setupPath)
	lifecycleAfter := requireStrongPermanentHostLock(t, lifecyclePath)
	if !os.SameFile(setupBefore, setupAfter) {
		t.Fatal("Host setup lock inode changed between transactions")
	}
	if !os.SameFile(lifecycleBefore, lifecycleAfter) {
		t.Fatal("Host lifecycle lock inode changed between transactions")
	}
}

func requireStrongPermanentHostLock(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Mode()&os.ModeSymlink != 0 || !isRootOwner(info) || !ok || stat.Nlink != 1 {
		t.Fatalf("unsafe permanent Host lock %s: mode=%v stat=%#v", path, info.Mode(), stat)
	}
	return info
}
