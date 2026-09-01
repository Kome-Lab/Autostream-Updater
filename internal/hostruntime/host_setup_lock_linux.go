//go:build linux

package hostruntime

import (
	"errors"
	"os"
	"path/filepath"
)

// AcquireHostRuntimeSetupLock serializes every root-owned Host runtime setup
// transaction with manual A/B upgrades. The lock inode is permanent so two
// processes can never split mutual exclusion by unlinking and recreating it.
func AcquireHostRuntimeSetupLock() (func(), error) {
	directory, err := ensurePrivilegedHostLockDirectory()
	if err != nil {
		return func() {}, err
	}
	return lockManualHostUpgradeFile(
		filepath.Join(directory, ".autostream-runtime-host-setup.lock"),
	)
}

// AcquireHostRuntimeSetupAndLifecycleLocks serializes an installer-style Host
// runtime transaction with both setup and online lifecycle operations. Every
// caller uses the canonical setup -> lifecycle order to avoid lock inversion.
func AcquireHostRuntimeSetupAndLifecycleLocks() (func(), error) {
	setupUnlock, err := AcquireHostRuntimeSetupLock()
	if err != nil {
		return func() {}, err
	}
	lifecycleUnlock, err := acquireHostLifecycleLock()
	if err != nil {
		setupUnlock()
		return func() {}, err
	}
	return func() {
		lifecycleUnlock()
		setupUnlock()
	}, nil
}

func ensurePrivilegedHostLockDirectory() (string, error) {
	directory := privilegedLockDir()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || !isRootOwner(info) {
		return "", errors.New("privileged Host lock directory is unsafe")
	}
	return directory, nil
}
