//go:build linux

package hostruntime

import "path/filepath"

func acquireHostLifecycleLock() (func(), error) {
	directory, err := ensurePrivilegedHostLockDirectory()
	if err != nil {
		return func() {}, err
	}
	return lockManualHostUpgradeFile(
		filepath.Join(directory, ".autostream-host-lifecycle.lock"),
	)
}

func acquireHeldHostLifecycleLock() (*heldHostLifecycleLock, error) {
	directory, err := ensurePrivilegedHostLockDirectory()
	if err != nil {
		return nil, err
	}
	return acquireHeldHostLifecycleLockAt(
		filepath.Join(directory, heldHostLifecycleLockFileName), false,
	)
}
