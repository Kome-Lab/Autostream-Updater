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
