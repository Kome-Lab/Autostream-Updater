package hostruntime

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

func validateManagedDirectoryChain(stateDir string) error {
	for directory, first := filepath.Clean(stateDir), true; ; directory, first = filepath.Dir(directory), false {
		info, err := os.Lstat(directory)
		if err != nil {
			return errors.New("managed state directory is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("managed state path must contain only real directories")
		}
		if first && !managedSnapshotOwnedByCurrentUser(info) {
			return errors.New("managed state directory must be owned by the updater service user")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
			if first || info.Mode()&os.ModeSticky == 0 {
				return errors.New("managed state path is writable by group or other users")
			}
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}
	}
}
