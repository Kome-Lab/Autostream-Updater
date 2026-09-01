//go:build !windows

package hostruntime

import (
	"os"
	"syscall"
)

func managedSnapshotOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func snapshotModeEnforced() bool { return true }
