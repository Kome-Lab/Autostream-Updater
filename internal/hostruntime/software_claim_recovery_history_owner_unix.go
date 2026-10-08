//go:build !windows

package hostruntime

import (
	"os"
	"syscall"
)

func softwareClaimRecoveryDirectoryOwnerSafe(info os.FileInfo, owner func(os.FileInfo) bool) bool {
	if info == nil || owner == nil || !owner(info) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	// Root readers provide the canonical service UID/GID predicate. A service
	// process must also retain its own primary group when the generic managed
	// snapshot predicate checks only its current UID.
	return ok && (stat.Uid != uint32(os.Geteuid()) || stat.Gid == uint32(os.Getegid()))
}

func softwareClaimRecoveryRecordOwnerSafe(info os.FileInfo, owner func(os.FileInfo) bool) bool {
	if !softwareClaimRecoveryDirectoryOwnerSafe(info, owner) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
