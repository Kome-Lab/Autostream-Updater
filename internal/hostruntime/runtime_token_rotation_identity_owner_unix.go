//go:build !windows

package hostruntime

import (
	"os"
	"syscall"
)

func runtimeCredentialOwnedBy(info os.FileInfo, uid, gid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid
}
