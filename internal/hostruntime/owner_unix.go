//go:build !windows

package hostruntime

import (
	"errors"
	"os"
	"syscall"
)

func requireRootOwner(info os.FileInfo) error {
	if !isRootOwner(info) {
		return errors.New("config must be owned by root")
	}
	return nil
}

func isRootOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
