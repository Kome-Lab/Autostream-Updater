//go:build windows

package hostruntime

import (
	"os"
	"syscall"
)

func systemdPortLinkOrReparse(info os.FileInfo) bool {
	if info == nil {
		return true
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
