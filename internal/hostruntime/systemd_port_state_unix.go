//go:build !windows

package hostruntime

import "os"

func systemdPortLinkOrReparse(info os.FileInfo) bool {
	return info == nil || info.Mode()&os.ModeSymlink != 0
}
