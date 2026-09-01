//go:build windows

package hostruntime

import (
	"errors"
	"os"
)

func updaterConfigInstallGID(string) (int, error) {
	return 0, errors.New("updater configure is supported only on Linux and requires root")
}

func updaterConfigHasInstallOwner(os.FileInfo, int) bool { return false }
