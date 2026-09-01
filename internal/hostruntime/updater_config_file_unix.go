//go:build linux

package hostruntime

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func updaterConfigInstallGID(installGroup string) (int, error) {
	if os.Geteuid() != 0 {
		return 0, errors.New("updater configure requires root")
	}
	if installGroup == "" {
		return 0, errors.New("updater configure install group is required")
	}
	group, err := user.LookupGroup(installGroup)
	if err != nil {
		return 0, fmt.Errorf("lookup %s group: %w", installGroup, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		return 0, fmt.Errorf("%s group has an invalid gid", installGroup)
	}
	return gid, nil
}

func updaterConfigHasInstallOwner(info os.FileInfo, gid int) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && int(stat.Gid) == gid
}
