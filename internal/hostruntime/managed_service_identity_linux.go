//go:build linux

package hostruntime

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

func LookupManagedServiceIdentity(
	userName, groupName string,
) (HostAgentConfigurePeerIdentity, error) {
	if os.Geteuid() != 0 {
		return HostAgentConfigurePeerIdentity{}, errors.New("Host Agent configure requires root")
	}
	userName = strings.TrimSpace(userName)
	groupName = strings.TrimSpace(groupName)
	if userName == "" || groupName == "" {
		return HostAgentConfigurePeerIdentity{}, errors.New("managed service user and group are required")
	}
	account, err := user.Lookup(userName)
	if err != nil {
		return HostAgentConfigurePeerIdentity{}, fmt.Errorf("lookup %s user: %w", userName, err)
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return HostAgentConfigurePeerIdentity{}, fmt.Errorf("lookup %s group: %w", groupName, err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return HostAgentConfigurePeerIdentity{}, fmt.Errorf("%s user has an invalid uid", userName)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || gid == 0 || account.Gid != group.Gid {
		return HostAgentConfigurePeerIdentity{}, fmt.Errorf(
			"%s user primary gid does not match %s group",
			userName,
			groupName,
		)
	}
	return HostAgentConfigurePeerIdentity{UID: uint32(uid), GID: uint32(gid)}, nil
}
