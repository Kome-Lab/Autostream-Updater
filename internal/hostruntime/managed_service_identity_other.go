//go:build !linux

package hostruntime

import "errors"

func LookupManagedServiceIdentity(
	string,
	string,
) (HostAgentConfigurePeerIdentity, error) {
	return HostAgentConfigurePeerIdentity{}, errors.New(
		"Host Agent configure is supported only on Linux and requires root",
	)
}
