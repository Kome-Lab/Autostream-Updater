//go:build windows

package hostruntime

import (
	"context"
	"errors"
)

func upgradeHostRuntimeFromVerifiedBundle(
	context.Context,
	ManualHostUpgradeRequest,
) (ManualHostUpgradeResult, error) {
	return ManualHostUpgradeResult{}, errors.New(
		"manual Host runtime upgrade is supported only on Linux",
	)
}

func inspectHostUpdateRecovery() (bool, error) {
	return false, errors.New(
		"Host update recovery inspection is supported only on Linux",
	)
}
