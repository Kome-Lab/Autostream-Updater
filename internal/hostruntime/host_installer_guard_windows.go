//go:build windows

package hostruntime

import (
	"context"
	"errors"
)

func restartHostAgentFromUpgradeGuard(
	context.Context,
	HostAgentUpgradeGuardRequest,
) error {
	return errors.New("Host Agent installer recovery guard is supported only on Linux")
}
