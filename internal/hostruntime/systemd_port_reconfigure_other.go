//go:build !linux

package hostruntime

import "errors"

func newPlatformSystemdPortExecution(
	LocalExecutorPolicy,
	LocalExecutorTarget,
	Target,
	executorMutationRuntime,
) (systemdPortRuntime, systemdPortStateStore, error) {
	return nil, nil, errors.New("systemd port reconfiguration requires Linux")
}
