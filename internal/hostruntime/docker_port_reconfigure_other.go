//go:build !linux

package hostruntime

import "errors"

func newPlatformDockerPortExecution(
	LocalExecutorPolicy,
	LocalExecutorTarget,
	Target,
	executorMutationRuntime,
) (dockerPortRuntime, dockerPortStateStore, error) {
	return nil, nil, errors.New("Docker port reconfiguration requires Linux")
}
