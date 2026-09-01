//go:build !linux

package hostruntime

import (
	"context"
	"errors"
)

func verifyHostAgentLiveSystemdSidecar(
	context.Context,
	LocalExecutorPolicy,
	LocalExecutorPolicy,
	LocalExecutorTarget,
	LocalExecutorTarget,
) (hostAgentLiveSystemdSidecarProof, error) {
	return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar adoption is supported only on Linux")
}
