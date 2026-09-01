//go:build !linux

package hostruntime

import (
	"context"
	"errors"
)

func (LocalExecutorClient) HostSelfUpdateWatchdogStatus(
	context.Context,
) (HostSelfUpdateRuntimeStatus, error) {
	return HostSelfUpdateRuntimeStatus{},
		errors.New("host self-update watchdog status requires Linux")
}

func (LocalExecutorClient) HostSelfUpdateStatus(
	context.Context,
	string,
	LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update requires Linux")
}

func (LocalExecutorClient) StageHostSelfUpdate(
	context.Context,
	string,
	HostSelfUpdateRequest,
	HostSelfUpdateGrantAuthorization,
	LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update requires Linux")
}

func (LocalExecutorClient) ActivateHostSelfUpdate(
	context.Context,
	string,
	string,
	LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update requires Linux")
}

func (LocalExecutorClient) ReconcileHostSelfUpdate(
	context.Context,
	string,
	HostSelfUpdateAgentProof,
	*HostSelfUpdateGrantAuthorization,
	LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return HostSelfUpdateRuntimeStatus{}, errors.New("host self-update requires Linux")
}
