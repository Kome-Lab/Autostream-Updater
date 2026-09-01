//go:build !linux

package hostruntime

import (
	"context"
	"errors"
)

func validateRuntimeCredentialDirectiveBinding(
	rotation HostAgentRuntimeTokenRotation,
) error {
	return rotation.Validate()
}

func (LocalExecutorClient) RuntimeCredentialStatus(
	context.Context,
	string,
) (RuntimeCredentialStatus, bool, error) {
	return RuntimeCredentialStatus{}, false, errors.New(
		"runtime credential rotation requires Linux",
	)
}

func (LocalExecutorClient) StageRuntimeCredential(
	context.Context,
	HostAgentRuntimeTokenRotation,
	BoundedSecret,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New(
		"runtime credential rotation requires Linux",
	)
}

func (LocalExecutorClient) PrepareRuntimeCredential(
	context.Context,
	HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New(
		"runtime credential rotation requires Linux",
	)
}

func (LocalExecutorClient) MarkRuntimeCredentialProofReady(
	context.Context,
	HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New(
		"runtime credential rotation requires Linux",
	)
}

func (LocalExecutorClient) ActivateRuntimeCredential(
	context.Context,
	HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New(
		"runtime credential rotation requires Linux",
	)
}

func (LocalExecutorClient) CancelRuntimeCredential(
	context.Context,
	HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New(
		"runtime credential rotation requires Linux",
	)
}

func (LocalExecutorClient) FinalizeRuntimeCredential(
	context.Context,
	HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New(
		"local executor runtime credential finalization requires Linux",
	)
}
