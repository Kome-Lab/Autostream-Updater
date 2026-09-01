//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"time"
)

func (c LocalExecutorClient) RuntimeCredentialStatus(
	ctx context.Context,
	serviceID string,
) (RuntimeCredentialStatus, bool, error) {
	request := LocalExecutorRequest{
		Version:   LocalExecutorMutationProtocolVersion,
		Operation: "runtime_credential_status",
		ServiceID: strings.TrimSpace(serviceID),
	}
	response, err := c.executeRuntimeCredentialRequest(ctx, request)
	if err != nil {
		var localErr *LocalExecutorClientError
		if errors.As(err, &localErr) && localErr.Code == "target_not_found" {
			return RuntimeCredentialStatus{}, false, nil
		}
		return RuntimeCredentialStatus{}, false, err
	}
	if response.RuntimeCredential == nil {
		return RuntimeCredentialStatus{}, false, errors.New(
			"local executor runtime credential status is missing",
		)
	}
	return *response.RuntimeCredential, true, nil
}

func (c LocalExecutorClient) StageRuntimeCredential(
	ctx context.Context,
	rotation HostAgentRuntimeTokenRotation,
	token BoundedSecret,
) (RuntimeCredentialStatus, error) {
	return c.executeRuntimeCredentialMutation(
		ctx, "runtime_credential_stage", rotation, token,
	)
}

func (c LocalExecutorClient) PrepareRuntimeCredential(
	ctx context.Context,
	rotation HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return c.executeRuntimeCredentialMutation(
		ctx, "runtime_credential_prepare", rotation, "",
	)
}

func (c LocalExecutorClient) MarkRuntimeCredentialProofReady(
	ctx context.Context,
	rotation HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return c.executeRuntimeCredentialMutation(
		ctx, "runtime_credential_proof_ready", rotation, "",
	)
}

func (c LocalExecutorClient) ActivateRuntimeCredential(
	ctx context.Context,
	rotation HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return c.executeRuntimeCredentialMutation(
		ctx, "runtime_credential_activate", rotation, "",
	)
}

func (c LocalExecutorClient) CancelRuntimeCredential(
	ctx context.Context,
	rotation HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return c.executeRuntimeCredentialMutation(
		ctx, "runtime_credential_cancel", rotation, "",
	)
}

func (c LocalExecutorClient) FinalizeRuntimeCredential(
	ctx context.Context,
	rotation HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return c.executeRuntimeCredentialMutation(
		ctx, "runtime_credential_finalize", rotation, "",
	)
}

func (c LocalExecutorClient) executeRuntimeCredentialMutation(
	ctx context.Context,
	operation string,
	rotation HostAgentRuntimeTokenRotation,
	token BoundedSecret,
) (RuntimeCredentialStatus, error) {
	if err := validateRuntimeCredentialDirectiveBinding(rotation); err != nil {
		return RuntimeCredentialStatus{}, errors.New(
			"runtime credential directive is invalid",
		)
	}
	request := LocalExecutorRequest{
		Version:   LocalExecutorMutationProtocolVersion,
		Operation: operation,
		ServiceID: rotation.ServiceID,
		RuntimeCredential: &RuntimeCredentialMutation{
			RotationID:       rotation.ID,
			ExecutionHostID:  rotation.ExecutionHostID,
			PreviousTokenID:  rotation.PreviousTokenID,
			StagedTokenID:    rotation.StagedTokenID,
			RotationRevision: rotation.Revision,
			RuntimeToken:     token,
		},
		SourcePolicyRevision:    rotation.ExpectedSourcePolicyRevision,
		OwnershipEpoch:          rotation.ExpectedOwnershipEpoch,
		OwnershipPolicyRevision: rotation.ExpectedProjectionRevision,
		ExecutorPolicyRevision:  rotation.ExpectedLocalExecutorPolicyRevision,
	}
	response, err := c.executeRuntimeCredentialRequest(ctx, request)
	if err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if response.RuntimeCredential == nil {
		return RuntimeCredentialStatus{}, errors.New(
			"local executor runtime credential response is missing",
		)
	}
	status := *response.RuntimeCredential
	if status.RotationID != rotation.ID ||
		status.ServiceID != rotation.ServiceID ||
		status.ExecutionHostID != rotation.ExecutionHostID ||
		status.PreviousTokenID != rotation.PreviousTokenID ||
		status.StagedTokenID != rotation.StagedTokenID ||
		status.OwnershipEpoch != rotation.ExpectedOwnershipEpoch ||
		status.SourcePolicyRevision != rotation.ExpectedSourcePolicyRevision ||
		status.ProjectionRevision != rotation.ExpectedProjectionRevision ||
		status.LocalExecutorPolicyRevision != rotation.ExpectedLocalExecutorPolicyRevision {
		return RuntimeCredentialStatus{}, errors.New(
			"local executor runtime credential response binding changed",
		)
	}
	return status, nil
}

func validateRuntimeCredentialDirectiveBinding(
	rotation HostAgentRuntimeTokenRotation,
) error {
	if !identifierPattern.MatchString(rotation.ID) ||
		!identifierPattern.MatchString(rotation.ServiceID) ||
		!validExecutionHostID(rotation.ExecutionHostID) ||
		!identifierPattern.MatchString(rotation.PreviousTokenID) ||
		!identifierPattern.MatchString(rotation.StagedTokenID) ||
		rotation.PreviousTokenID == rotation.StagedTokenID ||
		rotation.Revision < 1 ||
		rotation.ExpectedOwnershipEpoch < 1 ||
		rotation.ExpectedSourcePolicyRevision < 1 ||
		rotation.ExpectedProjectionRevision < 1 ||
		rotation.ExpectedLocalExecutorPolicyRevision < 1 {
		return errors.New("runtime credential directive binding is invalid")
	}
	return nil
}

func (c LocalExecutorClient) executeRuntimeCredentialRequest(
	ctx context.Context,
	request LocalExecutorRequest,
) (LocalExecutorResponse, error) {
	if err := request.Validate(); err != nil {
		return LocalExecutorResponse{}, err
	}
	socketPath := strings.TrimSpace(c.SocketPath)
	if socketPath == "" {
		socketPath = LocalExecutorSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return LocalExecutorResponse{}, errors.New(
			"local executor socket path is invalid",
		)
	}
	timeout := c.MutationTimeout
	if timeout <= 0 || timeout > localExecutorMutationClientTimeout {
		timeout = localExecutorMutationClientTimeout
	}
	dialer := net.Dialer{Timeout: localExecutorClientTimeout}
	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return LocalExecutorResponse{}, errors.New(
			"connect to local executor",
		)
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return LocalExecutorResponse{}, errors.New(
			"local executor connection type is invalid",
		)
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	if err := EncodeLocalExecutorRequest(connection, request); err != nil {
		return LocalExecutorResponse{}, errors.New(
			"send local executor runtime credential request",
		)
	}
	if err := connection.CloseWrite(); err != nil {
		return LocalExecutorResponse{}, errors.New(
			"finish local executor runtime credential request",
		)
	}
	response, err := DecodeLocalExecutorResponse(connection)
	if err != nil {
		return LocalExecutorResponse{}, errors.New(
			"read local executor runtime credential response",
		)
	}
	if response.Error != nil {
		return LocalExecutorResponse{}, &LocalExecutorClientError{
			Code: response.Error.Code, Message: response.Error.Message,
		}
	}
	return response, nil
}
