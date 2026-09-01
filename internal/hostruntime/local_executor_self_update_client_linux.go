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

const localExecutorHostSelfUpdateWatchdogClientTimeout = 2 * time.Second

func (c LocalExecutorClient) HostSelfUpdateWatchdogStatus(
	ctx context.Context,
) (HostSelfUpdateRuntimeStatus, error) {
	watchdogContext, cancel := context.WithTimeout(
		ctx,
		localExecutorHostSelfUpdateWatchdogClientTimeout,
	)
	defer cancel()
	watchdogClient := c
	watchdogClient.Timeout = localExecutorHostSelfUpdateWatchdogClientTimeout
	return watchdogClient.executeHostSelfUpdateRequest(
		watchdogContext,
		LocalExecutorRequest{
			Version:   LocalExecutorMutationProtocolVersion,
			Operation: localExecutorHostSelfUpdateWatchdogOperation,
			ServiceID: localExecutorHostSelfUpdateWatchdogServiceID,
		},
	)
}

func (c LocalExecutorClient) HostSelfUpdateStatus(
	ctx context.Context,
	hostID string,
	fence LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return c.executeHostSelfUpdate(
		ctx, "host_self_update_status", hostID, nil, "", nil, nil, fence,
	)
}

func (c LocalExecutorClient) StageHostSelfUpdate(
	ctx context.Context,
	hostID string,
	request HostSelfUpdateRequest,
	authorization HostSelfUpdateGrantAuthorization,
	fence LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return c.executeHostSelfUpdate(
		ctx, "host_self_update_stage", hostID, &request, "", nil,
		&authorization, fence,
	)
}

func (c LocalExecutorClient) ActivateHostSelfUpdate(
	ctx context.Context,
	hostID, generation string,
	fence LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return c.executeHostSelfUpdate(
		ctx, "host_self_update_activate", hostID, nil, generation, nil, nil, fence,
	)
}

func (c LocalExecutorClient) ReconcileHostSelfUpdate(
	ctx context.Context,
	hostID string,
	proof HostSelfUpdateAgentProof,
	authorization *HostSelfUpdateGrantAuthorization,
	fence LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return c.executeHostSelfUpdate(
		ctx, "host_self_update_reconcile", hostID, nil, "", &proof,
		authorization, fence,
	)
}

func (c LocalExecutorClient) executeHostSelfUpdate(
	ctx context.Context,
	operation, hostID string,
	update *HostSelfUpdateRequest,
	generation string,
	proof *HostSelfUpdateAgentProof,
	authorization *HostSelfUpdateGrantAuthorization,
	fence LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	request := LocalExecutorRequest{
		Version:                  LocalExecutorMutationProtocolVersion,
		Operation:                operation,
		ServiceID:                hostID,
		HostSelfUpdate:           update,
		HostSelfUpdateProof:      proof,
		HostSelfUpdateGeneration: generation,
		HostSelfUpdateGrant:      authorization,
		SourcePolicyRevision:     fence.SourcePolicyRevision,
		OwnershipEpoch:           fence.OwnershipEpoch,
		OwnershipPolicyRevision:  fence.OwnershipPolicyRevision,
		ExecutorPolicyRevision:   fence.ExecutorPolicyRevision,
	}
	status, err := c.executeHostSelfUpdateRequest(ctx, request)
	if err == nil ||
		authorization == nil ||
		ctx.Err() != nil {
		return status, err
	}
	var responseError *LocalExecutorClientError
	if errors.As(err, &responseError) &&
		responseError.Code != "authorization_uncertain" {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	// The root executor durably records the exact grant before consuming it.
	// Retrying the identical IPC request closes a lost consume-response or
	// local socket response without issuing or applying a second directive.
	return c.executeHostSelfUpdateRequest(ctx, request)
}

func (c LocalExecutorClient) executeHostSelfUpdateRequest(
	ctx context.Context,
	request LocalExecutorRequest,
) (HostSelfUpdateRuntimeStatus, error) {
	socketPath := strings.TrimSpace(c.SocketPath)
	if socketPath == "" {
		socketPath = LocalExecutorSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return HostSelfUpdateRuntimeStatus{}, errors.New("local executor socket path is invalid")
	}
	timeout := c.Timeout
	if request.Operation == "host_self_update_stage" {
		timeout = c.MutationTimeout
		if timeout <= 0 || timeout > localExecutorMutationClientTimeout {
			timeout = localExecutorMutationClientTimeout
		}
	} else if timeout <= 0 || timeout > localExecutorClientTimeout {
		timeout = localExecutorClientTimeout
	}
	dialer := net.Dialer{Timeout: localExecutorClientTimeout}
	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, errors.New("connect to local executor")
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return HostSelfUpdateRuntimeStatus{}, errors.New("local executor connection type is invalid")
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	if err := EncodeLocalExecutorRequest(connection, request); err != nil {
		return HostSelfUpdateRuntimeStatus{}, errors.New("send local executor host self-update request")
	}
	if err := connection.CloseWrite(); err != nil {
		return HostSelfUpdateRuntimeStatus{}, errors.New("finish local executor host self-update request")
	}
	response, err := DecodeLocalExecutorResponse(connection)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, errors.New("read local executor host self-update response")
	}
	if response.Error != nil {
		return HostSelfUpdateRuntimeStatus{}, &LocalExecutorClientError{Code: response.Error.Code, Message: response.Error.Message}
	}
	if response.HostSelfUpdate == nil {
		return HostSelfUpdateRuntimeStatus{}, errors.New("local executor host self-update response is missing")
	}
	return *response.HostSelfUpdate, nil
}
