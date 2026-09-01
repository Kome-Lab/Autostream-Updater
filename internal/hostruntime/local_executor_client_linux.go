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

func (c LocalExecutorClient) Probe(ctx context.Context, serviceID string) (LocalExecutorProbe, error) {
	if !identifierPattern.MatchString(strings.TrimSpace(serviceID)) || serviceID != strings.TrimSpace(serviceID) {
		return LocalExecutorProbe{}, errors.New("local executor probe service identity is invalid")
	}
	socketPath := strings.TrimSpace(c.SocketPath)
	if socketPath == "" {
		socketPath = LocalExecutorSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return LocalExecutorProbe{}, errors.New("local executor socket path is invalid")
	}
	timeout := c.Timeout
	if timeout <= 0 || timeout > localExecutorClientTimeout {
		timeout = localExecutorClientTimeout
	}
	dialer := net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return LocalExecutorProbe{}, errors.New("connect to local executor")
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return LocalExecutorProbe{}, errors.New("local executor connection type is invalid")
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	request := LocalExecutorRequest{
		Version:   LocalExecutorProtocolVersion,
		Operation: "probe",
		ServiceID: serviceID,
	}
	if err := EncodeLocalExecutorRequest(connection, request); err != nil {
		return LocalExecutorProbe{}, errors.New("send local executor probe")
	}
	if err := connection.CloseWrite(); err != nil {
		return LocalExecutorProbe{}, errors.New("finish local executor probe request")
	}
	response, err := DecodeLocalExecutorResponse(connection)
	if err != nil {
		return LocalExecutorProbe{}, errors.New("read local executor probe")
	}
	if response.Error != nil {
		return LocalExecutorProbe{}, &LocalExecutorClientError{Code: response.Error.Code, Message: response.Error.Message}
	}
	return *response.Probe, nil
}

func (c LocalExecutorClient) Stage(ctx context.Context, plan MutationPlan, fence LocalExecutorMutationFence) (MutationStageResult, error) {
	response, err := c.executeMutation(ctx, "stage", plan, fence, "")
	if err != nil {
		return MutationStageResult{}, err
	}
	if response.Stage == nil ||
		response.Stage.SessionID != plan.SessionID ||
		response.Stage.PlanSHA256 != plan.PlanSHA256 ||
		normalizeDigest(response.Stage.ArtifactDigest) != normalizeDigest(plan.ArtifactDigest) {
		return MutationStageResult{}, errors.New("local executor stage response does not match the immutable plan")
	}
	return *response.Stage, nil
}

func (c LocalExecutorClient) Apply(ctx context.Context, plan MutationPlan, fence LocalExecutorMutationFence, grant BoundedSecret) (ApplyResult, error) {
	return c.executeMutationResult(ctx, "apply", plan, fence, grant)
}

func (c LocalExecutorClient) Reconcile(ctx context.Context, plan MutationPlan, fence LocalExecutorMutationFence, grant BoundedSecret) (ApplyResult, error) {
	return c.executeMutationResult(ctx, "reconcile", plan, fence, grant)
}

func (c LocalExecutorClient) PortReconfigure(
	ctx context.Context,
	plan SystemdPortReconfigurePlan,
	fence LocalExecutorMutationFence,
	grant BoundedSecret,
) (SystemdPortReconfigureResult, error) {
	return c.executePortMutation(ctx, "port_reconfigure", plan, fence, grant)
}

func (c LocalExecutorClient) PortReconfigureReconcile(
	ctx context.Context,
	plan SystemdPortReconfigurePlan,
	fence LocalExecutorMutationFence,
	grant BoundedSecret,
) (SystemdPortReconfigureResult, error) {
	return c.executePortMutation(ctx, "port_reconfigure_reconcile", plan, fence, grant)
}

func (c LocalExecutorClient) executeMutationResult(ctx context.Context, operation string, plan MutationPlan, fence LocalExecutorMutationFence, grant BoundedSecret) (ApplyResult, error) {
	response, err := c.executeMutation(ctx, operation, plan, fence, grant)
	if err != nil {
		return ApplyResult{}, err
	}
	if response.Result == nil ||
		response.SessionID != plan.SessionID ||
		response.PlanSHA256 != plan.PlanSHA256 {
		return ApplyResult{}, errors.New("local executor mutation response does not match the immutable plan")
	}
	return *response.Result, nil
}

func (c LocalExecutorClient) executeMutation(ctx context.Context, operation string, plan MutationPlan, fence LocalExecutorMutationFence, grant BoundedSecret) (LocalExecutorResponse, error) {
	if err := plan.Validate(); err != nil {
		return LocalExecutorResponse{}, errors.New("local executor mutation plan is invalid")
	}
	socketPath := strings.TrimSpace(c.SocketPath)
	if socketPath == "" {
		socketPath = LocalExecutorSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return LocalExecutorResponse{}, errors.New("local executor socket path is invalid")
	}
	timeout := c.MutationTimeout
	if timeout <= 0 || timeout > localExecutorMutationClientTimeout {
		timeout = localExecutorMutationClientTimeout
	}
	dialer := net.Dialer{Timeout: localExecutorClientTimeout}
	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return LocalExecutorResponse{}, errors.New("connect to local executor")
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return LocalExecutorResponse{}, errors.New("local executor connection type is invalid")
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	request := LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: operation,
		ServiceID: plan.TargetID, Plan: &plan,
		SourcePolicyRevision:    fence.SourcePolicyRevision,
		OwnershipEpoch:          fence.OwnershipEpoch,
		OwnershipPolicyRevision: fence.OwnershipPolicyRevision,
		ExecutorPolicyRevision:  fence.ExecutorPolicyRevision,
		MutationGrant:           grant,
	}
	if err := EncodeLocalExecutorRequest(connection, request); err != nil {
		return LocalExecutorResponse{}, errors.New("send local executor mutation request")
	}
	if err := connection.CloseWrite(); err != nil {
		return LocalExecutorResponse{}, errors.New("finish local executor mutation request")
	}
	response, err := DecodeLocalExecutorResponse(connection)
	if err != nil {
		return LocalExecutorResponse{}, errors.New("read local executor mutation response")
	}
	if response.Error != nil {
		return LocalExecutorResponse{}, &LocalExecutorClientError{Code: response.Error.Code, Message: response.Error.Message}
	}
	return response, nil
}

func (c LocalExecutorClient) executePortMutation(
	ctx context.Context,
	operation string,
	plan SystemdPortReconfigurePlan,
	fence LocalExecutorMutationFence,
	grant BoundedSecret,
) (SystemdPortReconfigureResult, error) {
	if err := plan.Validate(); err != nil {
		return SystemdPortReconfigureResult{}, errors.New("local executor port plan is invalid")
	}
	socketPath := strings.TrimSpace(c.SocketPath)
	if socketPath == "" {
		socketPath = LocalExecutorSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return SystemdPortReconfigureResult{}, errors.New("local executor socket path is invalid")
	}
	timeout := c.MutationTimeout
	if timeout <= 0 || timeout > localExecutorMutationClientTimeout {
		timeout = localExecutorMutationClientTimeout
	}
	dialer := net.Dialer{Timeout: localExecutorClientTimeout}
	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return SystemdPortReconfigureResult{}, errors.New("connect to local executor")
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return SystemdPortReconfigureResult{}, errors.New("local executor connection type is invalid")
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	request := LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: operation,
		ServiceID: plan.TargetID, PortPlan: &plan,
		SourcePolicyRevision:    fence.SourcePolicyRevision,
		OwnershipEpoch:          fence.OwnershipEpoch,
		OwnershipPolicyRevision: fence.OwnershipPolicyRevision,
		ExecutorPolicyRevision:  fence.ExecutorPolicyRevision,
		MutationGrant:           grant,
	}
	if err := EncodeLocalExecutorRequest(connection, request); err != nil {
		return SystemdPortReconfigureResult{}, errors.New("send local executor port mutation request")
	}
	if err := connection.CloseWrite(); err != nil {
		return SystemdPortReconfigureResult{}, errors.New("finish local executor port mutation request")
	}
	response, err := DecodeLocalExecutorResponse(connection)
	if err != nil {
		return SystemdPortReconfigureResult{}, errors.New("read local executor port mutation response")
	}
	if response.Error != nil {
		return SystemdPortReconfigureResult{}, &LocalExecutorClientError{Code: response.Error.Code, Message: response.Error.Message}
	}
	if response.PortResult == nil ||
		response.SessionID != plan.SessionID ||
		response.PlanSHA256 != plan.PortPlanSHA256 {
		return SystemdPortReconfigureResult{}, errors.New("local executor port mutation response does not match the immutable plan")
	}
	return *response.PortResult, nil
}
