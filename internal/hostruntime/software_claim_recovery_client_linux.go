//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func (c LocalExecutorClient) InspectSoftwareClaimRecovery(ctx context.Context, inspection SoftwareClaimRecoveryInspection, fence LocalExecutorMutationFence) (SoftwareClaimRecoveryProof, error) {
	request := LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: localExecutorSoftwareClaimRecoveryOperation,
		ServiceID: inspection.Request.TargetID, SoftwareClaimRecovery: &inspection,
		SourcePolicyRevision: fence.SourcePolicyRevision, OwnershipEpoch: fence.OwnershipEpoch,
		OwnershipPolicyRevision: fence.OwnershipPolicyRevision, ExecutorPolicyRevision: fence.ExecutorPolicyRevision,
	}
	if request.Validate() != nil {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery inspection request is invalid")
	}
	socketPath := strings.TrimSpace(c.SocketPath)
	if socketPath == "" {
		socketPath = LocalExecutorSocketPath
	}
	if !filepath.IsAbs(socketPath) {
		return SoftwareClaimRecoveryProof{}, errors.New("local executor socket path is invalid")
	}
	timeout := c.Timeout
	if timeout <= 0 || timeout > localExecutorClientTimeout {
		timeout = localExecutorClientTimeout
	}
	dialer := net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return SoftwareClaimRecoveryProof{}, errors.New("connect to local executor recovery inspection")
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return SoftwareClaimRecoveryProof{}, errors.New("local executor connection type is invalid")
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	if EncodeLocalExecutorRequest(connection, request) != nil || connection.CloseWrite() != nil {
		return SoftwareClaimRecoveryProof{}, errors.New("send local executor recovery inspection")
	}
	response, err := DecodeLocalExecutorResponse(connection)
	if err != nil {
		return SoftwareClaimRecoveryProof{}, errors.New("read local executor recovery inspection")
	}
	if response.Error != nil {
		return SoftwareClaimRecoveryProof{}, &LocalExecutorClientError{Code: response.Error.Code, Message: response.Error.Message}
	}
	if response.SoftwareClaimRecovery == nil {
		return SoftwareClaimRecoveryProof{}, errors.New("local executor recovery inspection returned another outcome")
	}
	proof := *response.SoftwareClaimRecovery
	if proof.RequestSHA256 != inspection.Request.sha256() || proof.OwnershipEpoch != fence.OwnershipEpoch ||
		proof.SourcePolicyRevision != fence.SourcePolicyRevision || proof.ProjectionRevision != fence.OwnershipPolicyRevision ||
		proof.ExecutorPolicyRevision != fence.ExecutorPolicyRevision || proof.ExecutorPolicySHA256 != inspection.ExecutorPolicySHA256 {
		return SoftwareClaimRecoveryProof{}, errors.New("local executor recovery inspection returned a different binding")
	}
	return proof, nil
}

func acquireSoftwareClaimRecoveryLifecycleLock(path string) (func(), error) {
	if validateManagedDirectoryChain(filepath.Dir(path)) != nil {
		return nil, errors.New("Host Agent recovery lifecycle state parent is unsafe")
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, errors.New("open Host Agent recovery lifecycle lock")
	}
	file := os.NewFile(uintptr(fd), "software-claim-recovery-lock")
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !managedSnapshotOwnedByCurrentUser(info) {
		_ = file.Close()
		return nil, errors.New("Host Agent recovery lifecycle lock is unsafe")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = file.Close()
		return nil, errors.New("Host Agent daemon or another recovery command is active; stop the managed Agent before explicit software claim recovery")
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = file.Close() }, nil
}
