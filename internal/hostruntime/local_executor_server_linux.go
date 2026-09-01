//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const localExecutorConnectionDeadline = 5 * time.Second

const (
	localExecutorRequestTimeout        = 30 * time.Second
	localExecutorMutationTimeout       = 30 * time.Minute
	localExecutorHostSelfUpdateTimeout = 4 * time.Second
	localExecutorResponseWriteTimeout  = 2 * time.Second
	localExecutorMaxConcurrentRequests = 8
)

type localExecutorPeer struct {
	PID int32
	UID uint32
	GID uint32
}

// ServeLocalExecutor starts the Linux-only, root-owned probe executor. The
// caller is expected to run this from its dedicated systemd service.
func ServeLocalExecutor(ctx context.Context, policyPath string) error {
	if os.Geteuid() != 0 {
		return errors.New("local executor requires root")
	}
	policy, err := LoadLocalExecutorPolicy(policyPath, true)
	if err != nil {
		return err
	}
	systemdState, err := newFileSystemdPortStateStore(LocalExecutorMutationStateDir, true)
	if err != nil {
		return err
	}
	dockerState, err := newFileDockerPortStateStore(LocalExecutorMutationStateDir, true)
	if err != nil {
		return err
	}
	appliedPortState := localExecutorAppliedPortState{
		systemd: systemdState,
		docker:  dockerState,
	}
	activated, inherited, err := localExecutorActivatedListener(
		policy.SocketPath,
		os.Getenv,
		os.Getpid(),
		func(fd uintptr) *os.File {
			return os.NewFile(fd, "systemd-local-executor-socket")
		},
	)
	if err != nil {
		return err
	}
	if inherited {
		if err := validateLocalExecutorSocketDirectory(filepath.Dir(policy.SocketPath), 0, policy.AgentGID); err != nil {
			_ = activated.Close()
			return err
		}
		socketInfo, err := verifyLocalExecutorSocket(policy.SocketPath, 0, policy.AgentGID)
		if err != nil {
			_ = activated.Close()
			return err
		}
		return serveLocalExecutorListener(ctx, policy, linuxLocalTargetVerifier{
			runner: OSCommandRunner{NewProcessGroup: true},
		}, nil, appliedPortState, activated, policy.SocketPath, socketInfo, false)
	}
	if err := prepareLocalExecutorSocketDirectory(filepath.Dir(policy.SocketPath), 0, policy.AgentGID); err != nil {
		return err
	}
	return serveLocalExecutor(ctx, policy, linuxLocalTargetVerifier{
		runner: OSCommandRunner{NewProcessGroup: true},
	}, nil, appliedPortState, 0, policy.SocketPath)
}

func serveLocalExecutorForTest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	verifier localTargetVerifier,
	httpClient *http.Client,
	serverUID uint32,
	socketPath string,
) error {
	return serveLocalExecutor(ctx, policy, verifier, httpClient, nil, serverUID, socketPath)
}

func serveLocalExecutor(
	ctx context.Context,
	policy LocalExecutorPolicy,
	verifier localTargetVerifier,
	httpClient *http.Client,
	systemdState systemdPortAppliedStateReader,
	serverUID uint32,
	socketPath string,
) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if verifier == nil || !filepath.IsAbs(socketPath) {
		return errors.New("local executor runtime is invalid")
	}
	directory := filepath.Dir(socketPath)
	if err := validateLocalExecutorSocketDirectory(directory, serverUID, policy.AgentGID); err != nil {
		return err
	}
	if err := removeVerifiedStaleLocalExecutorSocket(socketPath, serverUID, policy.AgentGID); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen on local executor socket: %w", err)
	}
	socketInfo, err := secureLocalExecutorSocket(socketPath, serverUID, policy.AgentGID)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return err
	}
	return serveLocalExecutorListener(
		ctx, policy, verifier, httpClient, systemdState,
		listener, socketPath, socketInfo, true,
	)
}

func serveLocalExecutorListener(
	ctx context.Context,
	policy LocalExecutorPolicy,
	verifier localTargetVerifier,
	httpClient *http.Client,
	systemdState systemdPortAppliedStateReader,
	listener *net.UnixListener,
	socketPath string,
	socketInfo os.FileInfo,
	removeSocket bool,
) error {
	defer listener.Close()
	serverContext, stopServer := context.WithCancel(ctx)
	defer stopServer()
	if removeSocket {
		defer removeSameLocalExecutorSocket(socketPath, socketInfo)
	}
	go func() {
		<-serverContext.Done()
		_ = listener.Close()
	}()
	go runRuntimeCredentialExpiryLoop(
		serverContext,
		policy,
		runtimeCredentialExpiryPollInterval,
	)
	requestSlots := make(chan struct{}, localExecutorMaxConcurrentRequests)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if serverContext.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept local executor connection: %w", err)
		}
		select {
		case requestSlots <- struct{}{}:
			go func() {
				defer func() { <-requestSlots }()
				serveLocalExecutorConnection(
					serverContext, connection, policy, verifier, httpClient,
					systemdState, stopServer,
				)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func localExecutorActivatedListener(
	socketPath string,
	getenv func(string) string,
	processID int,
	fileForFD func(uintptr) *os.File,
) (*net.UnixListener, bool, error) {
	listenPID := strings.TrimSpace(getenv("LISTEN_PID"))
	listenFDs := strings.TrimSpace(getenv("LISTEN_FDS"))
	listenNames := strings.TrimSpace(getenv("LISTEN_FDNAMES"))
	if listenPID == "" && listenFDs == "" && listenNames == "" {
		return nil, false, nil
	}
	pid, pidErr := strconv.Atoi(listenPID)
	count, countErr := strconv.Atoi(listenFDs)
	if pidErr != nil || countErr != nil || pid != processID || count != 1 ||
		listenNames != "autostream-local-executor" || fileForFD == nil {
		return nil, false, errors.New("local executor systemd socket activation metadata is invalid")
	}
	file := fileForFD(3)
	if file == nil {
		return nil, false, errors.New("local executor systemd socket activation descriptor is unavailable")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, false, errors.New("local executor systemd socket activation descriptor is invalid")
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok || unixListener.Addr().Network() != "unix" || unixListener.Addr().String() != socketPath {
		_ = listener.Close()
		return nil, false, errors.New("local executor systemd socket activation address is invalid")
	}
	return unixListener, true, nil
}

func serveLocalExecutorConnection(
	ctx context.Context,
	connection *net.UnixConn,
	policy LocalExecutorPolicy,
	verifier localTargetVerifier,
	httpClient *http.Client,
	systemdState systemdPortAppliedStateReader,
	stopServer context.CancelFunc,
) {
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(localExecutorConnectionDeadline))
	peer, err := localExecutorPeerCredential(connection)
	if err != nil ||
		(peer.UID != 0 &&
			validateLocalExecutorPeer(peer, policy.AgentUID) != nil) ||
		peer.PID <= 0 {
		return
	}
	request, err := DecodeLocalExecutorRequest(connection)
	if err != nil {
		_ = EncodeLocalExecutorResponse(connection, localExecutorFailure("invalid_request"))
		return
	}
	if validateLocalExecutorPeerForOperation(
		peer,
		policy.AgentUID,
		request.Operation,
	) != nil {
		return
	}
	_ = connection.SetReadDeadline(time.Time{})
	requestContext, cancel := localExecutorRequestContext(ctx, request.Operation)
	defer cancel()
	var response LocalExecutorResponse
	if request.Operation == localExecutorHostSelfUpdateWatchdogOperation {
		// The fixed-slot watchdog already holds the host lifecycle lock while
		// proving a restarted executor. Keep this read-only handshake outside
		// handleLocalExecutorMutation and its lock/prepare path.
		response = handleLocalExecutorWatchdogStatus(
			request,
			defaultHostSelfUpdateExecutorRuntime(),
		)
	} else if request.Operation == "probe" {
		response = handleLocalExecutorRequestWithSystemdState(
			requestContext, policy, request, verifier, httpClient, systemdState,
		)
	} else {
		rt := defaultExecutorMutationRuntime()
		rt.httpClient = httpClient
		response = handleLocalExecutorMutation(requestContext, policy, request, rt)
	}
	_ = connection.SetWriteDeadline(time.Now().Add(localExecutorResponseWriteTimeout))
	_ = EncodeLocalExecutorResponse(connection, response)
	if localExecutorResponseRequiresRuntimeRestart(response) &&
		stopServer != nil {
		stopServer()
	}
}

func localExecutorRequestContext(
	parent context.Context,
	operation string,
) (context.Context, context.CancelFunc) {
	requestTimeout := localExecutorMutationTimeout
	switch operation {
	case "probe":
		requestTimeout = localExecutorRequestTimeout
	case localExecutorHostSelfUpdateWatchdogOperation:
		requestTimeout = localExecutorHostSelfUpdateWatchdogClientTimeout
	case "host_self_update_status",
		"host_self_update_activate",
		"host_self_update_reconcile":
		// These calls use the default five-second Local Executor client
		// deadline. Keep their server-side work bounded early enough to kill
		// an uncooperative identity process and still encode a response.
		requestTimeout = localExecutorHostSelfUpdateTimeout
	}
	return context.WithTimeout(parent, requestTimeout)
}

func localExecutorResponseRequiresRuntimeRestart(
	response LocalExecutorResponse,
) bool {
	return response.HostSelfUpdate != nil &&
		response.HostSelfUpdate.RestartRequested
}

func localExecutorPeerCredential(connection *net.UnixConn) (localExecutorPeer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return localExecutorPeer{}, errors.New("read local executor peer credentials")
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || controlErr != nil || credential == nil {
		return localExecutorPeer{}, errors.New("read local executor peer credentials")
	}
	return localExecutorPeer{PID: credential.Pid, UID: credential.Uid, GID: credential.Gid}, nil
}

func validateLocalExecutorPeer(peer localExecutorPeer, expectedUID uint32) error {
	if expectedUID == 0 || peer.PID <= 0 || peer.UID != expectedUID {
		return errors.New("local executor peer UID rejected")
	}
	return nil
}

func validateLocalExecutorPeerForOperation(
	peer localExecutorPeer,
	expectedUID uint32,
	operation string,
) error {
	if peer.PID <= 0 {
		return errors.New("local executor peer PID rejected")
	}
	if operation == localExecutorHostSelfUpdateWatchdogOperation {
		if peer.UID != 0 {
			return errors.New(
				"local executor watchdog status requires a root peer",
			)
		}
		return nil
	}
	if peer.UID == 0 {
		return errors.New(
			"local executor root peer may only request watchdog status",
		)
	}
	return validateLocalExecutorPeer(peer, expectedUID)
}

func handleLocalExecutorWatchdogStatus(
	request LocalExecutorRequest,
	rt hostSelfUpdateExecutorRuntime,
) LocalExecutorResponse {
	if request.Operation != localExecutorHostSelfUpdateWatchdogOperation ||
		request.Validate() != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion,
			"invalid_request",
		)
	}
	// Do not call prepare, loadState, status, or grant recovery here. A
	// watchdog probe must neither initialize nor converge durable state.
	state, err := rt.loadPersistedState()
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion,
			"state_unavailable",
		)
	}
	currentSlot, err := rt.readCurrentSlot()
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion,
			"state_unavailable",
		)
	}
	status := HostSelfUpdateRuntimeStatus{
		State:                   state,
		CurrentSlot:             currentSlot,
		ExecutorVersion:         rt.executorVersion,
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		LastAction:              HostSelfUpdateActionNone,
	}
	response := LocalExecutorResponse{
		Version:        LocalExecutorMutationProtocolVersion,
		HostSelfUpdate: &status,
	}
	if response.Validate() != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion,
			"internal_error",
		)
	}
	return response
}

func prepareLocalExecutorSocketDirectory(directory string, ownerUID, agentGID uint32) error {
	parent := filepath.Dir(directory)
	if err := validateLocalExecutorSocketParents(parent, ownerUID); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(directory, 0o750); err != nil {
			return fmt.Errorf("create local executor socket directory: %w", err)
		}
		created, statErr := os.Lstat(directory)
		if statErr != nil {
			return errors.New("created local executor socket directory is unavailable")
		}
		stat, statOK := created.Sys().(*syscall.Stat_t)
		if created.Mode()&os.ModeSymlink != 0 || !created.IsDir() ||
			!statOK || stat.Uid != ownerUID || created.Mode().Perm()&0o022 != 0 {
			return errors.New("created local executor socket directory is unsafe")
		}
		if err := secureLocalExecutorSocketDirectory(directory, ownerUID, agentGID); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("stat local executor socket directory: %w", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("local executor socket directory must not be a symlink")
	}
	return validateLocalExecutorSocketDirectory(directory, ownerUID, agentGID)
}

func secureLocalExecutorSocketDirectory(directory string, ownerUID, agentGID uint32) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return errors.New("local executor socket directory cannot be secured")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		!ok || stat.Uid != ownerUID || info.Mode().Perm()&0o022 != 0 {
		return errors.New("local executor socket directory cannot be secured")
	}
	if err := os.Chown(directory, int(ownerUID), int(agentGID)); err != nil {
		return fmt.Errorf("set local executor socket directory owner: %w", err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		return fmt.Errorf("set local executor socket directory mode: %w", err)
	}
	return validateLocalExecutorSocketDirectory(directory, ownerUID, agentGID)
}

func validateLocalExecutorSocketParents(directory string, ownerUID uint32) error {
	for current := filepath.Clean(directory); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
			info.Mode().Perm()&0o022 != 0 {
			return errors.New("local executor socket parents must be trusted non-writable directories")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != ownerUID {
			return errors.New("local executor socket parents must have the trusted owner")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func validateLocalExecutorSocketDirectory(directory string, ownerUID, agentGID uint32) error {
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o750 {
		return errors.New("local executor socket directory must be a non-symlink directory with mode 0750")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Gid != agentGID {
		return errors.New("local executor socket directory owner or group is invalid")
	}
	return nil
}

func removeVerifiedStaleLocalExecutorSocket(socketPath string, ownerUID, agentGID uint32) error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 ||
		info.Mode().Perm() != 0o660 {
		return errors.New("existing local executor socket is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Gid != agentGID {
		return errors.New("existing local executor socket owner or group is invalid")
	}
	connection, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		return errors.New("local executor socket is already active")
	}
	current, err := os.Lstat(socketPath)
	if err != nil || !os.SameFile(info, current) {
		return errors.New("local executor socket changed before cleanup")
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove stale local executor socket: %w", err)
	}
	return nil
}

func secureLocalExecutorSocket(socketPath string, ownerUID, agentGID uint32) (os.FileInfo, error) {
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return nil, errors.New("local executor listener did not create a safe socket")
	}
	if err := os.Chown(socketPath, int(ownerUID), int(agentGID)); err != nil {
		return nil, fmt.Errorf("set local executor socket owner: %w", err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return nil, fmt.Errorf("set local executor socket mode: %w", err)
	}
	return verifyLocalExecutorSocket(socketPath, ownerUID, agentGID)
}

func verifyLocalExecutorSocket(socketPath string, ownerUID, agentGID uint32) (os.FileInfo, error) {
	secured, err := os.Lstat(socketPath)
	if err != nil || secured.Mode()&os.ModeSymlink != 0 || secured.Mode()&os.ModeSocket == 0 ||
		secured.Mode().Perm() != 0o660 {
		return nil, errors.New("local executor socket security verification failed")
	}
	stat, ok := secured.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Gid != agentGID {
		return nil, errors.New("local executor socket security verification failed")
	}
	return secured, nil
}

func removeSameLocalExecutorSocket(socketPath string, expected os.FileInfo) {
	current, err := os.Lstat(socketPath)
	if err == nil && current.Mode()&os.ModeSymlink == 0 && os.SameFile(expected, current) {
		_ = os.Remove(socketPath)
	}
}

func processCgroupTextMatches(contents, expected string) bool {
	if !validLocalExecutorCgroup(expected) {
		return false
	}
	for _, line := range strings.Split(contents, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[2] == expected {
			return true
		}
	}
	return false
}

func readBoundedProcFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(data) == 0 || int64(len(data)) > maximum {
		return nil, errors.New("proc file is unavailable or oversized")
	}
	return data, nil
}

func parsePositivePID(value string) (int, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || pid < 1 {
		return 0, errors.New("runtime has no valid process ID")
	}
	return pid, nil
}
