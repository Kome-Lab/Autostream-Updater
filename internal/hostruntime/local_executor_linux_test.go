//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLocalExecutorLinuxPeerCredentialAndExactUID(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("dedicated non-root Agent UID is required")
	}
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "executor.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan *net.UnixConn, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	credential, err := localExecutorPeerCredential(server)
	if err != nil {
		t.Fatalf("localExecutorPeerCredential: %v", err)
	}
	if int(credential.UID) != os.Getuid() || int(credential.GID) != os.Getgid() {
		t.Fatalf("credential=%+v uid=%d gid=%d", credential, os.Getuid(), os.Getgid())
	}
	if err := validateLocalExecutorPeer(credential, uint32(os.Getuid())); err != nil {
		t.Fatalf("own UID rejected: %v", err)
	}
	if err := validateLocalExecutorPeer(credential, credential.UID+1); err == nil {
		t.Fatal("different service UID was accepted")
	}
}

func TestLocalExecutorLinuxWatchdogStatusPeerIsStrictlyRootOnly(t *testing.T) {
	const agentUID = uint32(1000)
	for name, test := range map[string]struct {
		peer      localExecutorPeer
		operation string
		wantError bool
	}{
		"root watchdog": {
			peer:      localExecutorPeer{PID: 10, UID: 0},
			operation: "host_self_update_watchdog_status",
		},
		"agent watchdog": {
			peer:      localExecutorPeer{PID: 11, UID: agentUID},
			operation: "host_self_update_watchdog_status",
			wantError: true,
		},
		"root mutation": {
			peer:      localExecutorPeer{PID: 12, UID: 0},
			operation: "host_self_update_status",
			wantError: true,
		},
		"agent mutation": {
			peer:      localExecutorPeer{PID: 13, UID: agentUID},
			operation: "host_self_update_status",
		},
		"foreign probe": {
			peer:      localExecutorPeer{PID: 14, UID: agentUID + 1},
			operation: "probe",
			wantError: true,
		},
		"missing pid": {
			peer:      localExecutorPeer{UID: 0},
			operation: "host_self_update_watchdog_status",
			wantError: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateLocalExecutorPeerForOperation(
				test.peer,
				agentUID,
				test.operation,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("err=%v wantError=%v", err, test.wantError)
			}
		})
	}
}

func TestLocalExecutorLinuxWatchdogStatusReadsWithoutMutation(t *testing.T) {
	root := t.TempDir()
	installRoot := filepath.Join(root, "opt", "autostream", "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	slotRoot := filepath.Join(slotsRoot, HostSelfUpdateSlotA)
	stateRoot := filepath.Join(root, "var", "lib", "host-self-update")
	statePath := filepath.Join(stateRoot, "state.json")
	grantPath := filepath.Join(stateRoot, "grant.json")
	reservedPath := filepath.Join(slotsRoot, ".B-interrupted.old")
	if err := os.MkdirAll(slotRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(slotRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(slotRoot, currentLink); err != nil {
		t.Fatal(err)
	}
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	statePayload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, statePayload, 0o600); err != nil {
		t.Fatal(err)
	}
	grantPayload := []byte(`{"sentinel":"must-not-be-recovered"}`)
	if err := os.WriteFile(grantPath, grantPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	reservedPayload := []byte("must-not-be-reaped")
	if err := os.WriteFile(reservedPath, reservedPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	beforeState, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	rt := hostSelfUpdateExecutorRuntime{
		installRoot:     installRoot,
		currentLink:     currentLink,
		slotsRoot:       slotsRoot,
		stateRoot:       stateRoot,
		statePath:       statePath,
		grantStatePath:  grantPath,
		downloadRoot:    filepath.Join(stateRoot, "downloads"),
		executorVersion: "v1.7.8",
		allowTestPaths:  true,
	}
	response := handleLocalExecutorWatchdogStatus(
		LocalExecutorRequest{
			Version:   LocalExecutorMutationProtocolVersion,
			Operation: "host_self_update_watchdog_status",
			ServiceID: "host-self-update-watchdog",
		},
		rt,
	)
	if response.Error != nil || response.HostSelfUpdate == nil {
		t.Fatalf("response=%#v", response)
	}
	if response.HostSelfUpdate.State != state ||
		response.HostSelfUpdate.CurrentSlot != HostSelfUpdateSlotA ||
		response.HostSelfUpdate.ExecutorVersion != "v1.7.8" {
		t.Fatalf("status=%#v", response.HostSelfUpdate)
	}
	afterState, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	afterStatePayload, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	afterGrantPayload, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	afterReservedPayload, err := os.ReadFile(reservedPath)
	if err != nil {
		t.Fatal(err)
	}
	currentTarget, err := os.Readlink(currentLink)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterStatePayload) != string(statePayload) ||
		!afterState.ModTime().Equal(beforeState.ModTime()) ||
		string(afterGrantPayload) != string(grantPayload) ||
		string(afterReservedPayload) != string(reservedPayload) ||
		currentTarget != slotRoot {
		t.Fatal("watchdog status mutated durable host self-update state")
	}

	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	response = handleLocalExecutorWatchdogStatus(
		LocalExecutorRequest{
			Version:   LocalExecutorMutationProtocolVersion,
			Operation: "host_self_update_watchdog_status",
			ServiceID: "host-self-update-watchdog",
		},
		rt,
	)
	if response.Error == nil || response.Error.Code != "state_unavailable" {
		t.Fatalf("missing-state response=%#v", response)
	}
	if _, err := os.Lstat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("watchdog status initialized missing state: %v", err)
	}
}

func TestLocalExecutorLinuxWatchdogStatusClientUsesFixedWireAndDeadline(t *testing.T) {
	if localExecutorHostSelfUpdateWatchdogClientTimeout != 2*time.Second {
		t.Fatalf(
			"watchdog status timeout=%v",
			localExecutorHostSelfUpdateWatchdogClientTimeout,
		)
	}
	t.Run("fixed wire", func(t *testing.T) {
		socketPath := filepath.Join(t.TempDir(), "executor.sock")
		listener, err := net.ListenUnix(
			"unix",
			&net.UnixAddr{Name: socketPath, Net: "unix"},
		)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		requests := make(chan LocalExecutorRequest, 1)
		serverDone := make(chan error, 1)
		go func() {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				serverDone <- acceptErr
				return
			}
			defer connection.Close()
			request, decodeErr := DecodeLocalExecutorRequest(connection)
			if decodeErr != nil {
				serverDone <- decodeErr
				return
			}
			requests <- request
			state, stateErr := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
			if stateErr != nil {
				serverDone <- stateErr
				return
			}
			status := HostSelfUpdateRuntimeStatus{
				State:                   state,
				CurrentSlot:             HostSelfUpdateSlotA,
				ExecutorVersion:         "v1.7.8",
				ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
				LastAction:              HostSelfUpdateActionNone,
			}
			serverDone <- EncodeLocalExecutorResponse(
				connection,
				LocalExecutorResponse{
					Version:        LocalExecutorMutationProtocolVersion,
					HostSelfUpdate: &status,
				},
			)
		}()

		status, err := (LocalExecutorClient{
			SocketPath: socketPath,
			Timeout:    30 * time.Minute,
		}).HostSelfUpdateWatchdogStatus(context.Background())
		if err != nil {
			t.Fatalf("HostSelfUpdateWatchdogStatus: %v", err)
		}
		if status.CurrentSlot != HostSelfUpdateSlotA {
			t.Fatalf("status=%#v", status)
		}
		request := <-requests
		if request != (LocalExecutorRequest{
			Version:   LocalExecutorMutationProtocolVersion,
			Operation: "host_self_update_watchdog_status",
			ServiceID: "host-self-update-watchdog",
		}) {
			t.Fatalf("request=%#v", request)
		}
		if err := <-serverDone; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("two second deadline", func(t *testing.T) {
		socketPath := filepath.Join(t.TempDir(), "executor.sock")
		listener, err := net.ListenUnix(
			"unix",
			&net.UnixAddr{Name: socketPath, Net: "unix"},
		)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		requestReceived := make(chan error, 1)
		release := make(chan struct{})
		go func() {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				requestReceived <- acceptErr
				return
			}
			defer connection.Close()
			_, decodeErr := DecodeLocalExecutorRequest(connection)
			requestReceived <- decodeErr
			<-release
		}()
		start := time.Now()
		_, err = (LocalExecutorClient{
			SocketPath: socketPath,
			Timeout:    30 * time.Minute,
		}).HostSelfUpdateWatchdogStatus(context.Background())
		elapsed := time.Since(start)
		close(release)
		if err == nil {
			t.Fatal("stalled watchdog status response was accepted")
		}
		if requestErr := <-requestReceived; requestErr != nil {
			t.Fatal(requestErr)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("watchdog status exceeded fixed deadline: %v", elapsed)
		}
	})
}

func TestLocalExecutorLinuxSocketPathRejectsSymlinkAndUnsafeMode(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := validateLocalExecutorSocketDirectory(linkDir, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("symlink socket directory was accepted")
	}
	if err := os.Chmod(realDir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := validateLocalExecutorSocketDirectory(realDir, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("group-writable socket directory was accepted")
	}
	socketTarget := filepath.Join(realDir, "target")
	if err := os.WriteFile(socketTarget, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	socketLink := filepath.Join(realDir, "executor.sock")
	if err := os.Symlink(socketTarget, socketLink); err != nil {
		t.Fatal(err)
	}
	if err := removeVerifiedStaleLocalExecutorSocket(socketLink, uint32(os.Getuid()), uint32(os.Getgid())); err == nil {
		t.Fatal("symlink socket path was accepted")
	}
}

func TestLocalExecutorLinuxOneRequestPerConnection(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("dedicated non-root Agent UID is required")
	}
	policy := validLocalExecutorPolicy(t)
	policy.AgentUID = uint32(os.Getuid())
	policy.AgentGID = uint32(os.Getgid())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(dir, "executor.sock")

	target := policy.Targets[0]
	httpServer := newLocalExecutorProbeServer(t, target, "v1.2.3", target.ConfigRevision)
	defer httpServer.Close()
	policy.Targets[0].LocalListen = endpointFromServer(t, httpServer)
	verifier := &fakeLocalTargetVerifier{observations: []LocalProcessObservation{
		validLocalProcessObservation(target, "v1.2.3"),
		validLocalProcessObservation(target, "v1.2.3"),
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan error, 1)
	go func() {
		ready <- serveLocalExecutorForTest(ctx, policy, verifier, httpServer.Client(), uint32(os.Getuid()), socketPath)
	}()
	waitForLocalExecutorSocket(t, socketPath)
	socketInfo, err := os.Lstat(socketPath)
	if err != nil || socketInfo.Mode().Perm() != 0o660 || socketInfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket info=%v err=%v", socketInfo, err)
	}
	stat, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
		t.Fatalf("socket owner=%+v uid=%d gid=%d", stat, os.Getuid(), os.Getgid())
	}

	valid := `{"version":1,"operation":"probe","service_id":"worker-01"}`
	for name, request := range map[string]string{
		"second request": valid + "\n" + valid + "\n",
		"unknown field":  `{"version":1,"operation":"probe","service_id":"worker-01","url":"http://attacker"}` + "\n",
		"oversize":       `{"version":1,"operation":"probe","service_id":"` + strings.Repeat("a", LocalExecutorProtocolMaxFrameBytes) + `"}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte(request)); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, _ := io.ReadAll(conn)
			_ = conn.Close()
			if !strings.Contains(string(response), `"code":"invalid_request"`) {
				t.Fatalf("response=%s", response)
			}
		})
	}

	cancel()
	select {
	case err := <-ready:
		if err != nil && err != context.Canceled {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestLocalExecutorLinuxClientUsesFixedProbeWire(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("dedicated non-root Agent UID is required")
	}
	policy := validLocalExecutorPolicy(t)
	policy.AgentUID = uint32(os.Getuid())
	policy.AgentGID = uint32(os.Getgid())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(dir, "executor.sock")
	target := policy.Targets[0]
	httpServer := newLocalExecutorProbeServer(t, target, "v1.2.3", target.ConfigRevision)
	defer httpServer.Close()
	policy.Targets[0].LocalListen = endpointFromServer(t, httpServer)
	verifier := &fakeLocalTargetVerifier{observations: []LocalProcessObservation{
		validLocalProcessObservation(target, "v1.2.3"),
		validLocalProcessObservation(target, "v1.2.3"),
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveLocalExecutorForTest(ctx, policy, verifier, httpServer.Client(), uint32(os.Getuid()), socketPath)
	}()
	waitForLocalExecutorSocket(t, socketPath)

	client := LocalExecutorClient{SocketPath: socketPath}
	probe, err := client.Probe(context.Background(), target.ServiceID)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if probe.ServiceID != target.ServiceID || probe.ConfigRevision != target.ConfigRevision {
		t.Fatalf("probe=%+v", probe)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestLocalExecutorLinuxCgroupComparisonRejectsWrongGroup(t *testing.T) {
	const expected = "/system.slice/autostream-worker.service"
	if !processCgroupTextMatches("0::"+expected+"\n", expected) {
		t.Fatal("matching cgroup was rejected")
	}
	if processCgroupTextMatches("0::/system.slice/attacker.service\n", expected) {
		t.Fatal("wrong cgroup was accepted")
	}
}

func TestLocalExecutorLinuxRejectsCoexistingForeignListenerInode(t *testing.T) {
	inodes := map[string]struct{}{"1001": {}, "1002": {}}
	owners := map[string][]int{"1001": {101}, "1002": {202}}
	matches := func(pid int, _ string) error {
		if pid == 101 {
			return nil
		}
		return errors.New("wrong cgroup")
	}
	if _, err := validateLocalExecutorSocketOwners(
		inodes,
		owners,
		"/system.slice/autostream-worker.service",
		matches,
	); err == nil {
		t.Fatal("coexisting foreign listener inode was accepted")
	}
	delete(inodes, "1002")
	if pid, err := validateLocalExecutorSocketOwners(
		inodes,
		owners,
		"/system.slice/autostream-worker.service",
		matches,
	); err != nil || pid != 101 {
		t.Fatalf("pid=%d err=%v", pid, err)
	}
}

func TestLocalExecutorLinuxRequestHangDoesNotBlockAcceptLoop(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("dedicated non-root Agent UID is required")
	}
	policy := validLocalExecutorPolicy(t)
	policy.AgentUID = uint32(os.Getuid())
	policy.AgentGID = uint32(os.Getgid())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(dir, "executor.sock")
	target := policy.Targets[0]
	httpServer := newLocalExecutorProbeServer(t, target, "v1.2.3", target.ConfigRevision)
	defer httpServer.Close()
	policy.Targets[0].LocalListen = endpointFromServer(t, httpServer)
	blocking := &blockingFirstLocalTargetVerifier{
		started: make(chan struct{}),
		target:  policy.Targets[0],
	}

	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveLocalExecutorForTest(ctx, policy, blocking, httpServer.Client(), uint32(os.Getuid()), socketPath)
	}()
	waitForLocalExecutorSocket(t, socketPath)

	firstDone := make(chan error, 1)
	go func() {
		_, err := (LocalExecutorClient{SocketPath: socketPath}).Probe(context.Background(), target.ServiceID)
		firstDone <- err
	}()
	select {
	case <-blocking.started:
	case <-time.After(3 * time.Second):
		t.Fatal("first verifier did not block")
	}

	secondContext, secondCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer secondCancel()
	if _, err := (LocalExecutorClient{SocketPath: socketPath}).Probe(secondContext, target.ServiceID); err != nil {
		t.Fatalf("second request was blocked by the first: %v", err)
	}

	cancel()
	select {
	case <-firstDone:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked request did not honor server cancellation")
	}
	select {
	case err := <-serverDone:
		if err != nil && err != context.Canceled {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestLocalExecutorLinuxSecuresDirectoryAfterRestrictiveUmask(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "socket")
	previous := syscall.Umask(0o077)
	err := os.Mkdir(directory, 0o750)
	syscall.Umask(previous)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0o700 {
		t.Fatalf("before mode=%v", before.Mode().Perm())
	}
	if err := secureLocalExecutorSocketDirectory(directory, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
		t.Fatalf("secureLocalExecutorSocketDirectory: %v", err)
	}
	after, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0o750 {
		t.Fatalf("after mode=%v", after.Mode().Perm())
	}
}

func TestLocalExecutorLinuxSystemdSocketActivationIsStrict(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "executor.sock")
	source, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"LISTEN_PID":     strconv.Itoa(os.Getpid()),
		"LISTEN_FDS":     "1",
		"LISTEN_FDNAMES": "autostream-local-executor",
	}
	activated, inherited, err := localExecutorActivatedListener(
		socketPath,
		func(key string) string { return env[key] },
		os.Getpid(),
		func(fd uintptr) *os.File {
			if fd != 3 {
				t.Fatalf("fd=%d", fd)
			}
			file, fileErr := source.File()
			if fileErr != nil {
				t.Fatal(fileErr)
			}
			return file
		},
	)
	if err != nil || !inherited || activated == nil {
		t.Fatalf("activated=%v inherited=%v err=%v", activated, inherited, err)
	}
	_ = activated.Close()

	for name, mutate := range map[string]func(map[string]string){
		"wrong pid":  func(env map[string]string) { env["LISTEN_PID"] = strconv.Itoa(os.Getpid() + 1) },
		"two fds":    func(env map[string]string) { env["LISTEN_FDS"] = "2" },
		"wrong name": func(env map[string]string) { env["LISTEN_FDNAMES"] = "attacker" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := map[string]string{}
			for key, value := range env {
				candidate[key] = value
			}
			mutate(candidate)
			if _, inherited, err := localExecutorActivatedListener(
				socketPath,
				func(key string) string { return candidate[key] },
				os.Getpid(),
				func(uintptr) *os.File { t.Fatal("invalid metadata opened fd"); return nil },
			); err == nil || inherited {
				t.Fatalf("inherited=%v err=%v", inherited, err)
			}
		})
	}
}

type blockingFirstLocalTargetVerifier struct {
	started chan struct{}
	target  LocalExecutorTarget
	calls   int
}

func (v *blockingFirstLocalTargetVerifier) Observe(ctx context.Context, _ LocalExecutorPolicy, _ LocalExecutorTarget) (LocalProcessObservation, error) {
	v.calls++
	if v.calls == 1 {
		close(v.started)
		<-ctx.Done()
		return LocalProcessObservation{}, ctx.Err()
	}
	return validLocalProcessObservation(v.target, "v1.2.3"), nil
}

func waitForLocalExecutorSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Lstat(socketPath); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("socket was not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
