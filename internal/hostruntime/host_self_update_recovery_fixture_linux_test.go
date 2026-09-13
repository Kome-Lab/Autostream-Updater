//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stageHostSelfUpdateStateForLinuxTest(
	t *testing.T,
	rt hostSelfUpdateExecutorRuntime,
	runner *hostSelfUpdateExecutorTestRunner,
	state HostSelfUpdateState,
	request HostSelfUpdateRequest,
) HostSelfUpdateState {
	t.Helper()
	artifactRoot := t.TempDir()
	binRoot := filepath.Join(artifactRoot, "bin")
	if err := os.MkdirAll(binRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		if err := os.WriteFile(
			filepath.Join(binRoot, binary),
			[]byte(binary+" "+request.Generation+"\n"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	digests, err := hostSelfUpdateArtifactBinaryDigests(artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	pendingSlot := otherHostSelfUpdateSlot(state.ActiveSlot)
	temporaryRoot := filepath.Join(
		rt.slotsRoot,
		"."+pendingSlot+"-"+shortID(request.Generation)+".new",
	)
	finalRoot := filepath.Join(rt.slotsRoot, pendingSlot)
	for _, root := range []string{temporaryRoot, finalRoot} {
		runner.registerBinaryIdentity(
			filepath.Join(root, "bin", "autostream-host-agent"),
			hostSelfUpdateExecutorTestBinaryIdentity{
				version:          request.AgentVersion,
				commit:           request.Commit,
				mutationProtocol: request.MutationProtocolVersion,
				recoveryProtocol: request.RecoveryProtocolVersion,
			},
		)
		runner.registerBinaryIdentity(
			filepath.Join(root, "bin", "autostream-local-executor"),
			hostSelfUpdateExecutorTestBinaryIdentity{
				version:          request.ExecutorVersion,
				commit:           request.Commit,
				mutationProtocol: request.MutationProtocolVersion,
				recoveryProtocol: request.RecoveryProtocolVersion,
			},
		)
	}
	if err := rt.stageSlot(
		context.Background(),
		pendingSlot,
		artifactRoot,
		request,
		digests,
	); err != nil {
		t.Fatalf("stage production-shaped host self-update slot: %v", err)
	}
	next, err := StageHostSelfUpdate(
		state,
		request,
		HostLifecycleBlockers{},
		digests,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(next); err != nil {
		t.Fatalf("persist staged production-shaped host self-update state: %v", err)
	}
	if err := rt.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		t.Fatalf("finalize staged production-shaped host self-update slot: %v", err)
	}
	return next
}

func newHostSelfUpdateRecoveryFixture(
	t *testing.T,
	currentSlot string,
	executorVersion string,
	now time.Time,
) (hostSelfUpdateExecutorRuntime, *hostSelfUpdateExecutorTestRunner) {
	t.Helper()
	root := t.TempDir()
	installRoot := filepath.Join(root, "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if err := os.MkdirAll(filepath.Join(slotsRoot, slot, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"autostream-host-agent",
			"autostream-local-executor",
		} {
			if err := os.WriteFile(
				filepath.Join(slotsRoot, slot, "bin", name),
				[]byte("test "+name+"\n"),
				0o755,
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(
		filepath.Join("slots", currentSlot),
		currentLink,
	); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	runner := &hostSelfUpdateExecutorTestRunner{
		version:          executorVersion,
		commit:           strings.Repeat("a", 40),
		serviceActive:    true,
		socketActive:     true,
		mainPID:          "4242",
		mutationProtocol: LocalExecutorMutationProtocolVersion,
		recoveryProtocol: HostSelfUpdateRecoveryProtocolVersion,
	}
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		runner.registerBinaryIdentity(
			filepath.Join(
				slotsRoot,
				slot,
				"bin",
				"autostream-local-executor",
			),
			hostSelfUpdateExecutorTestBinaryIdentity{
				version:          executorVersion,
				commit:           strings.Repeat("a", 40),
				mutationProtocol: LocalExecutorMutationProtocolVersion,
				recoveryProtocol: HostSelfUpdateRecoveryProtocolVersion,
			},
		)
	}
	rt := hostSelfUpdateExecutorRuntime{
		installRoot:         installRoot,
		currentLink:         currentLink,
		slotsRoot:           slotsRoot,
		stateRoot:           stateRoot,
		statePath:           filepath.Join(stateRoot, "state.json"),
		downloadRoot:        filepath.Join(stateRoot, "downloads"),
		arch:                "amd64",
		executorVersion:     executorVersion,
		runner:              runner,
		downloader:          hostSelfUpdateExecutorTestDownloader{},
		now:                 func() time.Time { return now },
		verificationTimeout: defaultHostSelfUpdateVerificationTimeout,
		allowTestPaths:      true,
		waitExecutorStable:  func(context.Context) error { return nil },
	}
	runner.runningExe = filepath.Join(
		slotsRoot,
		currentSlot,
		"bin",
		"autostream-local-executor",
	)
	rt.resolveProcessExe = func(int) (string, error) {
		if runner.runningExe == "" {
			return "", errors.New("injected missing process executable")
		}
		return runner.runningExe, nil
	}
	rt.watchdogStatus = func(
		context.Context,
	) (HostSelfUpdateRuntimeStatus, error) {
		state, err := rt.loadPersistedState()
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		current, err := rt.readCurrentSlot()
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		return HostSelfUpdateRuntimeStatus{
			State:                   state,
			CurrentSlot:             current,
			ExecutorVersion:         rt.executorVersion,
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
			LastAction:              HostSelfUpdateActionNone,
		}, nil
	}
	if err := rt.prepare(); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}
