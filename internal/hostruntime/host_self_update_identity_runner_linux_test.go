//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHostSelfUpdateBinaryIdentityCancellationKillsProcessSession(t *testing.T) {
	fixture := newHostSelfUpdateHangingIdentityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	rt := hostSelfUpdateExecutorRuntime{
		runner:         OSCommandRunner{NewProcessGroup: true},
		allowTestPaths: true,
	}
	request := validHostSelfUpdateRequest()
	started := time.Now()
	err := rt.verifyHostSelfUpdateBinaryIdentity(
		ctx,
		fixture.slotRoot,
		"autostream-host-agent",
		request.AgentVersion,
		request,
	)
	assertHostSelfUpdateIdentityCancellation(
		t,
		err,
		time.Since(started),
		2*time.Second,
		fixture.pidPaths,
	)
}

func TestHealthyLocalExecutorIdentityCancellationKillsProcessSession(t *testing.T) {
	rt, _ := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		testHostSelfUpdateNow(),
	)
	status, err := rt.status()
	if err != nil {
		t.Fatal(err)
	}
	state := status.State
	identityFixture := installHostSelfUpdateHangingIdentityFixture(
		t,
		filepath.Join(rt.slotsRoot, HostSelfUpdateSlotA),
		"autostream-local-executor",
	)
	rt.identityRunner = hostSelfUpdateIdentityCommandRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = rt.verifyHealthyLocalExecutor(ctx, HostSelfUpdateSlotA, state)
	assertHostSelfUpdateIdentityCancellation(
		t,
		err,
		time.Since(started),
		2*time.Second,
		identityFixture.pidPaths,
	)
}

func TestLocalExecutorHostSelfUpdateServerDeadlineKillsIdentitySessionBeforeClientTimeout(
	t *testing.T,
) {
	fixture := newHostSelfUpdateHangingIdentityFixture(t)
	ctx, cancel := localExecutorRequestContext(
		context.Background(),
		"host_self_update_activate",
	)
	defer cancel()
	started := time.Now()
	_, err := (hostSelfUpdateIdentityCommandRunner{}).Run(
		ctx,
		fixture.slotRoot,
		nil,
		fixture.binaryPath,
		"--version",
	)
	elapsed := time.Since(started)
	if elapsed < localExecutorHostSelfUpdateTimeout-time.Second {
		t.Fatalf(
			"server identity context returned after %s, before its outer timeout",
			elapsed,
		)
	}
	assertHostSelfUpdateIdentityCancellation(
		t,
		err,
		elapsed,
		localExecutorClientTimeout,
		fixture.pidPaths,
	)
}

func TestLocalExecutorHostSelfUpdateHandlerReturnsAfterIdentityTimeout(t *testing.T) {
	fixture := newHostSelfUpdateSlotValidationFixture(t)
	status, err := fixture.rt.stage(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	state := status.State
	slotRoot := filepath.Join(fixture.rt.slotsRoot, state.PendingSlot)
	identityFixture := installHostSelfUpdateHangingIdentityFixture(
		t,
		slotRoot,
		"autostream-host-agent",
	)
	digest, err := hashFile(identityFixture.binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	digestMarker := filepath.Join(slotRoot, ".agent-sha256")
	if err := os.Chmod(digestMarker, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(digestMarker, []byte(digest+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(digestMarker, 0o444); err != nil {
		t.Fatal(err)
	}
	state.PendingAgentSHA256 = digest
	if err := fixture.rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	fixture.rt.runner = OSCommandRunner{NewProcessGroup: true}

	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{
		PanelURL: "https://panel.example.com",
	}
	policy.SourcePolicyRevision = 7
	policy.ProjectionRevision = 11
	policy.PolicyRevision = 9
	request := LocalExecutorRequest{
		Version:                  LocalExecutorMutationProtocolVersion,
		Operation:                "host_self_update_activate",
		ServiceID:                policy.HostID,
		HostSelfUpdateGeneration: fixture.request.Generation,
		SourcePolicyRevision:     policy.SourcePolicyRevision,
		OwnershipEpoch:           3,
		OwnershipPolicyRevision:  policy.ProjectionRevision,
		ExecutorPolicyRevision:   policy.PolicyRevision,
	}
	ctx, cancel := localExecutorRequestContext(
		context.Background(),
		request.Operation,
	)
	defer cancel()
	started := time.Now()
	response := handleLocalExecutorHostSelfUpdate(
		ctx,
		policy,
		request,
		fixture.rt,
	)
	elapsed := time.Since(started)
	if response.Error == nil ||
		response.Error.Code != "state_unavailable" {
		t.Fatalf(
			"unexpected identity-timeout response code: %+v",
			response.Error,
		)
	}
	assertHostSelfUpdateIdentityCancellation(
		t,
		errors.New("identity verification rejected"),
		elapsed,
		localExecutorClientTimeout,
		identityFixture.pidPaths,
	)
}

type hostSelfUpdateHangingIdentityFixture struct {
	slotRoot   string
	binaryPath string
	pidPaths   []string
}

func newHostSelfUpdateHangingIdentityFixture(
	t *testing.T,
) hostSelfUpdateHangingIdentityFixture {
	t.Helper()
	slotRoot := t.TempDir()
	binRoot := filepath.Join(slotRoot, "bin")
	if err := os.MkdirAll(binRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	return installHostSelfUpdateHangingIdentityFixture(
		t,
		slotRoot,
		"autostream-host-agent",
	)
}

func installHostSelfUpdateHangingIdentityFixture(
	t *testing.T,
	slotRoot string,
	binaryName string,
) hostSelfUpdateHangingIdentityFixture {
	t.Helper()
	binRoot := filepath.Join(slotRoot, "bin")
	binaryPath := filepath.Join(binRoot, binaryName)
	script := `#!/bin/sh
trap '' TERM
/bin/sh -c 'trap "" TERM; while :; do sleep 1; done' &
identity_dir=${0%/bin/*}
printf '%s\n' "$$" > "$identity_dir/.identity-parent.pid"
printf '%s\n' "$!" > "$identity_dir/.identity-child.pid"
while :; do sleep 1; done
`
	if err := os.WriteFile(binaryPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return hostSelfUpdateHangingIdentityFixture{
		slotRoot:   slotRoot,
		binaryPath: binaryPath,
		pidPaths: []string{
			filepath.Join(slotRoot, ".identity-parent.pid"),
			filepath.Join(slotRoot, ".identity-child.pid"),
		},
	}
}

func assertHostSelfUpdateIdentityCancellation(
	t *testing.T,
	err error,
	elapsed, maxElapsed time.Duration,
	pidPaths []string,
) {
	t.Helper()
	if err == nil {
		t.Fatal("expected timed out binary identity verification")
	}
	if elapsed >= maxElapsed {
		t.Fatalf(
			"binary identity cancellation took %s, want < %s",
			elapsed,
			maxElapsed,
		)
	}

	for _, path := range pidPaths {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf(
				"identity process did not start: verification=%v pid_file=%v",
				err,
				statErr,
			)
		}
		pid := readHostSelfUpdateIdentityTestPID(t, path)
		deadline := time.Now().Add(2 * time.Second)
		for {
			probeErr := syscall.Kill(pid, 0)
			if errors.Is(probeErr, syscall.ESRCH) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("identity process %d from %s survived cancellation", pid, path)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestHostSelfUpdateSlotIdentityBudgetPrecedesClientDeadline(t *testing.T) {
	const fixedSlotBinaries = 2
	processBudget := fixedSlotBinaries *
		(hostSelfUpdateBinaryIdentityTimeout + hostSelfUpdateIdentityWaitDelay)
	if processBudget >= localExecutorClientTimeout {
		t.Fatalf(
			"host self-update identity process budget = %s, client deadline = %s",
			processBudget,
			localExecutorClientTimeout,
		)
	}
	if localExecutorHostSelfUpdateTimeout+
		hostSelfUpdateIdentityWaitDelay >= localExecutorClientTimeout {
		t.Fatalf(
			"host self-update server timeout + process wait = %s, client deadline = %s",
			localExecutorHostSelfUpdateTimeout+hostSelfUpdateIdentityWaitDelay,
			localExecutorClientTimeout,
		)
	}
	if hostSelfUpdateDetachedVerifyTimeout+
		hostSelfUpdateIdentityWaitDelay >= localExecutorHostSelfUpdateTimeout {
		t.Fatalf(
			"detached verification timeout + process wait = %s, server timeout = %s",
			hostSelfUpdateDetachedVerifyTimeout+hostSelfUpdateIdentityWaitDelay,
			localExecutorHostSelfUpdateTimeout,
		)
	}
}

func readHostSelfUpdateIdentityTestPID(t *testing.T, path string) int {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil || pid <= 1 {
		t.Fatalf("invalid identity test PID in %s: %q", path, string(body))
	}
	return pid
}
