//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthySlotWatchdogRollsBackWhenCandidateNeverContactsPanel(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }

	wrongSlot, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotB,
	)
	if err != nil {
		t.Fatalf("candidate watchdog no-op: %v", err)
	}
	if wrongSlot.State.Phase != HostSelfUpdatePhaseActivating ||
		wrongSlot.CurrentSlot != HostSelfUpdateSlotA ||
		runner.restarts != 0 {
		t.Fatalf("candidate slot was allowed to own recovery: %#v restarts=%d", wrongSlot, runner.restarts)
	}
	if current, err := rt.readCurrentSlot(); err != nil ||
		current != HostSelfUpdateSlotB {
		t.Fatalf(
			"candidate watchdog mutated current: slot=%q err=%v",
			current,
			err,
		)
	}

	status, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	)
	if err != nil {
		t.Fatalf("healthy watchdog rollback: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		status.State.FailedGeneration != request.Generation ||
		status.CurrentSlot != HostSelfUpdateSlotA ||
		status.State.ActiveAgentVersion != "v1.7.8" ||
		runner.restarts != 1 ||
		runner.executorRestarts != 1 ||
		len(runner.restartOrder) != 2 ||
		runner.restartOrder[0] != hostSelfUpdateExecutorServiceUnit ||
		runner.restartOrder[1] != hostSelfUpdateServiceUnit {
		t.Fatalf(
			"panel-less candidate crash was not rolled back: status=%#v agent_restarts=%d executor_restarts=%d order=%v",
			status,
			runner.restarts,
			runner.executorRestarts,
			runner.restartOrder,
		)
	}
}

func TestNonHealthySlotWatchdogDoesNotRecoverSharedSlotArtifacts(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(
		rt.slotsRoot,
		"."+HostSelfUpdateSlotB+"-111111111111.new",
	)
	if err := os.MkdirAll(artifact, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(artifact, "must-remain")
	if err := os.WriteFile(sentinel, []byte("pending timer no-op\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(rt.statePath)
	if err != nil {
		t.Fatal(err)
	}
	currentBefore, err := os.Readlink(rt.currentLink)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotB,
	); err != nil {
		t.Fatalf("non-healthy watchdog no-op: %v", err)
	}
	if body, err := os.ReadFile(sentinel); err != nil ||
		string(body) != "pending timer no-op\n" {
		t.Fatalf(
			"non-healthy watchdog recovered shared artifact: body=%q err=%v",
			body,
			err,
		)
	}
	stateAfter, err := os.ReadFile(rt.statePath)
	if err != nil || string(stateAfter) != string(stateBefore) {
		t.Fatalf("non-healthy watchdog mutated state: err=%v", err)
	}
	currentAfter, err := os.Readlink(rt.currentLink)
	if err != nil || currentAfter != currentBefore {
		t.Fatalf(
			"non-healthy watchdog mutated current: before=%q after=%q err=%v",
			currentBefore,
			currentAfter,
			err,
		)
	}
}

func TestHealthySlotWatchdogLeavesRollbackFenceWhenExecutorRestartFails(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }
	runner.failExecutor = true

	if _, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	); !errors.Is(err, errHostSelfUpdateRollback) {
		t.Fatalf("executor restart failure err=%v", err)
	}
	persisted, err := rt.loadPersistedState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Phase != HostSelfUpdatePhaseRollingBack ||
		persisted.FailedGeneration != request.Generation ||
		runner.executorRestarts != 1 ||
		runner.restarts != 0 {
		t.Fatalf(
			"rollback fence was cleared after executor restart failure: state=%#v agent_restarts=%d executor_restarts=%d",
			persisted,
			runner.restarts,
			runner.executorRestarts,
		)
	}
	if current, err := rt.readCurrentSlot(); err != nil ||
		current != HostSelfUpdateSlotA {
		t.Fatalf("healthy current was not restored: slot=%q err=%v", current, err)
	}

	runner.failExecutor = false
	status, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	)
	if err != nil {
		t.Fatalf("resume rollback: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		runner.executorRestarts != 2 ||
		runner.restarts != 1 {
		t.Fatalf(
			"resumed rollback did not converge: status=%#v agent_restarts=%d executor_restarts=%d",
			status,
			runner.restarts,
			runner.executorRestarts,
		)
	}
}

func TestHealthySlotWatchdogLeavesRollbackFenceWhenSocketHandshakeFails(
	t *testing.T,
) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }
	rt.watchdogStatus = func(
		context.Context,
	) (HostSelfUpdateRuntimeStatus, error) {
		return HostSelfUpdateRuntimeStatus{}, context.DeadlineExceeded
	}

	if _, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	); !errors.Is(err, errHostSelfUpdateRollback) {
		t.Fatalf("socket handshake failure err=%v", err)
	}
	persisted, err := rt.loadPersistedState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Phase != HostSelfUpdatePhaseRollingBack ||
		persisted.FailedGeneration != request.Generation ||
		runner.executorRestarts != 1 ||
		runner.restarts != 0 {
		t.Fatalf(
			"socket handshake failure cleared rollback fence: state=%#v agent_restarts=%d executor_restarts=%d",
			persisted,
			runner.restarts,
			runner.executorRestarts,
		)
	}
	if current, err := rt.readCurrentSlot(); err != nil ||
		current != HostSelfUpdateSlotA {
		t.Fatalf(
			"healthy current was not retained after handshake failure: slot=%q err=%v",
			current,
			err,
		)
	}
}
