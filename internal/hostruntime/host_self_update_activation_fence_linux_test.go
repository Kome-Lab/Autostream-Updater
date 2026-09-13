//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLocalExecutorStopsOldRuntimeWheneverRestartWasRequested(t *testing.T) {
	if localExecutorResponseRequiresRuntimeRestart(LocalExecutorResponse{}) {
		t.Fatal("empty response requested a runtime restart")
	}
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	if !localExecutorResponseRequiresRuntimeRestart(LocalExecutorResponse{
		Version: LocalExecutorMutationProtocolVersion,
		HostSelfUpdate: &HostSelfUpdateRuntimeStatus{
			State:                   state,
			CurrentSlot:             HostSelfUpdateSlotA,
			ExecutorVersion:         "v1.7.8",
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
			RestartRequested:        true,
		},
	}) {
		t.Fatal("old executor would survive a lost activation response")
	}
}

func TestLocalExecutorHostSelfUpdateActivationUsesOnlyRootClock(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	rt.verificationTimeout = 2 * time.Minute
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	status, err := rt.activate(context.Background(), request.Generation)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if !status.State.ActivationStartedAt.Equal(rootNow) ||
		!status.State.ActivationDeadline.Equal(rootNow.Add(2*time.Minute)) ||
		runner.restarts != 1 {
		t.Fatalf("activation did not persist the root clock: status=%#v restarts=%d", status, runner.restarts)
	}
}

func TestLocalExecutorHostSelfUpdateSwitchFailurePersistsRollbackFence(t *testing.T) {
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
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	rt.switchCurrentHook = func(string) error {
		return errors.New("injected atomic switch failure")
	}
	if _, err := rt.activate(
		context.Background(),
		request.Generation,
	); !errors.Is(err, errHostSelfUpdateRollback) {
		t.Fatalf("switch failure err=%v", err)
	}
	rt.switchCurrentHook = nil
	status, err := rt.status()
	if err != nil {
		t.Fatal(err)
	}
	if status.State.Phase != HostSelfUpdatePhaseRollingBack ||
		status.State.FailedGeneration != request.Generation ||
		status.CurrentSlot != HostSelfUpdateSlotA ||
		runner.restarts != 0 {
		t.Fatalf("switch failure was not durably fenced: %#v restarts=%d", status, runner.restarts)
	}
	status, err = rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	)
	if err != nil {
		t.Fatalf("watchdog finish rollback: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		status.State.FailedGeneration != request.Generation ||
		status.CurrentSlot != HostSelfUpdateSlotA ||
		runner.restarts != 1 {
		t.Fatalf("healthy slot did not converge: %#v restarts=%d", status, runner.restarts)
	}
}
