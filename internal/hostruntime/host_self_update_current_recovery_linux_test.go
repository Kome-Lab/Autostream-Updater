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

func TestHealthySlotWatchdogReconstructsCurrentFromDurableState(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	for _, healthySlot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		healthySlot := healthySlot
		t.Run("healthy_"+healthySlot, func(t *testing.T) {
			for _, currentState := range []struct {
				name  string
				setup func(*testing.T, hostSelfUpdateExecutorRuntime, string)
			}{
				{
					name: "missing",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, _ string) {
						t.Helper()
						if err := os.Remove(rt.currentLink); err != nil {
							t.Fatal(err)
						}
					},
				},
				{
					name: "regular_file",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, _ string) {
						t.Helper()
						if err := os.Remove(rt.currentLink); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(rt.currentLink, []byte("not a slot\n"), 0o644); err != nil {
							t.Fatal(err)
						}
					},
				},
				{
					name: "malformed_symlink",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, _ string) {
						t.Helper()
						if err := os.Remove(rt.currentLink); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink("../../outside", rt.currentLink); err != nil {
							t.Fatal(err)
						}
					},
				},
				{
					name: "dangling_symlink",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, _ string) {
						t.Helper()
						if err := os.Remove(rt.currentLink); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(filepath.Join("slots", "missing"), rt.currentLink); err != nil {
							t.Fatal(err)
						}
					},
				},
				{
					name: "power_loss_immediately_after_switch",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, pendingSlot string) {
						t.Helper()
						if err := rt.switchCurrent(pendingSlot); err != nil {
							t.Fatal(err)
						}
					},
				},
			} {
				currentState := currentState
				t.Run(currentState.name, func(t *testing.T) {
					rt, runner := newHostSelfUpdateRecoveryFixture(
						t,
						healthySlot,
						"v1.7.8",
						rootNow,
					)
					state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
					if err != nil {
						t.Fatal(err)
					}
					state.ActiveSlot = healthySlot
					state.HealthySlot = healthySlot
					request := validHostSelfUpdateRequest()
					state = stageHostSelfUpdateStateForLinuxTest(
						t, rt, runner, state, request,
					)
					state, err = BeginHostSelfUpdateActivation(
						state,
						rootNow,
						time.Minute,
					)
					if err != nil {
						t.Fatal(err)
					}
					if err := rt.saveState(state); err != nil {
						t.Fatal(err)
					}
					currentState.setup(t, rt, state.PendingSlot)
					rt.now = func() time.Time {
						return rootNow.Add(2 * time.Minute)
					}

					status, err := rt.recoverExpiredHostSelfUpdate(
						context.Background(),
						healthySlot,
					)
					if err != nil {
						t.Fatalf("recover fixed healthy slot: %v", err)
					}
					if status.State.Phase != HostSelfUpdatePhaseStable ||
						status.State.ActiveSlot != healthySlot ||
						status.State.HealthySlot != healthySlot ||
						status.State.FailedGeneration != request.Generation ||
						status.CurrentSlot != healthySlot ||
						runner.restarts != 1 {
						t.Fatalf(
							"fixed recovery did not converge: status=%#v restarts=%d",
							status,
							runner.restarts,
						)
					}
					currentSlot, err := rt.readCurrentSlot()
					if err != nil || currentSlot != healthySlot {
						t.Fatalf(
							"current was not reconstructed: slot=%q err=%v",
							currentSlot,
							err,
						)
					}
				})
			}
		})
	}
}

func TestHealthySlotWatchdogRejectsArbitraryRecoveryPaths(t *testing.T) {
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
	if err := os.Remove(rt.currentLink); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }
	if _, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		filepath.Join("..", HostSelfUpdateSlotA),
	); err == nil || !strings.Contains(err.Error(), "slot is invalid") {
		t.Fatalf("arbitrary recovery path err=%v", err)
	}
	if _, err := os.Lstat(rt.currentLink); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected recovery path mutated current: %v", err)
	}
	if runner.restarts != 0 {
		t.Fatalf("rejected recovery path restarted agent %d times", runner.restarts)
	}
}

func TestExpiredActivationAtHealthySlotCannotLoopSwitchCurrent(t *testing.T) {
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
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }
	status, err := rt.reconcile(
		context.Background(),
		HostSelfUpdateAgentProof{RunningAgentVersion: "v1.7.8"},
	)
	if err != nil {
		t.Fatalf("expired healthy activation: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseRollingBack ||
		status.State.FailedGeneration != request.Generation ||
		status.LastAction != HostSelfUpdateActionRestartHealthy ||
		status.CurrentSlot != HostSelfUpdateSlotA ||
		runner.restarts != 1 {
		t.Fatalf("expired activation retried candidate switch: %#v restarts=%d", status, runner.restarts)
	}
}
