//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyHealthyLocalExecutorWaitsForTransientSystemdExecutor(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		now,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(
		rt.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	var resolvedPIDs []int
	rt.resolveProcessExe = func(pid int) (string, error) {
		resolvedPIDs = append(resolvedPIDs, pid)
		if len(resolvedPIDs) == 1 {
			return "/usr/lib/systemd/systemd-executor", nil
		}
		return expected, nil
	}
	waits := 0
	rt.waitExecutorStable = func(context.Context) error {
		waits++
		return nil
	}

	if err := rt.verifyHealthyLocalExecutor(
		context.Background(),
		HostSelfUpdateSlotA,
		state,
	); err != nil {
		t.Fatalf("verifyHealthyLocalExecutor: %v", err)
	}
	if len(resolvedPIDs) != 3 || waits != 2 || runner.mainPIDChecks != 3 {
		t.Fatalf(
			"transient verification probes=%v waits=%d MainPID_reads=%d",
			resolvedPIDs,
			waits,
			runner.mainPIDChecks,
		)
	}
	for _, pid := range resolvedPIDs {
		if pid != 4242 {
			t.Fatalf("resolved PIDs=%v, want one stable MainPID", resolvedPIDs)
		}
	}
}

func TestAcquireHealthyLocalExecutorRejectsUnsafeOrPersistentHelper(
	t *testing.T,
) {
	for _, test := range []struct {
		name         string
		running      string
		wantError    string
		wantResolves int
		wantWaits    int
	}{
		{
			name:         "untrusted_same_basename",
			running:      "/tmp/systemd-executor",
			wantError:    "not running the healthy slot binary",
			wantResolves: 1,
			wantWaits:    0,
		},
		{
			name:         "persistent_allowlisted_helper",
			running:      "/usr/lib/systemd/systemd-executor",
			wantError:    "startup probe limit",
			wantResolves: hostSelfUpdateSystemdExecutorProbes,
			wantWaits:    hostSelfUpdateSystemdExecutorProbes - 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt, runner := newHostSelfUpdateRecoveryFixture(
				t,
				HostSelfUpdateSlotA,
				"v1.7.8",
				time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC),
			)
			expected := filepath.Join(
				rt.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				"autostream-local-executor",
			)
			resolves := 0
			waits := 0
			rt.resolveProcessExe = func(int) (string, error) {
				resolves++
				return test.running, nil
			}
			rt.waitExecutorStable = func(context.Context) error {
				waits++
				return nil
			}

			_, err := rt.acquireHealthyLocalExecutorPID(
				context.Background(),
				expected,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("helper verification err=%v", err)
			}
			if resolves != test.wantResolves || waits != test.wantWaits ||
				runner.mainPIDChecks != test.wantResolves {
				t.Fatalf(
					"helper verification resolves=%d waits=%d MainPID_reads=%d",
					resolves,
					waits,
					runner.mainPIDChecks,
				)
			}
		})
	}
}

func TestAcquireHealthyLocalExecutorHonorsCanceledTransitionWait(
	t *testing.T,
) {
	rt, _ := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC),
	)
	expected := filepath.Join(
		rt.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	rt.resolveProcessExe = func(int) (string, error) {
		return "/usr/lib/systemd/systemd-executor", nil
	}
	rt.waitExecutorStable = func(context.Context) error {
		waits++
		cancel()
		return ctx.Err()
	}

	_, err := rt.acquireHealthyLocalExecutorPID(ctx, expected)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transition err=%v", err)
	}
	if waits != 1 {
		t.Fatalf("canceled transition waits=%d", waits)
	}
}

func TestAcquireHealthyLocalExecutorRejectsPIDChurnDuringTransition(
	t *testing.T,
) {
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC),
	)
	expected := filepath.Join(
		rt.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	runner.secondMainPID = "4343"
	resolves := 0
	rt.resolveProcessExe = func(int) (string, error) {
		resolves++
		if resolves == 1 {
			return "/usr/lib/systemd/systemd-executor", nil
		}
		return expected, nil
	}

	_, err := rt.acquireHealthyLocalExecutorPID(
		context.Background(),
		expected,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"MainPID changed during systemd-executor transition",
	) {
		t.Fatalf("PID churn err=%v", err)
	}
	if resolves != 2 || runner.mainPIDChecks != 2 {
		t.Fatalf(
			"PID churn resolves=%d MainPID_reads=%d",
			resolves,
			runner.mainPIDChecks,
		)
	}
}

func TestHealthySlotWatchdogRequiresRunningHealthyExecutorIdentity(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	for name, mutate := range map[string]func(
		hostSelfUpdateExecutorRuntime,
		*hostSelfUpdateExecutorTestRunner,
	){
		"start_then_crash": func(
			_ hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.failServiceAfter = 1
		},
		"main_pid_changes_during_probe": func(
			_ hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.secondMainPID = "4343"
		},
		"wrong_main_executable": func(
			rt hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.runningExe = filepath.Join(
				rt.slotsRoot,
				HostSelfUpdateSlotB,
				"bin",
				"autostream-local-executor",
			)
		},
		"wrong_mutation_protocol": func(
			rt hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			path := filepath.Clean(filepath.Join(
				rt.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				"autostream-local-executor",
			))
			identity := runner.binaryIdentities[path]
			identity.mutationProtocol =
				LocalExecutorMutationProtocolVersion - 1
			runner.binaryIdentities[path] = identity
		},
		"socket_service_has_no_main_pid": func(
			_ hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.mainPID = "0"
		},
		"socket_activation_is_inactive": func(
			_ hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.socketActive = false
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
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
			if err := rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
				t.Fatal(err)
			}
			rt.now = func() time.Time {
				return rootNow.Add(2 * time.Minute)
			}
			mutate(rt, runner)

			if _, err := rt.recoverExpiredHostSelfUpdate(
				context.Background(),
				HostSelfUpdateSlotA,
			); !errors.Is(err, errHostSelfUpdateRollback) {
				t.Fatalf("unhealthy executor proof err=%v", err)
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
					"unhealthy executor cleared rollback fence: state=%#v agent_restarts=%d executor_restarts=%d",
					persisted,
					runner.restarts,
					runner.executorRestarts,
				)
			}
		})
	}
}
