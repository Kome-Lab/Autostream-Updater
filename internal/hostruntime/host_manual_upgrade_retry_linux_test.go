//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestManualHostUpgradeStopFailureUsesDetachedAgentRecovery(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	fixture.runner.stopAfterSideEffectErr = true
	ctx, cancel := context.WithCancel(context.Background())
	fixture.runner.stopCancel = cancel
	defer cancel()

	result, err := upgradeHostRuntimeWithRuntime(
		ctx, fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"stop Host Agent for manual runtime upgrade",
	) {
		t.Fatalf("side-effecting stop failure result=%+v err=%v", result, err)
	}
	if !fixture.runner.agentActive || fixture.runner.stopCalls != 1 {
		t.Fatalf("old Agent was not restored: active=%v stops=%d", fixture.runner.agentActive, fixture.runner.stopCalls)
	}
	if len(fixture.runner.restartContextCanceled) != 2 ||
		fixture.runner.restartContextCanceled[0] ||
		fixture.runner.restartContextCanceled[1] {
		t.Fatalf(
			"Agent recovery inherited canceled context: %v",
			fixture.runner.restartContextCanceled,
		)
	}
}

func TestManualHostUpgradeSameArchiveRetryUsesFreshGeneration(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)
	fixture.runner.failTargetAgent = true
	firstResult, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "restart Host Agent") ||
		firstResult != (ManualHostUpgradeResult{}) {
		t.Fatalf(
			"first activation failure result=%+v err=%v",
			firstResult,
			err,
		)
	}
	if !fixture.runner.targetAgentFailed || fixture.runner.stopCalls != 1 {
		t.Fatalf(
			"first request did not cross the activation fence: target_failed=%v stops=%d",
			fixture.runner.targetAgentFailed,
			fixture.runner.stopCalls,
		)
	}
	failed, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || failed.Phase != HostSelfUpdatePhaseStable ||
		failed.ActiveSlot != HostSelfUpdateSlotA ||
		failed.HealthySlot != HostSelfUpdateSlotA ||
		failed.ActiveAgentVersion != manualHostUpgradeTestOldVersion ||
		failed.ActiveExecutorVersion != manualHostUpgradeTestOldVersion ||
		failed.FailedGeneration == "" || failed.PendingGeneration != "" ||
		failed.PendingSlot != "" || failed.RollbackSlot != "" {
		t.Fatalf("failed state=%+v err=%v", failed, err)
	}
	firstBinding, _, err := readManualHostUpdateSlotBinding(
		HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
	)
	if err != nil || firstBinding.Generation != failed.FailedGeneration {
		t.Fatalf(
			"failed slot generation=%q failed_generation=%q err=%v",
			firstBinding.Generation,
			failed.FailedGeneration,
			err,
		)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("rollback current slot=%q err=%v", current, err)
	}
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil {
		t.Fatalf("same archive retry: %v", err)
	}
	if result.PreviousSlot != HostSelfUpdateSlotA ||
		result.ActiveSlot != HostSelfUpdateSlotB ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("retry result=%+v", result)
	}
	committed, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || committed.Phase != HostSelfUpdatePhaseStable ||
		committed.ActiveSlot != HostSelfUpdateSlotB ||
		committed.HealthySlot != HostSelfUpdateSlotB ||
		committed.RollbackSlot != HostSelfUpdateSlotA ||
		committed.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		committed.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion ||
		committed.RollbackAgentVersion != manualHostUpgradeTestOldVersion ||
		committed.RollbackExecutorVersion != manualHostUpgradeTestOldVersion ||
		committed.FailedGeneration != failed.FailedGeneration ||
		committed.PendingGeneration != "" || committed.PendingSlot != "" {
		t.Fatalf("retry state=%+v err=%v", committed, err)
	}
	retryBinding, _, err := readManualHostUpdateSlotBinding(
		HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
	)
	if err != nil || retryBinding.Generation == failed.FailedGeneration ||
		!sameManualHostUpgradeArchiveContent(firstBinding, retryBinding) {
		t.Fatalf(
			"retry binding generation=%q failed_generation=%q same_content=%v err=%v",
			retryBinding.Generation,
			failed.FailedGeneration,
			sameManualHostUpgradeArchiveContent(firstBinding, retryBinding),
			err,
		)
	}
	current, err = fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("committed current slot=%q err=%v", current, err)
	}
	if fixture.runner.stopCalls != 2 {
		t.Fatalf("retry stop calls=%d want=2", fixture.runner.stopCalls)
	}
	assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)

	stateBeforeNoOp := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.selfUpdate.statePath,
	)
	stopsBeforeNoOp := fixture.runner.stopCalls
	restartsBeforeNoOp := append([]string(nil), fixture.runner.restartOrder...)
	noOp, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || noOp.PreviousSlot != HostSelfUpdateSlotB ||
		noOp.ActiveSlot != HostSelfUpdateSlotB ||
		noOp.Version != manualHostUpgradeTestTargetVersion ||
		!noOp.AlreadyCurrent {
		t.Fatalf("already-current result=%+v err=%v", noOp, err)
	}
	if fixture.runner.stopCalls != stopsBeforeNoOp ||
		fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(restartsBeforeNoOp) {
		t.Fatalf(
			"already-current request mutated services: stops=%d want=%d restarts=%v want=%v",
			fixture.runner.stopCalls,
			stopsBeforeNoOp,
			fixture.runner.restartOrder,
			restartsBeforeNoOp,
		)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.selfUpdate.statePath, stateBeforeNoOp,
	)
	current, err = fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("already-current current slot=%q err=%v", current, err)
	}
	assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
}

func TestManualHostUpgradeSameVersionStillRejectsDurableBlocker(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err != nil {
		t.Fatalf("seed current target runtime: %v", err)
	}
	checkpoint := writeManualHostUpgradeLinuxCheckpoint(t, fixture, "started")
	before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)
	stops := fixture.runner.stopCalls

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked same-version result=%+v err=%v", result, err)
	}
	if fixture.runner.stopCalls != stops {
		t.Fatalf("blocked same-version retry stopped Agent: %d -> %d", stops, fixture.runner.stopCalls)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(t, checkpoint, before)
}

func TestManualHostUpgradeBlocksOnTerminalGrantWithoutMutation(t *testing.T) {
	for _, phase := range []string{
		hostSelfUpdateGrantPhaseApplied,
		hostSelfUpdateGrantPhaseFailed,
	} {
		t.Run(phase, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			if _, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			); err != nil {
				t.Fatalf("seed current target runtime: %v", err)
			}
			request, _, err := readManualHostUpdateSlotBinding(
				HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
			)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := LoadLocalExecutorPolicy(fixture.policyPath, false)
			if err != nil {
				t.Fatal(err)
			}
			policySHA256, err := policy.SHA256()
			if err != nil {
				t.Fatal(err)
			}
			authorization := validHostSelfUpdateGrantAuthorization(
				"stage",
				request,
				LocalExecutorMutationFence{
					SourcePolicyRevision:    policy.SourcePolicyRevision,
					OwnershipEpoch:          3,
					OwnershipPolicyRevision: policy.ProjectionRevision,
					ExecutorPolicyRevision:  policy.PolicyRevision,
				},
				policySHA256,
			)
			grant := newHostSelfUpdateGrantState(authorization)
			grant.Phase = phase
			if phase == hostSelfUpdateGrantPhaseApplied {
				receipt := consumedHostSelfUpdateGrant(authorization).Grant
				grant.Receipt = &receipt
			}
			if err := saveHostSelfUpdateGrantState(
				fixture.runtime.selfUpdate.grantStatePath, grant, false,
			); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(fixture.runtime.selfUpdate.grantStatePath)
			if err != nil {
				t.Fatal(err)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil ||
				!strings.Contains(err.Error(), "existing Host self-update grant blocks") ||
				result != (ManualHostUpgradeResult{}) {
				t.Fatalf("terminal grant result=%+v err=%v", result, err)
			}
			after, err := os.ReadFile(fixture.runtime.selfUpdate.grantStatePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("terminal Host self-update grant changed while blocking upgrade")
			}
		})
	}
}

func TestManualHostUpgradeLoadsLegacyHelperTargetsBeforeLocking(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	legacy := validHelperTestConfig(t)
	legacy.Targets[0].Systemd.Unit = "custom-legacy-worker.service"
	legacyPath := writeHelperTestConfig(t, legacy)
	fixture.runtime.paths.legacyHelperConfigPath = legacyPath
	var lockedLegacy []Target
	fixture.runtime.acquireTargetLocks = func(
		_ LocalExecutorPolicy,
		targets []Target,
	) (func(), error) {
		lockedLegacy = append([]Target(nil), targets...)
		return func() {}, nil
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err != nil {
		t.Fatalf("upgrade with legacy helper policy: %v", err)
	}
	if len(lockedLegacy) != 1 || lockedLegacy[0].Systemd == nil ||
		lockedLegacy[0].Systemd.Unit != "custom-legacy-worker.service" {
		t.Fatalf("legacy targets were not fenced: %+v", lockedLegacy)
	}
}

func TestManualHostUpgradeUnlockedWaitProcessExit(t *testing.T) {
	// A real process at the expected slot path exits strictly after the query
	// returns its PID and before EvalSymlinks reads /proc/<pid>/exe. This is a
	// process-boundary fixture, not the real systemd installer oracle.
	for index, unit := range manualHostRecoveryUnitInstances {
		for _, state := range []string{"active", "activating", "deactivating"} {
			for _, after := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/after_%t", index, state, after), func(t *testing.T) {
					root := t.TempDir()
					slot := []string{"a", "b"}[index]
					executable := filepath.Join(root, slot, "bin", "autostream-local-executor")
					body, err := os.ReadFile("/bin/sleep")
					if err != nil {
						t.Fatal(err)
					}
					manualHostUpgradeLinuxWriteFile(t, executable, body, 0o755)
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					process := exec.CommandContext(ctx, executable, "10")
					if err := process.Start(); err != nil {
						t.Fatal(err)
					}
					reaped := false
					t.Cleanup(func() {
						if !reaped {
							_ = process.Process.Kill()
							_ = process.Wait()
						}
					})
					procPath := fmt.Sprintf("/proc/%d/exe", process.Process.Pid)
					if actual, err := filepath.EvalSymlinks(procPath); err != nil || actual != executable {
						t.Fatalf("regular slot process was not established: err=%v", err)
					}
					queries, resolves := 0, 0
					rt := manualHostUpgradeRuntime{selfUpdate: hostSelfUpdateExecutorRuntime{slotsRoot: root}}
					rt.runner = softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, dir string, env []string, name string, args ...string) (string, error) {
						if dir != "/" || env != nil || name != "/usr/bin/systemctl" || len(args) != 7 ||
							strings.Join(args[:6], " ") != "show --property=ActiveState --property=SubState --property=MainPID --property=ControlPID --property=Result" {
							t.Fatal("process fixture changed the bounded query or mutated services")
						}
						if args[6] == unit {
							queries++
							if !reaped {
								return fmt.Sprintf("ActiveState=%s\nSubState=running\nMainPID=%d\nControlPID=0\nResult=success\n", state, process.Process.Pid), nil
							}
						}
						return "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nResult=success\n", nil
					})
					rt.resolveProcessExe = func(pid int) (string, error) {
						resolves++
						if pid != process.Process.Pid || reaped || queries != 1 {
							t.Fatal("exit was not between the PID query and resolver")
						}
						if err := process.Process.Kill(); err != nil {
							t.Fatal(err)
						}
						_ = process.Wait()
						reaped = true
						return filepath.EvalSymlinks(procPath)
					}
					started := time.Now()
					if after {
						err = waitManualHostUpgradeRecoveryQuiescent(ctx, rt, false)
						if err != nil || queries != 2 || resolves != 1 || time.Since(started) < 100*time.Millisecond {
							t.Fatalf("missing did not require a fresh stopped observation: queries=%d resolves=%d err=%v", queries, resolves, err)
						}
					} else {
						// Frozen 90361b2 wait returns this non-CanSettle error directly.
						err = validateManualHostUpgradeRecoveryServicePreconditions(ctx, rt, false)
						if err == nil || err.Error() != unit+" recovery process is unconfirmed" ||
							!errors.Is(err, os.ErrNotExist) || manualHostUpgradeRecoveryCanSettle(err) || queries != 1 {
							t.Fatalf("base refusal or original cause was lost: err=%v queries=%d", err, queries)
						}
					}
					t.Logf("UI183-R4 process_exit slot=%s state=%s after=%t queries=%d resolves=%d", slot, state, after, queries, resolves)
				})
			}
		}
	}
}

func TestManualHostUpgradeUnlockedWaitMissingFreshPreflight(t *testing.T) {
	for _, unit := range manualHostRecoveryUnitInstances {
		for _, mode := range []string{"success", "persistent", "canceled", "foreign", "identity", "policy", "state", "slot", "lock", "under_lock", "after_side_effect"} {
			t.Run(unit+"/"+mode, func(t *testing.T) {
				fixture, runner := newManualHostUpgradeConcurrencyFixture(t, unit, "after_lock", true)
				ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
				defer cancel()
				identity := snapshotManualHostUpgradeLinuxProtectedFile(t, fixture.identityPath)
				policy := snapshotManualHostUpgradeLinuxProtectedFile(t, fixture.policyPath)
				state := snapshotManualHostUpgradeLinuxProtectedFile(t, fixture.runtime.selfUpdate.statePath)
				targetHeld, targetAcquires, polls, missing := false, 0, 0, 0
				waitComplete := false
				var unlockOrder []string
				lockPath := filepath.Join(fixture.root, "permanent-lifecycle.lock")
				manualHostUpgradeLinuxWriteFile(t, lockPath, []byte("lock"), 0o600)
				lockInfo, err := os.Lstat(lockPath)
				if err != nil {
					t.Fatal(err)
				}
				acquire := fixture.runtime.acquireLocks
				fixture.runtime.acquireLocks = func() (func(), error) {
					if runner.attempts == 1 {
						switch mode {
						case "identity":
							manualHostUpgradeLinuxWriteFile(t, fixture.identityPath, append(identity.payload, '\n'), 0o600)
						case "policy":
							manualHostUpgradeLinuxWriteFile(t, fixture.policyPath, append(policy.payload, '\n'), 0o600)
						case "state":
							manualHostUpgradeLinuxWriteFile(t, fixture.runtime.selfUpdate.statePath, append(state.payload, '\n'), 0o600)
						case "slot":
							path := filepath.Join(fixture.runtime.selfUpdate.slotsRoot, "a", "bin", "autostream-host-agent")
							body, err := os.ReadFile(path)
							if err != nil {
								t.Fatal(err)
							}
							manualHostUpgradeLinuxWriteFile(t, path, append(body, '\n'), 0o755)
						case "lock":
							if err := os.Rename(lockPath, lockPath+".retained"); err != nil {
								t.Fatal(err)
							}
							manualHostUpgradeLinuxWriteFile(t, lockPath, []byte("other"), 0o600)
							return nil, verifyManualHostUpgradePreflightLocks([]manualHostUpgradePreflightLock{{path: lockPath, info: lockInfo}})
						}
					}
					unlock, err := acquire()
					return func() { unlockOrder = append(unlockOrder, "lifecycle"); unlock() }, err
				}
				fixture.runtime.acquireTargetLocks = func(LocalExecutorPolicy, []Target) (func(), error) {
					targetHeld = true
					targetAcquires++
					return func() { targetHeld = false; unlockOrder = append(unlockOrder, "target") }, nil
				}
				fixture.runtime.runner = softwareClaimRecoveryDiagnosticTestRunner(func(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
					if name == "/usr/bin/systemctl" && len(args) == 7 && args[0] == "show" && args[6] == unit &&
						!runner.locked && runner.handoffs == 1 && fixture.runner.stopCalls == 0 && !waitComplete {
						if targetHeld || strings.Join(unlockOrder, ",") != "target,lifecycle" {
							t.Fatal("wait began before both deferred unlocks")
						}
						deadline, ok := ctx.Deadline()
						if !ok || time.Until(deadline) > 30*time.Second {
							t.Fatal("wait escaped the shared preflight deadline")
						}
						polls++
						if polls == 1 || mode == "persistent" || mode == "foreign" {
							return "ActiveState=deactivating\nSubState=stop\nMainPID=5101\nControlPID=0\nResult=success\n", nil
						}
						waitComplete = true
					}
					return runner.Run(ctx, dir, env, name, args...)
				})
				resolve := fixture.runtime.resolveProcessExe
				cause := &os.PathError{Op: "readlink", Path: "private-process-path", Err: syscall.ENOENT}
				fixture.runtime.resolveProcessExe = func(pid int) (string, error) {
					if pid == 5101 && (mode == "under_lock" || !runner.locked) {
						if mode == "foreign" && polls > 1 {
							return "/private-foreign-executable", nil
						}
						missing++
						if mode == "canceled" {
							cancel()
						}
						return "", cause
					}
					return resolve(pid)
				}
				if mode == "after_side_effect" {
					fixture.runner.stopHook = func() error {
						return &manualHostUpgradeRecoveryUnconfirmed{unit: unit, cause: cause,
							observed: manualHostRecoveryServiceProperties{state: "active", mainPID: 5101}}
					}
				}
				result, err := upgradeHostRuntimeWithRuntime(ctx, fixture.request, fixture.runtime)
				if mode == "success" {
					if err != nil || result.ActiveSlot != HostSelfUpdateSlotB || runner.attempts != 2 ||
						runner.handoffs != 1 || targetAcquires != 2 || missing != 1 || polls != 2 {
						t.Fatalf("fresh preflight incomplete: result=%+v err=%v attempts=%d targets=%d missing=%d polls=%d", result, err, runner.attempts, targetAcquires, missing, polls)
					}
					assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
					assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
				} else {
					if err == nil || result != (ManualHostUpgradeResult{}) {
						t.Fatal("negative became successful")
					}
					if mode == "after_side_effect" {
						if runner.attempts != 2 || runner.handoffs != 1 || fixture.runner.stopCalls != 1 {
							t.Fatal("side-effecting refusal retried")
						}
					} else if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 ||
						fixture.runner.recoveryReloads != 0 || fixture.runner.recoveryResetFailedAttempts != 0 {
						t.Fatal("negative crossed the first mutation boundary")
					}
					if mode == "persistent" && (!errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cause) || missing < 2) {
						t.Fatalf("persistent missing lost deadline/cause: missing=%d err=%v", missing, err)
					}
					if mode == "canceled" && (!errors.Is(err, context.Canceled) || !errors.Is(err, cause) || missing != 1) {
						t.Fatal("cancellation lost its original missing cause")
					}
					var process *manualHostUpgradeRecoveryUnconfirmed
					if mode == "foreign" && (!errors.As(err, &process) || process.classification() != "path_mismatch") {
						t.Fatal("fresh foreign PID was not classified and refused")
					}
					if mode == "under_lock" && (runner.attempts != 1 || runner.handoffs != 1 || polls != 0 || !errors.Is(err, cause)) {
						t.Fatal("under-lock missing acquired a new wait/handoff")
					}
					if mode != "state" && mode != "after_side_effect" {
						assertManualHostUpgradeLinuxProtectedFileUnchanged(t, fixture.runtime.selfUpdate.statePath, state)
					}
				}
				if mode != "identity" {
					assertManualHostUpgradeLinuxProtectedFileUnchanged(t, fixture.identityPath, identity)
				}
				if mode != "policy" {
					assertManualHostUpgradeLinuxProtectedFileUnchanged(t, fixture.policyPath, policy)
				}
				if mode != "lock" {
					current, statErr := os.Lstat(lockPath)
					if statErr != nil || !os.SameFile(lockInfo, current) {
						t.Fatal("permanent lifecycle inode changed")
					}
				}
				t.Logf("UI183-R4 preflight unit=%s mode=%s attempts=%d missing=%d polls=%d stops=%d", unit, mode, runner.attempts, missing, polls, fixture.runner.stopCalls)
			})
		}
	}
}

func TestManualHostUpgradeUnlockedWaitRejectsUnconfirmed(t *testing.T) {
	for _, item := range []struct {
		name           string
		cause          error
		classification string
	}{
		{"EACCES", syscall.EACCES, "resolution_error/EACCES"},
		{"EPERM", syscall.EPERM, "resolution_error/EPERM"},
		{"ENODEV", syscall.ENODEV, "resolution_error/ENODEV"},
		{"EIO", syscall.EIO, "resolution_error/EIO"},
		{"unknown", errors.New("private-arbitrary-error"), "resolution_error/OTHER"},
		{"string_ENOENT", errors.New("ENOENT"), "resolution_error/OTHER"},
		{"mismatch", nil, "path_mismatch"},
		{"inactive_pid", syscall.ENOENT, "resolution_error/ENOENT"},
		{"failed_pid", syscall.ENOENT, "resolution_error/ENOENT"},
		{"control_pid", syscall.ENOENT, ""},
		{"zero_pid", syscall.ENOENT, ""},
		{"invalid_query", syscall.ENOENT, ""},
		{"unknown_state", syscall.ENOENT, ""},
	} {
		t.Run(item.name, func(t *testing.T) {
			var diagnostic bytes.Buffer
			writer := log.Writer()
			log.SetOutput(&diagnostic)
			t.Cleanup(func() { log.SetOutput(writer) })
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			unit := manualHostRecoveryUnitInstances[0]
			body := "ActiveState=active\nSubState=running\nMainPID=42\nControlPID=0\nResult=success\n"
			switch item.name {
			case "inactive_pid":
				body = strings.Replace(body, "active", "inactive", 1)
			case "failed_pid":
				body = strings.Replace(body, "active", "failed", 1)
			case "control_pid":
				body = strings.Replace(body, "ControlPID=0", "ControlPID=43", 1)
			case "zero_pid":
				body = strings.Replace(body, "MainPID=42", "MainPID=0", 1)
			case "invalid_query":
				body = strings.Replace(body, "Result=success\n", "", 1)
			case "unknown_state":
				body = strings.Replace(body, "active", "private-state", 1)
			}
			calls, resolves := 0, 0
			rt := manualHostUpgradeRuntime{}
			rt.runner = softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, _ string, _ []string, name string, args ...string) (string, error) {
				calls++
				if name != "/usr/bin/systemctl" || len(args) != 7 || args[6] != unit {
					t.Fatal("negative changed services or queried an unrelated unit")
				}
				return body, nil
			})
			rt.resolveProcessExe = func(int) (string, error) {
				resolves++
				if item.cause == nil {
					return "/private-foreign-path", nil
				}
				return "", &os.PathError{Op: "readlink", Path: "private-process-path", Err: item.cause}
			}
			if item.name == "zero_pid" {
				// PID0 alone is not quiescence while active; keep the old busy wait.
				if err := waitManualHostUpgradeRecoveryQuiescent(ctx, rt, false); !errors.Is(err, context.DeadlineExceeded) || resolves != 0 {
					t.Fatal("active PID0 became successful or resolved a process")
				}
				return
			}
			err := waitManualHostUpgradeRecoveryQuiescent(ctx, rt, false)
			var process *manualHostUpgradeRecoveryUnconfirmed
			if err == nil || calls != 1 || strings.Contains(err.Error(), "private-") ||
				item.classification != "" && (!errors.As(err, &process) || process.classification() != item.classification) {
				t.Fatalf("non-missing refusal changed or disclosed cause: calls=%d err=%v", calls, err)
			}
			if item.classification == "" && resolves != 0 {
				t.Fatal("invalid query/control PID reached resolver")
			}
			if item.cause != nil && item.classification != "" && !errors.Is(err, item.cause) {
				t.Fatal("final refusal lost the typed original cause")
			}
			if strings.Contains(diagnostic.String(), "private-") || item.classification != "" &&
				!strings.Contains(diagnostic.String(), "manual Host recovery process refusal cause="+item.classification) {
				t.Fatal("final closed diagnostic was absent or disclosed a raw cause")
			}
		})
	}
	t.Run("closed_unknown_and_fixed_unit", func(t *testing.T) {
		process := &manualHostUpgradeRecoveryUnconfirmed{unit: "private-unit", cause: os.ErrNotExist,
			observed: manualHostRecoveryServiceProperties{state: "active", mainPID: 42}}
		if manualHostUpgradeRecoveryMissingCanBeReobserved(context.Background(), process) {
			t.Fatal("non-A/B unit acquired wait permission")
		}
		process.cause = nil
		if process.classification() != "UNKNOWN" {
			t.Fatal("unrecorded cause was inferred")
		}
	})
}

func TestManualHostUpgradeUnlockedWaitDiagnosticParity(t *testing.T) {
	for _, unit := range manualHostRecoveryUnitInstances {
		for _, failure := range []error{syscall.ENOENT, syscall.EACCES, nil} {
			t.Run(fmt.Sprintf("%s/%v", unit, failure), func(t *testing.T) {
				var outcomes []string
				for _, enabled := range []bool{false, true} {
					calls, queries := 0, 0
					d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
					d.Phase, d.LifecycleHeld = "recovery_service", false
					body := "ActiveState=active\nSubState=running\nMainPID=42\nControlPID=0\nResult=success\n"
					inner := softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, _ string, _ []string, name string, args ...string) (string, error) {
						calls++
						if name != "/usr/bin/systemctl" || len(args) != 7 {
							t.Fatal("diagnostic parity mutated services")
						}
						if args[6] == unit {
							queries++
							if queries == 1 {
								return body, nil
							}
						}
						return "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nResult=success\n", nil
					})
					var selected CommandRunner = inner
					if enabled {
						selected = softwareClaimRecoveryDiagnosticRunner{inner, &d}
					}
					rt := manualHostUpgradeRuntime{runner: selected, resolveProcessExe: func(int) (string, error) {
						if failure != nil {
							return "", &os.PathError{Op: "readlink", Path: "private-path", Err: failure}
						}
						return "/private-foreign-path", nil
					}}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					err := waitManualHostUpgradeRecoveryQuiescent(ctx, rt, false)
					message, classification := "", "NONE"
					if err != nil {
						message = err.Error()
						var process *manualHostUpgradeRecoveryUnconfirmed
						if !errors.As(err, &process) || failure != nil && !errors.Is(err, failure) {
							t.Fatal("diagnostic wrapper replaced the original cause")
						}
						classification = process.classification()
					}
					outcomes = append(outcomes, fmt.Sprintf("%s/%s/%d/%d", message, classification, calls, queries))
					if failure == syscall.ENOENT {
						wantCalls := 3
						if unit == manualHostRecoveryUnitInstances[1] {
							wantCalls = 4
						}
						if err != nil || calls != wantCalls || queries != 2 {
							t.Fatal("missing skipped complete A/B stopped observation")
						}
					} else if err == nil || message != unit+" recovery process is unconfirmed" || queries != 1 {
						t.Fatal("diagnostic parity weakened a refusal")
					}
				}
				if outcomes[0] != outcomes[1] {
					t.Fatal("OFF/ON changed output/error, calls or cause classification")
				}
			})
		}
	}
	for _, slot := range []string{"a", "b"} {
		for _, tc := range []struct {
			name, actual, class string
			canonical           bool
			cause               error
		}{
			{"executor_usr", "/usr/lib/systemd/systemd-executor", "systemd_executor", true, nil},
			{"executor_lib", "/lib/systemd/systemd-executor", "systemd_executor", true, nil},
			{"executor_noncanonical", "/usr/lib/systemd/./systemd-executor", "systemd_executor", false, nil},
			{"other_slot", "other_slot", "other_fixed_slot_binary", true, nil},
			{"manager", "/usr/lib/systemd/systemd", "systemd_manager", true, nil},
			{"shell", "/bin/bash", "fixed_shell", true, nil},
			{"foreign", "/private-observation-秘密/foreign", "other", true, nil},
			{"empty", "", "empty", false, nil},
			{"limit", strings.Repeat("x", 4096), "other", true, nil},
			{"over_limit", strings.Repeat("x", 4097), "not_captured", false, nil},
			{"expected_with_error", "expected", "expected_slot_binary", true,
				&os.PathError{Op: "readlink", Path: "/private-observation-秘密/error", Err: syscall.EACCES}},
		} {
			t.Run("executable_comparison/"+slot+"/"+tc.name, func(t *testing.T) {
				var outcomes []string
				for _, enabled := range []bool{false, true} {
					var captured bytes.Buffer
					oldWriter := log.Writer()
					log.SetOutput(&captured)
					defer log.SetOutput(oldWriter)
					unit := "autostream-host-self-update-recovery@" + slot + ".service"
					root := "/private-observation-秘密/slots"
					expected := filepath.Join(root, slot, "bin", "autostream-local-executor")
					actual := tc.actual
					if actual == "expected" {
						actual = expected
					} else if actual == "other_slot" {
						other := "b"
						if slot == "b" {
							other = "a"
						}
						actual = filepath.Join(root, other, "bin", "autostream-local-executor")
					}
					var trace []string
					body := "ActiveState=active\nSubState=start\nMainPID=42\nControlPID=0\nResult=success\n"
					inner := softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, _ string, _ []string, name string, args ...string) (string, error) {
						if name != "/usr/bin/systemctl" || len(args) != 7 || args[0] != "show" {
							t.Fatal("observation changed services or query shape")
						}
						trace = append(trace, fmt.Sprint(args))
						if args[6] == unit {
							return body, nil
						}
						return "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nResult=success\n", nil
					})
					d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
					d.Phase = "recovery_service"
					var runner CommandRunner = inner
					if enabled {
						runner = softwareClaimRecoveryDiagnosticRunner{inner, &d}
					}
					resolves := 0
					rt := manualHostUpgradeRuntime{runner: runner, resolveProcessExe: func(pid int) (string, error) {
						resolves++
						if pid != 42 {
							t.Fatal("resolver did not use preceding MainPID")
						}
						body = "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nResult=success\n"
						return actual, tc.cause
					}}
					rt.selfUpdate.slotsRoot = root
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					err := waitManualHostUpgradeRecoveryQuiescent(ctx, rt, false)
					var process *manualHostUpgradeRecoveryUnconfirmed
					if err == nil || err.Error() != unit+" recovery process is unconfirmed" || !errors.As(err, &process) ||
						errors.Unwrap(process) != tc.cause || manualHostUpgradeRecoveryCanSettle(err) ||
						manualHostUpgradeRecoveryMissingCanBeReobserved(ctx, err) || resolves != 1 {
						t.Fatal("comparison metadata changed the original refusal/cause or retried")
					}
					wantQueries := 1
					if slot == "b" {
						wantQueries = 2
					}
					if len(trace) != wantQueries {
						t.Fatal("comparison metadata added a query")
					}
					classification := "path_mismatch"
					if tc.cause != nil {
						classification = "resolution_error/EACCES"
					}
					if process.classification() != classification {
						t.Fatal("comparison metadata changed cause classification")
					}
					const marker = "manual Host recovery executable comparison="
					text := captured.String()
					if strings.Count(text, marker) != 1 || strings.Contains(text, "private-observation-") {
						t.Fatal("comparison record missing, duplicated or exposed a private operand/error")
					}
					_, encoded, _ := strings.Cut(text, marker)
					encoded = strings.SplitN(encoded, "\n", 2)[0]
					var record manualHostUpgradeExecutableComparison
					if len(encoded) > 2048 || json.Unmarshal([]byte(encoded), &record) != nil ||
						record.SchemaVersion != 1 || record.RecordKind != "recovery_executable_comparison" ||
						record.Slot != slot || record.CallSite != "unlocked_wait" || !record.NonAtomic ||
						record.PrecedingUnitState != "active" || record.PrecedingUnitSubstate != "start" ||
						record.PrecedingUnitResult != "success" || record.MainPIDKind != "positive" || record.ControlPIDKind != "zero" ||
						record.ResolverErrorNil != (tc.cause == nil) || record.ActualEqualsExpected != (actual == expected) ||
						record.Actual.Class != tc.class || record.Expected.Class != "expected_slot_binary" {
						t.Fatal("record is not the preceding snapshot and same resolver comparison")
					}
					for index, operand := range []manualHostUpgradeExecutableOperand{record.Actual, record.Expected} {
						value, canonical := actual, tc.canonical
						if index == 1 {
							value, canonical = expected, true
						}
						if len(value) > 4096 {
							if operand.Bytes != nil || operand.SHA256 != nil || operand.Canonical != nil {
								t.Fatal("oversize operand was captured")
							}
						} else if operand.Bytes == nil || *operand.Bytes != len(value) || operand.SHA256 == nil ||
							*operand.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(value))) ||
							operand.Canonical == nil || *operand.Canonical != canonical {
							t.Fatal("operand hash/length used reconstructed or normalized bytes")
						}
					}
					outcomes = append(outcomes, fmt.Sprintf("%s/%s/%v/%d/%s", err.Error(), process.classification(), trace, resolves, encoded))
				}
				if outcomes[0] != outcomes[1] {
					t.Fatal("OFF/ON changed refusal, comparison bytes or external calls")
				}
			})
		}
	}
}
