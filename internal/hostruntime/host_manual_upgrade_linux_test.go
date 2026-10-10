//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManualHostUpgradeBootstrapsMissingSlotAndCommitsRuntimePair(
	t *testing.T,
) {
	t.Run("UI183_watchdog_concurrency", testManualHostUpgradeWatchdogConcurrency)
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil {
		t.Fatalf("upgradeHostRuntimeWithRuntime: %v", err)
	}
	if result.PreviousSlot != HostSelfUpdateSlotA ||
		result.ActiveSlot != HostSelfUpdateSlotB ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("result=%+v", result)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)

	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("current slot=%q err=%v", current, err)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotB ||
		state.HealthySlot != HostSelfUpdateSlotB ||
		state.RollbackSlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion ||
		state.RollbackAgentVersion != manualHostUpgradeTestOldVersion ||
		state.RollbackExecutorVersion != manualHostUpgradeTestOldVersion ||
		state.FailedGeneration != "" || state.PendingGeneration != "" {
		t.Fatalf("persisted state=%+v", state)
	}
	stateRootInfo, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot)
	if err != nil || !stateRootInfo.IsDir() ||
		stateRootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("bootstrapped state root info=%v err=%v", stateRootInfo, err)
	}
	assertManualHostUpgradeLinuxSlotBinding(
		t, fixture, HostSelfUpdateSlotB,
	)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	wantRestartOrder := []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
	}
	if fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(wantRestartOrder) {
		t.Fatalf(
			"restart order=%v want=%v",
			fixture.runner.restartOrder,
			wantRestartOrder,
		)
	}
	if fixture.runner.stopCalls != 1 || fixture.watchdogCalls != 1 ||
		fixture.waitStableCalls < 4 ||
		fixture.runner.mainPIDReads[hostSelfUpdateServiceUnit] < 4 ||
		fixture.runner.mainPIDReads[hostSelfUpdateExecutorServiceUnit] < 4 ||
		fixture.processExeResolves[3101] < 4 ||
		fixture.processExeResolves[3102] < 4 ||
		fixture.runner.identityReads["autostream-host-agent"] < 4 ||
		fixture.runner.identityReads["autostream-local-executor"] < 4 {
		t.Fatalf(
			"strong verification was incomplete: stops=%d watchdog=%d waits=%d pid_reads=%v exe_resolves=%v identity_reads=%v",
			fixture.runner.stopCalls,
			fixture.watchdogCalls,
			fixture.waitStableCalls,
			fixture.runner.mainPIDReads,
			fixture.processExeResolves,
			fixture.runner.identityReads,
		)
	}
}

// These bounded injections extend the existing installer fixture. The actual
// old paired binaries, timers and systemd are also exercised by installer-order
// CI; this model controls the three otherwise nondeterministic read boundaries.
type manualHostUpgradeConcurrencyRunner struct {
	base        *manualHostUpgradeLinuxRunner
	unit        string
	phase       string
	locked      bool
	failed      bool
	injected    bool
	reads       int
	attempts    int
	handoffs    int
	foreign     bool
	controlPID  bool
	unknown     bool
	residual    bool
	unobserved  bool
	beforeState string
	beforePID   int
}

func (r *manualHostUpgradeConcurrencyRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	if name != "/usr/bin/systemctl" || len(args) < 2 {
		return r.base.Run(ctx, dir, env, name, args...)
	}
	unit := args[len(args)-1]
	if unit != r.unit {
		return r.base.Run(ctx, dir, env, name, args...)
	}
	if args[0] == "reset-failed" {
		r.failed = false
		return r.base.Run(ctx, dir, env, name, args...)
	}
	combined := len(args) == 7 && args[0] == "show" && args[1] == "--property=ActiveState"
	if args[0] != "is-active" && !combined && !(len(args) == 4 && args[1] == "--property=MainPID") {
		return r.base.Run(ctx, dir, env, name, args...)
	}
	state, subState, result, pid := "inactive", "dead", "success", 0
	if r.failed {
		state, subState, result = "failed", "failed", "exit-code"
	}
	if r.locked && (combined || args[0] == "is-active") {
		r.reads++
		trigger := 1
		if r.phase == "later_check" {
			trigger = 2
		}
		if !r.injected && r.reads == trigger {
			r.injected, r.failed = true, true
			r.base.recoveryFailedUnits[r.unit] = true
			state, subState, pid = "activating", "start", 5101
			if r.phase == "between_state_pid" && !combined {
				state, subState, pid = "inactive", "dead", 0
			}
		}
	}
	if len(args) == 4 && args[1] == "--property=MainPID" {
		if r.injected && r.reads <= 2 {
			r.beforePID = 5101
			return "5101\n", nil
		}
		return "0\n", nil
	}
	if args[0] == "is-active" {
		r.beforeState = state
		return state + "\n", nil
	}
	if r.unobserved {
		return "", errors.New("unobserved recovery service")
	}
	if r.unknown {
		state = "unknown"
	}
	if r.residual {
		state, subState, pid = "inactive", "dead", 5101
	}
	control := 0
	if r.controlPID {
		control = 5201
	}
	return fmt.Sprintf("ActiveState=%s\nSubState=%s\nMainPID=%d\nControlPID=%d\nResult=%s\n",
		state, subState, pid, control, result), nil
}

// Frozen f72d1bd recovery precondition, including its two separate commands.
// It remains an expected refusal, not a hidden successful installer retry.
func manualHostUpgradeBeforeConcurrency(ctx context.Context, runner CommandRunner, allowFailedBootstrap bool) error {
	for _, unit := range manualHostRecoveryUnitInstances {
		output, _ := runner.Run(ctx, "/", nil, "/usr/bin/systemctl", "is-active", unit)
		state := strings.TrimSpace(output)
		if state == "" {
			return fmt.Errorf("read %s active state", unit)
		}
		output, err := runner.Run(ctx, "/", nil, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", unit)
		if err != nil {
			return err
		}
		pid, err := strconv.Atoi(strings.TrimSpace(output))
		if err != nil || pid < 0 {
			return errors.New("invalid MainPID")
		}
		if pid != 0 || (state != "inactive" && !(allowFailedBootstrap && state == "failed")) {
			return fmt.Errorf("%s must be inactive and have no MainPID", unit)
		}
	}
	return nil
}

func testManualHostUpgradeWatchdogConcurrency(t *testing.T) {
	for _, unit := range manualHostRecoveryUnitInstances {
		for _, phase := range []string{"after_lock", "between_state_pid", "later_check"} {
			for _, persisted := range []bool{false, true} {
				name := fmt.Sprintf("%s/%s/persisted_%t", unit, phase, persisted)
				t.Run(name, func(t *testing.T) {
					_, r := newManualHostUpgradeConcurrencyFixture(t, unit, phase, persisted)
					r.locked = true
					err := manualHostUpgradeBeforeConcurrency(context.Background(), r, true)
					if phase == "later_check" && err == nil {
						err = manualHostUpgradeBeforeConcurrency(context.Background(), r, !persisted)
					}
					if err == nil {
						t.Fatal("frozen precondition did not reject the injected running PID")
					}
					beforeState, beforePID := r.beforeState, r.beforePID
					// Holding the lifecycle lock cannot turn failed into inactive.
					r.reads = 10
					for observation := 0; observation < 3; observation++ {
						output, err := r.Run(context.Background(), "/", nil, "/usr/bin/systemctl", "is-active", unit)
						if err != nil || output != "failed\n" {
							t.Fatal("failed unexpectedly healed while installer held lifecycle lock")
						}
					}
					t.Logf("UI183 before unit=%s checkpoint=%s persisted=%t refusal=true state=%s MainPID=%d ControlPID=0 retained_failed=3 installer_lock=held watchdog_lock=blocked", unit, phase, persisted, beforeState, beforePID)
					fixture, runner := newManualHostUpgradeConcurrencyFixture(t, unit, phase, persisted)
					identity := snapshotManualHostUpgradeLinuxProtectedFile(t, fixture.identityPath)
					policy := snapshotManualHostUpgradeLinuxProtectedFile(t, fixture.policyPath)
					result, err := upgradeHostRuntimeWithRuntime(context.Background(), fixture.request, fixture.runtime)
					if err != nil || result.ActiveSlot != HostSelfUpdateSlotB {
						t.Fatalf("same overlap after result=%+v err=%v", result, err)
					}
					assertManualHostUpgradeLinuxProtectedFileUnchanged(t, fixture.identityPath, identity)
					assertManualHostUpgradeLinuxProtectedFileUnchanged(t, fixture.policyPath, policy)
					assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
					assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
					if persisted && (runner.attempts != 2 || runner.handoffs != 1 || fixture.runner.recoveryResetFailedCalls != 0) {
						t.Fatalf("persisted handoff attempts=%d handoffs=%d resets=%d", runner.attempts, runner.handoffs, fixture.runner.recoveryResetFailedCalls)
					}
					t.Logf("UI183 after unit=%s checkpoint=%s persisted=%t attempts=%d handoffs=%d active_slot=b pair=matching", unit, phase, persisted, runner.attempts, runner.handoffs)
				})
			}
		}
	}
	for _, negative := range []string{"preexisting_failed", "foreign_pid", "control_pid", "inactive_pid", "unknown", "unobserved", "identity", "policy", "state", "slot", "archive", "unit", "canceled", "timeout", "attempt_limit"} {
		t.Run("reject_"+negative, func(t *testing.T) {
			fixture, runner := newManualHostUpgradeConcurrencyFixture(t, manualHostRecoveryUnitInstances[0], "after_lock", true)
			state := snapshotManualHostUpgradeLinuxProtectedFile(t, fixture.runtime.selfUpdate.statePath)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch negative {
			case "preexisting_failed":
				runner.failed, runner.injected = true, true
			case "foreign_pid":
				runner.foreign = true
			case "control_pid":
				runner.controlPID = true
			case "inactive_pid":
				runner.residual = true
			case "unknown":
				runner.unknown = true
			case "unobserved":
				runner.unobserved = true
			case "timeout":
				ctx, cancel = context.WithTimeout(context.Background(), 150*time.Millisecond)
				defer cancel()
			}
			acquire := fixture.runtime.acquireLocks
			fixture.runtime.acquireLocks = func() (func(), error) {
				unlock, err := acquire()
				return func() {
					unlock()
					if negative == "attempt_limit" && fixture.runner.stopCalls == 0 {
						runner.injected, runner.reads = false, 0
					}
					if runner.handoffs != 1 || fixture.runner.stopCalls != 0 {
						return
					}
					switch negative {
					case "identity":
						body, _ := os.ReadFile(fixture.identityPath)
						manualHostUpgradeLinuxWriteFile(t, fixture.identityPath, []byte(strings.Replace(string(body), "Host A", "Host changed", 1)), 0o600)
					case "policy":
						body, _ := os.ReadFile(fixture.policyPath)
						manualHostUpgradeLinuxWriteFile(t, fixture.policyPath, append(body, '\n'), 0o600)
					case "state":
						body, _ := os.ReadFile(fixture.runtime.selfUpdate.statePath)
						manualHostUpgradeLinuxWriteFile(t, fixture.runtime.selfUpdate.statePath, append(body, '\n'), 0o600)
					case "slot":
						body, _ := os.ReadFile(filepath.Join(fixture.runtime.selfUpdate.slotsRoot, "a", "bin", "autostream-host-agent"))
						manualHostUpgradeLinuxWriteFile(t, filepath.Join(fixture.runtime.selfUpdate.slotsRoot, "a", "bin", "autostream-host-agent"), append(body, '\n'), 0o755)
					case "archive":
						manualHostUpgradeLinuxWriteFile(t, filepath.Join(fixture.artifactRoot, "checksums.txt"), []byte("changed\n"), 0o600)
					case "unit":
						manualHostUpgradeLinuxWriteFile(t, fixture.runtime.paths.installedRecoveryService, []byte("unknown unit\n"), 0o644)
					case "canceled":
						cancel()
					case "timeout":
						runner.failed = true
					case "attempt_limit":
						runner.injected, runner.reads = false, 0
					}
				}, err
			}
			result, err := upgradeHostRuntimeWithRuntime(ctx, fixture.request, fixture.runtime)
			if err == nil || result != (ManualHostUpgradeResult{}) || fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 || fixture.runner.recoveryReloads != 0 || fixture.runner.recoveryResetFailedAttempts != 0 {
				t.Fatalf("negative crossed mutation boundary: result=%+v err=%v stops=%d", result, err, fixture.runner.stopCalls)
			}
			if negative != "state" {
				assertManualHostUpgradeLinuxProtectedFileUnchanged(t, fixture.runtime.selfUpdate.statePath, state)
			}
			if negative == "attempt_limit" && runner.attempts != 3 {
				t.Fatalf("attempt limit=%d want=3", runner.attempts)
			}
			if negative == "preexisting_failed" && runner.attempts != 1 {
				t.Fatal("pre-existing failed service was retried")
			}
			t.Logf("UI183 negative=%s attempts=%d writes=0 refused=true", negative, runner.attempts)
		})
	}
	for _, mutation := range []string{"missing", "replaced", "unsafe"} {
		t.Run("lock_"+mutation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lifecycle.lock")
			if err := os.WriteFile(path, []byte("lock"), 0o600); err != nil {
				t.Fatal(err)
			}
			info, _ := os.Lstat(path)
			locks := []manualHostUpgradePreflightLock{{path: path, info: info}}
			if mutation == "unsafe" {
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if mutation == "replaced" {
					if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := verifyManualHostUpgradePreflightLocks(locks); err == nil {
				t.Fatal("changed permanent lock accepted")
			}
		})
	}
}

func newManualHostUpgradeConcurrencyFixture(t *testing.T, unit, phase string, persisted bool) (*manualHostUpgradeLinuxFixture, *manualHostUpgradeConcurrencyRunner) {
	t.Helper()
	fixture := newManualHostUpgradeLinuxFixture(t)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	for _, binary := range []string{"autostream-host-agent", "autostream-local-executor"} {
		body, err := os.ReadFile(filepath.Join(fixture.runtime.selfUpdate.slotsRoot, "a", "bin", binary))
		if err != nil {
			t.Fatal(err)
		}
		manualHostUpgradeLinuxWriteFile(t, filepath.Join(fixture.runtime.selfUpdate.slotsRoot, "b", "bin", binary), body, 0o755)
	}
	if persisted {
		state, err := NewHostSelfUpdateState(manualHostUpgradeTestOldVersion, manualHostUpgradeTestOldVersion)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.runtime.selfUpdate.saveState(state); err != nil {
			t.Fatal(err)
		}
	} else {
		removeManualHostUpgradeLinuxStateRoot(t, fixture)
	}
	runner := &manualHostUpgradeConcurrencyRunner{base: fixture.runner, unit: unit, phase: phase}
	fixture.runtime.runner = runner
	fixture.runtime.acquireLocks = func() (func(), error) {
		runner.locked = true
		runner.attempts++
		return func() {
			runner.locked = false
			if fixture.runner.stopCalls == 0 {
				runner.handoffs++
				if persisted {
					runner.failed = false
					delete(fixture.runner.recoveryFailedUnits, unit)
				}
			}
		}, nil
	}
	resolve := fixture.runtime.resolveProcessExe
	fixture.runtime.resolveProcessExe = func(pid int) (string, error) {
		if pid == 5101 {
			if runner.foreign {
				return "/tmp/foreign-executor", nil
			}
			slot := "a"
			if unit == manualHostRecoveryUnitInstances[1] {
				slot = "b"
			}
			return filepath.Join(fixture.runtime.selfUpdate.slotsRoot, slot, "bin", "autostream-local-executor"), nil
		}
		return resolve(pid)
	}
	return fixture, runner
}

func TestManualHostUpgradeRollsBackWhenTargetAgentActivationFails(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	fixture.runner.failTargetAgent = true
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "restart Host Agent") {
		t.Fatalf("target Agent activation failure result=%+v err=%v", result, err)
	}
	if result != (ManualHostUpgradeResult{}) {
		t.Fatalf("failed upgrade returned a result: %+v", result)
	}
	if !fixture.runner.targetAgentFailed {
		t.Fatal("target Host Agent failure injection did not execute")
	}
	current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
	if currentErr != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("rollback current slot=%q err=%v", current, currentErr)
	}
	state, stateErr := fixture.runtime.selfUpdate.loadPersistedState()
	if stateErr != nil {
		t.Fatalf("load rollback state: %v", stateErr)
	}
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestOldVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestOldVersion ||
		!strings.HasPrefix(state.FailedGeneration, manualHostUpgradeBindingVersion+"-") ||
		state.PendingGeneration != "" || state.RollbackSlot != "" {
		t.Fatalf("rollback state=%+v", state)
	}
	if info, statErr := os.Lstat(fixture.runtime.selfUpdate.stateRoot); statErr != nil ||
		!info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("post-fence rollback removed bootstrap root: info=%v err=%v", info, statErr)
	}
	assertManualHostUpgradeLinuxSlotBinding(
		t, fixture, HostSelfUpdateSlotB,
	)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)
	wantRestartOrder := []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
	}
	if fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(wantRestartOrder) {
		t.Fatalf(
			"rollback restart order=%v want=%v",
			fixture.runner.restartOrder,
			wantRestartOrder,
		)
	}
	if fixture.watchdogCalls != 2 || fixture.waitStableCalls < 5 {
		t.Fatalf(
			"rollback proof was incomplete: watchdog=%d waits=%d",
			fixture.watchdogCalls,
			fixture.waitStableCalls,
		)
	}
}

func TestManualHostUpgradeRejectsTamperedArtifactBeforeMutation(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	tampered := filepath.Join(
		fixture.artifactRoot,
		"bin",
		"autostream-host-agent",
	)
	if err := os.WriteFile(
		tampered,
		[]byte("target:autostream-host-agent\ntampered\n"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "checksum verification failed") {
		t.Fatalf("tampered artifact err=%v", err)
	}
	if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
		t.Fatalf(
			"artifact rejection mutated services: stops=%d restarts=%v",
			fixture.runner.stopCalls,
			fixture.runner.restartOrder,
		)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotB,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection created slot b: %v", err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection persisted state: %v", err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection created state root: %v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("artifact rejection current slot=%q err=%v", current, err)
	}
}

func TestManualHostUpgradeRejectsDurableBlockerBeforeCreatingStateRoot(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	writeManualHostUpgradeLinuxCheckpoint(t, fixture, "started")

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked upgrade result=%+v err=%v", result, err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocker rejection created state root: %v", err)
	}
	assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
}

func TestManualHostUpgradeRejectsUnsafeBootstrapStateLayout(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*manualHostUpgradeLinuxFixture) error
	}{
		{
			name: "parent mode",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				removeManualHostUpgradeLinuxStateRoot(t, fixture)
				return os.Chmod(fixture.runtime.paths.localExecutorStateRoot, 0o755)
			},
		},
		{
			name: "root mode",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				return os.Chmod(fixture.runtime.selfUpdate.stateRoot, 0o755)
			},
		},
		{
			name: "root symlink",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				removeManualHostUpgradeLinuxStateRoot(t, fixture)
				target := filepath.Join(fixture.root, "unsafe-state-root-target")
				if err := os.Mkdir(target, 0o700); err != nil {
					return err
				}
				return os.Symlink(target, fixture.runtime.selfUpdate.stateRoot)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			if err := test.mutate(fixture); err != nil {
				t.Fatal(err)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil || result != (ManualHostUpgradeResult{}) {
				t.Fatalf("unsafe layout result=%+v err=%v", result, err)
			}
			if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
				t.Fatalf("unsafe layout mutated services: stops=%d restarts=%v", fixture.runner.stopCalls, fixture.runner.restartOrder)
			}
		})
	}
}

func TestManualHostUpgradeRejectsStateRootEEXISTRace(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	mkdirCalls := 0
	fixture.runtime.mkdirStateRoot = func(path string, mode os.FileMode) error {
		mkdirCalls++
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		return os.Mkdir(path, mode)
	}

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if !errors.Is(err, fs.ErrExist) || result != (ManualHostUpgradeResult{}) {
		t.Fatalf("EEXIST race result=%+v err=%v", result, err)
	}
	if mkdirCalls != 1 {
		t.Fatalf("state root mkdir calls=%d want=1", mkdirCalls)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); err != nil {
		t.Fatalf("racing state root was removed: %v", err)
	}
	assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
}

func TestManualHostUpgradeSameVersionPersistsMissingBootstrapState(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		payload, err := os.ReadFile(filepath.Join(fixture.artifactRoot, "bin", binary))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(
				fixture.runtime.selfUpdate.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				binary,
			),
			payload,
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	removeManualHostUpgradeLinuxStateRoot(t, fixture)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || !result.AlreadyCurrent ||
		result.ActiveSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version bootstrap result=%+v err=%v", result, err)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version bootstrap state=%+v err=%v", state, err)
	}
	if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
		t.Fatalf("same-version bootstrap mutated services: stops=%d restarts=%v", fixture.runner.stopCalls, fixture.runner.restartOrder)
	}
}

func TestManualHostUpgradeCleansCreatedStateRootWhenBootstrapFsyncFails(
	t *testing.T,
) {
	for _, failAt := range []string{"child", "parent"} {
		t.Run(failAt, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			removeManualHostUpgradeLinuxStateRoot(t, fixture)
			injected := errors.New("injected bootstrap directory fsync failure")
			failed := false
			fixture.runtime.selfUpdate.syncDir = func(path string) error {
				want := fixture.runtime.selfUpdate.stateRoot
				if failAt == "parent" {
					want = fixture.runtime.paths.localExecutorStateRoot
				}
				if !failed && filepath.Clean(path) == filepath.Clean(want) {
					failed = true
					return injected
				}
				return syncDirectory(path)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if !errors.Is(err, injected) || result != (ManualHostUpgradeResult{}) {
				t.Fatalf("%s fsync result=%+v err=%v", failAt, result, err)
			}
			if !failed {
				t.Fatalf("%s fsync injection was not reached", failAt)
			}
			if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s fsync failure retained created root: %v", failAt, err)
			}
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
		})
	}
}
