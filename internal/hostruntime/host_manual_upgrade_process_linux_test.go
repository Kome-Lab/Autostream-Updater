//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestManualHostUpgradeUnlockedStartupExecutorFreshObservation(t *testing.T) {
	for _, slot := range []string{"a", "b"} {
		for _, tc := range []struct {
			name, actual, state, substate, result string
			control                               int
			cause                                 error
		}{
			{"usr", "/usr/lib/systemd/systemd-executor", "activating", "start", "success", 0, nil},
			{"lib", "/lib/systemd/systemd-executor", "activating", "start", "success", 0, nil},
			{"noncanonical", "/usr/lib/systemd/./systemd-executor", "activating", "start", "success", 0, nil},
			{"other_slot", "other_slot", "activating", "start", "success", 0, nil},
			{"manager", "/usr/lib/systemd/systemd", "activating", "start", "success", 0, nil},
			{"foreign", "/private-foreign-executor", "activating", "start", "success", 0, nil},
			{"inactive_pid", "/usr/lib/systemd/systemd-executor", "inactive", "dead", "success", 0, nil},
			{"active_start", "/usr/lib/systemd/systemd-executor", "active", "start", "success", 0, nil},
			{"active_running", "/usr/lib/systemd/systemd-executor", "active", "running", "success", 0, nil},
			{"deactivating", "/usr/lib/systemd/systemd-executor", "deactivating", "stop", "success", 0, nil},
			{"start_pre", "/usr/lib/systemd/systemd-executor", "activating", "start-pre", "success", 0, nil},
			{"failed_result", "/usr/lib/systemd/systemd-executor", "activating", "start", "exit-code", 0, nil},
			{"control_pid", "/usr/lib/systemd/systemd-executor", "activating", "start", "success", 1, nil},
			{"permission", "/usr/lib/systemd/systemd-executor", "activating", "start", "success", 0, os.ErrPermission},
			{"ENODEV", "/usr/lib/systemd/systemd-executor", "activating", "start", "success", 0, syscall.ENODEV},
		} {
			t.Run(slot+"/"+tc.name, func(t *testing.T) {
				unit, root := "autostream-host-self-update-recovery@"+slot+".service", "/private-startup-slots"
				expected := filepath.Join(root, slot, "bin", "autostream-local-executor")
				actual := tc.actual
				if actual == "other_slot" {
					other := "a"
					if slot == "a" {
						other = "b"
					}
					actual = filepath.Join(root, other, "bin", "autostream-local-executor")
				}
				initial := fmt.Sprintf("ActiveState=%s\nSubState=%s\nMainPID=42\nControlPID=%d\nResult=%s\n", tc.state, tc.substate, tc.control, tc.result)
				const stopped = "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nResult=success\n"
				body, queries, resolves := initial, 0, 0
				complete := tc.name == "usr" || tc.name == "lib"
				rt := manualHostUpgradeRuntime{runner: softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, _ string, _ []string, name string, args ...string) (string, error) {
					if name != "/usr/bin/systemctl" || len(args) != 7 || strings.Join(args[:6], " ") != "show --property=ActiveState --property=SubState --property=MainPID --property=ControlPID --property=Result" {
						t.Fatal("startup wait changed services/query")
					}
					queries++
					if args[6] == unit {
						return body, nil
					}
					return stopped, nil
				}), resolveProcessExe: func(pid int) (string, error) {
					resolves++
					if pid == 43 && complete {
						body = stopped
						return expected, nil
					}
					if pid != 42 {
						t.Fatal("resolver inherited a stale PID")
					}
					body = "ActiveState=active\nSubState=running\nMainPID=43\nControlPID=0\nResult=success\n"
					return actual, tc.cause
				}}
				rt.selfUpdate.slotsRoot = root
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if complete {
					// Reproduce the original refusal before the unlocked-only correction.
					err := validateManualHostUpgradeRecoveryServicePreconditions(ctx, rt, false)
					var process *manualHostUpgradeRecoveryUnconfirmed
					if !errors.As(err, &process) || process.classification() != "path_mismatch" || errors.Unwrap(process) != nil || manualHostUpgradeRecoveryCanSettle(err) {
						t.Fatal("helper became an under-lock handoff/final permission")
					}
					process.comparison.Actual.Class = "other" // Diagnostic metadata is never authority.
					if !manualHostUpgradeRecoveryStartupCanBeReobserved(ctx, err) {
						t.Fatal("typed same-resolver condition was lost")
					}
					process.unit = "private-unit"
					if manualHostUpgradeRecoveryStartupCanBeReobserved(ctx, err) {
						t.Fatal("unknown unit acquired helper wait")
					}
					body, queries, resolves = initial, 0, 0
				}
				err := waitManualHostUpgradeRecoveryQuiescent(ctx, rt, false)
				wantQueries := 1
				if slot == "b" {
					wantQueries = 2
				}
				if complete {
					wantQueries *= 3
					if slot == "a" {
						wantQueries++
					} // Final poll also reads unchanged B.
					if err != nil || queries != wantQueries || resolves != 2 || body != stopped {
						t.Fatalf("helper skipped fresh PID, regular binary or complete stop: queries=%d resolves=%d err=%v", queries, resolves, err)
					}
				} else {
					wantResolves := 1
					if tc.control != 0 {
						wantResolves = 0
					}
					if err == nil || queries != wantQueries || resolves != wantResolves || tc.cause != nil && !errors.Is(err, tc.cause) {
						t.Fatal("unconfirmed helper negative was reobserved or lost cause")
					}
				}
			})
		}
	}
}

func TestVerifyManualHostUnitProcessWaitsForTransientSystemdExecutor(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	var resolvedPIDs []int
	fixture.runtime.resolveProcessExe = func(pid int) (string, error) {
		resolvedPIDs = append(resolvedPIDs, pid)
		if len(resolvedPIDs) == 1 {
			return "/usr/lib/systemd/systemd-executor", nil
		}
		return expected, nil
	}

	identity, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err != nil {
		t.Fatalf("verifyManualHostUnitProcess: %v", err)
	}
	if identity.Version != manualHostUpgradeTestOldVersion {
		t.Fatalf("identity version=%q", identity.Version)
	}
	if len(resolvedPIDs) != 3 || fixture.waitStableCalls != 2 ||
		fixture.runner.mainPIDReads[hostSelfUpdateExecutorServiceUnit] != 3 ||
		fixture.runner.identityReads["autostream-local-executor"] != 1 {
		t.Fatalf("executable resolutions=%v, want transient plus stable pair", resolvedPIDs)
	}
	for _, pid := range resolvedPIDs {
		if pid != 3102 {
			t.Fatalf("resolved PIDs=%v, want one stable MainPID", resolvedPIDs)
		}
	}
}

func TestVerifyManualHostUnitProcessRejectsUntrustedSystemdExecutorPath(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	resolves := 0
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		resolves++
		return "/tmp/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		return nil
	}

	_, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"executing outside the selected slot",
	) {
		t.Fatalf("untrusted systemd-executor path err=%v", err)
	}
	if resolves != 1 || waits != 0 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"untrusted path resolves=%d waits=%d identity_reads=%d",
			resolves,
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessBoundsPersistentSystemdExecutor(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	resolves := 0
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		resolves++
		return "/usr/lib/systemd/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		return nil
	}

	_, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "startup probe limit") {
		t.Fatalf("persistent systemd-executor err=%v", err)
	}
	if resolves != hostSelfUpdateSystemdExecutorProbes ||
		waits != hostSelfUpdateSystemdExecutorProbes-1 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"persistent helper resolves=%d waits=%d identity_reads=%d",
			resolves,
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessHonorsCanceledTransitionWait(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		return "/usr/lib/systemd/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		cancel()
		return ctx.Err()
	}

	_, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transition err=%v", err)
	}
	if waits != 1 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"canceled transition waits=%d identity_reads=%d",
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessRejectsPIDChurn(t *testing.T) {
	for _, test := range []struct {
		name             string
		transientFirst   bool
		wantError        string
		wantStableWaits  int
		wantResolveCalls int
	}{
		{
			name:             "during_systemd_executor_transition",
			transientFirst:   true,
			wantError:        "MainPID changed during systemd-executor transition",
			wantStableWaits:  1,
			wantResolveCalls: 2,
		},
		{
			name:             "after_expected_executable",
			wantError:        "MainPID changed during stability verification",
			wantStableWaits:  1,
			wantResolveCalls: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			expected := filepath.Join(
				fixture.runtime.selfUpdate.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				"autostream-local-executor",
			)
			fixture.runner.mainPIDSequence = map[string][]int{
				hostSelfUpdateExecutorServiceUnit: {3102, 4102},
			}
			resolves := 0
			fixture.runtime.resolveProcessExe = func(int) (string, error) {
				resolves++
				if test.transientFirst && resolves == 1 {
					return "/usr/lib/systemd/systemd-executor", nil
				}
				return expected, nil
			}

			_, err := verifyManualHostUnitProcess(
				context.Background(),
				hostSelfUpdateExecutorServiceUnit,
				expected,
				"autostream-local-executor",
				fixture.runtime,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("PID churn err=%v", err)
			}
			if resolves != test.wantResolveCalls ||
				fixture.waitStableCalls != test.wantStableWaits ||
				fixture.runner.identityReads["autostream-local-executor"] != 0 {
				t.Fatalf(
					"PID churn resolves=%d waits=%d identity_reads=%d",
					resolves,
					fixture.waitStableCalls,
					fixture.runner.identityReads["autostream-local-executor"],
				)
			}
		})
	}
}
