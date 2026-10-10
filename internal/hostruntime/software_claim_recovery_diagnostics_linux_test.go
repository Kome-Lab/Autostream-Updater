//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type softwareClaimRecoveryDiagnosticTestRunner func(context.Context, string, []string, string, ...string) (string, error)

func (f softwareClaimRecoveryDiagnosticTestRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	return f(ctx, dir, env, name, args...)
}

// Invoked by the existing mandatory root refusal parent, so these guards
// require positive Linux execution without replacing the original cases.
func softwareClaimRecoveryDiagnosticChecks(t *testing.T) {
	for _, slot := range []int{0, 1} {
		for _, boundary := range []string{"inactive", "failed", "active", "activating", "deactivating", "nonzero_pid", "unknown_state", "empty_state", "invalid_pid", "negative_pid", "overflow_pid", "pid_error"} {
			t.Run("service_diagnostic/"+[]string{"a", "b"}[slot]+"/"+boundary, func(t *testing.T) {
				state, subState, result, pid := "inactive", "dead", "success", "0"
				var pidErr error
				switch boundary {
				case "failed":
					state, subState, result = "failed", "failed", "exit-code"
				case "active":
					state, subState = "active", "running"
				case "activating":
					state, subState = "activating", "start"
				case "deactivating":
					state, subState = "deactivating", "stop"
				case "nonzero_pid":
					pid = "42"
				case "unknown_state":
					state = "private-state-sentinel"
				case "empty_state":
					state = ""
				case "invalid_pid":
					pid = "private-pid-sentinel"
				case "negative_pid":
					pid = "-1"
				case "overflow_pid":
					pid = strings.Repeat("9", 40)
				case "pid_error":
					pidErr = errors.New("private-error-sentinel")
				}
				targetOutput := fmt.Sprintf("ActiveState=%s\nSubState=%s\nMainPID=%s\nControlPID=0\nResult=%s\n", state, subState, pid, result)
				type outcome struct {
					guard          string
					trace, outputs []string
					errors         []error
					resolves       int
				}
				var outcomes []outcome
				for _, enabled := range []bool{false, true} {
					fixture, _, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
					d := newSoftwareClaimRecoveryRootRefusal(request.SoftwareClaimRecovery.Request)
					d.LifecycleHeld, d.Phase = true, "recovery_service"
					unread := d.Slots
					var got outcome
					var originalOutput string
					var originalErr error
					base := runtime.manual.runner
					inner := softwareClaimRecoveryDiagnosticTestRunner(func(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
						if dir != "/" || env != nil || name != "/usr/bin/systemctl" {
							t.Fatal("guard changed command path, directory or environment")
						}
						queried := -1
						for index, unit := range manualHostRecoveryUnitInstances {
							want := []string{"show", "--property=ActiveState", "--property=SubState", "--property=MainPID", "--property=ControlPID", "--property=Result", unit}
							if reflect.DeepEqual(args, want) {
								queried = index
							}
						}
						if queried < 0 {
							t.Fatal("guard issued an unexpected query")
						}
						got.trace = append(got.trace, []string{"a", "b"}[queried])
						if queried == slot {
							originalOutput, originalErr = targetOutput, pidErr
						} else {
							originalOutput, originalErr = base.Run(ctx, dir, env, name, args...)
							if originalOutput != "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nResult=success\n" || originalErr != nil {
								t.Fatal("untargeted slot did not retain its legal five-property response")
							}
						}
						return originalOutput, originalErr
					})
					var selected CommandRunner = inner
					if enabled {
						selected = softwareClaimRecoveryDiagnosticRunner{inner, &d}
					}
					// Check the exact outward values as well as the external trace.
					runtime.manual.runner = softwareClaimRecoveryDiagnosticTestRunner(func(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
						output, err := selected.Run(ctx, dir, env, name, args...)
						if output != originalOutput || err != originalErr {
							t.Fatal("diagnostic replaced original output/error")
						}
						got.outputs, got.errors = append(got.outputs, output), append(got.errors, err)
						return output, err
					})
					runtime.manual.resolveProcessExe = func(pid int) (string, error) {
						got.resolves++
						if pid != 42 {
							t.Fatal("guard resolved an unobserved process")
						}
						return filepath.Join(runtime.manual.selfUpdate.slotsRoot, []string{"a", "b"}[slot], "bin", "autostream-local-executor"), nil
					}
					guardErr := validateManualHostUpgradeRecoveryServicePreconditions(context.Background(), runtime.manual, false)
					if (guardErr == nil) != (boundary == "inactive") {
						t.Fatal("strict manual-upgrade admission changed")
					}
					got.guard = fmt.Sprintf("%T:%v", guardErr, guardErr)
					wantTrace := []string{"a"}
					if slot == 1 || boundary == "inactive" {
						wantTrace = append(wantTrace, "b")
					}
					wantResolves := 0
					if boundary == "nonzero_pid" {
						wantResolves = 1
					}
					if !reflect.DeepEqual(got.trace, wantTrace) || got.resolves != wantResolves || fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 || fixture.runner.recoveryReloads != 0 || fixture.runner.recoveryResetFailedAttempts != 0 || fixture.runner.recoveryResetFailedCalls != 0 {
						t.Fatal("diagnostic changed exact query trace, process reads or a service")
					}
					if enabled {
						want := unread[slot]
						want.CombinedCommand, want.StateCommand, want.PIDCommand = "success", "success", "success"
						want.CombinedShape, want.State = "invalid", "unknown"
						valid := boundary == "inactive" || boundary == "failed" || boundary == "active" || boundary == "activating" || boundary == "deactivating" || boundary == "nonzero_pid"
						if valid {
							want.CombinedShape, want.State, want.PIDValid, want.PIDZero = "valid", state, true, boundary != "nonzero_pid"
							want.MainPIDKind, want.ControlPIDKind = "zero", "zero"
							if boundary == "nonzero_pid" {
								want.MainPIDKind = "positive"
							}
						}
						if boundary == "pid_error" {
							want.CombinedCommand, want.StateCommand, want.PIDCommand, want.CombinedShape = "launch_other", "launch_other", "launch_other", "not_read"
						}
						if d.Slots[slot] != want {
							t.Fatal("combined observation lost full-query validity or command/PID classification")
						}
						other := 1 - slot
						want = unread[other]
						if slot == 1 || boundary == "inactive" {
							want.State, want.StateCommand, want.PIDCommand = "inactive", "success", "success"
							want.CombinedCommand, want.CombinedShape = "success", "valid"
							want.PIDValid, want.PIDZero, want.MainPIDKind, want.ControlPIDKind = true, true, "zero", "zero"
						}
						if d.Slots[other] != want {
							t.Fatal("diagnostic fabricated or lost the untargeted slot")
						}
					} else if d.Slots != unread {
						t.Fatal("disabled diagnostic published an observation")
					}
					body, err := json.Marshal(d)
					if err != nil || !d.valid() || strings.Contains(string(body), "private-") || strings.Contains(string(body), "MainPID") {
						t.Fatal("refusal observation leaked unbounded guard input")
					}
					outcomes = append(outcomes, got)
				}
				if !reflect.DeepEqual(outcomes[0], outcomes[1]) {
					t.Fatal("diagnostic OFF/ON changed guard error, output/error or external trace")
				}
				t.Logf("UI183-R1 diagnostic_off_on=true query_trace=%s refused=%t service_changes=0 output_error_preserved=true", strings.Join(outcomes[0].trace, ","), boundary != "inactive")
			})
		}
	}
	t.Run("diagnostic_pass_through", func(t *testing.T) {
		d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
		originalErr := errors.New("private-error-sentinel")
		calls := 0
		base := softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, dir string, env []string, name string, args ...string) (string, error) {
			calls++
			if dir != "/original" || !reflect.DeepEqual(env, []string{"SAFE=original"}) || name != "/original-command" || !reflect.DeepEqual(args, []string{"original-argument"}) {
				t.Fatal("diagnostic changed delegated command input")
			}
			return "private-output-sentinel", originalErr
		})
		got, err := (softwareClaimRecoveryDiagnosticRunner{base, &d}).Run(context.Background(), "/original", []string{"SAFE=original"}, "/original-command", "original-argument")
		if got != "private-output-sentinel" || err != originalErr || calls != 1 || d.Slots[0].State != "not_read" || d.Slots[1].State != "not_read" {
			t.Fatal("diagnostic replaced output/error or inspected an unrelated command")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if softwareClaimRecoveryCommandClass(ctx, originalErr) != "canceled" || softwareClaimRecoveryCommandClass(context.Background(), nil) != "success" ||
			softwareClaimRecoveryCommandClass(context.Background(), &exec.ExitError{}) != "exit_other" {
			t.Fatal("closed command error classification changed")
		}
	})
	t.Run("diagnostic_closed_encoding", func(t *testing.T) {
		d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
		d.Phase = "lifecycle_lock"
		if !d.valid() {
			t.Fatal("bounded lock refusal metadata is invalid")
		}
		for _, poison := range []string{"phase", "state", "command", "pid", "sha", "lock", "fabricated_pid", "fabricated_state"} {
			copy := d
			switch poison {
			case "phase":
				copy.Phase = "private-sentinel"
			case "state":
				copy.Slots[0].State = "private-sentinel"
			case "command":
				copy.Slots[0].PIDCommand = "private-sentinel"
			case "pid":
				copy.Slots[0].PIDZero = true
			case "sha":
				copy.RequestSHA256 = "private-sentinel"
			case "lock":
				copy.LifecycleHeld = true
			case "fabricated_pid":
				copy.Slots[0].PIDValid = true
			case "fabricated_state":
				copy.Slots[0].StateCommand = "success"
			}
			if copy.valid() {
				t.Fatal("unknown diagnostic metadata was accepted")
			}
		}
	})
	softwareUpdateChainRootJournalParserChecks(t)
	softwareClaimRecoveryR1ObservationChecks(t)
}
