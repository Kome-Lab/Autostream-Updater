//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
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
				fixture, policy, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
				state, pid := "inactive\n", "0\n"
				var pidErr error
				switch boundary {
				case "failed", "active", "activating", "deactivating":
					state = boundary + "\n"
				case "nonzero_pid":
					pid = "42\n"
				case "unknown_state":
					state = "private-state-sentinel\n"
				case "empty_state":
					state = ""
				case "invalid_pid":
					pid = "private-pid-sentinel\n"
				case "negative_pid":
					pid = "-1\n"
				case "overflow_pid":
					pid = strings.Repeat("9", 40)
				case "pid_error":
					pidErr = errors.New("private-error-sentinel")
				}
				d := newSoftwareClaimRecoveryRootRefusal(request.SoftwareClaimRecovery.Request)
				d.LifecycleHeld = true
				reads := 0
				base := runtime.manual.runner
				inner := softwareClaimRecoveryDiagnosticTestRunner(func(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
					unit := manualHostRecoveryUnitInstances[slot]
					if name == "/usr/bin/systemctl" && reflect.DeepEqual(args, []string{"is-active", unit}) {
						reads++
						return state, errors.New("ordinary nonactive command status")
					}
					if name == "/usr/bin/systemctl" && reflect.DeepEqual(args, []string{"show", "--property=MainPID", "--value", unit}) {
						reads++
						return pid, pidErr
					}
					return base.Run(ctx, dir, env, name, args...)
				})
				runtime.manual.runner = softwareClaimRecoveryDiagnosticRunner{inner, &d}
				// The shared installer predicate remains strict. Software claim now
				// proves exclusion independently, with stronger unit/slot/FD guards.
				_ = policy
				guardErr := validateManualHostUpgradeRecoveryServicePreconditions(context.Background(), runtime.manual, false)
				if boundary == "inactive" {
					if guardErr != nil {
						t.Fatal("diagnostic changed ordinary inactive service admission")
					}
				} else if guardErr == nil {
					t.Fatal("diagnostic weakened the strict manual-upgrade guard")
				}
				wantReads := 2
				if boundary == "empty_state" {
					wantReads = 1
				}
				if reads != wantReads || fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
					t.Fatal("diagnostic added a guard query or changed a service")
				}
				d.Phase = "recovery_service"
				body, err := json.Marshal(d)
				if err != nil || !d.valid() || strings.Contains(string(body), "private-") || strings.Contains(string(body), "MainPID") {
					t.Fatal("refusal observation leaked unbounded guard input")
				}
				observed := d.Slots[slot]
				wantValid := boundary != "empty_state" && boundary != "invalid_pid" && boundary != "negative_pid" && boundary != "overflow_pid" && boundary != "pid_error"
				if observed.PIDValid != wantValid || observed.PIDZero != (wantValid && boundary != "nonzero_pid") || observed.StateCommand != "launch_other" {
					t.Fatal("diagnostic lost the original service input classification")
				}
				if slot == 0 && boundary != "inactive" && d.Slots[1].State != "not_read" {
					t.Fatal("diagnostic fabricated an unqueried slot observation")
				}
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
}
