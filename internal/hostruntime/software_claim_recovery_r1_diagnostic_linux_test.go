//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// One fixed focus set; CI also invokes observations through the unchanged
// mandatory root refusal parent. No real service/cgroup is started here.
func TestSoftwareClaimRecoveryR1Diagnostic(t *testing.T) {
	softwareClaimRecoveryWatchdogSnapshotChecks(t)
	softwareClaimRecoveryWatchdogProcessChecks(t)
	softwareClaimRecoveryDiagnosticChecks(t)
}

func softwareClaimRecoveryR1ObservationChecks(t *testing.T) {
	softwareClaimRecoveryManualObservationChecks(t)
	softwareClaimRecoveryQueryRoutingChecks(t)
	for _, mode := range []string{"valid_zero", "valid_positive", "malformed", "error", "canceled"} {
		t.Run("r1_combined_show/"+mode, func(t *testing.T) {
			d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
			d.LifecycleHeld, d.Phase = true, "recovery_service"
			body := softwareClaimRecoveryWatchdogUnitTestOutput("a", softwareClaimRecoveryWatchdogUnitPath)
			originalErr := error(nil)
			ctx := context.Background()
			if mode == "valid_positive" {
				body = strings.Replace(body, "MainPID=0\n", "MainPID=42\n", 1)
				body = strings.Replace(body, "ControlGroup=\n", "ControlGroup=/system.slice/autostream-host-self-update-recovery@a.service\n", 1)
			}
			if mode == "malformed" {
				body = "private-raw-output"
			}
			if mode == "error" || mode == "canceled" {
				originalErr = &os.PathError{Op: "query", Path: "private-raw-path", Err: syscall.EACCES}
			}
			if mode == "canceled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			calls := 0
			base := softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, dir string, env []string, name string, args ...string) (string, error) {
				calls++
				if dir != "/" || len(env) != 0 || name != "/usr/bin/systemctl" || !softwareClaimRecoveryCombinedQuery(args, manualHostRecoveryUnitInstances[0]) {
					t.Fatal("observation changed combined query")
				}
				return body, originalErr
			})
			runner := softwareClaimRecoveryDiagnosticRunner{base, &d}
			args := []string{"show", "--all"}
			for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
				args = append(args, "--property="+key)
			}
			args = append(args, manualHostRecoveryUnitInstances[0])
			got, err := runner.Run(ctx, "/", nil, "/usr/bin/systemctl", args...)
			if got != body || err != originalErr || calls != 1 {
				t.Fatal("combined observation replaced output/error or added a query")
			}
			if err == nil {
				unit, parseErr := parseSoftwareClaimRecoveryWatchdogUnit(got, "a", softwareClaimRecoveryWatchdogUnitPath)
				softwareClaimRecoveryObserveUnit(runner, "a", unit, parseErr)
			}
			s := d.Slots[0]
			if mode == "valid_zero" || mode == "valid_positive" {
				want := "zero"
				if mode == "valid_positive" {
					want = "positive"
				}
				if s.CombinedCommand != "success" || s.CombinedShape != "valid" || s.MainPIDKind != want || s.ControlPIDKind != "zero" || !s.PIDValid {
					t.Fatal("actual combined shape/PID classification missing")
				}
			} else if mode == "malformed" {
				if s.CombinedCommand != "success" || s.CombinedShape != "invalid" || s.PIDValid {
					t.Fatal("malformed successful query reported valid PID")
				}
			} else if s.CombinedShape != "not_read" || s.MainPIDKind != "unknown" {
				t.Fatal("failed combined query fabricated a parsed PID")
			}
			encoded, _ := json.Marshal(d)
			if !d.valid() || strings.Contains(string(encoded), "private-") || d.Slots[1].CombinedCommand != "not_run" {
				t.Fatal("combined query metadata is unbounded or fabricated")
			}
		})
	}
	for _, name := range []string{"NONE", "ENOENT", "ENODEV", "EACCES", "EPERM", "ENOTDIR", "EIO", "OTHER", "pretend_errno"} {
		t.Run("r1_typed_errno/"+name, func(t *testing.T) {
			var err error
			codes := map[string]error{"ENOENT": syscall.ENOENT, "ENODEV": syscall.ENODEV, "EACCES": syscall.EACCES, "EPERM": syscall.EPERM, "ENOTDIR": syscall.ENOTDIR, "EIO": syscall.EIO}
			if code, ok := codes[name]; ok {
				err = fmt.Errorf("private-wrapped: %w", &os.PathError{Op: "read", Path: "private-path", Err: code})
			}
			want := name
			if name == "OTHER" || name == "pretend_errno" {
				err = errors.New("private ENOENT ENODEV text")
				want = "OTHER"
			}
			if softwareClaimRecoveryErrno(err) != want {
				t.Fatal("typed errno classification inferred text or lost original wrapping")
			}
		})
	}
	for _, name := range []string{"empty", "two", "malformed", "duplicate", "excess", "oversize", "partial_enodev", "partial_eio"} {
		t.Run("r1_member_reader/"+name, func(t *testing.T) {
			body := "42\n43\n"
			var failure error
			switch name {
			case "empty":
				body = ""
			case "malformed":
				body = "private-member\n"
			case "duplicate":
				body = "42\n42\n"
			case "excess":
				body = "1\n2\n3\n"
			case "oversize":
				body = strings.Repeat(" ", 4097)
			case "partial_enodev":
				failure = &os.PathError{Op: "read", Path: "private-path", Err: syscall.ENODEV}
			case "partial_eio":
				failure = syscall.EIO
			}
			var reader io.Reader = strings.NewReader(body)
			if failure != nil {
				reader = &softwareClaimRecoveryR1ErrorReader{body: []byte(body), err: failure}
			}
			d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
			d.observeProcess(1, softwareClaimRecoveryWatchdogUnit{slot: "a"}, "initial_members")
			members, err := readSoftwareClaimWatchdogMembers(reader, d.Process)
			positive := name == "empty" || name == "two"
			if (err == nil) != positive || (!positive && members != nil) {
				t.Fatal("reader diagnosis changed refusal or published partial members")
			}
			stage := "parse"
			if name == "oversize" || name == "excess" {
				stage = "bounds"
			}
			if failure != nil {
				stage = "read"
			}
			if d.Process.ReaderStage != stage || d.Process.PartialRead != (failure != nil) || d.Process.BoundsExceeded != (name == "oversize" || name == "excess") {
				t.Fatal("reader stage/partial/bounds not captured")
			}
			if failure != nil && d.Process.Errno != softwareClaimRecoveryErrno(failure) {
				t.Fatal("reader typed error lost before generic refusal")
			}
			if !d.Process.valid() {
				t.Fatal("reader diagnostic is outside closed bounds")
			}
		})
	}
	t.Run("r1_open_and_path", func(t *testing.T) {
		p := softwareClaimRecoveryProcessDiagnostic{}
		_, err := readSoftwareClaimWatchdogCgroupObserved("private-invalid", &p)
		if err == nil || p.ReaderStage != "path_check" || p.Errno != "NONE" {
			t.Fatal("invalid path diagnostic changed refusal")
		}
		_, err = readSoftwareClaimWatchdogCgroupObserved("/ui179-r1-observation-nonexistent/autostream-host-self-update-recovery@a.service", &p)
		if !errors.Is(err, os.ErrNotExist) || p.ReaderStage != "open" || p.Errno != "ENOENT" {
			t.Fatal("actual fixed-root open error not captured unchanged")
		}
	})
	softwareClaimRecoveryR1ProcessParityChecks(t)
	t.Run("r1_closed_process_record", func(t *testing.T) {
		d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
		d.observeProcess(1, softwareClaimRecoveryWatchdogUnit{slot: "a"}, "initial_members")
		d.LifecycleHeld, d.Phase, d.WatchdogGuard = true, "watchdog_guard", "process_cgroup"
		if !d.valid() {
			t.Fatal("NOT_CAPTURED record is invalid")
		}
		for _, bad := range []string{"errno", "site", "stage", "attempt", "namespace", "combined_shape"} {
			copy := d
			p := *d.Process
			copy.Process = &p
			switch bad {
			case "errno":
				p.Errno = "private-raw-error"
			case "site":
				p.Site = "private-raw-site"
			case "stage":
				p.ReaderStage = "private-raw-stage"
			case "attempt":
				p.Attempt = 5
			case "namespace":
				p.Namespaces[0].Mount = "private-raw-path"
			case "combined_shape":
				copy.Slots[0].CombinedShape = "private-body"
			}
			if copy.valid() {
				t.Fatal("raw/unbounded process observation accepted")
			}
		}
	})
}

func softwareClaimRecoveryManualObservationChecks(t *testing.T) {
	unit := manualHostRecoveryUnitInstances[0]
	valid := "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nResult=success\n"
	for _, mode := range []string{"valid_zero", "main_positive", "control_positive", "missing", "duplicate", "unknown_key", "malformed", "unknown_state", "unknown_substate", "unknown_result", "invalid_control", "negative_control", "oversize", "empty", "error", "canceled", "pre_canceled"} {
		t.Run("r1_manual_query/"+mode, func(t *testing.T) {
			body, suffix := valid, ""
			var originalErr error
			switch mode {
			case "main_positive":
				body = strings.Replace(body, "MainPID=0", "MainPID=42", 1)
			case "control_positive":
				body = strings.Replace(body, "ControlPID=0", "ControlPID=43", 1)
			case "missing":
				body, suffix = strings.Replace(body, "ControlPID=0\n", "", 1), " recovery properties are incomplete"
			case "duplicate":
				body, suffix = body+"MainPID=0\n", " recovery properties have duplicate fields"
			case "unknown_key":
				body, suffix = body+"PrivateKey=private-sentinel\n", " recovery properties are incomplete"
			case "malformed":
				body, suffix = "private-raw-output", " recovery properties are invalid"
			case "unknown_state":
				body, suffix = strings.Replace(body, "inactive", "private-state", 1), " recovery state is unknown"
			case "unknown_substate":
				body, suffix = strings.Replace(body, "dead", "private-substate", 1), " recovery substate is unknown"
			case "unknown_result":
				body, suffix = strings.Replace(body, "success", "private-result", 1), " recovery result is unknown"
			case "invalid_control":
				body, suffix = strings.Replace(body, "ControlPID=0", "ControlPID=private-pid", 1), " recovery properties are incomplete"
			case "negative_control":
				body, suffix = strings.Replace(body, "ControlPID=0", "ControlPID=-1", 1), " recovery properties are incomplete"
			case "oversize":
				body = strings.Repeat(" ", 4097)
			case "empty":
				body = ""
			case "error":
				originalErr = errors.New("private-original-error")
			}
			type outcome struct {
				observed manualHostRecoveryServiceProperties
				failure  string
				calls    int
			}
			var outcomes []outcome
			for _, enabled := range []bool{false, true} {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "pre_canceled" {
					cancel()
				}
				d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
				d.LifecycleHeld, d.Phase = true, "recovery_service"
				unread := d.Slots
				calls := 0
				inner := softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, dir string, env []string, name string, args ...string) (string, error) {
					calls++
					if dir != "/" || env != nil || name != "/usr/bin/systemctl" || !reflect.DeepEqual(args, []string{"show", "--property=ActiveState", "--property=SubState", "--property=MainPID", "--property=ControlPID", "--property=Result", unit}) {
						t.Fatal("manual reader changed its single fixed query")
					}
					if mode == "canceled" {
						cancel()
					}
					return body, originalErr
				})
				var selected CommandRunner = inner
				if enabled {
					selected = softwareClaimRecoveryDiagnosticRunner{inner, &d}
				}
				probe := softwareClaimRecoveryDiagnosticTestRunner(func(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
					output, err := selected.Run(ctx, dir, env, name, args...)
					if output != body || err != originalErr {
						t.Fatal("manual observation replaced the original output/error")
					}
					return output, err
				})
				observed, err := readManualHostUpgradeRecoveryServiceProperties(ctx, probe, unit)
				wantError := ""
				if suffix != "" {
					wantError = unit + suffix
				}
				if mode == "oversize" || mode == "empty" || mode == "error" {
					wantError = "read " + unit + " recovery properties"
				}
				if mode == "canceled" || mode == "pre_canceled" {
					wantError = context.Canceled.Error()
				}
				failure := ""
				if err != nil {
					failure = err.Error()
				}
				wantCalls := 1
				if mode == "pre_canceled" {
					wantCalls = 0
				}
				if failure != wantError || calls != wantCalls {
					t.Fatal("manual parser changed error text, context or query count")
				}
				if mode == "canceled" || mode == "pre_canceled" {
					if err != context.Canceled {
						t.Fatal("manual reader replaced the original context error")
					}
				}
				parsed := mode == "valid_zero" || mode == "main_positive" || mode == "control_positive"
				if parsed || mode == "canceled" {
					want := manualHostRecoveryServiceProperties{state: "inactive", subState: "dead", result: "success"}
					if mode == "main_positive" {
						want.mainPID = 42
					}
					if mode == "control_positive" {
						want.controlPID = 43
					}
					if observed != want {
						t.Fatal("manual parser changed its original successful/late-canceled result")
					}
				}
				if enabled && mode != "pre_canceled" {
					want := unread[0]
					want.State, want.StateCommand, want.PIDCommand, want.CombinedCommand, want.CombinedShape = "unknown", "success", "success", "success", "invalid"
					if parsed {
						want.State, want.PIDValid, want.PIDZero, want.CombinedShape = "inactive", true, mode != "main_positive", "valid"
						want.MainPIDKind, want.ControlPIDKind = "zero", "zero"
						if mode == "main_positive" {
							want.MainPIDKind = "positive"
						}
						if mode == "control_positive" {
							want.ControlPIDKind = "positive"
						}
					}
					if mode == "error" {
						want.StateCommand, want.PIDCommand, want.CombinedCommand, want.CombinedShape = "launch_other", "launch_other", "launch_other", "not_read"
					}
					if mode == "canceled" {
						want.StateCommand, want.PIDCommand, want.CombinedCommand, want.CombinedShape = "success", "success", "success", "not_read"
					}
					if d.Slots[0] != want {
						t.Fatal("manual observation accepted an incomplete query or lost actual metadata")
					}
				} else if d.Slots[0] != unread[0] {
					t.Fatal("unexecuted/disabled query fabricated metadata")
				}
				encoded, _ := json.Marshal(d)
				if !d.valid() || strings.Contains(string(encoded), "private-") || d.Slots[1] != unread[1] {
					t.Fatal("manual observation leaked raw input or invented the other slot")
				}
				outcomes = append(outcomes, outcome{observed, failure, calls})
			}
			if outcomes[0] != outcomes[1] {
				t.Fatal("manual diagnostic OFF/ON changed parser result/error/call count")
			}
		})
	}
	for _, slot := range []int{0, 1} {
		t.Run("r1_control_pid_refusal/"+[]string{"a", "b"}[slot], func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				fixture, _, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
				base := runtime.manual.runner
				var trace []string
				inner := softwareClaimRecoveryDiagnosticTestRunner(func(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
					output, err := base.Run(ctx, dir, env, name, args...)
					trace = append(trace, args[len(args)-1])
					if args[len(args)-1] == manualHostRecoveryUnitInstances[slot] {
						output = strings.Replace(output, "ControlPID=0", "ControlPID=43", 1)
					}
					return output, err
				})
				d := newSoftwareClaimRecoveryRootRefusal(request.SoftwareClaimRecovery.Request)
				runtime.manual.runner = inner
				if enabled {
					runtime.manual.runner = softwareClaimRecoveryDiagnosticRunner{inner, &d}
				}
				err := validateManualHostUpgradeRecoveryServicePreconditions(context.Background(), runtime.manual, false)
				want := []string{manualHostRecoveryUnitInstances[0]}
				if slot == 1 {
					want = append(want, manualHostRecoveryUnitInstances[1])
				}
				if err == nil || err.Error() != manualHostRecoveryUnitInstances[slot]+" must have no ControlPID" || !reflect.DeepEqual(trace, want) || fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 || fixture.runner.recoveryReloads != 0 || fixture.runner.recoveryResetFailedAttempts != 0 {
					t.Fatal("positive ControlPID lost strict refusal or changed a service/query")
				}
			}
		})
	}
}

func softwareClaimRecoveryQueryRoutingChecks(t *testing.T) {
	for _, slot := range []string{"a", "b"} {
		for _, mode := range []string{"manual", "complete", "swapped", "missing", "duplicate", "extra", "manual_all", "other_unit", "other_path", "other_dir", "environment", "complete_missing"} {
			t.Run("r1_query_route/"+slot+"/"+mode, func(t *testing.T) {
				unit := "autostream-host-self-update-recovery@" + slot + ".service"
				args := []string{"show", "--property=ActiveState", "--property=SubState", "--property=MainPID", "--property=ControlPID", "--property=Result", unit}
				dir, path := "/", "/usr/bin/systemctl"
				var env []string
				if mode == "complete" || mode == "complete_missing" {
					args = []string{"show", "--all"}
					for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
						args = append(args, "--property="+key)
					}
					args = append(args, unit)
				}
				switch mode {
				case "swapped":
					args[1], args[2] = args[2], args[1]
				case "missing", "complete_missing":
					args = append(args[:2], args[3:]...)
				case "duplicate":
					args[2] = args[1]
				case "extra":
					args = append(args[:6], "--property=PrivateKey", unit)
				case "manual_all":
					args = append([]string{"show", "--all"}, args[1:]...)
				case "other_unit":
					args[6] = "foreign.service"
				case "other_path":
					path = "/other/systemctl"
				case "other_dir":
					dir = "/other"
				case "environment":
					env = []string{"SAFE=original"}
				}
				manualOutput := "ActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nResult=success\n"
				originalErr := errors.New("private-original-error")
				wantOutput, wantErr := "private-original-output", error(originalErr)
				if mode == "manual" {
					wantOutput, wantErr = manualOutput, nil
				}
				if mode == "complete" {
					wantOutput, wantErr = softwareClaimRecoveryWatchdogUnitTestOutput(slot, softwareClaimRecoveryWatchdogUnitPath), nil
				}
				calls, fullCalls := 0, 0
				base := softwareClaimRecoveryDiagnosticTestRunner(func(_ context.Context, gotDir string, gotEnv []string, gotPath string, gotArgs ...string) (string, error) {
					calls++
					if gotDir != dir || gotPath != path || !reflect.DeepEqual(gotEnv, env) || !reflect.DeepEqual(gotArgs, args) {
						t.Fatal("fixture changed delegated input")
					}
					return wantOutput, wantErr
				})
				fixture := softwareClaimRecoveryWatchdogFixtureRunner{base: base, unitOutput: func(gotSlot string) string {
					fullCalls++
					if gotSlot != slot {
						t.Fatal("complete query routed to the wrong slot")
					}
					return softwareClaimRecoveryWatchdogUnitTestOutput(gotSlot, softwareClaimRecoveryWatchdogUnitPath)
				}}
				d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
				d.LifecycleHeld, d.Phase = true, "recovery_service"
				unread := d.Slots
				output, err := (softwareClaimRecoveryDiagnosticRunner{fixture, &d}).Run(context.Background(), dir, env, path, args...)
				wantCalls, wantFull := 1, 0
				if mode == "complete" {
					wantCalls, wantFull = 0, 1
				}
				if output != wantOutput || err != wantErr || calls != wantCalls || fullCalls != wantFull {
					t.Fatal("fixture conflated manual/full queries or changed pass-through output/error/calls")
				}
				index := 0
				if slot == "b" {
					index = 1
				}
				if mode == "manual" {
					if len(strings.Split(strings.TrimSuffix(output, "\n"), "\n")) != 5 || d.Slots[index].CombinedShape != "valid" {
						t.Fatal("manual route did not retain exactly five valid properties")
					}
				} else if mode == "complete" {
					parsed, parseErr := parseSoftwareClaimRecoveryWatchdogUnit(output, slot, softwareClaimRecoveryWatchdogUnitPath)
					if parseErr != nil || parsed.slot != slot || !isCanonicalBareSHA256(parsed.staticIdentity) || d.Slots[index].CombinedShape != "not_checked" {
						t.Fatal("complete route replaced original full-unit evidence")
					}
				} else if d.Slots != unread {
					t.Fatal("near-match/pass-through query fabricated metadata")
				}
				if d.Slots[1-index] != unread[1-index] {
					t.Fatal("query invented the unrequested slot")
				}
			})
		}
	}
}

type softwareClaimRecoveryR1ErrorReader struct {
	body []byte
	err  error
}

func (r *softwareClaimRecoveryR1ErrorReader) Read(p []byte) (int, error) {
	n := copy(p, r.body)
	r.body = r.body[n:]
	return n, r.err
}

func softwareClaimRecoveryR1ProcessParityChecks(t *testing.T) {
	for _, site := range []string{"initial", "final"} {
		for _, code := range []string{"ENOENT", "ENODEV", "EACCES", "OTHER", "steady", "never_settles", "canceled", "shape"} {
			t.Run("r1_process_parity/"+site+"/"+code, func(t *testing.T) {
				var signatures []string
				for _, enabled := range []bool{false, true} {
					group := "/system.slice/autostream-host-self-update-recovery@a.service"
					units := []softwareClaimRecoveryWatchdogUnit{{slot: "a", controlGroup: group, staticIdentity: "a"}, {slot: "b", staticIdentity: "b"}}
					if code == "shape" {
						units[0].controlGroup = "/system.slice/foreign.service"
					}
					if code == "never_settles" {
						units[0].mainPID = 42
					}
					var injected error
					switch code {
					case "ENOENT":
						injected = syscall.ENOENT
					case "ENODEV":
						injected = syscall.ENODEV
					case "EACCES":
						injected = syscall.EACCES
					case "OTHER":
						injected = errors.New("private ENOENT text")
					}
					// Only positive-PID initial ENOENT now joins the existing
					// bounded full observation; other errors still refuse.
					if site == "initial" && injected != nil {
						units[0].mainPID = 42
					}
					calls, joins := 0, 0
					rt := softwareClaimWatchdogProcessRuntime{read: func(int) (softwareClaimWatchdogProcessObservation, error) {
						return softwareClaimWatchdogProcessObservation{}, errors.New("must not read unknown PID")
					}, binary: func(context.Context, int, string, os.FileInfo) error { return nil }, sameLock: func(int) error { return nil },
						members: func(string) ([]int, error) {
							calls++
							if injected != nil && (site == "initial" || calls%2 == 0) {
								return nil, injected
							}
							return []int{}, nil
						},
						units: func(context.Context) ([]softwareClaimRecoveryWatchdogUnit, error) { joins++; return units, nil }}
					d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
					if enabled {
						rt.diagnostic = &d
					}
					ctx := context.Background()
					if code == "canceled" {
						c, cancel := context.WithCancel(ctx)
						cancel()
						ctx = c
					}
					err := verifySoftwareClaimWatchdogProcessRuntime(ctx, "/protected/slots", units, nil, rt)
					reason := "success"
					if err != nil {
						var authority softwareClaimWatchdogAuthorityError
						if !errors.As(err, &authority) {
							t.Fatal("guard error type changed")
						}
						reason = authority.reason
					}
					signatures = append(signatures, fmt.Sprintf("%s/%d/%d", reason, calls, joins))
					if enabled && code == "canceled" && d.Process != nil {
						t.Fatal("canceled operation collected a fabricated process view")
					}
					if enabled && injected != nil && d.Process != nil {
						wantSite := "initial_members"
						if site == "final" {
							wantSite = "final_members"
						}
						if d.Process.Site != wantSite || d.Process.Errno != softwareClaimRecoveryErrno(injected) || d.Process.ReaderStage != "not_captured" {
							t.Fatal("initial/final or original callback errno lost")
						}
					}
					if code == "never_settles" && joins != 3 {
						t.Fatal("existing three-join limit changed")
					}
					if site == "initial" && code == "ENOENT" && (reason != "process_transition" || calls != 4 || joins != 3) {
						t.Fatal("positive-PID initial ENOENT did not retain the four-observation bound")
					}
					if site == "initial" && (code == "ENODEV" || code == "EACCES" || code == "OTHER") && joins != 0 {
						t.Fatal("other errno gained an observation retry")
					}
				}
				if !reflect.DeepEqual(signatures[:1], signatures[1:]) {
					t.Fatal("diagnostic changed original result/member reads/unit joins")
				}
			})
		}
	}
	t.Run("r1_namespace_canceled_unknown", func(t *testing.T) {
		d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
		unit := softwareClaimRecoveryWatchdogUnit{slot: "a", mainPID: os.Getpid()}
		d.observeProcess(1, unit, "initial_members")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		d.observeCgroupRefusal(ctx, unit)
		for _, n := range d.Process.Namespaces {
			if n.PID != "unknown" || n.Cgroup != "unknown" || n.Mount != "unknown" {
				t.Fatal("canceled namespace read fabricated equality")
			}
		}
		if !d.Process.Refused || !d.Process.valid() {
			t.Fatal("diagnostic failure hid original refusal")
		}
	})
}
