//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/example/autostream-contracts/pkg/contracts"
)

type dockerSmokeDiagnosticLog struct{ strings.Builder }

func (*dockerSmokeDiagnosticLog) Helper() {}
func (l *dockerSmokeDiagnosticLog) Logf(format string, args ...any) {
	fmt.Fprintf(&l.Builder, format+"\n", args...)
}

type dockerSmokeDiagnosticCommand func(context.Context, string, []string, string, ...string) (string, error)

func (f dockerSmokeDiagnosticCommand) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	return f(ctx, dir, env, name, args...)
}

func TestDockerSmokeDiagnosticChildReturn(t *testing.T) {
	for _, test := range []struct {
		name, path, operation, crash, expected string
		expectGrant                            bool
		consumed                               int
	}{
		{"missing_response", "", "port_reconfigure", "after_restart", "applied", true, 1},
		{"grant_mismatch", "present", "port_reconfigure", "", "applied", true, 0},
		{"both", "", "port_reconfigure", "after_target_verify", "applied", true, 0},
		{"reconcile_rollback", "", "port_reconfigure_reconcile", "", "rolled_back", true, 1},
		{"reconcile_applied", "present", "port_reconfigure_reconcile", "", "applied", false, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &dockerPortSmokeRunner{}
			runner.beginSTPortDiagnostic("combined_recovery", true)
			payload := dockerPortSmokeChildPayload{
				Plan: SystemdPortReconfigurePlan{PortContractVersion: 2}, Operation: test.operation,
				ResponsePath: test.path, ExpectGrant: test.expectGrant,
			}
			response := LocalExecutorResponse{Version: LocalExecutorMutationProtocolVersion,
				Error: &LocalExecutorFailure{Code: "mutation_precondition_failed", Message: "precondition failed"}}
			var log dockerSmokeDiagnosticLog
			// The two former fatal branches share this actual child-return helper.
			runner.logSTPortChildReturn(&log, payload, test.crash, response, test.consumed)
			runner.logSTPortChildReturn(&log, payload, test.crash, response, test.consumed)
			for _, label := range []string{"child return:", "Docker smoke result:", "Docker smoke boundary:"} {
				if strings.Count(log.String(), label) != 1 {
					t.Fatal("child return summary missing or duplicated")
				}
			}
			for _, field := range []string{
				"expected=" + test.expected, "response_valid=true", "port_present=false", "nested_present=false",
				"plan_match=false", "state_known=false", "recovery_required=false", "error_code=mutation_precondition_failed",
				fmt.Sprintf("consume_count=%d", test.consumed),
				fmt.Sprintf("response_path_present=%t", test.path != ""),
				fmt.Sprintf("grant_count_matches=%t", test.expectGrant == (test.consumed == 1)),
				fmt.Sprintf("returned_before_expected_crash=%t", test.crash != ""),
			} {
				if !strings.Contains(log.String(), field) {
					t.Fatalf("missing fixed diagnostic field %s", field)
				}
			}
			if log.Len() > 4096 {
				t.Fatal("child summary exceeds 4 KiB")
			}
		})
	}
}

func TestDockerSmokeDiagnosticResultPreservation(t *testing.T) {
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	response := h.run(t, "port_reconfigure")
	if response.Validate() != nil || response.PortResult == nil || !portV2AcceptedResultMatchesPlan(h.plan, *response.PortResult) {
		t.Fatal("expected valid product result for the existing plan")
	}
	payload := dockerPortSmokeChildPayload{Plan: h.plan, Operation: "port_reconfigure", ExpectGrant: true}
	before, err := json.Marshal([]any{payload, response})
	if err != nil {
		t.Fatal("cannot snapshot diagnostic inputs")
	}
	counts := h.runtime.mutationCounts()
	runner := &dockerPortSmokeRunner{}
	runner.beginSTPortDiagnostic("combined_recovery", true)
	var log dockerSmokeDiagnosticLog
	runner.logSTPortChildReturn(&log, payload, "after_restart", response, 1)
	after, err := json.Marshal([]any{payload, response})
	if err != nil || string(before) != string(after) || counts != h.runtime.mutationCounts() {
		t.Fatal("diagnostic changed response, plan or completed processing")
	}
	for _, field := range []string{"actual=applied", "status=succeeded", "response_valid=true", "port_present=true", "nested_present=true", "plan_match=true", "state_known=true", "recovery_required=false"} {
		if !strings.Contains(log.String(), field) {
			t.Fatalf("missing valid-result diagnostic field %s", field)
		}
	}
}

func TestDockerSmokeDiagnosticNormalReturn(t *testing.T) {
	runner := &dockerPortSmokeRunner{}
	runner.beginSTPortDiagnostic("combined_recovery", false)
	before := runner.stPortDiagnostic
	if err := runner.observeSTPortPhase("after_restart"); err != nil {
		t.Fatal("phase observer changed result")
	}
	runner.observeSTPortRunner(dockerPortSmokeRunnerObservation{phase: "command"}, true)
	if runner.stPortDiagnostic != before {
		t.Fatal("disabled observer changed diagnostic state")
	}
	var log dockerSmokeDiagnosticLog
	for _, payload := range []dockerPortSmokeChildPayload{
		{Plan: SystemdPortReconfigurePlan{PortContractVersion: 2}, ResponsePath: "present", ExpectGrant: true},
		{Plan: SystemdPortReconfigurePlan{PortContractVersion: 0}},
	} {
		runner.logSTPortChildReturn(&log, payload, "", LocalExecutorResponse{}, 1)
	}
	if log.Len() != 0 || runner.stPortDiagnostic != before {
		t.Fatal("normal or non-versioned return produced diagnostics")
	}
}

func TestDockerSmokeDiagnosticBoundaries(t *testing.T) {
	for _, phase := range []string{"command", "compose_capture", "mapping_read", "mapping_parse", "listener_tcp", "listener_identity", "unknown"} {
		t.Run(phase, func(t *testing.T) {
			runner := &dockerPortSmokeRunner{}
			runner.beginSTPortDiagnostic("combined_recovery", true)
			runner.observeSTPortRunner(dockerPortSmokeRunnerObservation{phase: phase, substage: "fixture_http"}, true)
			first := runner.stPortDiagnostic
			runner.observeSTPortRunner(dockerPortSmokeRunnerObservation{phase: "command"}, true)
			runner.observeSTPortRunner(dockerPortSmokeRunnerObservation{phase: "command"}, false)
			if first.firstFailure != phase || first.firstFailure != runner.stPortDiagnostic.firstFailure ||
				first.firstFailureSubstage != runner.stPortDiagnostic.firstFailureSubstage || runner.stPortDiagnostic.runnerCalls != 3 {
				t.Fatal("runner boundary was lost or overwritten")
			}
		})
	}
}

func TestDockerSmokeDiagnosticBoundsAndSecrets(t *testing.T) {
	const sentinel = "DIAGNOSTIC_SECRET_SENTINEL"
	unknown := strings.Repeat(sentinel, 512)
	runner := &dockerPortSmokeRunner{}
	runner.beginSTPortDiagnostic("combined_recovery", true)
	for i := 0; i < 64; i++ {
		_ = runner.observeSTPortPhase("after_grant_consume")
	}
	for i := 0; i < 256; i++ {
		runner.observeSTPortRunner(dockerPortSmokeRunnerObservation{phase: unknown, substage: unknown}, true)
	}
	if runner.stPortDiagnostic.phaseCapped || runner.stPortDiagnostic.runnerCapped {
		t.Fatal("counters capped before their existing limits")
	}
	for i := 0; i < 300; i++ {
		_ = runner.observeSTPortPhase(unknown)
		runner.observeSTPortRunner(dockerPortSmokeRunnerObservation{phase: "command"}, false)
	}
	var log dockerSmokeDiagnosticLog
	response := LocalExecutorResponse{Version: 1000000, SessionID: unknown, PlanSHA256: unknown,
		PortResult: &SystemdPortReconfigureResult{Result: unknown, Status: unknown, Message: unknown},
		Error:      &LocalExecutorFailure{Code: unknown, Message: unknown}}
	payload := dockerPortSmokeChildPayload{Plan: SystemdPortReconfigurePlan{PortContractVersion: 2, JobID: unknown}, Operation: unknown, ExpectGrant: true}
	runner.logSTPortChildReturn(&log, payload, unknown, response, 1000000)
	for _, field := range []string{"expected=applied", "actual=unknown", "status=unknown", "version=-1", "error_code=unknown", "consume_count=-1",
		"crash_phase=unknown", "first_phase=after_grant_consume", "last_phase=unknown", "phase_calls=64", "phase_capped=true",
		"first_runner_failure=unknown", "first_runner_substage=unknown", "runner_calls=256", "runner_capped=true"} {
		if !strings.Contains(log.String(), field) {
			t.Fatalf("missing bounded diagnostic field %s", field)
		}
	}
	if strings.Contains(log.String(), sentinel) || log.Len() > 4096 {
		t.Fatal("diagnostic disclosed unknown input or exceeded its bound")
	}
	// A phase from a different process/step must not be attributed to this result.
	log.Reset()
	runner.logSTPortResultFailure(&log, unknown, response, payload.Plan, unknown, -2)
	if strings.Contains(log.String(), sentinel) || !strings.Contains(log.String(), "first_phase=none") ||
		!strings.Contains(log.String(), "first_runner_failure=none") || !strings.Contains(log.String(), "same_process_observation=false") {
		t.Fatal("unknown step reused unrelated evidence")
	}
}

func TestDockerSmokeDiagnosticRunnerResultUnchanged(t *testing.T) {
	const sentinel = "DIAGNOSTIC_RUNNER_SECRET_SENTINEL"
	cause := errors.New(sentinel)
	original := fmt.Errorf("%s: %w", sentinel, cause)
	for _, active := range []bool{false, true} {
		calls := 0
		ctx := context.Background()
		env, args := []string{sentinel}, []string{"info", sentinel}
		runner := &dockerPortSmokeRunner{base: dockerSmokeDiagnosticCommand(func(gotCtx context.Context, dir string, gotEnv []string, name string, gotArgs ...string) (string, error) {
			calls++
			if gotCtx != ctx || dir != sentinel || name != sentinel || !reflect.DeepEqual(env, gotEnv) || !reflect.DeepEqual(args, gotArgs) {
				t.Fatal("diagnostics changed runner inputs")
			}
			return sentinel, original
		})}
		runner.beginSTPortDiagnostic("combined_recovery", active)
		output, err := runner.Run(ctx, sentinel, env, sentinel, args...)
		if calls != 1 || output != sentinel || err != original || errors.Unwrap(err) != cause || !errors.Is(err, cause) {
			t.Fatal("diagnostics changed command count, output or error identity")
		}
		var log dockerSmokeDiagnosticLog
		runner.logSTPortResultFailure(&log, "combined_recovery", LocalExecutorResponse{}, SystemdPortReconfigurePlan{}, "unknown", 0)
		expectedCalls := 0
		if active {
			expectedCalls = calls
		}
		if strings.Contains(log.String(), sentinel) || runner.stPortDiagnostic.active != active || runner.stPortDiagnostic.runnerCalls != expectedCalls {
			t.Fatal("runner diagnostic disclosed data or observed a disabled call")
		}
	}
}

func TestDockerSmokeDiagnosticListenerStages(t *testing.T) {
	root := t.TempDir()
	runner := &dockerPortSmokeRunner{captureDir: filepath.Join(root, "captures")}
	for _, test := range []struct{ name, body, stage string }{
		{"missing", "", "execution_read"},
		{"decode", "{", "execution_decode"},
		{"source", `{"configs":{"listener":{"file":"/foreign/listener"}}}`, "listener_source"},
		{"cancelled", "", "context"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, test.name+".json")
			ctx := context.Background()
			body := []byte(test.body)
			if test.name == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				body, _ = json.Marshal(map[string]any{"configs": map[string]any{"listener": map[string]string{"file": filepath.Join(root, "docker-listener-configs", "worker", "absent")}}})
			}
			if len(body) != 0 {
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal("cannot prepare execution fixture")
				}
			}
			observation := dockerPortSmokeRunnerObservation{phase: "listener_identity"}
			err := runner.verifyMountedListener(ctx, path, 0, &observation)
			if err == nil || observation.substage != test.stage {
				t.Fatal("listener helper lost its observed failure stage")
			}
			if test.name == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("read error identity changed")
			}
			if test.name == "cancelled" && err != context.Canceled {
				t.Fatal("context error identity changed")
			}
		})
	}
	observation := dockerPortSmokeRunnerObservation{phase: "listener_identity"}
	if err := verifyDockerPortSmokeListenerFileObserved(filepath.Join(root, "absent"), 0, &observation); err == nil || observation.substage != "listener_file" {
		t.Fatal("local listener identity failure lost its stage")
	}
}

func TestDockerSmokeDiagnosticListenerMatches(t *testing.T) {
	record := dockerPortSmokeListenerRecord{Path: "DIAGNOSTIC_PATH_SENTINEL", SHA256: "DIAGNOSTIC_DIGEST_SENTINEL", Device: 3, Inode: 5}
	for _, stage := range []string{"execution_read", "execution_decode", "listener_source", "context", "listener_file", "fixture_http", "identity_match", "DIAGNOSTIC_STAGE_SENTINEL"} {
		observation := dockerPortSmokeRunnerObservation{phase: "listener_identity"}
		observation.atListenerStage(stage)
		observation.observeListenerMatch(record, record.SHA256, record.Device, record.Inode+1)
		runner := &dockerPortSmokeRunner{}
		runner.beginSTPortDiagnostic("combined_recovery", true)
		runner.observeSTPortRunner(observation, true)
		runner.observeSTPortRunner(dockerPortSmokeRunnerObservation{phase: "command"}, true)
		var log dockerSmokeDiagnosticLog
		runner.logSTPortResultFailure(&log, "combined_recovery", LocalExecutorResponse{}, SystemdPortReconfigurePlan{}, "unknown", 0)
		expected := stage
		if strings.Contains(stage, "SENTINEL") {
			expected = "unknown"
		}
		for _, field := range []string{"first_runner_failure=listener_identity", "first_runner_substage=" + expected,
			"first_failure_identity_compared=true", "first_failure_bytes_match=true", "first_failure_device_match=true", "first_failure_inode_match=false"} {
			if !strings.Contains(log.String(), field) {
				t.Fatalf("missing listener diagnostic field %s", field)
			}
		}
		if strings.Contains(log.String(), "SENTINEL") {
			t.Fatal("listener diagnostic disclosed an unknown value")
		}
	}
	for _, actual := range []dockerPortSmokeListenerRecord{
		record, {SHA256: "different", Device: 3, Inode: 5}, {SHA256: record.SHA256, Device: 4, Inode: 5},
	} {
		var observation dockerPortSmokeRunnerObservation
		observation.observeListenerMatch(record, actual.SHA256, actual.Device, actual.Inode)
		if !observation.identity.compared || observation.identity.bytesMatch != (record.SHA256 == actual.SHA256) ||
			observation.identity.deviceMatch != (record.Device == actual.Device) || observation.identity.inodeMatch != (record.Inode == actual.Inode) {
			t.Fatal("listener comparison observation changed")
		}
	}
}
