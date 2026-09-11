//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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

type dockerSmokeDiagnosticAssertion struct {
	dockerSmokeDiagnosticLog
	fatals int
}

var dockerSmokeDiagnosticFatal = &struct{ stopped bool }{true}

func (l *dockerSmokeDiagnosticAssertion) Fatalf(format string, args ...any) {
	l.fatals++
	l.Logf(format, args...)
	panic(dockerSmokeDiagnosticFatal) // Stand in for testing.T's non-returning Fatalf.
}

func captureDockerSmokeRollback(t *testing.T, log *dockerSmokeDiagnosticAssertion, response LocalExecutorResponse, plan SystemdPortReconfigurePlan) (failed bool) {
	t.Helper()
	defer func() {
		if failure := recover(); failure != nil {
			if failure != dockerSmokeDiagnosticFatal {
				panic(failure)
			}
			failed = true
		}
	}()
	assertDockerPortSmokeRolledBack(log, response, plan)
	return false
}

// The pre-diagnostic eight-condition oracle, compared with the real assertion.
func originalDockerSmokeRollbackMismatch(response LocalExecutorResponse, plan SystemdPortReconfigurePlan) bool {
	return response.Validate() != nil || response.PortResult == nil || response.PortResult.Result != systemdPortResultRolledBack ||
		response.PortResult.Docker == nil || response.PortResult.AppliedPort != plan.OldPort ||
		response.PortResult.Docker.AppliedPublishedPort != plan.Docker.OldPublishedPort ||
		response.PortResult.Docker.AppliedContainerPort != plan.Docker.OldContainerPort ||
		response.PortResult.Docker.AppliedHealthPort != plan.Docker.OldHealthPort
}

func dockerSmokeLegacyResult(t *testing.T) (dockerPortHarness, LocalExecutorResponse) {
	t.Helper()
	h := newDockerPortHarness(t)
	h.runtime.failTargetRecreate = true
	response := executeDockerPortRequest(context.Background(), h.policy, h.request("port_reconfigure"), h.runtime, h.state)
	if response.Validate() != nil || originalDockerSmokeRollbackMismatch(response, h.plan) || response.PortResult.PortContractVersion != 0 {
		t.Fatal("existing root-free fixture did not produce a valid legacy rollback")
	}
	return h, response
}

type dockerSmokeObservedRuntime struct {
	dockerPortRuntime
	crash func(string) error
}

func (r dockerSmokeObservedRuntime) CrashPoint(point string) error { return r.crash(point) }

func TestDockerSmokeDiagnosticLegacyMutation(t *testing.T) {
	control, _ := dockerSmokeLegacyResult(t)
	h := newDockerPortHarness(t)
	h.runtime.failTargetRecreate = true
	request := h.request("port_reconfigure")
	before, _ := json.Marshal([]any{request, h.plan, h.policy})
	var log dockerSmokeDiagnosticAssertion
	runner, calls := &dockerPortSmokeRunner{}, 0
	var returned LocalExecutorResponse
	response, grants := observeDockerPortSmokeUnhealthyMutation(&log, runner, h.plan, func(scope *dockerPortSmokeLegacyDiagnostic) (LocalExecutorResponse, int) {
		calls++
		returned = executeDockerPortRequest(scope.withFailureObserver(context.Background()), h.policy, request,
			dockerSmokeObservedRuntime{h.runtime, scope.wrapCrashPoint(h.runtime.CrashPoint)}, h.state)
		return returned, h.runtime.consumeCalls
	})
	after, _ := json.Marshal([]any{request, h.plan, h.policy})
	if calls != 1 || grants != 1 || response.PortResult != returned.PortResult || response.Error != returned.Error || string(before) != string(after) {
		t.Fatal("diagnostic changed mutation count, request, plan, grant or response identity")
	}
	counts := func(r *fakeDockerPortRuntime) [4]int {
		return [4]int{r.consumeCalls, r.writeCalls, r.restoreCalls, r.recreateCalls}
	}
	if counts(h.runtime) != counts(control.runtime) || runner.legacyDiagnostic != nil {
		t.Fatal("diagnostic changed runtime calls or left its scope open")
	}
	if captureDockerSmokeRollback(t, &log, response, h.plan) || log.fatals != 0 {
		t.Fatal("real rollback assertion changed success")
	}
	for _, field := range []string{"response_valid=true", "version=v2 contract=legacy", "actual=rolled_back", "state_known=true", "recovery_required=not_applicable", "grant_count_matches=true", "local_failure_observed=false", "first_local_phase=unobserved", "first_phase=after_grant_consume"} {
		if !strings.Contains(log.String(), field) {
			t.Fatalf("missing fixed field %s", field)
		}
	}
	if strings.Count(log.String(), "Docker smoke legacy rollback:") != 1 || strings.Count(log.String(), "Docker smoke legacy boundary:") != 1 || log.Len() > 4096 {
		t.Fatal("successful mutation summary missing, duplicated or unbounded")
	}
}

func TestDockerSmokeDiagnosticLegacyResults(t *testing.T) {
	for _, test := range []struct {
		name, field string
		change      func(*LocalExecutorResponse)
	}{
		{"normal", "actual=rolled_back", func(*LocalExecutorResponse) {}},
		{"missing_port", "port_present=false", func(r *LocalExecutorResponse) { r.PortResult = nil }},
		{"missing_docker", "docker_present=false", func(r *LocalExecutorResponse) { r.PortResult.Docker = nil }},
		{"applied", "actual=applied", func(r *LocalExecutorResponse) { r.PortResult.Result = systemdPortResultApplied }},
		{"unchanged", "actual=unchanged", func(r *LocalExecutorResponse) { r.PortResult.Result = systemdPortResultUnchanged }},
		{"rollback_failed", "actual=rollback_failed", func(r *LocalExecutorResponse) { r.PortResult.Result = systemdPortResultRollbackFailed }},
		{"unknown", "actual=unknown", func(r *LocalExecutorResponse) { r.PortResult.Result = "SECRET_UNKNOWN_RESULT" }},
		{"invalid_response", "response_valid=false", func(r *LocalExecutorResponse) { r.Version = -99 }},
		{"unknown_contract", "contract=unknown", func(r *LocalExecutorResponse) { r.PortResult.PortContractVersion = 99 }},
		{"invalid_message", "response_valid=false", func(r *LocalExecutorResponse) { r.PortResult.Message = "secret\nmessage" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, response := dockerSmokeLegacyResult(t)
			test.change(&response)
			before, _ := json.Marshal(response)
			var log dockerSmokeDiagnosticAssertion
			observeDockerPortSmokeUnhealthyMutation(&log, &dockerPortSmokeRunner{}, h.plan, func(*dockerPortSmokeLegacyDiagnostic) (LocalExecutorResponse, int) { return response, 1 })
			failed := captureDockerSmokeRollback(t, &log, response, h.plan)
			after, _ := json.Marshal(response)
			if failed != (test.name != "normal") || failed != originalDockerSmokeRollbackMismatch(response, h.plan) || string(before) != string(after) {
				t.Fatal("real assertion or diagnostic changed the legacy result/acceptance condition")
			}
			if !strings.Contains(log.String(), test.field) || strings.Contains(log.String(), "SECRET") || strings.Contains(log.String(), "secret") || log.Len() > 4096 {
				t.Fatal("missing, unsafe or unbounded legacy result summary")
			}
		})
	}
}

func TestDockerSmokeDiagnosticLegacyPorts(t *testing.T) {
	for index, name := range []string{"advertised", "published", "container", "health"} {
		t.Run(name, func(t *testing.T) {
			h, response := dockerSmokeLegacyResult(t)
			ports := []*int{&h.plan.OldPort, &h.plan.Docker.OldPublishedPort, &h.plan.Docker.OldContainerPort, &h.plan.Docker.OldHealthPort}
			*ports[index]++
			var log dockerSmokeDiagnosticAssertion
			if !captureDockerSmokeRollback(t, &log, response, h.plan) || !originalDockerSmokeRollbackMismatch(response, h.plan) {
				t.Fatal("old port mismatch passed")
			}
			for other, label := range []string{"advertised", "published", "container", "health"} {
				if !strings.Contains(log.String(), fmt.Sprintf("old_%s_match=%t", label, other != index)) {
					t.Fatal("old port mismatch was not isolated")
				}
			}
		})
	}
	// Diagnostic new-plan comparisons are not additional acceptance conditions.
	h, response := dockerSmokeLegacyResult(t)
	h.plan.NewPort = h.plan.OldPort
	h.plan.Docker.NewPublishedPort, h.plan.Docker.NewContainerPort, h.plan.Docker.NewHealthPort = h.plan.Docker.OldPublishedPort, h.plan.Docker.OldContainerPort, h.plan.Docker.OldHealthPort
	var log dockerSmokeDiagnosticAssertion
	if captureDockerSmokeRollback(t, &log, response, h.plan) {
		t.Fatal("new-plan comparisons changed rollback acceptance")
	}
	for _, label := range []string{"advertised", "published", "container", "health"} {
		if !strings.Contains(dockerPortSmokeRollbackSummary(response, h.plan), "new_"+label+"_match=true") {
			t.Fatal("new-plan match not reported")
		}
	}
}

func TestDockerSmokeDiagnosticLegacyGrantsAndBindings(t *testing.T) {
	for _, count := range []int{-1, 0, 1, 2, 64, 1000000} {
		t.Run(fmt.Sprintf("count_%d", count), func(t *testing.T) {
			h, response := dockerSmokeLegacyResult(t)
			response.PlanSHA256, response.SessionID = strings.Repeat("e", 64), "other-valid-session-0123456789"
			var log dockerSmokeDiagnosticAssertion
			got, grants := observeDockerPortSmokeUnhealthyMutation(&log, &dockerPortSmokeRunner{}, h.plan, func(*dockerPortSmokeLegacyDiagnostic) (LocalExecutorResponse, int) { return response, count })
			if grants != count || got.PortResult != response.PortResult || captureDockerSmokeRollback(t, &log, got, h.plan) {
				t.Fatal("diagnostic changed grant count, result or original rollback assertion")
			}
			for _, field := range []string{fmt.Sprintf("grant_count=%d", dockerPortSmokeBoundedCount(count, 64)), fmt.Sprintf("grant_count_matches=%t", count == 1), "plan_match=false", "session_match=false"} {
				if !strings.Contains(log.String(), field) {
					t.Fatalf("missing fixed field %s", field)
				}
			}
		})
	}
}

func TestDockerSmokeDiagnosticLegacyScopeIsolation(t *testing.T) {
	runner := &dockerPortSmokeRunner{}
	var log dockerSmokeDiagnosticLog
	var absent *dockerPortSmokeLegacyDiagnostic
	absent.observeRunner(dockerPortSmokeRunnerObservation{}, true)
	absent.logReturn(&log, LocalExecutorResponse{}, SystemdPortReconfigurePlan{}, 0)
	first := runner.beginLegacyDiagnostic()
	first.observeRunner(dockerPortSmokeRunnerObservation{phase: "command"}, true)
	second := runner.beginLegacyDiagnostic()
	first.observeRunner(dockerPortSmokeRunnerObservation{phase: "mapping_read"}, true)
	first.logReturn(&log, LocalExecutorResponse{}, SystemdPortReconfigurePlan{}, 0)
	otherProcess := (&dockerPortSmokeRunner{}).beginLegacyDiagnostic()
	otherProcess.observeRunner(dockerPortSmokeRunnerObservation{phase: "listener_tcp"}, true)
	second.logReturn(&log, LocalExecutorResponse{}, SystemdPortReconfigurePlan{}, 0)
	second.logReturn(&log, LocalExecutorResponse{}, SystemdPortReconfigurePlan{}, 0)
	if strings.Count(log.String(), "Docker smoke legacy rollback:") != 1 || !strings.Contains(log.String(), "runner_failure_observed=false") || second.runnerCalls != 0 || first.runnerCalls != 1 {
		t.Fatal("scope mixed a previous, inactive or other-process observation")
	}
	second.close()
	second.wrapCrashPoint(nil)("after_grant_consume")
	second.observeRunner(dockerPortSmokeRunnerObservation{phase: "command"}, true)
	if second.phaseCalls != 0 || second.runnerCalls != 0 {
		t.Fatal("closed scope kept observing")
	}
	// A command begun in the old scope returns after the new scope starts.
	var next *dockerPortSmokeLegacyDiagnostic
	runner.base = dockerSmokeDiagnosticCommand(func(context.Context, string, []string, string, ...string) (string, error) {
		next = runner.beginLegacyDiagnostic()
		return "private-output", errors.New("private-error")
	})
	runner.beginLegacyDiagnostic()
	runner.Run(context.Background(), "", nil, "fixture-command")
	if next.runnerCalls != 0 {
		t.Fatal("late command was charged to a later mutation")
	}
}

func TestDockerSmokeDiagnosticLegacyBoundaryPreservation(t *testing.T) {
	cause := errors.New("PRIVATE_RUNNER_ERROR")
	original := fmt.Errorf("PRIVATE_WRAPPER: %w", cause)
	ctx := context.Background()
	env, args := []string{"PRIVATE_ENV"}, []string{"PRIVATE_ARG"}
	calls := 0
	runner := &dockerPortSmokeRunner{base: dockerSmokeDiagnosticCommand(func(got context.Context, dir string, gotEnv []string, name string, gotArgs ...string) (string, error) {
		calls++
		if got != ctx || dir != "PRIVATE_DIR" || name != "PRIVATE_COMMAND" || !reflect.DeepEqual(gotEnv, env) || !reflect.DeepEqual(gotArgs, args) {
			t.Fatal("runner inputs changed")
		}
		return "PRIVATE_OUTPUT", original
	})}
	scope := runner.beginLegacyDiagnostic()
	output, err := runner.Run(ctx, "PRIVATE_DIR", env, "PRIVATE_COMMAND", args...)
	if calls != 1 || output != "PRIVATE_OUTPUT" || err != original || errors.Unwrap(err) != cause {
		t.Fatal("runner return, error identity or count changed")
	}
	scope.observeRunner(dockerPortSmokeRunnerObservation{phase: "listener_identity", substage: "identity_match", identity: dockerPortSmokeIdentityObservation{true, true, false, true}}, true)
	hookCalls, callbackCalls := 0, 0
	hook := scope.wrapCrashPoint(func(point string) error {
		hookCalls++
		if point != "after_port_env_write" {
			t.Fatal("original hook argument changed")
		}
		return original
	})
	if hook("after_port_env_write") != original || hookCalls != 1 {
		t.Fatal("original hook result/count changed")
	}
	if scope.wrapCrashPoint(nil)("after_docker_recreate") != nil {
		t.Fatal("nil hook changed success")
	}
	ctx = context.WithValue(ctx, localExecutionFailureContextKey{}, func(phase localExecutionFailurePhase, class localExecutionFailureClass) {
		callbackCalls++
		if phase != localFailureDockerListener || class != localFailureCanceled {
			t.Fatal("original failure callback arguments changed")
		}
	})
	observed := scope.withFailureObserver(ctx)
	observeLocalExecutionFailure(observed, localFailureDockerListener, context.Canceled)
	observeLocalExecutionFailure(scope.withFailureObserver(context.Background()), localFailureHTTPHealth, context.DeadlineExceeded)
	var log dockerSmokeDiagnosticLog
	scope.logReturn(&log, LocalExecutorResponse{}, SystemdPortReconfigurePlan{}, 0)
	for _, field := range []string{"first_runner_failure=command", "last_runner_failure=listener_identity", "last_runner_substage=identity_match", "first_phase=after_port_env_write", "last_phase=after_docker_recreate", "local_failure_observed=true", "first_local_phase=docker_listener", "last_local_phase=http_health", "first_local_class=canceled", "last_local_class=deadline"} {
		if !strings.Contains(log.String(), field) {
			t.Fatalf("missing fixed boundary %s", field)
		}
	}
	if callbackCalls != 1 || strings.Contains(log.String(), "PRIVATE") || log.Len() > 4096 {
		t.Fatal("callback changed or diagnostic disclosed private data")
	}
}

func TestDockerSmokeDiagnosticLegacyBoundsAndSecrets(t *testing.T) {
	secret := strings.Repeat("PRIVATE_TOKEN_PATH_ID_DIGEST_ERROR", 512)
	for _, grants := range []int{-100, 1000000} {
		scope := (&dockerPortSmokeRunner{}).beginLegacyDiagnostic()
		for i := 0; i < 300; i++ {
			scope.wrapCrashPoint(nil)(secret)
			scope.observeRunner(dockerPortSmokeRunnerObservation{phase: secret, substage: secret}, true)
			callback := scope.withFailureObserver(context.Background()).Value(localExecutionFailureContextKey{}).(func(localExecutionFailurePhase, localExecutionFailureClass))
			callback(255, 255)
		}
		var log dockerSmokeDiagnosticAssertion
		response := LocalExecutorResponse{Version: -1000000, SessionID: secret, PlanSHA256: secret, Error: &LocalExecutorFailure{Code: secret, Message: secret}, PortResult: &SystemdPortReconfigureResult{Result: secret, Status: secret, Message: secret, PortContractVersion: -1}}
		plan := SystemdPortReconfigurePlan{SessionID: secret, PortPlanSHA256: secret}
		scope.logReturn(&log, response, plan, grants)
		captureDockerSmokeRollback(t, &log, response, plan)
		for _, field := range []string{"version=unknown", "contract=unknown", "actual=unknown", "error_present=true error_code=unknown", "grant_count=-1", "phase_calls=64 phase_capped=true", "runner_calls=256 runner_capped=true", "local_calls=64 local_capped=true"} {
			if !strings.Contains(log.String(), field) {
				t.Fatalf("missing bounded field %s", field)
			}
		}
		if strings.Contains(log.String(), "PRIVATE") || log.Len() > 4096 {
			t.Fatal("summary disclosed data or exceeded 4 KiB")
		}
	}
	for _, value := range []int{-1, 1000000} {
		if dockerPortSmokeBoundedCount(value, 64) != -1 {
			t.Fatal("counter escaped bounds")
		}
	}
	response := LocalExecutorResponse{Version: LocalExecutorMutationProtocolVersion, Error: &LocalExecutorFailure{Code: "mutation_precondition_failed", Message: "precondition failed"}}
	if !strings.Contains(dockerPortSmokeRollbackSummary(response, SystemdPortReconfigurePlan{}), "error_code=mutation_precondition_failed") {
		t.Fatal("known error code lost")
	}
}

func TestDockerSmokeDiagnosticLegacyCallerConnection(t *testing.T) {
	source, err := os.ReadFile("docker_port_daemon_smoke_linux_test.go")
	if err != nil {
		t.Fatal("cannot read actual smoke caller")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "smoke.go", source, 0)
	if err != nil {
		t.Fatal("cannot parse actual smoke caller")
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	calls := func(name, target string) []token.Pos {
		var positions []token.Pos
		ast.Inspect(functions[name].Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			called := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				called = function.Name
			case *ast.SelectorExpr:
				called = function.Sel.Name
			}
			if called == target {
				positions = append(positions, call.Pos())
			}
			return true
		})
		return positions
	}
	observed, assertion := calls("TestDockerPortDaemonSmoke", "observeDockerPortSmokeUnhealthyMutation"), calls("TestDockerPortDaemonSmoke", "assertDockerPortSmokeRolledBack")
	if len(observed) != 1 || len(assertion) != 1 || observed[0] >= assertion[0] {
		t.Fatal("unhealthy caller bypasses observation or assertion")
	}
	for _, target := range []string{"handleLocalExecutorMutation", "withFailureObserver", "wrapCrashPoint"} {
		if len(calls("runDockerPortSmokeMutation", target)) != 1 {
			t.Fatal("actual mutation helper lost its handler/observer connection")
		}
	}
	mutate, logged := calls("observeDockerPortSmokeUnhealthyMutation", "mutate"), calls("observeDockerPortSmokeUnhealthyMutation", "logReturn")
	if len(mutate) != 1 || len(logged) != 1 || mutate[0] >= logged[0] || len(calls("assertDockerPortSmokeRolledBack", "dockerPortSmokeRollbackSummary")) != 1 || len(calls("assertDockerPortSmokeRolledBack", "Fatalf")) != 1 {
		t.Fatal("real mutation return or fatal assertion bypasses safe summary")
	}
	if !strings.Contains(string(source), "return runDockerPortSmokeMutation(t, runner, stateDir, unhealthyPlan, \"port_reconfigure\", nil, scope)") || !strings.Contains(string(source), "if rollbackGrants != 1 {") || !strings.Contains(string(source), "t.Fatalf(\"rollback mutation grant calls=%d\", rollbackGrants)") {
		t.Fatal("actual unhealthy request or existing grant fatal boundary changed")
	}
}
