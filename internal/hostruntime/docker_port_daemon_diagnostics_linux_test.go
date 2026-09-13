//go:build linux

package hostruntime

import (
	"sync"
)

type dockerPortSmokeRunner struct {
	base             CommandRunner
	imageID          string
	repositoryDigest string
	captureDir       string
	adapter          dockerPortAdapter

	mu               sync.Mutex
	repositoryCalls  int
	stPortDiagnostic dockerPortSmokeSTPortDiagnostic
	legacyDiagnostic *dockerPortSmokeLegacyDiagnostic
}

// This fixture-only observation never changes a runner result or a crash hook.
// It retains closed phase names and capped counters, never command data/errors.
type dockerPortSmokeSTPortDiagnostic struct {
	step, firstPhase, lastPhase, firstFailure string
	firstFailureSubstage                      string
	firstFailureIdentity                      dockerPortSmokeIdentityObservation
	runnerCalls, phaseCalls                   int
	runnerCapped, phaseCapped, active         bool
	childReturnLogged                         bool
}

type dockerPortSmokeIdentityObservation struct {
	compared, bytesMatch, deviceMatch, inodeMatch bool
}

type dockerPortSmokeRunnerObservation struct {
	phase, substage string
	identity        dockerPortSmokeIdentityObservation
}

func (o *dockerPortSmokeRunnerObservation) atListenerStage(stage string) {
	if o != nil {
		o.substage = stage
	}
}

func (o *dockerPortSmokeRunnerObservation) observeListenerMatch(record dockerPortSmokeListenerRecord, digest string, device, inode uint64) {
	if o != nil {
		o.identity = dockerPortSmokeIdentityObservation{true, digest == record.SHA256, device == record.Device, inode == record.Inode}
	}
}

func (r *dockerPortSmokeRunner) beginSTPortDiagnostic(step string, sameProcess bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stPortDiagnostic = dockerPortSmokeSTPortDiagnostic{step: dockerPortSmokeStep(step), active: sameProcess}
}

func dockerPortSmokeStep(step string) string {
	switch step {
	case "noop", "local_only", "container_only", "combined_recovery", "rollback":
		return step
	default:
		return "unknown"
	}
}

func (r *dockerPortSmokeRunner) observeSTPortPhase(phase string) error {
	switch phase {
	case "after_grant_consume", "before_policy_write", "after_policy_write", "after_policy_reload",
		"after_sidecar_write", "after_restart", "after_target_verify", "after_rollback_latch", "after_rollback_runtime_write", "after_result_save":
	default:
		phase = "unknown"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	diagnostic := &r.stPortDiagnostic
	if diagnostic.active {
		if diagnostic.firstPhase == "" {
			diagnostic.firstPhase = phase
		}
		diagnostic.lastPhase = phase
		if diagnostic.phaseCalls < 64 {
			diagnostic.phaseCalls++
		} else {
			diagnostic.phaseCapped = true
		}
	}
	return nil
}

func (r *dockerPortSmokeRunner) observeSTPortRunner(observation dockerPortSmokeRunnerObservation, failed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	diagnostic := &r.stPortDiagnostic
	if !diagnostic.active {
		return
	}
	if diagnostic.runnerCalls < 256 {
		diagnostic.runnerCalls++
	} else {
		diagnostic.runnerCapped = true
	}
	if failed && diagnostic.firstFailure == "" {
		switch observation.phase {
		case "command", "compose_capture", "mapping_read", "mapping_parse", "listener_tcp", "listener_identity":
			diagnostic.firstFailure = observation.phase
		default:
			diagnostic.firstFailure = "unknown"
		}
		diagnostic.firstFailureSubstage = "none"
		if diagnostic.firstFailure == "listener_identity" {
			switch observation.substage {
			case "execution_read", "execution_decode", "listener_source", "context", "listener_file", "fixture_http", "identity_match":
				diagnostic.firstFailureSubstage = observation.substage
			default:
				diagnostic.firstFailureSubstage = "unknown"
			}
			diagnostic.firstFailureIdentity = observation.identity
		} else if diagnostic.firstFailure == "unknown" {
			diagnostic.firstFailureSubstage = "unknown"
		}
	}
}

type dockerPortSmokeLogger interface {
	Helper()
	Logf(string, ...any)
}

// Called immediately after the handler returns, before either child fatal.
// Keep the existing grant predicate and derive expectations only from the input.
func (r *dockerPortSmokeRunner) logSTPortChildReturn(t dockerPortSmokeLogger, payload dockerPortSmokeChildPayload, crashPhase string, response LocalExecutorResponse, consumed int) {
	t.Helper()
	grantMatches := payload.ExpectGrant == (consumed == 1)
	if payload.Plan.PortContractVersion != 2 || (grantMatches && payload.ResponsePath != "" && crashPhase == "") {
		return
	}
	r.mu.Lock()
	logged := r.stPortDiagnostic.childReturnLogged
	r.stPortDiagnostic.childReturnLogged = true
	r.mu.Unlock()
	if logged {
		return
	}
	expected := systemdPortResultApplied
	if payload.Operation == "port_reconfigure_reconcile" && payload.ExpectGrant {
		expected = systemdPortResultRolledBack
	}
	expectedCrash := crashPhase != ""
	switch crashPhase {
	case "":
		crashPhase = "none"
	case "after_docker_recreate", "after_restart", "after_target_verify":
	default:
		crashPhase = "unknown"
	}
	t.Logf("ST-PORT Docker smoke child return: handler_returned=true expected_crash=%t crash_phase=%s returned_before_expected_crash=%t response_path_present=%t expect_grant=%t grant_count_matches=%t",
		expectedCrash, crashPhase, expectedCrash, payload.ResponsePath != "", payload.ExpectGrant, grantMatches)
	r.logSTPortResultFailure(t, "combined_recovery", response, payload.Plan, expected, consumed)
}

func (r *dockerPortSmokeRunner) logSTPortResultFailure(t dockerPortSmokeLogger, step string, response LocalExecutorResponse, plan SystemdPortReconfigurePlan, expected string, consumed int) {
	t.Helper()
	resultName := func(value string) string {
		switch value {
		case systemdPortResultApplied, systemdPortResultUnchanged, systemdPortResultRolledBack, systemdPortResultRollbackFailed:
			return value
		default:
			return "unknown"
		}
	}
	actual, status, errorCode := "absent", "absent", "none"
	validResponse := response.Validate() == nil
	nested, matches, stateKnown, recovery := false, false, false, false
	if result := response.PortResult; result != nil {
		actual = resultName(result.Result)
		status = "unknown"
		switch result.Status {
		case "succeeded", "rolled_back", "failed":
			status = result.Status
		}
		nested, stateKnown, recovery = result.PortResult != nil, result.StateKnown, result.RecoveryRequired
		matches = validResponse && nested && portV2AcceptedResultMatchesPlan(plan, *result)
	}
	if response.Error != nil {
		errorCode = "unknown"
		if validLocalExecutorFailureCode(response.Error.Code) {
			errorCode = response.Error.Code
		}
	}
	version := response.Version
	if version != LocalExecutorProtocolVersion && version != LocalExecutorMutationProtocolVersion {
		version = -1
	}
	if consumed < 0 || consumed > 64 {
		consumed = -1
	}
	t.Logf("ST-PORT Docker smoke result: step=%s expected=%s actual=%s status=%s version=%d response_valid=%t port_present=%t nested_present=%t plan_match=%t state_known=%t recovery_required=%t error_present=%t error_code=%s consume_count=%d",
		dockerPortSmokeStep(step), resultName(expected), actual, status, version, validResponse, response.PortResult != nil, nested, matches, stateKnown, recovery, response.Error != nil, errorCode, consumed)
	r.mu.Lock()
	diagnostic := r.stPortDiagnostic
	r.mu.Unlock()
	if diagnostic.step != dockerPortSmokeStep(step) {
		diagnostic = dockerPortSmokeSTPortDiagnostic{}
	}
	for _, value := range []*string{&diagnostic.firstPhase, &diagnostic.lastPhase, &diagnostic.firstFailure, &diagnostic.firstFailureSubstage} {
		if *value == "" {
			*value = "none"
		}
	}
	t.Logf("ST-PORT Docker smoke boundary: same_process_observation=%t first_phase=%s last_phase=%s phase_calls=%d phase_capped=%t first_runner_failure=%s first_runner_substage=%s first_failure_identity_compared=%t first_failure_bytes_match=%t first_failure_device_match=%t first_failure_inode_match=%t runner_calls=%d runner_capped=%t",
		diagnostic.active, diagnostic.firstPhase, diagnostic.lastPhase, diagnostic.phaseCalls, diagnostic.phaseCapped, diagnostic.firstFailure, diagnostic.firstFailureSubstage,
		diagnostic.firstFailureIdentity.compared, diagnostic.firstFailureIdentity.bytesMatch, diagnostic.firstFailureIdentity.deviceMatch, diagnostic.firstFailureIdentity.inodeMatch,
		diagnostic.runnerCalls, diagnostic.runnerCapped)
}
