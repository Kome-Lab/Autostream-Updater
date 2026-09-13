//go:build linux

package hostruntime

import (
	"context"
	"fmt"
	"sync"
)

// A scope belongs to one in-process legacy mutation. Runner calls capture its
// pointer on entry, so a late return can never be charged to a later mutation.
type dockerPortSmokeLegacyDiagnostic struct {
	mu                                                               sync.Mutex
	active, logged                                                   bool
	firstPhase, lastPhase                                            string
	firstRunner, lastRunner                                          dockerPortSmokeRunnerObservation
	firstLocalPhase, lastLocalPhase, firstLocalClass, lastLocalClass string
	phaseCalls, runnerCalls, localCalls                              int
	phaseCapped, runnerCapped, localCapped                           bool
}

func (r *dockerPortSmokeRunner) beginLegacyDiagnostic() *dockerPortSmokeLegacyDiagnostic {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.legacyDiagnostic != nil {
		r.legacyDiagnostic.close()
	}
	scope := &dockerPortSmokeLegacyDiagnostic{active: true}
	r.legacyDiagnostic = scope
	return scope
}

func (s *dockerPortSmokeLegacyDiagnostic) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
}

func observeDockerPortSmokeUnhealthyMutation(t dockerPortSmokeLogger, r *dockerPortSmokeRunner, plan SystemdPortReconfigurePlan, mutate func(*dockerPortSmokeLegacyDiagnostic) (LocalExecutorResponse, int)) (LocalExecutorResponse, int) {
	t.Helper()
	scope := r.beginLegacyDiagnostic()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		scope.close()
		if r.legacyDiagnostic == scope {
			r.legacyDiagnostic = nil
		}
	}()
	response, grants := mutate(scope)
	// Always log once, including success, before either caller assertion.
	scope.logReturn(t, response, plan, grants)
	return response, grants
}

func dockerPortSmokeBoundedCount(value, limit int) int {
	if value < 0 || value > limit {
		return -1
	}
	return value
}

func dockerPortSmokeIncrement(count *int, capped *bool, limit int) {
	if *count < 0 || *count >= limit {
		*count = limit
		*capped = true
		return
	}
	*count++
}

func (s *dockerPortSmokeLegacyDiagnostic) wrapCrashPoint(original func(string) error) func(string) error {
	return func(point string) error {
		phase := "unknown"
		switch point {
		case "after_grant_consume", "after_port_env_write", "after_docker_recreate", "after_applied_state_save":
			phase = point
		}
		s.mu.Lock()
		if s.active {
			if s.firstPhase == "" {
				s.firstPhase = phase
			}
			s.lastPhase = phase
			dockerPortSmokeIncrement(&s.phaseCalls, &s.phaseCapped, 64)
		}
		s.mu.Unlock()
		if original != nil {
			return original(point)
		}
		return nil
	}
}

func dockerPortSmokeClosedRunner(observation dockerPortSmokeRunnerObservation) dockerPortSmokeRunnerObservation {
	switch observation.phase {
	case "command", "compose_capture", "mapping_read", "mapping_parse", "listener_tcp":
		observation.substage, observation.identity = "none", dockerPortSmokeIdentityObservation{}
	case "listener_identity":
		switch observation.substage {
		case "execution_read", "execution_decode", "listener_source", "context", "listener_file", "fixture_http", "identity_match":
		default:
			observation.substage = "unknown"
		}
	default:
		observation = dockerPortSmokeRunnerObservation{phase: "unknown", substage: "unknown"}
	}
	return observation
}

func (s *dockerPortSmokeLegacyDiagnostic) observeRunner(observation dockerPortSmokeRunnerObservation, failed bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		return
	}
	dockerPortSmokeIncrement(&s.runnerCalls, &s.runnerCapped, 256)
	if failed {
		observation = dockerPortSmokeClosedRunner(observation)
		if s.firstRunner.phase == "" {
			s.firstRunner = observation
		}
		s.lastRunner = observation
	}
}

func dockerPortSmokeLocalPhase(phase localExecutionFailurePhase) string {
	names := map[localExecutionFailurePhase]string{
		localFailurePolicySelect: "policy_select", localFailurePolicySave: "policy_save",
		localFailurePolicyWrite: "policy_write", localFailurePolicyReload: "policy_reload", localFailurePolicyVerify: "policy_verify",
		localFailureForwardBudget: "forward_budget", localFailureForwardWrite: "forward_write", localFailureForwardRestart: "forward_restart", localFailureForwardProbe: "forward_probe",
		localFailureProbeProjection: "probe_projection", localFailureProbeBefore: "probe_before", localFailureProbeHTTP: "probe_http", localFailureProbeDockerMapping: "probe_docker_mapping",
		localFailureProbeAfter: "probe_after", localFailureProbeBaseline: "probe_baseline", localFailureProbeResponse: "probe_response",
		localFailureDockerContainer: "docker_container", localFailureDockerPID: "docker_pid", localFailureDockerCgroup: "docker_cgroup", localFailureDockerVersion: "docker_version", localFailureDockerListener: "docker_listener",
		localFailureSystemdRelease: "systemd_release", localFailureSystemdProcess: "systemd_process", localFailureSystemdPID: "systemd_pid", localFailureSystemdCgroup: "systemd_cgroup", localFailureSystemdListener: "systemd_listener",
		localFailureHTTPHealth: "http_health", localFailureHTTPVersion: "http_version",
		localFailureDockerPrepareTarget: "docker_prepare_target", localFailureDockerPrepareApplied: "docker_prepare_applied", localFailureDockerPrepareObserve: "docker_prepare_observe", localFailureDockerPrepareObservation: "docker_prepare_observation",
		localFailureDockerPrepareSnapshot: "docker_prepare_snapshot", localFailureDockerPrepareContainer: "docker_prepare_container", localFailureDockerPrepareImage: "docker_prepare_image", localFailureDockerPrepareRepository: "docker_prepare_repository",
		localFailureDockerPrepareVersionEnv: "docker_prepare_version_env", localFailureDockerPrepareCompose: "docker_prepare_compose", localFailureDockerPrepareTargetPayload: "docker_prepare_target_payload", localFailureDockerPrepareRollbackPayload: "docker_prepare_rollback_payload",
		localFailureDockerPrepareTargetModel: "docker_prepare_target_model", localFailureDockerPrepareRollbackModel: "docker_prepare_rollback_model", localFailureDockerPrepareAvailability: "docker_prepare_availability",
		localFailureDockerVerifyTarget: "docker_verify_target", localFailureDockerVerifyObserve: "docker_verify_observe", localFailureDockerVerifyIdentity: "docker_verify_identity",
		localFailureDockerObserveMapping: "docker_observe_mapping", localFailureDockerObserveModel: "docker_observe_model", localFailureDockerObserveBaseline: "docker_observe_baseline", localFailureDockerObserveOwnership: "docker_observe_ownership", localFailureDockerObserveListener: "docker_observe_listener", localFailureDockerObserveEndpoint: "docker_observe_endpoint",
		localFailureDockerListenerBinding: "docker_listener_binding", localFailureDockerListenerNamespace: "docker_listener_namespace", localFailureDockerListenerSocketTable: "docker_listener_socket_table", localFailureDockerListenerOwnerProof: "docker_listener_owner_proof", localFailureDockerListenerRecheck: "docker_listener_recheck",
		localFailureDockerOwnerProcessDisappeared: "docker_owner_process_disappeared", localFailureDockerOwnerDescriptorDisappeared: "docker_owner_descriptor_disappeared",
	}
	if name, ok := names[phase]; ok {
		return name
	}
	return "unknown"
}

func (s *dockerPortSmokeLegacyDiagnostic) withFailureObserver(ctx context.Context) context.Context {
	original, _ := ctx.Value(localExecutionFailureContextKey{}).(func(localExecutionFailurePhase, localExecutionFailureClass))
	return context.WithValue(ctx, localExecutionFailureContextKey{}, func(phase localExecutionFailurePhase, class localExecutionFailureClass) {
		name := "unknown"
		switch class {
		case localFailureValidation:
			name = "validation"
		case localFailureOperation:
			name = "operation"
		case localFailureDeadline:
			name = "deadline"
		case localFailureCanceled:
			name = "canceled"
		}
		s.mu.Lock()
		if s.active {
			if s.firstLocalPhase == "" {
				s.firstLocalPhase, s.firstLocalClass = dockerPortSmokeLocalPhase(phase), name
			}
			s.lastLocalPhase, s.lastLocalClass = dockerPortSmokeLocalPhase(phase), name
			dockerPortSmokeIncrement(&s.localCalls, &s.localCapped, 64)
		}
		s.mu.Unlock()
		if original != nil {
			original(phase, class)
		}
	})
}

func dockerPortSmokeRollbackSummary(response LocalExecutorResponse, plan SystemdPortReconfigurePlan) string {
	version, contract, actual, status, state, recovery, code := "unknown", "absent", "absent", "unobserved", "unobserved", "not_applicable", "none"
	switch response.Version {
	case LocalExecutorProtocolVersion:
		version = "v1"
	case LocalExecutorMutationProtocolVersion:
		version = "v2"
	}
	var old, next [4]bool
	port, docker := response.PortResult != nil, false
	if result := response.PortResult; result != nil {
		contract = "unknown"
		switch result.PortContractVersion {
		case 0:
			contract = "legacy"
		case 2:
			contract = "v2"
		}
		actual = "unknown"
		switch result.Result {
		case systemdPortResultApplied, systemdPortResultUnchanged, systemdPortResultRolledBack, systemdPortResultRollbackFailed:
			actual = result.Result
		}
		if contract != "unknown" {
			status = "unknown"
			switch result.Status {
			case "succeeded", "rolled_back", "failed":
				status = result.Status
			}
			state = fmt.Sprintf("%t", result.StateKnown)
			if contract == "v2" {
				recovery = fmt.Sprintf("%t", result.RecoveryRequired)
			}
		}
		old[0], next[0] = result.AppliedPort == plan.OldPort, result.AppliedPort == plan.NewPort
		docker = result.Docker != nil
		if docker && plan.Docker != nil {
			old[1], old[2], old[3] = result.Docker.AppliedPublishedPort == plan.Docker.OldPublishedPort, result.Docker.AppliedContainerPort == plan.Docker.OldContainerPort, result.Docker.AppliedHealthPort == plan.Docker.OldHealthPort
			next[1], next[2], next[3] = result.Docker.AppliedPublishedPort == plan.Docker.NewPublishedPort, result.Docker.AppliedContainerPort == plan.Docker.NewContainerPort, result.Docker.AppliedHealthPort == plan.Docker.NewHealthPort
		}
	}
	if response.Error != nil {
		code = "unknown"
		if validLocalExecutorFailureCode(response.Error.Code) {
			code = response.Error.Code
		}
	}
	// Validate the actual contract. Legacy results have no required nested V2 result.
	return fmt.Sprintf("response_valid=%t version=%s contract=%s port_present=%t docker_present=%t expected=rolled_back actual=%s status=%s state_known=%s recovery_required=%s old_advertised_match=%t old_published_match=%t old_container_match=%t old_health_match=%t new_advertised_match=%t new_published_match=%t new_container_match=%t new_health_match=%t plan_match=%t session_match=%t error_present=%t error_code=%s",
		response.Validate() == nil, version, contract, port, docker, actual, status, state, recovery, old[0], old[1], old[2], old[3], next[0], next[1], next[2], next[3],
		plan.PortPlanSHA256 != "" && response.PlanSHA256 == plan.PortPlanSHA256, plan.SessionID != "" && response.SessionID == plan.SessionID, response.Error != nil, code)
}

func (s *dockerPortSmokeLegacyDiagnostic) logReturn(t dockerPortSmokeLogger, response LocalExecutorResponse, plan SystemdPortReconfigurePlan, grants int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.logged {
		return
	}
	s.logged = true
	label := func(value string) string {
		if value == "" {
			return "unobserved"
		}
		return value
	}
	t.Logf("Docker smoke legacy rollback: scope=legacy_unhealthy_rollback handler_returned=true %s grant_count=%d expected_grant_count=1 grant_count_matches=%t",
		dockerPortSmokeRollbackSummary(response, plan), dockerPortSmokeBoundedCount(grants, 64), grants == 1)
	t.Logf("Docker smoke legacy boundary: scope=legacy_unhealthy_rollback same_process_observation=true phase_observed=%t first_phase=%s last_phase=%s phase_calls=%d phase_capped=%t runner_failure_observed=%t first_runner_failure=%s last_runner_failure=%s first_runner_substage=%s last_runner_substage=%s first_failure_identity_compared=%t first_failure_bytes_match=%t first_failure_device_match=%t first_failure_inode_match=%t runner_calls=%d runner_capped=%t local_failure_observed=%t first_local_phase=%s last_local_phase=%s first_local_class=%s last_local_class=%s local_calls=%d local_capped=%t",
		s.firstPhase != "", label(s.firstPhase), label(s.lastPhase), dockerPortSmokeBoundedCount(s.phaseCalls, 64), s.phaseCapped,
		s.firstRunner.phase != "", label(s.firstRunner.phase), label(s.lastRunner.phase), label(s.firstRunner.substage), label(s.lastRunner.substage),
		s.firstRunner.identity.compared, s.firstRunner.identity.bytesMatch, s.firstRunner.identity.deviceMatch, s.firstRunner.identity.inodeMatch, dockerPortSmokeBoundedCount(s.runnerCalls, 256), s.runnerCapped,
		s.firstLocalPhase != "", label(s.firstLocalPhase), label(s.lastLocalPhase), label(s.firstLocalClass), label(s.lastLocalClass), dockerPortSmokeBoundedCount(s.localCalls, 64), s.localCapped)
}
