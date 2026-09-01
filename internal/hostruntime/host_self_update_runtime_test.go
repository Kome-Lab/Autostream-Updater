package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHostSelfUpdateGrantPlanSHA256UsesCanonicalBareDigest(t *testing.T) {
	request := validHostSelfUpdateRequest()
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    7,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: 11,
		ExecutorPolicyRevision:  9,
	}
	planSHA256, err := hostSelfUpdateGrantPlanSHA256(
		"stage",
		HostAgentPolicy{
			SelfUpdateID:       "self-update-host-a-0001",
			SelfUpdateRevision: 5,
		},
		request,
		fence,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !mutationPlanHashPattern.MatchString(planSHA256) ||
		digestPattern.MatchString(planSHA256) {
		t.Fatalf("plan digest is not canonical bare sha256: %q", planSHA256)
	}

	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		request,
		fence,
		"sha256:"+strings.Repeat("a", 64),
	)
	if authorization.Binding.PlanSHA256 != planSHA256 {
		t.Fatalf(
			"grant helper plan digest=%q want=%q",
			authorization.Binding.PlanSHA256,
			planSHA256,
		)
	}
	prefixed := authorization
	prefixed.Binding.PlanSHA256 = "sha256:" + planSHA256
	if err := prefixed.validate(); err == nil {
		t.Fatal("prefixed plan digest crossed the host/root grant boundary")
	}
}

func TestLocalExecutorHostSelfUpdateProtocolIsStrictAndCredentialFree(t *testing.T) {
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision: 7, OwnershipEpoch: 3,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 9,
	}
	request := LocalExecutorRequest{
		Version:   LocalExecutorMutationProtocolVersion,
		Operation: "host_self_update_stage",
		ServiceID: "host-a",
		HostSelfUpdate: func() *HostSelfUpdateRequest {
			value := validHostSelfUpdateRequest()
			return &value
		}(),
		SourcePolicyRevision:    fence.SourcePolicyRevision,
		OwnershipEpoch:          fence.OwnershipEpoch,
		OwnershipPolicyRevision: fence.OwnershipPolicyRevision,
		ExecutorPolicyRevision:  fence.ExecutorPolicyRevision,
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		*request.HostSelfUpdate,
		fence,
		"sha256:"+strings.Repeat("a", 64),
	)
	request.HostSelfUpdateGrant = &authorization
	var encoded bytes.Buffer
	if err := EncodeLocalExecutorRequest(&encoded, request); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	decoded, err := DecodeLocalExecutorRequest(&encoded)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if decoded.HostSelfUpdate == nil ||
		decoded.HostSelfUpdate.Generation != request.HostSelfUpdate.Generation ||
		decoded.HostSelfUpdateGrant == nil ||
		decoded.HostSelfUpdateGrant.Token.Reveal() !=
			authorization.Token.Reveal() {
		t.Fatalf("request binding was lost: %#v", decoded)
	}
	structured, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request for logging: %v", err)
	}
	if bytes.Contains(structured, []byte(authorization.Token.Reveal())) {
		t.Fatal("host self-update grant leaked through structured JSON")
	}
	request.MutationGrant = NewBoundedSecret("must-not-cross-self-update-boundary")
	if err := request.Validate(); err == nil {
		t.Fatal("host self-update accepted a credential")
	}
	request.MutationGrant = NewBoundedSecret("")
	request.Plan = &MutationPlan{}
	if err := request.Validate(); err == nil {
		t.Fatal("host self-update accepted a software mutation plan")
	}
}

func TestLocalExecutorHostSelfUpdateWatchdogStatusProtocolIsFixed(t *testing.T) {
	request := LocalExecutorRequest{
		Version:   LocalExecutorMutationProtocolVersion,
		Operation: "host_self_update_watchdog_status",
		ServiceID: "host-self-update-watchdog",
	}
	var encoded bytes.Buffer
	if err := EncodeLocalExecutorRequest(&encoded, request); err != nil {
		t.Fatalf("encode watchdog status request: %v", err)
	}
	decoded, err := DecodeLocalExecutorRequest(&encoded)
	if err != nil {
		t.Fatalf("decode watchdog status request: %v", err)
	}
	if decoded != request {
		t.Fatalf("decoded watchdog status request=%#v want=%#v", decoded, request)
	}

	for name, mutate := range map[string]func(*LocalExecutorRequest){
		"wrong protocol": func(value *LocalExecutorRequest) {
			value.Version = LocalExecutorProtocolVersion
		},
		"caller selected service": func(value *LocalExecutorRequest) {
			value.ServiceID = "host-a"
		},
		"policy revision": func(value *LocalExecutorRequest) {
			value.SourcePolicyRevision = 1
		},
		"ownership epoch": func(value *LocalExecutorRequest) {
			value.OwnershipEpoch = 1
		},
		"ownership policy revision": func(value *LocalExecutorRequest) {
			value.OwnershipPolicyRevision = 1
		},
		"executor policy revision": func(value *LocalExecutorRequest) {
			value.ExecutorPolicyRevision = 1
		},
		"generation": func(value *LocalExecutorRequest) {
			value.HostSelfUpdateGeneration = "candidate"
		},
		"mutation grant": func(value *LocalExecutorRequest) {
			value.MutationGrant = NewBoundedSecret("must-not-cross-watchdog-boundary")
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("watchdog status accepted caller-controlled input: %#v", candidate)
			}
		})
	}
}

func validHostSelfUpdateGrantAuthorization(
	operation string,
	request HostSelfUpdateRequest,
	fence LocalExecutorMutationFence,
	policySHA256 string,
) HostSelfUpdateGrantAuthorization {
	now := time.Date(2026, 7, 28, 1, 2, 3, 0, time.UTC)
	authorization := HostSelfUpdateGrantAuthorization{
		Binding: HostSelfUpdateGrantBinding{
			ID:                                  "grant-host-a-" + operation,
			SelfUpdateID:                        "self-update-host-a-0001",
			AttemptGeneration:                   request.Generation,
			Operation:                           operation,
			ExecutionHostID:                     "host-a",
			AgentServiceID:                      "host-agent-a",
			ExpectedSelfUpdateRevision:          5,
			ExpectedOwnershipEpoch:              fence.OwnershipEpoch,
			ExpectedSourcePolicyRevision:        fence.SourcePolicyRevision,
			ExpectedProjectionRevision:          fence.OwnershipPolicyRevision,
			ExpectedLocalExecutorPolicyRevision: fence.ExecutorPolicyRevision,
			ExpectedLocalExecutorPolicySHA256:   policySHA256,
			AgentVersion:                        request.AgentVersion,
			ExecutorVersion:                     request.ExecutorVersion,
			ReleaseCommit:                       request.Commit,
			ArtifactSHA256:                      request.ArtifactSHA256,
			AgentProtocolVersion:                request.AgentProtocolVersion,
			ExecutorProtocolVersion:             request.ExecutorProtocolVersion,
			MutationProtocolVersion:             request.MutationProtocolVersion,
			RecoveryProtocolVersion:             request.RecoveryProtocolVersion,
			Release:                             request.Release,
			DirectiveIssuedAt:                   now,
			SessionID:                           "session-host-a-" + operation,
			Revision:                            1,
			IssuedAt:                            now,
			ExpiresAt:                           now.Add(2 * time.Minute),
		},
		Token: NewBoundedSecret("ast_hsug_test-host-a-" + operation),
	}
	authorization.Binding.PlanSHA256, _ = hostSelfUpdateGrantPlanSHA256(
		operation,
		HostAgentPolicy{
			SelfUpdateID:       authorization.Binding.SelfUpdateID,
			SelfUpdateRevision: authorization.Binding.ExpectedSelfUpdateRevision,
		},
		request,
		fence,
	)
	return authorization
}

func consumedHostSelfUpdateGrant(
	authorization HostSelfUpdateGrantAuthorization,
) HostSelfUpdateGrantConsumeResult {
	grant := authorization.Binding
	consumedAt := grant.IssuedAt.Add(time.Second)
	grant.ConsumedAt = &consumedAt
	if grant.Operation == "stage" {
		grant.StageClaimRevision = grant.ExpectedSelfUpdateRevision + 1
		grant.StageClaimedAt = &consumedAt
	}
	return HostSelfUpdateGrantConsumeResult{
		Grant:    grant,
		Consumed: true,
	}
}

func hostSelfUpdateControllerTestGrantProvider(
	context.Context,
	string,
) (HostSelfUpdateGrantAuthorization, error) {
	return HostSelfUpdateGrantAuthorization{}, nil
}

type hostSelfUpdateControllerTestExecutor struct {
	status          HostSelfUpdateRuntimeStatus
	stageResult     *HostSelfUpdateRuntimeStatus
	stageRequests   []HostSelfUpdateRequest
	activateCalls   []string
	reconcileProofs []HostSelfUpdateAgentProof
}

func (e *hostSelfUpdateControllerTestExecutor) HostSelfUpdateStatus(
	context.Context,
	string,
	LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	return e.status, nil
}

func (e *hostSelfUpdateControllerTestExecutor) StageHostSelfUpdate(
	_ context.Context,
	_ string,
	request HostSelfUpdateRequest,
	_ HostSelfUpdateGrantAuthorization,
	_ LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	e.stageRequests = append(e.stageRequests, request)
	if e.stageResult != nil {
		e.status = *e.stageResult
		return e.status, nil
	}
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	state, err = StageHostSelfUpdate(
		state,
		request,
		HostLifecycleBlockers{},
		validHostSelfUpdateSlotDigests(),
	)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	e.status.State = state
	return e.status, nil
}

func TestHostSelfUpdateControllerReturnsFailClosedStageStatus(t *testing.T) {
	request := validHostSelfUpdateRequest()
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	failedState := state
	failedState.FailedGeneration = request.Generation
	failed := HostSelfUpdateRuntimeStatus{
		State:                   failedState,
		CurrentSlot:             failedState.ActiveSlot,
		ExecutorVersion:         failedState.ActiveExecutorVersion,
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		LastAction:              HostSelfUpdateActionNone,
	}
	executor := &hostSelfUpdateControllerTestExecutor{
		status: HostSelfUpdateRuntimeStatus{
			State:                   state,
			CurrentSlot:             state.ActiveSlot,
			ExecutorVersion:         state.ActiveExecutorVersion,
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		},
		stageResult: &failed,
	}
	controller, err := NewHostSelfUpdateController(
		executor,
		HostSelfUpdateControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    7,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: 11,
		ExecutorPolicyRevision:  9,
	}
	status, err := controller.Reconcile(
		context.Background(),
		"host-a",
		&request,
		HostSelfUpdateAgentProof{},
		fence,
		HostLifecycleBlockers{},
		hostSelfUpdateControllerTestGrantProvider,
	)
	if err != nil {
		t.Fatalf("fail-closed stage status was dropped: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		status.State.FailedGeneration != request.Generation ||
		len(executor.activateCalls) != 0 {
		t.Fatalf("unexpected fail-closed stage status: %#v", status)
	}
}

func (e *hostSelfUpdateControllerTestExecutor) ActivateHostSelfUpdate(
	_ context.Context,
	_ string,
	generation string,
	_ LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	e.activateCalls = append(e.activateCalls, generation)
	state, err := beginHostSelfUpdateActivationForTest(e.status.State)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	e.status.State = state
	e.status.CurrentSlot = HostSelfUpdateSlotB
	// The real activation restarts the caller, so losing the response is an
	// expected uncertain outcome. Durable status drives the next process.
	return HostSelfUpdateRuntimeStatus{}, errors.New("connection closed for restart")
}

func (e *hostSelfUpdateControllerTestExecutor) ReconcileHostSelfUpdate(
	_ context.Context,
	_ string,
	proof HostSelfUpdateAgentProof,
	_ *HostSelfUpdateGrantAuthorization,
	_ LocalExecutorMutationFence,
) (HostSelfUpdateRuntimeStatus, error) {
	e.reconcileProofs = append(e.reconcileProofs, proof)
	observation := HostSelfUpdateObservation{
		CurrentSlot:             e.status.CurrentSlot,
		RunningAgentVersion:     proof.RunningAgentVersion,
		PanelHeartbeatVersion:   proof.PanelHeartbeatVersion,
		HeartbeatGeneration:     proof.HeartbeatGeneration,
		ExecutorVersion:         "v1.8.0",
		ExecutorProtocol:        LocalExecutorMutationProtocolVersion,
		ExecutorHealthy:         true,
		ExecutorProbeGeneration: e.status.State.PendingGeneration,
	}
	state, action, err := ReconcileHostSelfUpdate(e.status.State, observation)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	e.status.State = state
	e.status.LastAction = action
	e.status.ExecutorVersion = observation.ExecutorVersion
	e.status.ExecutorProtocolVersion = observation.ExecutorProtocol
	if action == HostSelfUpdateActionRestoreHealthy {
		e.status.CurrentSlot = state.HealthySlot
		e.status.RestartRequested = true
	}
	return e.status, nil
}

func TestHostSelfUpdateControllerUsesDurableReconcileAfterActivationDisconnect(t *testing.T) {
	request := validHostSelfUpdateRequest()
	initial, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	executor := &hostSelfUpdateControllerTestExecutor{
		status: HostSelfUpdateRuntimeStatus{
			State:                   initial,
			CurrentSlot:             HostSelfUpdateSlotA,
			ExecutorVersion:         "v1.7.8",
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		},
	}
	controller, err := NewHostSelfUpdateController(
		executor,
		HostSelfUpdateControllerOptions{},
	)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision: 7, OwnershipEpoch: 3,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 9,
	}

	status, err := controller.Reconcile(
		context.Background(),
		"host-a",
		&request,
		HostSelfUpdateAgentProof{RunningAgentVersion: "v1.7.8"},
		fence,
		HostLifecycleBlockers{},
		hostSelfUpdateControllerTestGrantProvider,
	)
	if err != nil {
		t.Fatalf("stage and activate: %v", err)
	}
	if len(executor.stageRequests) != 1 ||
		len(executor.activateCalls) != 1 ||
		status.State.Phase != HostSelfUpdatePhaseActivating {
		t.Fatalf("activation was not durably staged: status=%#v executor=%#v", status, executor)
	}
	// The activation response can be lost while the old socket-activated
	// executor is draining. The next reconciliation starts only after the
	// replacement executor reports the pending runtime identity.
	executor.status.ExecutorVersion = request.ExecutorVersion
	executor.status.ExecutorProtocolVersion = request.ExecutorProtocolVersion

	status, err = controller.Reconcile(
		context.Background(),
		"host-a",
		&request,
		HostSelfUpdateAgentProof{RunningAgentVersion: "v1.8.0"},
		fence,
		HostLifecycleBlockers{},
		hostSelfUpdateControllerTestGrantProvider,
	)
	if err != nil {
		t.Fatalf("reconcile before heartbeat: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseVerifying ||
		status.LastAction != HostSelfUpdateActionAwaitProof {
		t.Fatalf("self-update committed without heartbeat proof: %#v", status)
	}

	status, err = controller.Reconcile(
		context.Background(),
		"host-a",
		&request,
		HostSelfUpdateAgentProof{
			RunningAgentVersion:   "v1.8.0",
			PanelHeartbeatVersion: "v1.8.0",
			HeartbeatGeneration:   request.Generation,
		},
		fence,
		HostLifecycleBlockers{},
		hostSelfUpdateControllerTestGrantProvider,
	)
	if err != nil {
		t.Fatalf("reconcile after heartbeat: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		status.State.ActiveSlot != HostSelfUpdateSlotB ||
		status.LastAction != HostSelfUpdateActionCommit {
		t.Fatalf("verified self-update did not commit: %#v", status)
	}
}

func TestHostSelfUpdateControllerCachesStableFailedGenerationWithoutGrant(t *testing.T) {
	request := validHostSelfUpdateRequest()
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision: 7, OwnershipEpoch: 3,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 9,
	}
	for _, drifted := range []bool{false, true} {
		name := "stable"
		if drifted {
			name = "after_slot_drift_recovery"
		}
		t.Run(name, func(t *testing.T) {
			state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
			if err != nil {
				t.Fatal(err)
			}
			state.FailedGeneration = request.Generation
			executor := &hostSelfUpdateControllerTestExecutor{
				status: HostSelfUpdateRuntimeStatus{
					State:                   state,
					CurrentSlot:             state.ActiveSlot,
					ExecutorVersion:         state.ActiveExecutorVersion,
					ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
				},
			}
			if drifted {
				executor.status.CurrentSlot = otherHostSelfUpdateSlot(state.ActiveSlot)
			}
			controller, err := NewHostSelfUpdateController(
				executor,
				HostSelfUpdateControllerOptions{},
			)
			if err != nil {
				t.Fatal(err)
			}
			grantCalls := 0
			grantProvider := func(
				context.Context,
				string,
			) (HostSelfUpdateGrantAuthorization, error) {
				grantCalls++
				return HostSelfUpdateGrantAuthorization{},
					errors.New("failed generation requested a grant")
			}

			status, err := controller.Reconcile(
				context.Background(), "host-a", &request,
				HostSelfUpdateAgentProof{}, fence,
				HostLifecycleBlockers{}, grantProvider,
			)
			if err != nil {
				t.Fatalf("cache stable failed generation: %v", err)
			}
			if drifted {
				if status.CurrentSlot != state.ActiveSlot ||
					status.LastAction != HostSelfUpdateActionRestoreHealthy {
					t.Fatalf("stable slot drift was not recovered: %#v", status)
				}
				status, err = controller.Reconcile(
					context.Background(), "host-a", &request,
					HostSelfUpdateAgentProof{}, fence,
					HostLifecycleBlockers{}, grantProvider,
				)
				if err != nil {
					t.Fatalf("cache failed generation after drift recovery: %v", err)
				}
			}
			if status.State.Phase != HostSelfUpdatePhaseStable ||
				status.State.FailedGeneration != request.Generation ||
				grantCalls != 0 ||
				len(executor.stageRequests) != 0 ||
				len(executor.activateCalls) != 0 {
				t.Fatalf(
					"failed generation was not a grantless stable no-op: status=%#v grants=%d executor=%#v",
					status,
					grantCalls,
					executor,
				)
			}
		})
	}
}

func TestHostSelfUpdateControllerWaitsForPendingExecutorDuringDrain(t *testing.T) {
	request := validHostSelfUpdateRequest()
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision: 7, OwnershipEpoch: 3,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 9,
	}
	for _, phase := range []string{
		HostSelfUpdatePhaseActivating,
		HostSelfUpdatePhaseVerifying,
	} {
		for _, mismatch := range []string{"version", "protocol"} {
			t.Run(phase+"_"+mismatch, func(t *testing.T) {
				state := activatingHostSelfUpdateState(t)
				state.Phase = phase
				status := HostSelfUpdateRuntimeStatus{
					State:                   state,
					CurrentSlot:             state.PendingSlot,
					ExecutorVersion:         state.PendingExecutorVersion,
					ExecutorProtocolVersion: state.PendingExecutorProtocol,
				}
				switch mismatch {
				case "version":
					status.ExecutorVersion = state.ActiveExecutorVersion
				case "protocol":
					status.ExecutorProtocolVersion = state.PendingExecutorProtocol - 1
				default:
					t.Fatalf("unknown mismatch %q", mismatch)
				}
				executor := &hostSelfUpdateControllerTestExecutor{status: status}
				controller, err := NewHostSelfUpdateController(
					executor,
					HostSelfUpdateControllerOptions{},
				)
				if err != nil {
					t.Fatal(err)
				}

				got, err := controller.Reconcile(
					context.Background(), "host-a", &request,
					HostSelfUpdateAgentProof{
						RunningAgentVersion:   request.AgentVersion,
						PanelHeartbeatVersion: request.AgentVersion,
						HeartbeatGeneration:   request.Generation,
					},
					fence,
					HostLifecycleBlockers{},
					nil,
				)
				if err != nil {
					t.Fatalf("wait for replacement executor: %v", err)
				}
				if got.State.Phase != phase ||
					got.CurrentSlot != state.PendingSlot ||
					got.ExecutorVersion != status.ExecutorVersion ||
					got.ExecutorProtocolVersion != status.ExecutorProtocolVersion ||
					len(executor.reconcileProofs) != 0 {
					t.Fatalf(
						"executor drain mutated the active transition: got=%#v executor=%#v",
						got,
						executor,
					)
				}
			})
		}
	}

	t.Run("changed_desired_generation_remains_rejected", func(t *testing.T) {
		state := activatingHostSelfUpdateState(t)
		executor := &hostSelfUpdateControllerTestExecutor{
			status: HostSelfUpdateRuntimeStatus{
				State:                   state,
				CurrentSlot:             state.PendingSlot,
				ExecutorVersion:         state.ActiveExecutorVersion,
				ExecutorProtocolVersion: state.PendingExecutorProtocol,
			},
		}
		controller, err := NewHostSelfUpdateController(
			executor,
			HostSelfUpdateControllerOptions{},
		)
		if err != nil {
			t.Fatal(err)
		}
		changed := request
		changed.Generation = "update-20260728-002"

		_, err = controller.Reconcile(
			context.Background(), "host-a", &changed,
			HostSelfUpdateAgentProof{}, fence,
			HostLifecycleBlockers{}, nil,
		)
		if err == nil ||
			!strings.Contains(err.Error(), "desired generation changed") {
			t.Fatalf("changed desired generation was hidden by executor drain: %v", err)
		}
		if len(executor.reconcileProofs) != 0 {
			t.Fatalf("changed generation reached root reconcile: %#v", executor)
		}
	})
}

func TestHostSelfUpdateControllerRejectsActiveMutation(t *testing.T) {
	request := validHostSelfUpdateRequest()
	initial, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	executor := &hostSelfUpdateControllerTestExecutor{
		status: HostSelfUpdateRuntimeStatus{
			State:                   initial,
			CurrentSlot:             HostSelfUpdateSlotA,
			ExecutorVersion:         "v1.7.8",
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		},
	}
	controller, err := NewHostSelfUpdateController(
		executor,
		HostSelfUpdateControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision: 7, OwnershipEpoch: 3,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 9,
	}
	if _, err := controller.Reconcile(
		context.Background(), "host-a", &request,
		HostSelfUpdateAgentProof{}, fence,
		HostLifecycleBlockers{ActiveJob: true},
		hostSelfUpdateControllerTestGrantProvider,
	); err == nil || !strings.Contains(err.Error(), "lifecycle mutation") {
		t.Fatalf("active job did not block self-update: %v", err)
	}

}

func TestHostSelfUpdateControllerRestoresStableSlotDriftBeforeStaging(t *testing.T) {
	request := validHostSelfUpdateRequest()
	initial, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	executor := &hostSelfUpdateControllerTestExecutor{
		status: HostSelfUpdateRuntimeStatus{
			State:                   initial,
			CurrentSlot:             HostSelfUpdateSlotB,
			ExecutorVersion:         "v1.7.8",
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		},
	}
	controller, err := NewHostSelfUpdateController(
		executor,
		HostSelfUpdateControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision: 7, OwnershipEpoch: 3,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 9,
	}
	status, err := controller.Reconcile(
		context.Background(), "host-a", &request,
		HostSelfUpdateAgentProof{}, fence, HostLifecycleBlockers{},
		hostSelfUpdateControllerTestGrantProvider,
	)
	if err != nil {
		t.Fatalf("restore stable slot drift: %v", err)
	}
	if status.CurrentSlot != HostSelfUpdateSlotA ||
		status.LastAction != HostSelfUpdateActionRestoreHealthy ||
		!status.RestartRequested {
		t.Fatalf("stable slot drift was not restored: %#v", status)
	}
	if len(executor.stageRequests) != 0 || len(executor.activateCalls) != 0 {
		t.Fatalf("new generation ran before drift recovery: %#v", executor)
	}
}

func TestHostSelfUpdateControllerResumesDurableStageAfterProcessCrash(t *testing.T) {
	request := validHostSelfUpdateRequest()
	initial, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageHostSelfUpdate(
		initial,
		request,
		HostLifecycleBlockers{},
		validHostSelfUpdateSlotDigests(),
	)
	if err != nil {
		t.Fatal(err)
	}
	executor := &hostSelfUpdateControllerTestExecutor{
		status: HostSelfUpdateRuntimeStatus{
			State:                   staged,
			CurrentSlot:             HostSelfUpdateSlotA,
			ExecutorVersion:         "v1.7.8",
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		},
	}
	controller, err := NewHostSelfUpdateController(
		executor,
		HostSelfUpdateControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision: 7, OwnershipEpoch: 3,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 9,
	}
	status, err := controller.Reconcile(
		context.Background(), "host-a", &request,
		HostSelfUpdateAgentProof{}, fence, HostLifecycleBlockers{},
		hostSelfUpdateControllerTestGrantProvider,
	)
	if err != nil {
		t.Fatalf("resume staged update: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseActivating ||
		len(executor.activateCalls) != 1 ||
		len(executor.stageRequests) != 0 {
		t.Fatalf("durable stage was stranded or restaged: status=%#v executor=%#v", status, executor)
	}
}
