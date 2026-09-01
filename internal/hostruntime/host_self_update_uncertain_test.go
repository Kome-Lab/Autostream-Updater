//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHostSelfUpdateUncertainStagePersistsFailureBeforeGrantCleanup(
	t *testing.T,
) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	rt := hostSelfUpdateExecutorRuntime{
		stateRoot:      stateRoot,
		statePath:      filepath.Join(stateRoot, "state.json"),
		grantStatePath: filepath.Join(stateRoot, "grant.json"),
		allowTestPaths: true,
	}
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    7,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: 11,
		ExecutorPolicyRevision:  9,
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		request,
		fence,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	prepared := newHostSelfUpdateGrantState(authorization)
	if err := saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		prepared,
		false,
	); err != nil {
		t.Fatal(err)
	}
	status := HostSelfUpdateRuntimeStatus{
		State:                   state,
		CurrentSlot:             state.ActiveSlot,
		ExecutorVersion:         state.ActiveExecutorVersion,
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
	}

	failed, err := rt.failClosedUncertainStage(
		status,
		request,
		authorization,
	)
	if err != nil {
		t.Fatalf("fail closed uncertain stage: %v", err)
	}
	if failed.State.Phase != HostSelfUpdatePhaseStable ||
		failed.State.FailedGeneration != request.Generation ||
		failed.State.PendingGeneration != "" ||
		failed.CurrentSlot != state.ActiveSlot {
		t.Fatalf("unexpected failed status: %#v", failed)
	}
	persisted, err := rt.loadPersistedState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.FailedGeneration != request.Generation {
		t.Fatalf("failure fence was not durable: %#v", persisted)
	}
	terminal, err := loadHostSelfUpdateGrantState(rt.grantStatePath, false)
	if err != nil ||
		terminal == nil ||
		terminal.Phase != hostSelfUpdateGrantPhaseFailed ||
		!terminal.matches(authorization) {
		t.Fatalf(
			"prepared grant did not converge to exact failure: %#v err=%v",
			terminal,
			err,
		)
	}
}

func TestHostSelfUpdateFreshStatusRecoversDurableGrantCrashMatrix(
	t *testing.T,
) {
	for _, testCase := range []struct {
		name           string
		operation      string
		grantPhase     string
		stateMode      string
		wantStatePhase string
		wantGrantPhase string
		wantRemoved    bool
		wantFailed     bool
	}{
		{
			name:           "prepared_stage_before_receipt",
			operation:      "stage",
			grantPhase:     hostSelfUpdateGrantPhasePrepared,
			stateMode:      "stable_old",
			wantStatePhase: HostSelfUpdatePhaseStable,
			wantGrantPhase: hostSelfUpdateGrantPhaseFailed,
			wantFailed:     true,
		},
		{
			name:           "consumed_stage_before_state",
			operation:      "stage",
			grantPhase:     hostSelfUpdateGrantPhaseConsumed,
			stateMode:      "stable_old",
			wantStatePhase: HostSelfUpdatePhaseStable,
			wantGrantPhase: hostSelfUpdateGrantPhaseFailed,
			wantFailed:     true,
		},
		{
			name:           "consumed_stage_after_staged_state",
			operation:      "stage",
			grantPhase:     hostSelfUpdateGrantPhaseConsumed,
			stateMode:      "staged",
			wantStatePhase: HostSelfUpdatePhaseStaged,
			wantGrantPhase: hostSelfUpdateGrantPhaseApplied,
		},
		{
			name:           "consumed_stage_after_stable_commit",
			operation:      "stage",
			grantPhase:     hostSelfUpdateGrantPhaseConsumed,
			stateMode:      "stable_target",
			wantStatePhase: HostSelfUpdatePhaseStable,
			wantGrantPhase: hostSelfUpdateGrantPhaseApplied,
		},
		{
			name:           "prepared_reconcile_before_receipt",
			operation:      "reconcile",
			grantPhase:     hostSelfUpdateGrantPhasePrepared,
			stateMode:      "activating",
			wantStatePhase: HostSelfUpdatePhaseActivating,
			wantRemoved:    true,
		},
		{
			name:           "consumed_reconcile_before_state",
			operation:      "reconcile",
			grantPhase:     hostSelfUpdateGrantPhaseConsumed,
			stateMode:      "activating",
			wantStatePhase: HostSelfUpdatePhaseActivating,
			wantGrantPhase: hostSelfUpdateGrantPhaseApplied,
		},
		{
			name:           "consumed_reconcile_after_stable_success",
			operation:      "reconcile",
			grantPhase:     hostSelfUpdateGrantPhaseConsumed,
			stateMode:      "stable_target",
			wantStatePhase: HostSelfUpdatePhaseStable,
			wantGrantPhase: hostSelfUpdateGrantPhaseApplied,
		},
		{
			name:           "consumed_reconcile_after_stable_rollback",
			operation:      "reconcile",
			grantPhase:     hostSelfUpdateGrantPhaseConsumed,
			stateMode:      "stable_failed",
			wantStatePhase: HostSelfUpdatePhaseStable,
			wantGrantPhase: hostSelfUpdateGrantPhaseApplied,
			wantFailed:     true,
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			rt := newHostSelfUpdateGrantRecoveryRuntime(t)
			request := validHostSelfUpdateRequest()
			state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
			if err != nil {
				t.Fatal(err)
			}
			if testCase.stateMode == "staged" ||
				testCase.stateMode == "activating" ||
				testCase.stateMode == "stable_target" {
				slotDigests := bindHostSelfUpdateGrantRecoverySlot(
					t,
					&rt,
					request,
				)
				state, err = StageHostSelfUpdate(
					state,
					request,
					HostLifecycleBlockers{},
					slotDigests,
				)
				if err != nil {
					t.Fatal(err)
				}
			}
			if testCase.stateMode == "activating" {
				state, err = BeginHostSelfUpdateActivation(
					state,
					time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC),
					time.Minute,
				)
				if err != nil {
					t.Fatal(err)
				}
			}
			if testCase.stateMode == "stable_target" {
				state = commitHostSelfUpdate(state)
				rt.executorVersion = request.ExecutorVersion
				if err := rt.switchCurrent(state.ActiveSlot); err != nil {
					t.Fatal(err)
				}
			}
			if testCase.stateMode == "stable_failed" {
				state.FailedGeneration = request.Generation
			}
			if err := rt.saveState(state); err != nil {
				t.Fatal(err)
			}
			fence := LocalExecutorMutationFence{
				SourcePolicyRevision:    7,
				OwnershipEpoch:          3,
				OwnershipPolicyRevision: 11,
				ExecutorPolicyRevision:  9,
			}
			authorization := validHostSelfUpdateGrantAuthorization(
				testCase.operation,
				request,
				fence,
				"sha256:"+strings.Repeat("a", 64),
			)
			grant := newHostSelfUpdateGrantState(authorization)
			if testCase.grantPhase == hostSelfUpdateGrantPhaseConsumed {
				receipt := consumedHostSelfUpdateGrant(authorization).Grant
				grant.Phase = hostSelfUpdateGrantPhaseConsumed
				grant.Receipt = &receipt
			}
			if err := saveHostSelfUpdateGrantState(
				rt.grantStatePath,
				grant,
				false,
			); err != nil {
				t.Fatal(err)
			}

			// A fresh runtime has no raw token or in-memory authorization
			// result; it can use only root-owned durable state.
			fresh := rt
			status, err := fresh.status()
			if err != nil {
				t.Fatalf("fresh status recovery: %v", err)
			}
			if status.State.Phase != testCase.wantStatePhase {
				t.Fatalf("recovered status=%#v", status)
			}
			if testCase.wantFailed &&
				status.State.FailedGeneration != request.Generation {
				t.Fatalf("failed generation was not fenced: %#v", status)
			}
			recoveredGrant, err := loadHostSelfUpdateGrantState(
				fresh.grantStatePath,
				false,
			)
			if err != nil {
				t.Fatal(err)
			}
			if testCase.wantRemoved {
				if recoveredGrant != nil {
					t.Fatalf(
						"orphan grant survived recovery: %#v",
						recoveredGrant,
					)
				}
			} else if recoveredGrant == nil ||
				recoveredGrant.Phase != testCase.wantGrantPhase {
				t.Fatalf(
					"grant phase=%#v, want %q",
					recoveredGrant,
					testCase.wantGrantPhase,
				)
			}
		})
	}
}

func TestHostSelfUpdateFreshStatusRejectsContradictoryDurableGrant(
	t *testing.T,
) {
	rt := newHostSelfUpdateGrantRecoveryRuntime(t)
	request := validHostSelfUpdateRequest()
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	state, err = StageHostSelfUpdate(
		state,
		request,
		HostLifecycleBlockers{},
		validHostSelfUpdateSlotDigests(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	other := request
	other.Generation = "update-20260728-contradictory"
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    7,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: 11,
		ExecutorPolicyRevision:  9,
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		other,
		fence,
		"sha256:"+strings.Repeat("a", 64),
	)
	grant := newHostSelfUpdateGrantState(authorization)
	receipt := consumedHostSelfUpdateGrant(authorization).Grant
	grant.Phase = hostSelfUpdateGrantPhaseConsumed
	grant.Receipt = &receipt
	if err := saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		grant,
		false,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := rt.status(); err == nil ||
		!strings.Contains(err.Error(), "contradicts") {
		t.Fatalf("contradictory durable grant status error = %v", err)
	}
	persisted, err := rt.loadPersistedState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Phase != HostSelfUpdatePhaseStaged ||
		persisted.PendingGeneration != request.Generation ||
		persisted.FailedGeneration != "" {
		t.Fatalf("contradictory grant mutated state: %#v", persisted)
	}
	unchangedGrant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		false,
	)
	if err != nil || unchangedGrant == nil ||
		unchangedGrant.Phase != hostSelfUpdateGrantPhaseConsumed {
		t.Fatalf(
			"contradictory grant was silently consumed: %#v err=%v",
			unchangedGrant,
			err,
		)
	}
}

func TestHostSelfUpdateFailedGenerationConvergesInterruptedPreparedGrant(
	t *testing.T,
) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	rt := hostSelfUpdateExecutorRuntime{
		stateRoot:      stateRoot,
		statePath:      filepath.Join(stateRoot, "state.json"),
		grantStatePath: filepath.Join(stateRoot, "grant.json"),
		allowTestPaths: true,
	}
	request := validHostSelfUpdateRequest()
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	state.FailedGeneration = request.Generation
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    7,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: 11,
		ExecutorPolicyRevision:  9,
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		request,
		fence,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if err := saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		newHostSelfUpdateGrantState(authorization),
		false,
	); err != nil {
		t.Fatal(err)
	}

	if err := rt.cleanFailedHostSelfUpdateGrant(state); err != nil {
		t.Fatalf("recover interrupted cleanup: %v", err)
	}
	terminal, err := loadHostSelfUpdateGrantState(rt.grantStatePath, false)
	if err != nil ||
		terminal == nil ||
		terminal.Phase != hostSelfUpdateGrantPhaseFailed ||
		!terminal.matches(authorization) {
		t.Fatalf(
			"interrupted prepared grant did not converge: %#v err=%v",
			terminal,
			err,
		)
	}
}

func newHostSelfUpdateGrantRecoveryRuntime(
	t *testing.T,
) hostSelfUpdateExecutorRuntime {
	t.Helper()
	root := t.TempDir()
	installRoot := filepath.Join(root, "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if err := os.MkdirAll(
			filepath.Join(slotsRoot, slot, "bin"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
		for _, binary := range []string{
			"autostream-host-agent",
			"autostream-local-executor",
		} {
			if err := os.WriteFile(
				filepath.Join(slotsRoot, slot, "bin", binary),
				[]byte(binary+"\n"),
				0o755,
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Symlink(
		filepath.Join("slots", HostSelfUpdateSlotA),
		filepath.Join(installRoot, "current"),
	); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	rt := hostSelfUpdateExecutorRuntime{
		installRoot:     installRoot,
		currentLink:     filepath.Join(installRoot, "current"),
		slotsRoot:       slotsRoot,
		stateRoot:       stateRoot,
		statePath:       filepath.Join(stateRoot, "state.json"),
		grantStatePath:  filepath.Join(stateRoot, "grant.json"),
		downloadRoot:    filepath.Join(stateRoot, "downloads"),
		executorVersion: "v1.7.8",
		arch:            "amd64",
		runner:          OSCommandRunner{},
		now:             time.Now,
		consumeGrant: func(
			context.Context,
			string,
			HostSelfUpdateGrantAuthorization,
		) (HostSelfUpdateGrantConsumeResult, error) {
			return HostSelfUpdateGrantConsumeResult{},
				errors.New("unexpected consume")
		},
		allowTestPaths: true,
	}
	if err := rt.prepare(); err != nil {
		t.Fatal(err)
	}
	return rt
}

func bindHostSelfUpdateGrantRecoverySlot(
	t *testing.T,
	rt *hostSelfUpdateExecutorRuntime,
	request HostSelfUpdateRequest,
) hostSelfUpdateSlotDigests {
	t.Helper()
	slotRoot := filepath.Join(rt.slotsRoot, HostSelfUpdateSlotB)
	digests, err := hostSelfUpdateArtifactBinaryDigests(slotRoot)
	if err != nil {
		t.Fatal(err)
	}
	markers, err := hostSelfUpdateSlotMarkers(
		request,
		map[string]string{
			"autostream-host-agent":     digests.AgentSHA256,
			"autostream-local-executor": digests.ExecutorSHA256,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range markers {
		if err := writeAtomicFile(
			filepath.Join(slotRoot, name),
			value,
			0o444,
		); err != nil {
			t.Fatal(err)
		}
	}
	rt.runner = hostSelfUpdateSlotIdentityRunner{request: request}
	return digests
}
