package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestRuntimeCredentialExecutorExpiryNeverChangesActiveIdentity(
	t *testing.T,
) {
	for _, localStageSucceeded := range []bool{false, true} {
		name := "before_local_stage"
		if localStageSucceeded {
			name = "after_local_stage"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 7, 28, 14, 0, 0, 0, time.UTC)
			policy, rt, request, activeBytes :=
				newRuntimeCredentialExecutorFixture(t, now)
			rt.acknowledgeStage = func(
				context.Context, string, string, int64, string, *http.Client,
			) (HostAgentRuntimeTokenRotation, error) {
				if !localStageSucceeded {
					return HostAgentRuntimeTokenRotation{}, errors.New(
						"panel unavailable",
					)
				}
				return testRuntimeTokenRotation(
					"local_staged", 3, now, now.Add(time.Second),
				), nil
			}
			stage := handleLocalExecutorRuntimeCredential(
				context.Background(), policy, request, rt,
			)
			if localStageSucceeded {
				requireRuntimeCredentialPhase(
					t, stage, RuntimeCredentialPhaseLocalStaged, 3,
				)
			} else if stage.Error == nil {
				t.Fatal("unavailable local-stage endpoint unexpectedly succeeded")
			}

			rt.now = func() time.Time {
				return now.Add(runtimeCredentialStagedMaxAge + time.Second)
			}
			rebooted := rt
			statusRequest := LocalExecutorRequest{
				Version:   LocalExecutorMutationProtocolVersion,
				Operation: "runtime_credential_status",
				ServiceID: request.ServiceID,
			}
			expired := handleLocalExecutorRuntimeCredential(
				context.Background(), policy, statusRequest, rebooted,
			)
			requireRuntimeCredentialPhase(
				t, expired, RuntimeCredentialPhaseExpired,
				stageRevision(localStageSucceeded),
			)
			activeAfter, err := os.ReadFile(rt.activeIdentity)
			if err != nil || !bytes.Equal(activeAfter, activeBytes) {
				t.Fatal("expiry changed the active Host Agent identity")
			}
			if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expired staged identity survived: %v", err)
			}

			activate := request
			activate.Operation = "runtime_credential_activate"
			activate.RuntimeCredential = cloneRuntimeCredentialMutation(
				request.RuntimeCredential,
				stageRevision(localStageSucceeded),
				"",
			)
			if response := handleLocalExecutorRuntimeCredential(
				context.Background(), policy, activate, rt,
			); response.Error == nil {
				t.Fatal("expired staged identity remained activatable")
			}

			cancel := request
			cancel.Operation = "runtime_credential_cancel"
			cancel.RuntimeCredential = cloneRuntimeCredentialMutation(
				request.RuntimeCredential,
				stageRevision(localStageSucceeded)+1,
				"",
			)
			cancelReady := handleLocalExecutorRuntimeCredential(
				context.Background(), policy, cancel, rt,
			)
			requireRuntimeCredentialPhase(
				t,
				cancelReady,
				RuntimeCredentialPhaseCancelReady,
				stageRevision(localStageSucceeded)+1,
			)
			final := cancel
			final.RuntimeCredential = cloneRuntimeCredentialMutation(
				request.RuntimeCredential,
				stageRevision(localStageSucceeded)+2,
				"",
			)
			requireRuntimeCredentialPhase(
				t,
				handleLocalExecutorRuntimeCredential(
					context.Background(), policy, final, rt,
				),
				RuntimeCredentialPhaseCancelled,
				stageRevision(localStageSucceeded)+2,
			)
		})
	}
}

func TestRuntimeCredentialExecutorUntrackedCancelFailsClosedWithoutWipingStage(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	policy, rt, request, activeBytes := newRuntimeCredentialExecutorFixture(
		t, now,
	)
	active, _, _, err := rt.loadIdentity(
		rt.activeIdentity, policy.AgentGID,
	)
	if err != nil {
		t.Fatal(err)
	}
	staged := active
	staged.RuntimeToken = testNewRuntimeToken
	stagedBytes, err := marshalRuntimeCredentialIdentity(staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.writeIdentityAtomic(
		rt.stagedIdentity, stagedBytes, policy.AgentGID, false,
	); err != nil {
		t.Fatal(err)
	}
	cancel := request
	cancel.Operation = "runtime_credential_cancel"
	cancel.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential, 3, "",
	)
	cancel.RuntimeCredential.RotationID = "attacker-supplied-rotation"
	cancel.RuntimeCredential.PreviousTokenID = "attacker-supplied-previous"
	cancel.RuntimeCredential.StagedTokenID = "attacker-supplied-staged"
	response := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, cancel, rt,
	)
	if response.Error == nil ||
		response.Error.Code != "mutation_precondition_failed" {
		t.Fatalf("untracked cancel response = %#v", response)
	}
	preserved, err := os.ReadFile(rt.stagedIdentity)
	if err != nil || !bytes.Equal(preserved, stagedBytes) {
		t.Fatal("untracked cancel changed the staged identity")
	}
	activeAfter, err := os.ReadFile(rt.activeIdentity)
	if err != nil || !bytes.Equal(activeAfter, activeBytes) {
		t.Fatal("untracked cancel changed the active identity")
	}
	if _, exists, err := rt.loadStatus(); err != nil || exists {
		t.Fatalf("untracked cancel created root state: exists=%v err=%v", exists, err)
	}
}

func TestRuntimeCredentialExecutorCancelRejectsRevisionSkipping(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 15, 15, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	rt.acknowledgeStage = func(
		context.Context, string, string, int64, string, *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		return testRuntimeTokenRotation(
			"local_staged", 3, now, now.Add(time.Second),
		), nil
	}
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(),
			policy,
			request,
			rt,
		),
		RuntimeCredentialPhaseLocalStaged,
		3,
	)
	skipped := request
	skipped.Operation = "runtime_credential_cancel"
	skipped.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		10,
		"",
	)
	if response := handleLocalExecutorRuntimeCredential(
		context.Background(),
		policy,
		skipped,
		rt,
	); response.Error == nil {
		t.Fatal("revision-skipping cancel unexpectedly changed root state")
	}
	status, exists, err := rt.loadStatus()
	if err != nil || !exists ||
		status.Phase != RuntimeCredentialPhaseLocalStaged ||
		status.RotationRevision != 3 {
		t.Fatalf("revision-skipping cancel state=%#v err=%v", status, err)
	}
}

func TestRuntimeCredentialExecutorUntrackedCancelRejectsOtherRevisions(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 15, 30, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	active, _, _, err := rt.loadIdentity(
		rt.activeIdentity,
		policy.AgentGID,
	)
	if err != nil {
		t.Fatal(err)
	}
	staged := active
	staged.RuntimeToken = testNewRuntimeToken
	stagedBytes, err := marshalRuntimeCredentialIdentity(staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.writeIdentityAtomic(
		rt.stagedIdentity,
		stagedBytes,
		policy.AgentGID,
		false,
	); err != nil {
		t.Fatal(err)
	}
	skipped := request
	skipped.Operation = "runtime_credential_cancel"
	skipped.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		4,
		"",
	)
	if response := handleLocalExecutorRuntimeCredential(
		context.Background(),
		policy,
		skipped,
		rt,
	); response.Error == nil {
		t.Fatal("untracked cancel unexpectedly succeeded")
	}
	preserved, err := os.ReadFile(rt.stagedIdentity)
	if err != nil || !bytes.Equal(preserved, stagedBytes) {
		t.Fatal("rejected untracked cancel changed the staged identity")
	}
	if _, exists, err := rt.loadStatus(); err != nil || exists {
		t.Fatalf("untracked cancel created root state: exists=%v err=%v", exists, err)
	}
}
