package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testOldRuntimeToken = "old-runtime-token-secret"
	testNewRuntimeToken = "new-runtime-token-secret"
)

func TestRuntimeCredentialExecutorRejectsUnsafeIdentityLayoutBeforeMutation(t *testing.T) {
	now := time.Date(2026, 8, 4, 8, 0, 0, 0, time.UTC)
	policy, rt, request, activeBefore := newRuntimeCredentialExecutorFixture(t, now)
	rt.verifyIdentityLayout = func() error {
		return errors.New("Host Agent identity layout ownership drifted")
	}

	response := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, request, rt,
	)
	if response.Error == nil || response.Error.Code != "state_invalid" {
		t.Fatalf("runtime credential response = %#v", response)
	}
	activeAfter, err := os.ReadFile(rt.activeIdentity)
	if err != nil || !bytes.Equal(activeAfter, activeBefore) {
		t.Fatalf("active identity changed: read error=%v", err)
	}
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged identity appeared: %v", err)
	}
	if _, exists, err := rt.loadStatus(); err != nil || exists {
		t.Fatalf("runtime credential state changed: exists=%v err=%v", exists, err)
	}
}

func TestRuntimeCredentialExecutorRechecksIdentityLayoutAfterPanelActivationBeforeActiveWrite(
	t *testing.T,
) {
	now := time.Date(2026, 8, 4, 8, 15, 0, 0, time.UTC)
	policy, rt, request, activeBefore := newRuntimeCredentialExecutorFixture(t, now)
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
			context.Background(), policy, request, rt,
		),
		RuntimeCredentialPhaseLocalStaged,
		3,
	)
	proof := request
	proof.Operation = "runtime_credential_proof_ready"
	proof.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		4,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(), policy, proof, rt,
		),
		RuntimeCredentialPhaseProofReady,
		4,
	)

	identityLayoutDrifted := false
	rt.verifyIdentityLayout = func() error {
		if identityLayoutDrifted {
			return errors.New("Host Agent identity layout permissions drifted")
		}
		return nil
	}
	rt.activate = func(
		context.Context, string, string, int64, string, *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		identityLayoutDrifted = true
		return testRuntimeTokenRotation(
			"activated", 5, now, now.Add(time.Second),
		), nil
	}
	activate := proof
	activate.Operation = "runtime_credential_activate"
	response := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, activate, rt,
	)
	if response.Error == nil || response.Error.Code != "state_invalid" {
		t.Fatalf("runtime credential response = %#v", response)
	}
	activeAfter, err := os.ReadFile(rt.activeIdentity)
	if err != nil || !bytes.Equal(activeAfter, activeBefore) {
		t.Fatalf("active identity changed after layout race: read error=%v", err)
	}
}

func TestEmergencyRuntimeCredentialRecoveryRejectsUnsafeIdentityLayoutBeforeMutation(t *testing.T) {
	now := time.Date(2026, 8, 4, 8, 30, 0, 0, time.UTC)
	policy, rt, _, activeBefore := newRuntimeCredentialExecutorFixture(t, now)
	checks := 0
	rt.verifyIdentityLayout = func() error {
		checks++
		return errors.New("Host Agent identity layout ownership drifted")
	}

	_, err := rt.recoverAfterEmergencyManualReconfigure(policy, "rotation-a")
	if err == nil || !strings.Contains(err.Error(), "identity layout ownership") {
		t.Fatalf("emergency recovery error = %v", err)
	}
	if checks != 1 {
		t.Fatalf("identity layout checks = %d", checks)
	}
	activeAfter, readErr := os.ReadFile(rt.activeIdentity)
	if readErr != nil || !bytes.Equal(activeAfter, activeBefore) {
		t.Fatalf("active identity changed: read error=%v", readErr)
	}
	if _, exists, loadErr := rt.loadStatus(); loadErr != nil || exists {
		t.Fatalf("runtime credential state changed: exists=%v err=%v", exists, loadErr)
	}
}

func TestRuntimeCredentialExecutorActivationResponseLossRecoversWithoutSecretLeak(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	policy, rt, request, activeBytes := newRuntimeCredentialExecutorFixture(
		t, now,
	)
	acknowledgedAt := now.Add(time.Second)
	rt.acknowledgeStage = func(
		_ context.Context,
		_, _ string,
		revision int64,
		token string,
		_ *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		if revision != 2 || token != testNewRuntimeToken {
			t.Fatalf("local-stage request revision=%d token=%q", revision, token)
		}
		return testRuntimeTokenRotation(
			"local_staged", 3, now, acknowledgedAt,
		), nil
	}
	activationCalls := 0
	rt.activate = func(
		_ context.Context,
		_, _ string,
		revision int64,
		token string,
		_ *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		activationCalls++
		if revision != 4 || token != testNewRuntimeToken {
			t.Fatalf("activate request revision=%d token=%q", revision, token)
		}
		if activationCalls == 1 {
			return HostAgentRuntimeTokenRotation{}, errors.New(
				"activation response lost",
			)
		}
		return testRuntimeTokenRotation(
			"activated", 5, now, acknowledgedAt,
		), nil
	}

	stage := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, request, rt,
	)
	requireRuntimeCredentialPhase(
		t, stage, RuntimeCredentialPhaseLocalStaged, 3,
	)
	metadata, err := os.ReadFile(rt.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(metadata, []byte(testOldRuntimeToken)) ||
		bytes.Contains(metadata, []byte(testNewRuntimeToken)) {
		t.Fatalf("root metadata leaked a runtime token: %s", metadata)
	}
	logJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(logJSON, []byte(testNewRuntimeToken)) ||
		!bytes.Contains(logJSON, []byte("[REDACTED]")) {
		t.Fatalf("structured request logging was not redacted: %s", logJSON)
	}

	proof := request
	proof.Operation = "runtime_credential_proof_ready"
	proof.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential, 4, "",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(), policy, proof, rt,
		),
		RuntimeCredentialPhaseProofReady,
		4,
	)

	activate := proof
	activate.Operation = "runtime_credential_activate"
	first := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, activate, rt,
	)
	if first.Error == nil {
		t.Fatal("lost activation response unexpectedly completed locally")
	}
	rebooted := rt
	second := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, activate, rebooted,
	)
	requireRuntimeCredentialPhase(
		t, second, RuntimeCredentialPhaseActivated, 5,
	)
	if activationCalls != 2 {
		t.Fatalf("activation calls=%d, want response-loss replay", activationCalls)
	}
	activeAfter, err := os.ReadFile(rt.activeIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(activeAfter, activeBytes) ||
		!bytes.Contains(activeAfter, []byte(testNewRuntimeToken)) {
		t.Fatal("active identity did not atomically switch to the staged token")
	}
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged identity survived activation: %v", err)
	}
}

func TestRuntimeCredentialExecutorRecoversWriteBeforeLedgerPowerLoss(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 13, 0, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	active, activeBytes, _, err := rt.loadIdentity(
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
	if _, err := os.Lstat(rt.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("power-loss fixture unexpectedly has metadata: %v", err)
	}
	rt.acknowledgeStage = func(
		context.Context, string, string, int64, string, *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		return testRuntimeTokenRotation(
			"local_staged", 3, now, now.Add(time.Second),
		), nil
	}
	response := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, request, rt,
	)
	requireRuntimeCredentialPhase(
		t, response, RuntimeCredentialPhaseLocalStaged, 3,
	)
	if digest := runtimeCredentialDigest(activeBytes); digest !=
		response.RuntimeCredential.PreviousIdentitySHA256 {
		t.Fatalf("previous identity digest=%q want=%q", response.RuntimeCredential.PreviousIdentitySHA256, digest)
	}

	bad := request
	bad.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential, 2, "different-staged-secret",
	)
	_ = os.Remove(rt.statePath)
	failed := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, bad, rt,
	)
	if failed.Error == nil {
		t.Fatal("mismatched claim replay accepted an orphaned staged identity")
	}
	preserved, err := os.ReadFile(rt.stagedIdentity)
	if err != nil || !bytes.Equal(preserved, stagedBytes) {
		t.Fatal("mismatched replay changed the orphaned staged identity")
	}
}

func TestRuntimeCredentialExecutorPersistsClaimBindingBeforeStagedFileWrite(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 13, 15, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	prepare := request
	prepare.Operation = "runtime_credential_prepare"
	prepare.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		1,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(),
			policy,
			prepare,
			rt,
		),
		RuntimeCredentialPhaseClaimPrepared,
		1,
	)
	rt.writeStagedIdentity = func(
		string,
		[]byte,
		uint32,
		bool,
	) error {
		return errors.New("injected stop before staged identity write")
	}
	failed := handleLocalExecutorRuntimeCredential(
		context.Background(),
		policy,
		request,
		rt,
	)
	if failed.Error == nil {
		t.Fatal("injected staged identity interruption was hidden")
	}
	status, exists, err := rt.loadStatus()
	if err != nil || !exists {
		t.Fatalf("load pre-write root binding: %v", err)
	}
	if status.Phase != RuntimeCredentialPhaseStageBound ||
		status.RotationRevision != 2 ||
		status.StagedIdentitySHA256 == runtimeCredentialDigest(nil) ||
		status.stagedRuntimeTokenSHA256 !=
			runtimeCredentialTokenDigest(testNewRuntimeToken) {
		t.Fatalf("pre-write root binding=%#v", status)
	}
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("interrupted write created a staged identity: %v", err)
	}

	rt.writeStagedIdentity = nil
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
}

func TestEmergencyManualReconfigureRecoveryAcceptsStageBoundWithoutFileImmediately(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 13, 20, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	prepare := request
	prepare.Operation = "runtime_credential_prepare"
	prepare.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		1,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(),
			policy,
			prepare,
			rt,
		),
		RuntimeCredentialPhaseClaimPrepared,
		1,
	)
	rt.writeStagedIdentity = func(
		string,
		[]byte,
		uint32,
		bool,
	) error {
		return errors.New("injected stop before staged identity write")
	}
	if response := handleLocalExecutorRuntimeCredential(
		context.Background(),
		policy,
		request,
		rt,
	); response.Error == nil {
		t.Fatal("injected staged identity interruption was hidden")
	}
	replacement := replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		"stage-bound-emergency-replacement-token",
	)

	recovered, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil ||
		recovered.Phase != RuntimeCredentialPhaseManualRecovered ||
		recovered.ActiveIdentitySHA256 !=
			runtimeCredentialDigest(replacement) {
		t.Fatalf(
			"stage-bound immediate recovery=%#v err=%v",
			recovered,
			err,
		)
	}
}

func TestEmergencyManualReconfigureRecoveryPromotesInstalledStageBoundAndRequiresTTL(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 13, 25, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	prepare := request
	prepare.Operation = "runtime_credential_prepare"
	prepare.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		1,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(),
			policy,
			prepare,
			rt,
		),
		RuntimeCredentialPhaseClaimPrepared,
		1,
	)
	rt.writeStagedIdentity = func(
		path string,
		data []byte,
		gid uint32,
		overwrite bool,
	) error {
		if err := rt.writeIdentityAtomic(
			path,
			data,
			gid,
			overwrite,
		); err != nil {
			return err
		}
		return errors.New("injected stop after staged identity write")
	}
	if response := handleLocalExecutorRuntimeCredential(
		context.Background(),
		policy,
		request,
		rt,
	); response.Error == nil {
		t.Fatal("injected post-write interruption was hidden")
	}
	status, exists, err := rt.loadStatus()
	if err != nil || !exists ||
		status.Phase != RuntimeCredentialPhaseStageBound {
		t.Fatalf("post-write stage-bound status=%#v exists=%v err=%v", status, exists, err)
	}
	if _, err := os.Lstat(rt.stagedIdentity); err != nil {
		t.Fatalf("post-write stage-bound file is unavailable: %v", err)
	}
	replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		"stage-bound-installed-emergency-replacement-token",
	)
	if _, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	); err == nil {
		t.Fatal("installed stage-bound identity bypassed the staged TTL")
	}
	status, exists, err = rt.loadStatus()
	if err != nil || !exists ||
		status.Phase != RuntimeCredentialPhaseStaged {
		t.Fatalf("installed stage-bound promotion=%#v exists=%v err=%v", status, exists, err)
	}
	if _, err := os.Lstat(rt.stagedIdentity); err != nil {
		t.Fatalf("pre-TTL rejection removed the staged identity: %v", err)
	}

	rt.now = func() time.Time {
		return now.Add(runtimeCredentialStagedMaxAge + time.Second)
	}
	recovered, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil ||
		recovered.Phase != RuntimeCredentialPhaseManualRecovered {
		t.Fatalf("post-TTL stage-bound recovery=%#v err=%v", recovered, err)
	}
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-TTL recovery retained the staged identity: %v", err)
	}
}

func TestClaimPreparedWriteBeforeLedgerCompatibilitySupportsEmergencyRecovery(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 13, 30, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	prepare := request
	prepare.Operation = "runtime_credential_prepare"
	prepare.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		1,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(),
			policy,
			prepare,
			rt,
		),
		RuntimeCredentialPhaseClaimPrepared,
		1,
	)
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
	replacement := replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		"legacy-write-emergency-replacement-token",
	)
	rt.now = func() time.Time {
		return now.Add(runtimeCredentialStagedMaxAge + time.Second)
	}

	recovered, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil ||
		recovered.Phase != RuntimeCredentialPhaseManualRecovered ||
		recovered.ActiveIdentitySHA256 !=
			runtimeCredentialDigest(replacement) {
		t.Fatalf(
			"write-before-ledger emergency recovery=%#v err=%v",
			recovered,
			err,
		)
	}
	if !rt.identityCleanupComplete() {
		t.Fatal("legacy write-before-ledger staged slot survived recovery")
	}
}

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

func newRuntimeCredentialExecutorFixture(
	t *testing.T,
	now time.Time,
) (
	LocalExecutorPolicy,
	runtimeCredentialExecutorRuntime,
	LocalExecutorRequest,
	[]byte,
) {
	t.Helper()
	root := t.TempDir()
	identityDir := filepath.Join(root, "identity")
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(identityDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(identityDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	active := managedHostAgentBootstrap("https://panel.example.com")
	active.NodeID = "worker-01"
	active.RuntimeToken = testOldRuntimeToken
	activeBytes, err := marshalRuntimeCredentialIdentity(active)
	if err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(identityDir, "agent.yaml")
	if err := os.WriteFile(activePath, activeBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(activePath, 0o640); err != nil {
		t.Fatal(err)
	}

	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.SourcePolicyRevision = 11
	policy.ProjectionRevision = 12
	policy.PolicyRevision = 13
	policy.Mutation = &LocalExecutorMutationPolicy{
		PanelURL: "https://panel.example.com",
	}
	rt := runtimeCredentialExecutorRuntime{
		identityDir:     identityDir,
		activeIdentity:  activePath,
		stagedIdentity:  filepath.Join(identityDir, "agent.staged.yaml"),
		wipingIdentity:  filepath.Join(identityDir, ".agent.staged.wipe"),
		statePath:       filepath.Join(stateDir, "runtime-credential.json"),
		allowTestPaths:  true,
		executorVersion: "v1.0.0",
		now: func() time.Time {
			return now
		},
	}
	request := LocalExecutorRequest{
		Version:                 LocalExecutorMutationProtocolVersion,
		Operation:               "runtime_credential_stage",
		ServiceID:               "worker-01",
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          7,
		OwnershipPolicyRevision: policy.ProjectionRevision,
		ExecutorPolicyRevision:  policy.PolicyRevision,
		RuntimeCredential: &RuntimeCredentialMutation{
			RotationID:       "rotation-a",
			ExecutionHostID:  policy.HostID,
			PreviousTokenID:  "old-token-id",
			StagedTokenID:    "new-token-id",
			RotationRevision: 2,
			RuntimeToken:     NewBoundedSecret(testNewRuntimeToken),
		},
	}
	return policy, rt, request, activeBytes
}

func testRuntimeTokenRotation(
	status string,
	revision int64,
	claimedAt time.Time,
	acknowledgedAt time.Time,
) HostAgentRuntimeTokenRotation {
	rotation := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-a",
		ServiceID:                           "worker-01",
		ExecutionHostID:                     "host-a",
		Status:                              status,
		Revision:                            revision,
		ExpectedOwnershipEpoch:              7,
		ExpectedSourcePolicyRevision:        11,
		ExpectedProjectionRevision:          12,
		ExpectedLocalExecutorPolicyRevision: 13,
		PreviousTokenID:                     "old-token-id",
		StagedTokenID:                       "new-token-id",
		CredentialClaimedAt:                 &claimedAt,
		LocalStageReceiptID:                 "receipt-a",
		LocalStageAcknowledgedAt:            &acknowledgedAt,
	}
	return rotation
}

func cloneRuntimeCredentialMutation(
	source *RuntimeCredentialMutation,
	revision int64,
	token string,
) *RuntimeCredentialMutation {
	copy := *source
	copy.RotationRevision = revision
	copy.RuntimeToken = NewBoundedSecret(token)
	return &copy
}

func requireRuntimeCredentialPhase(
	t *testing.T,
	response LocalExecutorResponse,
	phase string,
	revision int64,
) {
	t.Helper()
	if response.Error != nil ||
		response.RuntimeCredential == nil ||
		response.RuntimeCredential.Phase != phase ||
		response.RuntimeCredential.RotationRevision != revision {
		t.Fatalf(
			"runtime credential response=%#v error=%#v, want phase=%s revision=%d",
			response,
			response.Error,
			phase,
			revision,
		)
	}
}

func stageRevision(localStageSucceeded bool) int64 {
	if localStageSucceeded {
		return 3
	}
	return 2
}

func TestRuntimeCredentialOrphanExpiryUsesBoundedFileAge(t *testing.T) {
	now := time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
	policy, rt, _, activeBytes := newRuntimeCredentialExecutorFixture(t, now)
	active, _, _, err := rt.loadIdentity(
		rt.activeIdentity, policy.AgentGID,
	)
	if err != nil {
		t.Fatal(err)
	}
	active.RuntimeToken = testNewRuntimeToken
	stagedBytes, err := marshalRuntimeCredentialIdentity(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.writeIdentityAtomic(
		rt.stagedIdentity, stagedBytes, policy.AgentGID, false,
	); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-runtimeCredentialStagedMaxAge - time.Second)
	if err := os.Chtimes(rt.stagedIdentity, old, old); err != nil {
		t.Fatal(err)
	}
	response := handleLocalExecutorRuntimeCredential(
		context.Background(),
		policy,
		LocalExecutorRequest{
			Version:   LocalExecutorMutationProtocolVersion,
			Operation: "runtime_credential_status",
			ServiceID: "worker-01",
		},
		rt,
	)
	if response.Error == nil || response.Error.Code != "target_not_found" {
		t.Fatalf("orphan expiry status=%#v", response)
	}
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired orphan survived: %v", err)
	}
	after, err := os.ReadFile(rt.activeIdentity)
	if err != nil || !bytes.Equal(after, activeBytes) {
		t.Fatal("orphan expiry changed active identity")
	}
}

func TestEmergencyManualReconfigureRecoveryIsDurableAndUnblocksNextRotation(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 17, 0, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	rt.acknowledgeStage = func(
		context.Context, string, string, int64, string, *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		return testRuntimeTokenRotation(
			"local_staged", 3, now, now.Add(time.Second),
		), nil
	}
	stage := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, request, rt,
	)
	requireRuntimeCredentialPhase(
		t, stage, RuntimeCredentialPhaseLocalStaged, 3,
	)
	rt.now = func() time.Time {
		return now.Add(runtimeCredentialStagedMaxAge + time.Second)
	}
	expired := handleLocalExecutorRuntimeCredential(
		context.Background(),
		policy,
		LocalExecutorRequest{
			Version:   LocalExecutorMutationProtocolVersion,
			Operation: "runtime_credential_status",
			ServiceID: request.ServiceID,
		},
		rt,
	)
	requireRuntimeCredentialPhase(
		t, expired, RuntimeCredentialPhaseExpired, 3,
	)

	replacement := replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		"emergency-replacement-runtime-token",
	)
	recovered, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Phase != RuntimeCredentialPhaseManualRecovered ||
		recovered.ActiveIdentitySHA256 !=
			runtimeCredentialDigest(replacement) {
		t.Fatalf("manual recovery status=%#v", recovered)
	}
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("manual recovery retained staged identity: %v", err)
	}
	rebooted := rt

	// A non-root peer cannot erase the terminal root ledger by sending a
	// syntactically valid finalize request for another rotation.
	mismatchedFinalize := request
	mismatchedFinalize.Operation = "runtime_credential_finalize"
	mismatchedFinalize.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		recovered.RotationRevision,
		"",
	)
	mismatchedFinalize.RuntimeCredential.RotationID = "different-rotation"
	mismatchedFinalize.RuntimeCredential.PreviousTokenID = "different-old-token"
	mismatchedFinalize.RuntimeCredential.StagedTokenID = "different-new-token"
	if response := handleLocalExecutorRuntimeCredential(
		context.Background(), policy, mismatchedFinalize, rebooted,
	); response.Error == nil {
		t.Fatal("mismatched finalize erased the emergency root ledger")
	}
	if persisted, exists, err := rebooted.loadStatus(); err != nil ||
		!exists ||
		persisted != recovered {
		t.Fatalf(
			"mismatched finalize changed terminal ledger: %#v exists=%t err=%v",
			persisted,
			exists,
			err,
		)
	}

	// A process restart and command replay use only the durable, secret-free
	// replacement digest and do not require either revoked bearer.
	replayed, err := rebooted.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil || replayed != recovered {
		t.Fatalf("manual recovery replay=%#v err=%v", replayed, err)
	}

	finalize := request
	finalize.Operation = "runtime_credential_finalize"
	finalize.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		recovered.RotationRevision,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(), policy, finalize, rebooted,
		),
		RuntimeCredentialPhaseManualRecovered,
		recovered.RotationRevision,
	)
	if _, err := os.Lstat(rt.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("finalized emergency ledger survived: %v", err)
	}

	next := request
	next.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		2,
		"post-emergency-runtime-token",
	)
	next.RuntimeCredential.RotationID = "rotation-after-emergency"
	next.RuntimeCredential.PreviousTokenID = "replacement-token-id"
	next.RuntimeCredential.StagedTokenID = "post-emergency-token-id"
	rt.acknowledgeStage = func(
		_ context.Context,
		_, rotationID string,
		revision int64,
		token string,
		_ *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		if rotationID != next.RuntimeCredential.RotationID ||
			revision != 2 ||
			token != next.RuntimeCredential.RuntimeToken.Reveal() {
			t.Fatal("next rotation local-stage binding changed")
		}
		claimedAt := rt.currentTime()
		acknowledgedAt := claimedAt.Add(time.Second)
		return HostAgentRuntimeTokenRotation{
			ID:                                  rotationID,
			ServiceID:                           next.ServiceID,
			ExecutionHostID:                     next.RuntimeCredential.ExecutionHostID,
			Status:                              "local_staged",
			Revision:                            3,
			ExpectedOwnershipEpoch:              next.OwnershipEpoch,
			ExpectedSourcePolicyRevision:        next.SourcePolicyRevision,
			ExpectedProjectionRevision:          next.OwnershipPolicyRevision,
			ExpectedLocalExecutorPolicyRevision: next.ExecutorPolicyRevision,
			PreviousTokenID:                     next.RuntimeCredential.PreviousTokenID,
			StagedTokenID:                       next.RuntimeCredential.StagedTokenID,
			CredentialClaimedAt:                 &claimedAt,
			LocalStageReceiptID:                 "receipt-after-emergency",
			LocalStageAcknowledgedAt:            &acknowledgedAt,
		}, nil
	}
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(), policy, next, rt,
		),
		RuntimeCredentialPhaseLocalStaged,
		3,
	)
}

func TestEmergencyManualReconfigureRecoveryRejectsUnsafeEvidence(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC)
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
			context.Background(), policy, request, rt,
		),
		RuntimeCredentialPhaseLocalStaged,
		3,
	)
	if _, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	); err == nil {
		t.Fatal("pre-TTL emergency recovery unexpectedly succeeded")
	}
	rt.now = func() time.Time {
		return now.Add(runtimeCredentialStagedMaxAge + time.Second)
	}
	if _, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		"different-rotation",
	); err == nil {
		t.Fatal("mismatched rotation ID unexpectedly recovered")
	}
	if _, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	); err == nil {
		t.Fatal("unchanged active credential unexpectedly recovered")
	}
}

func TestEmergencyManualReconfigureRecoveryAcceptsActivatedLedger(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 18, 30, 0, 0, time.UTC)
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
			context.Background(), policy, request, rt,
		),
		RuntimeCredentialPhaseLocalStaged,
		3,
	)
	proof := request
	proof.Operation = "runtime_credential_proof_ready"
	proof.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		4,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(), policy, proof, rt,
		),
		RuntimeCredentialPhaseProofReady,
		4,
	)
	rt.activate = func(
		context.Context, string, string, int64, string, *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		return testRuntimeTokenRotation(
			"activated", 5, now, now.Add(time.Second),
		), nil
	}
	activate := proof
	activate.Operation = "runtime_credential_activate"
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(), policy, activate, rt,
		),
		RuntimeCredentialPhaseActivated,
		5,
	)
	replacement := replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		"activated-emergency-replacement-token",
	)
	recovered, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil ||
		recovered.Phase != RuntimeCredentialPhaseManualRecovered ||
		recovered.ActiveIdentitySHA256 !=
			runtimeCredentialDigest(replacement) {
		t.Fatalf("activated emergency recovery=%#v err=%v", recovered, err)
	}
}

func TestEmergencyManualReconfigureRecoveryAcceptsCancelReadyWithoutTTL(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 18, 45, 0, 0, time.UTC)
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
			context.Background(), policy, request, rt,
		),
		RuntimeCredentialPhaseLocalStaged,
		3,
	)
	cancel := request
	cancel.Operation = "runtime_credential_cancel"
	cancel.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		4,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(), policy, cancel, rt,
		),
		RuntimeCredentialPhaseCancelReady,
		4,
	)
	replacement := replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		"cancel-ready-emergency-replacement-token",
	)

	recovered, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil ||
		recovered.Phase != RuntimeCredentialPhaseManualRecovered ||
		recovered.ActiveIdentitySHA256 !=
			runtimeCredentialDigest(replacement) {
		t.Fatalf("cancel-ready emergency recovery=%#v err=%v", recovered, err)
	}
}

func TestEmergencyManualReconfigureRecoveryAcceptsClaimPreparedWithoutTTL(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 18, 50, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	prepare := request
	prepare.Operation = "runtime_credential_prepare"
	prepare.RuntimeCredential = cloneRuntimeCredentialMutation(
		request.RuntimeCredential,
		1,
		"",
	)
	requireRuntimeCredentialPhase(
		t,
		handleLocalExecutorRuntimeCredential(
			context.Background(), policy, prepare, rt,
		),
		RuntimeCredentialPhaseClaimPrepared,
		1,
	)
	replacement := replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		"claim-prepared-emergency-replacement-token",
	)

	recovered, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil ||
		recovered.Phase != RuntimeCredentialPhaseManualRecovered ||
		recovered.ActiveIdentitySHA256 !=
			runtimeCredentialDigest(replacement) {
		t.Fatalf("claim-prepared emergency recovery=%#v err=%v", recovered, err)
	}
}

func TestManualRecoveryPowerLossBeforeStagedWipeReconcilesExactSlot(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 19, 0, 0, 0, time.UTC)
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
			context.Background(), policy, request, rt,
		),
		RuntimeCredentialPhaseLocalStaged,
		3,
	)
	replacement := replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		"power-loss-replacement-runtime-token",
	)
	status, exists, err := rt.loadStatus()
	if err != nil || !exists {
		t.Fatalf("load recovery fixture status: %v", err)
	}
	status.Phase = RuntimeCredentialPhaseManualRecovered
	status.ActiveIdentitySHA256 = runtimeCredentialDigest(replacement)
	status.activeRuntimeTokenSHA256 = runtimeCredentialTokenDigest(
		"power-loss-replacement-runtime-token",
	)
	if err := rt.saveStatus(status); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(rt.stagedIdentity); err != nil {
		t.Fatalf("power-loss fixture lost staged slot: %v", err)
	}

	response := handleLocalExecutorRuntimeCredential(
		context.Background(),
		policy,
		LocalExecutorRequest{
			Version:   LocalExecutorMutationProtocolVersion,
			Operation: "runtime_credential_status",
			ServiceID: request.ServiceID,
		},
		rt,
	)
	requireRuntimeCredentialPhase(
		t,
		response,
		RuntimeCredentialPhaseManualRecovered,
		status.RotationRevision,
	)
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf("reboot did not complete exact staged wipe: %v", err)
	}
}

func TestManualRecoveryResumesQuarantinedStagedIdentityWipe(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, rt runtimeCredentialExecutorRuntime)
	}{
		{
			name: "after-quarantine-rename",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
			) {
				t.Helper()
			},
		},
		{
			name: "during-overwrite",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
			) {
				t.Helper()
				file, err := os.OpenFile(
					rt.wipingIdentity,
					os.O_RDWR,
					0,
				)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(make([]byte, 8)); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Sync(); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "after-truncate",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
			) {
				t.Helper()
				if err := os.Truncate(rt.wipingIdentity, 0); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "after-unlink-before-directory-sync",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
			) {
				t.Helper()
				if err := os.Remove(rt.wipingIdentity); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 7, 28, 19, 15, 0, 0, time.UTC)
			policy, rt, request, _ :=
				newRuntimeCredentialExecutorFixture(t, now)
			rt.acknowledgeStage = func(
				context.Context,
				string,
				string,
				int64,
				string,
				*http.Client,
			) (HostAgentRuntimeTokenRotation, error) {
				return testRuntimeTokenRotation(
					"local_staged",
					3,
					now,
					now.Add(time.Second),
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
			replacementToken := "wipe-crash-replacement-runtime-token"
			replacement := replaceRuntimeCredentialIdentityForTest(
				t,
				rt,
				policy,
				replacementToken,
			)
			status, exists, err := rt.loadStatus()
			if err != nil || !exists {
				t.Fatalf("load wipe-crash fixture status: %v", err)
			}
			status.Phase = RuntimeCredentialPhaseManualRecovered
			status.ActiveIdentitySHA256 =
				runtimeCredentialDigest(replacement)
			status.activeRuntimeTokenSHA256 =
				runtimeCredentialTokenDigest(replacementToken)
			if err := rt.saveStatus(status); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(
				rt.stagedIdentity,
				rt.wipingIdentity,
			); err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, rt)

			response := handleLocalExecutorRuntimeCredential(
				context.Background(),
				policy,
				LocalExecutorRequest{
					Version:   LocalExecutorMutationProtocolVersion,
					Operation: "runtime_credential_status",
					ServiceID: request.ServiceID,
				},
				rt,
			)
			requireRuntimeCredentialPhase(
				t,
				response,
				RuntimeCredentialPhaseManualRecovered,
				status.RotationRevision,
			)
			if !rt.identityCleanupComplete() {
				t.Fatal("reboot did not complete quarantined identity wipe")
			}
		})
	}
}

func TestEmergencyManualReconfigureRecoveryRejectsRevokedOrInvalidReplacement(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, rt runtimeCredentialExecutorRuntime, policy LocalExecutorPolicy)
	}{
		{
			name: "same-token-with-different-yaml-formatting",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
				policy LocalExecutorPolicy,
			) {
				t.Helper()
				active, _, _, err := rt.loadIdentity(
					rt.activeIdentity,
					policy.AgentGID,
				)
				if err != nil {
					t.Fatal(err)
				}
				reformatted, err := marshalManagedBootstrapConfig(active)
				if err != nil {
					t.Fatal(err)
				}
				reformatted = append([]byte("# Same identity, different YAML bytes.\n"), reformatted...)
				if err := rt.writeIdentityAtomic(
					rt.activeIdentity,
					reformatted,
					policy.AgentGID,
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "service-name-drift",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
				policy LocalExecutorPolicy,
			) {
				t.Helper()
				active, _, _, err := rt.loadIdentity(
					rt.activeIdentity,
					policy.AgentGID,
				)
				if err != nil {
					t.Fatal(err)
				}
				active.RuntimeToken = "replacement-runtime-token"
				active.ServiceName = "different-host-agent-service"
				replacement, err := marshalRuntimeCredentialIdentity(active)
				if err != nil {
					t.Fatal(err)
				}
				if err := rt.writeIdentityAtomic(
					rt.activeIdentity,
					replacement,
					policy.AgentGID,
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non-canonical-runtime-token",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
				policy LocalExecutorPolicy,
			) {
				t.Helper()
				active, _, _, err := rt.loadIdentity(
					rt.activeIdentity,
					policy.AgentGID,
				)
				if err != nil {
					t.Fatal(err)
				}
				active.RuntimeToken = "replacement runtime token"
				replacement, err := marshalRuntimeCredentialIdentity(active)
				if err != nil {
					t.Fatal(err)
				}
				if err := rt.writeIdentityAtomic(
					rt.activeIdentity,
					replacement,
					policy.AgentGID,
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 7, 28, 19, 30, 0, 0, time.UTC)
			policy, rt, request, _ := newRuntimeCredentialExecutorFixture(
				t,
				now,
			)
			rt.acknowledgeStage = func(
				context.Context,
				string,
				string,
				int64,
				string,
				*http.Client,
			) (HostAgentRuntimeTokenRotation, error) {
				return testRuntimeTokenRotation(
					"local_staged",
					3,
					now,
					now.Add(time.Second),
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
			rt.now = func() time.Time {
				return now.Add(runtimeCredentialStagedMaxAge + time.Second)
			}
			tt.mutate(t, rt, policy)

			if _, err := rt.recoverAfterEmergencyManualReconfigure(
				policy,
				request.RuntimeCredential.RotationID,
			); err == nil {
				t.Fatal("unsafe replacement identity unexpectedly recovered")
			}
		})
	}
}

func replaceRuntimeCredentialIdentityForTest(
	t *testing.T,
	rt runtimeCredentialExecutorRuntime,
	policy LocalExecutorPolicy,
	token string,
) []byte {
	t.Helper()
	active, _, _, err := rt.loadIdentity(
		rt.activeIdentity,
		policy.AgentGID,
	)
	if err != nil {
		t.Fatal(err)
	}
	active.RuntimeToken = token
	replacement, err := marshalRuntimeCredentialIdentity(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.writeIdentityAtomic(
		rt.activeIdentity,
		replacement,
		policy.AgentGID,
		true,
	); err != nil {
		t.Fatal(err)
	}
	return replacement
}
