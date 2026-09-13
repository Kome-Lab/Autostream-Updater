package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
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
