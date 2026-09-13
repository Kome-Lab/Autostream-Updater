package hostruntime

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

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
