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
