package hostruntime

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

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
