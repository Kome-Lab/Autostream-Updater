package hostruntime

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAuthoritativeNilRetiresRootClaimPreparedAndUnblocksNextRotation(
	t *testing.T,
) {
	status := testClaimPreparedRuntimeCredentialStatus(
		"rotation-canceled-before-claim",
		"token-abandoned",
	)
	executor := &claimingRuntimeCredentialExecutor{}
	executor.status = status
	executor.exists = true
	claim := runtimeTokenClaimStateFromStatus(
		status,
		"claim-canceled-before-response",
	)
	claims := &memoryRuntimeTokenClaimStateStore{state: &claim}
	panel := &claimingRuntimeTokenRotationPanel{}
	agent := newRuntimeTokenRotationTestAgent(claims, executor, panel)

	// Blind recovery cannot prove that the server canceled the lane.
	if err := agent.recoverRuntimeTokenRotation(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
	if !executor.exists || executor.cancelCalls != 0 {
		t.Fatal("blind recovery retired the prepared root ledger")
	}

	// A successful policy response with no rotation is authoritative.
	if err := agent.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{},
	); err != nil {
		t.Fatal(err)
	}
	if executor.exists ||
		executor.cancelCalls != 2 {
		t.Fatalf(
			"prepared root retirement exists=%t cancel_calls=%d",
			executor.exists,
			executor.cancelCalls,
		)
	}
	if _, exists, err := claims.Load(); err != nil || exists {
		t.Fatalf("prepared claim survived authoritative nil: %v", err)
	}

	next := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-after-authoritative-nil",
		ServiceID:                           status.ServiceID,
		ExecutionHostID:                     status.ExecutionHostID,
		Status:                              "staged",
		Revision:                            1,
		ExpectedOwnershipEpoch:              status.OwnershipEpoch,
		ExpectedSourcePolicyRevision:        status.SourcePolicyRevision,
		ExpectedProjectionRevision:          status.ProjectionRevision,
		ExpectedLocalExecutorPolicyRevision: status.LocalExecutorPolicyRevision,
		PreviousTokenID:                     status.PreviousTokenID,
		StagedTokenID:                       "token-after-authoritative-nil",
	}
	if err := agent.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &next},
	); err != nil {
		t.Fatal(err)
	}
	if executor.prepareCalls != 1 ||
		panel.claimCalls != 1 ||
		executor.stageCalls != 1 {
		t.Fatalf(
			"next prepare=%d claim=%d stage=%d",
			executor.prepareCalls,
			panel.claimCalls,
			executor.stageCalls,
		)
	}
}

func TestNewRevisionOneDirectiveRetiresDifferentRootClaimPrepared(
	t *testing.T,
) {
	status := testClaimPreparedRuntimeCredentialStatus(
		"rotation-old-prepared",
		"token-old-staged",
	)
	executor := &claimingRuntimeCredentialExecutor{}
	executor.status = status
	executor.exists = true
	oldClaim := runtimeTokenClaimStateFromStatus(
		status,
		"claim-old-prepared",
	)
	claims := &memoryRuntimeTokenClaimStateStore{state: &oldClaim}
	panel := &claimingRuntimeTokenRotationPanel{}
	agent := newRuntimeTokenRotationTestAgent(claims, executor, panel)
	next := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-new-authoritative",
		ServiceID:                           status.ServiceID,
		ExecutionHostID:                     status.ExecutionHostID,
		Status:                              "staged",
		Revision:                            1,
		ExpectedOwnershipEpoch:              status.OwnershipEpoch,
		ExpectedSourcePolicyRevision:        status.SourcePolicyRevision,
		ExpectedProjectionRevision:          status.ProjectionRevision,
		ExpectedLocalExecutorPolicyRevision: status.LocalExecutorPolicyRevision,
		PreviousTokenID:                     status.PreviousTokenID,
		StagedTokenID:                       "token-new-staged",
	}

	if err := agent.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &next},
	); err != nil {
		t.Fatal(err)
	}
	if executor.cancelCalls != 2 ||
		executor.prepareCalls != 1 ||
		panel.claimCalls != 1 ||
		executor.stageCalls != 1 {
		t.Fatalf(
			"cancel=%d prepare=%d claim=%d stage=%d",
			executor.cancelCalls,
			executor.prepareCalls,
			panel.claimCalls,
			executor.stageCalls,
		)
	}
}

func TestClaimPreparedReplaysCommittedRevisionTwoWithExactClaimID(
	t *testing.T,
) {
	status := testClaimPreparedRuntimeCredentialStatus(
		"rotation-claim-response-lost",
		"token-claimed",
	)
	executor := &claimingRuntimeCredentialExecutor{}
	executor.status = status
	executor.exists = true
	claim := runtimeTokenClaimStateFromStatus(
		status,
		"claim-response-lost",
	)
	claims := &memoryRuntimeTokenClaimStateStore{state: &claim}
	panel := &claimingRuntimeTokenRotationPanel{}
	agent := newRuntimeTokenRotationTestAgent(claims, executor, panel)
	claimedAt := time.Now().UTC()
	directive := runtimeCredentialRotationFromStatus(status)
	directive.Status = "staged"
	directive.Revision = 2
	directive.CredentialClaimedAt = &claimedAt

	if err := agent.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &directive},
	); err != nil {
		t.Fatal(err)
	}
	if executor.prepareCalls != 0 ||
		panel.claimCalls != 1 ||
		panel.claimID != claim.ClaimID ||
		executor.stageCalls != 1 {
		t.Fatalf(
			"prepare=%d replay_claim=%d claim_id=%q stage=%d",
			executor.prepareCalls,
			panel.claimCalls,
			panel.claimID,
			executor.stageCalls,
		)
	}
	if _, exists, err := claims.Load(); err != nil || exists {
		t.Fatalf("replayed claim was not consumed: %v", err)
	}
}

func TestStageBoundMissingFileReplaysCommittedClaimOverExactClaimID(
	t *testing.T,
) {
	status := testClaimPreparedRuntimeCredentialStatus(
		"rotation-stage-bound-replay",
		"token-stage-bound-replay",
	)
	status.Phase = RuntimeCredentialPhaseStageBound
	status.RotationRevision = 2
	status.StagedIdentitySHA256 =
		"sha256:" + strings.Repeat("b", 64)
	status.stagedRuntimeTokenSHA256 =
		"sha256:" + strings.Repeat("c", 64)
	executor := &claimingRuntimeCredentialExecutor{}
	executor.status = status
	executor.exists = true
	claim := runtimeTokenClaimStateFromStatus(
		status,
		"claim-stage-bound-replay",
	)
	claims := &memoryRuntimeTokenClaimStateStore{state: &claim}
	panel := &claimingRuntimeTokenRotationPanel{}
	agent := newRuntimeTokenRotationTestAgent(claims, executor, panel)
	identity := agent.currentIdentity()
	agent.LoadRuntimeIdentity = func(
		path string,
		_ bool,
	) (Config, error) {
		if path == HostAgentStagedIdentityPath {
			return Config{}, &os.PathError{
				Op:   "stat",
				Path: path,
				Err:  os.ErrNotExist,
			}
		}
		return identity, nil
	}
	claimedAt := time.Now().UTC()
	directive := runtimeCredentialRotationFromStatus(status)
	directive.Status = "staged"
	directive.Revision = 2
	directive.CredentialClaimedAt = &claimedAt

	if err := agent.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &directive},
	); err != nil {
		t.Fatal(err)
	}
	if executor.prepareCalls != 0 ||
		panel.claimCalls != 1 ||
		panel.claimID != claim.ClaimID ||
		executor.stageCalls != 1 {
		t.Fatalf(
			"prepare=%d claim=%d claim_id=%q stage=%d",
			executor.prepareCalls,
			panel.claimCalls,
			panel.claimID,
			executor.stageCalls,
		)
	}
	if _, exists, err := claims.Load(); err != nil || exists {
		t.Fatalf("stage-bound replay retained claim state: %v", err)
	}
}
