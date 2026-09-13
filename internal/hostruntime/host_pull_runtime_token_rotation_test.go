package hostruntime

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExpiredClaimReplayWithoutRootLedgerFailsClosedOnCancelAfterRestart(
	t *testing.T,
) {
	now := time.Now().UTC()
	claimedAt := now.Add(-runtimeCredentialStagedMaxAge - 2*time.Hour)
	cancelRequestedAt := now
	staged := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-expired-claim",
		ServiceID:                           "host-agent-a",
		ExecutionHostID:                     "host-a",
		Status:                              "staged",
		Revision:                            2,
		ExpectedOwnershipEpoch:              7,
		ExpectedSourcePolicyRevision:        11,
		ExpectedProjectionRevision:          12,
		ExpectedLocalExecutorPolicyRevision: 13,
		PreviousTokenID:                     "token-old",
		StagedTokenID:                       "token-new",
		CredentialClaimedAt:                 &claimedAt,
	}
	claimStore := &memoryRuntimeTokenClaimStateStore{
		state: &RuntimeTokenClaimState{
			SchemaVersion:               runtimeTokenClaimStateVersion,
			RotationID:                  staged.ID,
			ServiceID:                   staged.ServiceID,
			ExecutionHostID:             staged.ExecutionHostID,
			PreviousTokenID:             staged.PreviousTokenID,
			StagedTokenID:               staged.StagedTokenID,
			ClaimID:                     "claim-expired",
			InitialRevision:             1,
			OwnershipEpoch:              staged.ExpectedOwnershipEpoch,
			SourcePolicyRevision:        staged.ExpectedSourcePolicyRevision,
			ProjectionRevision:          staged.ExpectedProjectionRevision,
			LocalExecutorPolicyRevision: staged.ExpectedLocalExecutorPolicyRevision,
			ExpiresAt:                   now.Add(-time.Hour),
		},
	}
	executor := &memoryRuntimeCredentialExecutor{
		cancelErr: errors.New("tracked root state is unavailable"),
	}
	panel := &memoryRuntimeTokenRotationPanel{}

	// A fresh process must not garbage-collect the only durable binding while
	// the server can still hold a claimed revision.
	restarted := newRuntimeTokenRotationTestAgent(
		claimStore, executor, panel,
	)
	if err := restarted.recoverRuntimeTokenRotation(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := claimStore.Load(); err != nil || !exists {
		t.Fatalf("expired cancel tombstone was lost on restart: %v", err)
	}

	// The expired claim cannot be used to obtain or stage the credential again.
	if err := restarted.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &staged},
	); err == nil {
		t.Fatal("expired claim credential replay unexpectedly succeeded")
	}
	if panel.claimCalls != 0 {
		t.Fatalf("expired claim reached claim endpoint %d times", panel.claimCalls)
	}
	if _, exists, err := claimStore.Load(); err != nil || !exists {
		t.Fatalf("expired cancel tombstone was removed after replay denial: %v", err)
	}

	cancel := staged
	cancel.Status = "cancel_requested"
	cancel.Revision = 3
	cancel.CancelRequestedAt = &cancelRequestedAt
	if err := restarted.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &cancel},
	); err == nil {
		t.Fatal("rootless cancel unexpectedly succeeded")
	}
	if panel.cancelCalls != 0 || panel.cancelToken != "" {
		t.Fatalf(
			"rootless cancel reached panel acknowledgement calls=%d token=%q",
			panel.cancelCalls,
			panel.cancelToken,
		)
	}
	if executor.cancelCalls != 1 || executor.exists {
		t.Fatalf(
			"rootless local cancel calls=%d exists=%v",
			executor.cancelCalls,
			executor.exists,
		)
	}
	if _, exists, err := claimStore.Load(); err != nil || !exists {
		t.Fatalf("failed rootless cancel removed claim tombstone: %v", err)
	}
}

func TestRuntimeTokenClaimStateMatchesBothTokenIDs(t *testing.T) {
	rotation := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-a",
		ServiceID:                           "host-agent-a",
		ExecutionHostID:                     "host-a",
		ExpectedOwnershipEpoch:              7,
		ExpectedSourcePolicyRevision:        11,
		ExpectedProjectionRevision:          12,
		ExpectedLocalExecutorPolicyRevision: 13,
		PreviousTokenID:                     "token-old",
		StagedTokenID:                       "token-new",
	}
	state := RuntimeTokenClaimState{
		RotationID:                  rotation.ID,
		ServiceID:                   rotation.ServiceID,
		ExecutionHostID:             rotation.ExecutionHostID,
		PreviousTokenID:             rotation.PreviousTokenID,
		StagedTokenID:               rotation.StagedTokenID,
		OwnershipEpoch:              rotation.ExpectedOwnershipEpoch,
		SourcePolicyRevision:        rotation.ExpectedSourcePolicyRevision,
		ProjectionRevision:          rotation.ExpectedProjectionRevision,
		LocalExecutorPolicyRevision: rotation.ExpectedLocalExecutorPolicyRevision,
	}
	if !state.matches(rotation) {
		t.Fatal("exact claim binding did not match")
	}
	rotation.StagedTokenID = "token-another"
	if state.matches(rotation) {
		t.Fatal("claim binding ignored staged token identity")
	}
}

func TestAuthoritativeNilRotationRetiresPreclaimCrashTombstone(
	t *testing.T,
) {
	now := time.Now().UTC()
	store := &memoryRuntimeTokenClaimStateStore{
		state: &RuntimeTokenClaimState{
			SchemaVersion:               runtimeTokenClaimStateVersion,
			RotationID:                  "rotation-canceled-before-claim",
			ServiceID:                   "host-agent-a",
			ExecutionHostID:             "host-a",
			PreviousTokenID:             "token-old",
			StagedTokenID:               "token-abandoned",
			ClaimID:                     "claim-before-crash",
			InitialRevision:             1,
			OwnershipEpoch:              7,
			SourcePolicyRevision:        11,
			ProjectionRevision:          12,
			LocalExecutorPolicyRevision: 13,
			ExpiresAt:                   now.Add(runtimeCredentialStagedMaxAge),
		},
	}
	executor := &claimingRuntimeCredentialExecutor{}
	panel := &claimingRuntimeTokenRotationPanel{}
	restarted := newRuntimeTokenRotationTestAgent(store, executor, panel)

	// Blind startup cannot distinguish a server outage from an unclaimed
	// rotation canceled while this process was down.
	if err := restarted.recoverRuntimeTokenRotation(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.Load(); err != nil || !exists {
		t.Fatalf("blind recovery removed the crash tombstone: %v", err)
	}

	// A successful policy response with an explicit nil rotation is
	// authoritative. With no root ledger, it retires the abandoned pre-claim
	// tombstone and unblocks a later independent rotation.
	if err := restarted.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{},
	); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.Load(); err != nil || exists {
		t.Fatalf("authoritative nil did not retire crash tombstone: %v", err)
	}

	next := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-after-cancel",
		ServiceID:                           "host-agent-a",
		ExecutionHostID:                     "host-a",
		Status:                              "staged",
		Revision:                            1,
		ExpectedOwnershipEpoch:              7,
		ExpectedSourcePolicyRevision:        11,
		ExpectedProjectionRevision:          12,
		ExpectedLocalExecutorPolicyRevision: 13,
		PreviousTokenID:                     "token-old",
		StagedTokenID:                       "token-next",
	}
	if err := restarted.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &next},
	); err != nil {
		t.Fatal(err)
	}
	if panel.claimCalls != 1 || executor.stageCalls != 1 {
		t.Fatalf(
			"next rotation did not progress claim_calls=%d stage_calls=%d",
			panel.claimCalls,
			executor.stageCalls,
		)
	}
	if _, exists, err := store.Load(); err != nil || exists {
		t.Fatalf("next rotation retained its consumed claim state: %v", err)
	}
}

func TestNewAuthenticatedDirectiveRetiresRootlessStaleClaim(
	t *testing.T,
) {
	now := time.Now().UTC()
	claims := &memoryRuntimeTokenClaimStateStore{
		state: &RuntimeTokenClaimState{
			SchemaVersion:               runtimeTokenClaimStateVersion,
			RotationID:                  "rotation-abandoned-before-root-prepare",
			ServiceID:                   "host-agent-a",
			ExecutionHostID:             "host-a",
			PreviousTokenID:             "token-old",
			StagedTokenID:               "token-abandoned",
			ClaimID:                     "claim-abandoned",
			InitialRevision:             1,
			OwnershipEpoch:              7,
			SourcePolicyRevision:        11,
			ProjectionRevision:          12,
			LocalExecutorPolicyRevision: 13,
			ExpiresAt:                   now.Add(time.Hour),
		},
	}
	executor := &claimingRuntimeCredentialExecutor{}
	panel := &claimingRuntimeTokenRotationPanel{}
	agent := newRuntimeTokenRotationTestAgent(claims, executor, panel)
	next := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-after-rootless-claim",
		ServiceID:                           "host-agent-a",
		ExecutionHostID:                     "host-a",
		Status:                              "staged",
		Revision:                            1,
		ExpectedOwnershipEpoch:              7,
		ExpectedSourcePolicyRevision:        11,
		ExpectedProjectionRevision:          12,
		ExpectedLocalExecutorPolicyRevision: 13,
		PreviousTokenID:                     "token-old",
		StagedTokenID:                       "token-next",
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
			"prepare=%d claim=%d stage=%d",
			executor.prepareCalls,
			panel.claimCalls,
			executor.stageCalls,
		)
	}
	if _, exists, err := claims.Load(); err != nil || exists {
		t.Fatalf("consumed replacement claim survived: %v", err)
	}
}

func TestRootClaimPreparationFailurePreventsPanelCredentialClaim(
	t *testing.T,
) {
	executor := &claimingRuntimeCredentialExecutor{}
	executor.prepareErr = errors.New("injected root preparation failure")
	panel := &claimingRuntimeTokenRotationPanel{}
	agent := newRuntimeTokenRotationTestAgent(
		&memoryRuntimeTokenClaimStateStore{},
		executor,
		panel,
	)
	directive := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-root-prepare-failure",
		ServiceID:                           "host-agent-a",
		ExecutionHostID:                     "host-a",
		Status:                              "staged",
		Revision:                            1,
		ExpectedOwnershipEpoch:              7,
		ExpectedSourcePolicyRevision:        11,
		ExpectedProjectionRevision:          12,
		ExpectedLocalExecutorPolicyRevision: 13,
		PreviousTokenID:                     "token-old",
		StagedTokenID:                       "token-new",
	}

	if err := agent.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &directive},
	); err == nil {
		t.Fatal("root preparation failure was hidden")
	}
	if executor.prepareCalls != 1 || panel.claimCalls != 0 {
		t.Fatalf(
			"prepare=%d claim=%d, panel claim must follow durable root preparation",
			executor.prepareCalls,
			panel.claimCalls,
		)
	}
}
