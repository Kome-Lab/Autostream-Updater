package hostruntime

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHostAgentFinalizesManualRecoveryBeforeNextRotation(t *testing.T) {
	executor := &claimingRuntimeCredentialExecutor{}
	executor.status = RuntimeCredentialStatus{
		Phase:                       RuntimeCredentialPhaseManualRecovered,
		RotationID:                  "rotation-emergency",
		ServiceID:                   "host-agent-a",
		ExecutionHostID:             "host-a",
		PreviousTokenID:             "token-old",
		StagedTokenID:               "token-revoked",
		RotationRevision:            3,
		OwnershipEpoch:              7,
		SourcePolicyRevision:        11,
		ProjectionRevision:          12,
		LocalExecutorPolicyRevision: 13,
	}
	executor.exists = true
	panel := &claimingRuntimeTokenRotationPanel{}
	claims := &memoryRuntimeTokenClaimStateStore{}
	agent := newRuntimeTokenRotationTestAgent(claims, executor, panel)
	replacement := managedHostAgentBootstrap("https://panel.example.com")
	replacement.RuntimeToken = "replacement-runtime-token"
	agent.LoadRuntimeIdentity = func(path string, _ bool) (Config, error) {
		if path != HostAgentIdentityPath {
			return Config{}, errors.New("unexpected identity path")
		}
		return replacement, nil
	}
	next := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-after-emergency",
		ServiceID:                           "host-agent-a",
		ExecutionHostID:                     "host-a",
		Status:                              "staged",
		Revision:                            1,
		ExpectedOwnershipEpoch:              7,
		ExpectedSourcePolicyRevision:        11,
		ExpectedProjectionRevision:          12,
		ExpectedLocalExecutorPolicyRevision: 13,
		PreviousTokenID:                     "token-replacement",
		StagedTokenID:                       "token-next",
	}
	if err := agent.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &next},
	); err != nil {
		t.Fatal(err)
	}
	if executor.finalizeCalls != 1 ||
		executor.stageCalls != 1 ||
		panel.claimCalls != 1 {
		t.Fatalf(
			"manual finalize=%d next claim=%d stage=%d",
			executor.finalizeCalls,
			panel.claimCalls,
			executor.stageCalls,
		)
	}
	if got := agent.currentIdentity().RuntimeToken; got != replacement.RuntimeToken {
		t.Fatalf("Host Agent retained pre-emergency identity: %q", got)
	}
}

func TestHostAgentManualRecoveryCrashKeepsRootLedgerAfterClaimCleanup(
	t *testing.T,
) {
	status := RuntimeCredentialStatus{
		Phase:                       RuntimeCredentialPhaseManualRecovered,
		RotationID:                  "rotation-emergency-crash",
		ServiceID:                   "host-agent-a",
		ExecutionHostID:             "host-a",
		PreviousTokenID:             "token-old",
		StagedTokenID:               "token-revoked",
		RotationRevision:            3,
		OwnershipEpoch:              7,
		SourcePolicyRevision:        11,
		ProjectionRevision:          12,
		LocalExecutorPolicyRevision: 13,
	}
	executor := &memoryRuntimeCredentialExecutor{
		status:      status,
		exists:      true,
		finalizeErr: errors.New("injected root finalize interruption"),
	}
	claim := RuntimeTokenClaimState{
		SchemaVersion:               runtimeTokenClaimStateVersion,
		RotationID:                  status.RotationID,
		ServiceID:                   status.ServiceID,
		ExecutionHostID:             status.ExecutionHostID,
		PreviousTokenID:             status.PreviousTokenID,
		StagedTokenID:               status.StagedTokenID,
		ClaimID:                     "claim-before-emergency",
		InitialRevision:             1,
		OwnershipEpoch:              status.OwnershipEpoch,
		SourcePolicyRevision:        status.SourcePolicyRevision,
		ProjectionRevision:          status.ProjectionRevision,
		LocalExecutorPolicyRevision: status.LocalExecutorPolicyRevision,
		ExpiresAt:                   time.Now().UTC().Add(time.Hour),
	}
	claims := &memoryRuntimeTokenClaimStateStore{state: &claim}
	panel := &memoryRuntimeTokenRotationPanel{}
	agent := newRuntimeTokenRotationTestAgent(claims, executor, panel)
	replacement := managedHostAgentBootstrap("https://panel.example.com")
	replacement.RuntimeToken = "replacement-runtime-token"
	agent.LoadRuntimeIdentity = func(path string, _ bool) (Config, error) {
		if path != HostAgentIdentityPath {
			return Config{}, errors.New("unexpected identity path")
		}
		return replacement, nil
	}

	if err := agent.recoverRuntimeTokenRotation(
		context.Background(),
	); err == nil {
		t.Fatal("injected root finalization interruption was hidden")
	}
	if _, exists, err := claims.Load(); err != nil || exists {
		t.Fatalf("claim ledger survived terminal pre-root cleanup: %v", err)
	}
	if !executor.exists {
		t.Fatal("root ledger was lost after interrupted finalization")
	}

	executor.finalizeErr = nil
	if err := agent.recoverRuntimeTokenRotation(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
	if executor.exists || executor.finalizeCalls != 2 {
		t.Fatalf(
			"root finalization was not idempotently retried: exists=%t calls=%d",
			executor.exists,
			executor.finalizeCalls,
		)
	}
	if got := agent.currentIdentity().RuntimeToken; got !=
		replacement.RuntimeToken {
		t.Fatalf("replacement identity was not retained: %q", got)
	}
}
