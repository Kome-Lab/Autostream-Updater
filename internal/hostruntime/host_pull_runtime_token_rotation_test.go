package hostruntime

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
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

type memoryRuntimeTokenClaimStateStore struct {
	mu    sync.Mutex
	state *RuntimeTokenClaimState
}

func (s *memoryRuntimeTokenClaimStateStore) Load() (
	RuntimeTokenClaimState,
	bool,
	error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return RuntimeTokenClaimState{}, false, nil
	}
	return *s.state, true, nil
}

func (s *memoryRuntimeTokenClaimStateStore) Save(
	state RuntimeTokenClaimState,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil && *s.state != state {
		return errors.New("claim state already exists")
	}
	copy := state
	s.state = &copy
	return nil
}

func (s *memoryRuntimeTokenClaimStateStore) Delete(
	expected RuntimeTokenClaimState,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil
	}
	if *s.state != expected {
		return errors.New("claim state changed before delete")
	}
	s.state = nil
	return nil
}

type memoryRuntimeCredentialExecutor struct {
	mu            sync.Mutex
	status        RuntimeCredentialStatus
	exists        bool
	prepareCalls  int
	prepareErr    error
	cancelCalls   int
	cancelErr     error
	finalizeCalls int
	finalizeErr   error
}

func (e *memoryRuntimeCredentialExecutor) RuntimeCredentialStatus(
	context.Context,
	string,
) (RuntimeCredentialStatus, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status, e.exists, nil
}

func (*memoryRuntimeCredentialExecutor) StageRuntimeCredential(
	context.Context,
	HostAgentRuntimeTokenRotation,
	BoundedSecret,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New("unexpected stage")
}

func (e *memoryRuntimeCredentialExecutor) PrepareRuntimeCredential(
	_ context.Context,
	rotation HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prepareCalls++
	if e.prepareErr != nil {
		return RuntimeCredentialStatus{}, e.prepareErr
	}
	e.status = RuntimeCredentialStatus{
		Phase:                       RuntimeCredentialPhaseClaimPrepared,
		RotationID:                  rotation.ID,
		ServiceID:                   rotation.ServiceID,
		ExecutionHostID:             rotation.ExecutionHostID,
		PreviousTokenID:             rotation.PreviousTokenID,
		StagedTokenID:               rotation.StagedTokenID,
		RotationRevision:            rotation.Revision,
		OwnershipEpoch:              rotation.ExpectedOwnershipEpoch,
		SourcePolicyRevision:        rotation.ExpectedSourcePolicyRevision,
		ProjectionRevision:          rotation.ExpectedProjectionRevision,
		LocalExecutorPolicyRevision: rotation.ExpectedLocalExecutorPolicyRevision,
	}
	e.exists = true
	return e.status, nil
}

func (*memoryRuntimeCredentialExecutor) MarkRuntimeCredentialProofReady(
	context.Context,
	HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New("unexpected proof")
}

func (*memoryRuntimeCredentialExecutor) ActivateRuntimeCredential(
	context.Context,
	HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	return RuntimeCredentialStatus{}, errors.New("unexpected activation")
}

func (e *memoryRuntimeCredentialExecutor) CancelRuntimeCredential(
	_ context.Context,
	rotation HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cancelCalls++
	if e.cancelErr != nil {
		return RuntimeCredentialStatus{}, e.cancelErr
	}
	phase := RuntimeCredentialPhaseCancelReady
	if e.exists &&
		e.status.Phase == RuntimeCredentialPhaseCancelReady {
		phase = RuntimeCredentialPhaseCancelled
	}
	e.status = RuntimeCredentialStatus{
		Phase:                       phase,
		RotationID:                  rotation.ID,
		ServiceID:                   rotation.ServiceID,
		ExecutionHostID:             rotation.ExecutionHostID,
		PreviousTokenID:             rotation.PreviousTokenID,
		StagedTokenID:               rotation.StagedTokenID,
		RotationRevision:            rotation.Revision,
		OwnershipEpoch:              rotation.ExpectedOwnershipEpoch,
		SourcePolicyRevision:        rotation.ExpectedSourcePolicyRevision,
		ProjectionRevision:          rotation.ExpectedProjectionRevision,
		LocalExecutorPolicyRevision: rotation.ExpectedLocalExecutorPolicyRevision,
	}
	e.exists = phase != RuntimeCredentialPhaseCancelled
	return e.status, nil
}

func (e *memoryRuntimeCredentialExecutor) FinalizeRuntimeCredential(
	_ context.Context,
	rotation HostAgentRuntimeTokenRotation,
) (RuntimeCredentialStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.finalizeCalls++
	if e.finalizeErr != nil {
		return RuntimeCredentialStatus{}, e.finalizeErr
	}
	if !e.exists ||
		e.status.RotationID != rotation.ID {
		return RuntimeCredentialStatus{},
			errors.New("terminal state is unavailable")
	}
	status := e.status
	e.exists = false
	return status, nil
}

type memoryRuntimeTokenRotationPanel struct {
	claimCalls  int
	claimID     string
	cancelCalls int
	cancelToken string
}

type claimingRuntimeCredentialExecutor struct {
	memoryRuntimeCredentialExecutor
	stageCalls int
}

func (e *claimingRuntimeCredentialExecutor) StageRuntimeCredential(
	_ context.Context,
	rotation HostAgentRuntimeTokenRotation,
	_ BoundedSecret,
) (RuntimeCredentialStatus, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stageCalls++
	e.status = RuntimeCredentialStatus{
		Phase:                       RuntimeCredentialPhaseLocalStaged,
		RotationID:                  rotation.ID,
		ServiceID:                   rotation.ServiceID,
		ExecutionHostID:             rotation.ExecutionHostID,
		PreviousTokenID:             rotation.PreviousTokenID,
		StagedTokenID:               rotation.StagedTokenID,
		RotationRevision:            3,
		OwnershipEpoch:              rotation.ExpectedOwnershipEpoch,
		SourcePolicyRevision:        rotation.ExpectedSourcePolicyRevision,
		ProjectionRevision:          rotation.ExpectedProjectionRevision,
		LocalExecutorPolicyRevision: rotation.ExpectedLocalExecutorPolicyRevision,
	}
	e.exists = true
	return e.status, nil
}

type claimingRuntimeTokenRotationPanel struct {
	memoryRuntimeTokenRotationPanel
}

func (p *claimingRuntimeTokenRotationPanel) ClaimRuntimeTokenRotation(
	_ context.Context,
	_ Config,
	rotation HostAgentRuntimeTokenRotation,
	claimID string,
) (RuntimeTokenRotationClaimResult, error) {
	p.claimCalls++
	p.claimID = claimID
	claimedAt := time.Now().UTC()
	rotation.Status = "staged"
	rotation.Revision = 2
	rotation.CredentialClaimedAt = &claimedAt
	return RuntimeTokenRotationClaimResult{
		Rotation: rotation,
		Credential: RuntimeTokenRotationCredential{
			TokenID: rotation.StagedTokenID,
			RuntimeToken: NewBoundedSecret(
				"next-runtime-token-secret",
			),
		},
		Claimed: true,
	}, nil
}

func (p *memoryRuntimeTokenRotationPanel) ClaimRuntimeTokenRotation(
	context.Context,
	Config,
	HostAgentRuntimeTokenRotation,
	string,
) (RuntimeTokenRotationClaimResult, error) {
	p.claimCalls++
	return RuntimeTokenRotationClaimResult{}, errors.New("unexpected claim")
}

func (*memoryRuntimeTokenRotationPanel) ProveRuntimeTokenRotation(
	context.Context,
	Config,
	HostAgentRuntimeTokenRotation,
	RuntimeTokenRotationHeartbeatProof,
) (HostAgentRuntimeTokenRotation, error) {
	return HostAgentRuntimeTokenRotation{}, errors.New("unexpected proof")
}

func (p *memoryRuntimeTokenRotationPanel) AcknowledgeRuntimeTokenRotationCancel(
	_ context.Context,
	identity Config,
	rotation HostAgentRuntimeTokenRotation,
) (HostAgentRuntimeTokenRotation, error) {
	p.cancelCalls++
	p.cancelToken = identity.RuntimeToken
	rotation.Status = "canceled"
	rotation.Revision++
	return rotation, nil
}

func newRuntimeTokenRotationTestAgent(
	claimStore RuntimeTokenClaimStateStore,
	executor LocalExecutorRuntimeCredentialClient,
	panel HostRuntimeTokenRotationControlPlane,
) *HostPullAgent {
	identity := managedHostAgentBootstrap("https://panel.example.com")
	identity.RuntimeToken = "old-runtime-token"
	return &HostPullAgent{
		Bootstrap:                 identity,
		currentBootstrap:          identity,
		RuntimeCredentialExecutor: executor,
		RuntimeTokenRotationPanel: panel,
		RuntimeTokenClaimState:    claimStore,
		LoadRuntimeIdentity:       func(string, bool) (Config, error) { return identity, nil },
		NewRuntimeTokenClaimID:    func() (string, error) { return "new-claim-id", nil },
		LifecycleBlockers:         func() HostLifecycleBlockers { return HostLifecycleBlockers{} },
	}
}

func testClaimPreparedRuntimeCredentialStatus(
	rotationID string,
	stagedTokenID string,
) RuntimeCredentialStatus {
	return RuntimeCredentialStatus{
		Phase:                       RuntimeCredentialPhaseClaimPrepared,
		RotationID:                  rotationID,
		ServiceID:                   "host-agent-a",
		ExecutionHostID:             "host-a",
		PreviousTokenID:             "token-old",
		StagedTokenID:               stagedTokenID,
		RotationRevision:            1,
		OwnershipEpoch:              7,
		SourcePolicyRevision:        11,
		ProjectionRevision:          12,
		LocalExecutorPolicyRevision: 13,
	}
}

func runtimeTokenClaimStateFromStatus(
	status RuntimeCredentialStatus,
	claimID string,
) RuntimeTokenClaimState {
	return RuntimeTokenClaimState{
		SchemaVersion:               runtimeTokenClaimStateVersion,
		RotationID:                  status.RotationID,
		ServiceID:                   status.ServiceID,
		ExecutionHostID:             status.ExecutionHostID,
		PreviousTokenID:             status.PreviousTokenID,
		StagedTokenID:               status.StagedTokenID,
		ClaimID:                     claimID,
		InitialRevision:             1,
		OwnershipEpoch:              status.OwnershipEpoch,
		SourcePolicyRevision:        status.SourcePolicyRevision,
		ProjectionRevision:          status.ProjectionRevision,
		LocalExecutorPolicyRevision: status.LocalExecutorPolicyRevision,
		ExpiresAt:                   time.Now().UTC().Add(time.Hour),
	}
}
