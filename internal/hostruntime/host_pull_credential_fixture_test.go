package hostruntime

import (
	"context"
	"errors"
	"sync"
	"time"
)

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
