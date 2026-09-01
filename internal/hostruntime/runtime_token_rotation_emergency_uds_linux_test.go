//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestEmergencyReplacementPollFinalizesRootLedgerAndStagesNextRotationOverUDS(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	policy, rt, request, _ := newRuntimeCredentialExecutorFixture(t, now)
	rt.acknowledgeStage = func(
		_ context.Context,
		_, rotationID string,
		revision int64,
		token string,
		_ *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		if rotationID != request.RuntimeCredential.RotationID ||
			revision != 2 ||
			token != testNewRuntimeToken {
			t.Fatal("initial rotation stage binding changed")
		}
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
	replacementToken := "emergency-uds-replacement-runtime-token"
	replaceRuntimeCredentialIdentityForTest(
		t,
		rt,
		policy,
		replacementToken,
	)
	rt.now = func() time.Time {
		return now.Add(runtimeCredentialStagedMaxAge + time.Second)
	}
	recovered, err := rt.recoverAfterEmergencyManualReconfigure(
		policy,
		request.RuntimeCredential.RotationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	policySHA256, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.LocalExecutorPolicySHA256 != policySHA256 ||
		recovered.SourcePolicyRevision != policy.SourcePolicyRevision ||
		recovered.ProjectionRevision != policy.ProjectionRevision ||
		recovered.LocalExecutorPolicyRevision != policy.PolicyRevision {
		t.Fatal("emergency recovery changed Local Executor policy fences")
	}

	next := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-after-emergency-uds",
		ServiceID:                           request.ServiceID,
		ExecutionHostID:                     policy.HostID,
		Status:                              "staged",
		Revision:                            1,
		ExpectedOwnershipEpoch:              request.OwnershipEpoch,
		ExpectedSourcePolicyRevision:        policy.SourcePolicyRevision,
		ExpectedProjectionRevision:          policy.ProjectionRevision,
		ExpectedLocalExecutorPolicyRevision: policy.PolicyRevision,
		PreviousTokenID:                     "replacement-token-id",
		StagedTokenID:                       "next-token-id",
	}
	nextToken := "next-runtime-token-after-emergency"
	rt.acknowledgeStage = func(
		_ context.Context,
		_, rotationID string,
		revision int64,
		token string,
		_ *http.Client,
	) (HostAgentRuntimeTokenRotation, error) {
		if rotationID != next.ID ||
			revision != 2 ||
			token != nextToken {
			t.Fatal("next rotation UDS stage binding changed")
		}
		claimedAt := rt.currentTime()
		acknowledgedAt := claimedAt.Add(time.Second)
		return HostAgentRuntimeTokenRotation{
			ID:                                  next.ID,
			ServiceID:                           next.ServiceID,
			ExecutionHostID:                     next.ExecutionHostID,
			Status:                              "local_staged",
			Revision:                            3,
			ExpectedOwnershipEpoch:              next.ExpectedOwnershipEpoch,
			ExpectedSourcePolicyRevision:        next.ExpectedSourcePolicyRevision,
			ExpectedProjectionRevision:          next.ExpectedProjectionRevision,
			ExpectedLocalExecutorPolicyRevision: next.ExpectedLocalExecutorPolicyRevision,
			PreviousTokenID:                     next.PreviousTokenID,
			StagedTokenID:                       next.StagedTokenID,
			CredentialClaimedAt:                 &claimedAt,
			LocalStageReceiptID:                 "receipt-after-emergency-uds",
			LocalStageAcknowledgedAt:            &acknowledgedAt,
		}, nil
	}

	socketPath, operations, stopServer := startRuntimeCredentialUDSTestServer(
		t,
		policy,
		rt,
	)
	defer stopServer()
	active, _, _, err := rt.loadIdentity(
		rt.activeIdentity,
		policy.AgentGID,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldClaim := runtimeTokenClaimStateFromStatus(
		recovered,
		"claim-before-emergency-recovery",
	)
	claims := &memoryRuntimeTokenClaimStateStore{state: &oldClaim}
	panel := &emergencyUDSRuntimeTokenPanel{
		replacementToken: replacementToken,
		nextToken:        nextToken,
	}
	client := LocalExecutorClient{
		SocketPath:      socketPath,
		MutationTimeout: 5 * time.Second,
	}
	agent := &HostPullAgent{
		Bootstrap:                 active,
		currentBootstrap:          active,
		RuntimeCredentialExecutor: client,
		RuntimeTokenRotationPanel: panel,
		RuntimeTokenClaimState:    claims,
		LoadRuntimeIdentity: func(path string, _ bool) (Config, error) {
			switch path {
			case HostAgentIdentityPath:
				identity, _, _, err := rt.loadIdentity(
					rt.activeIdentity,
					policy.AgentGID,
				)
				return identity, err
			case HostAgentStagedIdentityPath:
				identity, _, _, err := rt.loadIdentity(
					rt.stagedIdentity,
					policy.AgentGID,
				)
				return identity, err
			default:
				return Config{}, errors.New("unexpected identity path")
			}
		},
		NewRuntimeTokenClaimID: func() (string, error) {
			return "claim-after-emergency-uds", nil
		},
		LifecycleBlockers: func() HostLifecycleBlockers {
			return HostLifecycleBlockers{}
		},
	}

	if err := agent.reconcileRuntimeTokenRotation(
		context.Background(),
		&HostAgentPolicy{RuntimeTokenRotation: &next},
	); err != nil {
		t.Fatal(err)
	}
	if panel.claimToken != replacementToken {
		t.Fatalf(
			"new-token poll used %q, want replacement token",
			panel.claimToken,
		)
	}
	if _, exists, err := claims.Load(); err != nil || exists {
		t.Fatalf("terminal or next claim ledger survived: %v", err)
	}
	status, exists, err := rt.loadStatus()
	if err != nil || !exists {
		t.Fatalf("load next root ledger: %v", err)
	}
	if status.RotationID != next.ID ||
		status.Phase != RuntimeCredentialPhaseLocalStaged ||
		status.LocalExecutorPolicySHA256 != policySHA256 ||
		status.SourcePolicyRevision != policy.SourcePolicyRevision ||
		status.ProjectionRevision != policy.ProjectionRevision ||
		status.LocalExecutorPolicyRevision != policy.PolicyRevision {
		t.Fatalf("next root ledger=%#v", status)
	}
	wantOperations := []string{
		"runtime_credential_status",
		"runtime_credential_finalize",
		"runtime_credential_status",
		"runtime_credential_prepare",
		"runtime_credential_status",
		"runtime_credential_stage",
	}
	if got := operations.snapshot(); !equalStrings(got, wantOperations) {
		t.Fatalf("UDS operations=%v want=%v", got, wantOperations)
	}
}

type emergencyUDSRuntimeTokenPanel struct {
	replacementToken string
	nextToken        string
	claimToken       string
}

func (p *emergencyUDSRuntimeTokenPanel) ClaimRuntimeTokenRotation(
	_ context.Context,
	identity Config,
	rotation HostAgentRuntimeTokenRotation,
	_ string,
) (RuntimeTokenRotationClaimResult, error) {
	p.claimToken = identity.RuntimeToken
	claimedAt := time.Now().UTC()
	rotation.Status = "staged"
	rotation.Revision = 2
	rotation.CredentialClaimedAt = &claimedAt
	return RuntimeTokenRotationClaimResult{
		Rotation: rotation,
		Credential: RuntimeTokenRotationCredential{
			TokenID:      rotation.StagedTokenID,
			RuntimeToken: NewBoundedSecret(p.nextToken),
		},
		Claimed: true,
	}, nil
}

func (*emergencyUDSRuntimeTokenPanel) ProveRuntimeTokenRotation(
	context.Context,
	Config,
	HostAgentRuntimeTokenRotation,
	RuntimeTokenRotationHeartbeatProof,
) (HostAgentRuntimeTokenRotation, error) {
	return HostAgentRuntimeTokenRotation{}, errors.New("unexpected proof")
}

func (*emergencyUDSRuntimeTokenPanel) AcknowledgeRuntimeTokenRotationCancel(
	context.Context,
	Config,
	HostAgentRuntimeTokenRotation,
) (HostAgentRuntimeTokenRotation, error) {
	return HostAgentRuntimeTokenRotation{}, errors.New("unexpected cancel")
}

type runtimeCredentialUDSOperations struct {
	mu     sync.Mutex
	values []string
}

func (o *runtimeCredentialUDSOperations) append(value string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.values = append(o.values, value)
}

func (o *runtimeCredentialUDSOperations) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.values...)
}

func startRuntimeCredentialUDSTestServer(
	t *testing.T,
	policy LocalExecutorPolicy,
	rt runtimeCredentialExecutorRuntime,
) (
	string,
	*runtimeCredentialUDSOperations,
	func(),
) {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "executor.sock")
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: socketPath, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}
	operations := &runtimeCredentialUDSOperations{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			request, decodeErr := DecodeLocalExecutorRequest(
				connection,
			)
			response := localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion,
				"invalid_request",
			)
			if decodeErr == nil {
				operations.append(request.Operation)
				response = handleLocalExecutorRuntimeCredential(
					ctx,
					policy,
					request,
					rt,
				)
			}
			_ = EncodeLocalExecutorResponse(connection, response)
			_ = connection.Close()
		}
	}()
	stop := func() {
		cancel()
		_ = listener.Close()
		<-done
		_ = os.Remove(socketPath)
	}
	return socketPath, operations, stop
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
