package hostruntime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newRuntimeCredentialExecutorFixture(
	t *testing.T,
	now time.Time,
) (
	LocalExecutorPolicy,
	runtimeCredentialExecutorRuntime,
	LocalExecutorRequest,
	[]byte,
) {
	t.Helper()
	root := t.TempDir()
	identityDir := filepath.Join(root, "identity")
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(identityDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(identityDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	active := managedHostAgentBootstrap("https://panel.example.com")
	active.NodeID = "worker-01"
	active.RuntimeToken = testOldRuntimeToken
	activeBytes, err := marshalRuntimeCredentialIdentity(active)
	if err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(identityDir, "agent.yaml")
	if err := os.WriteFile(activePath, activeBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(activePath, 0o640); err != nil {
		t.Fatal(err)
	}

	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.SourcePolicyRevision = 11
	policy.ProjectionRevision = 12
	policy.PolicyRevision = 13
	policy.Mutation = &LocalExecutorMutationPolicy{
		PanelURL: "https://panel.example.com",
	}
	rt := runtimeCredentialExecutorRuntime{
		identityDir:     identityDir,
		activeIdentity:  activePath,
		stagedIdentity:  filepath.Join(identityDir, "agent.staged.yaml"),
		wipingIdentity:  filepath.Join(identityDir, ".agent.staged.wipe"),
		statePath:       filepath.Join(stateDir, "runtime-credential.json"),
		allowTestPaths:  true,
		executorVersion: "v1.0.0",
		now: func() time.Time {
			return now
		},
	}
	request := LocalExecutorRequest{
		Version:                 LocalExecutorMutationProtocolVersion,
		Operation:               "runtime_credential_stage",
		ServiceID:               "worker-01",
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          7,
		OwnershipPolicyRevision: policy.ProjectionRevision,
		ExecutorPolicyRevision:  policy.PolicyRevision,
		RuntimeCredential: &RuntimeCredentialMutation{
			RotationID:       "rotation-a",
			ExecutionHostID:  policy.HostID,
			PreviousTokenID:  "old-token-id",
			StagedTokenID:    "new-token-id",
			RotationRevision: 2,
			RuntimeToken:     NewBoundedSecret(testNewRuntimeToken),
		},
	}
	return policy, rt, request, activeBytes
}

func testRuntimeTokenRotation(
	status string,
	revision int64,
	claimedAt time.Time,
	acknowledgedAt time.Time,
) HostAgentRuntimeTokenRotation {
	rotation := HostAgentRuntimeTokenRotation{
		ID:                                  "rotation-a",
		ServiceID:                           "worker-01",
		ExecutionHostID:                     "host-a",
		Status:                              status,
		Revision:                            revision,
		ExpectedOwnershipEpoch:              7,
		ExpectedSourcePolicyRevision:        11,
		ExpectedProjectionRevision:          12,
		ExpectedLocalExecutorPolicyRevision: 13,
		PreviousTokenID:                     "old-token-id",
		StagedTokenID:                       "new-token-id",
		CredentialClaimedAt:                 &claimedAt,
		LocalStageReceiptID:                 "receipt-a",
		LocalStageAcknowledgedAt:            &acknowledgedAt,
	}
	return rotation
}

func cloneRuntimeCredentialMutation(
	source *RuntimeCredentialMutation,
	revision int64,
	token string,
) *RuntimeCredentialMutation {
	copy := *source
	copy.RotationRevision = revision
	copy.RuntimeToken = NewBoundedSecret(token)
	return &copy
}

func requireRuntimeCredentialPhase(
	t *testing.T,
	response LocalExecutorResponse,
	phase string,
	revision int64,
) {
	t.Helper()
	if response.Error != nil ||
		response.RuntimeCredential == nil ||
		response.RuntimeCredential.Phase != phase ||
		response.RuntimeCredential.RotationRevision != revision {
		t.Fatalf(
			"runtime credential response=%#v error=%#v, want phase=%s revision=%d",
			response,
			response.Error,
			phase,
			revision,
		)
	}
}

func stageRevision(localStageSucceeded bool) int64 {
	if localStageSucceeded {
		return 3
	}
	return 2
}
