//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalExecutorClientRetriesExactGrantOnAuthorizationUncertain(
	t *testing.T,
) {
	socketPath := filepath.Join(t.TempDir(), "executor.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	request := validHostSelfUpdateRequest()
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    7,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: 11,
		ExecutorPolicyRevision:  9,
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		request,
		fence,
		"sha256:"+strings.Repeat("a", 64),
	)
	initial, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageHostSelfUpdate(
		initial,
		request,
		HostLifecycleBlockers{},
		validHostSelfUpdateSlotDigests(),
	)
	if err != nil {
		t.Fatal(err)
	}
	serverErr := make(chan error, 1)
	receivedTokens := make(chan string, 2)
	go func() {
		for attempt := 0; attempt < 2; attempt++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverErr <- acceptErr
				return
			}
			decoded, decodeErr := DecodeLocalExecutorRequest(connection)
			if decodeErr != nil {
				_ = connection.Close()
				serverErr <- decodeErr
				return
			}
			receivedTokens <- decoded.HostSelfUpdateGrant.Token.Reveal()
			var response LocalExecutorResponse
			if attempt == 0 {
				response = localExecutorFailureForVersion(
					LocalExecutorMutationProtocolVersion,
					"authorization_uncertain",
				)
			} else {
				response = LocalExecutorResponse{
					Version: LocalExecutorMutationProtocolVersion,
					HostSelfUpdate: &HostSelfUpdateRuntimeStatus{
						State:                   staged,
						CurrentSlot:             HostSelfUpdateSlotA,
						ExecutorVersion:         "v1.7.8",
						ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
					},
				}
			}
			encodeErr := EncodeLocalExecutorResponse(connection, response)
			_ = connection.Close()
			if encodeErr != nil {
				serverErr <- encodeErr
				return
			}
		}
		serverErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, err := (LocalExecutorClient{
		SocketPath:      socketPath,
		Timeout:         time.Second,
		MutationTimeout: time.Second,
	}).StageHostSelfUpdate(
		ctx,
		"host-a",
		request,
		authorization,
		fence,
	)
	if err != nil {
		t.Fatalf("exact IPC retry failed: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStaged {
		t.Fatalf("retry status=%#v", status)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("fake local executor: %v", err)
	}
	first := <-receivedTokens
	second := <-receivedTokens
	if first != authorization.Token.Reveal() || second != first {
		t.Fatal("IPC retry did not preserve the exact raw grant")
	}
}

func TestHostSelfUpdateGrantConsumeResponseLossResumesExactGrant(t *testing.T) {
	root := t.TempDir()
	grantPath := filepath.Join(root, "host-self-update", "grant.json")
	if err := os.MkdirAll(filepath.Dir(grantPath), 0o700); err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    7,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: 11,
		ExecutorPolicyRevision:  9,
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		request,
		fence,
		"sha256:"+strings.Repeat("a", 64),
	)
	consumeCalls := 0
	rt := hostSelfUpdateExecutorRuntime{
		grantStatePath: grantPath,
		allowTestPaths: true,
		now: func() time.Time {
			return authorization.Binding.IssuedAt.Add(30 * time.Second)
		},
		consumeGrant: func(
			context.Context,
			string,
			HostSelfUpdateGrantAuthorization,
		) (HostSelfUpdateGrantConsumeResult, error) {
			consumeCalls++
			if consumeCalls == 1 {
				return HostSelfUpdateGrantConsumeResult{},
					errors.New("consume response lost")
			}
			state, err := loadHostSelfUpdateGrantState(grantPath, false)
			if err != nil || state == nil ||
				state.Phase != hostSelfUpdateGrantPhasePrepared {
				t.Fatalf(
					"consume retry lacked prepared fence: state=%#v err=%v",
					state,
					err,
				)
			}
			result := consumedHostSelfUpdateGrant(authorization)
			result.Consumed = false
			return result, nil
		},
	}

	if err := rt.authorizeHostSelfUpdate(
		context.Background(),
		"https://panel.example.com",
		authorization,
	); err != nil {
		t.Fatalf("exact consume replay failed: %v", err)
	}
	state, err := loadHostSelfUpdateGrantState(grantPath, false)
	if err != nil || state == nil ||
		state.Phase != hostSelfUpdateGrantPhaseConsumed ||
		state.Receipt == nil {
		t.Fatalf("consume receipt was not durable: state=%#v err=%v", state, err)
	}
	payload, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), authorization.Token.Reveal()) {
		t.Fatal("raw host self-update grant was persisted")
	}
	if consumeCalls != 2 {
		t.Fatalf("exact consume retry calls=%d", consumeCalls)
	}
	if err := rt.markHostSelfUpdateGrantApplied(authorization); err != nil {
		t.Fatalf("mark grant applied: %v", err)
	}
	applied, err := rt.hostSelfUpdateGrantApplied(authorization)
	if err != nil || !applied {
		t.Fatalf("applied fence missing: applied=%v err=%v", applied, err)
	}
	if err := rt.authorizeHostSelfUpdate(
		context.Background(),
		"https://panel.example.com",
		authorization,
	); err != nil {
		t.Fatalf("applied exact replay rejected: %v", err)
	}
	if consumeCalls != 2 {
		t.Fatalf("applied exact replay re-consumed grant: calls=%d", consumeCalls)
	}
}

func TestHostSelfUpdateGrantPreparedFenceRejectsDifferentRawGrant(t *testing.T) {
	root := t.TempDir()
	grantPath := filepath.Join(root, "host-self-update", "grant.json")
	if err := os.MkdirAll(filepath.Dir(grantPath), 0o700); err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    7,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: 11,
		ExecutorPolicyRevision:  9,
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		request,
		fence,
		"sha256:"+strings.Repeat("a", 64),
	)
	consumeCalls := 0
	rt := hostSelfUpdateExecutorRuntime{
		grantStatePath: grantPath,
		allowTestPaths: true,
		now: func() time.Time {
			return authorization.Binding.IssuedAt.Add(30 * time.Second)
		},
		consumeGrant: func(
			context.Context,
			string,
			HostSelfUpdateGrantAuthorization,
		) (HostSelfUpdateGrantConsumeResult, error) {
			consumeCalls++
			return HostSelfUpdateGrantConsumeResult{},
				errors.New("consume result remains unknown")
		},
	}
	if err := rt.authorizeHostSelfUpdate(
		context.Background(),
		"https://panel.example.com",
		authorization,
	); !errors.Is(err, errHostSelfUpdateGrantUncertain) {
		t.Fatalf("uncertain consume result=%v", err)
	}
	if consumeCalls != 2 {
		t.Fatalf("exact root consume attempts=%d", consumeCalls)
	}
	state, err := loadHostSelfUpdateGrantState(grantPath, false)
	if err != nil || state == nil ||
		state.Phase != hostSelfUpdateGrantPhasePrepared {
		t.Fatalf("prepared consume fence missing: state=%#v err=%v", state, err)
	}

	mismatched := authorization
	mismatched.Token = NewBoundedSecret(
		authorization.Token.Reveal() + "-different",
	)
	if err := rt.authorizeHostSelfUpdate(
		context.Background(),
		"https://panel.example.com",
		mismatched,
	); err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("different grant crossed uncertain consume fence: %v", err)
	}
	if consumeCalls != 2 {
		t.Fatalf("different grant reached Panel: calls=%d", consumeCalls)
	}
}

func TestValidateHostSelfUpdateGrantBindsRootPolicyAndRelease(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{
		PanelURL: "https://panel.example.com",
	}
	policy.SourcePolicyRevision = 7
	policy.ProjectionRevision = 11
	policy.PolicyRevision = 9
	policySHA256, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: policy.ProjectionRevision,
		ExecutorPolicyRevision:  policy.PolicyRevision,
	}
	request := validHostSelfUpdateRequest()
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage", request, fence, policySHA256,
	)
	if err := validateHostSelfUpdateGrantForOperation(
		policy,
		fence,
		"stage",
		&request,
		state,
		authorization,
	); err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}

	tests := map[string]func(*HostSelfUpdateGrantAuthorization){
		"policy digest": func(value *HostSelfUpdateGrantAuthorization) {
			value.Binding.ExpectedLocalExecutorPolicySHA256 =
				"sha256:" + strings.Repeat("c", 64)
		},
		"ownership epoch": func(value *HostSelfUpdateGrantAuthorization) {
			value.Binding.ExpectedOwnershipEpoch++
		},
		"artifact": func(value *HostSelfUpdateGrantAuthorization) {
			value.Binding.ArtifactSHA256 =
				"sha256:" + strings.Repeat("d", 64)
		},
		"generation": func(value *HostSelfUpdateGrantAuthorization) {
			value.Binding.AttemptGeneration = "generation-other"
		},
		"plan": func(value *HostSelfUpdateGrantAuthorization) {
			value.Binding.PlanSHA256 =
				"sha256:" + strings.Repeat("e", 64)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			tampered := authorization
			mutate(&tampered)
			if err := validateHostSelfUpdateGrantForOperation(
				policy,
				fence,
				"stage",
				&request,
				state,
				tampered,
			); err == nil {
				t.Fatal("tampered grant was accepted")
			}
		})
	}
}
