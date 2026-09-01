package hostruntime

import (
	"bytes"
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

func TestLocalExecutorProtocolPreservesExactV2GrantBinding(t *testing.T) {
	plan := MutationPlan{
		JobID: "job-one", HostID: "host-a", TargetID: "worker-01",
		ServiceType: "worker", DeploymentMode: ModeSystemd,
		TargetVersion: "v1.2.4", LeaseGeneration: 4,
		SessionID:  "session-0123456789abcdef",
		PlanSHA256: "sha256:" + strings.Repeat("a", 64),
	}
	binding := contracts.UpdaterMutationGrantBinding{
		Lease: contracts.UpdaterLeaseEnvelope{
			ProtocolVersion: 2,
			LeaseID:         "lease-software-one",
			LeaseGeneration: int64(plan.LeaseGeneration),
		},
		Operation: contracts.UpdaterMutationApply,
		SessionID: plan.SessionID,
	}
	request := LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: "apply",
		ServiceID: plan.TargetID, Plan: &plan,
		SourcePolicyRevision: 5, OwnershipEpoch: 7,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 13,
		MutationGrant:          NewBoundedSecret("one-time-v2-mutation-grant"),
		MutationGrantV2Binding: &binding,
	}

	var encoded bytes.Buffer
	if err := EncodeLocalExecutorRequest(&encoded, request); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	decoded, err := DecodeLocalExecutorRequest(&encoded)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if decoded.MutationGrant.Reveal() != request.MutationGrant.Reveal() ||
		decoded.MutationGrantV2Binding == nil ||
		!reflect.DeepEqual(*decoded.MutationGrantV2Binding, binding) {
		t.Fatal("local executor protocol did not preserve the exact v2 mutation grant binding")
	}
}

func TestExecutorMutationGateConsumesExactV2BindingOnce(t *testing.T) {
	fixedNow := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	plan := MutationPlan{
		JobID: "job-one", HostID: "host-a", TargetID: "worker-01",
		ServiceType: "worker", DeploymentMode: ModeSystemd,
		TargetVersion: "v1.2.4", LeaseGeneration: 4,
		SessionID:  "session-0123456789abcdef",
		PlanSHA256: "sha256:" + strings.Repeat("a", 64),
	}
	binding := contracts.UpdaterMutationGrantBinding{
		Lease: contracts.UpdaterLeaseEnvelope{
			ProtocolVersion: 2,
			LeaseID:         "lease-software-one",
			LeaseGeneration: int64(plan.LeaseGeneration),
		},
		Operation: contracts.UpdaterMutationApply,
		SessionID: plan.SessionID,
	}
	legacyCalls := 0
	v2Calls := 0
	var gotRequest contracts.UpdaterMutationGrantConsumeRequest
	var gotNow time.Time
	rt := executorMutationRuntime{
		consumeGrant: func(context.Context, string, string, string, MutationGrantBinding, *http.Client) error {
			legacyCalls++
			return nil
		},
		consumeV2Grant: func(
			_ context.Context,
			_, _, _ string,
			request contracts.UpdaterMutationGrantConsumeRequest,
			_ *http.Client,
			now time.Time,
		) error {
			v2Calls++
			gotRequest = request
			gotNow = now
			return nil
		},
		v2GrantBinding: &binding,
		now:            func() time.Time { return fixedNow },
	}
	if err := consumeExecutorMutationGrant(
		context.Background(), "https://panel.example.com", plan, "apply",
		NewBoundedSecret("one-time-v2-mutation-grant"), rt,
	); err != nil {
		t.Fatal(err)
	}
	if legacyCalls != 0 || v2Calls != 1 {
		t.Fatalf("legacy/v2 consume calls=%d/%d", legacyCalls, v2Calls)
	}
	if !reflect.DeepEqual(gotRequest, contracts.UpdaterMutationGrantConsumeRequest{Binding: binding}) || !gotNow.Equal(fixedNow) {
		t.Fatal("root mutation gate did not consume the exact v2 binding at the injected time")
	}
}
