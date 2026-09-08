package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

type agentPortNoOpExecutor struct {
	hostPullExecutionTestExecutor
	now, observedAt time.Time
	invalid         bool
}

func (e *agentPortNoOpExecutor) PortReconfigureV2(_ context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (SystemdPortReconfigureResult, error) {
	e.v2PortApplyCalls++
	return e.observe(plan, fence, grant, "port_reconfigure")
}

func (e *agentPortNoOpExecutor) PortReconfigureReconcileV2(_ context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (SystemdPortReconfigureResult, error) {
	e.v2PortReconCalls++
	return e.observe(plan, fence, grant, "port_reconfigure_reconcile")
}

func (e *agentPortNoOpExecutor) observe(plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant, operation string) (SystemdPortReconfigureResult, error) {
	if !grant.Token.Empty() || !contracts.SystemUpdatePortPlanIsNoOp(plan.SharedPortPlan()) ||
		validateV2PortMutationGrantBinding(e.now, grant.Binding, operation, plan, fence, nil, nil) != nil {
		return SystemdPortReconfigureResult{}, io.ErrUnexpectedEOF
	}
	request := LocalExecutorRequest{Version: 2, Operation: operation, ServiceID: plan.TargetID, PortPlan: &plan,
		SourcePolicyRevision: fence.SourcePolicyRevision, OwnershipEpoch: fence.OwnershipEpoch,
		OwnershipPolicyRevision: fence.OwnershipPolicyRevision, ExecutorPolicyRevision: fence.ExecutorPolicyRevision,
		MutationGrant: grant.Token, MutationGrantV2Binding: &grant.Binding}
	var wire bytes.Buffer
	if EncodeLocalExecutorRequest(&wire, request) != nil {
		return SystemdPortReconfigureResult{}, io.ErrUnexpectedEOF
	}
	decoded, err := DecodeLocalExecutorRequest(&wire)
	if err != nil || !decoded.MutationGrant.Empty() || decoded.MutationGrantV2Binding == nil {
		return SystemdPortReconfigureResult{}, io.ErrUnexpectedEOF
	}
	result := agentPortObservedResult(*decoded.PortPlan, contracts.SystemUpdatePortReconfigurationUnchanged, e.observedAt, false)
	if e.invalid {
		result.PortResult.Observation.PolicyDiskVerified = false
	}
	return result, nil
}

// Exercise the real Agent, adapter, codec, and result projection with a CP
// fixture that refuses every mutation-grant HTTP request for its no-op job.
func TestSTPortAgentNoOpOmitsGrantHTTPAndRequiresFreshProof(t *testing.T) {
	for _, test := range []struct {
		name                       string
		mode                       contracts.SystemUpdatePortMode
		recovery, changed, invalid bool
		staleAgent                 bool
	}{
		{name: "local_only", mode: contracts.SystemUpdatePortModeLocalOnly},
		{name: "combined", mode: contracts.SystemUpdatePortModeLocalAndAdvertised},
		{name: "fresh_recovery_lease", recovery: true},
		{name: "changed_plan_requires_grant", changed: true},
		{name: "invalid_root_proof", invalid: true},
		{name: "stale_agent_projection", staleAgent: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode := test.mode
			if mode == "" {
				mode = contracts.SystemUpdatePortModeLocalOnly
			}
			lease, originalJob, policy, originalPlan := agentPortV2Fixture(t, mode, !test.changed)
			observedAt := lease.LeaseExpiresAt.Add(-4 * time.Minute)
			now := observedAt.Add(time.Second)
			dir := t.TempDir()
			journal, err := OpenJournal(dir)
			if err != nil {
				t.Fatal("open no-op journal")
			}
			if test.recovery {
				for _, err := range []error{journal.SetActive(&originalJob), journal.SetActivePortPlan(originalPlan), journal.StagePortPolicy(policy, originalJob, originalPlan)} {
					if err != nil {
						t.Fatal("stage no-op recovery")
					}
				}
				journal, err = OpenJournal(dir)
				if err != nil {
					t.Fatal("reopen no-op recovery")
				}
				lease.LeaseGeneration++
			}
			grants, terminals := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/services/update-jobs/claim" {
					writeV2PanelJSON(t, w, http.StatusOK, lease)
					return
				}
				if strings.Contains(r.URL.Path, "mutation-grants") {
					grants++
					writeV2PanelJSON(t, w, http.StatusConflict, map[string]string{"code": "system_update_mutation_grant_state_invalid"})
					return
				}
				payload, err := io.ReadAll(r.Body)
				var result contracts.UpdaterResultEnvelope
				if err != nil || json.Unmarshal(payload, &result) != nil {
					t.Error("read no-op report")
				} else if result.PortReconfigure != nil {
					terminals++
					expected := agentPortObservedResult(originalPlan, contracts.SystemUpdatePortReconfigurationUnchanged, observedAt, true)
					if contracts.ValidateUpdaterResultEnvelope(lease, payload) != nil ||
						!contracts.EqualSystemUpdatePortResults(*expected.PortResult, *result.PortReconfigure) || result.AppliedRevision != originalPlan.Before.ConfigRevision {
						t.Error("no-op terminal lacks exact fresh B proof")
					}
				} else if contracts.ValidateUpdaterProgressEnvelope(lease, payload) != nil && !test.changed {
					t.Error("invalid no-op progress")
				}
				writeV2PanelJSON(t, w, http.StatusOK, nil)
			}))
			defer server.Close()
			client := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
			client.Now = func() time.Time { return now }
			claim := v2PanelClaimRequest("")
			if test.recovery {
				claim.ActiveJobID = originalJob.ID
			}
			job, _, err := client.ClaimHost(context.Background(), claim)
			if err != nil {
				t.Fatal("claim no-op fixture")
			}
			executor := &agentPortNoOpExecutor{now: now, observedAt: observedAt, invalid: test.invalid}
			agent := &HostPullAgent{Bootstrap: Config{NodeID: job.AgentServiceID}, StateDir: dir, Journal: journal, PortExecutor: executor,
				NewSessionID: func() (string, error) { return originalPlan.SessionID, nil }}
			probes := 0
			agent.ObserveTargets = func(_ context.Context, candidate HostAgentPolicy) ([]HostTargetObservation, error) {
				probes++
				ref := originalPlan.Before
				if test.staleAgent || !portAgentPolicyMatchesSnapshot(candidate, job.TargetID, ref) {
					return nil, io.ErrUnexpectedEOF
				}
				return []HostTargetObservation{{ServiceID: job.TargetID, Availability: TargetAvailabilityAvailable,
					PolicyRevision: ref.ExecutorPolicyRevision, PolicySHA256: ref.ExecutorPolicySHA256, ConfigRevision: ref.ConfigRevision, ConfigSHA256: ref.ConfigSHA256,
					PortContractVersion: 2, PolicyTransitionVersion: 1, SourcePolicyRevision: ref.SourcePolicyRevision, ProjectionRevision: ref.ProjectionRevision,
					EndpointRevision: ref.AppliedEndpointRevision, AgentUID: 1201, AgentGID: 1202, ObservedAt: observedAt,
					ReportedPort: ref.LocalListenPort, ReportedServiceType: job.EffectiveType(), ReportedDeploymentMode: job.DeploymentMode}}, nil
			}
			binding := HostAgentBinding{ExecutionHostID: job.HostID, OwnershipEpoch: job.OwnershipEpoch, TransportMode: HostTransportPullV2}
			beforeGrants, beforeTerminals, beforeProbes := grants, terminals, probes
			beforeApply, beforeReconcile := executor.v2PortApplyCalls, executor.v2PortReconCalls
			beforeLegacyApply, beforeLegacyReconcile := executor.portApplyCalls, executor.portReconCalls
			err = agent.processPortReconfigurationJob(context.Background(), client, binding, policy, *job)
			rootCalls := executor.v2PortApplyCalls - beforeApply + executor.v2PortReconCalls - beforeReconcile
			grantCalls, terminalCalls, probeCalls := grants-beforeGrants, terminals-beforeTerminals, probes-beforeProbes
			if test.changed {
				if err == nil || grantCalls != 2 || rootCalls != 0 || terminalCalls != 0 {
					t.Fatal("changed plan bypassed the CP mutation grant")
				}
				return
			}
			if grantCalls != 0 || rootCalls != 1 || executor.portApplyCalls-beforeLegacyApply != 0 || executor.portReconCalls-beforeLegacyReconcile != 0 ||
				(test.recovery && executor.v2PortReconCalls-beforeReconcile != 1) {
				t.Fatal("no-op issued a grant, lost its v2 binding, or invoked root twice")
			}
			if test.invalid || test.staleAgent {
				if err == nil || terminalCalls != 0 || journal.Active() == nil || journal.Active().PortResult != nil {
					t.Fatal("unverified no-op became accepted")
				}
				return
			}
			if err != nil || terminalCalls != 1 || probeCalls != 1 || journal.Active() != nil || len(journal.Pending()) != 0 {
				t.Fatal("fresh no-op proof did not complete through the public result path")
			}
		})
	}
}

func agentPortV2Fixture(t *testing.T, mode contracts.SystemUpdatePortMode, noOp bool) (contracts.UpdaterLeaseEnvelope, UpdateJob, HostAgentPolicy, SystemdPortReconfigurePlan) {
	t.Helper()
	now := time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC)
	endpoint := contracts.SystemUpdatePortEndpoint{Host: "worker.example.test", Port: 443, SSLEnabled: true, PublicURL: "https://worker.example.test/"}
	endpointDigest, err := contracts.ComputeSystemUpdatePortEndpointSHA256(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	b := contracts.SystemUpdatePortSnapshotRef{
		SnapshotID: "ps1:" + strings.Repeat("1", 64), SnapshotSHA256: "sha256:" + strings.Repeat("1", 64),
		SourcePolicyRevision: 5, ProjectionRevision: 11, ExecutorPolicyRevision: 23,
		ExecutorPolicySHA256: "sha256:" + strings.Repeat("a", 64), EndpointRevision: 3, AppliedEndpointRevision: 3,
		ConfigRevision: 6, ConfigSHA256: "sha256:" + strings.Repeat("d", 64),
		AdvertisedPort: 443, AdvertisedEndpointSHA256: endpointDigest, LocalListenPort: 18081,
	}
	target, rollback := b, b
	if !noOp {
		target.SnapshotID, target.SnapshotSHA256 = "ps1:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("2", 64)
		rollback.SnapshotID, rollback.SnapshotSHA256 = "ps1:"+strings.Repeat("3", 64), "sha256:"+strings.Repeat("3", 64)
		target.SourcePolicyRevision++
		target.ProjectionRevision++
		target.ExecutorPolicyRevision++
		target.ConfigRevision++
		rollback.SourcePolicyRevision += 2
		rollback.ProjectionRevision += 2
		rollback.ExecutorPolicyRevision += 2
		rollback.ConfigRevision += 2
		target.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("b", 64)
		rollback.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("c", 64)
		target.ConfigSHA256 = "sha256:" + strings.Repeat("e", 64)
		rollback.ConfigSHA256 = "sha256:" + strings.Repeat("f", 64)
		target.LocalListenPort = 18084
		if mode == contracts.SystemUpdatePortModeLocalAndAdvertised {
			target.AdvertisedPort = 8443
			target.EndpointRevision++
			target.AppliedEndpointRevision++
			rollback.EndpointRevision += 2
			rollback.AppliedEndpointRevision += 2
			endpoint.Port = 8443
			endpoint.PublicURL = "https://worker.example.test:8443/"
			target.AdvertisedEndpointSHA256, err = contracts.ComputeSystemUpdatePortEndpointSHA256(endpoint)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	shared := contracts.SystemUpdatePortReconfiguration{
		PortContractVersion: 2, Mode: mode, Before: &b, Target: &target, Rollback: &rollback,
		NetworkNamespace: "host", Protocol: contracts.SystemUpdatePortProtocolTCP,
	}
	shared.PortPlanSHA256, err = contracts.ComputeSystemUpdatePortPlanSHA256(shared)
	if err != nil || contracts.ValidateSystemUpdatePortPlan(shared) != nil {
		t.Fatal("invalid test port plan")
	}
	desired := contracts.UpdaterDesiredOperation{Operation: contracts.UpdaterDesiredPortReconfigure, PortReconfigure: &shared}
	identity := contracts.UpdaterTargetIdentity{TargetKind: contracts.UpdaterTargetApplication, ServiceID: "worker-01", ServiceType: contracts.SystemUpdateTargetWorker,
		DeploymentMode: contracts.SystemUpdateDeploymentSystemd, ExpectedConfigRevision: b.ConfigRevision}
	lease := v2PanelLease(t, now, desired, identity, contracts.UpdaterCapabilityPort)
	lease.Command.MutationAuthorization.DesiredRevision = target.ConfigRevision
	digest, err := contracts.ComputeUpdaterCommandCanonicalDigest(identity, target.ConfigRevision, 9, desired)
	if err != nil {
		t.Fatal(err)
	}
	lease.Command.CanonicalPayloadDigest, lease.Command.MutationAuthorization.CanonicalArgumentDigest = digest, digest
	if err := contracts.ValidateUpdaterLease(now, lease); err != nil {
		t.Fatal(err)
	}
	job, err := mapV2LeaseToUpdateJob(lease, "")
	if err != nil {
		t.Fatal(err)
	}
	policy := HostAgentPolicy{ServiceID: "updater-01", TransportMode: HostTransportPullV2, ExecutionHostID: "host-01", OwnershipEpoch: 9,
		Revision: b.ProjectionRevision, SourcePolicyRevision: b.SourcePolicyRevision, LocalExecutorPolicyRevision: b.ExecutorPolicyRevision,
		LocalExecutorPolicySHA256: b.ExecutorPolicySHA256,
		Targets: []HostAgentPolicyTarget{{ServiceID: "worker-01", ServiceType: "worker", DeploymentMode: ModeSystemd,
			EndpointRevision: b.EndpointRevision, AppliedEndpointRevision: b.AppliedEndpointRevision,
			AppliedConfigRevision: b.ConfigRevision, AppliedConfigSHA256: b.ConfigSHA256,
			DesiredEndpoint:     &HostAgentEndpoint{Host: "worker.example.test", Port: b.AdvertisedPort, SSLEnabled: true, PublicURL: "https://worker.example.test/"},
			AppliedEndpoint:     &HostAgentEndpoint{Host: "worker.example.test", Port: 443, SSLEnabled: true, PublicURL: "https://worker.example.test/"},
			LocalListenEndpoint: &HostAgentEndpoint{Host: "127.0.0.1", Port: b.LocalListenPort, PublicURL: "http://127.0.0.1:18081"}}},
	}
	plan, err := portExecutionPlanFromJob(policy, job, "session-1234567890abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return lease, job, policy, plan
}

func TestSTPortAgentFreshClaimRequiresCompleteBeforeProjection(t *testing.T) {
	for _, mode := range []contracts.SystemUpdatePortMode{contracts.SystemUpdatePortModeLocalOnly, contracts.SystemUpdatePortModeLocalAndAdvertised} {
		for _, noOp := range []bool{false, true} {
			name := string(mode) + "/changed"
			if noOp {
				name = string(mode) + "/unchanged"
			}
			t.Run(name, func(t *testing.T) {
				_, job, policy, plan := agentPortV2Fixture(t, mode, noOp)
				binding := HostAgentBinding{ExecutionHostID: job.HostID, OwnershipEpoch: job.OwnershipEpoch, TransportMode: HostTransportPullV2}
				if err := policy.validateForService(job.AgentServiceID, 0); err != nil {
					t.Fatal("before projection must be a valid host policy")
				}
				if err := validateHostPullClaim(job, job.AgentServiceID, binding, policy); err != nil {
					t.Fatal("fresh claim rejected the complete before projection")
				}
				if job.PolicyRevision != job.PortReconfigure.Before.ProjectionRevision ||
					!samePortSnapshot(plan.Before, job.PortReconfigure.Before) || !samePortSnapshot(plan.Target, job.PortReconfigure.Target) ||
					!samePortSnapshot(plan.Rollback, job.PortReconfigure.Rollback) || plan.PortIntentSHA256 != job.PortReconfigure.PortPlanSHA256 {
					t.Fatal("claim planning changed immutable intent")
				}
				if mode == contracts.SystemUpdatePortModeLocalAndAdvertised && !noOp {
					target := policy.Targets[0]
					// The former guard required pending T desire inside a B policy.
					// This valid CP projection is its red contract example.
					legacyMixedGuard := (target.EndpointRevision == job.PortReconfigure.Before.EndpointRevision || target.EndpointRevision == job.PortReconfigure.Target.EndpointRevision) &&
						target.DesiredEndpoint != nil && target.DesiredEndpoint.Port == job.PortReconfigure.Target.AdvertisedPort
					if legacyMixedGuard {
						t.Fatal("fixture did not expose the former mixed projection guard")
					}
					t.Log("red_witness=legacy_mixed_guard_rejects_complete_before")
					job.RecoveryRequired = true
					for _, ref := range []*contracts.SystemUpdatePortSnapshotRef{plan.Before, plan.Target, plan.Rollback} {
						candidate, err := portPolicyCandidate(policy, job.TargetID, *ref)
						if err != nil || validateHostPullClaim(job, job.AgentServiceID, binding, candidate) != nil {
							t.Fatal("recovery lost an original B/T/R projection")
						}
					}
				}
			})
		}
	}
}

func TestSTPortAgentFreshClaimRejectsMixedProjection(t *testing.T) {
	_, job, policy, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	targetPolicy, err := portPolicyCandidate(policy, job.TargetID, *plan.Target)
	if err != nil {
		t.Fatal("build target projection fixture")
	}
	binding := HostAgentBinding{ExecutionHostID: job.HostID, OwnershipEpoch: job.OwnershipEpoch, TransportMode: HostTransportPullV2}
	for _, test := range []struct {
		name   string
		mutate func(*HostAgentPolicy)
	}{
		{"desired_missing", func(p *HostAgentPolicy) { p.Targets[0].DesiredEndpoint = nil }},
		{"applied_missing", func(p *HostAgentPolicy) { p.Targets[0].AppliedEndpoint = nil }},
		{"desired_port", func(p *HostAgentPolicy) { p.Targets[0].DesiredEndpoint.Port = plan.Target.AdvertisedPort }},
		{"desired_host", func(p *HostAgentPolicy) { p.Targets[0].DesiredEndpoint.Host = "other.example.test" }},
		{"desired_ssl", func(p *HostAgentPolicy) { p.Targets[0].DesiredEndpoint.SSLEnabled = false }},
		{"desired_public_url", func(p *HostAgentPolicy) { p.Targets[0].DesiredEndpoint.PublicURL = "https://other.example.test/" }},
		{"pending_endpoint_revision", func(p *HostAgentPolicy) { p.Targets[0].EndpointRevision = plan.Target.EndpointRevision }},
		{"pending_desired_target", func(p *HostAgentPolicy) { p.Targets[0].DesiredEndpoint = targetPolicy.Targets[0].DesiredEndpoint }},
		{"mixed_endpoint_bindings", func(p *HostAgentPolicy) {
			p.Targets[0].AppliedEndpoint.Host = "other.example.test"
			p.Targets[0].DesiredEndpoint.Host = "other.example.test"
		}},
		{"complete_target", func(p *HostAgentPolicy) { *p = clonePortAgentPolicy(targetPolicy) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePortAgentPolicy(policy)
			test.mutate(&candidate)
			if validateHostPullClaim(job, job.AgentServiceID, binding, candidate) == nil {
				t.Fatal("fresh claim accepted a mixed or altered before projection")
			}
			if _, err := portExecutionPlanFromJob(candidate, job, plan.SessionID); err == nil {
				t.Fatal("mixed or altered projection reached root plan construction")
			}
		})
	}
}

func agentPortObservedResult(plan SystemdPortReconfigurePlan, kind contracts.SystemUpdatePortReconfigurationResult, at time.Time, agentVerified bool) SystemdPortReconfigureResult {
	result := SystemdPortReconfigureResult{DeploymentMode: plan.DeploymentMode, PortContractVersion: 2, Result: string(kind), Status: "succeeded", StateKnown: true, Message: "port observation verified",
		PortResult: &contracts.SystemUpdatePortResultV2{Result: kind, Observation: contracts.SystemUpdatePortObservation{
			PolicyDiskVerified: true, PolicyMemoryVerified: true, AgentProjectionVerified: agentVerified, ListenerVerified: true, ObservedAt: at,
		}}}
	ref := plan.Target
	if kind == contracts.SystemUpdatePortReconfigurationUnchanged {
		ref = plan.Before
	}
	if kind == contracts.SystemUpdatePortReconfigurationRolledBack {
		ref = plan.Rollback
		result.Status = "rolled_back"
	}
	if kind == contracts.SystemUpdatePortReconfigurationRollbackFailed {
		result.Status, result.StateKnown, result.RecoveryRequired = "failed", false, true
		result.PortResult.Observation.ListenerVerified = false
		result.PortResult.Observation.AgentProjectionVerified = false
		return result
	}
	result.PortResult.ObservedSnapshotID, result.PortResult.ObservedSnapshotSHA256 = ref.SnapshotID, ref.SnapshotSHA256
	result.PortResult.ObservedConfigRevision, result.PortResult.ObservedConfigSHA256 = ref.ConfigRevision, ref.ConfigSHA256
	result.PortResult.ObservedExecutorPolicyRevision, result.PortResult.ObservedExecutorPolicySHA256 = ref.ExecutorPolicyRevision, ref.ExecutorPolicySHA256
	return result
}

func TestSTPortAgentTypedResultsCrossWireAndPreserveObservation(t *testing.T) {
	for _, mode := range []contracts.SystemUpdatePortMode{contracts.SystemUpdatePortModeLocalOnly, contracts.SystemUpdatePortModeLocalAndAdvertised} {
		for _, kind := range []contracts.SystemUpdatePortReconfigurationResult{contracts.SystemUpdatePortReconfigurationApplied, contracts.SystemUpdatePortReconfigurationUnchanged, contracts.SystemUpdatePortReconfigurationRolledBack} {
			t.Run(string(mode)+"/"+string(kind), func(t *testing.T) {
				lease, job, _, plan := agentPortV2Fixture(t, mode, kind == contracts.SystemUpdatePortReconfigurationUnchanged)
				at := lease.LeaseExpiresAt.Add(-4 * time.Minute)
				observed := agentPortObservedResult(plan, kind, at, true)
				requests := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/services/update-jobs/claim" {
						writeV2PanelJSON(t, w, http.StatusOK, lease)
						return
					}
					payload, err := io.ReadAll(r.Body)
					if err != nil || contracts.ValidateUpdaterResultEnvelope(lease, payload) != nil {
						t.Error("wire result validation failed")
					}
					var result contracts.UpdaterResultEnvelope
					if json.Unmarshal(payload, &result) != nil || result.PortReconfigure == nil || !contracts.EqualSystemUpdatePortResults(*result.PortReconfigure, *observed.PortResult) ||
						result.AppliedRevision != observed.PortResult.ObservedConfigRevision || result.DesiredRevision != plan.Target.ConfigRevision {
						t.Error("wire result changed immutable content")
					}
					requests++
					writeV2PanelJSON(t, w, http.StatusOK, nil)
				}))
				defer server.Close()
				client := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
				client.Now = func() time.Time { return at.Add(time.Second) }
				claimed, _, err := client.ClaimHost(context.Background(), v2PanelClaimRequest(""))
				if err != nil || claimed.PolicyRevision != plan.Before.ProjectionRevision || claimed.PolicyRevision == lease.Command.MutationAuthorization.DesiredRevision {
					t.Fatal("JP and D were conflated")
				}
				port := PortReconfigurationJobReport(*observed.PortResult)
				report := JobReport{ServiceID: job.AgentServiceID, LeaseGeneration: job.LeaseGeneration, Sequence: 1, Status: observed.Status, Progress: 100, PortReconfigure: &port}
				if err := client.Report(context.Background(), job.ID, report); err != nil {
					t.Fatal(err)
				}
				client.Now = func() time.Time { return at.Add(2 * time.Second) }
				if err := client.Report(context.Background(), job.ID, report); err != nil {
					t.Fatal(err)
				}
				if requests != 2 {
					t.Fatal("result was not sent twice")
				}
				copy := cloneV2PanelReport(report)
				copy.PortReconfigure.Observation.ObservedAt = at.Add(time.Second)
				if err := client.Report(context.Background(), job.ID, copy); err == nil {
					t.Fatal("same sequence accepted a rewritten observation time")
				}
			})
		}
	}
}

func TestSTPortAgentFailedRecoveryKeepsCursorAndAcceptsLaterRollback(t *testing.T) {
	_, job, policy, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	dir := t.TempDir()
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActivePortPlan(plan); err != nil {
		t.Fatal(err)
	}
	if err := journal.StagePortPolicy(policy, job, plan); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 6, 17, 1, 0, 0, time.UTC)
	failed := agentPortObservedResult(plan, contracts.SystemUpdatePortReconfigurationRollbackFailed, at, false)
	if _, err := journal.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "failed", "port_rollback_failed", "recovery required", 100, &failed); err != nil {
		t.Fatal(err)
	}
	agent := &HostPullAgent{Journal: journal, StateDir: dir}
	panel := &hostPullExecutionTestPanel{}
	if err := agent.flushExecutionReports(context.Background(), panel); err != nil {
		t.Fatal(err)
	}
	active := journal.Active()
	if active == nil || active.PortResult != nil || !active.RecoveryRequired || active.LastRecoveryObservation == nil {
		t.Fatal("failed attempt consumed the accepted slot or cleared the cursor")
	}
	restarted, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	agent.Journal = restarted
	job.LeaseGeneration++
	job.ReportSequence = 5
	job.RecoveryRequired = true
	if err := restarted.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	plan.LeaseGeneration = job.LeaseGeneration
	plan.PortPlanSHA256, err = plan.ComputePortPlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetActivePortPlan(plan); err != nil {
		t.Fatal(err)
	}
	if err := restarted.StagePortPolicy(policy, job, plan); err != nil {
		t.Fatal(err)
	}
	rolledBack := agentPortObservedResult(plan, contracts.SystemUpdatePortReconfigurationRolledBack, at.Add(time.Minute), true)
	if _, err := restarted.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "rolled_back", "", "restored", 100, &rolledBack); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "failed", "", "late", 100, &failed); err == nil {
		t.Fatal("late failed recovery replaced accepted rollback")
	}
	oldTarget := agentPortObservedResult(plan, contracts.SystemUpdatePortReconfigurationApplied, at, true)
	if _, err := restarted.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "succeeded", "", "late", 100, &oldTarget); err == nil {
		t.Fatal("late target replaced accepted rollback")
	}
	reloaded, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if accepted := reloaded.Active().PortResult; accepted == nil || !contracts.EqualSystemUpdatePortResults(*accepted, *rolledBack.PortResult) {
		t.Fatal("accepted result was not durable")
	}
	// A fresh lease changes transport identity only.
	job.LeaseGeneration++
	job.ReportSequence = 1
	if err := reloaded.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	if _, err := reloaded.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "rolled_back", "", "restored", 100, &rolledBack); err != nil {
		t.Fatal(err)
	}
	changedTime := rolledBack
	changedTime.PortResult = clonePortResult(rolledBack.PortResult)
	changedTime.PortResult.Observation.ObservedAt = at.Add(3 * time.Minute)
	if _, err := reloaded.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "rolled_back", "", "restored", 100, &changedTime); err == nil {
		t.Fatal("fresh transport changed the accepted observation time")
	}
}

func TestSTPortAgentRestartKeepsRootRollbackProjection(t *testing.T) {
	_, job, policy, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	dir := t.TempDir()
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{journal.SetActive(&job), journal.SetActivePortPlan(plan), journal.StagePortPolicy(policy, job, plan)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	root := agentPortObservedResult(plan, contracts.SystemUpdatePortReconfigurationRolledBack, time.Date(2026, 9, 6, 17, 1, 0, 0, time.UTC), false)
	probes := 0
	wrongRoot := true
	agent := &HostPullAgent{Journal: journal, StateDir: dir, ObserveTargets: func(_ context.Context, candidate HostAgentPolicy) ([]HostTargetObservation, error) {
		probes++
		if !portAgentPolicyMatchesSnapshot(candidate, job.TargetID, plan.Rollback) {
			t.Error("probe did not receive saved R candidate")
		}
		observation := HostTargetObservation{ServiceID: job.TargetID, Availability: TargetAvailabilityAvailable, PolicyRevision: plan.Rollback.ExecutorPolicyRevision,
			PolicySHA256: plan.Rollback.ExecutorPolicySHA256, ConfigRevision: plan.Rollback.ConfigRevision, ConfigSHA256: plan.Rollback.ConfigSHA256,
			PortContractVersion: 2, PolicyTransitionVersion: 1, SourcePolicyRevision: plan.Rollback.SourcePolicyRevision, ProjectionRevision: plan.Rollback.ProjectionRevision,
			EndpointRevision: plan.Rollback.AppliedEndpointRevision, AgentUID: 1201, AgentGID: 1202, ObservedAt: root.PortResult.Observation.ObservedAt,
			ReportedPort: plan.Rollback.LocalListenPort, ReportedServiceType: "worker", ReportedDeploymentMode: ModeSystemd}
		if wrongRoot {
			observation.PolicySHA256 = plan.Target.ExecutorPolicySHA256
		}
		return []HostTargetObservation{observation}, nil
	}}
	if _, err := agent.verifyPortResultProjection(context.Background(), job, plan, root); err == nil {
		t.Fatal("old root proof marked R projection verified")
	}
	if active, err := journal.portPolicyCandidate(""); err != nil || !portAgentPolicyMatchesSnapshot(*active, job.TargetID, plan.Before) {
		t.Fatal("failed observation changed the active projection")
	}
	wrongRoot = false
	verified, err := agent.verifyPortResultProjection(context.Background(), job, plan, root)
	if err != nil || !verified.PortResult.Observation.AgentProjectionVerified || probes != 2 {
		t.Fatalf("projection verification: %v", err)
	}
	journal, err = OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	agent.Journal = journal
	cpT, err := portPolicyCandidate(policy, job.TargetID, *plan.Target)
	if err != nil {
		t.Fatal(err)
	}
	active, err := agent.portRecoveryPolicy(cpT)
	if err != nil || !portAgentPolicyMatchesSnapshot(active, job.TargetID, plan.Rollback) {
		t.Fatal("CP T downgraded saved R after restart")
	}
	if err := journal.adoptPortPolicy(job.ID, plan.Target.SnapshotID); err == nil {
		t.Fatal("rollback latch allowed T adoption")
	}
	changed := clonePortAgentPolicy(cpT)
	changed.OwnershipEpoch++
	if _, err := agent.portRecoveryPolicy(changed); err == nil {
		t.Fatal("changed ownership used original candidate")
	}
	if reflect.DeepEqual(active, cpT) {
		t.Fatal("R and T projections unexpectedly match")
	}
}

func TestSTPortAgentAcceptedResultsRemainImmutableAcrossFreshLeases(t *testing.T) {
	for _, kind := range []contracts.SystemUpdatePortReconfigurationResult{contracts.SystemUpdatePortReconfigurationApplied, contracts.SystemUpdatePortReconfigurationUnchanged, contracts.SystemUpdatePortReconfigurationRolledBack} {
		t.Run(string(kind), func(t *testing.T) {
			_, job, _, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalOnly, kind == contracts.SystemUpdatePortReconfigurationUnchanged)
			dir := t.TempDir()
			journal, err := OpenJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.SetActive(&job); err != nil {
				t.Fatal(err)
			}
			result := agentPortObservedResult(plan, kind, time.Date(2026, 9, 6, 17, 1, 0, 0, time.UTC), true)
			if _, err := journal.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, result.Status, "", "verified", 100, &result); err != nil {
				t.Fatal(err)
			}
			journal, err = OpenJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			job.LeaseGeneration++
			job.ReportSequence = 8
			job.RecoveryRequired = true
			if err := journal.SetActive(&job); err != nil {
				t.Fatal(err)
			}
			if _, err := journal.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, result.Status, "", "verified", 100, &result); err != nil {
				t.Fatal(err)
			}
			changed := result
			changed.PortResult = clonePortResult(result.PortResult)
			changed.PortResult.Observation.ObservedAt = changed.PortResult.Observation.ObservedAt.Add(time.Second)
			if _, err := journal.QueuePort(job.ID, job.AgentServiceID, "", job.LeaseGeneration, result.Status, "", "verified", 100, &changed); err == nil {
				t.Fatal("fresh lease rewrote accepted result")
			}
			if !contracts.EqualSystemUpdatePortResults(*journal.Active().PortResult, *result.PortResult) {
				t.Fatal("accepted result changed")
			}
		})
	}
}

func TestSTPortAgentUnknownAndPremutationFailureNeverFabricateResult(t *testing.T) {
	lease, job, _, _ := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalOnly, false)
	for _, status := range []string{"failed", "canceled", "reconciling"} {
		t.Run(status, func(t *testing.T) {
			report := JobReport{ServiceID: job.AgentServiceID, LeaseGeneration: job.LeaseGeneration, Sequence: 1, Status: status}
			if status == "reconciling" {
				report.Code = "outcome_ambiguous"
			}
			if err := validateV2PanelReportBinding(lease, job, job.ID, report); err != nil {
				t.Fatal(err)
			}
			mapped, err := mapV2JobReport(lease, report, lease.LeaseExpiresAt.Add(-time.Minute))
			if err != nil || mapped.result == nil || mapped.result.PortReconfigure != nil || mapped.result.AutomaticResendAllowed {
				t.Fatalf("unexpected result: %v", err)
			}
			if status == "reconciling" && mapped.result.Outcome != contracts.UpdaterOutcomeAmbiguous {
				t.Fatal("unknown outcome was converted to success")
			}
		})
	}
}

type agentPortTransitionExecutor struct {
	hostPullExecutionTestExecutor
	observedAt time.Time
	invalid    bool
}

func (e *agentPortTransitionExecutor) PortReconfigureV2(_ context.Context, plan SystemdPortReconfigurePlan, _ LocalExecutorMutationFence, _ V2MutationGrant) (SystemdPortReconfigureResult, error) {
	e.v2PortApplyCalls++
	if e.portApplyErr != nil {
		return SystemdPortReconfigureResult{}, e.portApplyErr
	}
	return e.rollbackResult(plan), nil
}

func (e *agentPortTransitionExecutor) PortReconfigureReconcileV2(_ context.Context, plan SystemdPortReconfigurePlan, _ LocalExecutorMutationFence, _ V2MutationGrant) (SystemdPortReconfigureResult, error) {
	e.v2PortReconCalls++
	return e.rollbackResult(plan), nil
}

func (e *agentPortTransitionExecutor) rollbackResult(plan SystemdPortReconfigurePlan) SystemdPortReconfigureResult {
	result := agentPortObservedResult(plan, contracts.SystemUpdatePortReconfigurationRolledBack, e.observedAt, false)
	if e.invalid {
		result.PortResult.Observation.PolicyDiskVerified = false
	}
	return result
}

// The Agent, Journal, V2 adapter, and HTTP response loss are real. The issuer,
// root result, and CP status/progress gates are bounded contract fixtures.
func TestSTPortAgentRollbackReportsRespectCPTransitionAndProgress(t *testing.T) {
	for _, test := range []struct {
		name            string
		mode            contracts.SystemUpdatePortMode
		recovery        bool
		previousFailure bool
		ambiguous       bool
		loseResponse    string
		invalidResult   bool
	}{
		{name: "fresh_local", mode: contracts.SystemUpdatePortModeLocalOnly},
		{name: "fresh_combined", mode: contracts.SystemUpdatePortModeLocalAndAdvertised},
		{name: "recovery_at_progress_ceiling", recovery: true},
		{name: "recovery_after_rollback_failed", recovery: true, previousFailure: true},
		{name: "same_process_ambiguous_reconcile", ambiguous: true},
		{name: "rolling_back_ack_loss", loseResponse: "rolling_back"},
		{name: "terminal_ack_loss", loseResponse: "rolled_back"},
		{name: "invalid_root_result", invalidResult: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode := test.mode
			if mode == "" {
				mode = contracts.SystemUpdatePortModeLocalAndAdvertised
			}
			lease, originalJob, policy, originalPlan := agentPortV2Fixture(t, mode, false)
			observedAt := lease.LeaseExpiresAt.Add(-4 * time.Minute)
			now := observedAt.Add(time.Second)
			expected := agentPortObservedResult(originalPlan, contracts.SystemUpdatePortReconfigurationRolledBack, observedAt, true).PortResult
			dir := t.TempDir()
			journal, err := OpenJournal(dir)
			if err != nil {
				t.Fatal("open transition journal")
			}
			if test.recovery {
				for _, err := range []error{journal.SetActive(&originalJob), journal.SetActivePortPlan(originalPlan), journal.StagePortPolicy(policy, originalJob, originalPlan)} {
					if err != nil {
						t.Fatal("stage interrupted transition")
					}
				}
				if test.previousFailure {
					failed := agentPortObservedResult(originalPlan, contracts.SystemUpdatePortReconfigurationRollbackFailed, observedAt.Add(-time.Second), false)
					if _, err := journal.QueuePort(originalJob.ID, originalJob.AgentServiceID, "", originalJob.LeaseGeneration, "failed", "port_rollback_failed", "recovery required", 100, &failed); err != nil {
						t.Fatal("persist failed rollback observation")
					}
					journal, err = OpenJournal(dir)
					if err != nil {
						t.Fatal("reopen recovery journal")
					}
				}
			}
			cpStatus, cpProgress := "claimed", 0
			if test.recovery {
				cpProgress = 100 // CP retains this across a fresh recovery lease.
			}
			activeLease := lease
			claims, grants, rolling, terminals, acceptances := 0, 0, 0, 0, 0
			lost := false
			var lostBody, acceptedBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if r.URL.Path == "/services/update-jobs/claim" {
					var request contracts.UpdateAgentClaimRequest
					if json.Unmarshal(body, &request) != nil {
						t.Error("invalid claim fixture request")
					}
					claims++
					activeLease = lease
					if request.ActiveJobID != "" {
						if request.ActiveJobID != originalJob.ID {
							t.Error("recovery changed the active job")
						}
						activeLease.LeaseGeneration++
						cpStatus = "reconciling"
					}
					writeV2PanelJSON(t, w, http.StatusOK, activeLease)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/mutation-grants") {
					if contracts.ValidateUpdaterMutationGrantIssueRequest(now, body) != nil {
						t.Error("invalid transition grant request")
					}
					grants++
					writeV2PanelJSON(t, w, http.StatusCreated, contracts.UpdaterMutationGrantIssueResponse{GrantToken: strings.Repeat("g", 32), ExpiresAt: now.Add(time.Minute)})
					return
				}
				step, nextProgress, allowed := "", cpProgress, false
				if contracts.ValidateUpdaterProgressEnvelope(activeLease, body) == nil {
					var progress contracts.UpdaterProgressEnvelope
					_ = json.Unmarshal(body, &progress)
					nextProgress = progress.Progress
					switch progress.Phase {
					case "accepted":
						step, allowed = "claimed", cpStatus == "claimed"
					case "executing":
						step, allowed = "installing", cpStatus == "claimed"
					case "rolling_back":
						step, allowed = "rolling_back", cpStatus == "installing" || cpStatus == "rolling_back"
					case "reconciling":
						step, allowed = "reconciling", cpStatus == "reconciling" || cpStatus == "rolling_back"
					}
				} else if contracts.ValidateUpdaterResultEnvelope(activeLease, body) == nil {
					var result contracts.UpdaterResultEnvelope
					_ = json.Unmarshal(body, &result)
					if result.Outcome == contracts.UpdaterOutcomeAmbiguous {
						step, allowed = "reconciling", cpStatus == "installing"
					} else if result.PortReconfigure != nil && contracts.EqualSystemUpdatePortResults(*expected, *result.PortReconfigure) {
						step, nextProgress = "rolled_back", 100
						allowed = cpStatus == "rolling_back" || cpStatus == "reconciling" || cpStatus == "rolled_back" && string(acceptedBody) == string(body)
					}
				}
				if !allowed || nextProgress < cpProgress {
					writeV2PanelJSON(t, w, http.StatusConflict, map[string]string{"code": "system_update_transition_invalid"})
					return
				}
				cpStatus, cpProgress = step, nextProgress
				if step == "rolling_back" {
					rolling++
					candidate, err := journal.portPolicyCandidate("")
					if err != nil || !portAgentPolicyMatchesSnapshot(*candidate, originalJob.TargetID, originalPlan.Rollback) {
						t.Error("rollback progress preceded verified durable R adoption")
					}
				}
				if step == "rolled_back" {
					terminals++
					if acceptedBody == nil {
						acceptedBody = append([]byte(nil), body...)
						acceptances++
					}
				}
				if step == test.loseResponse {
					if !lost {
						lost, lostBody = true, append([]byte(nil), body...)
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error("inject committed response loss")
							return
						}
						_ = conn.Close()
						return
					}
					if string(lostBody) != string(body) {
						t.Error("same-lease retry rewrote the committed report")
					}
				}
				writeV2PanelJSON(t, w, http.StatusOK, nil)
			}))
			defer server.Close()
			client := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
			client.Now = func() time.Time { return now }
			request := v2PanelClaimRequest("")
			if test.recovery {
				request.ActiveJobID = originalJob.ID
			}
			job, _, err := client.ClaimHost(context.Background(), request)
			if err != nil {
				t.Fatal("claim transition fixture")
			}
			executor := &agentPortTransitionExecutor{observedAt: observedAt, invalid: test.invalidResult}
			if test.ambiguous {
				executor.portApplyErr = io.ErrUnexpectedEOF
			}
			agent := &HostPullAgent{Bootstrap: Config{NodeID: job.AgentServiceID}, Journal: journal, StateDir: dir, PortExecutor: executor,
				NewSessionID: func() (string, error) { return originalPlan.SessionID, nil }}
			probes := 0
			agent.ObserveTargets = func(_ context.Context, candidate HostAgentPolicy) ([]HostTargetObservation, error) {
				probes++
				ref := originalPlan.Rollback
				if !portAgentPolicyMatchesSnapshot(candidate, job.TargetID, ref) {
					return nil, io.ErrUnexpectedEOF
				}
				return []HostTargetObservation{{ServiceID: job.TargetID, Availability: TargetAvailabilityAvailable,
					PolicyRevision: ref.ExecutorPolicyRevision, PolicySHA256: ref.ExecutorPolicySHA256, ConfigRevision: ref.ConfigRevision, ConfigSHA256: ref.ConfigSHA256,
					PortContractVersion: 2, PolicyTransitionVersion: 1, SourcePolicyRevision: ref.SourcePolicyRevision, ProjectionRevision: ref.ProjectionRevision,
					EndpointRevision: ref.AppliedEndpointRevision, AgentUID: 1201, AgentGID: 1202, ObservedAt: observedAt,
					ReportedPort: ref.LocalListenPort, ReportedServiceType: job.EffectiveType(), ReportedDeploymentMode: job.DeploymentMode}}, nil
			}
			binding := HostAgentBinding{ExecutionHostID: job.HostID, OwnershipEpoch: job.OwnershipEpoch, TransportMode: HostTransportPullV2}
			err = agent.processPortReconfigurationJob(context.Background(), client, binding, policy, *job)
			if test.invalidResult {
				if err == nil || grants != 1 || executor.v2PortApplyCalls != 1 || probes != 0 || rolling != 0 || terminals != 0 || journal.Active().PortResult != nil {
					t.Fatal("invalid root result advanced rollback reporting")
				}
				return
			}
			if test.loseResponse != "" {
				if err == nil || !lost || journal.Active() == nil || len(journal.Pending()) != 1 {
					t.Fatal("committed response loss did not retain the durable cursor")
				}
				payload, readErr := os.ReadFile(journal.path)
				var persisted journalData
				if readErr != nil || json.Unmarshal(payload, &persisted) != nil || persisted.ActiveJob == nil || len(persisted.Pending) != 1 {
					t.Fatal("response loss was not persisted")
				}
				if test.loseResponse == "rolled_back" {
					if persisted.ActiveJob.PortResult == nil || !contracts.EqualSystemUpdatePortResults(*expected, *persisted.ActiveJob.PortResult) {
						t.Fatal("terminal response loss changed the durable first result")
					}
				} else if persisted.ActiveJob.PortResult != nil {
					t.Fatal("rollback progress filled the accepted result slot")
				}
				rootCalls := executor.v2PortApplyCalls + executor.v2PortReconCalls
				if err := agent.flushExecutionReports(context.Background(), client); err != nil || executor.v2PortApplyCalls+executor.v2PortReconCalls != rootCalls {
					t.Fatal("report retry failed or repeated a root invocation")
				}
				if test.loseResponse == "rolling_back" {
					journal, err = OpenJournal(dir)
					if err != nil {
						t.Fatal("reopen acknowledged rollback progress")
					}
					agent.Journal = journal
					request.ActiveJobID = job.ID
					job, _, err = client.ClaimHost(context.Background(), request)
					candidate, candidateErr := journal.portPolicyCandidate("")
					if err != nil || candidateErr != nil || !job.RecoveryRequired {
						t.Fatal("progress response loss did not obtain same-job recovery")
					}
					err = agent.processPortReconfigurationJob(context.Background(), client, binding, *candidate, *job)
				} else {
					err = nil
				}
			}
			if err != nil || cpStatus != "rolled_back" || cpProgress != 100 || acceptances != 1 || journal.Active() != nil || len(journal.Pending()) != 0 {
				t.Fatal("verified rollback did not settle through legal monotonic reports")
			}
			wantRolling, wantClaims, wantRoot, wantTerminals := 1, 1, 1, 1
			if test.recovery || test.ambiguous {
				wantRolling = 0
			}
			if test.ambiguous {
				wantRoot = 2
			}
			if test.loseResponse == "rolling_back" {
				wantRolling, wantClaims, wantRoot = 2, 2, 2
			}
			if test.loseResponse == "rolled_back" {
				wantTerminals = 2
			}
			if rolling != wantRolling || claims != wantClaims || grants != wantRoot || terminals != wantTerminals || executor.v2PortApplyCalls+executor.v2PortReconCalls != wantRoot ||
				test.recovery && executor.v2PortApplyCalls != 0 || !test.recovery && executor.v2PortApplyCalls != 1 {
				t.Fatal("rollback reporting changed claim or root execution counts")
			}
		})
	}
}
