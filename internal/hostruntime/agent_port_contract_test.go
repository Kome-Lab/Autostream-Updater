package hostruntime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

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
