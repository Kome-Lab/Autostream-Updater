package hostruntime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

// This exercises the real Agent execution and HTTP adapters with a bounded
// root-result stub. It does not claim a real systemd/Docker integration run.
func TestSTPortAgentRestartBeforeProjectionAdoptionReachesSameJobClaim(t *testing.T) {
	type fixture struct {
		name     string
		mode     contracts.SystemUpdatePortMode
		kind     contracts.SystemUpdatePortReconfigurationResult
		negative string
	}
	var fixtures []fixture
	for _, mode := range []contracts.SystemUpdatePortMode{contracts.SystemUpdatePortModeLocalOnly, contracts.SystemUpdatePortModeLocalAndAdvertised} {
		for _, kind := range []contracts.SystemUpdatePortReconfigurationResult{contracts.SystemUpdatePortReconfigurationApplied, contracts.SystemUpdatePortReconfigurationUnchanged, contracts.SystemUpdatePortReconfigurationRolledBack} {
			fixtures = append(fixtures, fixture{name: string(mode) + "/" + string(kind), mode: mode, kind: kind})
		}
	}
	for _, name := range []string{"unknown CP snapshot", "ownership changed", "JP changed", "root proof mismatch", "unstable runtime",
		"stale generation", "skipped generation", "reused command", "expired lease", "lease beyond authorization"} {
		fixtures = append(fixtures, fixture{name: name, mode: contracts.SystemUpdatePortModeLocalAndAdvertised, kind: contracts.SystemUpdatePortReconfigurationRolledBack, negative: name})
	}
	for _, test := range fixtures {
		t.Run(test.name, func(t *testing.T) {
			lease, job, policy, plan := agentPortV2Fixture(t, test.mode, test.kind == contracts.SystemUpdatePortReconfigurationUnchanged)
			expectedIssues := 1
			if test.kind == contracts.SystemUpdatePortReconfigurationUnchanged {
				expectedIssues = 0
			}
			if err := policy.validateForService(job.AgentServiceID, 0); err != nil {
				t.Fatal("fixture must use the valid production policy union")
			}
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
			// Persisted B is the actual stop point: root has an observation,
			// but Agent projection adoption and reporting have not happened.
			journal, err = OpenJournal(dir)
			if err != nil {
				t.Fatal(err)
			}
			cpTarget, err := journal.portPolicyCandidate(plan.Target.SnapshotID)
			if err != nil {
				t.Fatal(err)
			}
			rootRef := plan.Target
			if test.kind == contracts.SystemUpdatePortReconfigurationRolledBack {
				rootRef = plan.Rollback
			}
			if test.kind == contracts.SystemUpdatePortReconfigurationUnchanged {
				rootRef = plan.Before
			}
			observedAt := lease.LeaseExpiresAt.Add(-4 * time.Minute)
			now := observedAt.Add(30 * time.Second)
			rootResult := agentPortObservedResult(plan, test.kind, observedAt, false)
			expected := clonePortResult(rootResult.PortResult)
			expected.Observation.AgentProjectionVerified = true
			executor := &hostPullExecutionTestExecutor{portReconResult: &rootResult}
			probe := LocalExecutorProbe{PortContractVersion: 2, PolicyTransitionVersion: 1, SourcePolicyRevision: rootRef.SourcePolicyRevision,
				ProjectionRevision: rootRef.ProjectionRevision, PolicyRevision: rootRef.ExecutorPolicyRevision, PolicySHA256: rootRef.ExecutorPolicySHA256,
				AgentUID: 1201, AgentGID: 1202, EndpointRevision: rootRef.AppliedEndpointRevision, ObservedAt: now,
				ServiceID: job.TargetID, ServiceType: job.EffectiveType(), DeploymentMode: job.DeploymentMode, ConfigRevision: rootRef.ConfigRevision, ConfigSHA256: rootRef.ConfigSHA256,
				CurrentVersion: "v1.2.3", MainPID: 51, ListenerPID: 51, ControlGroup: "/system.slice/worker.service",
				ListenerAddress: "127.0.0.1:" + strconv.Itoa(rootRef.LocalListenPort)}
			advanceSTPortLease(t, &lease)
			claims, issues, terminals := 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/services/update-jobs/claim" {
					var claim contracts.UpdateAgentClaimRequest
					if json.NewDecoder(r.Body).Decode(&claim) != nil || claim.ActiveJobID != job.ID {
						t.Error("recovery did not claim the saved job")
					}
					claims++
					writeV2PanelJSON(t, w, http.StatusOK, lease)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error("read recovery request")
				}
				if strings.HasSuffix(r.URL.Path, "/mutation-grants") {
					var issue contracts.UpdaterMutationGrantIssueRequest
					if contracts.ValidateUpdaterMutationGrantIssueRequest(now, body) != nil || json.Unmarshal(body, &issue) != nil ||
						issue.Binding.Operation != contracts.UpdaterMutationPortReconfigureReconcile || issue.Binding.SessionID != plan.SessionID ||
						!reflect.DeepEqual(issue.Binding.Lease, lease) {
						t.Error("recovery grant did not retain original intent and session")
					}
					issues++
					writeV2PanelJSON(t, w, http.StatusCreated, contracts.UpdaterMutationGrantIssueResponse{GrantToken: strings.Repeat("g", 32), ExpiresAt: now.Add(time.Minute)})
					return
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(body, &fields) != nil {
					t.Error("decode recovery report")
				}
				if _, progress := fields["phase"]; progress {
					if contracts.ValidateUpdaterProgressEnvelope(lease, body) != nil {
						t.Error("invalid recovery progress")
					}
				} else {
					var result contracts.UpdaterResultEnvelope
					if contracts.ValidateUpdaterResultEnvelope(lease, body) != nil || json.Unmarshal(body, &result) != nil || result.PortReconfigure == nil ||
						!contracts.EqualSystemUpdatePortResults(*expected, *result.PortReconfigure) {
						t.Error("recovery changed the accepted observation")
					}
					candidate, err := journal.portPolicyCandidate("")
					if err != nil || !portAgentPolicyMatchesSnapshot(*candidate, job.TargetID, rootRef) || journal.Active().PortResult == nil {
						t.Error("terminal preceded durable projection adoption")
					}
					terminals++
				}
				writeV2PanelJSON(t, w, http.StatusOK, nil)
			}))
			defer server.Close()
			panel := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
			panel.Now = func() time.Time { return now }
			binding := HostAgentBinding{ExecutionHostID: job.HostID, OwnershipEpoch: job.OwnershipEpoch, TransportMode: HostTransportPullV2}
			agent := &HostPullAgent{Bootstrap: Config{NodeID: job.AgentServiceID}, StateDir: dir, Journal: journal, ControlPlane: panel, PortExecutor: executor}
			switch test.negative {
			case "unknown CP snapshot":
				cpTarget.LocalExecutorPolicyRevision += 9
			case "ownership changed":
				binding.OwnershipEpoch++
			case "JP changed":
				journal.data.ActiveJob.PolicyRevision++
			case "stale generation":
				lease.LeaseGeneration--
			case "skipped generation":
				lease.LeaseGeneration++
			case "reused command":
				lease.Command.CommandID = job.CommandID
			case "expired lease":
				lease.LeaseExpiresAt = now.Add(-time.Second)
			case "lease beyond authorization":
				lease.LeaseExpiresAt = lease.Command.MutationAuthorization.ExpiresAt.Add(time.Second)
			case "root proof mismatch":
				probe.PolicySHA256 = "sha256:" + strings.Repeat("9", 64)
			case "unstable runtime":
				status := HostSelfUpdateRuntimeStatus{}
				status.State.Phase = HostSelfUpdatePhaseStaged
				agent.selfUpdateStatus.Store(&status)
			}
			agent.ObserveTargets = NewLocalExecutorTargetObserver(agentPortProbeStub{probe})
			err = agent.executeOnce(context.Background(), binding, *cpTarget)
			if test.negative == "" {
				if err != nil || claims != 1 || issues != expectedIssues || terminals != 1 || executor.v2PortReconCalls != 1 || journal.Active() != nil {
					t.Fatalf("same-job recovery did not complete: %v", err)
				}
				if executor.portFences[0] != (LocalExecutorMutationFence{SourcePolicyRevision: plan.Before.SourcePolicyRevision, OwnershipPolicyRevision: plan.Before.ProjectionRevision,
					ExecutorPolicyRevision: plan.Before.ExecutorPolicyRevision, OwnershipEpoch: job.OwnershipEpoch}) {
					t.Fatal("recovery changed original authorization fence")
				}
				if reopened, err := OpenJournal(dir); err != nil || reopened.Active() != nil {
					t.Fatal("terminal acknowledgement did not durably clear the cursor")
				}
			} else {
				if err == nil || terminals != 0 || journal.Active() == nil || journal.Active().PortResult != nil {
					t.Fatal("unverified recovery was accepted")
				}
				if test.negative != "root proof mismatch" && (issues != 0 || executor.v2PortReconCalls != 0) {
					t.Fatal("invalid authority reached root reconcile")
				}
			}
			if executor.v2PortApplyCalls != 0 || executor.portApplyCalls != 0 || executor.applyCalls != 0 {
				t.Fatal("restart reapplied the target")
			}
		})
	}
}

func TestSTPortFreshLeasePreservesJournalAndImmutableIntent(t *testing.T) {
	lease, original, policy, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	advanceSTPortLease(t, &lease)
	fresh, err := mapV2LeaseToUpdateJob(lease, original.ID)
	if err != nil || !sameRecoveredJobIntent(original, fresh) {
		t.Fatal("validated next-generation transport identity was rejected")
	}
	dir := t.TempDir()
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{journal.SetActive(&original), journal.SetActivePortPlan(plan), journal.StagePortPolicy(policy, original, plan)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	journal, err = OpenJournal(dir)
	if err != nil || journal.SetActive(&fresh) != nil {
		t.Fatal("restarted journal rejected the fresh same-job lease")
	}
	if !reflect.DeepEqual(journal.ActivePortPlan(), &plan) || journal.Active().CommandID != fresh.CommandID {
		t.Fatal("fresh lease replaced the saved plan or failed to adopt transport identity")
	}
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{"job", func(v *UpdateJob) { v.ID = "different-job" }},
		{"target", func(v *UpdateJob) { v.TargetID = "different-target" }},
		{"updater", func(v *UpdateJob) { v.AgentServiceID = "different-updater" }},
		{"host", func(v *UpdateJob) { v.HostID = "different-host" }},
		{"fence", func(v *UpdateJob) { v.OwnershipEpoch++ }},
		{"job_policy", func(v *UpdateJob) { v.PolicyRevision++ }},
		{"before", func(v *UpdateJob) { v.PortReconfigure.Before.LocalListenPort++ }},
		{"target_snapshot", func(v *UpdateJob) { v.PortReconfigure.Target.LocalListenPort++ }},
		{"rollback", func(v *UpdateJob) { v.PortReconfigure.Rollback.LocalListenPort++ }},
		{"reused_command", func(v *UpdateJob) { v.CommandID = original.CommandID }},
		{"stale_generation", func(v *UpdateJob) { v.LeaseGeneration = original.LeaseGeneration }},
		{"skipped_generation", func(v *UpdateJob) { v.LeaseGeneration++ }},
		{"not_recovery", func(v *UpdateJob) { v.RecoveryRequired = false }},
		{"invalid_expiry", func(v *UpdateJob) { v.LeaseExpiresAt = "invalid" }},
		{"same_lease_extension", func(v *UpdateJob) { v.CommandID = original.CommandID; v.LeaseGeneration = original.LeaseGeneration }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneV2PanelJob(fresh)
			test.mutate(&changed)
			if sameRecoveredJobIntent(original, changed) {
				t.Fatal("recovery replaced immutable intent or reused/retimed a lease")
			}
			if changed.ID != original.ID {
				return // executeOnce guards a different job before SetActive.
			}
			isolated, err := OpenJournal(t.TempDir())
			if err != nil || isolated.SetActive(&original) != nil || isolated.SetActive(&changed) == nil ||
				!reflect.DeepEqual(isolated.Active(), journalJobWithoutCredentials(original)) {
				t.Fatal("journal did not retain the original job after rejecting recovery")
			}
		})
	}
	software, replaced := original, fresh
	software.Operation, replaced.Operation = updateJobOperationSoftwareUpdate, updateJobOperationSoftwareUpdate
	software.PortReconfigure, replaced.PortReconfigure = nil, nil
	if sameRecoveredJobIntent(software, replaced) {
		t.Fatal("port recovery exception admitted a software command replacement")
	}
}

func journalJobWithoutCredentials(job UpdateJob) *UpdateJob {
	copy := cloneV2PanelJob(job)
	copy.LeaseToken, copy.ReleaseToken = "", ""
	return &copy
}
