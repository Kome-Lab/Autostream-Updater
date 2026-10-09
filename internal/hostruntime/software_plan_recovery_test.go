package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

type softwarePlanRecoveryTestPanel struct {
	*V2PanelClient
	policy HostAgentPolicy
}

type softwarePlanRecoveryWithoutBinder struct {
	HostPullControlPlane
	HostPullExecutionControlPlane
}

func (p *softwarePlanRecoveryTestPanel) FetchHostAgentPolicy(context.Context, string, int64) (*HostAgentPolicy, bool, error) {
	copy := p.policy
	return &copy, true, nil
}

type softwarePlanRecoveryTestDownloader struct{ calls int }

func (d *softwarePlanRecoveryTestDownloader) Download(context.Context, string, string, string, string) (DownloadedArtifact, error) {
	d.calls++
	return DownloadedArtifact{}, errors.New("saved-plan recovery must not download")
}
func (d *softwarePlanRecoveryTestDownloader) ResolveDockerReleaseForArch(context.Context, string, string, string, string, string, string) (ResolvedDockerRelease, error) {
	d.calls++
	return ResolvedDockerRelease{}, errors.New("saved-plan recovery must not resolve a release")
}

type softwarePlanRecoveryTestExecutor struct {
	hostPullExecutionTestExecutor
	plans []MutationPlan
}

func (e *softwarePlanRecoveryTestExecutor) ReconcileV2(ctx context.Context, plan MutationPlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (ApplyResult, error) {
	e.plans = append(e.plans, plan)
	return e.hostPullExecutionTestExecutor.ReconcileV2(ctx, plan, fence, grant)
}

type softwarePlanRecoveryHTTPFixture struct {
	lease      contracts.UpdaterLeaseEnvelope
	returned   contracts.UpdaterLeaseEnvelope
	generation int64
	lostClaim  bool
	wrongLease string
	terminal   bool
	claims     []contracts.UpdateAgentClaimRequest
	grants     int
	reports    int
}

// The HTTP fixture exercises the production V2 adapter. The separate pinned
// CP process oracle remains the authority for server-side lease generation.
func newSoftwarePlanRecoveryHTTPHarness(t *testing.T, legacy, distinct bool) (*HostPullAgent, *softwarePlanRecoveryTestPanel, *softwarePlanRecoveryHTTPFixture, *softwarePlanRecoveryTestExecutor, *softwarePlanRecoveryTestDownloader, SoftwareClaimRecoveryRequest, MutationPlan) {
	t.Helper()
	now := time.Now().UTC()
	bootstrap := managedHostAgentBootstrap("https://panel.example.com")
	policy := HostAgentPolicy{ServiceID: bootstrap.NodeID, ExecutionHostID: "host-a", TransportMode: HostTransportPullV2, OwnershipEpoch: 3,
		Revision: 8, SourcePolicyRevision: 8, LocalExecutorPolicyRevision: 8, LocalExecutorPolicySHA256: "sha256:" + strings.Repeat("b", 64),
		Targets: []HostAgentPolicyTarget{{ServiceID: "worker-01", ServiceType: "worker", DeploymentMode: ModeSystemd, AppliedConfigRevision: 1}}}
	if distinct {
		policy.SourcePolicyRevision, policy.Revision, policy.LocalExecutorPolicyRevision = 11, 13, 17
	}
	lease := v2PanelSoftwareLease(t, now)
	lease.LeaseGeneration = 1
	authorization := &lease.Command.MutationAuthorization
	authorization.UpdaterID, authorization.HostID, authorization.Fence = bootstrap.NodeID, policy.ExecutionHostID, 3
	authorization.DesiredRevision, authorization.Target.ExpectedConfigRevision = 1, 1
	hostPullRefreshV2CommandDigest(t, &lease.Command)
	fixture := &softwarePlanRecoveryHTTPFixture{lease: lease, generation: 1}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/services/update-jobs/claim":
			var claim contracts.UpdateAgentClaimRequest
			if json.NewDecoder(r.Body).Decode(&claim) != nil {
				t.Error("invalid bounded claim fixture request")
				writeV2PanelJSON(t, w, http.StatusBadRequest, nil)
				return
			}
			fixture.claims = append(fixture.claims, claim)
			if claim.UpdaterID != bootstrap.NodeID || claim.HostID != policy.ExecutionHostID || claim.Fence != 3 ||
				claim.LeaseGeneration != fixture.generation || (claim.ActiveJobID != "" && claim.ActiveJobID != authorization.JobID) {
				writeV2PanelJSON(t, w, http.StatusConflict, nil)
				return
			}
			if fixture.terminal {
				writeV2PanelJSON(t, w, http.StatusOK, map[string]bool{"clear_active_job": true})
				return
			}
			if claim.ActiveJobID != "" {
				fixture.generation++
				fixture.lease.LeaseGeneration = fixture.generation
				fixture.lease.Command.CommandID = "software-plan-recovery-" + strconv.FormatInt(fixture.generation, 10)
			}
			if fixture.lostClaim {
				fixture.lostClaim = false
				writeV2PanelJSON(t, w, http.StatusServiceUnavailable, nil)
				return
			}
			returned := fixture.lease
			switch fixture.wrongLease {
			case "foreign_job":
				returned.Command.MutationAuthorization.JobID = "foreign-job"
			case "changed_version":
				copy := *returned.Command.DesiredOperation.SoftwareUpdate
				copy.TargetVersion = "v1.2.5"
				returned.Command.DesiredOperation.SoftwareUpdate = &copy
			case "generation_jump":
				returned.LeaseGeneration++
			}
			hostPullRefreshV2CommandDigest(t, &returned.Command)
			fixture.returned = returned
			writeV2PanelJSON(t, w, http.StatusOK, returned)
		case strings.Contains(r.URL.Path, "/mutation-grants"):
			fixture.grants++
			payload, err := io.ReadAll(r.Body)
			var issue contracts.UpdaterMutationGrantIssueRequest
			if err != nil || contracts.ValidateUpdaterMutationGrantIssueRequest(now, payload) != nil || json.Unmarshal(payload, &issue) != nil ||
				issue.Binding.Operation != contracts.UpdaterMutationReconcile || issue.Binding.Lease.LeaseGeneration != fixture.generation {
				t.Error("recovery requested an invalid or non-reconcile grant")
			}
			writeV2PanelJSON(t, w, http.StatusCreated, contracts.UpdaterMutationGrantIssueResponse{GrantToken: strings.Repeat("g", 32), ExpiresAt: now.Add(2 * time.Minute)})
		case strings.HasSuffix(r.URL.Path, "/report"):
			fixture.reports++
			payload, err := io.ReadAll(r.Body)
			if err != nil || contracts.ValidateUpdaterProgressEnvelope(fixture.lease, payload) != nil && contracts.ValidateUpdaterResultEnvelope(fixture.lease, payload) != nil {
				t.Error("recovery emitted an invalid fresh-lease progress or result")
			}
			writeV2PanelJSON(t, w, http.StatusOK, nil)
		default:
			t.Error("unexpected saved-plan recovery endpoint")
			writeV2PanelJSON(t, w, http.StatusNotFound, nil)
		}
	}))
	t.Cleanup(server.Close)
	panel := &softwarePlanRecoveryTestPanel{V2PanelClient: NewV2PanelClient(PanelClient{BaseURL: server.URL, HTTP: server.Client(), Token: "synthetic-runtime-token"}), policy: policy}
	panel.Now = func() time.Time { return now }
	executor, downloader := &softwarePlanRecoveryTestExecutor{}, &softwarePlanRecoveryTestDownloader{}
	agent, err := NewHostPullAgent(bootstrap, HostPullAgentOptions{StateDir: t.TempDir(), ControlPlane: panel, Executor: executor, Downloader: downloader, RecoveryOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	job, clear, err := panel.ClaimHost(context.Background(), HostPullClaimRequest{UpdaterID: bootstrap.NodeID, HostID: policy.ExecutionHostID, Fence: 3, LeaseGeneration: 1})
	if err != nil || clear || job == nil {
		t.Fatal("initial software lease fixture is invalid")
	}
	binding := HostAgentBinding{ServiceID: bootstrap.NodeID, ServiceType: ServiceTypeUpdateAgent, ExecutionHostID: policy.ExecutionHostID, TransportMode: HostTransportPullV2, OwnershipEpoch: 3}
	if err := agent.bindSoftwareClaim(panel, binding, policy, nil, job); err != nil {
		t.Fatal(err)
	}
	if legacy {
		job.SoftwareUpdate, job.PolicyRevision = nil, 1
	}
	agent.Journal, err = OpenJournal(agent.StateDir)
	if err != nil || agent.Journal.SetActive(job) != nil {
		t.Fatal("save initial software cursor")
	}
	plan := MutationPlan{JobID: job.ID, HostID: job.HostID, TargetID: job.TargetID, ServiceType: job.EffectiveType(), DeploymentMode: job.DeploymentMode,
		CurrentVersion: job.CurrentVersion, TargetVersion: job.EffectiveVersion(), ConfigSHA256: policy.LocalExecutorPolicySHA256, LeaseGeneration: job.LeaseGeneration,
		ArtifactDigest: strings.Repeat("a", 64), ExpectedVersion: job.EffectiveVersion(), SessionID: "session-0123456789abcdef"}
	plan.PlanSHA256, err = plan.ComputePlanSHA256()
	if err != nil || agent.Journal.SetActivePlan(plan) != nil {
		t.Fatal("save trusted original plan")
	}
	request := SoftwareClaimRecoveryRequest{JobID: job.ID, LeaseGeneration: 1, TargetID: job.TargetID, CurrentVersion: job.CurrentVersion,
		TargetVersion: job.EffectiveVersion(), ConfigRevision: 1, OwnershipEpoch: 3}
	fixture.claims = nil
	return agent, panel, fixture, executor, downloader, request, plan
}

func TestSoftwarePlanRecoveryLostClaimPreservesPlanAndExactRereadReconciles(t *testing.T) {
	for _, variant := range []struct{ legacy, distinct bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run("legacy="+strconv.FormatBool(variant.legacy)+"/distinct="+strconv.FormatBool(variant.distinct), func(t *testing.T) {
			agent, panel, fixture, executor, downloader, request, originalPlan := newSoftwarePlanRecoveryHTTPHarness(t, variant.legacy, variant.distinct)
			if _, err := agent.Journal.Queue(request.JobID, agent.Bootstrap.NodeID, "", 1, "claimed", "", "validated original claim", 5, "", ""); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(agent.Journal.path)
			if err != nil {
				t.Fatal(err)
			}
			fixture.lostClaim = true
			if err := agent.RecoverSoftwarePlanAfterGenerationRead(context.Background(), request); err == nil {
				t.Fatal("lost claim response was accepted")
			}
			after, err := os.ReadFile(agent.Journal.path)
			if err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(agent.Journal.ActivePlan(), &originalPlan) || len(agent.Journal.Pending()) != 1 || fixture.generation != 2 {
				t.Fatal("uncertain claim changed the original cursor, plan, pending reports, or bytes")
			}
			// A restart has no transport lease. The operator supplies only the
			// exact current generation of this same central job.
			fresh := &softwarePlanRecoveryTestPanel{V2PanelClient: NewV2PanelClient(panel.PanelClient), policy: panel.policy}
			fresh.Now = panel.Now
			agent, err = NewHostPullAgent(agent.Bootstrap, HostPullAgentOptions{StateDir: agent.StateDir, ControlPlane: fresh, Executor: executor, Downloader: downloader, RecoveryOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			request.LeaseGeneration = 2
			if err := agent.RecoverSoftwarePlanAfterGenerationRead(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if len(fixture.claims) != 2 || fixture.claims[1].ActiveJobID != request.JobID || fixture.claims[1].LeaseGeneration != 2 ||
				fixture.grants != 1 || fixture.reports != 2 || executor.v2ReconCalls != 1 ||
				executor.stageCalls+executor.applyCalls+executor.v2ApplyCalls+downloader.calls != 0 || agent.Journal.Active() != nil {
				t.Fatal("exact generation-gap recovery did not reconcile once without restaging or applying")
			}
			if len(executor.plans) != 1 || !sameJournalSoftwarePlanIntent(originalPlan, executor.plans[0]) || executor.plans[0].LeaseGeneration != 3 {
				t.Fatal("recovery substituted the original immutable software plan")
			}
			if fresh.lease == nil || !reflect.DeepEqual(fresh.lease.lease, fixture.returned) || fresh.lease.job.SoftwareUpdate == nil ||
				fresh.lease.job.PolicyRevision != panel.policy.Revision || fresh.lease.job.SoftwareUpdate.SourcePolicyRevision != panel.policy.SourcePolicyRevision ||
				fresh.lease.job.SoftwareUpdate.ExecutorPolicyRevision != panel.policy.LocalExecutorPolicyRevision ||
				fresh.lease.job.SoftwareUpdate.ExecutorPolicySHA256 != originalPlan.ConfigSHA256 ||
				fresh.lease.job.SoftwareUpdate.ConfigRevision != 1 || fresh.lease.lease.Command.MutationAuthorization.DesiredRevision != 1 ||
				fresh.lease.lease.Command.CanonicalPayloadDigest != fresh.lease.job.SoftwareUpdate.CommandSHA256 {
				t.Fatal("recovery changed the original wire lease or lost the authenticated policy projection")
			}
		})
	}
}

func TestSoftwarePlanRecoveryRejectsUntrustedRereadWithoutChangingJournal(t *testing.T) {
	for _, failure := range []string{"config", "ownership", "target", "version", "policy_digest", "policy_source", "policy_projection", "policy_executor", "missing_binding_adapter", "foreign_job", "changed_version", "generation_jump", "stale_generation", "foreign_pending", "terminal_intent"} {
		t.Run(failure, func(t *testing.T) {
			agent, panel, fixture, executor, downloader, request, _ := newSoftwarePlanRecoveryHTTPHarness(t, false, false)
			switch failure {
			case "config":
				request.ConfigRevision++
			case "ownership":
				request.OwnershipEpoch++
			case "target":
				request.TargetID = "foreign-target"
			case "version":
				request.TargetVersion = "v1.2.5"
			case "policy_digest":
				panel.policy.LocalExecutorPolicySHA256 = "sha256:" + strings.Repeat("c", 64)
			case "policy_source":
				panel.policy.SourcePolicyRevision++
			case "policy_projection":
				panel.policy.Revision++
			case "policy_executor":
				panel.policy.LocalExecutorPolicyRevision++
			case "missing_binding_adapter":
				withoutBinder := softwarePlanRecoveryWithoutBinder{panel, panel}
				agent.ControlPlane = recoveryOnlyHostPullControlPlane{HostPullControlPlane: withoutBinder, execution: withoutBinder}
			case "foreign_job", "changed_version", "generation_jump":
				fixture.wrongLease = failure
			case "stale_generation":
				fixture.generation = 2
			case "foreign_pending":
				if _, err := agent.Journal.Queue("foreign-job", agent.Bootstrap.NodeID, "", 1, "claimed", "", "other claim", 5, "", ""); err != nil {
					t.Fatal(err)
				}
			case "terminal_intent":
				intent := newSoftwareClaimRecoveryIntent(request, agent.Bootstrap.NodeID, panel.policy.ExecutionHostID, panel.policy)
				intent.Attempts = []softwareClaimRecoveryAttempt{{LeaseGeneration: 1, StartedAt: time.Now().UTC()}}
				if err := saveSoftwareClaimRecoveryIntent(agent.StateDir, "", intent); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(agent.Journal.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.RecoverSoftwarePlanAfterGenerationRead(context.Background(), request); err == nil {
				t.Fatal("untrusted saved-plan recovery was accepted")
			}
			after, err := os.ReadFile(agent.Journal.path)
			if err != nil || !bytes.Equal(before, after) || fixture.grants+fixture.reports+executor.stageCalls+executor.v2ReconCalls+executor.v2ApplyCalls+downloader.calls != 0 {
				t.Fatal("untrusted reread changed state, reported, downloaded, or executed")
			}
		})
	}
}
