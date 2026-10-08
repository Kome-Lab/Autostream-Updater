package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type softwareClaimRecoveryTestPanel struct {
	policy          HostAgentPolicy
	job             UpdateJob
	generation      uint64
	claims          []HostPullClaimRequest
	reports         []JobReport
	lostClaim       bool
	failBeforeClaim bool
	lostReport      bool
	denyReportOnce  bool
	wrongJob        bool
	terminal        bool
}

func (*softwareClaimRecoveryTestPanel) RegisterHostAgent(context.Context, Config, map[string]any) (HostAgentBinding, error) {
	return HostAgentBinding{}, errors.New("read-only recovery must not register")
}
func (*softwareClaimRecoveryTestPanel) HeartbeatHostAgent(context.Context, Config, string, map[string]any) error {
	return errors.New("read-only recovery must not heartbeat")
}
func (p *softwareClaimRecoveryTestPanel) FetchHostAgentPolicy(context.Context, string, int64) (*HostAgentPolicy, bool, error) {
	copy := p.policy
	return &copy, true, nil
}
func (p *softwareClaimRecoveryTestPanel) ClaimHost(_ context.Context, request HostPullClaimRequest) (*UpdateJob, bool, error) {
	p.claims = append(p.claims, request)
	if p.failBeforeClaim {
		p.failBeforeClaim = false
		return nil, false, errors.New("transport failed before server generation CAS")
	}
	if request.ActiveJobID != p.job.ID || request.UpdaterID != p.job.AgentServiceID || request.HostID != p.job.HostID ||
		request.Fence != p.job.OwnershipEpoch || uint64(request.LeaseGeneration) != p.generation {
		return nil, false, errors.New("exact recovery generation or identity differs")
	}
	if p.terminal {
		return &UpdateJob{ProtocolVersion: 2, ID: p.job.ID, AgentServiceID: p.job.AgentServiceID, Status: "canceled", RecoveryClear: true}, true, nil
	}
	p.generation++
	if p.lostClaim {
		p.lostClaim = false
		return nil, false, errors.New("claim response lost after durable server advance")
	}
	job := p.job
	job.LeaseGeneration, job.ReportSequence = p.generation, 1
	job.CommandID = "recovery-command-" + strconv.FormatUint(p.generation, 10)
	job.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	job.RecoveryRequired, job.Status = true, "reconciling"
	if p.wrongJob {
		job.ID = "foreign-job"
	}
	return &job, false, nil
}
func (p *softwareClaimRecoveryTestPanel) Report(_ context.Context, jobID string, report JobReport) error {
	if jobID != p.job.ID || report.Status != "failed" || report.Code != "software_claim_orphan_recovered" ||
		report.LeaseGeneration != p.generation || report.Sequence != 1 || !reportLeaseIsCredentialFree(report) {
		return errors.New("terminal-only recovery report is invalid")
	}
	if p.denyReportOnce {
		p.denyReportOnce = false
		return errors.New("report transport failed before acceptance")
	}
	p.reports = append(p.reports, report)
	p.terminal = true
	if p.lostReport {
		p.lostReport = false
		return errors.New("terminal response lost")
	}
	return nil
}
func (*softwareClaimRecoveryTestPanel) IssueMutationGrant(context.Context, string, MutationGrantRequest) (MutationGrant, error) {
	return MutationGrant{}, errors.New("terminal-only recovery must not issue a grant")
}

func reportLeaseIsCredentialFree(report JobReport) bool {
	return report.LeaseToken == "" && report.ArtifactDigest == "" && report.PreviousDigest == ""
}

type softwareClaimRecoveryTestInspector struct {
	calls    int
	reject   bool
	rejectAt int
}

func (i *softwareClaimRecoveryTestInspector) InspectSoftwareClaimRecovery(_ context.Context, inspection SoftwareClaimRecoveryInspection, fence LocalExecutorMutationFence) (SoftwareClaimRecoveryProof, error) {
	i.calls++
	if i.reject || i.rejectAt == i.calls {
		return SoftwareClaimRecoveryProof{}, errors.New("root absence unconfirmed")
	}
	return SoftwareClaimRecoveryProof{RequestSHA256: inspection.Request.sha256(), UpdaterID: "host-agent-a", HostID: "host-a",
		SourcePolicyRevision: fence.SourcePolicyRevision, ProjectionRevision: fence.OwnershipPolicyRevision,
		ExecutorPolicyRevision: fence.ExecutorPolicyRevision, ExecutorPolicySHA256: inspection.ExecutorPolicySHA256,
		OwnershipEpoch: fence.OwnershipEpoch, RuntimeVersion: "v2.0.0", NoMutation: true, ObservedAt: time.Now().UTC()}, nil
}

func newSoftwareClaimRecoveryHarness(t *testing.T) (*HostPullAgent, *softwareClaimRecoveryTestPanel, *softwareClaimRecoveryTestInspector, *hostPullExecutionTestExecutor, SoftwareClaimRecoveryRequest) {
	t.Helper()
	bootstrap := managedHostAgentBootstrap("https://panel.example.com")
	policy := HostAgentPolicy{ServiceID: bootstrap.NodeID, TransportMode: HostTransportPullV2, ExecutionHostID: "host-a", OwnershipEpoch: 3,
		Revision: 8, SourcePolicyRevision: 8, LocalExecutorPolicyRevision: 8, LocalExecutorPolicySHA256: "sha256:" + strings.Repeat("d", 64),
		Targets: []HostAgentPolicyTarget{{ServiceID: "control-panel", ServiceType: "control_panel", DeploymentMode: ModeSystemd, AppliedConfigRevision: 1}}}
	request := SoftwareClaimRecoveryRequest{JobID: "orphan-job-one", LeaseGeneration: 1, TargetID: "control-panel", CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ConfigRevision: 1, OwnershipEpoch: 3}
	panel := &softwareClaimRecoveryTestPanel{policy: policy, generation: 1, job: UpdateJob{
		ProtocolVersion: 2, ID: request.JobID, Operation: updateJobOperationSoftwareUpdate, AgentServiceID: bootstrap.NodeID,
		HostID: policy.ExecutionHostID, TransportMode: HostTransportPullV2, OwnershipEpoch: 3,
		TargetID: request.TargetID, TargetType: "control_panel", ServiceType: "control_panel", DeploymentMode: ModeSystemd,
		CurrentVersion: request.CurrentVersion, TargetVersion: request.TargetVersion,
		SoftwareUpdate: &SoftwareUpdateJobBinding{ConfigRevision: 1, CommandSHA256: "sha256:" + strings.Repeat("c", 64)},
	}}
	inspector, executor := &softwareClaimRecoveryTestInspector{}, &hostPullExecutionTestExecutor{}
	agent, err := NewHostPullAgent(bootstrap, HostPullAgentOptions{StateDir: t.TempDir(), ControlPlane: panel, Executor: executor,
		ClaimRecoveryInspector: inspector, Downloader: hostPullFailingDownloader{}, AgentVersion: "v2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	return agent, panel, inspector, executor, request
}

func TestSoftwareClaimRecoverySettlesExactOrphanWithoutExecuting(t *testing.T) {
	agent, panel, inspector, executor, request := newSoftwareClaimRecoveryHarness(t)
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(panel.claims) != 2 || panel.claims[0].ActiveJobID != request.JobID || panel.claims[0].LeaseGeneration != 1 ||
		panel.claims[1].ActiveJobID != request.JobID || panel.claims[1].LeaseGeneration != 2 || len(panel.reports) != 1 || inspector.calls < 2 {
		t.Fatalf("exact recovery claim/report counts differ: claims=%d reports=%d inspections=%d", len(panel.claims), len(panel.reports), inspector.calls)
	}
	if executor.stageCalls+executor.applyCalls+executor.reconcileCalls+executor.v2ApplyCalls+executor.v2ReconCalls != 0 ||
		agent.Journal.Active() != nil || len(agent.Journal.Pending()) != 0 {
		t.Fatal("terminal-only recovery executed software or retained an unsettled cursor")
	}
	intent, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || !intent.Settled || intent.Original != request || len(intent.Attempts) != 1 {
		t.Fatal("original durable recovery history was not retained")
	}
	payload, err := os.ReadFile(filepath.Join(agent.StateDir, softwareClaimRecoveryIntentName))
	if err != nil || strings.Contains(string(payload), "token") || strings.Contains(string(payload), "lease_id") {
		t.Fatal("durable recovery intent contains credential fields")
	}
}

func TestSoftwareClaimRecoveryLostClaimRequiresExactManualGenerationCAS(t *testing.T) {
	agent, panel, _, executor, request := newSoftwareClaimRecoveryHarness(t)
	panel.lostClaim = true
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
		t.Fatal("lost claim response was accepted")
	}
	if len(panel.claims) != 1 || panel.generation != 2 {
		t.Fatal("server lost-response fixture did not advance exactly once")
	}
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil || len(panel.claims) != 1 {
		t.Fatal("old attempted generation was retried blindly")
	}
	wrong := request
	wrong.LeaseGeneration = 9
	if err := agent.RecoverSoftwareClaim(context.Background(), wrong); err == nil || len(panel.reports) != 0 {
		t.Fatal("wrong reread generation settled the job")
	}
	intent, _, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || intent.Original != request || len(intent.Attempts) != 2 || intent.Attempts[0].LeaseGeneration != 1 {
		t.Fatal("failed supplied generation replaced original intent history")
	}
	request.LeaseGeneration = 2
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	intent, _, err = loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !intent.Settled || len(intent.Attempts) != 3 || intent.Attempts[2].LeaseGeneration != 2 {
		t.Fatal("explicit exact-generation CAS was not preserved")
	}
	if executor.stageCalls+executor.applyCalls+executor.reconcileCalls != 0 {
		t.Fatal("recovery retry reached a software executor")
	}
}

func TestSoftwareClaimRecoveryUnchangedGenerationRequiresExplicitRereadConfirmation(t *testing.T) {
	agent, panel, _, _, request := newSoftwareClaimRecoveryHarness(t)
	panel.failBeforeClaim = true
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
		t.Fatal("pre-request transport loss was accepted")
	}
	if panel.generation != 1 || len(panel.claims) != 1 {
		t.Fatal("pre-request failure advanced the server cursor")
	}
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil || len(panel.claims) != 1 {
		t.Fatal("uncertain old cursor was retried without reread confirmation")
	}
	if err := agent.RecoverSoftwareClaimAfterGenerationRead(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	intent, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || !intent.Settled || intent.Original != request || len(intent.Attempts) != 2 ||
		intent.Attempts[0].ConfirmedReread || !intent.Attempts[1].ConfirmedReread || intent.Attempts[1].LeaseGeneration != 1 {
		t.Fatal("explicit unchanged-generation reread replaced or failed to retain durable history")
	}
}

func TestSoftwareClaimRecoveryConfirmedOldGenerationCannotOverrideActualServerAdvance(t *testing.T) {
	agent, panel, _, _, request := newSoftwareClaimRecoveryHarness(t)
	panel.lostClaim = true
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
		t.Fatal("lost server-advanced claim was accepted")
	}
	if err := agent.RecoverSoftwareClaimAfterGenerationRead(context.Background(), request); err == nil || len(panel.reports) != 0 || panel.generation != 2 {
		t.Fatal("confirmation overrode exact server generation CAS")
	}
	intent, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || intent.Settled || intent.Original != request || len(intent.Attempts) != 2 || !intent.Attempts[1].ConfirmedReread {
		t.Fatal("rejected confirmed reread discarded original ambiguity history")
	}
	request.LeaseGeneration = 2
	if err := agent.RecoverSoftwareClaimAfterGenerationRead(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestSoftwareClaimRecoveryLostTerminalResponseRetainsIntentAndAcceptsSameJobClear(t *testing.T) {
	agent, panel, _, _, request := newSoftwareClaimRecoveryHarness(t)
	panel.lostReport = true
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
		t.Fatal("lost terminal acknowledgment was accepted")
	}
	if agent.Journal.Active() == nil || len(agent.Journal.Pending()) != 0 {
		t.Fatal("lost terminal report did not retain a credential-free active cursor")
	}
	restarted, err := NewHostPullAgent(agent.Bootstrap, HostPullAgentOptions{StateDir: agent.StateDir, ControlPlane: panel,
		Executor: agent.Executor, ClaimRecoveryInspector: agent.ClaimRecoveryInspector, AgentVersion: "v2.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	request.LeaseGeneration = panel.generation
	if err := restarted.RecoverSoftwareClaim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if restarted.Journal.Active() != nil || len(panel.reports) != 1 || len(panel.claims) != 2 || panel.claims[1].LeaseGeneration != 2 {
		t.Fatal("restart replayed a terminal report or discarded an unproven cursor")
	}
}

func TestSoftwareClaimRecoveryExistingNonexecutingCursorAndLostReclaimGap(t *testing.T) {
	agent, panel, _, executor, request := newSoftwareClaimRecoveryHarness(t)
	journal, err := OpenJournal(agent.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	agent.Journal = journal
	job := panel.job
	job.LeaseGeneration, job.ReportSequence, job.CommandID = 1, 1, "original-claim-command"
	job.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	binding := HostAgentBinding{ServiceID: agent.Bootstrap.NodeID, ServiceType: ServiceTypeUpdateAgent, TransportMode: HostTransportPullV2, ExecutionHostID: "host-a", OwnershipEpoch: 3}
	if err := agent.bindSoftwareClaim(panel, binding, panel.policy, nil, &job); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	panel.denyReportOnce = true
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
		t.Fatal("unaccepted terminal result was settled")
	}
	if agent.Journal.Active() == nil || agent.Journal.Active().LeaseGeneration != 2 {
		t.Fatal("first recovery did not retain the exact nonexecuting cursor")
	}
	request.LeaseGeneration = 2
	panel.lostClaim = true
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
		t.Fatal("lost recovery claim response was accepted")
	}
	if agent.Journal.Active().LeaseGeneration != 2 || panel.generation != 3 {
		t.Fatal("lost response changed the retained cursor")
	}
	before := len(panel.claims)
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil || len(panel.claims) != before {
		t.Fatal("ambiguous retained generation was retried blindly")
	}
	request.LeaseGeneration = 3
	if err := agent.RecoverSoftwareClaim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if agent.Journal.Active() != nil || executor.stageCalls+executor.applyCalls+executor.reconcileCalls != 0 || len(panel.reports) != 1 {
		t.Fatal("explicit generation-gap recovery executed software or failed to settle")
	}
}

func TestSoftwareClaimRecoveryLegacyAndRejectedWireCursorsConvergeOnlyToTerminal(t *testing.T) {
	for _, kind := range []string{"legacy_config_cursor", "rejected_wire_cursor"} {
		t.Run(kind, func(t *testing.T) {
			agent, panel, _, executor, request := newSoftwareClaimRecoveryHarness(t)
			journal, err := OpenJournal(agent.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			agent.Journal = journal
			job := panel.job
			job.LeaseGeneration, job.ReportSequence, job.CommandID = 1, 1, "original-nonexecuting-command"
			job.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
			if kind == "legacy_config_cursor" {
				job.SoftwareUpdate, job.PolicyRevision = nil, request.ConfigRevision
			} else {
				job.SoftwareClaimRejected, job.PolicyRevision = true, 0
			}
			if err := journal.SetActive(&job); err != nil {
				t.Fatal(err)
			}
			if err := agent.RecoverSoftwareClaim(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if agent.Journal.Active() != nil || len(panel.reports) != 1 || panel.reports[0].Status != "failed" ||
				executor.stageCalls+executor.applyCalls+executor.reconcileCalls != 0 {
				t.Fatal("original nonexecuting cursor was applied or did not converge to an authenticated failed terminal")
			}
		})
	}
}

func TestSoftwareClaimRecoveryMalformedRetainedCommandRejectsBeforeMarker(t *testing.T) {
	for _, commandID := range []string{"", "invalid command"} {
		t.Run(commandID, func(t *testing.T) {
			agent, panel, inspector, executor, request := newSoftwareClaimRecoveryHarness(t)
			journal, err := OpenJournal(agent.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			job := panel.job
			job.SoftwareUpdate, job.PolicyRevision = nil, request.ConfigRevision
			job.LeaseGeneration, job.ReportSequence, job.CommandID = 1, 1, commandID
			job.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
			if err := journal.SetActive(&job); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(agent.StateDir, "journal.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readSoftwareClaimRecoveryJournal(agent.StateDir); err != nil {
				t.Fatal("malformed command fixture must remain readable as a legacy journal")
			}
			if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
				t.Fatal("malformed retained command was admitted to terminal recovery")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) {
				t.Fatal("refused preflight changed the retained cursor")
			}
			if _, err := os.Lstat(filepath.Join(agent.StateDir, softwareClaimRecoveryIntentName)); !os.IsNotExist(err) {
				t.Fatal("refused preflight created a mutation-blocking intent")
			}
			if len(panel.claims)+len(panel.reports)+inspector.calls+executor.stageCalls+executor.applyCalls+executor.reconcileCalls != 0 {
				t.Fatal("malformed cursor recovery proceeded beyond strict local admission")
			}
		})
	}
}

func newSoftwareClaimRecoveryFirstProgressHarness(t *testing.T) (*HostPullAgent, *softwareClaimRecoveryTestPanel, *softwareClaimRecoveryTestInspector, *hostPullExecutionTestExecutor, SoftwareClaimRecoveryRequest) {
	t.Helper()
	agent, panel, inspector, executor, request := newSoftwareClaimRecoveryHarness(t)
	journal, err := OpenJournal(agent.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	job := panel.job
	job.LeaseGeneration, job.ReportSequence, job.CommandID, job.Status = 1, 1, "original-claim-command", "claimed"
	job.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	binding := HostAgentBinding{ServiceID: agent.Bootstrap.NodeID, ServiceType: ServiceTypeUpdateAgent, TransportMode: HostTransportPullV2, ExecutionHostID: panel.policy.ExecutionHostID, OwnershipEpoch: 3}
	if err := agent.bindSoftwareClaim(panel, binding, panel.policy, nil, &job); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Queue(job.ID, job.AgentServiceID, "", 1, "claimed", "", "update job claimed and fixed target validated", 5, "", ""); err != nil {
		t.Fatal(err)
	}
	agent.Journal = journal
	return agent, panel, inspector, executor, request
}

func TestSoftwareClaimRecoveryFirstProgressAckLossPreservesPendingUntilFreshTerminalProof(t *testing.T) {
	for _, failure := range []string{"none", "lost_claim", "root_after_claim", "foreign_lease"} {
		t.Run(failure, func(t *testing.T) {
			agent, panel, inspector, executor, request := newSoftwareClaimRecoveryFirstProgressHarness(t)
			before, err := os.ReadFile(agent.Journal.path)
			if err != nil {
				t.Fatal(err)
			}
			data, err := readSoftwareClaimRecoveryJournal(agent.StateDir)
			if err != nil || data.ActiveJob.ReportSequence != 0 || len(data.Pending) != 1 {
				t.Fatal("initial acknowledgement fixture does not preserve the durable sequence boundary")
			}
			switch failure {
			case "lost_claim":
				panel.lostClaim = true
			case "root_after_claim":
				inspector.rejectAt = 4
			case "foreign_lease":
				panel.wrongJob = true
			}
			err = agent.RecoverSoftwareClaim(context.Background(), request)
			if failure == "none" {
				if err != nil || agent.Journal.Active() != nil || len(agent.Journal.Pending()) != 0 || len(panel.reports) != 1 {
					t.Fatalf("authenticated no-mutation recovery did not settle the pending first progress: %v", err)
				}
			} else {
				after, readErr := os.ReadFile(agent.Journal.path)
				if err == nil || readErr != nil || string(before) != string(after) || len(agent.Journal.Pending()) != 1 || len(panel.reports) != 0 {
					t.Fatal("unconfirmed recovery discarded the original pending acknowledgement or cursor")
				}
			}
			if executor.stageCalls+executor.applyCalls+executor.v2ApplyCalls+executor.reconcileCalls+executor.v2ReconCalls != 0 {
				t.Fatal("first progress acknowledgement recovery executed software")
			}
		})
	}
}

func TestSoftwareClaimRecoveryFirstProgressAdmissionRejectsOtherPendingState(t *testing.T) {
	for _, failure := range []string{"foreign_job", "foreign_service", "wrong_generation", "wrong_sequence", "terminal", "artifact", "port", "token", "legacy_binding", "multiple", "wrong_next_sequence"} {
		t.Run(failure, func(t *testing.T) {
			agent, panel, _, _, request := newSoftwareClaimRecoveryFirstProgressHarness(t)
			data := agent.Journal.data
			data.Pending = append([]PendingReport(nil), data.Pending...)
			job := cloneV2PanelJob(*data.ActiveJob)
			data.ActiveJob = &job
			switch failure {
			case "foreign_job":
				data.Pending[0].JobID = "foreign-job"
			case "foreign_service":
				data.Pending[0].Report.ServiceID = "foreign-agent"
			case "wrong_generation":
				data.Pending[0].Report.LeaseGeneration++
			case "wrong_sequence":
				data.Pending[0].Report.Sequence++
			case "terminal":
				data.Pending[0].Report.Status = "failed"
			case "artifact":
				data.Pending[0].Report.ArtifactDigest = "sha256:" + strings.Repeat("a", 64)
			case "port":
				data.Pending[0].Report.PortReconfigure = &PortReconfigurationJobReport{}
			case "token":
				data.Pending[0].Report.LeaseToken = "protected-test-credential"
			case "legacy_binding":
				data.ActiveJob.SoftwareUpdate, data.ActiveJob.PolicyRevision = nil, 1
			case "multiple":
				data.Pending = append(data.Pending, data.Pending[0])
			case "wrong_next_sequence":
				data.NextSeq++
			}
			if softwareClaimRecoveryPendingAllowed(data) {
				t.Fatal("terminal-only recovery accepted unrelated or malformed pending state")
			}
			payload, err := json.Marshal(data)
			if err != nil || os.WriteFile(agent.Journal.path, payload, 0o600) != nil {
				t.Fatal("persist pending refusal fixture")
			}
			before, err := os.ReadFile(agent.Journal.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil || len(panel.claims)+len(panel.reports) != 0 {
				t.Fatal("malformed pending recovery reached CP claim or report")
			}
			after, err := os.ReadFile(agent.Journal.path)
			if err != nil || string(before) != string(after) {
				t.Fatal("refused pending preflight changed original bytes")
			}
			if _, err := os.Lstat(filepath.Join(agent.StateDir, softwareClaimRecoveryIntentName)); !os.IsNotExist(err) {
				t.Fatal("refused pending preflight created a blocking intent")
			}
		})
	}
}

func TestSoftwareClaimRecoveryRejectsForeignRequestAndRootUnknownBeforeClaim(t *testing.T) {
	for _, name := range []string{"config", "ownership", "target", "root_unknown", "foreign_lease"} {
		t.Run(name, func(t *testing.T) {
			agent, panel, inspector, _, request := newSoftwareClaimRecoveryHarness(t)
			switch name {
			case "config":
				request.ConfigRevision++
			case "ownership":
				request.OwnershipEpoch++
			case "target":
				request.TargetID = "foreign-target"
			case "root_unknown":
				inspector.reject = true
			case "foreign_lease":
				panel.wrongJob = true
			}
			if err := agent.RecoverSoftwareClaim(context.Background(), request); err == nil {
				t.Fatal("unsafe orphan recovery was accepted")
			}
			if len(panel.reports) != 0 || agent.Journal != nil && agent.Journal.Active() != nil {
				t.Fatal("rejected recovery reported or adopted a foreign cursor")
			}
			if name != "foreign_lease" && len(panel.claims) != 0 {
				t.Fatal("recovery claimed before policy and root absence proof")
			}
		})
	}
}

func TestSoftwareClaimRecoveryInspectionDoesNotWriteOrClaim(t *testing.T) {
	agent, panel, _, _, request := newSoftwareClaimRecoveryHarness(t)
	if _, err := agent.InspectSoftwareClaim(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(agent.StateDir)
	if err != nil || len(entries) != 0 || len(panel.claims) != 0 || len(panel.reports) != 0 || agent.Journal != nil {
		t.Fatal("read-only inspection changed recovery state")
	}
}
