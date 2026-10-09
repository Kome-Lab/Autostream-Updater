//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newSoftwareClaimRecoveryRootHarness(t *testing.T) (*manualHostUpgradeLinuxFixture, LocalExecutorPolicy, LocalExecutorRequest, softwareClaimRecoveryRootRuntime) {
	t.Helper()
	fixture := newManualHostUpgradeLinuxFixture(t)
	policy, err := LoadLocalExecutorPolicy(fixture.policyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	policy.SourcePolicyRevision, policy.ProjectionRevision, policy.PolicyRevision = 8, 8, 8
	policy.Targets[0].ConfigRevision = 1
	policy.Targets[0].ConfigSHA256 = "sha256:" + strings.Repeat("e", 64)
	digest, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxMkdir(t, fixture.runtime.paths.hostStateRoot, 0o700)
	fixture.runtime.selfUpdate.executorVersion = manualHostUpgradeTestOldVersion
	state, err := NewHostSelfUpdateState(manualHostUpgradeTestOldVersion, manualHostUpgradeTestOldVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.selfUpdate.saveState(state); err != nil {
		t.Fatal(err)
	}
	request := SoftwareClaimRecoveryRequest{JobID: "orphan-job-one", LeaseGeneration: 1, TargetID: policy.Targets[0].ServiceID, CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ConfigRevision: 1, OwnershipEpoch: 3}
	authenticated := HostAgentPolicy{ServiceID: "host-agent-a", TransportMode: HostTransportPullV2, ExecutionHostID: policy.HostID, OwnershipEpoch: 3,
		Revision: 8, SourcePolicyRevision: 8, LocalExecutorPolicyRevision: 8, LocalExecutorPolicySHA256: digest,
		Targets: []HostAgentPolicyTarget{{ServiceID: request.TargetID, ServiceType: policy.Targets[0].ServiceType, DeploymentMode: ModeSystemd, AppliedConfigRevision: 1, AppliedConfigSHA256: policy.Targets[0].ConfigSHA256}}}
	runtime := softwareClaimRecoveryRootRuntime{manual: fixture.runtime, acquireLifecycle: func() (func(), error) { return func() {}, nil },
		readPolicy: func(context.Context, LocalExecutorPolicy) (HostAgentPolicy, error) { return authenticated, nil }}
	local := LocalExecutorRequest{Version: 2, Operation: localExecutorSoftwareClaimRecoveryOperation, ServiceID: request.TargetID,
		SoftwareClaimRecovery: &SoftwareClaimRecoveryInspection{Request: request, ExecutorPolicySHA256: digest}, SourcePolicyRevision: 8, OwnershipEpoch: 3, OwnershipPolicyRevision: 8, ExecutorPolicyRevision: 8}
	return fixture, policy, local, runtime
}

func writeSoftwareClaimRecoveryRootJSON(t *testing.T, path string, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxMkdir(t, filepath.Dir(path), 0o700)
	manualHostUpgradeLinuxWriteFile(t, path, append(payload, '\n'), 0o600)
}

func TestSoftwareClaimRecoveryRootProofIsReadOnlyAndKeepsUnrelatedTerminalHistory(t *testing.T) {
	fixture, policy, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
	checkpoint := updateCheckpoint{SchemaVersion: 1, JobID: "unrelated-terminal-job", TargetID: "worker-01", DeploymentMode: ModeSystemd, Phase: "succeeded", TargetVersion: "v2.0.0"}
	path := filepath.Join(fixture.runtime.paths.localExecutorStateRoot, ".autostream-updater-terminal.checkpoint.json")
	writeSoftwareClaimRecoveryRootJSON(t, path, checkpoint)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := inspectSoftwareClaimRecoveryRoot(context.Background(), policy, request, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Validate() != nil || !proof.NoMutation || proof.SourcePolicyRevision != 8 || proof.ProjectionRevision != 8 || proof.ExecutorPolicyRevision != 8 || proof.OwnershipEpoch != 3 {
		t.Fatal("root absence proof lost independent fences")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("root inspection changed unrelated terminal history")
	}
	if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
		t.Fatal("read-only root proof changed a service")
	}
}

func TestSoftwareClaimRecoveryRootRefusesRequestedTerminalAndAmbiguousState(t *testing.T) {
	softwareClaimRecoveryDiagnosticChecks(t)
	for _, name := range []string{"requested_terminal_checkpoint", "requested_terminal_ledger", "other_active_checkpoint", "unsafe_journal", "unknown_journal_field", "clear_fence", "runtime_claim", "staged_identity", "orphan_stage", "pending_report", "unmarked_active", "policy_fence", "ownership_fence", "mixed_runtime"} {
		t.Run(name, func(t *testing.T) {
			fixture, policy, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
			root := fixture.runtime.paths.localExecutorStateRoot
			switch name {
			case "requested_terminal_checkpoint", "other_active_checkpoint":
				job, phase := request.SoftwareClaimRecovery.Request.JobID, "succeeded"
				if name == "other_active_checkpoint" {
					job, phase = "other-job", "installing"
				}
				writeSoftwareClaimRecoveryRootJSON(t, filepath.Join(root, ".autostream-updater-unsafe.checkpoint.json"), updateCheckpoint{SchemaVersion: 1, JobID: job, TargetID: request.ServiceID, DeploymentMode: ModeSystemd, Phase: phase, TargetVersion: "v2.0.1"})
			case "requested_terminal_ledger":
				ledger := executorMutationLedger{SchemaVersion: 1, JobID: request.SoftwareClaimRecovery.Request.JobID, TargetID: request.ServiceID, PlanSHA256: strings.Repeat("a", 64), SessionID: "session-0123456789abcdef", LeaseGeneration: 1, Operation: "reconcile", State: remoteLedgerTerminal,
					Intent: remoteMutationIntent{HostID: policy.HostID, TargetID: request.ServiceID, ServiceType: "worker", DeploymentMode: ModeSystemd, CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ConfigSHA256: "sha256:" + strings.Repeat("d", 64), ArtifactDigest: "sha256:" + strings.Repeat("c", 64)},
					Stage:  &remoteStage{RootDir: filepath.Join(root, "stages", "terminal"), ArtifactDigest: "sha256:" + strings.Repeat("c", 64)}, Result: &ApplyResult{Status: "succeeded"}}
				if ledger.validate(ledger.TargetID) != nil {
					t.Fatal("terminal ledger negative fixture is invalid")
				}
				writeSoftwareClaimRecoveryRootJSON(t, filepath.Join(root, "ledger", "target-"+remoteStableKey(ledger.TargetID)+".json"), ledger)
			case "unsafe_journal":
				path := filepath.Join(fixture.runtime.paths.hostStateRoot, "journal.json")
				writeSoftwareClaimRecoveryRootJSON(t, path, journalData{NextSeq: 1})
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "unknown_journal_field":
				manualHostUpgradeLinuxWriteFile(t, filepath.Join(fixture.runtime.paths.hostStateRoot, "journal.json"), []byte(`{"next_sequence":1,"unknown_authority":true}`), 0o600)
			case "clear_fence":
				writeSoftwareClaimRecoveryRootJSON(t, filepath.Join(fixture.runtime.paths.hostStateRoot, journalActiveClearMarkerName), map[string]bool{"must_remain": true})
			case "runtime_claim":
				writeSoftwareClaimRecoveryRootJSON(t, filepath.Join(fixture.runtime.paths.hostStateRoot, runtimeTokenClaimStateFileName), map[string]bool{"must_remain": true})
			case "staged_identity":
				manualHostUpgradeLinuxWriteFile(t, fixture.runtime.paths.stagedIdentityPath, []byte("protected staged identity\n"), 0o600)
			case "orphan_stage":
				manualHostUpgradeLinuxMkdir(t, filepath.Join(root, "stages", "unconfirmed"), 0o700)
			case "pending_report":
				writeSoftwareClaimRecoveryRootJSON(t, filepath.Join(fixture.runtime.paths.hostStateRoot, "journal.json"), journalData{NextSeq: 2, Pending: []PendingReport{{JobID: "other-job", Report: JobReport{ServiceID: "host-agent-a", Status: "claimed", Sequence: 1}}}})
			case "unmarked_active":
				writeSoftwareClaimRecoveryRootJSON(t, filepath.Join(fixture.runtime.paths.hostStateRoot, "journal.json"), journalData{NextSeq: 1, ActiveJob: &UpdateJob{ID: "other-job", TargetID: request.ServiceID, ServiceType: "worker", DeploymentMode: ModeSystemd, TargetVersion: "v2.0.1"}})
			case "policy_fence":
				request.OwnershipPolicyRevision = 9
			case "ownership_fence":
				request.OwnershipEpoch = 4
				request.SoftwareClaimRecovery.Request.OwnershipEpoch = 4
			case "mixed_runtime":
				runtime.manual.selfUpdate.executorVersion = manualHostUpgradeTestTargetVersion
			}
			if _, err := inspectSoftwareClaimRecoveryRoot(context.Background(), policy, request, runtime); err == nil {
				t.Fatal("unsafe root absence was accepted")
			}
			if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
				t.Fatal("refused root inspection changed a service")
			}
		})
	}
}

func TestSoftwareClaimRecoveryIntentBlocksInstallerUntilAuthenticatedSettlement(t *testing.T) {
	fixture, policy, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
	auth, err := runtime.readPolicy(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	intent := newSoftwareClaimRecoveryIntent(request.SoftwareClaimRecovery.Request, auth.ServiceID, auth.ExecutionHostID, auth)
	// Preserve legacy settled-marker compatibility. Schema 2 settlement needs
	// the actual authenticated clear receipt, exercised by the history tests.
	intent.SchemaVersion = 1
	intent.Attempts = []softwareClaimRecoveryAttempt{{LeaseGeneration: 1, StartedAt: manualHostUpgradeTestActivationNow}}
	if err := saveSoftwareClaimRecoveryIntent(fixture.runtime.paths.hostStateRoot, "", intent); err != nil {
		t.Fatal(err)
	}
	if err := rejectManualHostUpgradeSoftwareClaimRecovery(fixture.runtime, policy); err == nil {
		t.Fatal("installer accepted an unsettled recovery intent")
	}
	if _, err := inspectSoftwareClaimRecoveryRoot(context.Background(), policy, request, runtime); err != nil {
		t.Fatal(err)
	}
	previous := softwareClaimRecoveryIntentSHA256(intent)
	intent.Settled = true
	intent.SettledAt = manualHostUpgradeTestActivationNow
	if err := saveSoftwareClaimRecoveryIntent(fixture.runtime.paths.hostStateRoot, previous, intent); err != nil {
		t.Fatal(err)
	}
	if err := rejectManualHostUpgradeSoftwareClaimRecovery(fixture.runtime, policy); err != nil {
		t.Fatal("installer did not permit an authenticated settled intent")
	}
}

func TestSoftwareClaimRecoveryRootPreflightAcceptsOnlyExactNonexecutingCursorWithoutMarker(t *testing.T) {
	for _, kind := range []string{"legacy", "rejected_wire", "full_binding", "full_binding_first_progress_pending"} {
		t.Run(kind, func(t *testing.T) {
			fixture, policy, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
			r := request.SoftwareClaimRecovery.Request
			job := UpdateJob{ProtocolVersion: 2, ID: r.JobID, Operation: updateJobOperationSoftwareUpdate, AgentServiceID: "host-agent-a",
				HostID: policy.HostID, TransportMode: HostTransportPullV2, OwnershipEpoch: 3, TargetID: r.TargetID,
				TargetType: "worker", ServiceType: "worker", DeploymentMode: ModeSystemd, CurrentVersion: r.CurrentVersion, TargetVersion: r.TargetVersion,
				LeaseGeneration: 1, CommandID: "original-claimed-command", LeaseExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), PolicyRevision: 1}
			if kind != "legacy" {
				job.SoftwareUpdate = &SoftwareUpdateJobBinding{ConfigRevision: 1, CommandSHA256: "sha256:" + strings.Repeat("c", 64)}
				job.SoftwareClaimRejected, job.PolicyRevision = true, 0
				if kind == "full_binding" || kind == "full_binding_first_progress_pending" {
					job.SoftwareClaimRejected, job.PolicyRevision = false, 8
					job.SoftwareUpdate.SourcePolicyRevision, job.SoftwareUpdate.ProjectionRevision, job.SoftwareUpdate.ExecutorPolicyRevision = 8, 8, 8
					job.SoftwareUpdate.ConfigSHA256, job.SoftwareUpdate.ExecutorPolicySHA256 = policy.Targets[0].ConfigSHA256, request.SoftwareClaimRecovery.ExecutorPolicySHA256
				}
			}
			path := filepath.Join(fixture.runtime.paths.hostStateRoot, "journal.json")
			data := journalData{NextSeq: 1, ActiveJob: &job}
			if kind == "full_binding_first_progress_pending" {
				job.Status = "claimed"
				data.NextSeq = 2
				data.Pending = []PendingReport{{JobID: job.ID, Report: JobReport{ServiceID: job.AgentServiceID, LeaseGeneration: 1,
					Sequence: 1, Status: "claimed", Progress: 5, Message: "update job claimed and fixed target validated"}}}
			}
			writeSoftwareClaimRecoveryRootJSON(t, path, data)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := inspectSoftwareClaimRecoveryRoot(context.Background(), policy, request, runtime); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) {
				t.Fatal("read-only preflight rewrote the original cursor")
			}
			if _, err := os.Lstat(filepath.Join(fixture.runtime.paths.hostStateRoot, softwareClaimRecoveryIntentName)); !os.IsNotExist(err) {
				t.Fatal("read-only preflight created a mutation-blocking marker")
			}
		})
	}
}
