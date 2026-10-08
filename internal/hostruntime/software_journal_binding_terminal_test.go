package hostruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSoftwareJournalTerminalRecoveryAllowsOnlyMarkedLostReplyGap(t *testing.T) {
	journal, stateDir, old, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
	if old.LeaseGeneration != 2 || request.LeaseGeneration != 3 || fresh.LeaseGeneration != 4 {
		t.Fatal("lost response fixture does not retain the stale local cursor and exact operator reread")
	}
	if err := journal.SetActive(&fresh); err == nil {
		t.Fatal("normal recovery accepted a lease-generation gap")
	}
	markerPath := filepath.Join(stateDir, softwareClaimRecoveryIntentName)
	markerBefore, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := journal.data
	expectedJob := cloneV2PanelJob(fresh)
	expected.ActiveJob, expected.NextSeq = &expectedJob, fresh.ReportSequence
	if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
		t.Fatalf("marked terminal-only lost-response recovery was rejected: %v", err)
	}
	if !reflect.DeepEqual(journal.data, expected) {
		t.Fatal("terminal recovery changed journal state beyond active lease cursor and sequence")
	}
	markerAfter, err := os.ReadFile(markerPath)
	if err != nil || !bytes.Equal(markerBefore, markerAfter) {
		t.Fatalf("terminal cursor binding rewrote original recovery attempts: %v", err)
	}
	fresh.SoftwareUpdate.SourcePolicyRevision = 91
	if !reflect.DeepEqual(journal.Active(), &expectedJob) {
		t.Fatal("terminal cursor retained caller-owned binding memory")
	}
}

func TestSoftwareJournalTerminalRecoverySupportsExactLegacyConfigurationCursor(t *testing.T) {
	journal, _, old, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, true)
	if old.SoftwareUpdate != nil || old.PolicyRevision != request.ConfigRevision {
		t.Fatal("legacy cursor fixture already has policy binding")
	}
	if err := journal.SetActive(&fresh); err == nil {
		t.Fatal("ordinary recovery accepted a planless legacy policy upgrade")
	}
	if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(journal.Active(), &fresh) || journal.ActivePlan() != nil || journal.ActivePortPlan() != nil || len(journal.Pending()) != 0 {
		t.Fatal("terminal-only legacy recovery created execution state")
	}
}

func TestSoftwareJournalTerminalRecoveryRequiresNoExistingCursorOrExactRetainedCursor(t *testing.T) {
	journal, _, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
		t.Fatalf("exact marked initial terminal claim was rejected: %v", err)
	}
	if !reflect.DeepEqual(journal.Active(), &fresh) {
		t.Fatal("initial terminal-only cursor differs from the fresh CP lease")
	}
}

func TestSoftwareJournalTerminalRecoveryAcceptsExactRejectedWireIntent(t *testing.T) {
	journal, stateDir, fresh, request, proof := newSoftwareJournalTerminalWireFixture(t)
	markerPath := filepath.Join(stateDir, softwareClaimRecoveryIntentName)
	before, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActive(&fresh); err == nil {
		t.Fatal("normal recovery promoted a rejected wire intent")
	}
	if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
		t.Fatalf("exact rejected wire intent could not settle terminal-only: %v", err)
	}
	if !reflect.DeepEqual(journal.Active(), &fresh) || journal.ActivePlan() != nil {
		t.Fatal("rejected wire recovery produced different or executable state")
	}
	after, err := os.ReadFile(markerPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected wire recovery rewrote its explicit recovery history: %v", err)
	}
}

func TestSoftwareJournalTerminalRecoveryAcceptsExactRejectedFullSnapshot(t *testing.T) {
	journal, _, old, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	old.SoftwareClaimRejected = true
	if err := journal.SetActive(&old); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(journal.Active(), &fresh) {
		t.Fatal("rejected snapshot recovery changed the frozen software authority")
	}
}

func TestSoftwareJournalTerminalRecoveryIsIdempotentForSameFreshCursor(t *testing.T) {
	journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
	if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	markerBefore, err := os.ReadFile(filepath.Join(stateDir, softwareClaimRecoveryIntentName))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err != nil {
		t.Fatalf("Resume could not bind the same fresh terminal cursor: %v", err)
	}
	after, err := os.ReadFile(journal.path)
	markerAfter, markerErr := os.ReadFile(filepath.Join(stateDir, softwareClaimRecoveryIntentName))
	if err != nil || markerErr != nil || !bytes.Equal(before, after) || !bytes.Equal(markerBefore, markerAfter) || !reflect.DeepEqual(journal.Active(), &fresh) {
		t.Fatal("same fresh terminal cursor was rewritten or lost")
	}
}

func TestSoftwareJournalTerminalRecoveryRejectsChangedRejectedWireIntent(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{"configuration", func(j *UpdateJob) { j.SoftwareUpdate.ConfigRevision++ }},
		{"command_digest", func(j *UpdateJob) { j.SoftwareUpdate.CommandSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"saved_configuration_digest", func(j *UpdateJob) { j.SoftwareUpdate.ConfigSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"foreign_job", func(j *UpdateJob) { j.ID = "job-other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, fresh, request, proof := newSoftwareJournalTerminalWireFixture(t)
			test.mutate(journal.data.ActiveJob)
			if err := journal.saveLocked(); err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
		})
	}
}

func TestSoftwareJournalTerminalRecoveryRejectsChangedRootProof(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*SoftwareClaimRecoveryProof)
	}{
		{"mutation_not_absent", func(p *SoftwareClaimRecoveryProof) { p.NoMutation = false }},
		{"request_digest", func(p *SoftwareClaimRecoveryProof) { p.RequestSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"updater", func(p *SoftwareClaimRecoveryProof) { p.UpdaterID = "updater-other" }},
		{"host", func(p *SoftwareClaimRecoveryProof) { p.HostID = "host-other" }},
		{"source", func(p *SoftwareClaimRecoveryProof) { p.SourcePolicyRevision++ }},
		{"projection", func(p *SoftwareClaimRecoveryProof) { p.ProjectionRevision++ }},
		{"executor", func(p *SoftwareClaimRecoveryProof) { p.ExecutorPolicyRevision++ }},
		{"policy_digest", func(p *SoftwareClaimRecoveryProof) { p.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64) }},
		{"epoch", func(p *SoftwareClaimRecoveryProof) { p.OwnershipEpoch++ }},
		{"invalid_runtime", func(p *SoftwareClaimRecoveryProof) { p.RuntimeVersion = "invalid" }},
		{"unobserved", func(p *SoftwareClaimRecoveryProof) { p.ObservedAt = time.Time{} }},
		{"stale", func(p *SoftwareClaimRecoveryProof) {
			p.ObservedAt = time.Now().UTC().Add(-localExecutorClientTimeout - time.Second)
		}},
		{"future", func(p *SoftwareClaimRecoveryProof) { p.ObservedAt = time.Now().UTC().Add(time.Hour) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
			test.mutate(&proof)
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
		})
	}
}

func TestSoftwareJournalTerminalRecoveryRejectsChangedFreshLease(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{"other_job", func(j *UpdateJob) { j.ID = "job-other" }},
		{"other_target", func(j *UpdateJob) { j.TargetID = "worker-other" }},
		{"current_version", func(j *UpdateJob) { j.CurrentVersion = "v1.0.1" }},
		{"target_version", func(j *UpdateJob) { j.TargetVersion = "v1.2.0" }},
		{"target_type", func(j *UpdateJob) { j.TargetType = "observability" }},
		{"service_type", func(j *UpdateJob) { j.ServiceType = "observability" }},
		{"deployment_mode", func(j *UpdateJob) { j.DeploymentMode = ModeDocker }},
		{"configuration", func(j *UpdateJob) { j.SoftwareUpdate.ConfigRevision++ }},
		{"saved_command_digest", func(j *UpdateJob) { j.SoftwareUpdate.CommandSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"saved_configuration_digest", func(j *UpdateJob) { j.SoftwareUpdate.ConfigSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"binding_removed", func(j *UpdateJob) { j.SoftwareUpdate = nil }},
		{"wrong_generation", func(j *UpdateJob) { j.LeaseGeneration-- }},
		{"not_recovery", func(j *UpdateJob) { j.RecoveryRequired = false }},
		{"terminal_clear", func(j *UpdateJob) { j.RecoveryClear = true }},
		{"missing_report_sequence", func(j *UpdateJob) { j.ReportSequence = 0 }},
		{"old_command", func(j *UpdateJob) { j.CommandID = "command-software-journal" }},
		{"expired_lease", func(j *UpdateJob) { j.LeaseExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano) }},
		{"rejected_wire_marker", func(j *UpdateJob) { j.SoftwareClaimRejected = true }},
		{"lease_credential", func(j *UpdateJob) { j.LeaseToken = "synthetic-credential" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, _, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
			test.mutate(&fresh)
			assertSoftwareJournalTerminalRejected(t, journal, stateDir, fresh, request, proof)
		})
	}
}

func newSoftwareJournalTerminalFixture(t *testing.T, legacy bool) (*Journal, string, UpdateJob, UpdateJob, SoftwareClaimRecoveryRequest, SoftwareClaimRecoveryProof, softwareClaimRecoveryIntent) {
	t.Helper()
	journal, stateDir, old, plan := newBoundSoftwareJournalFixture(t, 11, 13, 17)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	if legacy {
		old.SoftwareUpdate, old.PolicyRevision = nil, 1
	}
	if err := journal.SetActive(&old); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkDeployed("previous-target", "v0.9.0"); err != nil {
		t.Fatal(err)
	}
	original := SoftwareClaimRecoveryRequest{JobID: old.ID, LeaseGeneration: 1, TargetID: old.TargetID,
		CurrentVersion: old.CurrentVersion, TargetVersion: old.EffectiveVersion(), ConfigRevision: 1, OwnershipEpoch: old.OwnershipEpoch}
	request := original
	request.LeaseGeneration = 3
	policy := HostAgentPolicy{ServiceID: old.AgentServiceID, ExecutionHostID: old.HostID, OwnershipEpoch: old.OwnershipEpoch,
		SourcePolicyRevision: 11, Revision: 13, LocalExecutorPolicyRevision: 17, LocalExecutorPolicySHA256: plan.ConfigSHA256}
	intent := newSoftwareClaimRecoveryIntent(original, old.AgentServiceID, old.HostID, policy)
	intent.Request = request
	for generation := uint64(1); generation <= request.LeaseGeneration; generation++ {
		intent.Attempts = append(intent.Attempts, softwareClaimRecoveryAttempt{LeaseGeneration: generation, StartedAt: time.Now().UTC()})
	}
	if err := saveSoftwareClaimRecoveryIntent(stateDir, "", intent); err != nil {
		t.Fatal(err)
	}
	fresh := cloneV2PanelJob(old)
	fresh.SoftwareUpdate, fresh.PolicyRevision = softwareJournalFullBinding(plan, 11, 13, 17), 13
	fresh.LeaseGeneration, fresh.RecoveryRequired, fresh.CommandID = 4, true, "command-terminal-four"
	fresh.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	proof := SoftwareClaimRecoveryProof{RequestSHA256: request.sha256(), UpdaterID: fresh.AgentServiceID, HostID: fresh.HostID,
		SourcePolicyRevision: 11, ProjectionRevision: 13, ExecutorPolicyRevision: 17, ExecutorPolicySHA256: plan.ConfigSHA256,
		OwnershipEpoch: fresh.OwnershipEpoch, RuntimeVersion: "v2.0.0", NoMutation: true, ObservedAt: time.Now().UTC()}
	return journal, stateDir, old, fresh, request, proof, intent
}

func assertSoftwareJournalTerminalRejected(t *testing.T, journal *Journal, stateDir string, fresh UpdateJob, request SoftwareClaimRecoveryRequest, proof SoftwareClaimRecoveryProof) {
	t.Helper()
	before, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(journal.data)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(stateDir, softwareClaimRecoveryIntentName)
	markerBefore, markerErr := os.ReadFile(markerPath)
	if markerErr != nil && !os.IsNotExist(markerErr) {
		t.Fatal(markerErr)
	}
	if err := journal.SetTerminalSoftwareClaimRecovery(fresh, request, proof); err == nil {
		t.Fatal("unsafe terminal software cursor replacement was accepted")
	}
	after, err := os.ReadFile(journal.path)
	actual, encodeErr := json.Marshal(journal.data)
	if err != nil || encodeErr != nil || !bytes.Equal(before, after) || !bytes.Equal(expected, actual) {
		t.Fatalf("rejected terminal recovery changed journal state: read=%v encode=%v", err, encodeErr)
	}
	markerAfter, afterErr := os.ReadFile(markerPath)
	if (markerErr == nil) != (afterErr == nil) || !bytes.Equal(markerBefore, markerAfter) {
		t.Fatal("rejected terminal recovery changed marker history")
	}
}

func newSoftwareJournalTerminalWireFixture(t *testing.T) (*Journal, string, UpdateJob, SoftwareClaimRecoveryRequest, SoftwareClaimRecoveryProof) {
	t.Helper()
	journal, stateDir, old, fresh, request, proof, _ := newSoftwareJournalTerminalFixture(t, false)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	old.SoftwareUpdate = &SoftwareUpdateJobBinding{ConfigRevision: old.SoftwareUpdate.ConfigRevision, CommandSHA256: old.SoftwareUpdate.CommandSHA256}
	old.PolicyRevision, old.SoftwareClaimRejected = 0, true
	if err := journal.SetActive(&old); err != nil {
		t.Fatal(err)
	}
	return journal, stateDir, fresh, request, proof
}
