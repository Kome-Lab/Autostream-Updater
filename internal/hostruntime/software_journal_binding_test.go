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

func TestSoftwareJournalRejectsActiveIntentReplacement(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{"command", func(j *UpdateJob) { j.CommandID = "command-software-other" }},
		{"target", func(j *UpdateJob) { j.TargetID = "worker-other" }},
		{"service_type", func(j *UpdateJob) { j.ServiceType = "observability" }},
		{"target_type", func(j *UpdateJob) { j.TargetType = "observability" }},
		{"updater", func(j *UpdateJob) { j.AgentServiceID = "updater-other" }},
		{"host", func(j *UpdateJob) { j.HostID = "host-other" }},
		{"epoch", func(j *UpdateJob) { j.OwnershipEpoch++ }},
		{"policy", func(j *UpdateJob) { j.PolicyRevision++ }},
		{"deployment_mode", func(j *UpdateJob) { j.DeploymentMode = ModeDocker }},
		{"current_version", func(j *UpdateJob) { j.CurrentVersion = "v1.0.1" }},
		{"target_version", func(j *UpdateJob) { j.TargetVersion = "v1.2.0" }},
		{"lease_generation_jump", func(j *UpdateJob) { j.LeaseGeneration += 2 }},
		{"operation", func(j *UpdateJob) { j.Operation = updateJobOperationBootstrap }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, _, job, plan := newSoftwareJournalBindingFixture(t)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			replacement := job
			test.mutate(&replacement)
			if err := journal.SetActive(&replacement); err == nil {
				t.Fatal("active software intent was replaced")
			}
			assertSoftwareJournalUnchanged(t, journal, before, job, plan)
		})
	}
}

func TestSoftwareJournalRejectsAnotherActiveCursor(t *testing.T) {
	journal, _, job, plan := newSoftwareJournalBindingFixture(t)
	before, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := job
	replacement.ID = "job-other"
	replacement.CommandID = "command-other"
	if err := journal.SetActive(&replacement); err == nil {
		t.Fatal("another cursor displaced the active software job and its plan")
	}
	assertSoftwareJournalUnchanged(t, journal, before, job, plan)
}

func TestSoftwareJournalRejectsSavedPlanReplacement(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*MutationPlan)
	}{
		{"target", func(p *MutationPlan) { p.TargetID = "worker-other" }},
		{"host", func(p *MutationPlan) { p.HostID = "host-other" }},
		{"service_type", func(p *MutationPlan) { p.ServiceType = "observability" }},
		{"current_version", func(p *MutationPlan) { p.CurrentVersion = "v1.0.1" }},
		{"target_version", func(p *MutationPlan) { p.TargetVersion, p.ExpectedVersion = "v1.2.0", "v1.2.0" }},
		{"artifact", func(p *MutationPlan) { p.ArtifactDigest = strings.Repeat("b", 64) }},
		{"policy_digest", func(p *MutationPlan) { p.ConfigSHA256 = "sha256:" + strings.Repeat("c", 64) }},
		{"session", func(p *MutationPlan) { p.SessionID = "session-software-other" }},
		{"generation_advance_without_claim", func(p *MutationPlan) { p.LeaseGeneration++ }},
		{"generation_regression", func(p *MutationPlan) { p.LeaseGeneration-- }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, _, job, plan := newSoftwareJournalBindingFixture(t)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			replacement := plan
			test.mutate(&replacement)
			replacement.PlanSHA256, err = replacement.ComputePlanSHA256()
			if err != nil || replacement.Validate() != nil {
				t.Fatalf("negative fixture must be a valid immutable plan: %v", err)
			}
			if err := journal.SetActivePlan(replacement); err == nil {
				t.Fatal("saved software plan was replaced")
			}
			assertSoftwareJournalUnchanged(t, journal, before, job, plan)
		})
	}
}

func TestSoftwareJournalRejectsMismatchedLoadedPlanIntent(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*MutationPlan)
	}{
		{"target", func(p *MutationPlan) { p.TargetID = "worker-other" }},
		{"host", func(p *MutationPlan) { p.HostID = "host-other" }},
		{"service_type", func(p *MutationPlan) { p.ServiceType = "observability" }},
		{"current_version", func(p *MutationPlan) { p.CurrentVersion = "v1.0.1" }},
		{"target_version", func(p *MutationPlan) { p.TargetVersion, p.ExpectedVersion = "v1.2.0", "v1.2.0" }},
		{"generation_after_cursor", func(p *MutationPlan) { p.LeaseGeneration++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, job, plan := newSoftwareJournalBindingFixture(t)
			test.mutate(&plan)
			var err error
			plan.PlanSHA256, err = plan.ComputePlanSHA256()
			if err != nil || plan.Validate() != nil {
				t.Fatalf("negative fixture must be a valid immutable plan: %v", err)
			}
			data := journalData{ActiveJob: &job, ActivePlan: &plan, NextSeq: 1, DeployedVersions: map[string]string{}}
			payload, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(journal.path, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenJournal(stateDir); err == nil {
				t.Fatal("persisted software plan was accepted for a different cursor intent")
			}
			after, err := os.ReadFile(journal.path)
			if err != nil || !bytes.Equal(payload, after) {
				t.Fatalf("failed journal load changed its source bytes: %v", err)
			}
		})
	}
}

func TestSoftwareJournalPreservesLegacyPrebindingCursorAndPlan(t *testing.T) {
	journal, stateDir, job, plan := newSoftwareJournalBindingFixture(t)
	before, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatalf("legacy prebinding journal was rejected: %v", err)
	}
	after, err := os.ReadFile(journal.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("loading the old cursor rewrote its authority: %v", err)
	}
	if active := reloaded.Active(); active == nil || active.ID != job.ID || active.CommandID != job.CommandID || active.PolicyRevision != job.PolicyRevision {
		t.Fatalf("legacy cursor changed during loading: %+v", active)
	}
	if actual := reloaded.ActivePlan(); !reflect.DeepEqual(actual, &plan) {
		t.Fatalf("legacy plan or hash changed during loading: %+v", actual)
	}
}

func TestSoftwareJournalAllowsNewCursorAfterDurableClear(t *testing.T) {
	journal, _, job, plan := newSoftwareJournalBindingFixture(t)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	job.ID = "job-after-clear"
	job.CommandID = "command-after-clear"
	if err := journal.SetActive(&job); err != nil {
		t.Fatalf("durably cleared cursor blocked a new job: %v", err)
	}
	plan.JobID = job.ID
	var err error
	plan.PlanSHA256, err = plan.ComputePlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActivePlan(plan); err != nil {
		t.Fatalf("new cursor could not retain its own immutable plan: %v", err)
	}
}

func newSoftwareJournalBindingFixture(t *testing.T) (*Journal, string, UpdateJob, MutationPlan) {
	t.Helper()
	stateDir := t.TempDir()
	journal, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	plan := validMutationPlan()
	plan.JobID = "job-software-journal"
	plan.PlanSHA256, err = plan.ComputePlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	job := UpdateJob{
		ProtocolVersion: 2, ID: plan.JobID, CommandID: "command-software-journal",
		Operation: updateJobOperationSoftwareUpdate, AgentServiceID: "updater-fixture",
		HostID: plan.HostID, TransportMode: HostTransportPullV2, OwnershipEpoch: 3, PolicyRevision: 8,
		TargetID: plan.TargetID, TargetType: plan.ServiceType, ServiceType: plan.ServiceType,
		DeploymentMode: plan.DeploymentMode, CurrentVersion: plan.CurrentVersion, TargetVersion: plan.TargetVersion,
		LeaseGeneration: plan.LeaseGeneration, ReportSequence: 1,
		LeaseExpiresAt: time.Date(2026, time.October, 8, 13, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	if err := journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	return journal, stateDir, job, plan
}

func assertSoftwareJournalUnchanged(t *testing.T, journal *Journal, before []byte, job UpdateJob, plan MutationPlan) {
	t.Helper()
	after, err := os.ReadFile(filepath.Join(filepath.Dir(journal.path), "journal.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected replacement changed durable state: %v", err)
	}
	if !reflect.DeepEqual(journal.Active(), &job) || !reflect.DeepEqual(journal.ActivePlan(), &plan) {
		t.Fatal("rejected replacement changed in-memory cursor or plan")
	}
}

func assertSoftwareJournalPersistedAuthority(t *testing.T, journal *Journal, job UpdateJob) {
	t.Helper()
	active := journal.Active()
	if active == nil || active.ReportSequence != 0 {
		t.Fatal("ephemeral claim report sequence was unexpectedly persisted")
	}
	if job.ReportSequence == 0 || journal.data.NextSeq != job.ReportSequence {
		t.Fatalf("durable report cursor differs from the fresh claim: got=%d expected=%d", journal.data.NextSeq, job.ReportSequence)
	}
	persisted := cloneV2PanelJob(job)
	persisted.ReportSequence = 0
	if !reflect.DeepEqual(active, &persisted) {
		t.Fatal("persisted software identity or C/S/P/E/D authority changed during restart")
	}
}
