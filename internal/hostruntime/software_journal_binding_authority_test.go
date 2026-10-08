package hostruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSoftwareJournalRetainsDistinctRevisionAuthority(t *testing.T) {
	for _, test := range []struct {
		name                         string
		source, projection, executor int64
	}{
		{"shared_policy_numbers", 8, 8, 8},
		{"distinct_policy_numbers", 11, 13, 17},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, job, plan := newBoundSoftwareJournalFixture(t, test.source, test.projection, test.executor)
			reloaded, err := OpenJournal(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalPersistedAuthority(t, reloaded, job)
			if !reflect.DeepEqual(reloaded.ActivePlan(), &plan) {
				t.Fatal("journal changed the frozen configuration and policy authority")
			}
			if journal.Active().PolicyRevision == journal.Active().SoftwareUpdate.ConfigRevision {
				t.Fatal("configuration C was stored as projection P")
			}
		})
	}
}

func TestSoftwareJournalRejectsFrozenBindingReplacement(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{"configuration", func(j *UpdateJob) { j.SoftwareUpdate.ConfigRevision++ }},
		{"configuration_digest", func(j *UpdateJob) { j.SoftwareUpdate.ConfigSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"configuration_digest_removed", func(j *UpdateJob) { j.SoftwareUpdate.ConfigSHA256 = "" }},
		{"command_digest", func(j *UpdateJob) { j.SoftwareUpdate.CommandSHA256 = "sha256:" + strings.Repeat("b", 64) }},
		{"source", func(j *UpdateJob) { j.SoftwareUpdate.SourcePolicyRevision++ }},
		{"projection_field", func(j *UpdateJob) { j.SoftwareUpdate.ProjectionRevision++ }},
		{"projection_and_cursor", func(j *UpdateJob) { j.SoftwareUpdate.ProjectionRevision++; j.PolicyRevision++ }},
		{"executor", func(j *UpdateJob) { j.SoftwareUpdate.ExecutorPolicyRevision++ }},
		{"executor_digest", func(j *UpdateJob) { j.SoftwareUpdate.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64) }},
		{"binding_removed", func(j *UpdateJob) { j.SoftwareUpdate = nil }},
		{"rejected_marker", func(j *UpdateJob) { j.SoftwareClaimRejected = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, _, job, plan := newBoundSoftwareJournalFixture(t, 11, 13, 17)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			changed := cloneV2PanelJob(job)
			test.mutate(&changed)
			if err := journal.SetActive(&changed); err == nil {
				t.Fatal("frozen software authority was replaced")
			}
			assertSoftwareJournalUnchanged(t, journal, before, job, plan)
		})
	}
}

func TestSoftwareJournalRejectsInvalidPersistedAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob, *MutationPlan)
	}{
		{"configuration_as_projection", func(j *UpdateJob, _ *MutationPlan) { j.PolicyRevision = j.SoftwareUpdate.ConfigRevision }},
		{"incomplete_policy", func(j *UpdateJob, _ *MutationPlan) { j.SoftwareUpdate.ExecutorPolicyRevision = 0 }},
		{"different_plan_policy_digest", func(j *UpdateJob, _ *MutationPlan) {
			j.SoftwareUpdate.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64)
		}},
		{"wire_only_with_plan", func(j *UpdateJob, _ *MutationPlan) {
			j.SoftwareUpdate = &SoftwareUpdateJobBinding{ConfigRevision: 1, CommandSHA256: "sha256:" + strings.Repeat("c", 64)}
			j.PolicyRevision = 0
			j.SoftwareClaimRejected = true
		}},
		{"rejected_without_intent", func(j *UpdateJob, _ *MutationPlan) { j.SoftwareUpdate = nil; j.SoftwareClaimRejected = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, job, plan := newBoundSoftwareJournalFixture(t, 11, 13, 17)
			test.mutate(&job, &plan)
			payload, err := json.Marshal(journalData{ActiveJob: &job, ActivePlan: &plan, NextSeq: 1})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(journal.path, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenJournal(stateDir); err == nil {
				t.Fatal("invalid saved software authority was accepted")
			}
			after, err := os.ReadFile(journal.path)
			if err != nil || !bytes.Equal(payload, after) {
				t.Fatalf("failed authority load changed source bytes: %v", err)
			}
		})
	}
}

func TestSoftwareJournalRejectsUnknownSoftwareBindingField(t *testing.T) {
	journal, stateDir, job, plan := newBoundSoftwareJournalFixture(t, 11, 13, 17)
	payload, err := json.Marshal(journalData{ActiveJob: &job, ActivePlan: &plan, NextSeq: 1})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	document["active_job"].(map[string]any)["software_update_binding"].(map[string]any)["unexpected_policy_revision"] = 19
	payload, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journal.path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(stateDir); err == nil {
		t.Fatal("unknown software binding field was accepted")
	}
	after, err := os.ReadFile(journal.path)
	if err != nil || !bytes.Equal(payload, after) {
		t.Fatalf("unknown binding rejection changed source bytes: %v", err)
	}
}

func TestSoftwareJournalDeepCopiesFrozenBinding(t *testing.T) {
	journal, _, job, _ := newBoundSoftwareJournalFixture(t, 11, 13, 17)
	expected := cloneV2PanelJob(job)
	job.SoftwareUpdate.ConfigRevision = 91
	job.SoftwareUpdate.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64)
	if !reflect.DeepEqual(journal.Active(), &expected) {
		t.Fatal("caller mutation changed stored software authority")
	}
	returned := journal.Active()
	returned.SoftwareUpdate.ProjectionRevision = 93
	if !reflect.DeepEqual(journal.Active(), &expected) {
		t.Fatal("returned cursor mutation changed stored software authority")
	}
}

func TestSoftwareJournalWireOnlyClaimRemainsNonExecuting(t *testing.T) {
	for _, test := range []struct {
		name     string
		rejected bool
		policy   int64
		valid    bool
	}{
		{"rejected_wire_intent", true, 0, true},
		{"unrejected_wire_intent", false, 0, false},
		{"wire_intent_with_invented_projection", true, 13, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, stateDir, job, plan := newSoftwareJournalBindingFixture(t)
			if err := journal.ClearActive(); err != nil {
				t.Fatal(err)
			}
			job.SoftwareUpdate = &SoftwareUpdateJobBinding{ConfigRevision: 1, CommandSHA256: "sha256:" + strings.Repeat("c", 64)}
			job.SoftwareClaimRejected, job.PolicyRevision = test.rejected, test.policy
			err := journal.SetActive(&job)
			if !test.valid {
				if err == nil {
					t.Fatal("wire-only cursor received invented executable authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.SetActivePlan(plan); err == nil {
				t.Fatal("rejected wire-only cursor obtained an execution plan")
			}
			reloaded, err := OpenJournal(stateDir)
			if err != nil || reloaded.ActivePlan() != nil {
				t.Fatalf("nonexecuting original wire intent was lost: %v", err)
			}
			assertSoftwareJournalPersistedAuthority(t, reloaded, job)
			promoted := cloneV2PanelJob(job)
			promoted.SoftwareUpdate = softwareJournalFullBinding(plan, 11, 13, 17)
			promoted.PolicyRevision, promoted.SoftwareClaimRejected = 13, false
			if err := journal.SetActive(&promoted); err == nil {
				t.Fatal("latest policy silently promoted rejected old wire intent")
			}
		})
	}
}

func TestSoftwareJournalRejectsFirstPlanWithDifferentPolicyDigest(t *testing.T) {
	journal, _, job, plan := newBoundSoftwareJournalFixture(t, 11, 13, 17)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	plan.ConfigSHA256 = "sha256:" + strings.Repeat("e", 64)
	var err error
	plan.PlanSHA256, err = plan.ComputePlanSHA256()
	if err != nil || plan.Validate() != nil {
		t.Fatalf("invalid policy-digest fixture: %v", err)
	}
	if err := journal.SetActivePlan(plan); err == nil || journal.ActivePlan() != nil {
		t.Fatal("first execution plan did not use its frozen executor policy digest")
	}
}

func newBoundSoftwareJournalFixture(t *testing.T, source, projection, executor int64) (*Journal, string, UpdateJob, MutationPlan) {
	t.Helper()
	journal, stateDir, job, plan := newSoftwareJournalBindingFixture(t)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	job.SoftwareUpdate = softwareJournalFullBinding(plan, source, projection, executor)
	job.PolicyRevision = projection
	if err := journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	return journal, stateDir, job, plan
}

func softwareJournalFullBinding(plan MutationPlan, source, projection, executor int64) *SoftwareUpdateJobBinding {
	return &SoftwareUpdateJobBinding{
		ConfigRevision: 1, ConfigSHA256: "sha256:" + strings.Repeat("d", 64), CommandSHA256: "sha256:" + strings.Repeat("c", 64),
		SourcePolicyRevision: source, ProjectionRevision: projection, ExecutorPolicyRevision: executor, ExecutorPolicySHA256: plan.ConfigSHA256,
	}
}
