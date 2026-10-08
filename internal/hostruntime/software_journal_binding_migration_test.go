package hostruntime

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSoftwareJournalRebindsOnlyFreshLeaseAndRetainsOriginalPlan(t *testing.T) {
	journal, stateDir, original, plan := newBoundSoftwareJournalFixture(t, 11, 13, 17)
	recovered := softwareJournalFreshRecovery(original)
	if err := journal.SetActive(&recovered); err != nil {
		t.Fatalf("valid fresh software lease was rejected: %v", err)
	}
	if !reflect.DeepEqual(journal.ActivePlan(), &plan) {
		t.Fatal("fresh claim rewrote the immutable saved plan")
	}
	// A crash between cursor persistence and plan-generation rebinding must
	// preserve the original session/artifact/D and remain recoverable.
	reloaded, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatalf("cursor/plan rebind crash state cannot reload: %v", err)
	}
	assertSoftwareJournalPersistedAuthority(t, reloaded, recovered)
	if !reflect.DeepEqual(reloaded.ActivePlan(), &plan) {
		t.Fatal("rebind crash state lost its original authority")
	}
	rebound := plan
	rebound.LeaseGeneration = recovered.LeaseGeneration
	rebound.PlanSHA256, err = rebound.ComputePlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if rebound.PlanSHA256 == plan.PlanSHA256 {
		t.Fatal("lease generation did not change the canonical plan hash")
	}
	if err := reloaded.SetActivePlan(rebound); err != nil {
		t.Fatalf("validated lease could not rebind its saved plan: %v", err)
	}
	if !reflect.DeepEqual(reloaded.ActivePlan(), &rebound) {
		t.Fatal("plan recovery changed more than its lease generation and hash")
	}
}

func TestSoftwareJournalMigratesLegacyOnlyWithTrustedOriginalPlan(t *testing.T) {
	journal, stateDir, old, plan := newLegacySoftwareMigrationFixture(t, 1, true)
	recovered := softwareJournalFreshRecovery(old)
	recovered.SoftwareUpdate = softwareJournalFullBinding(plan, 11, 13, 17)
	recovered.PolicyRevision = 13
	if err := journal.SetActive(&recovered); err != nil {
		t.Fatalf("trusted prebinding plan could not migrate: %v", err)
	}
	if !reflect.DeepEqual(journal.Active(), &recovered) || !reflect.DeepEqual(journal.ActivePlan(), &plan) {
		t.Fatal("legacy migration changed the old session, artifact, policy digest or plan hash")
	}
	reloaded, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatalf("legacy migration crash state did not retain original authority: %v", err)
	}
	assertSoftwareJournalPersistedAuthority(t, reloaded, recovered)
	if !reflect.DeepEqual(reloaded.ActivePlan(), &plan) {
		t.Fatal("legacy migration crash state did not retain original plan authority")
	}
	rebound := plan
	rebound.LeaseGeneration = recovered.LeaseGeneration
	rebound.PlanSHA256, err = rebound.ComputePlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.SetActivePlan(rebound); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reloaded.ActivePlan(), &rebound) {
		t.Fatal("migrated plan was not rebound to its validated lease")
	}
}

func TestSoftwareJournalRejectsUntrustedLegacyMigration(t *testing.T) {
	for _, test := range []struct {
		name      string
		oldPolicy int64
		savedPlan bool
		mutate    func(*UpdateJob)
	}{
		{"no_original_plan", 1, false, func(*UpdateJob) {}},
		{"old_revision_already_projection", 13, true, func(*UpdateJob) {}},
		{"old_configuration_mismatch", 1, true, func(j *UpdateJob) { j.SoftwareUpdate.ConfigRevision = 2 }},
		{"latest_executor_digest", 1, true, func(j *UpdateJob) { j.SoftwareUpdate.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64) }},
		{"target", 1, true, func(j *UpdateJob) { j.TargetID = "worker-other" }},
		{"host", 1, true, func(j *UpdateJob) { j.HostID = "host-other" }},
		{"updater", 1, true, func(j *UpdateJob) { j.AgentServiceID = "updater-other" }},
		{"epoch", 1, true, func(j *UpdateJob) { j.OwnershipEpoch++ }},
		{"current_version", 1, true, func(j *UpdateJob) { j.CurrentVersion = "v1.0.1" }},
		{"target_version", 1, true, func(j *UpdateJob) { j.TargetVersion = "v1.2.0" }},
		{"deployment_mode", 1, true, func(j *UpdateJob) { j.DeploymentMode = ModeDocker }},
		{"unchanged_command", 1, true, func(j *UpdateJob) { j.CommandID = "command-software-journal" }},
		{"generation_jump", 1, true, func(j *UpdateJob) { j.LeaseGeneration++ }},
		{"same_generation", 1, true, func(j *UpdateJob) { j.LeaseGeneration-- }},
		{"missing_recovery_marker", 1, true, func(j *UpdateJob) { j.RecoveryRequired = false }},
		{"nonexecuting_marker_change", 1, true, func(j *UpdateJob) { j.SoftwareClaimRejected = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, _, old, plan := newLegacySoftwareMigrationFixture(t, test.oldPolicy, test.savedPlan)
			before, err := os.ReadFile(journal.path)
			if err != nil {
				t.Fatal(err)
			}
			recovered := softwareJournalFreshRecovery(old)
			recovered.SoftwareUpdate = softwareJournalFullBinding(plan, 11, 13, 17)
			recovered.PolicyRevision = 13
			test.mutate(&recovered)
			if err := journal.SetActive(&recovered); err == nil {
				t.Fatal("old command was reapproved without its original trusted authority")
			}
			if test.savedPlan {
				assertSoftwareJournalUnchanged(t, journal, before, old, plan)
			} else {
				after, err := os.ReadFile(journal.path)
				if err != nil || string(before) != string(after) || !reflect.DeepEqual(journal.Active(), &old) || journal.ActivePlan() != nil {
					t.Fatalf("failed planless migration changed the retained cursor: %v", err)
				}
			}
		})
	}
}

func newLegacySoftwareMigrationFixture(t *testing.T, oldPolicy int64, savedPlan bool) (*Journal, string, UpdateJob, MutationPlan) {
	t.Helper()
	journal, stateDir, job, plan := newSoftwareJournalBindingFixture(t)
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	job.PolicyRevision = oldPolicy
	if err := journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	if savedPlan {
		if err := journal.SetActivePlan(plan); err != nil {
			t.Fatal(err)
		}
	}
	return journal, stateDir, job, plan
}

func softwareJournalFreshRecovery(job UpdateJob) UpdateJob {
	recovered := cloneV2PanelJob(job)
	recovered.RecoveryRequired = true
	recovered.LeaseGeneration++
	recovered.CommandID = "command-software-recovery"
	recovered.LeaseExpiresAt = time.Date(2026, time.October, 8, 14, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	return recovered
}
