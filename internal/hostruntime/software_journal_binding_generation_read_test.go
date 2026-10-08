package hostruntime

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSoftwareJournalGenerationReadAdoptsGapWithOriginalTrustedPlan(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "bound"
		if legacy {
			name = "trusted_legacy"
		}
		t.Run(name, func(t *testing.T) {
			journal, stateDir, old, fresh, plan := newSoftwareJournalAdoptionFixture(t, legacy)
			request := softwareJournalGenerationReadRequest(old, 3)
			fresh.LeaseGeneration = 4
			if err := journal.AdoptRecoveredSoftwareClaim(fresh); err == nil {
				t.Fatal("ordinary adoption accepted an operator-only generation gap")
			}
			expected := journal.data
			copy := cloneV2PanelJob(fresh)
			expected.ActiveJob, expected.NextSeq, expected.Pending = &copy, fresh.ReportSequence, nil
			renames := 0
			journal.renameFile = func(source, destination string) error { renames++; return os.Rename(source, destination) }
			if err := journal.AdoptRecoveredSoftwareClaimAfterGenerationRead(fresh, request); err != nil {
				t.Fatal(err)
			}
			if renames != 1 || !reflect.DeepEqual(journal.data, expected) || !reflect.DeepEqual(journal.ActivePlan(), &plan) {
				t.Fatal("explicit generation read changed original plan/session/artifact/D or split pending handoff")
			}
			reloaded, err := OpenJournal(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalPersistedAuthority(t, reloaded, fresh)
			if !reflect.DeepEqual(reloaded.ActivePlan(), &plan) {
				t.Fatal("generation-read crash state lost the original trusted plan")
			}
		})
	}
}

func TestSoftwareJournalGenerationReadRejectsChangedRequestOrAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Journal, *UpdateJob, *SoftwareClaimRecoveryRequest)
	}{
		{"no_original_plan", func(j *Journal, _ *UpdateJob, _ *SoftwareClaimRecoveryRequest) { j.data.ActivePlan = nil }},
		{"wrong_configuration", func(_ *Journal, _ *UpdateJob, r *SoftwareClaimRecoveryRequest) { r.ConfigRevision++ }},
		{"wrong_policy_digest", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) {
			j.SoftwareUpdate.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64)
		}},
		{"source", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) {
			j.SoftwareUpdate.SourcePolicyRevision++
		}},
		{"projection", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) {
			j.SoftwareUpdate.ProjectionRevision++
			j.PolicyRevision++
		}},
		{"executor", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) {
			j.SoftwareUpdate.ExecutorPolicyRevision++
		}},
		{"command_digest", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) {
			j.SoftwareUpdate.CommandSHA256 = "sha256:" + strings.Repeat("a", 64)
		}},
		{"foreign_job", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) { j.ID = "job-other" }},
		{"other_target", func(_ *Journal, _ *UpdateJob, r *SoftwareClaimRecoveryRequest) { r.TargetID = "worker-other" }},
		{"versions", func(_ *Journal, _ *UpdateJob, r *SoftwareClaimRecoveryRequest) { r.TargetVersion = "v1.2.0" }},
		{"epoch", func(_ *Journal, _ *UpdateJob, r *SoftwareClaimRecoveryRequest) { r.OwnershipEpoch++ }},
		{"old_request_generation", func(_ *Journal, j *UpdateJob, r *SoftwareClaimRecoveryRequest) {
			r.LeaseGeneration = 1
			j.LeaseGeneration = 2
		}},
		{"wrong_fresh_generation", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) { j.LeaseGeneration++ }},
		{"same_command", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) {
			j.CommandID = "command-software-journal"
		}},
		{"invalid_expiry", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) { j.LeaseExpiresAt = "invalid" }},
		{"no_recovery", func(_ *Journal, j *UpdateJob, _ *SoftwareClaimRecoveryRequest) { j.RecoveryRequired = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, _, old, fresh, _ := newSoftwareJournalAdoptionFixture(t, false)
			request := softwareJournalGenerationReadRequest(old, 3)
			fresh.LeaseGeneration = 4
			test.mutate(journal, &fresh, &request)
			if err := journal.saveLocked(); err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalAdoptionRejected(t, journal, func() error { return journal.AdoptRecoveredSoftwareClaimAfterGenerationRead(fresh, request) })
		})
	}
}

func TestSoftwareJournalGenerationReadRejectsUntrustedLegacyPlan(t *testing.T) {
	for _, name := range []string{"configuration", "policy_digest", "missing_plan", "pending_foreign_job"} {
		t.Run(name, func(t *testing.T) {
			journal, _, old, fresh, _ := newSoftwareJournalAdoptionFixture(t, true)
			request := softwareJournalGenerationReadRequest(old, 3)
			fresh.LeaseGeneration = 4
			switch name {
			case "configuration":
				journal.data.ActiveJob.PolicyRevision = 13
			case "policy_digest":
				fresh.SoftwareUpdate.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("e", 64)
			case "missing_plan":
				journal.data.ActivePlan = nil
			case "pending_foreign_job":
				journal.data.Pending[0].JobID = "job-other"
			}
			if err := journal.saveLocked(); err != nil {
				t.Fatal(err)
			}
			assertSoftwareJournalAdoptionRejected(t, journal, func() error { return journal.AdoptRecoveredSoftwareClaimAfterGenerationRead(fresh, request) })
		})
	}
}

func TestSoftwareJournalGenerationReadRejectsUnsettledTerminalIntent(t *testing.T) {
	journal, stateDir, old, fresh, plan := newSoftwareJournalAdoptionFixture(t, false)
	request := softwareJournalGenerationReadRequest(old, 3)
	fresh.LeaseGeneration = 4
	original := softwareJournalGenerationReadRequest(old, old.LeaseGeneration)
	policy := HostAgentPolicy{ServiceID: old.AgentServiceID, ExecutionHostID: old.HostID, OwnershipEpoch: old.OwnershipEpoch,
		SourcePolicyRevision: 11, Revision: 13, LocalExecutorPolicyRevision: 17, LocalExecutorPolicySHA256: plan.ConfigSHA256}
	intent := newSoftwareClaimRecoveryIntent(original, old.AgentServiceID, old.HostID, policy)
	intent.Request = request
	intent.Attempts = []softwareClaimRecoveryAttempt{{LeaseGeneration: old.LeaseGeneration, StartedAt: time.Now().UTC()}, {LeaseGeneration: request.LeaseGeneration, StartedAt: time.Now().UTC()}}
	if err := saveSoftwareClaimRecoveryIntent(stateDir, "", intent); err != nil {
		t.Fatal(err)
	}
	assertSoftwareJournalAdoptionRejected(t, journal, func() error { return journal.AdoptRecoveredSoftwareClaimAfterGenerationRead(fresh, request) })
}

func softwareJournalGenerationReadRequest(old UpdateJob, generation uint64) SoftwareClaimRecoveryRequest {
	config := old.PolicyRevision
	if old.SoftwareUpdate != nil {
		config = old.SoftwareUpdate.ConfigRevision
	}
	return SoftwareClaimRecoveryRequest{JobID: old.ID, LeaseGeneration: generation, TargetID: old.TargetID,
		CurrentVersion: old.CurrentVersion, TargetVersion: old.EffectiveVersion(), ConfigRevision: config, OwnershipEpoch: old.OwnershipEpoch}
}
