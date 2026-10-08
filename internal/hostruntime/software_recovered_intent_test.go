package hostruntime

import (
	"strings"
	"testing"
	"time"
)

func TestRecoveredSoftwareIntentRequiresOriginalFrozenAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob, *UpdateJob)
	}{
		{"missing_original", func(a, r *UpdateJob) { a.SoftwareUpdate = nil }},
		{"missing_recovered", func(a, r *UpdateJob) { r.SoftwareUpdate = nil }},
		{"legacy_nil_pair", func(a, r *UpdateJob) { a.SoftwareUpdate, r.SoftwareUpdate = nil, nil }},
		{"wire_only_rejected", func(a, r *UpdateJob) {
			wire := SoftwareUpdateJobBinding{ConfigRevision: 1, CommandSHA256: a.SoftwareUpdate.CommandSHA256}
			a.SoftwareUpdate, r.SoftwareUpdate = &wire, &wire
			a.PolicyRevision, r.PolicyRevision, a.SoftwareClaimRejected, r.SoftwareClaimRejected = 0, 0, true, true
		}},
		{"rejected_full_pair", func(a, r *UpdateJob) { a.SoftwareClaimRejected, r.SoftwareClaimRejected = true, true }},
		{"configuration", func(a, r *UpdateJob) { a.SoftwareUpdate.ConfigRevision, r.SoftwareUpdate.ConfigRevision = 0, 0 }},
		{"command_digest", func(a, r *UpdateJob) {
			a.SoftwareUpdate.CommandSHA256, r.SoftwareUpdate.CommandSHA256 = "invalid", "invalid"
		}},
		{"source", func(a, r *UpdateJob) {
			a.SoftwareUpdate.SourcePolicyRevision, r.SoftwareUpdate.SourcePolicyRevision = 0, 0
		}},
		{"projection", func(a, r *UpdateJob) { a.SoftwareUpdate.ProjectionRevision, r.SoftwareUpdate.ProjectionRevision = 0, 0 }},
		{"executor", func(a, r *UpdateJob) {
			a.SoftwareUpdate.ExecutorPolicyRevision, r.SoftwareUpdate.ExecutorPolicyRevision = 0, 0
		}},
		{"executor_digest", func(a, r *UpdateJob) {
			a.SoftwareUpdate.ExecutorPolicySHA256, r.SoftwareUpdate.ExecutorPolicySHA256 = "invalid", "invalid"
		}},
		{"projection_alias", func(a, r *UpdateJob) {
			a.PolicyRevision, r.PolicyRevision = a.SoftwareUpdate.ConfigRevision, r.SoftwareUpdate.ConfigRevision
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			active, recovered := recoveredSoftwareIntentFixture(11, 13, 17)
			test.mutate(&active, &recovered)
			if sameRecoveredJobIntent(active, recovered) {
				t.Fatal("fresh software recovery accepted a missing, incomplete, rejected, or mixed authority")
			}
		})
	}
	for _, revisions := range []struct {
		name                         string
		source, projection, executor int64
	}{
		{"reported_revisions", 8, 8, 8},
		{"distinct_revisions", 11, 13, 17},
	} {
		t.Run(revisions.name, func(t *testing.T) {
			active, recovered := recoveredSoftwareIntentFixture(revisions.source, revisions.projection, revisions.executor)
			if !sameRecoveredJobIntent(active, recovered) {
				t.Fatal("exact frozen software authority rejected a valid fresh next-generation lease")
			}
		})
	}
}

func TestRecoveredSoftwareIntentPreservesExactNonExecutingCursor(t *testing.T) {
	for _, name := range []string{"legacy_nil", "wire_only_rejected"} {
		t.Run(name, func(t *testing.T) {
			active, _ := recoveredSoftwareIntentFixture(11, 13, 17)
			active.SoftwareUpdate, active.PolicyRevision = nil, 1
			if name == "wire_only_rejected" {
				active.SoftwareUpdate = &SoftwareUpdateJobBinding{ConfigRevision: 1, CommandSHA256: "sha256:" + strings.Repeat("c", 64)}
				active.PolicyRevision, active.SoftwareClaimRejected = 0, true
			}
			recovered := cloneV2PanelJob(active)
			if !sameRecoveredJobIntent(active, recovered) {
				t.Fatal("an unchanged saved nonexecuting cursor was rejected")
			}
			recovered.CommandID = "command-replacement"
			if sameRecoveredJobIntent(active, recovered) {
				t.Fatal("nonexecuting cursor accepted a new software command without original full authority")
			}
		})
	}
}

func TestRecoveredSoftwareIntentKeepsFreshLeaseAndImmutableFields(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{"configuration", func(r *UpdateJob) { r.SoftwareUpdate.ConfigRevision++ }},
		{"configuration_digest", func(r *UpdateJob) { r.SoftwareUpdate.ConfigSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"command_digest", func(r *UpdateJob) { r.SoftwareUpdate.CommandSHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"source", func(r *UpdateJob) { r.SoftwareUpdate.SourcePolicyRevision++ }},
		{"projection", func(r *UpdateJob) { r.SoftwareUpdate.ProjectionRevision++; r.PolicyRevision++ }},
		{"executor", func(r *UpdateJob) { r.SoftwareUpdate.ExecutorPolicyRevision++ }},
		{"executor_digest", func(r *UpdateJob) { r.SoftwareUpdate.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("a", 64) }},
		{"ownership", func(r *UpdateJob) { r.OwnershipEpoch++ }},
		{"job", func(r *UpdateJob) { r.ID = "job-other" }},
		{"target", func(r *UpdateJob) { r.TargetID = "worker-other" }},
		{"current_version", func(r *UpdateJob) { r.CurrentVersion = "v1.0.1" }},
		{"target_version", func(r *UpdateJob) { r.TargetVersion = "v1.2.0" }},
		{"same_command", func(r *UpdateJob) { r.CommandID = "command-original-software" }},
		{"stale_generation", func(r *UpdateJob) { r.LeaseGeneration-- }},
		{"generation_gap", func(r *UpdateJob) { r.LeaseGeneration++ }},
		{"not_recovery", func(r *UpdateJob) { r.RecoveryRequired = false }},
		{"invalid_expiry", func(r *UpdateJob) { r.LeaseExpiresAt = "invalid" }},
		{"same_lease_extension", func(r *UpdateJob) { r.CommandID, r.LeaseGeneration = "command-original-software", 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			active, recovered := recoveredSoftwareIntentFixture(11, 13, 17)
			test.mutate(&recovered)
			if sameRecoveredJobIntent(active, recovered) {
				t.Fatal("software recovery replaced immutable intent or reused/retimed a lease")
			}
		})
	}
}

func recoveredSoftwareIntentFixture(source, projection, executor int64) (UpdateJob, UpdateJob) {
	plan := validMutationPlan()
	active := UpdateJob{ProtocolVersion: 2, ID: plan.JobID, CommandID: "command-original-software", Operation: updateJobOperationSoftwareUpdate,
		AgentServiceID: "updater-fixture", HostID: plan.HostID, TransportMode: HostTransportPullV2, OwnershipEpoch: 3, PolicyRevision: projection,
		TargetID: plan.TargetID, TargetType: plan.ServiceType, ServiceType: plan.ServiceType, DeploymentMode: plan.DeploymentMode,
		CurrentVersion: plan.CurrentVersion, TargetVersion: plan.TargetVersion, SoftwareUpdate: softwareJournalFullBinding(plan, source, projection, executor),
		LeaseGeneration: 2, ReportSequence: 1, LeaseExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	recovered := cloneV2PanelJob(active)
	recovered.CommandID, recovered.LeaseGeneration, recovered.RecoveryRequired = "command-fresh-software", 3, true
	recovered.LeaseExpiresAt = time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339Nano)
	return active, recovered
}
