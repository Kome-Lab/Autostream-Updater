package hostruntime

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

func validateJournalSoftwareJob(job UpdateJob) error {
	if job.SoftwareUpdate == nil {
		if job.SoftwareClaimRejected || (isV2SoftwareJob(job) && job.PolicyRevision < 1) {
			return errors.New("update journal software claim lacks its saved intent")
		}
		return nil // Retain prebinding journals without inventing policy authority.
	}
	if !isV2SoftwareJob(job) || job.SoftwareUpdate.validateIntent() != nil {
		return errors.New("update journal software claim binding is invalid")
	}
	if job.SoftwareUpdate.Validate() == nil {
		if job.PolicyRevision != job.SoftwareUpdate.ProjectionRevision {
			return errors.New("update journal software projection revision is invalid")
		}
	} else if !job.SoftwareClaimRejected || job.PolicyRevision != 0 {
		return errors.New("update journal unbound software claim must remain rejected")
	}
	return nil
}

func validateJournalSoftwarePlan(job UpdateJob, plan MutationPlan, currentLease bool) error {
	if !isV2SoftwareJob(job) {
		return nil
	}
	if job.SoftwareClaimRejected || plan.JobID != job.ID || plan.HostID != job.HostID ||
		plan.TargetID != job.TargetID || plan.ServiceType != job.EffectiveType() ||
		plan.DeploymentMode != job.DeploymentMode || plan.CurrentVersion != job.CurrentVersion ||
		plan.TargetVersion != job.EffectiveVersion() || plan.LeaseGeneration > job.LeaseGeneration ||
		(currentLease && plan.LeaseGeneration != job.LeaseGeneration) ||
		(job.SoftwareUpdate != nil && plan.ConfigSHA256 != job.SoftwareUpdate.ExecutorPolicySHA256) {
		return errors.New("update journal software plan does not match its saved authority")
	}
	return nil
}

func journalLegacySoftwareBindingMatches(active, recovered UpdateJob, plan *MutationPlan) bool {
	return active.SoftwareUpdate == nil && recovered.SoftwareUpdate != nil && recovered.SoftwareUpdate.Validate() == nil &&
		active.PolicyRevision == recovered.SoftwareUpdate.ConfigRevision &&
		active.SoftwareClaimRejected == recovered.SoftwareClaimRejected &&
		active.LeaseGeneration != recovered.LeaseGeneration && sameRecoveredJobLease(active, recovered) &&
		sameSoftwareJobIdentity(active, recovered) && plan != nil && plan.Validate() == nil &&
		validateJournalSoftwarePlan(active, *plan, false) == nil &&
		plan.ConfigSHA256 == recovered.SoftwareUpdate.ExecutorPolicySHA256
}

func sameJournalSoftwarePlanIntent(left, right MutationPlan) bool {
	left.LeaseGeneration, right.LeaseGeneration = 0, 0
	left.PlanSHA256, right.PlanSHA256 = "", ""
	return left == right
}

// Restart never reconstructs authority from the current policy. Only an exact
// frozen software cursor, or its original legacy plan, can retain old reports.
func validateJournalSoftwarePendingForRestart(data journalData) error {
	active := data.ActiveJob
	if active == nil || !isV2SoftwareJob(*active) || active.SoftwareClaimRejected ||
		active.TransportMode != HostTransportPullV2 || active.OwnershipEpoch < 1 || active.LeaseGeneration == 0 ||
		!identifierPattern.MatchString(active.ID) || !identifierPattern.MatchString(active.CommandID) ||
		!identifierPattern.MatchString(active.AgentServiceID) || !validExecutionHostID(active.HostID) ||
		!identifierPattern.MatchString(active.TargetID) || active.LeaseToken != "" || !active.ReleaseToken.Empty() ||
		data.ActivePortPlan != nil || data.ActivePortPolicy != nil {
		return errors.New("update journal software pending cursor is ambiguous")
	}
	if active.SoftwareUpdate != nil {
		if active.SoftwareUpdate.Validate() != nil || validateJournalSoftwareJob(*active) != nil {
			return errors.New("update journal software pending authority is incomplete")
		}
	} else if active.PolicyRevision < 1 || data.ActivePlan == nil || data.ActivePlan.Validate() != nil ||
		validateJournalSoftwarePlan(*active, *data.ActivePlan, false) != nil {
		return errors.New("update journal legacy software pending lacks its original plan")
	}
	var previous uint64
	for _, pending := range data.Pending {
		report := pending.Report
		_, progressStatus := v2ProgressPhase(report.Status)
		if pending.JobID != active.ID || report.LeaseGeneration != active.LeaseGeneration || report.ServiceID != active.AgentServiceID ||
			report.Sequence == 0 || report.Sequence <= previous || report.Sequence >= data.NextSeq ||
			report.LeaseToken != "" || report.PortReconfigure != nil ||
			(!progressStatus && !isTerminalUpdateStatus(report.Status)) || report.Progress < 0 || report.Progress > 100 ||
			(report.ArtifactDigest != "" && canonicalReportDigest(report.ArtifactDigest) == "") ||
			(report.PreviousDigest != "" && canonicalReportDigest(report.PreviousDigest) == "") {
			return errors.New("update journal software pending report does not match its saved cursor")
		}
		previous = report.Sequence
	}
	return nil
}

// SetTerminalSoftwareClaimRecovery is only for the recovery Agent after an
// authenticated fresh CP lease and root absence inspection, while holding the
// recovery lifecycle lock. The fixed durable marker forbids software mutation;
// this method never supplies apply authority or relaxes normal SetActive.
func (j *Journal) SetTerminalSoftwareClaimRecovery(job UpdateJob, request SoftwareClaimRecoveryRequest, proof SoftwareClaimRecoveryProof) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	now := time.Now().UTC()
	expires, expiryErr := time.Parse(time.RFC3339Nano, job.LeaseExpiresAt)
	if request.Validate() != nil || proof.Validate() != nil || !proof.NoMutation || proof.RequestSHA256 != request.sha256() ||
		proof.ObservedAt.After(now.Add(time.Second)) || now.Sub(proof.ObservedAt) > localExecutorClientTimeout ||
		!isV2SoftwareJob(job) || job.validateOperationUnion() != nil || validateJournalSoftwareJob(job) != nil ||
		job.SoftwareUpdate == nil || job.SoftwareUpdate.Validate() != nil || job.SoftwareClaimRejected ||
		job.ID != request.JobID || job.TargetID != request.TargetID || job.CurrentVersion != request.CurrentVersion ||
		job.EffectiveVersion() != request.TargetVersion || job.SoftwareUpdate.ConfigRevision != request.ConfigRevision ||
		job.OwnershipEpoch != request.OwnershipEpoch ||
		!job.RecoveryRequired || job.RecoveryClear || job.LeaseGeneration != request.LeaseGeneration+1 ||
		job.ReportSequence == 0 || !identifierPattern.MatchString(job.CommandID) ||
		job.LeaseToken != "" || !job.ReleaseToken.Empty() || expiryErr != nil || !expires.After(now) ||
		job.AgentServiceID != proof.UpdaterID || job.HostID != proof.HostID || job.OwnershipEpoch != proof.OwnershipEpoch ||
		job.SoftwareUpdate.SourcePolicyRevision != proof.SourcePolicyRevision ||
		job.SoftwareUpdate.ProjectionRevision != proof.ProjectionRevision ||
		job.SoftwareUpdate.ExecutorPolicyRevision != proof.ExecutorPolicyRevision ||
		job.SoftwareUpdate.ExecutorPolicySHA256 != proof.ExecutorPolicySHA256 {
		return errors.New("terminal software recovery lease or root absence proof is invalid")
	}
	if validateJournalData(j.data) != nil || j.data.ActivePlan != nil || j.data.ActivePortPlan != nil ||
		j.data.ActivePortPolicy != nil || j.data.ActiveStageFailure != nil || !softwareClaimRecoveryPendingAllowed(j.data) {
		return errors.New("terminal software recovery cannot replace execution or pending report state")
	}
	stateDir := filepath.Dir(j.path)
	if validateManagedDirectoryChain(stateDir) != nil {
		return errors.New("terminal software recovery state directory is unsafe")
	}
	intent, exists, err := loadSoftwareClaimRecoveryIntent(stateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || intent.Settled || intent.Request != request || !softwareClaimRecoveryJobMatches(intent, job) {
		return errors.New("terminal software recovery durable request compare-and-swap failed")
	}
	if active := j.data.ActiveJob; active != nil {
		if !sameSoftwareJobIdentity(*active, job) || active.LeaseGeneration == 0 ||
			!identifierPattern.MatchString(active.CommandID) || active.LeaseToken != "" || !active.ReleaseToken.Empty() {
			return errors.New("terminal software recovery cannot replace another retained cursor")
		}
		if active.SoftwareUpdate != nil {
			if active.SoftwareUpdate.Validate() == nil {
				if *active.SoftwareUpdate != *job.SoftwareUpdate || active.PolicyRevision != job.PolicyRevision {
					return errors.New("terminal software recovery cannot replace saved software authority")
				}
			} else if !active.SoftwareClaimRejected || active.PolicyRevision != 0 || active.SoftwareUpdate.validateIntent() != nil ||
				active.SoftwareUpdate.ConfigRevision != job.SoftwareUpdate.ConfigRevision ||
				active.SoftwareUpdate.CommandSHA256 != job.SoftwareUpdate.CommandSHA256 ||
				(active.SoftwareUpdate.ConfigSHA256 != "" && active.SoftwareUpdate.ConfigSHA256 != job.SoftwareUpdate.ConfigSHA256) {
				return errors.New("terminal software recovery cannot replace saved software authority")
			}
		} else if active.PolicyRevision != request.ConfigRevision {
			return errors.New("terminal software recovery legacy cursor does not retain its original configuration revision")
		}
		if active.LeaseGeneration == job.LeaseGeneration && active.CommandID == job.CommandID &&
			active.LeaseExpiresAt == job.LeaseExpiresAt && !active.SoftwareClaimRejected && active.SoftwareUpdate != nil &&
			*active.SoftwareUpdate == *job.SoftwareUpdate && active.PolicyRevision == job.PolicyRevision {
			return nil // The same fresh terminal-only cursor is already durable.
		}
		if active.LeaseGeneration > request.LeaseGeneration || active.CommandID == job.CommandID {
			return errors.New("terminal software recovery requires the exact supplied fresh lease")
		}
	}
	return j.saveSoftwareRecoveryAdoptionLocked(job)
}

// AdoptRecoveredSoftwareClaim commits a validated ordinary recovery lease and
// invalidates only its old lease's pending reports in the same atomic save.
// The saved plan/session/artifact/policy authority remains available to rebind.
func (j *Journal) AdoptRecoveredSoftwareClaim(job UpdateJob) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	active := j.data.ActiveJob
	if active == nil || !isV2SoftwareJob(*active) || !isV2SoftwareJob(job) ||
		job.SoftwareUpdate == nil || job.SoftwareUpdate.Validate() != nil ||
		active.SoftwareClaimRejected || job.SoftwareClaimRejected || job.RecoveryClear || !job.RecoveryRequired ||
		job.validateOperationUnion() != nil || validateJournalSoftwareJob(job) != nil ||
		(!sameRecoveredJobIntent(*active, job) && !journalLegacySoftwareBindingMatches(*active, job, j.data.ActivePlan)) ||
		job.LeaseGeneration != active.LeaseGeneration+1 ||
		active.CommandID == job.CommandID || job.ReportSequence == 0 ||
		active.LeaseToken != "" || !active.ReleaseToken.Empty() || job.LeaseToken != "" || !job.ReleaseToken.Empty() ||
		validateJournalData(j.data) != nil || j.data.ActivePortPlan != nil || j.data.ActivePortPolicy != nil {
		return errors.New("recovered software claim does not match the saved ordinary lease and authority")
	}
	if j.data.ActivePlan != nil {
		if err := validateJournalSoftwarePlan(job, *j.data.ActivePlan, false); err != nil {
			return err
		}
	}
	return j.saveSoftwareRecoveryAdoptionLocked(job)
}

// AdoptRecoveredSoftwareClaimAfterGenerationRead is the explicit same-job
// reconciliation entry after an operator rereads the central lease generation.
// The original trusted plan and frozen authority are required for every gap.
func (j *Journal) AdoptRecoveredSoftwareClaimAfterGenerationRead(job UpdateJob, request SoftwareClaimRecoveryRequest) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	active, plan := j.data.ActiveJob, j.data.ActivePlan
	if request.Validate() != nil || active == nil || plan == nil || plan.Validate() != nil ||
		!sameSoftwareJobIdentity(*active, job) || active.SoftwareClaimRejected || job.SoftwareClaimRejected ||
		job.SoftwareUpdate == nil || job.SoftwareUpdate.Validate() != nil ||
		job.validateOperationUnion() != nil || validateJournalSoftwareJob(job) != nil ||
		active.LeaseGeneration == 0 || request.LeaseGeneration < active.LeaseGeneration ||
		job.LeaseGeneration != request.LeaseGeneration+1 || !job.RecoveryRequired || job.RecoveryClear || job.ReportSequence == 0 ||
		active.CommandID == job.CommandID || !identifierPattern.MatchString(active.CommandID) || !identifierPattern.MatchString(job.CommandID) ||
		active.LeaseToken != "" || !active.ReleaseToken.Empty() || job.LeaseToken != "" || !job.ReleaseToken.Empty() ||
		job.ID != request.JobID || job.TargetID != request.TargetID || job.CurrentVersion != request.CurrentVersion ||
		job.EffectiveVersion() != request.TargetVersion || job.SoftwareUpdate.ConfigRevision != request.ConfigRevision ||
		job.OwnershipEpoch != request.OwnershipEpoch || validateJournalData(j.data) != nil ||
		j.data.ActivePortPlan != nil || j.data.ActivePortPolicy != nil ||
		validateJournalSoftwarePlan(job, *plan, false) != nil {
		return errors.New("explicit software reconciliation does not match its original trusted plan and exact generation request")
	}
	if active.SoftwareUpdate != nil {
		if active.SoftwareUpdate.Validate() != nil || *active.SoftwareUpdate != *job.SoftwareUpdate || active.PolicyRevision != job.PolicyRevision {
			return errors.New("explicit software reconciliation cannot replace frozen policy authority")
		}
	} else if active.PolicyRevision != request.ConfigRevision || plan.ConfigSHA256 != job.SoftwareUpdate.ExecutorPolicySHA256 {
		return errors.New("explicit software reconciliation legacy cursor lacks its original trusted policy plan")
	}
	oldExpiry, oldErr := time.Parse(time.RFC3339Nano, active.LeaseExpiresAt)
	freshExpiry, freshErr := time.Parse(time.RFC3339Nano, job.LeaseExpiresAt)
	if oldErr != nil || freshErr != nil || oldExpiry.IsZero() || freshExpiry.IsZero() {
		return errors.New("explicit software reconciliation lease expiry binding is invalid")
	}
	stateDir := filepath.Dir(j.path)
	if validateManagedDirectoryChain(stateDir) != nil {
		return errors.New("explicit software reconciliation state directory is unsafe")
	}
	intent, exists, err := loadSoftwareClaimRecoveryIntent(stateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || (exists && !intent.Settled) {
		return errors.New("explicit software reconciliation cannot replace a terminal-only recovery intent")
	}
	return j.saveSoftwareRecoveryAdoptionLocked(job)
}

func (j *Journal) saveSoftwareRecoveryAdoptionLocked(job UpdateJob) error {
	active := j.data.ActiveJob
	for _, pending := range j.data.Pending {
		if pending.JobID != active.ID || pending.Report.LeaseGeneration != active.LeaseGeneration ||
			pending.Report.ServiceID != active.AgentServiceID || pending.Report.Sequence == 0 ||
			pending.Report.LeaseToken != "" || pending.Report.PortReconfigure != nil {
			return errors.New("recovered software claim cannot discard unrelated pending reports")
		}
	}
	copy := cloneV2PanelJob(job)
	next := j.data
	next.ActiveJob = &copy
	next.NextSeq = job.ReportSequence
	next.Pending = nil
	if err := j.saveDataLocked(next); err != nil {
		return j.poisonLocked(fmt.Errorf("persist recovered software lease and pending report handoff: %w", err))
	}
	for _, pending := range j.data.Pending {
		delete(j.leaseTokens, pendingLeaseKey(pending.JobID, pending.Report.Sequence))
	}
	j.data = next
	return nil
}
