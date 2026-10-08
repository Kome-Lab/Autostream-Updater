package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

// RecoverSoftwarePlanAfterGenerationRead is the explicit recovery entry when
// CP advanced a same-job recovery lease but the response was lost. The caller
// supplies the generation reread from that exact central job. The original
// saved plan remains the only software intent; this entry can only reconcile.
func (a *HostPullAgent) RecoverSoftwarePlanAfterGenerationRead(ctx context.Context, request SoftwareClaimRecoveryRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if a == nil || a.Executor == nil || a.executionRunning.Load() || a.rotationRunning.Load() {
		return errors.New("saved software plan recovery dependencies are unavailable or busy")
	}
	unlock, err := a.lockSoftwareClaimRecoveryLifecycle(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	binding, policy, err := a.softwareClaimRecoveryPolicy(ctx, request)
	if err != nil {
		return err
	}
	panel, ok := a.ControlPlane.(HostPullExecutionControlPlane)
	if !ok {
		return errors.New("saved software plan recovery control plane is unavailable")
	}
	if marker, exists, err := loadSoftwareClaimRecoveryIntent(a.StateDir, managedSnapshotOwnedByCurrentUser); err != nil || exists && !marker.Settled {
		return errors.New("terminal-only software claim intent blocks saved-plan reconciliation")
	}
	// OpenJournal deliberately scrubs old pending reports. This strict reader
	// leaves the original bytes and reports intact until a fresh authenticated
	// lease or exact terminal proof authorizes their transition.
	journal, err := readSoftwarePlanRecoveryJournal(a.StateDir)
	if err != nil {
		return err
	}
	active, plan := journal.Active(), journal.ActivePlan()
	if err := validateSoftwarePlanRecoveryOriginal(request, binding, policy, active, plan); err != nil {
		return err
	}
	if a.Journal != nil && a.Journal.Err() != nil {
		return errors.New("saved software plan recovery journal requires restart")
	}
	a.Journal = journal
	if err := a.validateRuntimeForClaim(ctx, binding, policy); err != nil {
		return err
	}
	job, clear, err := panel.ClaimHost(ctx, HostPullClaimRequest{UpdaterID: a.Bootstrap.NodeID, HostID: binding.ExecutionHostID,
		ActiveJobID: request.JobID, LeaseGeneration: int64(request.LeaseGeneration), Fence: request.OwnershipEpoch})
	if err != nil {
		return softwarePlanRecoveryGenerationRereadError()
	}
	if clear {
		if job == nil || validateV2RecoveryClear(*active, *job, a.Bootstrap.NodeID) != nil {
			return errors.New("saved software plan recovery clear does not prove the exact retained job")
		}
		if err := a.Journal.DropJobReports(active.ID); err != nil {
			return err
		}
		if err := cleanupJobDirectory(a.StateDir, active.ID); err != nil {
			return errors.New("clean authenticated terminal software recovery job state")
		}
		return a.Journal.ClearActive()
	}
	if job == nil || !isV2SoftwareJob(*job) || !job.RecoveryRequired || job.RecoveryClear ||
		job.ID != request.JobID || job.LeaseGeneration != request.LeaseGeneration+1 {
		return softwarePlanRecoveryGenerationRereadError()
	}
	// This comparison cursor is never persisted. Its generation represents the
	// exact operator reread, allowing the normal binder to validate CP's next
	// lease while still fixing the original plan and policy authority.
	comparison := cloneV2PanelJob(*active)
	comparison.LeaseGeneration = request.LeaseGeneration
	if err := a.bindSoftwareClaim(panel, binding, policy, &comparison, job); err != nil {
		return err
	}
	if err := validateHostPullClaim(*job, a.Bootstrap.NodeID, binding, policy); err != nil {
		return err
	}
	if !sameSoftwareJobIdentity(*active, *job) || job.SoftwareClaimRejected ||
		job.SoftwareUpdate == nil || job.SoftwareUpdate.ConfigRevision != request.ConfigRevision {
		return errors.New("fresh software recovery lease changed the retained original intent")
	}
	if err := a.Journal.AdoptRecoveredSoftwareClaimAfterGenerationRead(*job, request); err != nil {
		return err
	}
	// RecoveryRequired was authenticated above. The existing branch rebinds
	// only the saved plan's lease, issues a reconcile grant, and accepts the
	// executor's durable result; it never downloads, stages, or applies.
	return a.processExecutionJob(ctx, panel, binding, policy, *job)
}

func softwarePlanRecoveryGenerationRereadError() error {
	return errors.New("saved software recovery claim outcome is uncertain; reread only this job's current lease generation and supply that exact value to recover-software-plan; the original cursor and plan remain")
}

func validateSoftwarePlanRecoveryOriginal(request SoftwareClaimRecoveryRequest, binding HostAgentBinding, policy HostAgentPolicy, active *UpdateJob, plan *MutationPlan) error {
	if active == nil || plan == nil || !isV2SoftwareJob(*active) || active.SoftwareClaimRejected ||
		active.validateOperationUnion() != nil || !softwareClaimIdentityMatches(*active, policy.ServiceID, binding, policy) ||
		active.ID != request.JobID || active.TargetID != request.TargetID || active.CurrentVersion != request.CurrentVersion || active.EffectiveVersion() != request.TargetVersion ||
		active.OwnershipEpoch != request.OwnershipEpoch || active.LeaseGeneration < 1 || active.LeaseGeneration >= math.MaxInt64 || request.LeaseGeneration < active.LeaseGeneration ||
		!identifierPattern.MatchString(active.CommandID) || active.LeaseToken != "" || !active.ReleaseToken.Empty() ||
		plan.Validate() != nil || validateJournalSoftwarePlan(*active, *plan, false) != nil || plan.ConfigSHA256 != policy.LocalExecutorPolicySHA256 {
		return errors.New("saved software recovery request does not match its original trusted cursor and plan")
	}
	if expires, err := time.Parse(time.RFC3339Nano, active.LeaseExpiresAt); err != nil || expires.IsZero() {
		return errors.New("saved software recovery original lease metadata is invalid")
	}
	target, _ := hostPullPolicyTarget(policy, request.TargetID)
	if active.SoftwareUpdate != nil {
		if !softwareClaimPolicyMatches(*active, policy, target) || active.SoftwareUpdate.ConfigRevision != request.ConfigRevision {
			return errors.New("saved software recovery authority differs from the authenticated policy")
		}
	} else if active.PolicyRevision != request.ConfigRevision {
		return errors.New("saved legacy software recovery cursor lacks its original configuration revision")
	}
	return nil
}

func readSoftwarePlanRecoveryJournal(stateDir string) (*Journal, error) {
	if validateManagedDirectoryChain(stateDir) != nil {
		return nil, errors.New("saved software recovery journal parent is unsafe")
	}
	for _, name := range []string{journalActiveClearMarkerName, journalActiveClearMarkerName + ".tmp"} {
		if _, err := os.Lstat(filepath.Join(stateDir, name)); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("saved software recovery journal has an unresolved clear fence")
		}
	}
	path := filepath.Join(stateDir, "journal.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		(snapshotModeEnforced() && info.Mode().Perm() != 0o600) || !managedSnapshotOwnedByCurrentUser(info) || info.Size() <= 0 || info.Size() > 4<<20 {
		return nil, errors.New("saved software recovery journal is missing or unsafe")
	}
	file, _, err := openVerifiedConfig(path, info)
	if err != nil {
		return nil, errors.New("saved software recovery journal changed during secure open")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20+1))
	decoder.DisallowUnknownFields()
	var data journalData
	if decoder.Decode(&data) != nil || validateJournalData(data) != nil || data.NextSeq < 1 || data.ActiveJob == nil || data.ActivePlan == nil ||
		data.ActivePortPlan != nil || data.ActivePortPolicy != nil {
		return nil, errors.New("saved software recovery journal lacks one valid original software plan")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("saved software recovery journal contains trailing or unknown state")
	}
	for _, pending := range data.Pending {
		if pending.JobID != data.ActiveJob.ID || pending.Report.ServiceID != data.ActiveJob.AgentServiceID || pending.Report.LeaseGeneration != data.ActiveJob.LeaseGeneration ||
			pending.Report.Sequence < 1 || pending.Report.LeaseToken != "" || pending.Report.PortReconfigure != nil {
			return nil, errors.New("saved software recovery journal contains another or unsafe pending report")
		}
	}
	return &Journal{path: path, data: data, leaseTokens: make(map[string]string), renameFile: os.Rename, syncDir: syncDirectory}, nil
}
