package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"time"
)

const localExecutorSoftwareClaimRecoveryOperation = "software_claim_recovery_inspect"

// SoftwareClaimRecoveryRequest is an operator's exact, credential-free cursor.
// It authorizes only a failed terminal result after the root executor proves
// that this job has never reached a local mutation boundary.
type SoftwareClaimRecoveryRequest struct {
	JobID           string `json:"job_id"`
	LeaseGeneration uint64 `json:"lease_generation"`
	TargetID        string `json:"target_id"`
	CurrentVersion  string `json:"current_version"`
	TargetVersion   string `json:"target_version"`
	ConfigRevision  int64  `json:"config_revision"`
	OwnershipEpoch  int64  `json:"ownership_epoch"`
}

func (r SoftwareClaimRecoveryRequest) Validate() error {
	if r.JobID != strings.TrimSpace(r.JobID) || !identifierPattern.MatchString(r.JobID) ||
		r.TargetID != strings.TrimSpace(r.TargetID) || !identifierPattern.MatchString(r.TargetID) ||
		r.CurrentVersion != strings.TrimSpace(r.CurrentVersion) || !versionPattern.MatchString(r.CurrentVersion) ||
		r.TargetVersion != strings.TrimSpace(r.TargetVersion) || !versionPattern.MatchString(r.TargetVersion) ||
		r.LeaseGeneration == 0 || r.LeaseGeneration >= math.MaxInt64 ||
		r.ConfigRevision < 1 || r.OwnershipEpoch < 1 {
		return errors.New("software claim recovery requires an exact job, target, versions, config revision, ownership epoch and lease generation")
	}
	return nil
}

func (r SoftwareClaimRecoveryRequest) sameIntent(other SoftwareClaimRecoveryRequest) bool {
	r.LeaseGeneration = 0
	other.LeaseGeneration = 0
	return r == other
}

func (r SoftwareClaimRecoveryRequest) sha256() string {
	encoded, _ := json.Marshal(r)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

type SoftwareClaimRecoveryInspection struct {
	Request              SoftwareClaimRecoveryRequest `json:"request"`
	ExecutorPolicySHA256 string                       `json:"executor_policy_sha256"`
}

// SoftwareClaimRecoveryProof contains metadata only. The root implementation
// reads fixed policy/state paths; no command, path, credential or grant can be
// supplied by the Agent.
type SoftwareClaimRecoveryProof struct {
	RequestSHA256          string    `json:"request_sha256"`
	UpdaterID              string    `json:"updater_id"`
	HostID                 string    `json:"host_id"`
	SourcePolicyRevision   int64     `json:"source_policy_revision"`
	ProjectionRevision     int64     `json:"projection_revision"`
	ExecutorPolicyRevision int64     `json:"executor_policy_revision"`
	ExecutorPolicySHA256   string    `json:"executor_policy_sha256"`
	OwnershipEpoch         int64     `json:"ownership_epoch"`
	RuntimeVersion         string    `json:"runtime_version"`
	NoMutation             bool      `json:"no_mutation"`
	ObservedAt             time.Time `json:"observed_at"`
	PriorSettledRawSHA256  string    `json:"prior_settled_raw_sha256,omitempty"`
}

func (p SoftwareClaimRecoveryProof) Validate() error {
	if !digestPattern.MatchString(p.RequestSHA256) ||
		!identifierPattern.MatchString(p.UpdaterID) || !validExecutionHostID(p.HostID) ||
		p.SourcePolicyRevision < 1 || p.ProjectionRevision < 1 || p.ExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(p.ExecutorPolicySHA256) || p.OwnershipEpoch < 1 ||
		p.RuntimeVersion != strings.TrimSpace(p.RuntimeVersion) || !versionPattern.MatchString(p.RuntimeVersion) ||
		!p.NoMutation || p.ObservedAt.IsZero() ||
		(p.PriorSettledRawSHA256 != "" && !softwareClaimRecoveryRawDigestValid(p.PriorSettledRawSHA256)) {
		return errors.New("software claim recovery absence proof is invalid")
	}
	return nil
}

type SoftwareClaimRecoveryInspector interface {
	InspectSoftwareClaimRecovery(context.Context, SoftwareClaimRecoveryInspection, LocalExecutorMutationFence) (SoftwareClaimRecoveryProof, error)
}

func (a *HostPullAgent) softwareClaimRecoveryInspector() (SoftwareClaimRecoveryInspector, error) {
	if a == nil {
		return nil, errors.New("software claim recovery agent is unavailable")
	}
	if a.ClaimRecoveryInspector != nil {
		return a.ClaimRecoveryInspector, nil
	}
	if inspector, ok := a.Executor.(SoftwareClaimRecoveryInspector); ok {
		return inspector, nil
	}
	return nil, errors.New("the installed Local Executor has no software claim recovery inspection")
}

func (a *HostPullAgent) inspectSoftwareClaimRecovery(
	ctx context.Context, request SoftwareClaimRecoveryRequest,
	binding HostAgentBinding, policy HostAgentPolicy,
) (SoftwareClaimRecoveryProof, error) {
	inspector, err := a.softwareClaimRecoveryInspector()
	if err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	proof, err := inspector.InspectSoftwareClaimRecovery(ctx, SoftwareClaimRecoveryInspection{
		Request: request, ExecutorPolicySHA256: policy.LocalExecutorPolicySHA256,
	}, LocalExecutorMutationFence{
		SourcePolicyRevision: policy.SourcePolicyRevision, OwnershipEpoch: binding.OwnershipEpoch,
		OwnershipPolicyRevision: policy.Revision, ExecutorPolicyRevision: policy.LocalExecutorPolicyRevision,
	})
	if err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	now := time.Now().UTC()
	if proof.Validate() != nil || proof.RequestSHA256 != request.sha256() ||
		proof.UpdaterID != a.Bootstrap.NodeID || proof.HostID != binding.ExecutionHostID ||
		proof.SourcePolicyRevision != policy.SourcePolicyRevision || proof.ProjectionRevision != policy.Revision ||
		proof.ExecutorPolicyRevision != policy.LocalExecutorPolicyRevision ||
		proof.ExecutorPolicySHA256 != policy.LocalExecutorPolicySHA256 || proof.OwnershipEpoch != request.OwnershipEpoch ||
		proof.RuntimeVersion != a.currentAgentVersion() || proof.ObservedAt.After(now.Add(time.Second)) ||
		now.Sub(proof.ObservedAt) > localExecutorClientTimeout {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery absence proof does not match the authenticated policy and installed runtime")
	}
	return proof, nil
}

func (a *HostPullAgent) softwareClaimRecoveryPolicy(ctx context.Context, request SoftwareClaimRecoveryRequest) (HostAgentBinding, HostAgentPolicy, error) {
	if a == nil || a.ControlPlane == nil || !a.currentIdentity().IsManagedBootstrap() {
		return HostAgentBinding{}, HostAgentPolicy{}, errors.New("software claim recovery dependencies are incomplete")
	}
	policy, changed, err := a.ControlPlane.FetchHostAgentPolicy(ctx, a.Bootstrap.NodeID, 0)
	if err != nil || !changed || policy == nil ||
		policy.validateForService(a.Bootstrap.NodeID, 0) != nil {
		return HostAgentBinding{}, HostAgentPolicy{}, errors.New("authenticate software claim recovery policy")
	}
	binding := HostAgentBinding{ServiceID: policy.ServiceID, ServiceType: ServiceTypeUpdateAgent,
		TransportMode: policy.TransportMode, ExecutionHostID: policy.ExecutionHostID, OwnershipEpoch: policy.OwnershipEpoch}
	if binding.validateForService(a.Bootstrap.NodeID) != nil {
		return HostAgentBinding{}, HostAgentPolicy{}, errors.New("authenticate software claim recovery host binding")
	}
	if err := validateSoftwareClaimRecoveryPolicy(request, binding, *policy); err != nil {
		return HostAgentBinding{}, HostAgentPolicy{}, err
	}
	return binding, *policy, nil
}

func validateSoftwareClaimRecoveryPolicy(request SoftwareClaimRecoveryRequest, binding HostAgentBinding, policy HostAgentPolicy) error {
	target, exists := hostPullPolicyTarget(policy, request.TargetID)
	if request.Validate() != nil || !exists || target.appliedConfigRevision() != request.ConfigRevision ||
		binding.TransportMode != HostTransportPullV2 || policy.TransportMode != HostTransportPullV2 ||
		binding.OwnershipEpoch != request.OwnershipEpoch || policy.OwnershipEpoch != request.OwnershipEpoch ||
		binding.ExecutionHostID != policy.ExecutionHostID || policy.ObserveOnly ||
		policy.SourcePolicyRevision < 1 || policy.Revision < 1 || policy.LocalExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(policy.LocalExecutorPolicySHA256) ||
		policy.RuntimeTokenRotation != nil || policy.SelfUpdate != nil || policy.SelfUpdateID != "" {
		return errors.New("software claim recovery request does not match the current authenticated target and ownership policy")
	}
	return nil
}

// InspectSoftwareClaim is read-only: it does not create an intent, open or
// rewrite a journal, claim a job, issue a grant, or change a service.
func (a *HostPullAgent) InspectSoftwareClaim(ctx context.Context, request SoftwareClaimRecoveryRequest) (SoftwareClaimRecoveryProof, error) {
	if err := request.Validate(); err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	binding, policy, err := a.softwareClaimRecoveryPolicy(ctx, request)
	if err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	return a.inspectSoftwareClaimRecovery(ctx, request, binding, policy)
}

// RecoverSoftwareClaim is the explicit operator entry for a known central
// claimed job without a local plan. Every claim names exactly that job. A lost
// claim response requires an operator reread of the same job's generation;
// the next supplied generation is a durable, audited CAS transition.
func (a *HostPullAgent) RecoverSoftwareClaim(ctx context.Context, request SoftwareClaimRecoveryRequest) error {
	return a.recoverSoftwareClaim(ctx, request, false)
}

// RecoverSoftwareClaimAfterGenerationRead additionally records the operator's
// explicit reread of this same job. It permits one supplied unchanged cursor
// to be tried again when a prior request may never have reached the server.
// CP's exact generation CAS remains authoritative if it actually advanced.
func (a *HostPullAgent) RecoverSoftwareClaimAfterGenerationRead(ctx context.Context, request SoftwareClaimRecoveryRequest) error {
	return a.recoverSoftwareClaim(ctx, request, true)
}

func (a *HostPullAgent) recoverSoftwareClaim(ctx context.Context, request SoftwareClaimRecoveryRequest, generationReadConfirmed bool) error {
	if err := request.Validate(); err != nil {
		return err
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
	if !ok || a.OpenJournal == nil {
		return errors.New("software claim recovery execution dependencies are incomplete")
	}
	snapshot, exists, err := loadSoftwareClaimRecoverySnapshot(a.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil {
		return err
	}
	intent := snapshot.Intent
	if exists && (intent.UpdaterID != a.Bootstrap.NodeID ||
		intent.HostID != binding.ExecutionHostID || !intent.policyMatches(policy)) {
		return errors.New("software claim recovery cannot replace another durable intent or policy")
	}
	rotating := exists && !intent.Original.sameIntent(request)
	if rotating && (intent.SchemaVersion != 2 || !intent.Settled || intent.TerminalClear == nil || intent.Original.JobID == request.JobID) {
		return errors.New("software claim recovery cannot replace an unsettled or legacy durable intent")
	}
	if exists && intent.Settled && !rotating {
		return nil
	}
	// Read strictly before OpenJournal can scrub legacy data. The root reader
	// first proves exact cursor absence without an intent; a refused preflight
	// must not leave a marker blocking the cursor's normal reconciliation.
	data, err := readSoftwareClaimRecoveryJournal(a.StateDir)
	if err != nil {
		return err
	}
	active := data.ActiveJob
	previousRaw := ""
	if !exists || rotating {
		intent = newSoftwareClaimRecoveryIntent(request, a.Bootstrap.NodeID, binding.ExecutionHostID, policy)
		if rotating {
			previousRaw = softwareClaimRecoveryRawSHA256(snapshot.Raw)
			intent.PreviousSettledRawSHA256 = previousRaw
		}
	}
	expected := request.LeaseGeneration
	if active != nil {
		target, _ := hostPullPolicyTarget(policy, request.TargetID)
		if !softwareClaimRecoveryCursorMatches(intent, *active) || active.LeaseGeneration < 1 || active.LeaseGeneration >= math.MaxInt64 ||
			active.EffectiveType() != target.ServiceType || active.DeploymentMode != target.DeploymentMode {
			return errors.New("software claim recovery retained cursor does not match its durable intent")
		}
		if request.LeaseGeneration < active.LeaseGeneration {
			return errors.New("software claim recovery requires a current generation at least as new as the retained exact job cursor")
		}
	} else if exists && !rotating {
		if request.LeaseGeneration < intent.Original.LeaseGeneration ||
			(!generationReadConfirmed && (request.LeaseGeneration == intent.Original.LeaseGeneration || intent.wasAttempted(request.LeaseGeneration))) {
			return softwareClaimRecoveryGenerationRereadError()
		}
	}
	if intent.wasAttempted(expected) && !generationReadConfirmed {
		return softwareClaimRecoveryGenerationRereadError()
	}
	proof, err := a.inspectSoftwareClaimRecovery(ctx, request, binding, policy)
	if err != nil {
		return err
	}
	if proof.PriorSettledRawSHA256 != intent.PreviousSettledRawSHA256 {
		return errors.New("software claim recovery root proof does not bind the exact preserved raw history")
	}
	previous := softwareClaimRecoveryIntentSHA256(intent)
	if !exists {
		previous = ""
	}
	intent.Request = request
	intent.Request.LeaseGeneration = expected
	intent.Attempts = append(intent.Attempts, softwareClaimRecoveryAttempt{LeaseGeneration: expected, StartedAt: time.Now().UTC(), ConfirmedReread: generationReadConfirmed})
	if rotating {
		if err := transitionSoftwareClaimRecoveryIntent(a.StateDir, previousRaw, intent, proof, defaultSoftwareClaimRecoveryHistoryStoreRuntime()); err != nil {
			return err
		}
	} else {
		if err := saveSoftwareClaimRecoveryIntent(a.StateDir, previous, intent); err != nil {
			return err
		}
	}
	proof, err = a.inspectSoftwareClaimRecovery(ctx, intent.Request, binding, policy)
	if err != nil {
		return err
	}
	if proof.PriorSettledRawSHA256 != intent.PreviousSettledRawSHA256 {
		return errors.New("software claim recovery root history changed after durable head transition; no claim was sent")
	}
	// Preserve an exact first progress acknowledgement until authenticated
	// fresh-lease adoption. OpenJournal would discard it before the claim.
	a.Journal = softwareClaimRecoveryJournalFromData(a.StateDir, data)
	return a.claimSoftwareClaimRecovery(ctx, panel, binding, policy, intent)
}

func softwareClaimRecoveryGenerationRereadError() error {
	return errors.New("software claim recovery claim outcome is uncertain; reread only this job's current lease generation and supply that exact value with --confirm-current-generation to recover-software-claim; the durable intent remains")
}

func (a *HostPullAgent) claimSoftwareClaimRecovery(ctx context.Context, panel HostPullExecutionControlPlane, binding HostAgentBinding, policy HostAgentPolicy, intent softwareClaimRecoveryIntent) error {
	proof, err := a.inspectSoftwareClaimRecovery(ctx, intent.Request, binding, policy)
	if err != nil {
		return err
	}
	if !softwareClaimRecoveryProofMatchesIntent(proof, intent) {
		return errors.New("software claim recovery root proof does not match its complete durable history")
	}
	claimRequest := HostPullClaimRequest{
		UpdaterID: a.Bootstrap.NodeID, HostID: binding.ExecutionHostID,
		ActiveJobID: intent.Request.JobID, LeaseGeneration: int64(intent.Request.LeaseGeneration), Fence: intent.Request.OwnershipEpoch,
	}
	job, clear, err := panel.ClaimHost(ctx, claimRequest)
	if err != nil {
		return softwareClaimRecoveryGenerationRereadError()
	}
	if clear {
		return a.settleSoftwareClaimRecovery(ctx, binding, policy, intent, job, claimRequest, false)
	}
	if job == nil || job.ProtocolVersion != 2 || job.ID != intent.Request.JobID ||
		job.LeaseGeneration != intent.Request.LeaseGeneration+1 || !job.RecoveryRequired || job.RecoveryClear ||
		job.EffectiveOperation() != updateJobOperationSoftwareUpdate {
		return softwareClaimRecoveryGenerationRereadError()
	}
	if err := a.bindSoftwareClaim(panel, binding, policy, nil, job); err != nil {
		return err
	}
	if err := validateHostPullClaim(*job, a.Bootstrap.NodeID, binding, policy); err != nil || !softwareClaimRecoveryJobMatches(intent, *job) {
		return errors.New("software claim recovery fresh lease does not match the durable terminal-only intent")
	}
	proof, err = a.inspectSoftwareClaimRecovery(ctx, intent.Request, binding, policy)
	if err != nil {
		return err
	}
	if !softwareClaimRecoveryProofMatchesIntent(proof, intent) {
		return errors.New("software claim recovery fresh lease lacks its exact immutable root history")
	}
	if err := a.Journal.SetTerminalSoftwareClaimRecovery(*job, intent.Request, proof); err != nil {
		return err
	}
	return a.ResumeSoftwareClaimRecovery(ctx, binding, policy, *job)
}

// ResumeSoftwareClaimRecovery must precede every normal software branch. It
// never constructs a plan or downloads an artifact, and requests no grant.
func (a *HostPullAgent) ResumeSoftwareClaimRecovery(ctx context.Context, binding HostAgentBinding, policy HostAgentPolicy, job UpdateJob) error {
	intent, exists, err := loadSoftwareClaimRecoveryIntent(a.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil {
		return err
	}
	if !exists || intent.Settled || !intent.policyMatches(policy) || !softwareClaimRecoveryJobMatches(intent, job) ||
		binding.ExecutionHostID != intent.HostID || binding.OwnershipEpoch != intent.Request.OwnershipEpoch ||
		validateHostPullClaim(job, a.Bootstrap.NodeID, binding, policy) != nil ||
		a.Journal == nil || a.Journal.ActivePlan() != nil || a.Journal.ActivePortPlan() != nil || len(a.Journal.Pending()) != 0 {
		return errors.New("software claim recovery cannot resume without its exact nonexecuting durable intent")
	}
	panel, ok := a.ControlPlane.(HostPullExecutionControlPlane)
	if !ok {
		return errors.New("software claim recovery control plane is unavailable")
	}
	proof, err := a.inspectSoftwareClaimRecovery(ctx, intent.Request, binding, policy)
	if err != nil {
		return err
	}
	if !softwareClaimRecoveryProofMatchesIntent(proof, intent) {
		return errors.New("software claim recovery terminal report lacks its exact immutable root history")
	}
	if err := a.Journal.SetTerminalSoftwareClaimRecovery(job, intent.Request, proof); err != nil {
		return err
	}
	// The durable intent precedes this direct report. There is deliberately no
	// pending journal report to lose its ephemeral V2 lease after restart. A
	// restarted Agent reclaims this same job, or accepts its terminal clear.
	if err := panel.Report(ctx, job.ID, JobReport{
		ServiceID: a.Bootstrap.NodeID, LeaseGeneration: job.LeaseGeneration,
		Sequence: job.ReportSequence, Status: "failed", Progress: 100,
		Code:    "software_claim_orphan_recovered",
		Message: "explicit recovery proved no local mutation; the original job was settled without applying software",
	}); err != nil {
		return err
	}
	clearRequest := HostPullClaimRequest{
		UpdaterID: a.Bootstrap.NodeID, HostID: binding.ExecutionHostID, ActiveJobID: job.ID,
		LeaseGeneration: int64(job.LeaseGeneration), Fence: intent.Request.OwnershipEpoch,
	}
	terminal, clear, err := panel.ClaimHost(ctx, clearRequest)
	if err != nil || !clear {
		return errors.New("software claim recovery terminal result awaits authenticated same-job clear; the durable intent remains")
	}
	return a.settleSoftwareClaimRecovery(ctx, binding, policy, intent, terminal, clearRequest, true)
}

func softwareClaimRecoveryJobMatches(intent softwareClaimRecoveryIntent, job UpdateJob) bool {
	if job.SoftwareUpdate == nil || job.ID != intent.Original.JobID || job.ProtocolVersion != 2 ||
		job.EffectiveOperation() != updateJobOperationSoftwareUpdate || job.AgentServiceID != intent.UpdaterID ||
		job.HostID != intent.HostID || job.TransportMode != HostTransportPullV2 ||
		job.OwnershipEpoch != intent.Original.OwnershipEpoch || job.TargetID != intent.Original.TargetID ||
		job.CurrentVersion != intent.Original.CurrentVersion || job.EffectiveVersion() != intent.Original.TargetVersion ||
		job.SoftwareUpdate.ConfigRevision != intent.Original.ConfigRevision ||
		job.PolicyRevision != intent.ProjectionRevision ||
		job.SoftwareUpdate.SourcePolicyRevision != intent.SourcePolicyRevision ||
		job.SoftwareUpdate.ProjectionRevision != intent.ProjectionRevision ||
		job.SoftwareUpdate.ExecutorPolicyRevision != intent.ExecutorPolicyRevision ||
		job.SoftwareUpdate.ExecutorPolicySHA256 != intent.ExecutorPolicySHA256 {
		return false
	}
	return true
}

func softwareClaimRecoveryCursorMatches(intent softwareClaimRecoveryIntent, job UpdateJob) bool {
	if job.ProtocolVersion != 2 || job.ID != intent.Original.JobID || job.EffectiveOperation() != updateJobOperationSoftwareUpdate ||
		job.AgentServiceID != intent.UpdaterID || job.HostID != intent.HostID || job.TransportMode != HostTransportPullV2 ||
		job.OwnershipEpoch != intent.Original.OwnershipEpoch || job.TargetID != intent.Original.TargetID ||
		job.CurrentVersion != intent.Original.CurrentVersion || job.EffectiveVersion() != intent.Original.TargetVersion ||
		!identifierPattern.MatchString(job.CommandID) || job.LeaseToken != "" || !job.ReleaseToken.Empty() || job.PortReconfigure != nil {
		return false
	}
	if job.SoftwareUpdate == nil {
		return !job.SoftwareClaimRejected && job.PolicyRevision == intent.Original.ConfigRevision
	}
	if job.SoftwareUpdate.Validate() == nil {
		return softwareClaimRecoveryJobMatches(intent, job)
	}
	return job.SoftwareClaimRejected && job.PolicyRevision == 0 && job.SoftwareUpdate.validateIntent() == nil &&
		job.SoftwareUpdate.ConfigRevision == intent.Original.ConfigRevision
}

// PrepareSoftwareClaimRecoveryClaim is the ordinary loop's only allowed
// claim while a terminal-only marker exists. Recording the exact retained
// generation before POST makes a lost response explicit instead of a retry.
func (a *HostPullAgent) PrepareSoftwareClaimRecoveryClaim(ctx context.Context, binding HostAgentBinding, policy HostAgentPolicy, active UpdateJob) error {
	intent, exists, err := loadSoftwareClaimRecoveryIntent(a.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil {
		return err
	}
	if !exists || intent.Settled || !intent.policyMatches(policy) || !softwareClaimRecoveryCursorMatches(intent, active) ||
		active.LeaseGeneration < 1 || active.LeaseGeneration >= math.MaxInt64 {
		return errors.New("software claim recovery cannot claim another or an executing cursor")
	}
	if intent.wasAttempted(active.LeaseGeneration) {
		return softwareClaimRecoveryGenerationRereadError()
	}
	request := intent.Original
	request.LeaseGeneration = active.LeaseGeneration
	if _, err := a.inspectSoftwareClaimRecovery(ctx, request, binding, policy); err != nil {
		return err
	}
	previous := softwareClaimRecoveryIntentSHA256(intent)
	intent.Request = request
	intent.Attempts = append(intent.Attempts, softwareClaimRecoveryAttempt{LeaseGeneration: active.LeaseGeneration, StartedAt: time.Now().UTC()})
	return saveSoftwareClaimRecoveryIntent(a.StateDir, previous, intent)
}

func (a *HostPullAgent) HasSoftwareClaimRecoveryIntent(jobID string) (bool, error) {
	intent, exists, err := loadSoftwareClaimRecoveryIntent(a.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || intent.Settled {
		return false, err
	}
	if jobID != "" && intent.Original.JobID != jobID {
		return false, errors.New("another terminal-only software claim recovery intent blocks normal job processing")
	}
	return true, nil
}

func (a *HostPullAgent) lockSoftwareClaimRecoveryLifecycle(ctx context.Context) (func(), error) {
	if a == nil || ctx.Err() != nil || !filepath.IsAbs(a.StateDir) || filepath.Dir(a.StateDir) == a.StateDir {
		return nil, errors.New("software claim recovery lifecycle is unavailable")
	}
	return acquireSoftwareClaimRecoveryLifecycleLock(filepath.Join(a.StateDir, softwareClaimRecoveryLockName))
}
