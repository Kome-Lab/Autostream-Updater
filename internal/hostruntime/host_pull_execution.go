package hostruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

type HostPullExecutionControlPlane interface {
	ClaimHost(context.Context, HostPullClaimRequest) (*UpdateJob, bool, error)
	Report(context.Context, string, JobReport) error
	IssueMutationGrant(context.Context, string, MutationGrantRequest) (MutationGrant, error)
}

type HostPullClaimRequest struct {
	UpdaterID       string
	HostID          string
	LeaseGeneration int64
	Fence           int64
	ActiveJobID     string
}

func newHostPullSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "session-" + hex.EncodeToString(value[:]), nil
}

func (a *HostPullAgent) mutationReady(
	binding HostAgentBinding,
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) bool {
	return a.mutationCapabilityReady(
		binding, policy, observations, observationFailed,
	) &&
		policy.RuntimeTokenRotation == nil
}

func (a *HostPullAgent) mutationCapabilityReady(
	binding HostAgentBinding,
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) bool {
	return a.executorReady(policy, observations, observationFailed) &&
		!policy.ObserveOnly &&
		binding.TransportMode == HostTransportPullV2 &&
		binding.OwnershipEpoch > 0 &&
		policy.TransportMode == HostTransportPullV2 &&
		policy.ExecutionHostID == binding.ExecutionHostID &&
		policy.OwnershipEpoch == binding.OwnershipEpoch
}

func (a *HostPullAgent) executorReady(
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) bool {
	if a == nil || policy == nil || observationFailed ||
		a.Executor == nil || a.Downloader == nil || a.NewSessionID == nil ||
		policy.TransportMode != HostTransportPullV2 ||
		policy.Revision < 1 ||
		policy.SourcePolicyRevision < 1 ||
		policy.LocalExecutorPolicyRevision < 1 ||
		policy.LocalExecutorPolicySHA256 == "" {
		return false
	}
	if _, ok := a.ControlPlane.(HostPullExecutionControlPlane); !ok {
		return false
	}
	observed := make(map[string]HostTargetObservation, len(observations))
	for _, observation := range observations {
		observed[observation.ServiceID] = observation
	}
	for _, target := range policy.Targets {
		observation, ok := observed[target.ServiceID]
		if !ok ||
			observation.Availability != TargetAvailabilityAvailable ||
			observation.PolicyRevision != policy.LocalExecutorPolicyRevision ||
			observation.PolicySHA256 != policy.LocalExecutorPolicySHA256 ||
			observation.ConfigRevision != target.appliedConfigRevision() ||
			!localExecutorConfigDigestMatchesTarget(
				*policy, target, observation.ConfigSHA256,
			) {
			return false
		}
	}
	return len(policy.Targets) > 0
}

func (a *HostPullAgent) startExecution(
	ctx context.Context,
	binding HostAgentBinding,
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) {
	if !a.mutationReady(binding, policy, observations, observationFailed) ||
		!a.executionRunning.CompareAndSwap(false, true) {
		return
	}
	policySnapshot := *policy
	policySnapshot.Targets = append([]HostAgentPolicyTarget(nil), policy.Targets...)
	go func() {
		defer a.executionRunning.Store(false)
		if err := a.executeOnce(ctx, binding, policySnapshot); err != nil &&
			ctx.Err() == nil {
			a.Logf("host pull agent execution poll failed: %v", err)
		}
	}()
}

func (a *HostPullAgent) executeOnce(ctx context.Context, binding HostAgentBinding, policy HostAgentPolicy) error {
	panel, ok := a.ControlPlane.(HostPullExecutionControlPlane)
	if !ok || a.Journal == nil {
		return errors.New("host pull execution dependencies are incomplete")
	}
	if activePolicy, err := a.portRecoveryPolicy(policy); err != nil {
		return err
	} else {
		policy = activePolicy
	}
	if err := a.validateRuntimeForClaim(ctx, binding, policy); err != nil {
		return err
	}
	active := a.Journal.Active()
	activeIDForRecovery := ""
	if active != nil {
		activeIDForRecovery = active.ID
	}
	terminalOnly, err := a.HasSoftwareClaimRecoveryIntent(activeIDForRecovery)
	if err != nil {
		return err
	}
	if terminalOnly && active == nil {
		return softwareClaimRecoveryGenerationRereadError()
	}
	if terminalOnly {
		if err := a.PrepareSoftwareClaimRecoveryClaim(ctx, binding, policy, *active); err != nil {
			return err
		}
	}
	leaseAvailable := true
	if active != nil && isV2SoftwareJob(*active) {
		if leaseState, ok := panel.(interface{ HasActiveLease(UpdateJob) bool }); ok {
			leaseAvailable = leaseState.HasActiveLease(*active)
		}
	}
	if terminalOnly {
		// The retained intent is settled only with a fresh exact same-job lease
		// or authenticated terminal clear; it never enters normal execution.
	} else if leaseAvailable {
		if err := a.flushExecutionReports(ctx, panel); err != nil {
			return err
		}
	}
	active = a.Journal.Active()
	activeID := ""
	leaseGeneration := int64(1)
	if active != nil {
		activeID = active.ID
		if active.LeaseGeneration == 0 || active.LeaseGeneration > math.MaxInt64 {
			return errors.New("active pull_v2 lease generation is invalid")
		}
		leaseGeneration = int64(active.LeaseGeneration)
	}
	claimRequest := HostPullClaimRequest{
		UpdaterID:       a.Bootstrap.NodeID,
		HostID:          binding.ExecutionHostID,
		LeaseGeneration: leaseGeneration,
		Fence:           binding.OwnershipEpoch,
		ActiveJobID:     activeID,
	}
	job, clearActive, err := panel.ClaimHost(ctx, claimRequest)
	if err != nil {
		return err
	}
	if clearActive {
		if terminalOnly {
			return a.CompleteSoftwareClaimRecoveryClear(ctx, binding, policy, job, claimRequest)
		}
		if active == nil || job == nil {
			return errors.New("terminal pull recovery proof does not match the active job")
		}
		if job.RecoveryClear {
			if err := validateV2RecoveryClear(*active, *job, a.Bootstrap.NodeID); err != nil {
				return err
			}
		} else if !sameRecoveredJobIntent(*active, *job) ||
			!isTerminalUpdateStatus(job.Status) {
			return errors.New("terminal pull recovery proof does not match the active job")
		}
		if isV2SoftwareJob(*active) {
			// Restart retains software reports until exact terminal proof. Only
			// this authenticated same-job clear permits dropping their old lease.
			if err := a.Journal.DropJobReports(active.ID); err != nil {
				return err
			}
		}
		if err := cleanupJobDirectory(a.StateDir, active.ID); err != nil {
			return fmt.Errorf("clean terminal pull recovery job state: %w", err)
		}
		return a.Journal.ClearActive()
	}
	if job == nil {
		return nil
	}
	if terminalOnly {
		// Root absence and the immutable recovery marker authorize terminal
		// settlement only; Resume uses its dedicated journal admission guard.
		if err := a.bindSoftwareClaim(panel, binding, policy, nil, job); err != nil {
			return err
		}
		return a.ResumeSoftwareClaimRecovery(ctx, binding, policy, *job)
	}
	if err := a.bindSoftwareClaim(panel, binding, policy, active, job); err != nil {
		if active == nil && !job.RecoveryRequired && softwareClaimIdentityMatches(*job, a.Bootstrap.NodeID, binding, policy) &&
			job.SoftwareUpdate != nil && job.SoftwareUpdate.validateIntent() == nil {
			job.SoftwareClaimRejected = true
			if journalErr := a.Journal.SetActive(job); journalErr != nil {
				return errors.Join(err, journalErr)
			}
		}
		return err
	}
	if job.SoftwareClaimRejected {
		return errors.New("software claim is retained for explicit terminal-only recovery")
	}
	if err := validateHostPullClaim(*job, a.Bootstrap.NodeID, binding, policy); err != nil {
		return err
	}
	if active != nil && (active.ID != job.ID || !job.RecoveryRequired) {
		return fmt.Errorf("refusing claim %s while interrupted job %s awaits recovery", job.ID, active.ID)
	}
	if active != nil && !sameRecoveredJobIntent(*active, *job) {
		return fmt.Errorf("refusing recovered claim %s because its immutable intent changed", job.ID)
	}
	if active != nil && isV2SoftwareJob(*active) && !leaseAvailable && job.LeaseGeneration == active.LeaseGeneration+1 {
		// Only an authenticated exact same-job recovery lease invalidates the
		// old report cursor. Claim errors or intent drift preserve every report.
		if err := a.Journal.AdoptRecoveredSoftwareClaim(*job); err != nil {
			return err
		}
	}
	return a.processExecutionJob(ctx, panel, binding, policy, *job)
}
