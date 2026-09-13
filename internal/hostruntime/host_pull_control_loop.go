package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// recoveryOnlyHostPullControlPlane prevents the operator recovery command from
// ever drifting into a normal claim. The underlying Panel client validates a
// structured terminal proof before returning clearActive; executeOnce then
// matches that proof to the durable active job before clearing the cursor.
type recoveryOnlyHostPullControlPlane struct {
	HostPullControlPlane
	execution HostPullExecutionControlPlane
}

func (c recoveryOnlyHostPullControlPlane) ClaimHost(
	ctx context.Context,
	request HostPullClaimRequest,
) (*UpdateJob, bool, error) {
	if strings.TrimSpace(request.ActiveJobID) == "" {
		return nil, false, errors.New("recovery-only claim requires an active job cursor")
	}
	job, clearActive, err := c.execution.ClaimHost(ctx, request)
	if err != nil {
		return nil, false, err
	}
	if clearActive && (job == nil || job.ID != strings.TrimSpace(request.ActiveJobID) ||
		(!isTerminalUpdateStatus(job.Status) &&
			!(job.RecoveryClear && job.ProtocolVersion == 2 &&
				isV2RecoveryClearStatus(job.Status)))) {
		return nil, false, errors.New("recovery-only claim received an unproven active cursor clear")
	}
	return job, clearActive, nil
}

func (c recoveryOnlyHostPullControlPlane) Report(
	ctx context.Context,
	jobID string,
	report JobReport,
) error {
	return c.execution.Report(ctx, jobID, report)
}

func (c recoveryOnlyHostPullControlPlane) IssueMutationGrant(
	ctx context.Context,
	jobID string,
	request MutationGrantRequest,
) (MutationGrant, error) {
	return c.execution.IssueMutationGrant(ctx, jobID, request)
}

func (a *HostPullAgent) Run(ctx context.Context) error {
	if a == nil || !a.currentIdentity().IsManagedBootstrap() || a.ControlPlane == nil || a.OpenJournal == nil {
		return errors.New("host pull agent dependencies are incomplete")
	}
	journal, err := a.OpenJournal(a.StateDir)
	if err != nil {
		return fmt.Errorf("open host pull agent journal: %w", err)
	}
	if journal == nil {
		return errors.New("open host pull agent journal returned nil")
	}
	if err := garbageCollectJobDirectories(a.StateDir, journal); err != nil {
		return fmt.Errorf("clean stale update job state: %w", err)
	}
	a.Journal = journal
	if a.RecoveryOnly {
		return a.runRecoveryOnly(ctx)
	}
	if !a.hasActiveRecovery() {
		if err := a.recoverRuntimeTokenRotation(ctx); err != nil &&
			ctx.Err() == nil {
			a.Logf("host runtime token rotation recovery failed: %v", err)
		}
	}

	var binding HostAgentBinding
	var policy *HostAgentPolicy
	var observations []HostTargetObservation
	var observationFailed bool

	register := func() bool {
		if !a.hasActiveRecovery() {
			if recoveryErr := a.recoverRuntimeTokenRotation(ctx); recoveryErr != nil {
				if ctx.Err() == nil {
					a.Logf(
						"host runtime token rotation recovery failed: %v",
						recoveryErr,
					)
				}
				// Registration is read-only and remains useful while the local
				// executor is unavailable. Reconciliation still fails closed before
				// any runtime-token mutation is attempted.
			}
		}
		capabilities := a.capabilities(binding, policy, observations, observationFailed)
		registered, registerErr := a.ControlPlane.RegisterHostAgent(ctx, a.currentIdentity(), capabilities)
		if registerErr != nil {
			if ctx.Err() == nil {
				a.Logf("host pull agent register failed: %v", registerErr)
			}
			return false
		}
		if binding.ExecutionHostID != "" &&
			(binding.ExecutionHostID != registered.ExecutionHostID || binding.OwnershipEpoch != registered.OwnershipEpoch) {
			policy = nil
			observations = nil
			observationFailed = false
		}
		binding = registered
		return true
	}
	refreshPolicy := func() bool {
		if binding.ExecutionHostID == "" {
			return true
		}
		currentRevision := int64(0)
		if policy != nil {
			currentRevision = policy.Revision
		}
		if active := a.Journal.Active(); active != nil && isPortContractV2(*active) {
			// A same-job R may legitimately be ahead of CP's still-pending T.
			// Fetch without a current revision, then apply the durable job fence.
			currentRevision = 0
		}
		next, changed, fetchErr := a.ControlPlane.FetchHostAgentPolicy(ctx, a.Bootstrap.NodeID, currentRevision)
		if fetchErr != nil {
			if ctx.Err() == nil {
				a.Logf("host pull agent policy refresh failed: %v", fetchErr)
			}
			return false
		}
		if !changed || next == nil {
			if policy != nil && !a.hasActiveRecovery() {
				if rotationErr := a.reconcileRuntimeTokenRotation(ctx, policy); rotationErr != nil {
					if ctx.Err() == nil {
						a.Logf(
							"host runtime token rotation reconcile failed: %v",
							rotationErr,
						)
					}
					return false
				}
			}
			return true
		}
		if next.ExecutionHostID != binding.ExecutionHostID ||
			next.OwnershipEpoch != binding.OwnershipEpoch ||
			next.TransportMode != binding.TransportMode {
			a.Logf("host pull agent policy binding mismatch")
			return false
		}
		resolved, resolveErr := a.portRecoveryPolicy(*next)
		if resolveErr != nil {
			a.Logf("host pull agent port recovery projection is unavailable")
			return false
		}
		policy = &resolved
		observations, observationFailed = a.observe(ctx, *policy)
		if a.hasActiveRecovery() {
			return true
		}
		if rotationErr := a.reconcileRuntimeTokenRotation(ctx, policy); rotationErr != nil {
			if ctx.Err() == nil {
				a.Logf(
					"host runtime token rotation reconcile failed: %v",
					rotationErr,
				)
			}
			return false
		}
		return true
	}
	heartbeat := func() bool {
		if policy != nil {
			observations, observationFailed = a.observe(ctx, *policy)
		}
		capabilities := a.capabilities(binding, policy, observations, observationFailed)
		if heartbeatErr := a.ControlPlane.HeartbeatHostAgent(
			ctx, a.currentIdentity(), "online", capabilities,
		); heartbeatErr != nil {
			if ctx.Err() == nil {
				a.Logf("host pull agent heartbeat failed: %v", heartbeatErr)
			}
			return false
		}
		a.recordRuntimeTokenRotationHeartbeat()
		a.recordSelfUpdateHeartbeat(policy)
		return ctx.Err() == nil
	}

	registerRetry := newHostAgentRetryState(a.HeartbeatInterval, a.Bootstrap.NodeID, "register")
	policyRetry := newHostAgentRetryState(a.PollInterval, a.Bootstrap.NodeID, "policy")
	heartbeatRetry := newHostAgentRetryState(a.HeartbeatInterval, a.Bootstrap.NodeID, "heartbeat")

	now := time.Now()
	registerRetry.record(now, register())
	policyRetry.record(now, refreshPolicy())
	heartbeatRetry.record(now, heartbeat())
	if a.hasActiveRecovery() {
		a.startExecutionCycle(ctx, binding, policy, observations, observationFailed)
	} else {
		a.startSelfUpdate(ctx, binding, policy)
		a.startExecutionCycle(ctx, binding, policy, observations, observationFailed)
	}

	pollTicker := time.NewTicker(hostAgentJitteredInterval(a.PollInterval, a.Bootstrap.NodeID, "policy-cadence"))
	defer pollTicker.Stop()
	heartbeatTicker := time.NewTicker(hostAgentJitteredInterval(a.HeartbeatInterval, a.Bootstrap.NodeID, "heartbeat-cadence"))
	defer heartbeatTicker.Stop()
	for {
		if err := a.Journal.Err(); err != nil {
			return fmt.Errorf("host pull agent journal requires restart: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pollTicker.C:
			now = time.Now()
			if policyRetry.ready(now) {
				policyRetry.record(now, refreshPolicy())
			}
			if a.hasActiveRecovery() {
				a.startExecutionCycle(ctx, binding, policy, observations, observationFailed)
			} else {
				a.startSelfUpdate(ctx, binding, policy)
				a.startExecutionCycle(ctx, binding, policy, observations, observationFailed)
			}
		case <-heartbeatTicker.C:
			now = time.Now()
			if registerRetry.ready(now) {
				registerRetry.record(now, register())
			}
			if heartbeatRetry.ready(now) {
				heartbeatRetry.record(now, heartbeat())
			}
			if !a.hasActiveRecovery() {
				a.startSelfUpdate(ctx, binding, policy)
			}
		}
	}
}
