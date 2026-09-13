package hostruntime

import (
	"context"
	"errors"
	"fmt"
	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
	"strings"
	"time"
)

func (a *HostPullAgent) runRecoveryOnly(ctx context.Context) error {
	if a == nil || a.Journal == nil {
		return errors.New("host update recovery journal is unavailable")
	}
	if err := a.Journal.Err(); err != nil {
		return fmt.Errorf("host update recovery journal requires restart: %w", err)
	}
	if !a.hasActiveRecovery() {
		return nil
	}
	var lastErr error
	for {
		if err := a.Journal.Err(); err != nil {
			return fmt.Errorf("host update recovery journal requires restart: %w", err)
		}
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return fmt.Errorf("host update recovery did not converge: %v: %w", lastErr, err)
			}
			return err
		}
		if !a.hasActiveRecovery() {
			return nil
		}

		binding, err := a.ControlPlane.RegisterHostAgent(
			ctx,
			a.currentIdentity(),
			a.capabilities(HostAgentBinding{}, nil, nil, false),
		)
		if err == nil {
			var policy *HostAgentPolicy
			policy, _, err = a.ControlPlane.FetchHostAgentPolicy(
				ctx, a.Bootstrap.NodeID, 0,
			)
			if err == nil && policy == nil {
				err = errors.New("recovery-only policy is unavailable")
			}
			if err == nil && !a.recoveryExecutionReady(binding, policy) {
				err = errors.New("recovery-only ownership policy is not ready")
			}
			var observations []HostTargetObservation
			var observationFailed bool
			if err == nil {
				observations, observationFailed = a.observe(ctx, *policy)
				err = a.ControlPlane.HeartbeatHostAgent(
					ctx,
					a.currentIdentity(),
					"online",
					a.capabilities(binding, policy, observations, observationFailed),
				)
				if err != nil {
					err = fmt.Errorf("refresh recovery-only heartbeat: %w", err)
				}
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil && a.hasActiveRecovery() {
				err = a.executeOnce(ctx, binding, *policy)
			}
		}
		if err != nil {
			lastErr = err
			if journalErr := a.Journal.Err(); journalErr != nil {
				return fmt.Errorf(
					"host update recovery journal commit failed: %w",
					errors.Join(err, journalErr),
				)
			}
			// executeOnce may have durably cleared ActiveJob and then failed to
			// remove/fsync its clear fence. Recovery-only installation must not
			// reinterpret that error as convergence merely because Active() is
			// now nil in this process.
			if !a.hasActiveRecovery() {
				return fmt.Errorf("host update recovery failed while clearing active state: %w", err)
			}
			if ctx.Err() == nil {
				a.Logf("host pull agent recovery-only attempt failed: %v", err)
			}
		}
		if !a.hasActiveRecovery() {
			return nil
		}

		timer := time.NewTimer(a.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (a *HostPullAgent) hasActiveRecovery() bool {
	return a != nil && a.Journal != nil && a.Journal.Active() != nil
}

func (a *HostPullAgent) recoveryExecutionReady(
	binding HostAgentBinding,
	policy *HostAgentPolicy,
) bool {
	if !a.hasActiveRecovery() || policy == nil ||
		binding.ServiceID != a.Bootstrap.NodeID ||
		binding.ServiceType != ServiceTypeUpdateAgent ||
		binding.TransportMode != HostTransportPullV2 ||
		binding.ExecutionHostID == "" ||
		binding.OwnershipEpoch < 1 ||
		policy.ServiceID != a.Bootstrap.NodeID ||
		policy.TransportMode != HostTransportPullV2 ||
		policy.ExecutionHostID != binding.ExecutionHostID ||
		policy.OwnershipEpoch != binding.OwnershipEpoch ||
		policy.Revision < 1 ||
		policy.SourcePolicyRevision < 1 ||
		policy.LocalExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(policy.LocalExecutorPolicySHA256) {
		return false
	}
	if _, ok := a.ControlPlane.(HostPullExecutionControlPlane); !ok {
		return false
	}
	active := a.Journal.Active()
	if active == nil {
		return false
	}
	switch active.EffectiveOperation() {
	case updateJobOperationSoftwareUpdate:
		return a.Executor != nil
	case updateJobOperationPortReconfigure:
		return a.PortExecutor != nil
	default:
		return false
	}
}

func (a *HostPullAgent) startExecutionCycle(
	ctx context.Context,
	binding HostAgentBinding,
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) {
	if !a.hasActiveRecovery() {
		a.startExecution(ctx, binding, policy, observations, observationFailed)
		return
	}
	if !a.recoveryExecutionReady(binding, policy) ||
		!a.executionRunning.CompareAndSwap(false, true) {
		return
	}
	policySnapshot := *policy
	policySnapshot.Targets = append(
		[]HostAgentPolicyTarget(nil), policy.Targets...,
	)
	go func() {
		defer a.executionRunning.Store(false)
		if !a.hasActiveRecovery() {
			return
		}
		if err := a.executeOnce(ctx, binding, policySnapshot); err != nil &&
			ctx.Err() == nil {
			a.Logf("host pull agent recovery poll failed: %v", err)
		}
	}()
}

func (a *HostPullAgent) currentIdentity() Config {
	if a == nil {
		return Config{}
	}
	a.identityMu.RLock()
	defer a.identityMu.RUnlock()
	if a.currentBootstrap.IsManagedBootstrap() {
		return a.currentBootstrap
	}
	return a.Bootstrap
}

func (a *HostPullAgent) currentAgentVersion() string {
	if a == nil || strings.TrimSpace(a.AgentVersion) == "" {
		return controlversion.Current()
	}
	return strings.TrimSpace(a.AgentVersion)
}

func (a *HostPullAgent) replaceRuntimeIdentity(identity Config) error {
	if a == nil || !identity.IsManagedBootstrap() {
		return errors.New("replacement Host Agent identity is invalid")
	}
	current := a.currentIdentity()
	if identity.PanelURL != current.PanelURL ||
		identity.NodeID != current.NodeID ||
		identity.ServiceName != current.ServiceName {
		return errors.New("runtime token rotation changed immutable Host Agent identity")
	}
	a.identityMu.Lock()
	a.currentBootstrap = identity
	a.identityMu.Unlock()
	return nil
}
