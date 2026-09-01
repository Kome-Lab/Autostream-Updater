package hostruntime

import (
	"context"
	"time"
)

const runtimeCredentialExpiryPollInterval = time.Minute

// runRuntimeCredentialExpiryLoop gives the root-owned staged credential a
// bounded lifetime even when the unprivileged Host Agent is stopped or cannot
// reach the control plane. It never changes the active identity.
func runRuntimeCredentialExpiryLoop(
	ctx context.Context,
	policy LocalExecutorPolicy,
	interval time.Duration,
) {
	if interval <= 0 {
		interval = runtimeCredentialExpiryPollInterval
	}
	reconcile := func() {
		unlock, err := acquireHostLifecycleLock()
		if err != nil {
			return
		}
		defer unlock()
		rt := defaultRuntimeCredentialExecutorRuntime()
		_ = reconcileRuntimeCredentialExpiry(rt, policy.AgentGID)
	}
	reconcile()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

func reconcileRuntimeCredentialExpiry(
	rt runtimeCredentialExecutorRuntime,
	agentGID uint32,
) error {
	if err := rt.validateIdentityLayout(); err != nil {
		return err
	}
	if _, _, err := rt.loadAndReconcileStatus(agentGID); err != nil {
		return err
	}
	return rt.validateIdentityLayout()
}
