package hostruntime

import "context"

// HostAgentUpgradeGuardRequest binds the delayed installer crash guard to the
// exact healthy runtime pair observed before the legacy Host Agent was stopped.
// It deliberately contains no identity, policy, job, or credential material.
type HostAgentUpgradeGuardRequest struct {
	ExpectedSlot   string
	AgentSHA256    string
	ExecutorSHA256 string
}

// RestartHostAgentFromUpgradeGuard starts the canonical Host Agent only when
// the platform implementation can still prove the exact pre-stop runtime pair
// and a safe Host journal. It is intended solely for the root-owned transient
// systemd guard installed by install-autostream-host-agent.
func RestartHostAgentFromUpgradeGuard(
	ctx context.Context,
	request HostAgentUpgradeGuardRequest,
) error {
	return restartHostAgentFromUpgradeGuard(ctx, request)
}
