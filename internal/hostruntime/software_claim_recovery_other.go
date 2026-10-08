//go:build !linux

package hostruntime

import (
	"context"
	"errors"
)

func (LocalExecutorClient) InspectSoftwareClaimRecovery(context.Context, SoftwareClaimRecoveryInspection, LocalExecutorMutationFence) (SoftwareClaimRecoveryProof, error) {
	return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery requires the installed Linux Local Executor")
}

// The managed production runtime is Linux-only. Other platforms retain the
// existing in-process test/control-loop behavior and cannot obtain root proof.
func acquireSoftwareClaimRecoveryLifecycleLock(string) (func(), error) { return func() {}, nil }

func softwareClaimRecoveryIntentBlocksHost(LocalExecutorPolicy) error {
	intent, exists, err := loadSoftwareClaimRecoveryIntent(HostPullAgentStateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || exists && !intent.Settled {
		return errors.New("a terminal-only software claim recovery intent blocks host mutation")
	}
	return nil
}
