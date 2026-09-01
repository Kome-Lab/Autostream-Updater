//go:build linux

package hostruntime

import (
	"os"
	"strings"
	"testing"
)

func TestManualHostUpgradeLocksFenceLegacyUpdateHostInstaller(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("privileged lock interoperability requires root")
	}

	legacyUnlock, err := lockManualHostUpgradeFile(
		legacyUpdateHostInstallLockPath,
	)
	if err != nil {
		t.Fatalf("lock legacy update-host installer path: %v", err)
	}

	upgradeUnlock, err := acquireManualHostUpgradeLocks()
	if err == nil {
		upgradeUnlock()
		legacyUnlock()
		t.Fatal("manual upgrade acquired locks while legacy installer lock was held")
	}
	if !strings.Contains(err.Error(), "another privileged Host lifecycle operation") {
		legacyUnlock()
		t.Fatalf("unexpected contention error: %v", err)
	}
	legacyUnlock()

	// A failed bridge-lock acquisition must release setup and lifecycle locks.
	upgradeUnlock, err = acquireManualHostUpgradeLocks()
	if err != nil {
		t.Fatalf("manual upgrade locks remained held after contention: %v", err)
	}
	upgradeUnlock()
}
