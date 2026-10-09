//go:build linux

package hostruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func softwareClaimRecoveryWatchdogFinalSnapshotChecks(t *testing.T) {
	for _, name := range []string{"stable", "binary_inode", "binary_bytes", "marker", "slot_directory", "current_link", "state", "unit", "absent_slot_appeared", "raw_unlocked_fd"} {
		t.Run("watchdog_final_snapshot/"+name, func(t *testing.T) {
			fixture, _, _, runtime := newSoftwareClaimRecoveryRootHarness(t)
			ctx := context.Background()
			observed, err := observeManualHostRuntimeForUpgrade(ctx, "a", false, runtime.manual)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := inspectSoftwareClaimRecoveryWatchdogs(ctx, runtime.manual, observed, runtime.lifecycle)
			if err != nil {
				t.Fatal(err)
			}
			rootA := filepath.Join(runtime.manual.selfUpdate.slotsRoot, "a")
			binary := filepath.Join(rootA, "bin", "autostream-local-executor")
			switch name {
			case "binary_inode":
				original, openErr := os.Open(binary)
				if openErr != nil {
					t.Fatal(openErr)
				}
				defer original.Close()
				body, err := os.ReadFile(binary)
				if err != nil || os.Remove(binary) != nil {
					t.Fatal("arrange private replacement inode")
				}
				manualHostUpgradeLinuxWriteFile(t, binary, body, 0o755)
			case "binary_bytes":
				manualHostUpgradeLinuxWriteFile(t, binary, []byte("changed executor\n"), 0o755)
			case "marker":
				path := filepath.Join(rootA, ".commit")
				if os.Chmod(path, 0o644) != nil {
					t.Fatal("arrange private marker input")
				}
				manualHostUpgradeLinuxWriteFile(t, path, []byte(strings.Repeat("f", 40)+"\n"), 0o444)
			case "slot_directory":
				if os.Chmod(rootA, 0o777) != nil {
					t.Fatal("arrange private directory input")
				}
			case "current_link":
				if os.Remove(runtime.manual.selfUpdate.currentLink) != nil || os.Symlink("slots/b", runtime.manual.selfUpdate.currentLink) != nil {
					t.Fatal("arrange private current-link input")
				}
			case "state":
				manualHostUpgradeLinuxWriteFile(t, runtime.manual.selfUpdate.statePath, []byte("{}\n"), 0o600)
			case "unit":
				manualHostUpgradeLinuxWriteFile(t, runtime.manual.paths.installedRecoveryService, []byte("[Service]\nExecStart=/foreign\n"), 0o644)
			case "absent_slot_appeared":
				manualHostUpgradeLinuxMkdir(t, filepath.Join(runtime.manual.selfUpdate.slotsRoot, "b"), 0o755)
			case "raw_unlocked_fd":
				unlockSoftwareClaimRecoveryWatchdogTestFD(t, runtime.lifecycle)
			}
			err = snapshot.Verify(ctx, runtime.manual, runtime.lifecycle)
			if name == "stable" && err != nil || name != "stable" && err == nil {
				t.Fatalf("final snapshot stability boundary: %v", err)
			}
			if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 || fixture.runner.recoveryResetFailedCalls != 0 || fixture.runner.recoveryReloads != 0 {
				t.Fatal("read-only snapshot changed a service")
			}
		})
	}
}
