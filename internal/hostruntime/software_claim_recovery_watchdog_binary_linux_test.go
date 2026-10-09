//go:build linux

package hostruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func softwareClaimRecoveryWatchdogBinaryChecks(t *testing.T) {
	for _, name := range []string{"live_measured_binary", "same_path_different_inode", "changed_digest", "different_root_slot", "missing_inode"} {
		t.Run("watchdog_binary/"+name, func(t *testing.T) {
			path, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			path, err = filepath.EvalSymlinks(path)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := snapshotSoftwareClaimWatchdogFile(context.Background(), path, 0o755, true)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := os.Stat("/proc/self/exe")
			if err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(t.TempDir(), "executor")
			if err := os.WriteFile(foreign, []byte("different executor\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "same_path_different_inode":
				observed, err = os.Stat(foreign)
				if err != nil {
					t.Fatal(err)
				}
			case "changed_digest":
				expected.digest = strings.Repeat("f", 64)
			case "different_root_slot":
				expected.path = foreign
			case "missing_inode":
				observed = nil
			}
			err = verifySoftwareClaimWatchdogProcessBinary(context.Background(), os.Getpid(), expected, observed, true)
			if name == "live_measured_binary" && err != nil || name != "live_measured_binary" && err == nil {
				t.Fatalf("live inode/digest/root namespace boundary: %v", err)
			}
		})
	}
}
