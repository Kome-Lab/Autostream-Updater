//go:build linux

package hostruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func softwareClaimRecoveryWatchdogBootstrapChecks(t *testing.T) {
	for _, name := range []string{"old_bootstrap_rollback", "unsupported_rollback_commit", "unsupported_rollback_version", "unbound_current_b"} {
		t.Run("watchdog_bootstrap/"+name, func(t *testing.T) {
			fixture, policy, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
			rootA := filepath.Join(runtime.manual.selfUpdate.slotsRoot, "a")
			rootB := filepath.Join(runtime.manual.selfUpdate.slotsRoot, "b")
			bound, _, err := readManualHostUpdateSlotBinding("a", runtime.manual.selfUpdate)
			if err != nil {
				t.Fatal(err)
			}
			beforePair := make(map[string]string)
			for _, binary := range []string{"autostream-host-agent", "autostream-local-executor"} {
				data, err := os.ReadFile(filepath.Join(rootA, "bin", binary))
				if err != nil {
					t.Fatal(err)
				}
				beforePair[binary] = string(data)
				manualHostUpgradeLinuxWriteFile(t, filepath.Join(rootB, "bin", binary), data, 0o755)
			}
			writeSoftwareClaimRecoveryWatchdogSlotBinding(t, runtime.manual.selfUpdate.slotsRoot, "b", bound)
			// Arrange the legitimate old unbound bootstrap input only inside this
			// new synthetic TempDir; product inspection never removes a marker.
			for _, slot := range []string{"a", "b"} {
				if slot == "b" && name != "unbound_current_b" {
					continue
				}
				slotRoot := filepath.Join(runtime.manual.selfUpdate.slotsRoot, slot)
				entries, err := os.ReadDir(slotRoot)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".") {
						if os.Remove(filepath.Join(slotRoot, entry.Name())) != nil {
							t.Fatal("arrange private unbound-slot input")
						}
					}
				}
			}
			if os.Remove(runtime.manual.selfUpdate.currentLink) != nil || os.Symlink(filepath.Join("slots", "b"), runtime.manual.selfUpdate.currentLink) != nil {
				t.Fatal("arrange private current slot b")
			}
			state, err := NewHostSelfUpdateState(manualHostUpgradeTestOldVersion, manualHostUpgradeTestOldVersion)
			if err != nil {
				t.Fatal(err)
			}
			state.ActiveSlot, state.HealthySlot, state.RollbackSlot = "b", "b", "a"
			state.RollbackAgentVersion, state.RollbackExecutorVersion = "v2.0.0", "v2.0.0"
			if runtime.manual.selfUpdate.saveState(state) != nil {
				t.Fatal("arrange private stable rollback state")
			}
			originalIdentity := runtime.manual.identityRunner
			runtime.manual.identityRunner = softwareClaimRecoveryDiagnosticTestRunner(func(ctx context.Context, dir string, env []string, binary string, args ...string) (string, error) {
				output, err := originalIdentity.Run(ctx, dir, env, binary, args...)
				if !pathWithin(rootA, binary) {
					return output, err
				}
				version, commit := "v2.0.0", softwareClaimRecoveryBootstrapCommit
				if name == "unsupported_rollback_commit" {
					commit = strings.Repeat("f", 40)
				}
				if name == "unsupported_rollback_version" {
					version = "v2.0.1"
				}
				output = strings.ReplaceAll(strings.ReplaceAll(output, manualHostUpgradeTestOldVersion, version), manualHostUpgradeTestOldCommit, commit)
				return output, err
			})
			unitRunner := runtime.manual.runner.(softwareClaimRecoveryWatchdogFixtureRunner)
			originalOutput := unitRunner.unitOutput
			unitRunner.unitOutput = func(slot string) string {
				state := "failed"
				if slot == "b" {
					state = "activating"
				}
				return softwareClaimRecoveryWatchdogUnitTestProperty(originalOutput(slot), "ActiveState", state)
			}
			runtime.manual.runner = unitRunner
			stateBefore, err := os.ReadFile(runtime.manual.selfUpdate.statePath)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := inspectSoftwareClaimRecoveryRoot(context.Background(), policy, request, runtime)
			if name == "old_bootstrap_rollback" {
				if err != nil || proof.Validate() != nil || !proof.NoMutation {
					t.Fatalf("preserved old rollback exclusion rejected: %v", err)
				}
				for _, binary := range []string{"autostream-host-agent", "autostream-local-executor"} {
					if fixture.runner.identityReads[binary] != 3 {
						t.Fatal("active pair observation was not reused for bound slot verification")
					}
				}
			} else if err == nil {
				t.Fatal("unreviewed unbound slot returned a proof")
			}
			stateAfter, readErr := os.ReadFile(runtime.manual.selfUpdate.statePath)
			if readErr != nil || string(stateBefore) != string(stateAfter) {
				t.Fatal("inspection changed stable rollback state")
			}
			for binary, before := range beforePair {
				data, err := os.ReadFile(filepath.Join(rootA, "bin", binary))
				if err != nil || string(data) != before {
					t.Fatal("inspection changed old pair bytes")
				}
			}
			if bound, err := runtime.manual.selfUpdate.hostSelfUpdateSlotHasBinding("a"); err != nil || bound {
				t.Fatal("inspection wrote a bootstrap marker")
			}
			if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 || fixture.runner.recoveryResetFailedCalls != 0 || fixture.runner.recoveryReloads != 0 {
				t.Fatal("inspection changed a service")
			}
		})
	}
}
