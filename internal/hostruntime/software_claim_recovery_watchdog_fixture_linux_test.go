//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type softwareClaimRecoveryWatchdogFixtureRunner struct {
	base       CommandRunner
	unitOutput func(string) string
}

func (r softwareClaimRecoveryWatchdogFixtureRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	if name == "/usr/bin/systemctl" && len(args) > 5 && args[0] == "show" {
		unit := args[len(args)-1]
		for _, slot := range []string{"a", "b"} {
			if unit == "autostream-host-self-update-recovery@"+slot+".service" {
				return r.unitOutput(slot), nil
			}
		}
	}
	return r.base.Run(ctx, dir, env, name, args...)
}

func configureSoftwareClaimRecoveryWatchdogFixture(t *testing.T, fixture *manualHostUpgradeLinuxFixture) (*heldHostLifecycleLock, func(string) string) {
	t.Helper()
	// Preserve the existing synthetic pair identity and all history tests. Its
	// measured slot is bound; the real ordinary installer uses bound b/old a.
	request := validHostSelfUpdateRequest()
	request.AgentVersion, request.ExecutorVersion, request.Commit = manualHostUpgradeTestOldVersion, manualHostUpgradeTestOldVersion, manualHostUpgradeTestOldCommit
	request.Release.Tag, request.Release.Commit = request.AgentVersion, request.Commit
	request.Release.ArchiveAssetName = hostAgentReleaseAssetName(request.AgentVersion, "amd64")
	writeSoftwareClaimRecoveryWatchdogSlotBinding(t, fixture.runtime.selfUpdate.slotsRoot, "a", request)
	manualHostUpgradeLinuxWriteFile(t, fixture.runtime.paths.installedRecoveryService, correctedManualHostRecoveryUnitBytes(t), 0o644)
	lockRoot := filepath.Join(fixture.root, "run", "autostream-updater")
	manualHostUpgradeLinuxMkdir(t, lockRoot, 0o700)
	held, err := acquireHeldHostLifecycleLockAt(filepath.Join(lockRoot, ".autostream-host-lifecycle.lock"), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(held.Release)
	output := func(slot string) string {
		return softwareClaimRecoveryWatchdogUnitTestOutput(slot, fixture.runtime.paths.installedRecoveryService)
	}
	fixture.runtime.runner = softwareClaimRecoveryWatchdogFixtureRunner{base: fixture.runtime.runner, unitOutput: output}
	return held, output
}

func unlockSoftwareClaimRecoveryWatchdogTestFD(t *testing.T, held *heldHostLifecycleLock) {
	t.Helper()
	if held == nil || held.file == nil || syscall.Flock(int(held.file.Fd()), syscall.LOCK_UN) != nil {
		t.Fatal("failed to arrange raw-unlocked private fixture FD")
	}
}

func writeSoftwareClaimRecoveryWatchdogSlotBinding(t *testing.T, slotsRoot, slot string, request HostSelfUpdateRequest) {
	t.Helper()
	root := filepath.Join(slotsRoot, slot)
	digests, err := hostSelfUpdateArtifactBinaryDigests(root)
	if err != nil {
		t.Fatal(err)
	}
	markers, err := hostSelfUpdateSlotMarkers(request, map[string]string{"autostream-host-agent": digests.AgentSHA256, "autostream-local-executor": digests.ExecutorSHA256})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range markers {
		manualHostUpgradeLinuxWriteFile(t, filepath.Join(root, name), data, 0o444)
	}
}

func softwareClaimRecoveryWatchdogExclusionChecks(t *testing.T) {
	softwareClaimRecoveryWatchdogUnitChecks(t)
	softwareClaimRecoveryWatchdogProcessChecks(t)
	softwareClaimRecoveryWatchdogBinaryChecks(t)
	softwareClaimRecoveryWatchdogSnapshotChecks(t)
	softwareClaimRecoveryWatchdogFinalSnapshotChecks(t)
	softwareClaimRecoveryWatchdogLockChecks(t)
	softwareClaimRecoveryWatchdogBootstrapChecks(t)
	for _, name := range []string{"trusted_failed", "trusted_activating_pid_zero", "released_lock", "raw_unlocked_fd", "changed_binary", "changed_marker", "changed_unit", "missing_capability", "deadline"} {
		t.Run("watchdog_exclusion/"+name, func(t *testing.T) {
			fixture, policy, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
			before, err := os.ReadFile(fixture.runtime.selfUpdate.statePath)
			if err != nil {
				t.Fatal(err)
			}
			base := runtime.manual.runner.(softwareClaimRecoveryWatchdogFixtureRunner)
			switch name {
			case "trusted_failed", "trusted_activating_pid_zero":
				state := "failed"
				if name == "trusted_activating_pid_zero" {
					state = "activating"
				}
				original := base.unitOutput
				base.unitOutput = func(slot string) string {
					return strings.Replace(original(slot), "ActiveState=inactive\n", "ActiveState="+state+"\n", 1)
				}
				runtime.manual.runner = base
			case "released_lock":
				runtime.lifecycle.Release()
			case "raw_unlocked_fd":
				unlockSoftwareClaimRecoveryWatchdogTestFD(t, runtime.lifecycle)
			case "changed_binary":
				manualHostUpgradeLinuxWriteFile(t, filepath.Join(fixture.runtime.selfUpdate.slotsRoot, "a", "bin", "autostream-local-executor"), []byte("untrusted binary\n"), 0o755)
			case "changed_marker":
				marker := filepath.Join(fixture.runtime.selfUpdate.slotsRoot, "a", ".commit")
				if err := os.Chmod(marker, 0o644); err != nil {
					t.Fatal(err)
				}
				manualHostUpgradeLinuxWriteFile(t, marker, []byte(strings.Repeat("f", 40)+"\n"), 0o444)
			case "changed_unit":
				manualHostUpgradeLinuxWriteFile(t, fixture.runtime.paths.installedRecoveryService, []byte("[Service]\nExecStart=/untrusted\n"), 0o644)
			case "missing_capability":
				runtime.lifecycle = nil
			}
			ctx := context.Background()
			if name == "deadline" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			proof, err := inspectSoftwareClaimRecoveryRoot(ctx, policy, request, runtime)
			if name == "trusted_failed" || name == "trusted_activating_pid_zero" {
				if err != nil || proof.Validate() != nil || !proof.NoMutation {
					t.Fatalf("trusted held-lock exclusion refused: %v", err)
				}
			} else if err == nil {
				t.Fatal("untrusted watchdog authority returned a proof")
			}
			after, readErr := os.ReadFile(fixture.runtime.selfUpdate.statePath)
			if readErr != nil || string(before) != string(after) || fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 || fixture.runner.recoveryResetFailedCalls != 0 || fixture.runner.recoveryReloads != 0 {
				t.Fatal("inspection changed runtime state or a service")
			}
			if !errors.Is(ctx.Err(), context.Canceled) && name == "deadline" {
				t.Fatal("deadline negative was not selected")
			}
		})
	}
}
