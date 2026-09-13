//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManualHostUpgradeBootstrapsMissingSlotAndCommitsRuntimePair(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil {
		t.Fatalf("upgradeHostRuntimeWithRuntime: %v", err)
	}
	if result.PreviousSlot != HostSelfUpdateSlotA ||
		result.ActiveSlot != HostSelfUpdateSlotB ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("result=%+v", result)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)

	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("current slot=%q err=%v", current, err)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotB ||
		state.HealthySlot != HostSelfUpdateSlotB ||
		state.RollbackSlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion ||
		state.RollbackAgentVersion != manualHostUpgradeTestOldVersion ||
		state.RollbackExecutorVersion != manualHostUpgradeTestOldVersion ||
		state.FailedGeneration != "" || state.PendingGeneration != "" {
		t.Fatalf("persisted state=%+v", state)
	}
	stateRootInfo, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot)
	if err != nil || !stateRootInfo.IsDir() ||
		stateRootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("bootstrapped state root info=%v err=%v", stateRootInfo, err)
	}
	assertManualHostUpgradeLinuxSlotBinding(
		t, fixture, HostSelfUpdateSlotB,
	)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	wantRestartOrder := []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
	}
	if fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(wantRestartOrder) {
		t.Fatalf(
			"restart order=%v want=%v",
			fixture.runner.restartOrder,
			wantRestartOrder,
		)
	}
	if fixture.runner.stopCalls != 1 || fixture.watchdogCalls != 1 ||
		fixture.waitStableCalls < 4 ||
		fixture.runner.mainPIDReads[hostSelfUpdateServiceUnit] < 4 ||
		fixture.runner.mainPIDReads[hostSelfUpdateExecutorServiceUnit] < 4 ||
		fixture.processExeResolves[3101] < 4 ||
		fixture.processExeResolves[3102] < 4 ||
		fixture.runner.identityReads["autostream-host-agent"] < 4 ||
		fixture.runner.identityReads["autostream-local-executor"] < 4 {
		t.Fatalf(
			"strong verification was incomplete: stops=%d watchdog=%d waits=%d pid_reads=%v exe_resolves=%v identity_reads=%v",
			fixture.runner.stopCalls,
			fixture.watchdogCalls,
			fixture.waitStableCalls,
			fixture.runner.mainPIDReads,
			fixture.processExeResolves,
			fixture.runner.identityReads,
		)
	}
}

func TestManualHostUpgradeRollsBackWhenTargetAgentActivationFails(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	fixture.runner.failTargetAgent = true
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "restart Host Agent") {
		t.Fatalf("target Agent activation failure result=%+v err=%v", result, err)
	}
	if result != (ManualHostUpgradeResult{}) {
		t.Fatalf("failed upgrade returned a result: %+v", result)
	}
	if !fixture.runner.targetAgentFailed {
		t.Fatal("target Host Agent failure injection did not execute")
	}
	current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
	if currentErr != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("rollback current slot=%q err=%v", current, currentErr)
	}
	state, stateErr := fixture.runtime.selfUpdate.loadPersistedState()
	if stateErr != nil {
		t.Fatalf("load rollback state: %v", stateErr)
	}
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestOldVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestOldVersion ||
		!strings.HasPrefix(state.FailedGeneration, manualHostUpgradeBindingVersion+"-") ||
		state.PendingGeneration != "" || state.RollbackSlot != "" {
		t.Fatalf("rollback state=%+v", state)
	}
	if info, statErr := os.Lstat(fixture.runtime.selfUpdate.stateRoot); statErr != nil ||
		!info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("post-fence rollback removed bootstrap root: info=%v err=%v", info, statErr)
	}
	assertManualHostUpgradeLinuxSlotBinding(
		t, fixture, HostSelfUpdateSlotB,
	)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)
	wantRestartOrder := []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
	}
	if fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(wantRestartOrder) {
		t.Fatalf(
			"rollback restart order=%v want=%v",
			fixture.runner.restartOrder,
			wantRestartOrder,
		)
	}
	if fixture.watchdogCalls != 2 || fixture.waitStableCalls < 5 {
		t.Fatalf(
			"rollback proof was incomplete: watchdog=%d waits=%d",
			fixture.watchdogCalls,
			fixture.waitStableCalls,
		)
	}
}

func TestManualHostUpgradeRejectsTamperedArtifactBeforeMutation(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	tampered := filepath.Join(
		fixture.artifactRoot,
		"bin",
		"autostream-host-agent",
	)
	if err := os.WriteFile(
		tampered,
		[]byte("target:autostream-host-agent\ntampered\n"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "checksum verification failed") {
		t.Fatalf("tampered artifact err=%v", err)
	}
	if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
		t.Fatalf(
			"artifact rejection mutated services: stops=%d restarts=%v",
			fixture.runner.stopCalls,
			fixture.runner.restartOrder,
		)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotB,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection created slot b: %v", err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection persisted state: %v", err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection created state root: %v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("artifact rejection current slot=%q err=%v", current, err)
	}
}

func TestManualHostUpgradeRejectsDurableBlockerBeforeCreatingStateRoot(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	writeManualHostUpgradeLinuxCheckpoint(t, fixture, "started")

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked upgrade result=%+v err=%v", result, err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocker rejection created state root: %v", err)
	}
	assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
}

func TestManualHostUpgradeRejectsUnsafeBootstrapStateLayout(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*manualHostUpgradeLinuxFixture) error
	}{
		{
			name: "parent mode",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				removeManualHostUpgradeLinuxStateRoot(t, fixture)
				return os.Chmod(fixture.runtime.paths.localExecutorStateRoot, 0o755)
			},
		},
		{
			name: "root mode",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				return os.Chmod(fixture.runtime.selfUpdate.stateRoot, 0o755)
			},
		},
		{
			name: "root symlink",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				removeManualHostUpgradeLinuxStateRoot(t, fixture)
				target := filepath.Join(fixture.root, "unsafe-state-root-target")
				if err := os.Mkdir(target, 0o700); err != nil {
					return err
				}
				return os.Symlink(target, fixture.runtime.selfUpdate.stateRoot)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			if err := test.mutate(fixture); err != nil {
				t.Fatal(err)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil || result != (ManualHostUpgradeResult{}) {
				t.Fatalf("unsafe layout result=%+v err=%v", result, err)
			}
			if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
				t.Fatalf("unsafe layout mutated services: stops=%d restarts=%v", fixture.runner.stopCalls, fixture.runner.restartOrder)
			}
		})
	}
}

func TestManualHostUpgradeRejectsStateRootEEXISTRace(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	mkdirCalls := 0
	fixture.runtime.mkdirStateRoot = func(path string, mode os.FileMode) error {
		mkdirCalls++
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		return os.Mkdir(path, mode)
	}

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if !errors.Is(err, fs.ErrExist) || result != (ManualHostUpgradeResult{}) {
		t.Fatalf("EEXIST race result=%+v err=%v", result, err)
	}
	if mkdirCalls != 1 {
		t.Fatalf("state root mkdir calls=%d want=1", mkdirCalls)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); err != nil {
		t.Fatalf("racing state root was removed: %v", err)
	}
	assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
}

func TestManualHostUpgradeSameVersionPersistsMissingBootstrapState(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		payload, err := os.ReadFile(filepath.Join(fixture.artifactRoot, "bin", binary))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(
				fixture.runtime.selfUpdate.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				binary,
			),
			payload,
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	removeManualHostUpgradeLinuxStateRoot(t, fixture)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || !result.AlreadyCurrent ||
		result.ActiveSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version bootstrap result=%+v err=%v", result, err)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version bootstrap state=%+v err=%v", state, err)
	}
	if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
		t.Fatalf("same-version bootstrap mutated services: stops=%d restarts=%v", fixture.runner.stopCalls, fixture.runner.restartOrder)
	}
}

func TestManualHostUpgradeCleansCreatedStateRootWhenBootstrapFsyncFails(
	t *testing.T,
) {
	for _, failAt := range []string{"child", "parent"} {
		t.Run(failAt, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			removeManualHostUpgradeLinuxStateRoot(t, fixture)
			injected := errors.New("injected bootstrap directory fsync failure")
			failed := false
			fixture.runtime.selfUpdate.syncDir = func(path string) error {
				want := fixture.runtime.selfUpdate.stateRoot
				if failAt == "parent" {
					want = fixture.runtime.paths.localExecutorStateRoot
				}
				if !failed && filepath.Clean(path) == filepath.Clean(want) {
					failed = true
					return injected
				}
				return syncDirectory(path)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if !errors.Is(err, injected) || result != (ManualHostUpgradeResult{}) {
				t.Fatalf("%s fsync result=%+v err=%v", failAt, result, err)
			}
			if !failed {
				t.Fatalf("%s fsync injection was not reached", failAt)
			}
			if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s fsync failure retained created root: %v", failAt, err)
			}
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
		})
	}
}
