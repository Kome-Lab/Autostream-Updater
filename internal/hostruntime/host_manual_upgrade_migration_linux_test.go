//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManualHostUpgradeMigratesLegacyRecoveryUnitDuringBootstrap(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryFailedUnits[manualHostRecoveryUnitInstances[0]] = true

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || result.ActiveSlot != HostSelfUpdateSlotB ||
		result.PreviousSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("legacy recovery migration result=%+v err=%v", result, err)
	}
	installed, err := os.ReadFile(fixture.runtime.paths.installedRecoveryService)
	if err != nil || manualHostRecoveryUnitDigest(installed) !=
		manualHostRecoveryUnitUpdaterCorrectedDigest {
		t.Fatalf("migrated recovery unit digest=%s err=%v", manualHostRecoveryUnitDigest(installed), err)
	}
	if _, err := os.Lstat(
		fixture.runtime.paths.installedRecoveryService + ".d",
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("known recovery drop-ins remained after upgrade: %v", err)
	}
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"recovery reloads=%d reset-failed=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotB ||
		state.HealthySlot != HostSelfUpdateSlotB {
		t.Fatalf("migrated bootstrap state=%+v err=%v", state, err)
	}
}

func TestManualHostUpgradeMigratesLegacyExecutorUnitDuringBootstrap(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyExecutorUnit(t, fixture)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || result.ActiveSlot != HostSelfUpdateSlotB ||
		result.PreviousSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("legacy executor migration result=%+v err=%v", result, err)
	}
	installed, err := os.ReadFile(fixture.runtime.paths.installedExecutorUnit)
	if err != nil || manualHostExecutorUnitTestDigest(installed) !=
		manualHostExecutorUnitUpdaterCorrectedDigest {
		t.Fatalf("migrated executor unit digest=%s err=%v", manualHostExecutorUnitTestDigest(installed), err)
	}
	if fixture.runner.recoveryReloads != 1 {
		t.Fatalf("executor unit daemon-reload calls=%d, want 1", fixture.runner.recoveryReloads)
	}
	if fmt.Sprint(fixture.runner.restartOrder) !=
		fmt.Sprint([]string{
			hostSelfUpdateExecutorServiceUnit,
			hostSelfUpdateServiceUnit,
		}) {
		t.Fatalf("executor migration restart order=%v", fixture.runner.restartOrder)
	}
}

func TestManualHostUpgradeSameVersionMigratesLegacyExecutorUnit(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	copyManualHostUpgradeArtifactBinariesToSlot(
		t, fixture, HostSelfUpdateSlotA,
	)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyExecutorUnit(t, fixture)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || !result.AlreadyCurrent ||
		result.ActiveSlot != HostSelfUpdateSlotA ||
		result.PreviousSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version executor migration result=%+v err=%v", result, err)
	}
	assertManualHostExecutorUnitCorrected(t, manualHostExecutorUnitFixture{
		installedPath: fixture.runtime.paths.installedExecutorUnit,
	})
	if fmt.Sprint(fixture.runner.restartOrder) !=
		fmt.Sprint([]string{hostSelfUpdateExecutorServiceUnit}) {
		t.Fatalf("same-version executor migration restart order=%v", fixture.runner.restartOrder)
	}
}

func TestManualHostUpgradeDoesNotMigrateRecoveryUnitBeforeBlockerChecks(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	writeManualHostUpgradeLinuxCheckpoint(t, fixture, "started")
	transitionArtifact := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		"."+HostSelfUpdateSlotB+"-111111111111.new",
	)
	manualHostUpgradeLinuxMkdir(t, transitionArtifact, 0o755)
	transitionBefore, err := os.Lstat(transitionArtifact)
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.paths.installedRecoveryService,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked recovery migration result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.paths.installedRecoveryService, legacyBefore,
	)
	if _, err := os.Lstat(
		fixture.runtime.paths.installedRecoveryService + ".d",
	); err != nil {
		t.Fatalf("blocked recovery migration removed known drop-ins: %v", err)
	}
	if fixture.runner.recoveryReloads != 0 ||
		fixture.runner.recoveryResetFailedCalls != 0 {
		t.Fatalf(
			"blocked recovery migration reloaded=%d reset-failed=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.stateRoot,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocked recovery migration created state root: %v", err)
	}
	transitionAfter, err := os.Lstat(transitionArtifact)
	if err != nil || !os.SameFile(transitionBefore, transitionAfter) {
		t.Fatalf("blocked recovery migration changed slot residue: info=%v err=%v", transitionAfter, err)
	}
}

func TestManualHostUpgradeSameVersionMigratesLegacyRecoveryUnit(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	copyManualHostUpgradeArtifactBinariesToSlot(
		t, fixture, HostSelfUpdateSlotA,
	)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryFailedUnits[manualHostRecoveryUnitInstances[0]] = true

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || !result.AlreadyCurrent ||
		result.ActiveSlot != HostSelfUpdateSlotA ||
		result.PreviousSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version recovery migration result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.stopCalls != 0 ||
		len(fixture.runner.restartOrder) != 0 ||
		fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"same-version migration stops=%d restarts=%v reloads=%d reset-failed=%d",
			fixture.runner.stopCalls,
			fixture.runner.restartOrder,
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version migration state=%+v err=%v", state, err)
	}
}

func TestManualHostUpgradeKeepsCorrectedRecoveryUnitAcrossRollbackAndRetry(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryFailedUnits[manualHostRecoveryUnitInstances[0]] = true
	fixture.runner.failTargetAgent = true

	first, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "restart Host Agent") ||
		first != (ManualHostUpgradeResult{}) {
		t.Fatalf("migration rollback result=%+v err=%v", first, err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("migration rollback current=%q err=%v", current, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"migration rollback reloads=%d reset-failed=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}

	fixture.runner.failTargetAgent = false
	retry, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || retry.ActiveSlot != HostSelfUpdateSlotB ||
		retry.PreviousSlot != HostSelfUpdateSlotA || retry.AlreadyCurrent {
		t.Fatalf("migration retry result=%+v err=%v", retry, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"migration retry repeated unit mutation: reloads=%d reset-failed=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
}

func TestManualHostUpgradeRetriesAfterBootstrapResetFailedFailure(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryFailedUnits[manualHostRecoveryUnitInstances[0]] = true
	fixture.runner.failRecoveryReset = true

	first, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "reset failed") ||
		first != (ManualHostUpgradeResult{}) {
		t.Fatalf("reset-failed injection result=%+v err=%v", first, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedAttempts != 1 ||
		fixture.runner.recoveryResetFailedCalls != 0 {
		t.Fatalf(
			"reset-failed first attempt reloads=%d attempts=%d successes=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedAttempts,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.stateRoot,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reset-failed injection created state root: %v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("reset-failed injection current=%q err=%v", current, err)
	}

	fixture.runner.failRecoveryReset = false
	retry, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || retry.ActiveSlot != HostSelfUpdateSlotB ||
		retry.PreviousSlot != HostSelfUpdateSlotA || retry.AlreadyCurrent {
		t.Fatalf("reset-failed retry result=%+v err=%v", retry, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedAttempts != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"reset-failed retry reloads=%d attempts=%d successes=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedAttempts,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
}

func TestManualHostUpgradeRejectsDowngradeBeforeRecoveryMutation(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	copyManualHostUpgradeArtifactBinariesToSlot(
		t, fixture, HostSelfUpdateSlotA,
	)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	configureManualHostUpgradeDowngradeArtifact(t, fixture)
	transitionArtifact := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		"."+HostSelfUpdateSlotB+"-111111111111.new",
	)
	manualHostUpgradeLinuxMkdir(t, transitionArtifact, 0o755)
	transitionBefore, err := os.Lstat(transitionArtifact)
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.paths.installedRecoveryService,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "downgrade") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("downgrade result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.paths.installedRecoveryService, legacyBefore,
	)
	transitionAfter, err := os.Lstat(transitionArtifact)
	if err != nil || !os.SameFile(transitionBefore, transitionAfter) {
		t.Fatalf("downgrade changed slot residue: info=%v err=%v", transitionAfter, err)
	}
	if fixture.runner.recoveryReloads != 0 ||
		fixture.runner.recoveryResetFailedCalls != 0 ||
		fixture.runner.stopCalls != 0 {
		t.Fatalf(
			"downgrade mutated runtime: reloads=%d reset-failed=%d stops=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
			fixture.runner.stopCalls,
		)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.stateRoot,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("downgrade created state root: %v", err)
	}
}

func TestManualHostUpgradeRejectsUnknownRecoveryOverrideBeforeMutation(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryEffectiveExtra = "/run/systemd/system/unknown.conf"
	legacyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.paths.installedRecoveryService,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "unknown effective") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("unknown recovery override result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.paths.installedRecoveryService, legacyBefore,
	)
	if fixture.runner.recoveryReloads != 0 ||
		fixture.runner.recoveryResetFailedCalls != 0 ||
		fixture.runner.stopCalls != 0 {
		t.Fatalf(
			"unknown override mutated runtime: reloads=%d reset-failed=%d stops=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
			fixture.runner.stopCalls,
		)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.stateRoot,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown override created state root: %v", err)
	}
}
