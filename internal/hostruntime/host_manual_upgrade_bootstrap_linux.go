//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func stopManualHostAgent(ctx context.Context, rt manualHostUpgradeRuntime) error {
	if _, err := rt.runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl",
		"stop", hostSelfUpdateServiceUnit,
	); err != nil {
		return errors.New("stop Host Agent for manual runtime upgrade")
	}
	if err := requireManualHostSystemdState(
		ctx, rt.runner, "is-active", hostSelfUpdateServiceUnit, "inactive",
	); err != nil {
		return errors.New("Host Agent did not become inactive for manual runtime upgrade")
	}
	return nil
}

func manualHostUpgradeSlotExists(
	slot string,
	rt manualHostUpgradeRuntime,
) (bool, error) {
	if !validHostSelfUpdateSlot(slot) {
		return false, errors.New("manual Host runtime pending slot is invalid")
	}
	path := filepath.Join(rt.selfUpdate.slotsRoot, slot)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, errors.New("inspect manual Host runtime pending slot")
	}
	if err := rt.selfUpdate.validateHostSelfUpdateSlotTree(slot); err != nil {
		return false, errors.New("manual Host runtime inactive slot is unsafe")
	}
	return true, nil
}

func persistManualHostUpgradeBootstrapState(
	state HostSelfUpdateState,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradeSnapshot, error) {
	updated, err := ensureManualHostUpgradeBootstrapStateRoot(snapshot, rt)
	if err != nil {
		return snapshot, err
	}
	if err := rt.selfUpdate.saveState(state); err != nil {
		restoreErr := restoreManualHostUpgradeOriginalState(
			state, false, updated, rt,
		)
		return snapshot, errors.Join(
			fmt.Errorf("persist bootstrap Host runtime stable state: %w", err),
			restoreErr,
		)
	}
	return updated, nil
}

func ensureManualHostUpgradeBootstrapStateRoot(
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradeSnapshot, error) {
	if snapshot.stateRoot.present {
		if !manualHostUpgradeDirectoryMatches(
			snapshot.stateParent, rt.allowTestPaths,
		) || !manualHostUpgradeDirectoryMatches(
			snapshot.stateRoot, rt.allowTestPaths,
		) {
			return snapshot, errors.New(
				"managed Host runtime state layout changed before bootstrap persistence",
			)
		}
		return snapshot, nil
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) {
		return snapshot, errors.New(
			"managed Host runtime state parent changed before bootstrap persistence",
		)
	}
	if err := rt.mkdirStateRoot(snapshot.stateRoot.path, 0o700); err != nil {
		return snapshot, fmt.Errorf(
			"create bootstrap Host self-update state root: %w", err,
		)
	}
	createdInfo, err := os.Lstat(snapshot.stateRoot.path)
	if err != nil {
		return snapshot, errors.New(
			"inspect created bootstrap Host self-update state root",
		)
	}
	snapshot.stateRoot.info = createdInfo
	snapshot.stateRoot.present = true
	snapshot.stateRoot.created = true
	fail := func(cause error) (manualHostUpgradeSnapshot, error) {
		cleanupErr := cleanupManualHostUpgradeCreatedStateRoot(snapshot, rt)
		return snapshot, errors.Join(cause, cleanupErr)
	}
	if err := validateManualHostUpgradeDirectoryInfo(
		snapshot.stateRoot.path,
		createdInfo,
		snapshot.stateRoot.mode,
		rt.allowTestPaths,
	); err != nil {
		return fail(errors.New(
			"created bootstrap Host self-update state root is unsafe",
		))
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) {
		return fail(errors.New(
			"managed Host runtime state parent changed during root creation",
		))
	}
	if err := syncManualHostUpgradeDirectory(
		snapshot.stateRoot.path, rt,
	); err != nil {
		return fail(fmt.Errorf(
			"sync bootstrap Host self-update state root: %w", err,
		))
	}
	if err := syncManualHostUpgradeDirectory(
		snapshot.stateParent.path, rt,
	); err != nil {
		return fail(fmt.Errorf(
			"sync bootstrap Host self-update state parent: %w", err,
		))
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) || !manualHostUpgradeDirectoryMatches(
		snapshot.stateRoot, rt.allowTestPaths,
	) {
		return fail(errors.New(
			"bootstrap Host self-update state layout changed after sync",
		))
	}
	return snapshot, nil
}

func cleanupManualHostUpgradeCreatedStateRoot(
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	created := snapshot.stateRoot
	if !created.created {
		return nil
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) || !manualHostUpgradeDirectoryMatches(
		created, rt.allowTestPaths,
	) {
		return errors.New(
			"created bootstrap Host self-update state root is not safely removable",
		)
	}
	entries, err := os.ReadDir(created.path)
	if err != nil || len(entries) != 0 {
		return errors.New(
			"created bootstrap Host self-update state root is not empty",
		)
	}
	if err := os.Remove(created.path); err != nil {
		return errors.New("remove created bootstrap Host self-update state root")
	}
	if err := syncManualHostUpgradeDirectory(
		snapshot.stateParent.path, rt,
	); err != nil {
		return fmt.Errorf(
			"sync created bootstrap Host self-update state root removal: %w", err,
		)
	}
	if _, err := os.Lstat(created.path); !errors.Is(err, os.ErrNotExist) {
		return errors.New(
			"created bootstrap Host self-update state root still exists",
		)
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) {
		return errors.New(
			"managed Host runtime state parent changed during root removal",
		)
	}
	return nil
}

func syncManualHostUpgradeDirectory(
	path string,
	rt manualHostUpgradeRuntime,
) error {
	if rt.selfUpdate.syncDir != nil {
		return rt.selfUpdate.syncDir(path)
	}
	return syncDirectory(path)
}

func restoreManualHostUpgradeOriginalState(
	state HostSelfUpdateState,
	originallyPersisted bool,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	current, err := rt.selfUpdate.loadPersistedState()
	if originallyPersisted {
		if err != nil || current != state {
			return errors.New("original Host self-update state changed during recovery")
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return cleanupManualHostUpgradeCreatedStateRoot(snapshot, rt)
	}
	if err != nil || current != state {
		return errors.New("temporary Host self-update state is not safely removable")
	}
	if err := os.Remove(rt.selfUpdate.statePath); err != nil {
		return errors.New("remove temporary bootstrap Host self-update state")
	}
	if err := syncManualHostUpgradeDirectory(rt.selfUpdate.stateRoot, rt); err != nil {
		return errors.New("sync temporary bootstrap Host self-update state removal")
	}
	if _, err := os.Lstat(rt.selfUpdate.statePath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("temporary bootstrap Host self-update state still exists")
	}
	return cleanupManualHostUpgradeCreatedStateRoot(snapshot, rt)
}

func recoverManualHostUpgradeBeforeFence(
	ctx context.Context,
	state HostSelfUpdateState,
	originallyPersisted bool,
	healthy manualHostRuntimeObservation,
	snapshot manualHostUpgradeSnapshot,
	agentStoppedForRecovery bool,
	rt manualHostUpgradeRuntime,
) error {
	currentState, err := rt.selfUpdate.loadPersistedState()
	if err != nil || currentState != state {
		return errors.New("stable Host self-update recovery state is unavailable")
	}
	if err := rt.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return fmt.Errorf("recover manual Host runtime candidate before activation: %w", err)
	}
	if err := rejectManualHostUpgradeTransitionResidue(rt.selfUpdate); err != nil {
		return err
	}
	currentSlot, err := rt.selfUpdate.readCurrentSlot()
	if err != nil || currentSlot != healthy.Slot {
		return errors.New("manual Host runtime current slot changed before recovery")
	}
	actual, err := observeManualHostRuntimeForUpgrade(
		ctx,
		healthy.Slot,
		agentStoppedForRecovery,
		rt,
	)
	if err != nil || actual != healthy {
		return errors.New("healthy Host runtime changed during pre-activation recovery")
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return err
	}
	return restoreManualHostUpgradeOriginalState(
		state, originallyPersisted, snapshot, rt,
	)
}
