//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

func upgradeHostRuntimeFromVerifiedBundle(
	ctx context.Context,
	request ManualHostUpgradeRequest,
) (ManualHostUpgradeResult, error) {
	if os.Geteuid() != 0 {
		return ManualHostUpgradeResult{}, errors.New(
			"manual Host runtime upgrade requires root",
		)
	}
	return upgradeHostRuntimeWithRuntime(
		ctx,
		request,
		defaultManualHostUpgradeRuntime(),
	)
}

func upgradeHostRuntimeWithRuntime(
	ctx context.Context,
	input ManualHostUpgradeRequest,
	rt manualHostUpgradeRuntime,
) (ManualHostUpgradeResult, error) {
	if err := prepareManualHostUpgradeRuntime(&rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	artifact, err := inspectManualHostUpgradeArtifact(ctx, input, rt)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	request, err := newManualHostSelfUpdateRequest(artifact, input)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}

	unlock, err := rt.acquireLocks()
	if err != nil {
		return ManualHostUpgradeResult{}, errors.New(
			"another Host runtime setup or lifecycle operation is active",
		)
	}
	defer unlock()

	snapshot, err := validateManualHostUpgradeInstallation(ctx, input.ArtifactRoot, rt)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	targetsUnlock, err := rt.acquireTargetLocks(
		snapshot.executorPolicy,
		snapshot.legacyHelperConfig.Targets,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, errors.New(
			"another managed target mutation is active",
		)
	}
	defer targetsUnlock()
	if err := validateManualHostUpgradeCoreServicePreconditions(
		ctx,
		rt,
		input.AgentStoppedForRecovery,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := validateManualHostUpgradeRecoveryServicePreconditions(
		ctx, rt, true,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	currentSlot, err := rt.selfUpdate.readCurrentSlot()
	if err != nil {
		return ManualHostUpgradeResult{}, errors.New(
			"managed Host runtime current slot is invalid",
		)
	}
	current, err := observeManualHostRuntimeForUpgrade(
		ctx,
		currentSlot,
		input.AgentStoppedForRecovery,
		rt,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	state, persisted, err := loadManualHostUpgradeState(current, rt)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := validateManualHostUpgradeCurrentState(
		ctx, current, state, persisted, rt,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := validateManualHostUpgradeRecoveryServicePreconditions(
		ctx,
		rt,
		!persisted && snapshot.recoveryUnitConfig != nil,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := inspectManualHostUpgradeDurableBlockers(
		ctx,
		state,
		snapshot.executorPolicy,
		snapshot.legacyHelperConfig.Targets,
		!persisted,
		rt,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}

	targetDigests, err := hostSelfUpdateArtifactBinaryDigests(
		input.ArtifactRoot,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, errors.New(
			"verified Host runtime bundle binaries are unavailable",
		)
	}
	if current.Agent.Version != current.Executor.Version ||
		current.Agent.Commit != current.Executor.Commit ||
		current.Agent.BuildDate != current.Executor.BuildDate {
		return ManualHostUpgradeResult{}, errors.New(
			"installed Host Agent and Local Executor are a mixed runtime",
		)
	}
	sameVersion := request.AgentVersion == current.Agent.Version
	if sameVersion {
		exact, exactErr := manualHostUpgradeAlreadyCurrent(
			currentSlot, current, request, targetDigests, rt,
		)
		if exactErr != nil {
			return ManualHostUpgradeResult{}, exactErr
		}
		if !exact {
			return ManualHostUpgradeResult{}, errors.New(
				"same-version Host runtime content drift is not upgradeable",
			)
		}
	} else if !updaterReleaseSemverAtLeast(
		request.AgentVersion,
		current.Agent.Version,
	) {
		return ManualHostUpgradeResult{}, errors.New(
			"manual Host runtime downgrade is rejected",
		)
	}
	if err := rt.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return ManualHostUpgradeResult{}, fmt.Errorf(
			"recover interrupted Host runtime slot transition: %w", err,
		)
	}
	if err := rejectManualHostUpgradeTransitionResidue(rt.selfUpdate); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if sameVersion {
		executorUnitNeedsRestart := snapshot.executorUnitConfig != nil &&
			!snapshot.executorUnitFinal
		if snapshot.recoveryUnitConfig != nil && !snapshot.recoveryUnitFinal {
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
			recheckedArtifact, recheckErr := inspectManualHostUpgradeArtifact(
				ctx, input, rt,
			)
			if recheckErr != nil || recheckedArtifact != artifact {
				return ManualHostUpgradeResult{}, errors.New(
					"verified Host runtime bundle changed before recovery unit migration",
				)
			}
			if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
				slot != currentSlot {
				return ManualHostUpgradeResult{}, errors.New(
					"managed Host runtime current slot changed before recovery unit migration",
				)
			}
			snapshot, err = migrateManualHostUpgradeRecoveryUnit(ctx, snapshot)
			if err != nil {
				return ManualHostUpgradeResult{}, err
			}
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		if snapshot.executorUnitConfig != nil && !snapshot.executorUnitFinal {
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
			recheckedArtifact, recheckErr := inspectManualHostUpgradeArtifact(
				ctx, input, rt,
			)
			if recheckErr != nil || recheckedArtifact != artifact {
				return ManualHostUpgradeResult{}, errors.New(
					"verified Host runtime bundle changed before Local Executor unit migration",
				)
			}
			if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
				slot != currentSlot {
				return ManualHostUpgradeResult{}, errors.New(
					"managed Host runtime current slot changed before Local Executor unit migration",
				)
			}
			snapshot, err = migrateManualHostUpgradeExecutorUnit(ctx, snapshot)
			if err != nil {
				return ManualHostUpgradeResult{}, err
			}
			if executorUnitNeedsRestart {
				if err := restartManualHostUpgradeLocalExecutor(ctx, currentSlot, current.Executor, rt); err != nil {
					return ManualHostUpgradeResult{}, err
				}
				executorUnitNeedsRestart = false
			}
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		if executorUnitNeedsRestart {
			if err := restartManualHostUpgradeLocalExecutor(ctx, currentSlot, current.Executor, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		if !persisted && snapshot.recoveryUnitConfig != nil {
			if err := normalizeManualHostUpgradeRecoveryServices(
				ctx, snapshot, rt,
			); err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		if !persisted {
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
			recheckedArtifact, err := inspectManualHostUpgradeArtifact(
				ctx, input, rt,
			)
			if err != nil || recheckedArtifact != artifact {
				return ManualHostUpgradeResult{}, errors.New(
					"verified Host runtime bundle changed before bootstrap persistence",
				)
			}
			if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
				slot != currentSlot {
				return ManualHostUpgradeResult{}, errors.New(
					"managed Host runtime current slot changed before bootstrap persistence",
				)
			}
			snapshot, err = persistManualHostUpgradeBootstrapState(
				state, snapshot, rt,
			)
			if err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		return ManualHostUpgradeResult{
			PreviousSlot:   currentSlot,
			ActiveSlot:     currentSlot,
			Version:        request.AgentVersion,
			AlreadyCurrent: true,
		}, nil
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	recheckedArtifact, err := inspectManualHostUpgradeArtifact(ctx, input, rt)
	if err != nil || recheckedArtifact != artifact {
		return ManualHostUpgradeResult{}, errors.New(
			"verified Host runtime bundle changed before staging",
		)
	}
	if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
		slot != currentSlot {
		return ManualHostUpgradeResult{}, errors.New(
			"managed Host runtime current slot changed before staging",
		)
	}
	snapshot, err = migrateManualHostUpgradeRecoveryUnit(ctx, snapshot)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	recheckedArtifact, err = inspectManualHostUpgradeArtifact(ctx, input, rt)
	if err != nil || recheckedArtifact != artifact {
		return ManualHostUpgradeResult{}, errors.New(
			"verified Host runtime bundle changed after recovery unit migration",
		)
	}
	if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
		slot != currentSlot {
		return ManualHostUpgradeResult{}, errors.New(
			"managed Host runtime current slot changed after recovery unit migration",
		)
	}
	snapshot, err = migrateManualHostUpgradeExecutorUnit(ctx, snapshot)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	recheckedArtifact, err = inspectManualHostUpgradeArtifact(ctx, input, rt)
	if err != nil || recheckedArtifact != artifact {
		return ManualHostUpgradeResult{}, errors.New(
			"verified Host runtime bundle changed after Local Executor unit migration",
		)
	}
	if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
		slot != currentSlot {
		return ManualHostUpgradeResult{}, errors.New(
			"managed Host runtime current slot changed after Local Executor unit migration",
		)
	}
	if !persisted && snapshot.recoveryUnitConfig != nil {
		if err := normalizeManualHostUpgradeRecoveryServices(
			ctx, snapshot, rt,
		); err != nil {
			return ManualHostUpgradeResult{}, err
		}
	}

	staged, err := StageHostSelfUpdate(
		state, request, HostLifecycleBlockers{}, targetDigests,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, fmt.Errorf(
			"stage manual Host runtime state: %w", err,
		)
	}
	_, err = manualHostUpgradeSlotExists(
		staged.PendingSlot, rt,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	statePersistedInitially := persisted
	if !persisted {
		snapshot, err = persistManualHostUpgradeBootstrapState(
			state, snapshot, rt,
		)
		if err != nil {
			return ManualHostUpgradeResult{}, err
		}
		persisted = true
	}
	abortBeforeFence := func(cause error) (ManualHostUpgradeResult, error) {
		recoveryCtx, cancel := context.WithTimeout(
			context.Background(), manualHostUpgradeRecoveryTimeout,
		)
		defer cancel()
		recoveryErr := recoverManualHostUpgradeBeforeFence(
			recoveryCtx,
			state,
			statePersistedInitially,
			current,
			snapshot,
			input.AgentStoppedForRecovery,
			rt,
		)
		return ManualHostUpgradeResult{}, errors.Join(cause, recoveryErr)
	}
	if err := rt.selfUpdate.stageSlot(
		ctx,
		staged.PendingSlot,
		input.ArtifactRoot,
		request,
		targetDigests,
	); err != nil {
		return abortBeforeFence(fmt.Errorf(
			"stage manual Host runtime slot: %w", err,
		))
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return abortBeforeFence(err)
	}
	activating, err := BeginHostSelfUpdateActivation(
		staged,
		rt.now().UTC(),
		rt.selfUpdate.verificationTimeout,
	)
	if err != nil {
		return abortBeforeFence(err)
	}
	rollbackAfterFence := func(cause error) (ManualHostUpgradeResult, error) {
		rollbackCtx, cancel := context.WithTimeout(
			context.Background(), manualHostUpgradeRecoveryTimeout,
		)
		defer cancel()
		rollbackErr := rollbackManualHostUpgrade(
			rollbackCtx, activating, current, rt,
		)
		return ManualHostUpgradeResult{}, errors.Join(cause, rollbackErr)
	}
	if err := rt.selfUpdate.saveState(activating); err != nil {
		return rollbackAfterFence(fmt.Errorf(
			"persist manual Host runtime activation fence: %w", err,
		))
	}
	if err := rt.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return rollbackAfterFence(fmt.Errorf(
			"promote manual Host runtime candidate slot: %w", err,
		))
	}
	remainingActivationTime := activating.ActivationDeadline.Sub(rt.now().UTC())
	if remainingActivationTime <= 0 {
		return rollbackAfterFence(errors.New(
			"manual Host runtime activation deadline expired",
		))
	}
	postFenceCtx, cancelPostFence := context.WithTimeout(
		ctx,
		remainingActivationTime,
	)
	defer cancelPostFence()
	if err := verifyManualHostUpgradeSnapshot(postFenceCtx, snapshot, rt); err != nil {
		return rollbackAfterFence(err)
	}
	if err := stopManualHostAgent(postFenceCtx, rt); err != nil {
		return rollbackAfterFence(err)
	}
	if err := inspectManualHostUpgradeDurableBlockers(
		postFenceCtx,
		activating,
		snapshot.executorPolicy,
		snapshot.legacyHelperConfig.Targets,
		false,
		rt,
	); err != nil {
		return rollbackAfterFence(err)
	}
	if err := verifyManualHostUpgradeSnapshot(postFenceCtx, snapshot, rt); err != nil {
		return rollbackAfterFence(err)
	}
	recheckedArtifact, err = inspectManualHostUpgradeArtifact(postFenceCtx, input, rt)
	if err != nil || recheckedArtifact != artifact {
		return rollbackAfterFence(errors.New(
			"verified Host runtime bundle changed before activation",
		))
	}
	if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
		slot != currentSlot {
		return rollbackAfterFence(errors.New(
			"managed Host runtime current slot changed before activation",
		))
	}
	if err := activateManualHostUpgrade(
		postFenceCtx, activating, request, snapshot, rt,
	); err != nil {
		return rollbackAfterFence(err)
	}
	return ManualHostUpgradeResult{
		PreviousSlot: currentSlot,
		ActiveSlot:   activating.PendingSlot,
		Version:      request.AgentVersion,
	}, nil
}

func prepareManualHostUpgradeRuntime(rt *manualHostUpgradeRuntime) error {
	if rt == nil {
		return errors.New("manual Host runtime upgrade is unavailable")
	}
	if rt.runner == nil {
		rt.runner = OSCommandRunner{NewProcessGroup: true}
	}
	if rt.identityRunner == nil {
		rt.identityRunner = rt.runner
	}
	if rt.now == nil {
		rt.now = time.Now
	}
	if rt.waitStable == nil {
		rt.waitStable = rt.selfUpdate.waitExecutorStable
	}
	if rt.resolveProcessExe == nil {
		rt.resolveProcessExe = rt.selfUpdate.resolveProcessExe
	}
	if rt.mkdirStateRoot == nil {
		rt.mkdirStateRoot = os.Mkdir
	}
	if rt.acquireTargetLocks == nil && rt.allowTestPaths {
		rt.acquireTargetLocks = func(LocalExecutorPolicy, []Target) (func(), error) {
			return func() {}, nil
		}
	}
	if len(rt.fixedCheckpoints) == 0 && !rt.allowTestPaths {
		rt.fixedCheckpoints = manualHostUpgradeFixedSystemdCheckpointTargets()
	}
	if rt.acquireLocks == nil || rt.acquireTargetLocks == nil || rt.waitStable == nil ||
		rt.resolveProcessExe == nil || rt.mkdirStateRoot == nil {
		return errors.New("manual Host runtime upgrade dependencies are incomplete")
	}
	if rt.selfUpdate.verificationTimeout < 30*time.Second ||
		rt.selfUpdate.verificationTimeout > 30*time.Minute {
		return errors.New("manual Host runtime verification timeout is invalid")
	}
	rt.selfUpdate.runner = rt.runner
	rt.selfUpdate.identityRunner = rt.identityRunner
	rt.selfUpdate.resolveProcessExe = rt.resolveProcessExe
	rt.selfUpdate.waitExecutorStable = rt.waitStable
	return nil
}
