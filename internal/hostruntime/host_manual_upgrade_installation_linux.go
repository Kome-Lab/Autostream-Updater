//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

func validateManualHostUpgradeInstallation(
	ctx context.Context,
	artifactRoot string,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradeSnapshot, error) {
	for _, path := range []string{
		rt.paths.stagedIdentityPath,
		rt.paths.wipingIdentityPath,
	} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return manualHostUpgradeSnapshot{}, errors.New(
				"Host Agent identity migration or rotation state blocks upgrade",
			)
		}
	}
	if _, err := LoadManagedBootstrapConfig(
		rt.paths.identityPath, !rt.allowTestPaths,
	); err != nil {
		return manualHostUpgradeSnapshot{}, errors.New(
			"managed Host Agent identity is unavailable or unsafe",
		)
	}
	executorPolicy, err := LoadLocalExecutorPolicy(
		rt.paths.policyPath, !rt.allowTestPaths,
	)
	if err != nil {
		return manualHostUpgradeSnapshot{}, errors.New(
			"managed Local Executor policy is unavailable or unsafe",
		)
	}
	identity, err := snapshotManualHostUpgradeFile(rt.paths.identityPath)
	if err != nil {
		return manualHostUpgradeSnapshot{}, err
	}
	policy, err := snapshotManualHostUpgradeFile(rt.paths.policyPath)
	if err != nil {
		return manualHostUpgradeSnapshot{}, err
	}
	var (
		legacyHelperConfig        HelperConfig
		legacyHelperConfigFile    secureManualHostUpgradeFile
		legacyHelperConfigPresent bool
	)
	if _, statErr := os.Lstat(rt.paths.legacyHelperConfigPath); statErr == nil {
		legacyHelperConfig, err = LoadHelperConfig(
			rt.paths.legacyHelperConfigPath,
			!rt.allowTestPaths,
		)
		if err != nil {
			return manualHostUpgradeSnapshot{}, errors.New(
				"legacy update helper configuration is unsafe",
			)
		}
		legacyHelperConfigFile, err = snapshotManualHostUpgradeFile(
			rt.paths.legacyHelperConfigPath,
		)
		if err != nil {
			return manualHostUpgradeSnapshot{}, err
		}
		legacyHelperConfigPresent = true
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return manualHostUpgradeSnapshot{}, errors.New(
			"legacy update helper configuration is unsafe",
		)
	}
	publicLinks := make([]secureManualHostUpgradeLink, 0, 2)
	for _, link := range []struct {
		path   string
		target string
	}{
		{rt.paths.publicAgentPath, filepath.Join(
			rt.selfUpdate.currentLink, "bin", "autostream-host-agent",
		)},
		{rt.paths.publicExecutorPath, filepath.Join(
			rt.selfUpdate.currentLink, "bin", "autostream-local-executor",
		)},
	} {
		protected, linkErr := snapshotManualHostUpgradePublicLink(
			link.path,
			link.target,
			rt.allowTestPaths,
		)
		if linkErr != nil {
			return manualHostUpgradeSnapshot{}, linkErr
		}
		publicLinks = append(publicLinks, protected)
	}
	unitPairs := [][2]string{
		{rt.paths.installedAgentUnit, filepath.Join(
			artifactRoot, "systemd", "autostream-host-agent.service",
		)},
		{rt.paths.installedExecutorUnit, filepath.Join(
			artifactRoot, "systemd", "autostream-local-executor.service",
		)},
		{rt.paths.installedExecutorSocket, filepath.Join(
			artifactRoot, "systemd", "autostream-local-executor.socket",
		)},
		{rt.paths.installedExecutorTmpfiles, filepath.Join(
			artifactRoot, "systemd", "autostream-local-executor.tmpfiles",
		)},
		{rt.paths.installedRecoveryService, filepath.Join(
			artifactRoot, "systemd", "autostream-host-self-update-recovery@.service",
		)},
		{rt.paths.installedRecoveryTimer, filepath.Join(
			artifactRoot, "systemd", "autostream-host-self-update-recovery@.timer",
		)},
	}
	installedFiles := make([]secureManualHostUpgradeFile, 0, len(unitPairs))
	var recoveryUnitConfig *manualHostRecoveryUnitMigrationConfig
	recoveryUnitFinal := false
	var executorUnitConfig *manualHostExecutorUnitMigrationConfig
	executorUnitFinal := false
	for _, pair := range unitPairs {
		installed, snapshotErr := snapshotManualHostUpgradeFile(pair[0])
		if snapshotErr != nil {
			return manualHostUpgradeSnapshot{}, errors.New(
				"installed Host runtime unit is unavailable or unsafe",
			)
		}
		source, snapshotErr := snapshotManualHostUpgradeFile(pair[1])
		if snapshotErr != nil {
			return manualHostUpgradeSnapshot{}, errors.New(
				"manual Host runtime upgrade requires unchanged systemd unit templates",
			)
		}
		if pair[0] == rt.paths.installedExecutorUnit &&
			manualHostExecutorUnitDigestIsCorrected(source.digest) {
			config := manualHostExecutorUnitMigrationConfig{
				CandidatePath:  pair[1],
				InstalledPath:  pair[0],
				Runner:         rt.runner,
				AllowTestPaths: rt.allowTestPaths,
				SyncDirectory:  rt.selfUpdate.syncDir,
			}
			if err := prepareManualHostExecutorUnitMigrationConfig(&config); err != nil {
				return manualHostUpgradeSnapshot{}, err
			}
			executorSnapshot, inspectErr := inspectManualHostExecutorUnitMigration(
				ctx, config,
			)
			if inspectErr != nil {
				return manualHostUpgradeSnapshot{}, inspectErr
			}
			executorUnitConfig = &config
			executorUnitFinal = manualHostExecutorUnitMigrationIsFinal(executorSnapshot)
		} else if pair[0] == rt.paths.installedRecoveryService &&
			manualHostRecoveryUnitDigestIsCorrected(source.digest) {
			config := manualHostRecoveryUnitMigrationConfig{
				CandidatePath:  pair[1],
				InstalledPath:  pair[0],
				Runner:         rt.runner,
				AllowTestPaths: rt.allowTestPaths,
				SyncDirectory:  rt.selfUpdate.syncDir,
			}
			if err := prepareManualHostRecoveryUnitMigrationConfig(&config); err != nil {
				return manualHostUpgradeSnapshot{}, err
			}
			recoverySnapshot, inspectErr := inspectManualHostRecoveryUnitMigration(
				ctx, config,
			)
			if inspectErr != nil {
				return manualHostUpgradeSnapshot{}, inspectErr
			}
			recoveryUnitConfig = &config
			recoveryUnitFinal =
				manualHostRecoveryUnitDigestIsCorrected(
					recoverySnapshot.installed.digest,
				) &&
					!recoverySnapshot.dropInDir.present &&
					len(recoverySnapshot.dropIns) == 0 &&
					manualHostRecoveryUnitEffectiveIsFinal(recoverySnapshot.effective)
		} else if installed.digest != source.digest {
			return manualHostUpgradeSnapshot{}, errors.New(
				"manual Host runtime upgrade requires unchanged systemd unit templates",
			)
		}
		if !rt.allowTestPaths &&
			(installed.info.Mode().Perm() != 0o644 || !isRootOwner(installed.info)) {
			return manualHostUpgradeSnapshot{}, errors.New(
				"installed Host runtime unit ownership or mode is unsafe",
			)
		}
		installedFiles = append(installedFiles, installed)
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{rt.selfUpdate.installRoot, 0o755},
		{rt.selfUpdate.slotsRoot, 0o755},
	} {
		info, statErr := os.Lstat(directory.path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			(!rt.allowTestPaths &&
				(info.Mode().Perm() != directory.mode || !isRootOwner(info) ||
					validateSecureRootPath(directory.path, true) != nil)) {
			return manualHostUpgradeSnapshot{}, errors.New(
				"managed Host runtime directory layout is unsafe",
			)
		}
	}
	stateParent, stateRoot, err := snapshotManualHostUpgradeStateLayout(rt)
	if err != nil {
		return manualHostUpgradeSnapshot{}, err
	}
	return manualHostUpgradeSnapshot{
		identity: identity, policy: policy, executorPolicy: executorPolicy,
		installedFiles:            installedFiles,
		publicLinks:               publicLinks,
		stateParent:               stateParent,
		stateRoot:                 stateRoot,
		recoveryUnitConfig:        recoveryUnitConfig,
		recoveryUnitFinal:         recoveryUnitFinal,
		executorUnitConfig:        executorUnitConfig,
		executorUnitFinal:         executorUnitFinal,
		legacyHelperConfig:        legacyHelperConfig,
		legacyHelperConfigFile:    legacyHelperConfigFile,
		legacyHelperConfigPresent: legacyHelperConfigPresent,
	}, nil
}

func snapshotManualHostUpgradeStateLayout(
	rt manualHostUpgradeRuntime,
) (secureManualHostUpgradeDirectory, secureManualHostUpgradeDirectory, error) {
	parentPath := filepath.Clean(rt.paths.localExecutorStateRoot)
	stateRootPath := filepath.Clean(rt.selfUpdate.stateRoot)
	if !filepath.IsAbs(parentPath) || !filepath.IsAbs(stateRootPath) ||
		stateRootPath != filepath.Join(parentPath, "host-self-update") {
		return secureManualHostUpgradeDirectory{},
			secureManualHostUpgradeDirectory{},
			errors.New("managed Host runtime state root is outside its exact parent")
	}
	parent, err := snapshotManualHostUpgradeDirectory(
		parentPath, 0o700, rt.allowTestPaths,
	)
	if err != nil {
		return secureManualHostUpgradeDirectory{},
			secureManualHostUpgradeDirectory{},
			errors.New("managed Host runtime state parent is unsafe")
	}
	stateRoot, err := snapshotManualHostUpgradeDirectory(
		stateRootPath, 0o700, rt.allowTestPaths,
	)
	if errors.Is(err, os.ErrNotExist) {
		return parent, secureManualHostUpgradeDirectory{
			path: stateRootPath,
			mode: 0o700,
		}, nil
	}
	if err != nil {
		return secureManualHostUpgradeDirectory{},
			secureManualHostUpgradeDirectory{},
			errors.New("managed Host runtime state root is unsafe")
	}
	return parent, stateRoot, nil
}

func migrateManualHostUpgradeRecoveryUnit(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
) (manualHostUpgradeSnapshot, error) {
	if snapshot.recoveryUnitConfig == nil || snapshot.recoveryUnitFinal {
		return snapshot, nil
	}
	if err := migrateManualHostRecoveryUnitForward(
		ctx, *snapshot.recoveryUnitConfig,
	); err != nil {
		return snapshot, err
	}
	installed, err := snapshotManualHostUpgradeFile(
		snapshot.recoveryUnitConfig.InstalledPath,
	)
	if err != nil || !manualHostRecoveryUnitDigestIsCorrected(installed.digest) {
		return snapshot, errors.New(
			"snapshot corrected Host recovery unit after migration",
		)
	}
	replaced := false
	for index := range snapshot.installedFiles {
		if snapshot.installedFiles[index].path ==
			snapshot.recoveryUnitConfig.InstalledPath {
			snapshot.installedFiles[index] = installed
			replaced = true
			break
		}
	}
	if !replaced {
		return snapshot, errors.New(
			"Host recovery unit migration snapshot is incomplete",
		)
	}
	snapshot.recoveryUnitFinal = true
	return snapshot, nil
}

func migrateManualHostUpgradeExecutorUnit(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
) (manualHostUpgradeSnapshot, error) {
	if snapshot.executorUnitConfig == nil || snapshot.executorUnitFinal {
		return snapshot, nil
	}
	if err := migrateManualHostExecutorUnitForward(
		ctx, *snapshot.executorUnitConfig,
	); err != nil {
		return snapshot, err
	}
	installed, err := snapshotManualHostUpgradeFile(
		snapshot.executorUnitConfig.InstalledPath,
	)
	if err != nil || !manualHostExecutorUnitDigestIsCorrected(installed.digest) {
		return snapshot, errors.New(
			"snapshot corrected Local Executor unit after migration",
		)
	}
	replaced := false
	for index := range snapshot.installedFiles {
		if snapshot.installedFiles[index].path ==
			snapshot.executorUnitConfig.InstalledPath {
			snapshot.installedFiles[index] = installed
			replaced = true
			break
		}
	}
	if !replaced {
		return snapshot, errors.New(
			"Local Executor unit migration snapshot is incomplete",
		)
	}
	snapshot.executorUnitFinal = true
	return snapshot, nil
}
