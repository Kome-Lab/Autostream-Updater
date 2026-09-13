//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func snapshotManualHostUpgradeDirectory(
	path string,
	mode os.FileMode,
	allowTestPaths bool,
) (secureManualHostUpgradeDirectory, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return secureManualHostUpgradeDirectory{}, err
	}
	if err := validateManualHostUpgradeDirectoryInfo(
		path, info, mode, allowTestPaths,
	); err != nil {
		return secureManualHostUpgradeDirectory{}, err
	}
	return secureManualHostUpgradeDirectory{
		path: path, info: info, mode: mode, present: true,
	}, nil
}

func validateManualHostUpgradeDirectoryInfo(
	path string,
	info os.FileInfo,
	mode os.FileMode,
	allowTestPaths bool,
) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode {
		return errors.New("manual Host runtime directory mode or type is unsafe")
	}
	if !allowTestPaths &&
		(!isRootOwner(info) || validateSecureRootPath(path, true) != nil) {
		return errors.New("manual Host runtime directory ownership is unsafe")
	}
	return nil
}

func snapshotManualHostUpgradeFile(path string) (secureManualHostUpgradeFile, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 ||
		info.Size() > defaultMaxArtifactBytes {
		return secureManualHostUpgradeFile{}, errors.New(
			"manual Host runtime protected file is unsafe",
		)
	}
	digest, err := hashFile(path)
	if err != nil || !isCanonicalBareSHA256(digest) {
		return secureManualHostUpgradeFile{}, errors.New(
			"hash manual Host runtime protected file",
		)
	}
	return secureManualHostUpgradeFile{path: path, info: info, digest: digest}, nil
}

func verifyManualHostUpgradeSnapshot(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, expected := range []secureManualHostUpgradeFile{
		snapshot.identity,
		snapshot.policy,
	} {
		if !manualHostUpgradeProtectedFileMatches(expected) {
			return errors.New(
				"Host Agent identity or Local Executor policy changed during upgrade",
			)
		}
	}
	for _, expected := range snapshot.installedFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !manualHostUpgradeProtectedFileMatches(expected) {
			return errors.New("installed Host runtime unit changed during upgrade")
		}
	}
	for _, expected := range snapshot.publicLinks {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := snapshotManualHostUpgradePublicLink(
			expected.path,
			expected.target,
			rt.allowTestPaths,
		)
		if err != nil || !os.SameFile(expected.info, current.info) ||
			expected.info.Mode() != current.info.Mode() ||
			expected.target != current.target {
			return errors.New("managed Host runtime public binary link changed during upgrade")
		}
	}
	if snapshot.legacyHelperConfigPresent {
		expected := snapshot.legacyHelperConfigFile
		if !manualHostUpgradeProtectedFileMatches(expected) {
			return errors.New("legacy update helper configuration changed during upgrade")
		}
	} else if _, err := os.Lstat(rt.paths.legacyHelperConfigPath); err == nil ||
		!errors.Is(err, os.ErrNotExist) {
		return errors.New("legacy update helper configuration appeared during upgrade")
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) {
		return errors.New("managed Host runtime state parent changed during upgrade")
	}
	if snapshot.stateRoot.present {
		if !manualHostUpgradeDirectoryMatches(
			snapshot.stateRoot, rt.allowTestPaths,
		) {
			return errors.New("managed Host runtime state root changed during upgrade")
		}
	} else if _, err := os.Lstat(snapshot.stateRoot.path); err == nil ||
		!errors.Is(err, os.ErrNotExist) {
		return errors.New("managed Host runtime state root appeared during upgrade")
	}
	if snapshot.recoveryUnitConfig != nil {
		current, err := inspectManualHostRecoveryUnitMigration(
			ctx, *snapshot.recoveryUnitConfig,
		)
		if err != nil {
			return err
		}
		if snapshot.recoveryUnitFinal &&
			(!manualHostRecoveryUnitDigestIsCorrected(current.installed.digest) ||
				current.dropInDir.present ||
				len(current.dropIns) != 0 ||
				!manualHostRecoveryUnitEffectiveIsFinal(current.effective)) {
			return errors.New("corrected Host recovery unit changed during upgrade")
		}
	}
	if snapshot.executorUnitConfig != nil {
		current, err := inspectManualHostExecutorUnitMigration(
			ctx, *snapshot.executorUnitConfig,
		)
		if err != nil {
			return err
		}
		if snapshot.executorUnitFinal &&
			!manualHostExecutorUnitMigrationIsFinal(current) {
			return errors.New("corrected Local Executor unit changed during upgrade")
		}
	}
	return ctx.Err()
}

func manualHostUpgradeDirectoryMatches(
	expected secureManualHostUpgradeDirectory,
	allowTestPaths bool,
) bool {
	if !expected.present || expected.info == nil {
		return false
	}
	current, err := os.Lstat(expected.path)
	return err == nil && os.SameFile(expected.info, current) &&
		expected.info.Mode() == current.Mode() &&
		validateManualHostUpgradeDirectoryInfo(
			expected.path, current, expected.mode, allowTestPaths,
		) == nil
}

func manualHostUpgradeProtectedFileMatches(
	expected secureManualHostUpgradeFile,
) bool {
	current, err := snapshotManualHostUpgradeFile(expected.path)
	return err == nil && os.SameFile(expected.info, current.info) &&
		expected.info.Mode() == current.info.Mode() &&
		expected.info.Size() == current.info.Size() &&
		expected.digest == current.digest
}

func snapshotManualHostUpgradePublicLink(
	path, expectedTarget string,
	allowTestPaths bool,
) (secureManualHostUpgradeLink, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 ||
		(!allowTestPaths &&
			(!isRootOwner(info) ||
				validateSecureRootPath(filepath.Dir(path), true) != nil)) {
		return secureManualHostUpgradeLink{}, errors.New(
			"managed Host runtime public binary link is unsafe",
		)
	}
	target, err := os.Readlink(path)
	if err != nil || target != expectedTarget {
		return secureManualHostUpgradeLink{}, errors.New(
			"managed Host runtime public binary link has drifted",
		)
	}
	return secureManualHostUpgradeLink{path: path, info: info, target: target}, nil
}

func rejectManualHostUpgradeTransitionResidue(
	rt hostSelfUpdateExecutorRuntime,
) error {
	entries, err := os.ReadDir(rt.slotsRoot)
	if err != nil {
		return errors.New("read managed Host runtime slots")
	}
	for _, entry := range entries {
		if entry.Name() != HostSelfUpdateSlotA &&
			entry.Name() != HostSelfUpdateSlotB {
			return errors.New(
				"an interrupted Host runtime slot transition must be recovered before upgrade",
			)
		}
	}
	entries, err = os.ReadDir(rt.installRoot)
	if err != nil {
		return errors.New("read managed Host runtime root")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".current-") {
			return errors.New(
				"an interrupted Host runtime current-link transition must be recovered before upgrade",
			)
		}
	}
	return nil
}
