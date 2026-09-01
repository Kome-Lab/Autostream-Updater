//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// v1.9.16 installed an explicit User=root/Group=root. On systemd 255 that form
// can remove CAP_SETUID from the service's effective set, which prevents the
// root executor from running its candidate smoke check through runuser. The
// Control Panel and independent Updater templates differ only in their exact
// Documentation URL, so both byte-exact generations remain recognized.
const (
	manualHostExecutorUnitControlPanelLegacyDigest    = "3d2e6157df4c99d0feb6a3567ae6b7bb54bab2e37bd7adaa8de5a1b00ec4f4b5"
	manualHostExecutorUnitControlPanelCorrectedDigest = "eab31390eacea5f8d0cc5da2666142df4322e50863cba01fb3127bea64362dac"
	manualHostExecutorUnitUpdaterLegacyDigest         = "4650220b10a21063e15f9a0a121bc0cd078f5d2f684c601fa50a95b04ae88225"
	manualHostExecutorUnitUpdaterCorrectedDigest      = "548db8de58ecfddc59f64abd408fe1bae3cfd8e35c2a664c0a81038debfac8c5"
)

func manualHostExecutorUnitDigestIsLegacy(digest string) bool {
	return digest == manualHostExecutorUnitControlPanelLegacyDigest ||
		digest == manualHostExecutorUnitUpdaterLegacyDigest
}

func manualHostExecutorUnitDigestIsCorrected(digest string) bool {
	return digest == manualHostExecutorUnitControlPanelCorrectedDigest ||
		digest == manualHostExecutorUnitUpdaterCorrectedDigest
}

type manualHostExecutorUnitMigrationConfig struct {
	CandidatePath  string
	InstalledPath  string
	Runner         CommandRunner
	AllowTestPaths bool
	SyncDirectory  func(string) error
}

type manualHostExecutorUnitMigrationSnapshot struct {
	candidate        secureManualHostUpgradeFile
	installed        secureManualHostUpgradeFile
	dropInPaths      []string
	needDaemonReload bool
}

func migrateManualHostExecutorUnitForward(
	ctx context.Context,
	config manualHostExecutorUnitMigrationConfig,
) error {
	if err := prepareManualHostExecutorUnitMigrationConfig(&config); err != nil {
		return err
	}
	snapshot, err := inspectManualHostExecutorUnitMigration(ctx, config)
	if err != nil {
		return err
	}
	if manualHostExecutorUnitDigestIsCorrected(snapshot.installed.digest) {
		if snapshot.needDaemonReload {
			if err := reloadManualHostExecutorUnitSystemd(ctx, config.Runner); err != nil {
				return err
			}
		}
		final, err := inspectManualHostExecutorUnitMigration(ctx, config)
		if err != nil {
			return err
		}
		if !manualHostExecutorUnitMigrationIsFinal(final) {
			return errors.New("Local Executor unit migration did not converge")
		}
		return nil
	}

	if !manualHostExecutorUnitDigestIsLegacy(snapshot.installed.digest) {
		return errors.New("installed Local Executor unit is not a known migration source")
	}
	if err := replaceManualHostExecutorUnit(ctx, snapshot, config); err != nil {
		return err
	}
	if err := reloadManualHostExecutorUnitSystemd(ctx, config.Runner); err != nil {
		return err
	}
	final, err := inspectManualHostExecutorUnitMigration(ctx, config)
	if err != nil {
		return err
	}
	if !manualHostExecutorUnitMigrationIsFinal(final) {
		return errors.New("Local Executor unit migration did not converge")
	}
	return nil
}

func prepareManualHostExecutorUnitMigrationConfig(
	config *manualHostExecutorUnitMigrationConfig,
) error {
	if config == nil || config.Runner == nil {
		return errors.New("Local Executor unit migration dependencies are incomplete")
	}
	config.CandidatePath = filepath.Clean(config.CandidatePath)
	config.InstalledPath = filepath.Clean(config.InstalledPath)
	if !filepath.IsAbs(config.CandidatePath) ||
		!filepath.IsAbs(config.InstalledPath) ||
		config.CandidatePath == config.InstalledPath {
		return errors.New("Local Executor unit migration paths are invalid")
	}
	if config.SyncDirectory == nil {
		config.SyncDirectory = syncDirectory
	}
	return nil
}

func inspectManualHostExecutorUnitMigration(
	ctx context.Context,
	config manualHostExecutorUnitMigrationConfig,
) (manualHostExecutorUnitMigrationSnapshot, error) {
	candidate, err := snapshotManualHostUpgradeFile(config.CandidatePath)
	if err != nil || !manualHostExecutorUnitDigestIsCorrected(candidate.digest) ||
		candidate.info.Mode().Perm() != 0o644 ||
		manualHostExecutorUnitLinkCount(candidate.info) != 1 ||
		(!config.AllowTestPaths && !isRootOwner(candidate.info)) {
		return manualHostExecutorUnitMigrationSnapshot{}, errors.New(
			"verified Local Executor unit candidate is not the corrected template",
		)
	}
	installed, err := snapshotManualHostUpgradeFile(config.InstalledPath)
	if err != nil ||
		(!manualHostExecutorUnitDigestIsLegacy(installed.digest) &&
			!manualHostExecutorUnitDigestIsCorrected(installed.digest)) ||
		installed.info.Mode().Perm() != 0o644 ||
		manualHostExecutorUnitLinkCount(installed.info) != 1 ||
		(!config.AllowTestPaths && !isRootOwner(installed.info)) {
		return manualHostExecutorUnitMigrationSnapshot{}, errors.New(
			"installed Local Executor unit is not a known migration source",
		)
	}
	if err := rejectManualHostExecutorUnitDropInDirectory(config); err != nil {
		return manualHostExecutorUnitMigrationSnapshot{}, err
	}
	dropInPaths, needDaemonReload, err :=
		readManualHostExecutorUnitEffectiveState(ctx, config)
	if err != nil {
		return manualHostExecutorUnitMigrationSnapshot{}, err
	}
	if len(dropInPaths) != 0 {
		return manualHostExecutorUnitMigrationSnapshot{}, errors.New(
			"effective Local Executor unit has an unexpected drop-in",
		)
	}
	return manualHostExecutorUnitMigrationSnapshot{
		candidate:        candidate,
		installed:        installed,
		dropInPaths:      dropInPaths,
		needDaemonReload: needDaemonReload,
	}, nil
}

func rejectManualHostExecutorUnitDropInDirectory(
	config manualHostExecutorUnitMigrationConfig,
) error {
	path := config.InstalledPath + ".d"
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		(!config.AllowTestPaths &&
			(!isRootOwner(info) || info.Mode().Perm() != 0o755)) {
		return errors.New("Local Executor unit drop-in directory is unsafe")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		return errors.New("Local Executor unit has an unexpected drop-in")
	}
	return errors.New("Local Executor unit has an unexpected drop-in directory")
}

func readManualHostExecutorUnitEffectiveState(
	ctx context.Context,
	config manualHostExecutorUnitMigrationConfig,
) ([]string, bool, error) {
	output, err := config.Runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "show",
		"--property=FragmentPath",
		"--property=DropInPaths",
		"--property=NeedDaemonReload",
		"autostream-local-executor.service",
	)
	if err != nil {
		return nil, false, errors.New("read effective Local Executor unit")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, false, errors.New("effective Local Executor unit output is invalid")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, false, errors.New("effective Local Executor unit output has duplicate fields")
		}
		values[key] = value
	}
	fragmentPath, hasFragmentPath := values["FragmentPath"]
	dropInPaths, hasDropInPaths := values["DropInPaths"]
	needDaemonReload, hasNeedDaemonReload := values["NeedDaemonReload"]
	if len(values) != 3 || !hasFragmentPath || fragmentPath == "" ||
		filepath.Clean(fragmentPath) != config.InstalledPath ||
		!hasDropInPaths || !hasNeedDaemonReload ||
		(needDaemonReload != "yes" && needDaemonReload != "no") {
		return nil, false, errors.New(
			"effective Local Executor unit is not the managed template",
		)
	}
	return strings.Fields(dropInPaths), needDaemonReload == "yes", nil
}

func replaceManualHostExecutorUnit(
	ctx context.Context,
	snapshot manualHostExecutorUnitMigrationSnapshot,
	config manualHostExecutorUnitMigrationConfig,
) error {
	if !manualHostExecutorUnitFileMatches(snapshot.candidate, config) ||
		!manualHostExecutorUnitFileMatches(snapshot.installed, config) {
		return errors.New("Local Executor unit migration snapshot changed before replacement")
	}
	current, err := inspectManualHostExecutorUnitMigration(ctx, config)
	if err != nil || !manualHostExecutorUnitSnapshotMatches(snapshot, current) {
		return errors.New("Local Executor unit migration effective state changed before replacement")
	}
	candidate, err := os.Open(config.CandidatePath)
	if err != nil {
		return errors.New("open corrected Local Executor unit candidate")
	}
	defer candidate.Close()
	temporary, err := os.CreateTemp(
		filepath.Dir(config.InstalledPath),
		".autostream-local-executor.service.new.*",
	)
	if err != nil {
		return errors.New("create Local Executor unit staging file")
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if _, err := io.Copy(temporary, candidate); err != nil {
		return errors.New("copy corrected Local Executor unit")
	}
	if err := temporary.Chmod(0o644); err != nil {
		return errors.New("set Local Executor unit staging mode")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("sync Local Executor unit staging file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close Local Executor unit staging file before replacement")
	}
	staged, err := snapshotManualHostUpgradeFile(temporaryPath)
	if err != nil || staged.digest != snapshot.candidate.digest ||
		!manualHostExecutorUnitDigestIsCorrected(staged.digest) ||
		staged.info.Mode().Perm() != 0o644 ||
		manualHostExecutorUnitLinkCount(staged.info) != 1 ||
		(!config.AllowTestPaths && !isRootOwner(staged.info)) {
		return errors.New("staged Local Executor unit is unsafe")
	}
	if !manualHostExecutorUnitFileMatches(snapshot.candidate, config) ||
		!manualHostExecutorUnitFileMatches(snapshot.installed, config) {
		return errors.New("Local Executor unit migration snapshot changed before commit")
	}
	current, err = inspectManualHostExecutorUnitMigration(ctx, config)
	if err != nil || !manualHostExecutorUnitSnapshotMatches(snapshot, current) {
		return errors.New("Local Executor unit migration effective state changed before commit")
	}
	if err := os.Rename(temporaryPath, config.InstalledPath); err != nil {
		return errors.New("replace Local Executor unit with corrected template")
	}
	if err := config.SyncDirectory(filepath.Dir(config.InstalledPath)); err != nil {
		return fmt.Errorf("sync corrected Local Executor unit replacement: %w", err)
	}
	return requireManualHostExecutorUnitInstalledCorrected(
		config, snapshot.candidate.digest,
	)
}

func requireManualHostExecutorUnitInstalledCorrected(
	config manualHostExecutorUnitMigrationConfig,
	expectedDigest string,
) error {
	installed, err := snapshotManualHostUpgradeFile(config.InstalledPath)
	if err != nil || !manualHostExecutorUnitDigestIsCorrected(expectedDigest) ||
		installed.digest != expectedDigest ||
		installed.info.Mode().Perm() != 0o644 ||
		manualHostExecutorUnitLinkCount(installed.info) != 1 ||
		(!config.AllowTestPaths && !isRootOwner(installed.info)) {
		return errors.New("installed Local Executor unit is not the corrected template")
	}
	return nil
}

func manualHostExecutorUnitFileMatches(
	expected secureManualHostUpgradeFile,
	config manualHostExecutorUnitMigrationConfig,
) bool {
	current, err := snapshotManualHostUpgradeFile(expected.path)
	return err == nil && os.SameFile(expected.info, current.info) &&
		expected.info.Mode() == current.info.Mode() &&
		expected.info.Size() == current.info.Size() &&
		expected.digest == current.digest &&
		manualHostExecutorUnitLinkCount(current.info) == 1 &&
		(config.AllowTestPaths || isRootOwner(current.info))
}

func manualHostExecutorUnitSnapshotMatches(
	expected, current manualHostExecutorUnitMigrationSnapshot,
) bool {
	if !manualHostExecutorUnitFileMatches(expected.candidate,
		manualHostExecutorUnitMigrationConfig{AllowTestPaths: true}) ||
		!manualHostExecutorUnitFileMatches(expected.installed,
			manualHostExecutorUnitMigrationConfig{AllowTestPaths: true}) {
		return false
	}
	return strings.Join(expected.dropInPaths, "\x00") ==
		strings.Join(current.dropInPaths, "\x00") &&
		expected.needDaemonReload == current.needDaemonReload
}

func manualHostExecutorUnitMigrationIsFinal(
	snapshot manualHostExecutorUnitMigrationSnapshot,
) bool {
	return manualHostExecutorUnitDigestIsCorrected(snapshot.installed.digest) &&
		len(snapshot.dropInPaths) == 0 && !snapshot.needDaemonReload
}

func manualHostExecutorUnitLinkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func reloadManualHostExecutorUnitSystemd(
	ctx context.Context,
	runner CommandRunner,
) error {
	if _, err := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "daemon-reload",
	); err != nil {
		return fmt.Errorf("reload corrected Local Executor unit: %w", err)
	}
	return nil
}
