//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	manualHostRecoveryUnitLegacyDigest    = "751c69c970407b4873d403971a192b33320d44b352aba58a9ab56c2fa1e1309c"
	manualHostRecoveryUnitCorrectedDigest = "d0a994dc4a0dc5dd27131f3878de4e9652d5679a4681174660249b66eb1813fd"
)

var manualHostRecoveryUnitKnownDropIns = map[string]string{
	"10-executable-guard.conf":      "264b1b3e55d6f4551af36daa2cc34d19baa162b21b0c724d0c62459eefe006fe",
	"20-bootstrap-state-guard.conf": "1964442535eb9f85ce594cb54c880fd8b92338951e3e103fac1fd5b88c85bf10",
}

var manualHostRecoveryUnitInstances = []string{
	"autostream-host-self-update-recovery@a.service",
	"autostream-host-self-update-recovery@b.service",
}

type manualHostRecoveryUnitMigrationConfig struct {
	CandidatePath  string
	InstalledPath  string
	Runner         CommandRunner
	AllowTestPaths bool
	SyncDirectory  func(string) error
}

type manualHostRecoveryUnitMigrationSnapshot struct {
	candidate secureManualHostUpgradeFile
	installed secureManualHostUpgradeFile
	dropInDir secureManualHostUpgradeDirectory
	dropIns   []secureManualHostUpgradeFile
	effective []manualHostRecoveryUnitEffectiveState
}

type manualHostRecoveryUnitEffectiveState struct {
	unit             string
	fragmentPath     string
	dropInPaths      []string
	needDaemonReload bool
}

func migrateManualHostRecoveryUnitForward(
	ctx context.Context,
	config manualHostRecoveryUnitMigrationConfig,
) error {
	if err := prepareManualHostRecoveryUnitMigrationConfig(&config); err != nil {
		return err
	}
	snapshot, err := inspectManualHostRecoveryUnitMigration(ctx, config)
	if err != nil {
		return err
	}
	if snapshot.dropInDir.present {
		if err := config.SyncDirectory(snapshot.dropInDir.path); err != nil {
			return fmt.Errorf(
				"resync Host recovery unit drop-in directory: %w", err,
			)
		}
	}
	if err := config.SyncDirectory(filepath.Dir(config.InstalledPath)); err != nil {
		return fmt.Errorf("resync Host recovery unit parent directory: %w", err)
	}
	snapshot, err = inspectManualHostRecoveryUnitMigration(ctx, config)
	if err != nil {
		return err
	}
	if snapshot.installed.digest == manualHostRecoveryUnitCorrectedDigest &&
		!snapshot.dropInDir.present &&
		len(snapshot.dropIns) == 0 &&
		manualHostRecoveryUnitEffectiveIsFinal(snapshot.effective) {
		return nil
	}

	if snapshot.installed.digest == manualHostRecoveryUnitLegacyDigest {
		if err := replaceManualHostRecoveryUnit(snapshot, config); err != nil {
			return err
		}
	}
	if err := requireManualHostRecoveryUnitInstalledCorrected(config); err != nil {
		return err
	}
	if err := reloadManualHostRecoveryUnitSystemd(ctx, config.Runner); err != nil {
		return err
	}
	current, err := inspectManualHostRecoveryUnitMigration(ctx, config)
	if err != nil {
		return err
	}
	if current.installed.digest != manualHostRecoveryUnitCorrectedDigest {
		return errors.New("corrected Host recovery unit was not retained after daemon-reload")
	}
	for _, state := range current.effective {
		if state.needDaemonReload {
			return fmt.Errorf("%s still requires daemon-reload after migration", state.unit)
		}
	}

	if err := removeManualHostRecoveryUnitKnownDropIns(current, config); err != nil {
		return err
	}
	if err := reloadManualHostRecoveryUnitSystemd(ctx, config.Runner); err != nil {
		return err
	}
	final, err := inspectManualHostRecoveryUnitMigration(ctx, config)
	if err != nil {
		return err
	}
	if final.installed.digest != manualHostRecoveryUnitCorrectedDigest ||
		final.dropInDir.present ||
		len(final.dropIns) != 0 ||
		!manualHostRecoveryUnitEffectiveIsFinal(final.effective) {
		return errors.New("Host recovery unit migration did not converge")
	}
	return nil
}

func prepareManualHostRecoveryUnitMigrationConfig(
	config *manualHostRecoveryUnitMigrationConfig,
) error {
	if config == nil || config.Runner == nil {
		return errors.New("Host recovery unit migration dependencies are incomplete")
	}
	config.CandidatePath = filepath.Clean(config.CandidatePath)
	config.InstalledPath = filepath.Clean(config.InstalledPath)
	if !filepath.IsAbs(config.CandidatePath) ||
		!filepath.IsAbs(config.InstalledPath) ||
		config.CandidatePath == config.InstalledPath {
		return errors.New("Host recovery unit migration paths are invalid")
	}
	if config.SyncDirectory == nil {
		config.SyncDirectory = syncDirectory
	}
	return nil
}

func inspectManualHostRecoveryUnitMigration(
	ctx context.Context,
	config manualHostRecoveryUnitMigrationConfig,
) (manualHostRecoveryUnitMigrationSnapshot, error) {
	candidate, err := snapshotManualHostUpgradeFile(config.CandidatePath)
	if err != nil || candidate.digest != manualHostRecoveryUnitCorrectedDigest ||
		candidate.info.Mode().Perm() != 0o644 ||
		manualHostRecoveryUnitLinkCount(candidate.info) != 1 ||
		(!config.AllowTestPaths && !manualHostRecoveryUnitRootOwned(candidate.info)) {
		return manualHostRecoveryUnitMigrationSnapshot{}, errors.New(
			"verified Host recovery unit candidate is not the corrected template",
		)
	}
	installed, err := snapshotManualHostUpgradeFile(config.InstalledPath)
	if err != nil ||
		(installed.digest != manualHostRecoveryUnitLegacyDigest &&
			installed.digest != manualHostRecoveryUnitCorrectedDigest) ||
		installed.info.Mode().Perm() != 0o644 ||
		manualHostRecoveryUnitLinkCount(installed.info) != 1 ||
		(!config.AllowTestPaths && !manualHostRecoveryUnitRootOwned(installed.info)) {
		return manualHostRecoveryUnitMigrationSnapshot{}, errors.New(
			"installed Host recovery unit is not a known migration source",
		)
	}
	dropInDir, dropIns, err := snapshotManualHostRecoveryUnitDropIns(config)
	if err != nil {
		return manualHostRecoveryUnitMigrationSnapshot{}, err
	}
	effective, err := readManualHostRecoveryUnitEffectiveState(ctx, config)
	if err != nil {
		return manualHostRecoveryUnitMigrationSnapshot{}, err
	}
	wantDropIns := manualHostRecoveryUnitDropInPaths(dropIns)
	knownDropIns := manualHostRecoveryUnitAllKnownDropInPaths(config.InstalledPath)
	for _, state := range effective {
		if filepath.Clean(state.fragmentPath) != config.InstalledPath {
			return manualHostRecoveryUnitMigrationSnapshot{}, fmt.Errorf(
				"%s has an unknown effective Host recovery unit override", state.unit,
			)
		}
		if state.needDaemonReload {
			if installed.digest != manualHostRecoveryUnitCorrectedDigest ||
				!manualHostRecoveryUnitPathsAreKnown(state.dropInPaths, knownDropIns) {
				return manualHostRecoveryUnitMigrationSnapshot{}, fmt.Errorf(
					"%s requires an unexpected daemon-reload", state.unit,
				)
			}
		} else if !equalManualHostRecoveryUnitPaths(state.dropInPaths, wantDropIns) {
			return manualHostRecoveryUnitMigrationSnapshot{}, fmt.Errorf(
				"%s has an unknown effective Host recovery unit override", state.unit,
			)
		}
	}
	return manualHostRecoveryUnitMigrationSnapshot{
		candidate: candidate,
		installed: installed,
		dropInDir: dropInDir,
		dropIns:   dropIns,
		effective: effective,
	}, nil
}

func snapshotManualHostRecoveryUnitDropIns(
	config manualHostRecoveryUnitMigrationConfig,
) (secureManualHostUpgradeDirectory, []secureManualHostUpgradeFile, error) {
	directoryPath := config.InstalledPath + ".d"
	directory, err := snapshotManualHostUpgradeDirectory(
		directoryPath, 0o755, config.AllowTestPaths,
	)
	if errors.Is(err, os.ErrNotExist) {
		return secureManualHostUpgradeDirectory{path: directoryPath, mode: 0o755}, nil, nil
	}
	if err != nil {
		return secureManualHostUpgradeDirectory{}, nil,
			errors.New("Host recovery unit drop-in directory is unsafe")
	}
	if !config.AllowTestPaths && !manualHostRecoveryUnitRootOwned(directory.info) {
		return secureManualHostUpgradeDirectory{}, nil,
			errors.New("Host recovery unit drop-in directory is unsafe")
	}
	entries, err := os.ReadDir(directoryPath)
	if err != nil {
		return secureManualHostUpgradeDirectory{}, nil,
			errors.New("read Host recovery unit drop-in directory")
	}
	dropIns := make([]secureManualHostUpgradeFile, 0, len(entries))
	for _, entry := range entries {
		expectedDigest, ok := manualHostRecoveryUnitKnownDropIns[entry.Name()]
		if !ok || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return secureManualHostUpgradeDirectory{}, nil,
				errors.New("Host recovery unit has an unknown drop-in")
		}
		path := filepath.Join(directoryPath, entry.Name())
		snapshot, snapshotErr := snapshotManualHostUpgradeFile(path)
		if snapshotErr != nil || snapshot.digest != expectedDigest ||
			snapshot.info.Mode().Perm() != 0o644 ||
			manualHostRecoveryUnitLinkCount(snapshot.info) != 1 ||
			(!config.AllowTestPaths &&
				!manualHostRecoveryUnitRootOwned(snapshot.info)) {
			return secureManualHostUpgradeDirectory{}, nil,
				errors.New("Host recovery unit drop-in is unsafe or modified")
		}
		dropIns = append(dropIns, snapshot)
	}
	sort.Slice(dropIns, func(i, j int) bool { return dropIns[i].path < dropIns[j].path })
	return directory, dropIns, nil
}

func manualHostRecoveryUnitLinkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func manualHostRecoveryUnitRootOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0
}

func readManualHostRecoveryUnitEffectiveState(
	ctx context.Context,
	config manualHostRecoveryUnitMigrationConfig,
) ([]manualHostRecoveryUnitEffectiveState, error) {
	states := make([]manualHostRecoveryUnitEffectiveState, 0, len(manualHostRecoveryUnitInstances))
	for _, unit := range manualHostRecoveryUnitInstances {
		output, err := config.Runner.Run(
			ctx, "/", nil, "/usr/bin/systemctl", "show",
			"--property=FragmentPath",
			"--property=DropInPaths",
			"--property=NeedDaemonReload",
			unit,
		)
		if err != nil {
			return nil, fmt.Errorf("read %s effective recovery unit: %w", unit, err)
		}
		values := map[string]string{}
		for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok || key == "" {
				return nil, fmt.Errorf("%s effective recovery unit output is invalid", unit)
			}
			if _, duplicate := values[key]; duplicate {
				return nil, fmt.Errorf("%s effective recovery unit output has duplicate fields", unit)
			}
			values[key] = value
		}
		fragmentPath, hasFragmentPath := values["FragmentPath"]
		dropInPaths, hasDropInPaths := values["DropInPaths"]
		needDaemonReload, hasNeedDaemonReload := values["NeedDaemonReload"]
		if len(values) != 3 || !hasFragmentPath || fragmentPath == "" ||
			!hasDropInPaths || !hasNeedDaemonReload ||
			(needDaemonReload != "yes" && needDaemonReload != "no") {
			return nil, fmt.Errorf("%s effective recovery unit output is incomplete", unit)
		}
		states = append(states, manualHostRecoveryUnitEffectiveState{
			unit:             unit,
			fragmentPath:     fragmentPath,
			dropInPaths:      strings.Fields(dropInPaths),
			needDaemonReload: needDaemonReload == "yes",
		})
	}
	return states, nil
}

func replaceManualHostRecoveryUnit(
	snapshot manualHostRecoveryUnitMigrationSnapshot,
	config manualHostRecoveryUnitMigrationConfig,
) error {
	if !manualHostRecoveryUnitFileMatches(snapshot.candidate, config) ||
		!manualHostRecoveryUnitFileMatches(snapshot.installed, config) ||
		!manualHostRecoveryUnitDropInSnapshotMatches(snapshot, config) {
		return errors.New("Host recovery unit migration snapshot changed before replacement")
	}
	candidate, err := os.Open(config.CandidatePath)
	if err != nil {
		return errors.New("open corrected Host recovery unit candidate")
	}
	defer candidate.Close()
	temporary, err := os.CreateTemp(
		filepath.Dir(config.InstalledPath),
		".autostream-host-self-update-recovery.service.new.*",
	)
	if err != nil {
		return errors.New("create Host recovery unit staging file")
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if _, err := io.Copy(temporary, candidate); err != nil {
		return errors.New("copy corrected Host recovery unit")
	}
	if err := temporary.Chmod(0o644); err != nil {
		return errors.New("set Host recovery unit staging mode")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("sync Host recovery unit staging file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close Host recovery unit staging file before replacement")
	}
	staged, err := snapshotManualHostUpgradeFile(temporaryPath)
	if err != nil || staged.digest != manualHostRecoveryUnitCorrectedDigest ||
		staged.info.Mode().Perm() != 0o644 ||
		manualHostRecoveryUnitLinkCount(staged.info) != 1 ||
		(!config.AllowTestPaths && !manualHostRecoveryUnitRootOwned(staged.info)) {
		return errors.New("staged Host recovery unit is unsafe")
	}
	if !manualHostRecoveryUnitFileMatches(snapshot.candidate, config) ||
		!manualHostRecoveryUnitFileMatches(snapshot.installed, config) ||
		!manualHostRecoveryUnitDropInSnapshotMatches(snapshot, config) {
		return errors.New("Host recovery unit migration snapshot changed before commit")
	}
	if err := os.Rename(temporaryPath, config.InstalledPath); err != nil {
		return errors.New("replace Host recovery unit with corrected template")
	}
	if err := config.SyncDirectory(filepath.Dir(config.InstalledPath)); err != nil {
		return fmt.Errorf("sync corrected Host recovery unit replacement: %w", err)
	}
	return requireManualHostRecoveryUnitInstalledCorrected(config)
}

func requireManualHostRecoveryUnitInstalledCorrected(
	config manualHostRecoveryUnitMigrationConfig,
) error {
	installed, err := snapshotManualHostUpgradeFile(config.InstalledPath)
	if err != nil || installed.digest != manualHostRecoveryUnitCorrectedDigest ||
		installed.info.Mode().Perm() != 0o644 ||
		manualHostRecoveryUnitLinkCount(installed.info) != 1 ||
		(!config.AllowTestPaths && !manualHostRecoveryUnitRootOwned(installed.info)) {
		return errors.New("installed Host recovery unit is not the corrected template")
	}
	return nil
}

func removeManualHostRecoveryUnitKnownDropIns(
	snapshot manualHostRecoveryUnitMigrationSnapshot,
	config manualHostRecoveryUnitMigrationConfig,
) error {
	if !snapshot.dropInDir.present {
		return nil
	}
	if !manualHostRecoveryUnitDropInSnapshotMatches(snapshot, config) {
		return errors.New("Host recovery unit drop-ins changed before cleanup")
	}
	for _, dropIn := range snapshot.dropIns {
		if !manualHostRecoveryUnitDropInFileMatches(dropIn, config) {
			return errors.New("Host recovery unit drop-in changed before removal")
		}
		if err := os.Remove(dropIn.path); err != nil {
			return errors.New("remove known Host recovery unit drop-in")
		}
		if err := config.SyncDirectory(snapshot.dropInDir.path); err != nil {
			return fmt.Errorf("sync Host recovery unit drop-in removal: %w", err)
		}
	}
	entries, err := os.ReadDir(snapshot.dropInDir.path)
	if err != nil || len(entries) != 0 {
		return errors.New("Host recovery unit drop-in directory did not become empty")
	}
	if err := os.Remove(snapshot.dropInDir.path); err != nil {
		return errors.New("remove empty Host recovery unit drop-in directory")
	}
	if err := config.SyncDirectory(filepath.Dir(config.InstalledPath)); err != nil {
		return fmt.Errorf("sync Host recovery unit drop-in directory removal: %w", err)
	}
	return nil
}

func manualHostRecoveryUnitDropInSnapshotMatches(
	snapshot manualHostRecoveryUnitMigrationSnapshot,
	config manualHostRecoveryUnitMigrationConfig,
) bool {
	if !snapshot.dropInDir.present {
		_, err := os.Lstat(snapshot.dropInDir.path)
		return errors.Is(err, os.ErrNotExist) && len(snapshot.dropIns) == 0
	}
	if !manualHostUpgradeDirectoryMatches(snapshot.dropInDir, config.AllowTestPaths) {
		return false
	}
	currentDirectory, err := os.Lstat(snapshot.dropInDir.path)
	if err != nil || (!config.AllowTestPaths &&
		!manualHostRecoveryUnitRootOwned(currentDirectory)) {
		return false
	}
	entries, err := os.ReadDir(snapshot.dropInDir.path)
	if err != nil || len(entries) != len(snapshot.dropIns) {
		return false
	}
	for _, dropIn := range snapshot.dropIns {
		if !manualHostRecoveryUnitDropInFileMatches(dropIn, config) {
			return false
		}
	}
	return true
}

func manualHostRecoveryUnitDropInFileMatches(
	expected secureManualHostUpgradeFile,
	config manualHostRecoveryUnitMigrationConfig,
) bool {
	return manualHostRecoveryUnitFileMatches(expected, config)
}

func manualHostRecoveryUnitFileMatches(
	expected secureManualHostUpgradeFile,
	config manualHostRecoveryUnitMigrationConfig,
) bool {
	current, err := snapshotManualHostUpgradeFile(expected.path)
	return err == nil && os.SameFile(expected.info, current.info) &&
		expected.info.Mode() == current.info.Mode() &&
		expected.info.Size() == current.info.Size() &&
		expected.digest == current.digest &&
		current.info.Mode().Perm() == 0o644 &&
		manualHostRecoveryUnitLinkCount(current.info) == 1 &&
		(config.AllowTestPaths || manualHostRecoveryUnitRootOwned(current.info))
}

func manualHostRecoveryUnitDropInPaths(
	dropIns []secureManualHostUpgradeFile,
) []string {
	paths := make([]string, 0, len(dropIns))
	for _, dropIn := range dropIns {
		paths = append(paths, filepath.Clean(dropIn.path))
	}
	sort.Strings(paths)
	return paths
}

func manualHostRecoveryUnitAllKnownDropInPaths(installedPath string) []string {
	paths := make([]string, 0, len(manualHostRecoveryUnitKnownDropIns))
	for name := range manualHostRecoveryUnitKnownDropIns {
		paths = append(paths, filepath.Join(installedPath+".d", name))
	}
	sort.Strings(paths)
	return paths
}

func manualHostRecoveryUnitPathsAreKnown(actual, known []string) bool {
	knownSet := make(map[string]struct{}, len(known))
	for _, path := range known {
		knownSet[filepath.Clean(path)] = struct{}{}
	}
	for _, path := range actual {
		if _, ok := knownSet[filepath.Clean(path)]; !ok {
			return false
		}
	}
	return true
}

func equalManualHostRecoveryUnitPaths(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	for index := range leftCopy {
		leftCopy[index] = filepath.Clean(leftCopy[index])
	}
	for index := range rightCopy {
		rightCopy[index] = filepath.Clean(rightCopy[index])
	}
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func manualHostRecoveryUnitEffectiveIsFinal(
	states []manualHostRecoveryUnitEffectiveState,
) bool {
	if len(states) != len(manualHostRecoveryUnitInstances) {
		return false
	}
	for _, state := range states {
		if state.needDaemonReload || len(state.dropInPaths) != 0 {
			return false
		}
	}
	return true
}

func reloadManualHostRecoveryUnitSystemd(
	ctx context.Context,
	runner CommandRunner,
) error {
	if _, err := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "daemon-reload",
	); err != nil {
		return fmt.Errorf("reload corrected Host recovery unit: %w", err)
	}
	return nil
}
