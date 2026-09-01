//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	hostInstallerGuardDropInPath = "/etc/systemd/system/autostream-host-agent.service.d/90-autostream-upgrade-recovery-guard.conf"
	hostInstallerGuardRunPrefix  = "/run/autostream-host-agent-upgrade-guard."
)

type hostInstallerGuardRuntime struct {
	manual         manualHostUpgradeRuntime
	markerPath     string
	dropInPath     string
	executablePath func() (string, error)
}

type hostInstallerGuardFile struct {
	path   string
	info   os.FileInfo
	digest string
}

type hostInstallerGuardObservation struct {
	currentInfo  os.FileInfo
	runtime      manualHostRuntimeObservation
	state        HostSelfUpdateState
	statePresent bool
	journal      journalData
	agent        hostInstallerGuardFile
	executor     hostInstallerGuardFile
	agentLink    secureManualHostUpgradeLink
	executorLink secureManualHostUpgradeLink
}

func defaultHostInstallerGuardRuntime() hostInstallerGuardRuntime {
	manual := defaultManualHostUpgradeRuntime()
	return hostInstallerGuardRuntime{
		manual:         manual,
		markerPath:     filepath.Join(manual.paths.hostStateRoot, journalActiveClearMarkerName),
		dropInPath:     hostInstallerGuardDropInPath,
		executablePath: os.Executable,
	}
}

func restartHostAgentFromUpgradeGuard(
	ctx context.Context,
	request HostAgentUpgradeGuardRequest,
) error {
	if os.Geteuid() != 0 {
		return errors.New("Host Agent installer recovery guard requires root")
	}
	return restartHostAgentFromUpgradeGuardWithRuntime(
		ctx,
		request,
		defaultHostInstallerGuardRuntime(),
	)
}

func restartHostAgentFromUpgradeGuardWithRuntime(
	ctx context.Context,
	request HostAgentUpgradeGuardRequest,
	rt hostInstallerGuardRuntime,
) error {
	if request.ExpectedSlot != HostSelfUpdateSlotA &&
		request.ExpectedSlot != HostSelfUpdateSlotB {
		return errors.New("Host Agent installer recovery guard slot is invalid")
	}
	if !isCanonicalBareSHA256(request.AgentSHA256) ||
		!isCanonicalBareSHA256(request.ExecutorSHA256) {
		return errors.New("Host Agent installer recovery guard digest is invalid")
	}
	if rt.executablePath == nil || strings.TrimSpace(rt.markerPath) == "" ||
		strings.TrimSpace(rt.dropInPath) == "" {
		return errors.New("Host Agent installer recovery guard dependencies are incomplete")
	}
	if err := prepareManualHostUpgradeRuntime(&rt.manual); err != nil {
		return err
	}

	guardPath, err := rt.executablePath()
	if err != nil {
		return errors.New("resolve Host Agent installer recovery guard executable")
	}
	guardPath = filepath.Clean(guardPath)
	if err := validateHostInstallerGuardExecutable(guardPath, rt.manual.allowTestPaths); err != nil {
		return err
	}
	dropIn, err := snapshotHostInstallerGuardDropIn(
		rt.dropInPath,
		guardPath,
		rt.markerPath,
		rt.manual.allowTestPaths,
	)
	if err != nil {
		return err
	}

	unlock, err := rt.manual.acquireLocks()
	if err != nil {
		return errors.New("another Host runtime setup or lifecycle operation is active")
	}
	defer unlock()

	first, err := observeHostInstallerGuard(
		ctx,
		request,
		guardPath,
		dropIn,
		rt,
	)
	if err != nil {
		return err
	}
	if err := rt.manual.waitStable(ctx); err != nil {
		return fmt.Errorf("wait for Host Agent installer recovery guard stability: %w", err)
	}
	second, err := observeHostInstallerGuard(
		ctx,
		request,
		guardPath,
		dropIn,
		rt,
	)
	if err != nil {
		return err
	}
	if !sameHostInstallerGuardObservation(first, second) {
		return errors.New("Host Agent installer recovery guard state changed during verification")
	}

	if _, err := rt.manual.runner.Run(
		ctx,
		"/",
		nil,
		"/usr/bin/systemctl",
		"start",
		hostSelfUpdateServiceUnit,
	); err != nil {
		return errors.New("start exact pre-upgrade Host Agent")
	}
	if err := verifyStartedHostInstallerGuardPair(ctx, request, first, rt); err != nil {
		return err
	}
	if err := removeHostInstallerGuardDropIn(ctx, dropIn, guardPath, rt); err != nil {
		return err
	}
	return nil
}

func observeHostInstallerGuard(
	ctx context.Context,
	request HostAgentUpgradeGuardRequest,
	guardPath string,
	dropIn hostInstallerGuardFile,
	rt hostInstallerGuardRuntime,
) (hostInstallerGuardObservation, error) {
	if err := requireHostInstallerGuardMarkerAbsent(rt.markerPath); err != nil {
		return hostInstallerGuardObservation{}, err
	}
	if err := validateHostInstallerGuardExecutable(
		guardPath,
		rt.manual.allowTestPaths,
	); err != nil {
		return hostInstallerGuardObservation{}, err
	}
	if !hostInstallerGuardFileMatches(dropIn) {
		return hostInstallerGuardObservation{}, errors.New(
			"Host Agent installer recovery guard drop-in changed",
		)
	}
	if err := validateManualHostUpgradeCoreServicePreconditions(
		ctx,
		rt.manual,
		true,
	); err != nil {
		return hostInstallerGuardObservation{}, err
	}

	currentSlot, err := rt.manual.selfUpdate.readCurrentSlot()
	if err != nil || currentSlot != request.ExpectedSlot {
		return hostInstallerGuardObservation{}, errors.New(
			"managed Host runtime no longer uses the exact pre-upgrade slot",
		)
	}
	currentInfo, err := os.Lstat(rt.manual.selfUpdate.currentLink)
	if err != nil || currentInfo.Mode()&os.ModeSymlink == 0 {
		return hostInstallerGuardObservation{}, errors.New(
			"managed Host runtime current link is unsafe",
		)
	}

	observed, err := observeManualHostRuntimeForUpgrade(
		ctx,
		request.ExpectedSlot,
		true,
		rt.manual,
	)
	if err != nil {
		return hostInstallerGuardObservation{}, err
	}
	state, statePresent, err := loadManualHostUpgradeState(observed, rt.manual)
	if err != nil {
		return hostInstallerGuardObservation{}, err
	}
	if err := validateManualHostUpgradeCurrentState(
		ctx,
		observed,
		state,
		statePresent,
		rt.manual,
	); err != nil {
		return hostInstallerGuardObservation{}, err
	}

	root := filepath.Join(
		rt.manual.selfUpdate.slotsRoot,
		request.ExpectedSlot,
		"bin",
	)
	agent, err := snapshotHostInstallerGuardRuntimeBinary(
		filepath.Join(root, "autostream-host-agent"),
		request.AgentSHA256,
		rt.manual.allowTestPaths,
	)
	if err != nil {
		return hostInstallerGuardObservation{}, err
	}
	executor, err := snapshotHostInstallerGuardRuntimeBinary(
		filepath.Join(root, "autostream-local-executor"),
		request.ExecutorSHA256,
		rt.manual.allowTestPaths,
	)
	if err != nil {
		return hostInstallerGuardObservation{}, err
	}
	agentLink, err := snapshotManualHostUpgradePublicLink(
		rt.manual.paths.publicAgentPath,
		filepath.Join(rt.manual.selfUpdate.currentLink, "bin", "autostream-host-agent"),
		rt.manual.allowTestPaths,
	)
	if err != nil {
		return hostInstallerGuardObservation{}, err
	}
	executorLink, err := snapshotManualHostUpgradePublicLink(
		rt.manual.paths.publicExecutorPath,
		filepath.Join(rt.manual.selfUpdate.currentLink, "bin", "autostream-local-executor"),
		rt.manual.allowTestPaths,
	)
	if err != nil {
		return hostInstallerGuardObservation{}, err
	}

	if err := validateManualHostUpgradeStateRoots(rt.manual); err != nil {
		return hostInstallerGuardObservation{}, err
	}
	journal, err := readManualHostUpgradeJournal(rt.manual)
	if err != nil {
		return hostInstallerGuardObservation{}, err
	}
	if _, err := manualHostUpgradeJournalRecoveryActive(journal); err != nil {
		return hostInstallerGuardObservation{}, err
	}
	if err := requireHostInstallerGuardMarkerAbsent(rt.markerPath); err != nil {
		return hostInstallerGuardObservation{}, err
	}

	return hostInstallerGuardObservation{
		currentInfo:  currentInfo,
		runtime:      observed,
		state:        state,
		statePresent: statePresent,
		journal:      journal,
		agent:        agent,
		executor:     executor,
		agentLink:    agentLink,
		executorLink: executorLink,
	}, nil
}

func verifyStartedHostInstallerGuardPair(
	ctx context.Context,
	request HostAgentUpgradeGuardRequest,
	before hostInstallerGuardObservation,
	rt hostInstallerGuardRuntime,
) error {
	if err := validateManualHostUpgradeCoreServicePreconditions(
		ctx,
		rt.manual,
		false,
	); err != nil {
		return err
	}
	current, err := rt.manual.selfUpdate.readCurrentSlot()
	if err != nil || current != request.ExpectedSlot {
		return errors.New("Host runtime current slot changed while the guard started the Agent")
	}
	observed, err := observeManualHostRuntime(ctx, request.ExpectedSlot, rt.manual)
	if err != nil {
		return err
	}
	if observed != before.runtime {
		return errors.New("restarted Host runtime identity differs from the exact pre-upgrade pair")
	}
	for _, expected := range []hostInstallerGuardFile{before.agent, before.executor} {
		if !hostInstallerGuardFileMatches(expected) {
			return errors.New("restarted Host runtime binary differs from the exact pre-upgrade pair")
		}
	}
	for _, expected := range []secureManualHostUpgradeLink{
		before.agentLink,
		before.executorLink,
	} {
		current, err := snapshotManualHostUpgradePublicLink(
			expected.path,
			expected.target,
			rt.manual.allowTestPaths,
		)
		if err != nil || !os.SameFile(expected.info, current.info) ||
			expected.info.Mode() != current.info.Mode() {
			return errors.New("Host runtime public link changed while the guard started the Agent")
		}
	}
	if err := requireHostInstallerGuardMarkerAbsent(rt.markerPath); err != nil {
		return err
	}
	return nil
}

func sameHostInstallerGuardObservation(
	first hostInstallerGuardObservation,
	second hostInstallerGuardObservation,
) bool {
	return first.currentInfo != nil && second.currentInfo != nil &&
		os.SameFile(first.currentInfo, second.currentInfo) &&
		first.currentInfo.Mode() == second.currentInfo.Mode() &&
		first.runtime == second.runtime &&
		first.statePresent == second.statePresent &&
		reflect.DeepEqual(first.state, second.state) &&
		reflect.DeepEqual(first.journal, second.journal) &&
		hostInstallerGuardFilesEqual(first.agent, second.agent) &&
		hostInstallerGuardFilesEqual(first.executor, second.executor) &&
		hostInstallerGuardLinksEqual(first.agentLink, second.agentLink) &&
		hostInstallerGuardLinksEqual(first.executorLink, second.executorLink)
}

func snapshotHostInstallerGuardRuntimeBinary(
	path string,
	expectedDigest string,
	allowTestPaths bool,
) (hostInstallerGuardFile, error) {
	file, err := snapshotHostInstallerGuardFile(path, 0o755, allowTestPaths)
	if err != nil || file.digest != expectedDigest {
		return hostInstallerGuardFile{}, errors.New(
			"managed Host runtime binary does not match the exact pre-upgrade digest",
		)
	}
	return file, nil
}

func snapshotHostInstallerGuardDropIn(
	path string,
	guardPath string,
	markerPath string,
	allowTestPaths bool,
) (hostInstallerGuardFile, error) {
	file, err := snapshotHostInstallerGuardFile(path, 0o644, allowTestPaths)
	if err != nil {
		return hostInstallerGuardFile{}, errors.New(
			"Host Agent installer recovery guard drop-in is unsafe",
		)
	}
	payload, err := os.ReadFile(path)
	if err != nil || string(payload) != hostInstallerGuardDropInContent(guardPath, markerPath) {
		return hostInstallerGuardFile{}, errors.New(
			"Host Agent installer recovery guard drop-in content is invalid",
		)
	}
	return file, nil
}

func snapshotHostInstallerGuardFile(
	path string,
	mode os.FileMode,
	allowTestPaths bool,
) (hostInstallerGuardFile, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode ||
		info.Size() <= 0 || info.Size() > defaultMaxArtifactBytes {
		return hostInstallerGuardFile{}, errors.New("Host Agent installer recovery guard file is unsafe")
	}
	if !allowTestPaths && (!isRootOwner(info) ||
		validateSecureRootPath(filepath.Dir(path), true) != nil) {
		return hostInstallerGuardFile{}, errors.New(
			"Host Agent installer recovery guard file ownership is unsafe",
		)
	}
	digest, err := hashFile(path)
	if err != nil || !isCanonicalBareSHA256(digest) {
		return hostInstallerGuardFile{}, errors.New("hash Host Agent installer recovery guard file")
	}
	return hostInstallerGuardFile{path: path, info: info, digest: digest}, nil
}

func validateHostInstallerGuardExecutable(path string, allowTestPaths bool) error {
	if !allowTestPaths {
		directory := filepath.Dir(path)
		if filepath.Dir(directory) != "/run" ||
			!strings.HasPrefix(filepath.Base(directory), filepath.Base(hostInstallerGuardRunPrefix)) ||
			filepath.Base(path) != "autostream-local-executor" {
			return errors.New("Host Agent installer recovery guard executable path is invalid")
		}
	}
	_, err := snapshotHostInstallerGuardFile(path, 0o700, allowTestPaths)
	if err != nil {
		return errors.New("Host Agent installer recovery guard executable is unsafe")
	}
	return nil
}

func hostInstallerGuardDropInContent(guardPath string, markerPath string) string {
	return "[Unit]\n" +
		"ConditionPathExists=!" + markerPath + "\n" +
		"ConditionFileIsExecutable=" + guardPath + "\n"
}

func requireHostInstallerGuardMarkerAbsent(path string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.New("Host Agent journal clear fence blocks legacy Agent restart")
}

func hostInstallerGuardFileMatches(expected hostInstallerGuardFile) bool {
	current, err := snapshotHostInstallerGuardFile(
		expected.path,
		expected.info.Mode().Perm(),
		true,
	)
	return err == nil && hostInstallerGuardFilesEqual(expected, current)
}

func hostInstallerGuardFilesEqual(
	first hostInstallerGuardFile,
	second hostInstallerGuardFile,
) bool {
	return first.info != nil && second.info != nil &&
		os.SameFile(first.info, second.info) &&
		first.info.Mode() == second.info.Mode() &&
		first.info.Size() == second.info.Size() &&
		first.info.ModTime().Equal(second.info.ModTime()) &&
		first.digest == second.digest
}

func hostInstallerGuardLinksEqual(
	first secureManualHostUpgradeLink,
	second secureManualHostUpgradeLink,
) bool {
	return first.info != nil && second.info != nil &&
		os.SameFile(first.info, second.info) &&
		first.info.Mode() == second.info.Mode() &&
		first.target == second.target
}

func removeHostInstallerGuardDropIn(
	ctx context.Context,
	expected hostInstallerGuardFile,
	guardPath string,
	rt hostInstallerGuardRuntime,
) error {
	if err := requireHostInstallerGuardMarkerAbsent(rt.markerPath); err != nil {
		return err
	}
	current, err := snapshotHostInstallerGuardDropIn(
		rt.dropInPath,
		guardPath,
		rt.markerPath,
		rt.manual.allowTestPaths,
	)
	if err != nil || !hostInstallerGuardFilesEqual(expected, current) {
		return errors.New("Host Agent installer recovery guard drop-in changed before removal")
	}
	if err := os.Remove(rt.dropInPath); err != nil {
		return errors.New("remove Host Agent installer recovery guard drop-in")
	}
	if err := syncDirectory(filepath.Dir(rt.dropInPath)); err != nil {
		return errors.New("sync Host Agent installer recovery guard drop-in directory")
	}
	if _, err := rt.manual.runner.Run(
		ctx,
		"/",
		nil,
		"/usr/bin/systemctl",
		"daemon-reload",
	); err != nil {
		return errors.New("reload systemd after Host Agent installer recovery guard")
	}
	return nil
}
