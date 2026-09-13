//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	manualHostUpgradeTestOldVersion    = "v9.9.8"
	manualHostUpgradeTestTargetVersion = "v9.9.9"
)

var (
	manualHostUpgradeTestOldCommit     = strings.Repeat("a", 40)
	manualHostUpgradeTestTargetCommit  = strings.Repeat("b", 40)
	manualHostUpgradeTestOldBuildDate  = time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	manualHostUpgradeTestBuildDate     = time.Date(2026, 8, 1, 4, 5, 6, 0, time.UTC)
	manualHostUpgradeTestActivationNow = time.Date(2026, 8, 2, 7, 8, 9, 0, time.UTC)
)

type manualHostUpgradeLinuxFixture struct {
	root               string
	artifactRoot       string
	identityPath       string
	policyPath         string
	publicAgentPath    string
	publicExecutorPath string
	request            ManualHostUpgradeRequest
	targetRequest      HostSelfUpdateRequest
	runtime            manualHostUpgradeRuntime
	runner             *manualHostUpgradeLinuxRunner
	waitStableCalls    int
	watchdogCalls      int
	processExeResolves map[int]int
}

type manualHostUpgradeLinuxRunner struct {
	currentLink                 string
	slotsRoot                   string
	agentActive                 bool
	executorActive              bool
	failTargetAgent             bool
	targetAgentFailed           bool
	stopAfterSideEffectErr      bool
	stopCancel                  context.CancelFunc
	stopHook                    func() error
	stopCalls                   int
	blockPostStopRestart        bool
	postStopRestartBlocked      bool
	postStopRestartCanceled     bool
	restartOrder                []string
	restartContextCanceled      []bool
	mainPIDReads                map[string]int
	mainPIDSequence             map[string][]int
	identityReads               map[string]int
	binaryIdentityHook          func(string) error
	agentRestartCount           int
	agentIdentityAfterRestart   int
	inactiveUnits               map[string]bool
	disabledUnits               map[string]bool
	recoveryUnitPath            string
	executorUnitPath            string
	recoveryEffectiveExtra      string
	recoveryReloads             int
	recoveryFailedUnits         map[string]bool
	failRecoveryReset           bool
	recoveryResetFailedAttempts int
	recoveryResetFailedCalls    int
}

func (r *manualHostUpgradeLinuxRunner) Run(
	ctx context.Context,
	_ string,
	_ []string,
	name string,
	args ...string,
) (string, error) {
	if name != "/usr/bin/systemctl" {
		return r.binaryIdentity(name, args...)
	}
	if len(args) == 0 {
		return "", errors.New("missing systemctl operation")
	}
	switch args[0] {
	case "is-active":
		quiet := len(args) == 3 && args[1] == "--quiet"
		unitIndex := 1
		if quiet {
			unitIndex = 2
		}
		if len(args) != unitIndex+1 {
			return "", errors.New("invalid systemctl is-active arguments")
		}
		unit := args[unitIndex]
		if r.recoveryFailedUnits[unit] {
			return "failed\n", errors.New("unit is failed")
		}
		active := r.unitActive(unit)
		if active {
			if quiet {
				return "", nil
			}
			return "active\n", nil
		}
		if quiet {
			return "", errors.New("unit is inactive")
		}
		return "inactive\n", errors.New("unit is inactive")
	case "is-enabled":
		if len(args) != 2 {
			return "", errors.New("invalid systemctl is-enabled arguments")
		}
		if r.disabledUnits[args[1]] {
			return "disabled\n", errors.New("unit is disabled")
		}
		return "enabled\n", nil
	case "stop":
		if len(args) != 2 || args[1] != hostSelfUpdateServiceUnit {
			return "", errors.New("unexpected systemctl stop")
		}
		r.stopCalls++
		r.agentActive = false
		if r.stopCancel != nil {
			r.stopCancel()
		}
		if r.stopHook != nil {
			if err := r.stopHook(); err != nil {
				return "", err
			}
		}
		if r.stopAfterSideEffectErr {
			return "", errors.New("injected stop failure after Agent became inactive")
		}
		return "", nil
	case "restart":
		if len(args) != 2 {
			return "", errors.New("invalid systemctl restart arguments")
		}
		if r.blockPostStopRestart && r.stopCalls > 0 &&
			!r.postStopRestartBlocked {
			r.postStopRestartBlocked = true
			<-ctx.Done()
			r.postStopRestartCanceled = true
			return "", ctx.Err()
		}
		unit := args[1]
		r.restartOrder = append(r.restartOrder, unit)
		r.restartContextCanceled = append(
			r.restartContextCanceled,
			ctx.Err() != nil,
		)
		if err := ctx.Err(); err != nil {
			return "", errors.New("restart inherited a canceled context")
		}
		switch unit {
		case hostSelfUpdateExecutorServiceUnit:
			r.executorActive = true
			return "", nil
		case hostSelfUpdateServiceUnit:
			r.agentRestartCount++
			slot, err := r.currentSlot()
			if err != nil {
				return "", err
			}
			if r.failTargetAgent && slot == HostSelfUpdateSlotB &&
				!r.targetAgentFailed {
				r.targetAgentFailed = true
				r.agentActive = false
				return "", errors.New("injected target Host Agent restart failure")
			}
			r.agentActive = true
			return "", nil
		default:
			return "", errors.New("unexpected systemctl restart unit")
		}
	case "daemon-reload":
		if len(args) != 1 {
			return "", errors.New("invalid systemctl daemon-reload arguments")
		}
		r.recoveryReloads++
		return "", nil
	case "reset-failed":
		if len(args) != 2 ||
			(args[1] != manualHostRecoveryUnitInstances[0] &&
				args[1] != manualHostRecoveryUnitInstances[1]) {
			return "", errors.New("unexpected systemctl reset-failed arguments")
		}
		r.recoveryResetFailedAttempts++
		if r.failRecoveryReset {
			return "", errors.New("injected recovery reset-failed failure")
		}
		delete(r.recoveryFailedUnits, args[1])
		r.recoveryResetFailedCalls++
		return "", nil
	case "show":
		if len(args) == 5 && args[1] == "--property=FragmentPath" &&
			args[2] == "--property=DropInPaths" &&
			args[3] == "--property=NeedDaemonReload" &&
			args[4] == hostSelfUpdateExecutorServiceUnit {
			return "FragmentPath=" + r.executorUnitPath + "\n" +
				"DropInPaths=\nNeedDaemonReload=no\n", nil
		}
		if len(args) == 5 && args[1] == "--property=FragmentPath" &&
			args[2] == "--property=DropInPaths" &&
			args[3] == "--property=NeedDaemonReload" &&
			(args[4] == manualHostRecoveryUnitInstances[0] ||
				args[4] == manualHostRecoveryUnitInstances[1]) {
			dropIns := []string{}
			entries, err := os.ReadDir(r.recoveryUnitPath + ".d")
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
			for _, entry := range entries {
				dropIns = append(
					dropIns,
					filepath.Join(r.recoveryUnitPath+".d", entry.Name()),
				)
			}
			sort.Strings(dropIns)
			if r.recoveryEffectiveExtra != "" {
				dropIns = append(dropIns, r.recoveryEffectiveExtra)
				sort.Strings(dropIns)
			}
			return "FragmentPath=" + r.recoveryUnitPath + "\n" +
				"DropInPaths=" + strings.Join(dropIns, " ") + "\n" +
				"NeedDaemonReload=no\n", nil
		}
		if len(args) != 4 || args[1] != "--property=MainPID" ||
			args[2] != "--value" {
			return "", errors.New("invalid systemctl show arguments")
		}
		unit := args[3]
		r.mainPIDReads[unit]++
		if sequence := r.mainPIDSequence[unit]; len(sequence) > 0 {
			index := r.mainPIDReads[unit] - 1
			if index >= len(sequence) {
				index = len(sequence) - 1
			}
			return fmt.Sprintf("%d\n", sequence[index]), nil
		}
		switch unit {
		case hostSelfUpdateServiceUnit:
			if !r.agentActive {
				return "0\n", nil
			}
			return "3101\n", nil
		case hostSelfUpdateExecutorServiceUnit:
			if !r.executorActive {
				return "0\n", nil
			}
			return "3102\n", nil
		case manualHostRecoveryUnitInstances[0], manualHostRecoveryUnitInstances[1]:
			return "0\n", nil
		default:
			return "", errors.New("unexpected systemctl show unit")
		}
	default:
		return "", errors.New("unexpected systemctl operation")
	}
}

func (r *manualHostUpgradeLinuxRunner) unitActive(unit string) bool {
	if r.inactiveUnits[unit] {
		return false
	}
	switch unit {
	case hostSelfUpdateServiceUnit:
		return r.agentActive
	case hostSelfUpdateExecutorServiceUnit:
		return r.executorActive
	case hostSelfUpdateExecutorSocketUnit,
		"autostream-host-self-update-recovery@a.timer",
		"autostream-host-self-update-recovery@b.timer":
		return true
	case "autostream-host-self-update-recovery@a.service",
		"autostream-host-self-update-recovery@b.service":
		return false
	default:
		return false
	}
}

func (r *manualHostUpgradeLinuxRunner) currentSlot() (string, error) {
	target, err := os.Readlink(r.currentLink)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(r.currentLink), target)
	}
	target = filepath.Clean(target)
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if target == filepath.Join(r.slotsRoot, slot) {
			return slot, nil
		}
	}
	return "", errors.New("current symlink is outside the test slots")
}

func (r *manualHostUpgradeLinuxRunner) binaryIdentity(
	name string,
	args ...string,
) (string, error) {
	if len(args) != 1 || args[0] != "--version" {
		return "", errors.New("unexpected binary identity arguments")
	}
	if r.binaryIdentityHook != nil {
		if err := r.binaryIdentityHook(name); err != nil {
			return "", err
		}
	}
	payload, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	r.identityReads[filepath.Base(name)]++
	version := manualHostUpgradeTestOldVersion
	commit := manualHostUpgradeTestOldCommit
	buildDate := manualHostUpgradeTestOldBuildDate
	if bytes.HasPrefix(payload, []byte("target:")) {
		version = manualHostUpgradeTestTargetVersion
		commit = manualHostUpgradeTestTargetCommit
		buildDate = manualHostUpgradeTestBuildDate
	} else if !bytes.HasPrefix(payload, []byte("old:")) {
		return "", errors.New("unrecognized test binary payload")
	}
	binary := filepath.Base(name)
	if binary == "autostream-host-agent" && r.agentRestartCount > 0 {
		r.agentIdentityAfterRestart++
	}
	output := fmt.Sprintf(
		"%s %s\ncommit: %s\nbuild_date: %s\n",
		binary,
		version,
		commit,
		buildDate.Format("2006-01-02T15:04:05Z"),
	)
	if binary == "autostream-local-executor" {
		output += fmt.Sprintf(
			"mutation_protocol: %d\nrecovery_protocol: %d\n",
			LocalExecutorMutationProtocolVersion,
			HostSelfUpdateRecoveryProtocolVersion,
		)
	}
	return output, nil
}
