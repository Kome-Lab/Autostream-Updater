//go:build linux

package hostruntime

import (
	"fmt"
	"path/filepath"
	"sort"
)

var manualHostUpgradeFixedSystemdServiceTypes = []string{
	"control_panel",
	"encoder_recorder",
	"observability",
	"discord_bot",
	"worker",
}

// AcquireHostConfigurationTargetLocks fences every fixed managed service
// target while an explicitly authorized Host configuration recovery observes
// and adopts one live systemd sidecar. The caller must already hold the Host
// setup and lifecycle locks.
func AcquireHostConfigurationTargetLocks() (func(), error) {
	return acquireManualHostUpgradeTargetLocks(LocalExecutorPolicy{}, nil)
}

// acquireManualHostUpgradeTargetLocks fences both active and replacement-era
// target mutations while the Host runtime is replaced. Callers must already
// hold the setup and Host lifecycle locks so every updater observes the common
// setup -> lifecycle -> target lock order.
func acquireManualHostUpgradeTargetLocks(
	policy LocalExecutorPolicy,
	legacyTargets []Target,
) (func(), error) {
	return acquireManualHostUpgradeTargetLocksInDir(
		privilegedLockDir(),
		policy,
		legacyTargets,
	)
}

func acquireManualHostUpgradeTargetLocksInDir(
	lockDir string,
	policy LocalExecutorPolicy,
	legacyTargets []Target,
) (func(), error) {
	paths := manualHostUpgradeTargetLockPaths(
		lockDir,
		policy,
		legacyTargets,
	)
	unlocks := make([]func(), 0, len(paths))
	for _, path := range paths {
		unlock, err := lockManualHostUpgradeFile(path)
		if err != nil {
			unlockManualHostUpgradeTargetLocks(unlocks)
			return func() {}, fmt.Errorf(
				"acquire privileged update target lock %q: %w",
				filepath.Base(path),
				err,
			)
		}
		unlocks = append(unlocks, unlock)
	}
	return func() {
		unlockManualHostUpgradeTargetLocks(unlocks)
	}, nil
}

func manualHostUpgradeTargetLockPaths(
	lockDir string,
	policy LocalExecutorPolicy,
	legacyTargets []Target,
) []string {
	keys := make(map[string]struct{}, len(policy.Targets)+len(legacyTargets)+6)
	for _, serviceType := range manualHostUpgradeFixedSystemdServiceTypes {
		profile, ok := standardSystemdProfileFor(serviceType)
		if !ok {
			continue
		}
		keys[profile.unit] = struct{}{}
	}
	keys[filepath.Clean("/opt/autostream")+"\x00autostream"] = struct{}{}
	for _, target := range policy.Targets {
		keys[manualHostUpgradePolicyTargetLockKey(target)] = struct{}{}
	}
	for _, target := range legacyTargets {
		keys[manualHostUpgradeTargetLockKey(target)] = struct{}{}
	}

	paths := make([]string, 0, len(keys))
	seenPaths := make(map[string]struct{}, len(keys))
	for key := range keys {
		path := filepath.Join(
			lockDir,
			".autostream-updater-"+shortID(key)+".lock",
		)
		if _, exists := seenPaths[path]; exists {
			continue
		}
		seenPaths[path] = struct{}{}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func manualHostUpgradePolicyTargetLockKey(target LocalExecutorTarget) string {
	runtimeTarget := Target{
		TargetID:       target.ServiceID,
		DeploymentMode: target.DeploymentMode,
		Systemd:        target.Systemd,
	}
	if target.DeploymentMode == ModeDocker && target.Docker != nil {
		runtimeTarget.Docker = &DockerTarget{
			ProjectDir:     "/opt/autostream",
			ComposeProject: "autostream",
		}
	}
	return manualHostUpgradeTargetLockKey(runtimeTarget)
}

func manualHostUpgradeTargetLockKey(target Target) string {
	key := target.TargetID
	if target.DeploymentMode == ModeDocker && target.Docker != nil {
		key = filepath.Clean(target.Docker.ProjectDir) + "\x00" +
			target.Docker.ComposeProject
	} else if target.DeploymentMode == ModeSystemd && target.Systemd != nil {
		key = target.Systemd.Unit
	}
	return key
}

func unlockManualHostUpgradeTargetLocks(unlocks []func()) {
	for index := len(unlocks) - 1; index >= 0; index-- {
		unlocks[index]()
	}
}
