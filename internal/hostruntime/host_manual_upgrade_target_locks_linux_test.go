//go:build linux

package hostruntime

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestManualHostUpgradeTargetLockPathsCoverFixedPolicyAndLegacyTargets(t *testing.T) {
	lockDir := "/run/test-autostream-updater-locks"
	policy := LocalExecutorPolicy{
		HostID: "edge-01",
		Targets: []LocalExecutorTarget{
			{
				ServiceID:      "worker-systemd",
				ServiceType:    "worker",
				DeploymentMode: ModeSystemd,
				Systemd: &SystemdTarget{
					Unit: "autostream-worker.service",
				},
			},
			{
				ServiceID:      "worker-docker",
				ServiceType:    "worker",
				DeploymentMode: ModeDocker,
				Docker:         &DockerTarget{},
			},
		},
	}
	legacyTargets := []Target{
		{
			TargetID:       "custom-systemd-one",
			DeploymentMode: ModeSystemd,
			Systemd:        &SystemdTarget{Unit: "legacy-custom.service"},
		},
		{
			TargetID:       "custom-systemd-two",
			DeploymentMode: ModeSystemd,
			Systemd:        &SystemdTarget{Unit: "legacy-custom.service"},
		},
		{
			TargetID:       "custom-docker-one",
			DeploymentMode: ModeDocker,
			Docker: &DockerTarget{
				ProjectDir:     "/srv/legacy-stack",
				ComposeProject: "legacy",
			},
		},
		{
			TargetID:       "custom-docker-two",
			DeploymentMode: ModeDocker,
			Docker: &DockerTarget{
				ProjectDir:     "/srv/legacy-stack/.",
				ComposeProject: "legacy",
			},
		},
	}

	keys := []string{
		"autostream-control-panel.service",
		"autostream-discord-bot.service",
		"autostream-encoder-recorder.service",
		"autostream-observability.service",
		"autostream-worker.service",
		"legacy-custom.service",
		filepath.Clean("/opt/autostream") + "\x00" + "autostream",
		filepath.Clean("/srv/legacy-stack") + "\x00" + "legacy",
	}
	want := make([]string, 0, len(keys))
	for _, key := range keys {
		want = append(want, filepath.Join(
			lockDir,
			".autostream-updater-"+shortID(key)+".lock",
		))
	}
	sort.Strings(want)

	got := manualHostUpgradeTargetLockPaths(lockDir, policy, legacyTargets)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("target lock paths = %#v, want %#v", got, want)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("target lock paths are not canonical: %#v", got)
	}
}

func TestAcquireManualHostUpgradeTargetLocksInteroperatesWithLegacyTargetLock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("strong privileged lock validation requires root")
	}
	lockDir := t.TempDir()
	policy := LocalExecutorPolicy{}
	legacyTargets := []Target{{
		TargetID:       "custom-systemd",
		DeploymentMode: ModeSystemd,
		Systemd:        &SystemdTarget{Unit: "legacy-custom.service"},
	}}
	paths := manualHostUpgradeTargetLockPaths(lockDir, policy, legacyTargets)
	if len(paths) == 0 {
		t.Fatal("fixed target lock set is empty")
	}
	contendedPath := filepath.Join(
		lockDir,
		".autostream-updater-"+shortID("legacy-custom.service")+".lock",
	)
	contendedIndex := sort.SearchStrings(paths, contendedPath)
	if contendedIndex <= 0 || contendedIndex >= len(paths) ||
		paths[contendedIndex] != contendedPath {
		t.Fatalf(
			"test contention path must follow an acquired path: index=%d paths=%#v",
			contendedIndex,
			paths,
		)
	}

	legacyUnlock, err := lockFile(contendedPath)
	if err != nil {
		t.Fatalf("acquire legacy target lock: %v", err)
	}
	if _, err := acquireManualHostUpgradeTargetLocksInDir(
		lockDir, policy, legacyTargets,
	); err == nil {
		legacyUnlock()
		t.Fatal("manual Host upgrade acquired a legacy-held target lock")
	}
	legacyUnlock()
	for _, path := range paths {
		unlock, err := lockFile(path)
		if err != nil {
			t.Fatalf("aggregate acquisition leaked %q after contention: %v", path, err)
		}
		unlock()
	}

	manualUnlock, err := acquireManualHostUpgradeTargetLocksInDir(
		lockDir, policy, legacyTargets,
	)
	if err != nil {
		t.Fatalf("acquire manual Host upgrade target locks after release: %v", err)
	}
	defer manualUnlock()
	if unlock, err := lockFile(contendedPath); err == nil {
		unlock()
		t.Fatal("legacy updater acquired a manual-upgrade-held target lock")
	}
}
