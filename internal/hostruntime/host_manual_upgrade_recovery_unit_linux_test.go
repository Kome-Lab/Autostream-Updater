//go:build linux

package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestMigrateManualHostRecoveryUnitLegacyWithoutDropIns(t *testing.T) {
	fixture := newManualHostRecoveryUnitFixture(t, legacyManualHostRecoveryUnitBytes(t))

	if err := migrateManualHostRecoveryUnitForward(
		context.Background(),
		manualHostRecoveryUnitMigrationConfig{
			CandidatePath:  fixture.candidatePath,
			InstalledPath:  fixture.installedPath,
			Runner:         fixture.runner,
			AllowTestPaths: true,
		},
	); err != nil {
		t.Fatalf("migrateManualHostRecoveryUnitForward: %v", err)
	}

	assertManualHostRecoveryUnitConverged(t, fixture)
	if fixture.runner.reloads != 2 {
		t.Fatalf("daemon-reload calls=%d, want 2", fixture.runner.reloads)
	}
}

func TestMigrateManualHostRecoveryUnitLegacyWithKnownDropIns(t *testing.T) {
	fixture := newManualHostRecoveryUnitFixture(t, legacyManualHostRecoveryUnitBytes(t))
	fixture.installKnownDropIns(t)

	if err := migrateManualHostRecoveryUnitForward(
		context.Background(), fixture.config(),
	); err != nil {
		t.Fatalf("migrateManualHostRecoveryUnitForward: %v", err)
	}

	assertManualHostRecoveryUnitConverged(t, fixture)
	if _, err := os.Lstat(fixture.installedPath + ".d"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("known drop-in directory remained after migration: %v", err)
	}
	if fixture.runner.reloads != 2 {
		t.Fatalf("daemon-reload calls=%d, want 2", fixture.runner.reloads)
	}
}

func TestMigrateManualHostRecoveryUnitCorrectedNoOp(t *testing.T) {
	fixture := newManualHostRecoveryUnitFixture(t, correctedManualHostRecoveryUnitBytes(t))
	if err := migrateManualHostRecoveryUnitForward(
		context.Background(), fixture.config(),
	); err != nil {
		t.Fatalf("migrateManualHostRecoveryUnitForward: %v", err)
	}
	assertManualHostRecoveryUnitConverged(t, fixture)
	if fixture.runner.reloads != 0 {
		t.Fatalf("daemon-reload calls=%d, want no-op", fixture.runner.reloads)
	}
}

func TestMigrateManualHostRecoveryUnitControlPanelLegacy(t *testing.T) {
	fixture := newManualHostRecoveryUnitFixture(
		t, controlPanelLegacyManualHostRecoveryUnitBytes(t),
	)
	if err := migrateManualHostRecoveryUnitForward(
		context.Background(), fixture.config(),
	); err != nil {
		t.Fatalf("migrateManualHostRecoveryUnitForward: %v", err)
	}
	assertManualHostRecoveryUnitConverged(t, fixture)
	if fixture.runner.reloads != 2 {
		t.Fatalf("daemon-reload calls=%d, want 2", fixture.runner.reloads)
	}
}

func TestMigrateManualHostRecoveryUnitControlPanelCorrectedNoOp(t *testing.T) {
	corrected := controlPanelCorrectedManualHostRecoveryUnitBytes(t)
	fixture := newManualHostRecoveryUnitFixture(t, corrected)
	if err := migrateManualHostRecoveryUnitForward(
		context.Background(), fixture.config(),
	); err != nil {
		t.Fatalf("migrateManualHostRecoveryUnitForward: %v", err)
	}
	installed, err := os.ReadFile(fixture.installedPath)
	if err != nil || string(installed) != string(corrected) {
		t.Fatalf("Control Panel corrected recovery unit changed: err=%v", err)
	}
	if fixture.runner.reloads != 0 {
		t.Fatalf("daemon-reload calls=%d, want 0", fixture.runner.reloads)
	}
}

func TestMigrateManualHostRecoveryUnitControlPanelCandidate(t *testing.T) {
	corrected := controlPanelCorrectedManualHostRecoveryUnitBytes(t)
	fixture := newManualHostRecoveryUnitFixture(
		t, controlPanelLegacyManualHostRecoveryUnitBytes(t),
	)
	if err := os.WriteFile(fixture.candidatePath, corrected, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := migrateManualHostRecoveryUnitForward(
		context.Background(), fixture.config(),
	); err != nil {
		t.Fatalf("migrateManualHostRecoveryUnitForward: %v", err)
	}
	installed, err := os.ReadFile(fixture.installedPath)
	if err != nil || string(installed) != string(corrected) {
		t.Fatalf("Control Panel recovery candidate was not retained: err=%v", err)
	}
	if fixture.runner.reloads != 2 {
		t.Fatalf("daemon-reload calls=%d, want 2", fixture.runner.reloads)
	}
}

func TestMigrateManualHostRecoveryUnitRemovesEmptyKnownDropInDirectory(
	t *testing.T,
) {
	fixture := newManualHostRecoveryUnitFixture(
		t, correctedManualHostRecoveryUnitBytes(t),
	)
	if err := os.Mkdir(fixture.installedPath+".d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := migrateManualHostRecoveryUnitForward(
		context.Background(), fixture.config(),
	); err != nil {
		t.Fatalf("migrateManualHostRecoveryUnitForward: %v", err)
	}
	assertManualHostRecoveryUnitConverged(t, fixture)
	if _, err := os.Lstat(
		fixture.installedPath + ".d",
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty known drop-in directory remained: %v", err)
	}
	if fixture.runner.reloads != 2 {
		t.Fatalf("daemon-reload calls=%d, want 2", fixture.runner.reloads)
	}
}

func TestMigrateManualHostRecoveryUnitRejectsUnknownInputs(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *manualHostRecoveryUnitFixture)
	}{
		{
			name: "installed base",
			mutate: func(t *testing.T, fixture *manualHostRecoveryUnitFixture) {
				t.Helper()
				if err := os.WriteFile(fixture.installedPath, []byte("unknown\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "candidate base",
			mutate: func(t *testing.T, fixture *manualHostRecoveryUnitFixture) {
				t.Helper()
				if err := os.WriteFile(fixture.candidatePath, []byte("unknown\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "installed hardlink",
			mutate: func(t *testing.T, fixture *manualHostRecoveryUnitFixture) {
				t.Helper()
				if err := os.Link(
					fixture.installedPath,
					fixture.installedPath+".hardlink",
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "candidate hardlink",
			mutate: func(t *testing.T, fixture *manualHostRecoveryUnitFixture) {
				t.Helper()
				if err := os.Link(
					fixture.candidatePath,
					fixture.candidatePath+".hardlink",
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "drop-in name",
			mutate: func(t *testing.T, fixture *manualHostRecoveryUnitFixture) {
				t.Helper()
				directory := fixture.installedPath + ".d"
				if err := os.Mkdir(directory, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, "99-unknown.conf"), []byte("[Unit]\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "effective override",
			mutate: func(_ *testing.T, fixture *manualHostRecoveryUnitFixture) {
				fixture.runner.effectiveExtra = "/run/systemd/system/unknown.conf"
			},
		},
		{
			name: "missing DropInPaths property",
			mutate: func(_ *testing.T, fixture *manualHostRecoveryUnitFixture) {
				fixture.runner.dropInProperty = "UnknownProperty"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostRecoveryUnitFixture(t, legacyManualHostRecoveryUnitBytes(t))
			test.mutate(t, &fixture)
			before, err := os.ReadFile(fixture.installedPath)
			if err != nil {
				t.Fatal(err)
			}
			err = migrateManualHostRecoveryUnitForward(
				context.Background(), fixture.config(),
			)
			if err == nil {
				t.Fatal("unknown recovery unit input was accepted")
			}
			after, readErr := os.ReadFile(fixture.installedPath)
			if readErr != nil || string(after) != string(before) {
				t.Fatalf("rejected migration changed installed base: err=%v", readErr)
			}
			if fixture.runner.reloads != 0 {
				t.Fatalf("rejected migration reloaded systemd %d times", fixture.runner.reloads)
			}
		})
	}
}

func TestMigrateManualHostRecoveryUnitRejectsHardlinkAddedAfterSnapshot(
	t *testing.T,
) {
	for _, target := range []string{"candidate", "installed", "drop-in"} {
		t.Run(target, func(t *testing.T) {
			fixture := newManualHostRecoveryUnitFixture(
				t, legacyManualHostRecoveryUnitBytes(t),
			)
			fixture.installKnownDropIns(t)
			path := fixture.candidatePath
			switch target {
			case "installed":
				path = fixture.installedPath
			case "drop-in":
				path = filepath.Join(
					fixture.installedPath+".d",
					"10-executable-guard.conf",
				)
			}
			hardlinkPath := path + ".outside-hardlink"
			if target == "drop-in" {
				hardlinkPath = fixture.installedPath + ".drop-in-hardlink"
			}
			injected := false
			fixture.runner.showHook = func() error {
				if injected {
					return nil
				}
				injected = true
				return os.Link(path, hardlinkPath)
			}

			err := migrateManualHostRecoveryUnitForward(
				context.Background(), fixture.config(),
			)
			if err == nil || !injected {
				t.Fatalf("post-snapshot hardlink err=%v injected=%v", err, injected)
			}
			if fixture.runner.reloads != 0 {
				t.Fatalf("post-snapshot hardlink reloaded systemd %d times", fixture.runner.reloads)
			}
			installed, readErr := os.ReadFile(fixture.installedPath)
			if readErr != nil || manualHostRecoveryUnitDigest(installed) !=
				manualHostRecoveryUnitUpdaterLegacyDigest {
				t.Fatalf("post-snapshot hardlink changed base err=%v", readErr)
			}
		})
	}
}

func TestMigrateManualHostRecoveryUnitConvergesAfterReloadFailure(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprintf("reload_%d", failAt), func(t *testing.T) {
			fixture := newManualHostRecoveryUnitFixture(
				t, legacyManualHostRecoveryUnitBytes(t),
			)
			fixture.installKnownDropIns(t)
			fixture.runner.failReloadAt = failAt
			injected := errors.New("injected daemon-reload failure")
			fixture.runner.reloadError = injected

			err := migrateManualHostRecoveryUnitForward(
				context.Background(), fixture.config(),
			)
			if !errors.Is(err, injected) {
				t.Fatalf("first migration err=%v", err)
			}
			assertManualHostRecoveryUnitConverged(t, fixture)
			_, dropInErr := os.Lstat(fixture.installedPath + ".d")
			if failAt == 1 && dropInErr != nil {
				t.Fatalf("first reload failure removed known drop-ins: %v", dropInErr)
			}
			if failAt == 2 && !errors.Is(dropInErr, os.ErrNotExist) {
				t.Fatalf("second reload failure retained drop-ins: %v", dropInErr)
			}

			fixture.runner.failReloadAt = 0
			fixture.runner.reloadError = nil
			if err := migrateManualHostRecoveryUnitForward(
				context.Background(), fixture.config(),
			); err != nil {
				t.Fatalf("converge migration: %v", err)
			}
			if _, err := os.Lstat(
				fixture.installedPath + ".d",
			); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("converged migration retained drop-ins: %v", err)
			}
		})
	}
}

func TestMigrateManualHostRecoveryUnitConvergesAfterNamespaceSyncFailure(
	t *testing.T,
) {
	for _, test := range []struct {
		name        string
		withDropIns bool
		path        func(manualHostRecoveryUnitFixture) string
		failAt      int
	}{
		{
			name:   "base replacement parent",
			path:   func(f manualHostRecoveryUnitFixture) string { return filepath.Dir(f.installedPath) },
			failAt: 2,
		},
		{
			name:        "drop-in removal directory",
			withDropIns: true,
			path:        func(f manualHostRecoveryUnitFixture) string { return f.installedPath + ".d" },
			failAt:      2,
		},
		{
			name:        "drop-in directory removal parent",
			withDropIns: true,
			path:        func(f manualHostRecoveryUnitFixture) string { return filepath.Dir(f.installedPath) },
			failAt:      3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostRecoveryUnitFixture(
				t, legacyManualHostRecoveryUnitBytes(t),
			)
			if test.withDropIns {
				fixture.installKnownDropIns(t)
			}
			targetPath := filepath.Clean(test.path(fixture))
			calls := 0
			failed := false
			injected := errors.New("injected recovery namespace sync failure")
			fixture.syncDirectory = func(path string) error {
				if filepath.Clean(path) == targetPath {
					calls++
					if !failed && calls == test.failAt {
						failed = true
						return injected
					}
				}
				return syncDirectory(path)
			}

			err := migrateManualHostRecoveryUnitForward(
				context.Background(), fixture.config(),
			)
			if !errors.Is(err, injected) || !failed {
				t.Fatalf("first migration err=%v failed=%v calls=%d", err, failed, calls)
			}
			callsAfterFailure := calls
			if err := migrateManualHostRecoveryUnitForward(
				context.Background(), fixture.config(),
			); err != nil {
				t.Fatalf("retry migration: %v", err)
			}
			if calls <= callsAfterFailure {
				t.Fatalf("retry did not resync %s: calls=%d", targetPath, calls)
			}
			assertManualHostRecoveryUnitConverged(t, fixture)
			if _, err := os.Lstat(
				fixture.installedPath + ".d",
			); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("retry retained drop-in directory: %v", err)
			}
		})
	}
}

type manualHostRecoveryUnitFixture struct {
	installedPath string
	candidatePath string
	runner        *manualHostRecoveryUnitRunner
	syncDirectory func(string) error
}

func (f manualHostRecoveryUnitFixture) config() manualHostRecoveryUnitMigrationConfig {
	return manualHostRecoveryUnitMigrationConfig{
		CandidatePath:  f.candidatePath,
		InstalledPath:  f.installedPath,
		Runner:         f.runner,
		AllowTestPaths: true,
		SyncDirectory:  f.syncDirectory,
	}
}

func (f manualHostRecoveryUnitFixture) installKnownDropIns(t *testing.T) {
	t.Helper()
	directory := f.installedPath + ".d"
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"10-executable-guard.conf":      "[Unit]\nConditionFileIsExecutable=/opt/autostream/host-agent/slots/%i/bin/autostream-local-executor\n",
		"20-bootstrap-state-guard.conf": "[Unit]\nConditionPathExists=/var/lib/autostream-local-executor/host-self-update/state.json\n",
	}
	for name, payload := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(payload), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func newManualHostRecoveryUnitFixture(
	t *testing.T,
	installed []byte,
) manualHostRecoveryUnitFixture {
	t.Helper()
	root := t.TempDir()
	installedPath := filepath.Join(
		root,
		"installed",
		"autostream-host-self-update-recovery@.service",
	)
	candidatePath := filepath.Join(
		root,
		"candidate",
		"autostream-host-self-update-recovery@.service",
	)
	for _, path := range []string{installedPath, candidatePath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(installedPath, installed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidatePath, correctedManualHostRecoveryUnitBytes(t), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &manualHostRecoveryUnitRunner{installedPath: installedPath}
	return manualHostRecoveryUnitFixture{
		installedPath: installedPath,
		candidatePath: candidatePath,
		runner:        runner,
	}
}

type manualHostRecoveryUnitRunner struct {
	installedPath  string
	reloads        int
	failReloadAt   int
	reloadError    error
	effectiveExtra string
	dropInProperty string
	showHook       func() error
	loaded         bool
	loadedDigest   string
	loadedDropIns  []string
}

func (r *manualHostRecoveryUnitRunner) Run(
	_ context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (string, error) {
	if dir != "/" || len(env) != 0 || name != "/usr/bin/systemctl" {
		return "", errors.New("unexpected recovery-unit command boundary")
	}
	if len(args) == 1 && args[0] == "daemon-reload" {
		r.reloads++
		if r.failReloadAt > 0 && r.reloads == r.failReloadAt {
			return "", r.reloadError
		}
		digest, dropIns, err := r.physicalState()
		if err != nil {
			return "", err
		}
		r.loaded = true
		r.loadedDigest = digest
		r.loadedDropIns = dropIns
		return "", nil
	}
	if len(args) != 5 || args[0] != "show" ||
		args[1] != "--property=FragmentPath" ||
		args[2] != "--property=DropInPaths" ||
		args[3] != "--property=NeedDaemonReload" ||
		(args[4] != manualHostRecoveryUnitInstances[0] &&
			args[4] != manualHostRecoveryUnitInstances[1]) {
		return "", errors.New("unexpected systemctl arguments")
	}
	if r.showHook != nil {
		if err := r.showHook(); err != nil {
			return "", err
		}
	}
	physicalDigest, physicalDropIns, err := r.physicalState()
	if err != nil {
		return "", err
	}
	if !r.loaded {
		r.loaded = true
		r.loadedDigest = physicalDigest
		r.loadedDropIns = append([]string(nil), physicalDropIns...)
	}
	dropIns := append([]string(nil), r.loadedDropIns...)
	needDaemonReload := r.loadedDigest != physicalDigest ||
		!equalManualHostRecoveryUnitPaths(r.loadedDropIns, physicalDropIns)
	if r.effectiveExtra != "" {
		dropIns = append(dropIns, r.effectiveExtra)
	}
	sort.Strings(dropIns)
	dropInProperty := r.dropInProperty
	if dropInProperty == "" {
		dropInProperty = "DropInPaths"
	}
	needDaemonReloadValue := "no"
	if needDaemonReload {
		needDaemonReloadValue = "yes"
	}
	return "FragmentPath=" + r.installedPath + "\n" +
		dropInProperty + "=" + strings.Join(dropIns, " ") + "\n" +
		"NeedDaemonReload=" + needDaemonReloadValue + "\n", nil
}

func (r *manualHostRecoveryUnitRunner) physicalState() (string, []string, error) {
	digest, err := hashFile(r.installedPath)
	if err != nil {
		return "", nil, err
	}
	dropIns := []string{}
	entries, err := os.ReadDir(r.installedPath + ".d")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", nil, err
	}
	for _, entry := range entries {
		dropIns = append(dropIns, filepath.Join(r.installedPath+".d", entry.Name()))
	}
	sort.Strings(dropIns)
	return digest, dropIns, nil
}

func correctedManualHostRecoveryUnitBytes(t *testing.T) []byte {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	path := filepath.Join(
		filepath.Dir(testFile),
		"..",
		"..",
		"systemd",
		"autostream-host-self-update-recovery@.service.example",
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := manualHostRecoveryUnitDigest(data); got !=
		manualHostRecoveryUnitUpdaterCorrectedDigest {
		t.Fatalf("production recovery unit digest=%s", got)
	}
	return data
}

func legacyManualHostRecoveryUnitBytes(t *testing.T) []byte {
	t.Helper()
	data := legacyManualHostRecoveryUnitBytesFromCorrected(
		t, correctedManualHostRecoveryUnitBytes(t),
	)
	if got := manualHostRecoveryUnitDigest(data); got !=
		manualHostRecoveryUnitUpdaterLegacyDigest {
		t.Fatalf("Updater legacy recovery unit digest=%s", got)
	}
	return data
}

func controlPanelCorrectedManualHostRecoveryUnitBytes(t *testing.T) []byte {
	t.Helper()
	updater := string(correctedManualHostRecoveryUnitBytes(t))
	corrected := strings.Replace(
		updater,
		"Documentation=https://github.com/Kome-Lab/Autostream-Updater\n",
		"Documentation=https://github.com/Kome-Lab/Autostream-ControlPanel\n",
		1,
	)
	if corrected == updater {
		t.Fatal("failed to construct Control Panel recovery unit")
	}
	data := []byte(corrected)
	if got := manualHostRecoveryUnitDigest(data); got !=
		manualHostRecoveryUnitControlPanelCorrectedDigest {
		t.Fatalf("Control Panel corrected recovery unit digest=%s", got)
	}
	return data
}

func controlPanelLegacyManualHostRecoveryUnitBytes(t *testing.T) []byte {
	t.Helper()
	data := legacyManualHostRecoveryUnitBytesFromCorrected(
		t, controlPanelCorrectedManualHostRecoveryUnitBytes(t),
	)
	if got := manualHostRecoveryUnitDigest(data); got !=
		manualHostRecoveryUnitControlPanelLegacyDigest {
		t.Fatalf("Control Panel legacy recovery unit digest=%s", got)
	}
	return data
}

func legacyManualHostRecoveryUnitBytesFromCorrected(
	t *testing.T,
	correctedBytes []byte,
) []byte {
	t.Helper()
	corrected := string(correctedBytes)
	legacy := strings.Replace(
		corrected,
		"ConditionPathExists=/var/lib/autostream-local-executor/host-self-update/state.json\n"+
			"ConditionFileIsExecutable=/opt/autostream/host-agent/slots/%i/bin/autostream-local-executor\n",
		"ConditionPathIsExecutable=/opt/autostream/host-agent/slots/%i/bin/autostream-local-executor\n",
		1,
	)
	if legacy == corrected {
		t.Fatal("production recovery unit does not contain corrected guard sequence")
	}
	return []byte(legacy)
}

func manualHostRecoveryUnitDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func assertManualHostRecoveryUnitConverged(
	t *testing.T,
	fixture manualHostRecoveryUnitFixture,
) {
	t.Helper()
	installed, err := os.ReadFile(fixture.installedPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := manualHostRecoveryUnitDigest(installed); got !=
		manualHostRecoveryUnitUpdaterCorrectedDigest {
		t.Fatalf("installed recovery unit digest=%s", got)
	}
}
