//go:build linux

package hostruntime

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func configureManualHostUpgradeLegacyRecoveryUnit(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	artifactPath := filepath.Join(
		fixture.artifactRoot,
		"systemd",
		"autostream-host-self-update-recovery@.service",
	)
	manualHostUpgradeLinuxWriteFile(
		t, artifactPath, correctedManualHostRecoveryUnitBytes(t), 0o644,
	)
	manualHostUpgradeLinuxWriteFile(
		t,
		fixture.runtime.paths.installedRecoveryService,
		legacyManualHostRecoveryUnitBytes(t),
		0o644,
	)
	dropInDirectory := fixture.runtime.paths.installedRecoveryService + ".d"
	manualHostUpgradeLinuxMkdir(t, dropInDirectory, 0o755)
	for name, payload := range map[string]string{
		"10-executable-guard.conf":      "[Unit]\nConditionFileIsExecutable=/opt/autostream/host-agent/slots/%i/bin/autostream-local-executor\n",
		"20-bootstrap-state-guard.conf": "[Unit]\nConditionPathExists=/var/lib/autostream-local-executor/host-self-update/state.json\n",
	} {
		manualHostUpgradeLinuxWriteFile(
			t, filepath.Join(dropInDirectory, name), []byte(payload), 0o644,
		)
	}
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)
}

func configureManualHostUpgradeLegacyExecutorUnit(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	corrected, legacy := manualHostExecutorUnitTemplateBytes(t)
	artifactPath := filepath.Join(
		fixture.artifactRoot,
		"systemd",
		"autostream-local-executor.service",
	)
	manualHostUpgradeLinuxWriteFile(t, artifactPath, corrected, 0o644)
	manualHostUpgradeLinuxWriteFile(
		t, fixture.runtime.paths.installedExecutorUnit, legacy, 0o644,
	)
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)
}

func copyManualHostUpgradeArtifactBinariesToSlot(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
	slot string,
) {
	t.Helper()
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		payload, err := os.ReadFile(filepath.Join(
			fixture.artifactRoot, "bin", binary,
		))
		if err != nil {
			t.Fatal(err)
		}
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(fixture.runtime.selfUpdate.slotsRoot, slot, "bin", binary),
			payload,
			0o755,
		)
	}
}

func configureManualHostUpgradeDowngradeArtifact(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(fixture.artifactRoot, "bin", binary),
			[]byte("old:"+binary+"\n"),
			0o755,
		)
	}
	manifestPath := filepath.Join(fixture.artifactRoot, "artifact-manifest.json")
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest manualHostArtifactManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SourceVersion = manualHostUpgradeTestOldVersion
	manifest.Commit = manualHostUpgradeTestOldCommit
	manifest.BuildDate = manualHostUpgradeTestOldBuildDate.Format(
		"2006-01-02T15:04:05Z",
	)
	manifest.Archive.Root = "autostream-host-agent_" +
		manualHostUpgradeTestOldVersion + "_linux_amd64"
	manifest.Archive.Name = manifest.Archive.Root + ".tar.gz"
	manifest.Compatibility.MinimumPanelVersion = manualHostUpgradeTestOldVersion
	payload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxWriteFile(
		t, manifestPath, append(payload, '\n'), 0o644,
	)
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)
}

func assertManualHostUpgradeRecoveryUnitConverged(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	installed, err := os.ReadFile(fixture.runtime.paths.installedRecoveryService)
	if err != nil || manualHostRecoveryUnitDigest(installed) !=
		manualHostRecoveryUnitUpdaterCorrectedDigest {
		t.Fatalf("recovery unit did not converge: err=%v", err)
	}
	if _, err := os.Lstat(
		fixture.runtime.paths.installedRecoveryService + ".d",
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery drop-in directory remained: %v", err)
	}
}

func manualHostUpgradeLinuxUnitPaths(root string) manualHostUpgradePaths {
	return manualHostUpgradePaths{
		installedAgentUnit: filepath.Join(
			root, "systemd", "autostream-host-agent.service",
		),
		installedExecutorUnit: filepath.Join(
			root, "systemd", "autostream-local-executor.service",
		),
		installedExecutorSocket: filepath.Join(
			root, "systemd", "autostream-local-executor.socket",
		),
		installedExecutorTmpfiles: filepath.Join(
			root, "tmpfiles.d", "autostream-local-executor.conf",
		),
		installedRecoveryService: filepath.Join(
			root,
			"systemd",
			"autostream-host-self-update-recovery@.service",
		),
		installedRecoveryTimer: filepath.Join(
			root,
			"systemd",
			"autostream-host-self-update-recovery@.timer",
		),
	}
}

func manualHostUpgradeLinuxMkdir(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func manualHostUpgradeLinuxWriteFile(
	t *testing.T,
	path string,
	payload []byte,
	mode fs.FileMode,
) {
	t.Helper()
	directory := filepath.Dir(path)
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		manualHostUpgradeLinuxMkdir(t, directory, 0o755)
	} else if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func manualHostUpgradeLinuxWriteChecksums(t *testing.T, root string) {
	t.Helper()
	entries := make([]string, 0, 16)
	err := filepath.WalkDir(root, func(
		path string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() == "checksums.txt" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		entries = append(
			entries,
			digest+"  ./"+filepath.ToSlash(relative),
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	manualHostUpgradeLinuxWriteFile(
		t,
		filepath.Join(root, "checksums.txt"),
		[]byte(strings.Join(entries, "\n")+"\n"),
		0o644,
	)
}
