//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateManualHostExecutorUnitLegacy(t *testing.T) {
	fixture := newManualHostExecutorUnitFixture(t, false)
	if err := migrateManualHostExecutorUnitForward(
		context.Background(), fixture.config(),
	); err != nil {
		t.Fatalf("migrateManualHostExecutorUnitForward: %v", err)
	}
	assertManualHostExecutorUnitCorrected(t, fixture)
	if fixture.runner.reloads != 1 {
		t.Fatalf("daemon-reload calls=%d, want 1", fixture.runner.reloads)
	}
}

func TestMigrateManualHostExecutorUnitCorrectedNoOp(t *testing.T) {
	fixture := newManualHostExecutorUnitFixture(t, true)
	if err := migrateManualHostExecutorUnitForward(
		context.Background(), fixture.config(),
	); err != nil {
		t.Fatalf("migrateManualHostExecutorUnitForward: %v", err)
	}
	assertManualHostExecutorUnitCorrected(t, fixture)
	if fixture.runner.reloads != 0 {
		t.Fatalf("daemon-reload calls=%d, want 0", fixture.runner.reloads)
	}
}

func TestMigrateManualHostExecutorUnitRejectsEffectiveDropIn(t *testing.T) {
	fixture := newManualHostExecutorUnitFixture(t, false)
	fixture.runner.dropInPaths = "/run/systemd/system/autostream-local-executor.service.d/override.conf"
	before, err := os.ReadFile(fixture.installedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateManualHostExecutorUnitForward(
		context.Background(), fixture.config(),
	); err == nil || !strings.Contains(err.Error(), "effective Local Executor unit") {
		t.Fatalf("drop-in migration err=%v", err)
	}
	after, err := os.ReadFile(fixture.installedPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected migration changed installed unit: err=%v", err)
	}
	if fixture.runner.reloads != 0 {
		t.Fatalf("rejected migration reloaded systemd %d times", fixture.runner.reloads)
	}
}

func TestMigrateManualHostExecutorUnitRejectsUnknownDigest(t *testing.T) {
	fixture := newManualHostExecutorUnitFixture(t, false)
	if err := os.WriteFile(fixture.installedPath, []byte("unknown\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := migrateManualHostExecutorUnitForward(
		context.Background(), fixture.config(),
	); err == nil || !strings.Contains(err.Error(), "known migration source") {
		t.Fatalf("unknown digest migration err=%v", err)
	}
	if fixture.runner.reloads != 0 {
		t.Fatalf("rejected migration reloaded systemd %d times", fixture.runner.reloads)
	}
}

type manualHostExecutorUnitFixture struct {
	candidatePath string
	installedPath string
	runner        *manualHostExecutorUnitRunner
}

func (f manualHostExecutorUnitFixture) config() manualHostExecutorUnitMigrationConfig {
	return manualHostExecutorUnitMigrationConfig{
		CandidatePath:  f.candidatePath,
		InstalledPath:  f.installedPath,
		Runner:         f.runner,
		AllowTestPaths: true,
	}
}

func newManualHostExecutorUnitFixture(
	t *testing.T,
	corrected bool,
) manualHostExecutorUnitFixture {
	t.Helper()
	root := t.TempDir()
	candidatePath := filepath.Join(root, "candidate.service")
	installedPath := filepath.Join(root, "installed.service")
	correctedBytes, legacyBytes := manualHostExecutorUnitTemplateBytes(t)
	if err := os.WriteFile(candidatePath, correctedBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	installedBytes := legacyBytes
	if corrected {
		installedBytes = correctedBytes
	}
	if err := os.WriteFile(installedPath, installedBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return manualHostExecutorUnitFixture{
		candidatePath: candidatePath,
		installedPath: installedPath,
		runner: &manualHostExecutorUnitRunner{
			installedPath: installedPath,
		},
	}
}

func manualHostExecutorUnitTemplateBytes(t *testing.T) ([]byte, []byte) {
	t.Helper()
	corrected, err := os.ReadFile(filepath.Join(
		"..", "..", "systemd", "autostream-local-executor.service.example",
	))
	if err != nil {
		t.Fatal(err)
	}
	comment := []byte("# Inherit the system manager's root identity. An explicit User=root/Group=root\n" +
		"# can remove CAP_SETUID from the effective set on systemd 255, while this\n" +
		"# policy-bounded executor needs it only to run candidate smoke checks via\n" +
		"# /usr/sbin/runuser.\n")
	legacy := bytes.Replace(
		corrected,
		comment,
		[]byte("User=root\nGroup=root\n"),
		1,
	)
	if bytes.Equal(corrected, legacy) {
		t.Fatal("failed to construct legacy Local Executor unit")
	}
	if got := manualHostExecutorUnitTestDigest(legacy); got != manualHostExecutorUnitLegacyDigest {
		t.Fatalf("legacy digest=%s want=%s", got, manualHostExecutorUnitLegacyDigest)
	}
	if got := manualHostExecutorUnitTestDigest(corrected); got != manualHostExecutorUnitCorrectedDigest {
		t.Fatalf("corrected digest=%s want=%s", got, manualHostExecutorUnitCorrectedDigest)
	}
	return corrected, legacy
}

func manualHostExecutorUnitTestDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func assertManualHostExecutorUnitCorrected(
	t *testing.T,
	fixture manualHostExecutorUnitFixture,
) {
	t.Helper()
	payload, err := os.ReadFile(fixture.installedPath)
	if err != nil || manualHostExecutorUnitTestDigest(payload) !=
		manualHostExecutorUnitCorrectedDigest {
		t.Fatalf("installed Local Executor unit digest=%s err=%v", manualHostExecutorUnitTestDigest(payload), err)
	}
}

type manualHostExecutorUnitRunner struct {
	installedPath string
	dropInPaths   string
	needReload    bool
	reloads       int
}

func (r *manualHostExecutorUnitRunner) Run(
	_ context.Context,
	_ string,
	_ []string,
	name string,
	args ...string,
) (string, error) {
	if name != "/usr/bin/systemctl" || len(args) == 0 {
		return "", fmt.Errorf("unexpected command %s %v", name, args)
	}
	switch args[0] {
	case "show":
		return fmt.Sprintf(
			"FragmentPath=%s\nDropInPaths=%s\nNeedDaemonReload=%s\n",
			r.installedPath,
			r.dropInPaths,
			map[bool]string{true: "yes", false: "no"}[r.needReload],
		), nil
	case "daemon-reload":
		r.reloads++
		r.needReload = false
		return "", nil
	default:
		return "", errors.New("unexpected systemctl operation")
	}
}
