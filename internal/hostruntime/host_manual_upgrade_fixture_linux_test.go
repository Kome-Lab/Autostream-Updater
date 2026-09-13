//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func assertManualHostUpgradeLinuxRejectedBeforeMutation(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	if !fixture.runner.agentActive || fixture.runner.stopCalls != 0 ||
		fixture.runner.agentIdentityAfterRestart != 0 {
		t.Fatalf(
			"old Agent was not restored and identity-verified: active=%v stops=%d post_restart_identity=%d",
			fixture.runner.agentActive,
			fixture.runner.stopCalls,
			fixture.runner.agentIdentityAfterRestart,
		)
	}
	if len(fixture.runner.restartOrder) != 0 {
		t.Fatalf(
			"rejected upgrade unexpectedly restarted services: %v",
			fixture.runner.restartOrder,
		)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("rejected upgrade current slot=%q err=%v", current, err)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.statePath,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected upgrade changed durable state: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotB,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected upgrade staged slot b: %v", err)
	}
}

func writeManualHostUpgradeLinuxCheckpoint(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
	phase string,
) string {
	t.Helper()
	checkpoint := updateCheckpoint{
		SchemaVersion:  checkpointSchemaVersion,
		JobID:          "fixture-job-1",
		TargetID:       "orphan-worker-01",
		DeploymentMode: ModeSystemd,
		Phase:          phase,
		TargetVersion:  "v2.0.0",
	}
	payload, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(
		fixture.runtime.paths.localExecutorStateRoot,
		".autostream-updater-fixture.checkpoint.json",
	)
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func removeManualHostUpgradeLinuxStateRoot(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	if err := os.Remove(fixture.runtime.selfUpdate.stateRoot); err != nil {
		t.Fatalf("remove fixture Host self-update state root: %v", err)
	}
}

func newManualHostUpgradeLinuxFixture(
	t *testing.T,
) *manualHostUpgradeLinuxFixture {
	t.Helper()
	fixture := &manualHostUpgradeLinuxFixture{
		root:               t.TempDir(),
		processExeResolves: make(map[int]int),
	}
	installRoot := filepath.Join(fixture.root, "opt", "autostream", "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	stateRoot := filepath.Join(
		fixture.root,
		"var",
		"lib",
		"autostream-local-executor",
		"host-self-update",
	)
	manualHostUpgradeLinuxMkdir(t, filepath.Join(slotsRoot, HostSelfUpdateSlotA, "bin"), 0o755)
	manualHostUpgradeLinuxMkdir(t, stateRoot, 0o700)
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(slotsRoot, HostSelfUpdateSlotA, "bin", binary),
			[]byte("old:"+binary+"\n"),
			0o755,
		)
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(
		filepath.Join("slots", HostSelfUpdateSlotA),
		currentLink,
	); err != nil {
		t.Fatal(err)
	}

	fixture.artifactRoot = filepath.Join(fixture.root, "verified-artifact")
	manualHostUpgradeLinuxMkdir(t, filepath.Join(fixture.artifactRoot, "bin"), 0o755)
	manualHostUpgradeLinuxMkdir(t, filepath.Join(fixture.artifactRoot, "systemd"), 0o755)
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(fixture.artifactRoot, "bin", binary),
			[]byte("target:"+binary+"\n"),
			0o755,
		)
	}

	installedRoot := filepath.Join(fixture.root, "etc")
	unitPaths := manualHostUpgradeLinuxUnitPaths(installedRoot)
	for _, unit := range []struct {
		source    string
		installed string
	}{
		{"autostream-host-agent.service", unitPaths.installedAgentUnit},
		{"autostream-local-executor.service", unitPaths.installedExecutorUnit},
		{"autostream-local-executor.socket", unitPaths.installedExecutorSocket},
		{"autostream-local-executor.tmpfiles", unitPaths.installedExecutorTmpfiles},
		{"autostream-host-self-update-recovery@.service", unitPaths.installedRecoveryService},
		{"autostream-host-self-update-recovery@.timer", unitPaths.installedRecoveryTimer},
	} {
		payload := []byte("fixture:" + unit.source + "\n")
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(fixture.artifactRoot, "systemd", unit.source),
			payload,
			0o644,
		)
		manualHostUpgradeLinuxWriteFile(t, unit.installed, payload, 0o644)
	}

	manifest := manualHostArtifactManifest{
		SchemaVersion: 1,
		Component:     "host-agent",
		SourceVersion: manualHostUpgradeTestTargetVersion,
		Commit:        manualHostUpgradeTestTargetCommit,
		BuildDate:     manualHostUpgradeTestBuildDate.Format("2006-01-02T15:04:05Z"),
	}
	manifest.Platform.OS = "linux"
	manifest.Platform.Arch = "amd64"
	manifest.Archive.Root = "autostream-host-agent_" +
		manualHostUpgradeTestTargetVersion + "_linux_amd64"
	manifest.Archive.Name = manifest.Archive.Root + ".tar.gz"
	manifest.Compatibility.MinimumPanelVersion =
		manualHostUpgradeTestTargetVersion
	manifest.Compatibility.RollbackCompatible = true
	manifest.Compatibility.DatabaseSchema = "none"
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxWriteFile(
		t,
		filepath.Join(fixture.artifactRoot, "artifact-manifest.json"),
		append(manifestPayload, '\n'),
		0o644,
	)
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)

	identityRoot := filepath.Join(fixture.root, "etc", "autostream", "updater")
	fixture.identityPath = filepath.Join(identityRoot, "agent.yaml")
	identityPayload := []byte(
		"panel_url: https://panel.example.com\n" +
			"node_id: host-a\n" +
			"runtime_token: runtime-secret\n" +
			"service_name: Host A\n",
	)
	manualHostUpgradeLinuxWriteFile(t, fixture.identityPath, identityPayload, 0o600)
	fixture.policyPath = filepath.Join(
		fixture.root,
		"etc",
		"autostream-local-executor",
		"policy.json",
	)
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.SourcePolicyRevision = 3
	policy.ProjectionRevision = 5
	policy.Mutation = &LocalExecutorMutationPolicy{
		PanelURL: "https://panel.example.com",
	}
	policyPayload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxWriteFile(
		t, fixture.policyPath, append(policyPayload, '\n'), 0o600,
	)

	fixture.publicAgentPath = filepath.Join(
		fixture.root, "usr", "local", "bin", "autostream-host-agent",
	)
	fixture.publicExecutorPath = filepath.Join(
		fixture.root,
		"usr",
		"local",
		"libexec",
		"autostream-local-executor",
	)
	for path, target := range map[string]string{
		fixture.publicAgentPath: filepath.Join(
			currentLink, "bin", "autostream-host-agent",
		),
		fixture.publicExecutorPath: filepath.Join(
			currentLink, "bin", "autostream-local-executor",
		),
	} {
		manualHostUpgradeLinuxMkdir(t, filepath.Dir(path), 0o755)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}

	fixture.runner = &manualHostUpgradeLinuxRunner{
		currentLink:         currentLink,
		slotsRoot:           slotsRoot,
		agentActive:         true,
		executorActive:      true,
		mainPIDReads:        make(map[string]int),
		identityReads:       make(map[string]int),
		inactiveUnits:       make(map[string]bool),
		disabledUnits:       make(map[string]bool),
		recoveryFailedUnits: make(map[string]bool),
		recoveryUnitPath:    unitPaths.installedRecoveryService,
		executorUnitPath:    unitPaths.installedExecutorUnit,
	}
	selfUpdate := hostSelfUpdateExecutorRuntime{
		installRoot:         installRoot,
		currentLink:         currentLink,
		slotsRoot:           slotsRoot,
		stateRoot:           stateRoot,
		statePath:           filepath.Join(stateRoot, "state.json"),
		grantStatePath:      filepath.Join(stateRoot, "grant-state.json"),
		downloadRoot:        filepath.Join(stateRoot, "downloads"),
		arch:                "amd64",
		executorVersion:     manualHostUpgradeTestTargetVersion,
		runner:              fixture.runner,
		identityRunner:      fixture.runner,
		now:                 func() time.Time { return manualHostUpgradeTestActivationNow },
		verificationTimeout: time.Minute,
		allowTestPaths:      true,
	}
	fixture.runtime = manualHostUpgradeRuntime{
		selfUpdate: selfUpdate,
		paths: manualHostUpgradePaths{
			identityPath:              fixture.identityPath,
			stagedIdentityPath:        filepath.Join(identityRoot, "agent.staged.yaml"),
			wipingIdentityPath:        filepath.Join(identityRoot, ".agent.staged.wipe"),
			policyPath:                fixture.policyPath,
			hostStateRoot:             filepath.Join(fixture.root, "var", "lib", "autostream-host-agent"),
			localExecutorStateRoot:    filepath.Join(fixture.root, "var", "lib", "autostream-local-executor"),
			runtimeCredentialPath:     filepath.Join(fixture.root, "var", "lib", "runtime-credential.json"),
			publicAgentPath:           fixture.publicAgentPath,
			publicExecutorPath:        fixture.publicExecutorPath,
			installedAgentUnit:        unitPaths.installedAgentUnit,
			installedExecutorUnit:     unitPaths.installedExecutorUnit,
			installedExecutorSocket:   unitPaths.installedExecutorSocket,
			installedExecutorTmpfiles: unitPaths.installedExecutorTmpfiles,
			installedRecoveryService:  unitPaths.installedRecoveryService,
			installedRecoveryTimer:    unitPaths.installedRecoveryTimer,
		},
		runner:         fixture.runner,
		identityRunner: fixture.runner,
		now:            func() time.Time { return manualHostUpgradeTestActivationNow },
		waitStable: func(context.Context) error {
			fixture.waitStableCalls++
			return nil
		},
		resolveProcessExe: func(pid int) (string, error) {
			fixture.processExeResolves[pid]++
			slot, err := fixture.runner.currentSlot()
			if err != nil {
				return "", err
			}
			var binary string
			switch pid {
			case 3101:
				binary = "autostream-host-agent"
			case 3102:
				binary = "autostream-local-executor"
			default:
				return "", errors.New("unknown test MainPID")
			}
			return filepath.Join(slotsRoot, slot, "bin", binary), nil
		},
		acquireLocks:   func() (func(), error) { return func() {}, nil },
		allowTestPaths: true,
	}
	fixture.runtime.selfUpdate.watchdogStatus = func(
		context.Context,
	) (HostSelfUpdateRuntimeStatus, error) {
		fixture.watchdogCalls++
		state, err := fixture.runtime.selfUpdate.loadPersistedState()
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		current, err := fixture.runtime.selfUpdate.readCurrentSlot()
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		executorVersion := manualHostUpgradeTestOldVersion
		if current == HostSelfUpdateSlotB {
			executorVersion = manualHostUpgradeTestTargetVersion
		}
		return HostSelfUpdateRuntimeStatus{
			State:                   state,
			CurrentSlot:             current,
			ExecutorVersion:         executorVersion,
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
			LastAction:              HostSelfUpdateActionNone,
		}, nil
	}
	fixture.request = ManualHostUpgradeRequest{
		ArtifactRoot:  fixture.artifactRoot,
		ArchiveSHA256: strings.Repeat("c", 64),
		ArchiveSize:   4096,
	}
	artifact, err := inspectManualHostUpgradeArtifact(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil {
		t.Fatalf("inspect fixture artifact: %v", err)
	}
	fixture.targetRequest, err = newManualHostSelfUpdateRequest(
		artifact, fixture.request,
	)
	if err != nil {
		t.Fatalf("bind fixture artifact: %v", err)
	}
	fixture.runner.identityReads = make(map[string]int)
	return fixture
}
