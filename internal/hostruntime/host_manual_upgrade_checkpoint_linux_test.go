//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManualHostUpgradeProductionArtifactRequiresInstallerStaging(
	t *testing.T,
) {
	unsafeStage := filepath.Join(
		t.TempDir(),
		"autostream-host-agent-install.A1b2C3d4",
	)
	unsafeRoot := filepath.Join(unsafeStage, "unpack", "artifact")
	manualHostUpgradeLinuxMkdir(t, unsafeRoot, 0o755)
	if err := os.Chmod(unsafeStage, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateManualHostUpgradeArtifactStagingPath(
		unsafeRoot,
		false,
	); err == nil || !strings.Contains(err.Error(), "outside the installer") {
		t.Fatalf("replaceable parent artifact err=%v", err)
	}

	if os.Geteuid() != 0 {
		t.Skip("root ownership contract is exercised by the root Docker fixture")
	}
	var stage string
	for attempt := 0; attempt < 100; attempt++ {
		name := fmt.Sprintf(
			"autostream-host-agent-install.%08x",
			uint32(time.Now().UnixNano()+int64(attempt)),
		)
		candidate := filepath.Join("/var/tmp", name)
		if err := os.Mkdir(candidate, 0o700); err == nil {
			stage = candidate
			break
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatalf("create production-shaped stage: %v", err)
		}
	}
	if stage == "" {
		t.Fatal("could not allocate a production-shaped stage")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stage); err != nil {
			t.Errorf("remove production-shaped stage: %v", err)
		}
	})
	unpack := filepath.Join(stage, "unpack")
	root := filepath.Join(unpack, "autostream-host-agent_v9.9.9_linux_amd64")
	manualHostUpgradeLinuxMkdir(t, unpack, 0o700)
	manualHostUpgradeLinuxMkdir(t, root, 0o755)
	if err := validateManualHostUpgradeArtifactStagingPath(root, false); err != nil {
		t.Fatalf("installer-created staging rejected: %v", err)
	}
	if err := os.Chmod(unpack, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateManualHostUpgradeArtifactStagingPath(
		root,
		false,
	); err == nil || !strings.Contains(err.Error(), "staging directory is unsafe") {
		t.Fatalf("replaceable unpack directory err=%v", err)
	}
}

func TestManualHostUpgradeAllowsTerminalLocalCheckpointWithoutMutation(
	t *testing.T,
) {
	for _, phase := range []string{"succeeded", "rolled_back"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			checkpoint := writeManualHostUpgradeLinuxCheckpoint(t, fixture, phase)
			before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err != nil {
				t.Fatalf("upgrade with terminal checkpoint: %v", err)
			}
			if result.ActiveSlot != HostSelfUpdateSlotB ||
				result.Version != manualHostUpgradeTestTargetVersion {
				t.Fatalf("result=%+v", result)
			}
			assertManualHostUpgradeLinuxProtectedFileUnchanged(
				t, checkpoint, before,
			)
		})
	}
}

func TestManualHostUpgradePreservesTerminalCheckpointAcrossRollback(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	checkpoint := writeManualHostUpgradeLinuxCheckpoint(t, fixture, "succeeded")
	before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)
	fixture.runner.failTargetAgent = true

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil {
		t.Fatal("injected activation failure unexpectedly succeeded")
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(t, checkpoint, before)
}

func TestManualHostUpgradeRejectsNonTerminalLocalCheckpointAndRestoresAgent(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	checkpoint := writeManualHostUpgradeLinuxCheckpoint(
		t, fixture, "started",
	)
	before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"non-terminal Local Executor update checkpoint",
	) {
		t.Fatalf("non-terminal checkpoint result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(t, checkpoint, before)
	assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
}

func TestManualHostUpgradeRejectsInvalidLocalCheckpointBeforeMutation(
	t *testing.T,
) {
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{name: "malformed JSON", payload: []byte("{not-json\n")},
		{
			name: "invalid fields",
			payload: []byte(
				`{"schema_version":1,"job_id":"fixture-job-1",` +
					`"target_id":"invalid target","deployment_mode":"systemd",` +
					`"phase":"succeeded","target_version":"v2.0.0"}` + "\n",
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			checkpoint := filepath.Join(
				fixture.runtime.paths.localExecutorStateRoot,
				".autostream-updater-invalid.checkpoint.json",
			)
			manualHostUpgradeLinuxWriteFile(t, checkpoint, test.payload, 0o600)
			checkpointBefore := snapshotManualHostUpgradeLinuxProtectedFile(
				t, checkpoint,
			)
			identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
				t, fixture.identityPath,
			)
			policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
				t, fixture.policyPath,
			)

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil || !strings.Contains(
				err.Error(), "Local Executor update checkpoint is invalid",
			) || result != (ManualHostUpgradeResult{}) {
				t.Fatalf("invalid checkpoint result=%+v err=%v", result, err)
			}
			assertManualHostUpgradeLinuxProtectedFileUnchanged(
				t, checkpoint, checkpointBefore,
			)
			assertManualHostUpgradeLinuxProtectedFileUnchanged(
				t, fixture.identityPath, identityBefore,
			)
			assertManualHostUpgradeLinuxProtectedFileUnchanged(
				t, fixture.policyPath, policyBefore,
			)
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
		})
	}
}

func TestManualHostUpgradeFixedSystemdCheckpointTargetsCoverEveryProfile(
	t *testing.T,
) {
	targets := manualHostUpgradeFixedSystemdCheckpointTargets()
	if len(targets) != len(manualHostUpgradeFixedSystemdServiceTypes) {
		t.Fatalf(
			"fixed checkpoint targets=%d want=%d",
			len(targets),
			len(manualHostUpgradeFixedSystemdServiceTypes),
		)
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		profile, ok := standardSystemdProfileFor(target.ServiceType)
		if !ok || target.DeploymentMode != ModeSystemd || target.Systemd == nil ||
			target.Systemd.Unit != profile.unit ||
			target.Systemd.ReleaseRoot != profile.releaseRoot {
			t.Fatalf("fixed checkpoint target=%+v profile=%+v", target, profile)
		}
		path := checkpointPath(target)
		if filepath.Dir(path) != profile.releaseRoot || seen[path] {
			t.Fatalf("fixed checkpoint path=%q duplicate=%v", path, seen[path])
		}
		seen[path] = true
	}
}

func TestManualHostUpgradeScansFixedCheckpointAbsentFromConfigurations(
	t *testing.T,
) {
	tests := []struct {
		name      string
		phase     string
		invalid   bool
		wantError string
	}{
		{name: "invalid", invalid: true, wantError: "checkpoint is invalid"},
		{name: "non-terminal", phase: "started", wantError: "non-terminal"},
		{name: "succeeded", phase: "succeeded"},
		{name: "rolled back", phase: "rolled_back"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			profile, ok := standardSystemdProfileFor("encoder_recorder")
			if !ok {
				t.Fatal("missing encoder_recorder systemd profile")
			}
			fixed := Target{
				TargetID:       "encoder-removed-from-policy",
				ServiceType:    "encoder_recorder",
				DeploymentMode: ModeSystemd,
				Systemd: &SystemdTarget{
					Unit: profile.unit,
					ReleaseRoot: filepath.Join(
						fixture.root,
						"opt",
						"autostream",
						"encoder-recorder",
						"releases",
					),
				},
			}
			fixture.runtime.fixedCheckpoints = []Target{fixed}
			path := checkpointPath(fixed)
			var payload []byte
			if test.invalid {
				payload = []byte("{}\n")
			} else {
				checkpoint := updateCheckpoint{
					SchemaVersion:  checkpointSchemaVersion,
					JobID:          "fixed-checkpoint-job",
					TargetID:       "historical-encoder-01",
					DeploymentMode: ModeSystemd,
					Phase:          test.phase,
					TargetVersion:  "v2.0.0",
				}
				var err error
				payload, err = json.Marshal(checkpoint)
				if err != nil {
					t.Fatal(err)
				}
				payload = append(payload, '\n')
			}
			manualHostUpgradeLinuxWriteFile(t, path, payload, 0o600)
			before := snapshotManualHostUpgradeLinuxProtectedFile(t, path)

			policy, err := LoadLocalExecutorPolicy(fixture.policyPath, false)
			if err != nil {
				t.Fatalf("load fixture policy: %v", err)
			}
			err = scanManualHostUpdateCheckpoints(policy, nil, fixture.runtime)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("terminal fixed checkpoint rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("fixed checkpoint err=%v want=%q", err, test.wantError)
			}
			assertManualHostUpgradeLinuxProtectedFileUnchanged(t, path, before)
		})
	}
}
