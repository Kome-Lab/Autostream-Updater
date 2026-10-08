//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kome-Lab/Autostream-Updater/internal/version"
)

type manualCompatibilityIdentityRunner struct {
	base          CommandRunner
	sourceVersion string
	drift         string
}

func (r manualCompatibilityIdentityRunner) Run(
	ctx context.Context,
	directory string,
	environment []string,
	name string,
	arguments ...string,
) (string, error) {
	output, err := r.base.Run(ctx, directory, environment, name, arguments...)
	if err != nil {
		return "", err
	}
	output = strings.Replace(output,
		" "+manualHostUpgradeTestTargetVersion+"\n",
		" "+r.sourceVersion+"\n", 1,
	)
	if filepath.Base(name) == "autostream-local-executor" {
		switch r.drift {
		case "pair_version":
			output = strings.Replace(output, " "+r.sourceVersion+"\n", " v2.0.0\n", 1)
		case "pair_commit":
			output = strings.Replace(output, manualHostUpgradeTestTargetCommit, strings.Repeat("f", 40), 1)
		case "mutation_protocol":
			output = strings.Replace(output, "mutation_protocol: 2", "mutation_protocol: 1", 1)
		case "recovery_protocol":
			output = strings.Replace(output, "recovery_protocol: 2", "recovery_protocol: 1", 1)
		}
	}
	return output, nil
}

func writeManualCompatibilityManifest(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
	sourceVersion, minimumPanel string,
) {
	t.Helper()
	path := filepath.Join(fixture.artifactRoot, "artifact-manifest.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest manualHostArtifactManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SourceVersion = sourceVersion
	manifest.Archive.Root = "autostream-host-agent_" + sourceVersion + "_linux_amd64"
	manifest.Archive.Name = manifest.Archive.Root + ".tar.gz"
	manifest.Compatibility.MinimumPanelVersion = minimumPanel
	payload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxWriteFile(t, path, append(payload, '\n'), 0o644)
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)
}

func TestManualHostUpgradePanelCompatibilityFloor(t *testing.T) {
	for _, sourceVersion := range []string{"v2.0.0", "v2.0.1", "v2.1.0"} {
		t.Run("accept_"+sourceVersion, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			writeManualCompatibilityManifest(t, fixture, sourceVersion, version.MinimumControlPanelVersion)
			fixture.runtime.identityRunner = manualCompatibilityIdentityRunner{
				base: fixture.runner, sourceVersion: sourceVersion,
			}
			artifact, err := inspectManualHostUpgradeArtifact(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err != nil || artifact.Version != sourceVersion ||
				artifact.MinimumPanel != version.MinimumControlPanelVersion {
				t.Fatalf("independent source/floor rejected: version=%s err=%v", sourceVersion, err)
			}
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
		})
	}
	for _, testCase := range []struct {
		name          string
		sourceVersion string
		floor         string
		drift         string
	}{
		{"blank_floor", "v2.0.1", "", ""},
		{"unsupported_floor", "v2.0.1", "v1.9.11", ""},
		{"prerelease_floor", "v2.0.1", "v2.0.0-beta", ""},
		{"source_as_floor", "v2.0.1", "v2.0.1", ""},
		{"future_floor", "v2.0.1", "v9.0.0", ""},
		{"source_below_floor", "v1.9.11", "v2.0.0", ""},
		{"source_prerelease", "v2.0.1-beta", "v2.0.0", ""},
		{"source_leading_zero", "v02.0.1", "v2.0.0", ""},
		{"pair_version", "v2.0.1", "v2.0.0", "pair_version"},
		{"pair_commit", "v2.0.1", "v2.0.0", "pair_commit"},
		{"mutation_protocol", "v2.0.1", "v2.0.0", "mutation_protocol"},
		{"recovery_protocol", "v2.0.1", "v2.0.0", "recovery_protocol"},
	} {
		t.Run("reject_"+testCase.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			writeManualCompatibilityManifest(t, fixture, testCase.sourceVersion, testCase.floor)
			fixture.runtime.identityRunner = manualCompatibilityIdentityRunner{
				base: fixture.runner, sourceVersion: testCase.sourceVersion, drift: testCase.drift,
			}
			if _, err := inspectManualHostUpgradeArtifact(
				context.Background(), fixture.request, fixture.runtime,
			); err == nil {
				t.Fatal("unreviewed floor or paired runtime identity accepted")
			}
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
		})
	}
}
