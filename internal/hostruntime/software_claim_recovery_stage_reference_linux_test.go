//go:build linux

package hostruntime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

type ui185FileObservation struct {
	Mode                 os.FileMode
	Size, Modified       int64
	Device, Inode, Links uint64
	UID, GID             uint32
	Changed              syscall.Timespec
	SHA256               string
}

// Ignore access time: reading evidence may update it. Preserve bytes, inode,
// owner, permissions, link count, size, mtime and ctime, including directories.
func ui185Snapshot(t *testing.T, roots ...string) map[string]ui185FileObservation {
	t.Helper()
	result := make(map[string]ui185FileObservation)
	for _, root := range roots {
		if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
			continue
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatal("Linux metadata unavailable")
			}
			observation := ui185FileObservation{Mode: info.Mode(), Size: info.Size(), Modified: info.ModTime().UnixNano(), Device: uint64(stat.Dev), Inode: stat.Ino, Links: uint64(stat.Nlink), UID: stat.Uid, GID: stat.Gid, Changed: stat.Ctim}
			var body []byte
			if info.Mode().IsRegular() {
				body, err = os.ReadFile(path)
			} else if info.Mode()&os.ModeSymlink != 0 {
				var link string
				link, err = os.Readlink(path)
				body = []byte(link)
			}
			if err != nil {
				return err
			}
			if body != nil {
				sum := sha256.Sum256(body)
				observation.SHA256 = hex.EncodeToString(sum[:])
			}
			result[path] = observation
			return nil
		})
		if err != nil {
			t.Fatal("snapshot immutable fixture evidence", err)
		}
	}
	return result
}

func ui185RequireSnapshot(t *testing.T, before map[string]ui185FileObservation, roots ...string) {
	t.Helper()
	if !reflect.DeepEqual(before, ui185Snapshot(t, roots...)) {
		t.Fatal("stage reference inspection changed source bytes or metadata")
	}
}

func ui185SnapshotDigest(snapshot map[string]ui185FileObservation) string {
	body, _ := json.Marshal(snapshot)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Use the real extraction return value used by ReleaseDownloader, rather than
// assigning a flat stage root. The full-chain fixture also calls prepareExecutorStage.
func ui185ExtractedLedger(t *testing.T, root, target, job string) executorMutationLedger {
	t.Helper()
	container := filepath.Join(root, "stages", remoteStableKey(job, target))
	artifact := filepath.Join(container, "artifact")
	manualHostUpgradeLinuxMkdir(t, artifact, 0o700)
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	body := []byte("UI185 immutable synthetic package\n")
	if tw.WriteHeader(&tar.Header{Name: "autostream-control-panel_v2.0.1_linux_amd64/history.txt", Mode: 0o644, Size: int64(len(body))}) != nil {
		t.Fatal("archive header")
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if tw.Close() != nil || gz.Close() != nil {
		t.Fatal("archive close")
	}
	archivePath := filepath.Join(artifact, "release.tar.gz")
	manualHostUpgradeLinuxWriteFile(t, archivePath, archive.Bytes(), 0o600)
	extracted, err := ExtractTarGz(archivePath, filepath.Join(artifact, "extracted"), 4096, 8)
	if err != nil {
		t.Fatal(err)
	}
	ledger := executorMutationLedger{SchemaVersion: 1, JobID: job, TargetID: target, PlanSHA256: strings.Repeat("a", 64), SessionID: "session-0123456789abcdef", LeaseGeneration: 1, Operation: "reconcile", State: remoteLedgerTerminal,
		Intent: remoteMutationIntent{HostID: "fixture-host", TargetID: target, ServiceType: "control_panel", DeploymentMode: ModeSystemd, CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ConfigSHA256: "sha256:" + strings.Repeat("d", 64), ArtifactDigest: "sha256:" + strings.Repeat("c", 64)},
		Stage:  &remoteStage{RootDir: extracted, ArtifactDigest: "sha256:" + strings.Repeat("c", 64)}, Result: &ApplyResult{Status: "succeeded"}}
	if ledger.validate(target) != nil {
		t.Fatal("invalid generated terminal fixture")
	}
	return ledger
}

func ui185SaveLedger(t *testing.T, root string, ledger executorMutationLedger) string {
	t.Helper()
	path := filepath.Join(root, "ledger", "target-"+remoteStableKey(ledger.TargetID)+".json")
	writeSoftwareClaimRecoveryRootJSON(t, path, ledger)
	return path
}

func ui185StageReferenceChecks(t *testing.T) {
	t.Helper()
	cases := []string{"nested_two", "direct_root", "legacy_direct_name", "docker_direct", "docker_nested", "external_history", "removed_history", "requested_terminal", "blocked_terminal", "other_nonterminal", "broken_json", "unknown_field", "bad_filename", "unsafe_ledger_mode", "ledger_symlink", "relative", "parent_escape", "prefix_collision", "noncanonical", "unknown_layout", "unknown_container", "container_symlink", "intermediate_symlink", "leaf_symlink", "unsafe_container_mode", "unsafe_intermediate_mode", "unsafe_leaf_mode", "unsafe_ledger_owner", "unsafe_container_owner", "unsafe_intermediate_owner", "unsafe_leaf_owner", "missing_leaf", "ambiguous_nested", "ambiguous_direct", "unknown_stage", "manual_smoke", "request_residue", "result_residue"}
	for _, name := range cases {
		t.Run("ui185_"+name, func(t *testing.T) {
			fixture, policy, request, runtime := newSoftwareClaimRecoveryRootHarness(t)
			blockedJob := ""
			if name == "blocked_terminal" {
				f, p, local, rt, agent, panel, first := prepareSoftwareClaimRecoveryHistoryRootCompleted(t)
				next := prepareSoftwareClaimRecoveryHistorySuccessor(t, agent, panel, first, "orphan-job-three")
				local.SoftwareClaimRecovery = &SoftwareClaimRecoveryInspection{Request: next, ExecutorPolicySHA256: panel.policy.LocalExecutorPolicySHA256}
				fixture, policy, request, runtime = f, p, local, rt
				blockedJob = first.JobID
			}
			root := fixture.runtime.paths.localExecutorStateRoot
			job := request.SoftwareClaimRecovery.Request.JobID
			ledger := ui185ExtractedLedger(t, root, request.ServiceID, "old-terminal-job")
			second := ui185ExtractedLedger(t, root, "other-history-target", "other-terminal-job")
			path := ui185SaveLedger(t, root, ledger)
			ui185SaveLedger(t, root, second)
			container := filepath.Dir(filepath.Dir(filepath.Dir(ledger.Stage.RootDir)))
			accepted := name == "nested_two" || name == "direct_root" || name == "legacy_direct_name" || name == "docker_direct" || name == "external_history" || name == "removed_history"
			switch name {
			case "direct_root":
				ledger.Stage.RootDir = container
			case "legacy_direct_name":
				legacy := filepath.Join(root, "stages", "legacy-direct-stage")
				if os.Rename(container, legacy) != nil {
					t.Fatal("construct preserved direct-root contract")
				}
				ledger.Stage.RootDir = legacy
			case "docker_direct", "docker_nested":
				ledger.Intent.DeploymentMode = ModeDocker
				digest := "sha256:" + strings.Repeat("c", 64)
				ledger.Stage.DockerBaseline = &dockerMutationBaseline{VersionEnvSHA256: digest, VersionEnvMode: 0o600, VersionEnvExisted: true, BundleVersion: "v2.0.0", ManifestDigest: digest, SourceVersion: "v2.0.0", ContainerID: "fixture-container", ImageID: digest, RepositoryDigest: digest}
				if name == "docker_direct" {
					ledger.Stage.RootDir = container
				}
			case "external_history", "removed_history":
				extra := ledger
				copyStage := *ledger.Stage
				extra.Stage = &copyStage
				extra.TargetID, extra.Intent.TargetID, extra.JobID = "historical-target", "historical-target", "historical-job"
				extra.Stage.RootDir = filepath.Join(t.TempDir(), "already-removed")
				if name == "removed_history" {
					extra.Stage.RootDir = filepath.Join(root, "stages", remoteStableKey("removed"), "artifact", "extracted", "package")
				} else {
					manualHostUpgradeLinuxMkdir(t, extra.Stage.RootDir, 0o700)
				}
				ui185SaveLedger(t, root, extra)
			case "requested_terminal":
				ledger.JobID = job
			case "blocked_terminal":
				ledger.JobID = blockedJob
			case "other_nonterminal":
				ledger.State, ledger.Operation, ledger.Result = remoteLedgerStaged, "stage", nil
			case "relative":
				ledger.Stage.RootDir = "relative/artifact/extracted/package"
			case "parent_escape":
				ledger.Stage.RootDir = root + "/stages/../stages/" + filepath.Base(container) + "/artifact/extracted/" + filepath.Base(ledger.Stage.RootDir)
			case "prefix_collision":
				ledger.Stage.RootDir = root + "/stages-extra/" + filepath.Base(container) + "/artifact/extracted/package"
			case "noncanonical":
				ledger.Stage.RootDir += "/."
			case "unknown_layout":
				ledger.Stage.RootDir = filepath.Join(container, "unknown", "extracted", "package")
			case "unknown_container":
				newContainer := filepath.Join(root, "stages", "not-a-stage-hash")
				if os.Rename(container, newContainer) != nil {
					t.Fatal("rename independent fixture")
				}
				ledger.Stage.RootDir = filepath.Join(newContainer, "artifact", "extracted", filepath.Base(ledger.Stage.RootDir))
			case "container_symlink", "intermediate_symlink", "leaf_symlink":
				victim := ledger.Stage.RootDir
				if name == "container_symlink" {
					victim = container
				}
				if name == "intermediate_symlink" {
					victim = filepath.Join(container, "artifact")
				}
				moved := victim + "-fixture-original"
				if os.Rename(victim, moved) != nil || os.Symlink(moved, victim) != nil {
					t.Fatal("construct independent symlink negative")
				}
			case "unsafe_container_mode", "unsafe_intermediate_mode", "unsafe_leaf_mode":
				victim := ledger.Stage.RootDir
				if name == "unsafe_container_mode" {
					victim = container
				}
				if name == "unsafe_intermediate_mode" {
					victim = filepath.Join(container, "artifact")
				}
				if os.Chmod(victim, 0o777) != nil {
					t.Fatal("unsafe independent fixture mode")
				}
			case "unsafe_ledger_owner", "unsafe_container_owner", "unsafe_intermediate_owner", "unsafe_leaf_owner":
				if os.Geteuid() != 0 {
					t.Skip("requires the existing privileged root suite")
				}
				victim := ledger.Stage.RootDir
				if name == "unsafe_container_owner" {
					victim = container
				}
				if name == "unsafe_intermediate_owner" {
					victim = filepath.Join(container, "artifact")
				}
				if name == "unsafe_ledger_owner" {
					victim = path
				}
				if os.Chown(victim, 1, 1) != nil {
					t.Fatal("unsafe independent fixture owner")
				}
			case "missing_leaf":
				ledger.Stage.RootDir = filepath.Join(filepath.Dir(ledger.Stage.RootDir), "missing")
			case "ambiguous_nested", "ambiguous_direct":
				extra := ledger
				copyStage := *ledger.Stage
				extra.Stage = &copyStage
				extra.TargetID, extra.Intent.TargetID, extra.JobID = "ambiguous-target", "ambiguous-target", "ambiguous-job"
				if name == "ambiguous_direct" {
					extra.Stage.RootDir = container
				}
				ui185SaveLedger(t, root, extra)
			case "unknown_stage", "manual_smoke":
				stageName := remoteStableKey("unreferenced-stage")
				if name == "manual_smoke" {
					stageName = "autostream-manual-smoke-v1.9.16"
				}
				manualHostUpgradeLinuxMkdir(t, filepath.Join(root, "stages", stageName), 0o700)
			case "request_residue", "result_residue":
				dir := "requests"
				if name == "result_residue" {
					dir = "results"
				}
				manualHostUpgradeLinuxMkdir(t, filepath.Join(root, dir), 0o700)
				manualHostUpgradeLinuxWriteFile(t, filepath.Join(root, dir, "residue.json"), []byte("{}\n"), 0o600)
			}
			ui185SaveLedger(t, root, ledger)
			if name == "unsafe_ledger_owner" && os.Chown(path, 1, 1) != nil {
				t.Fatal("unsafe ledger owner")
			}
			switch name {
			case "broken_json":
				manualHostUpgradeLinuxWriteFile(t, path, []byte("{\n"), 0o600)
			case "unknown_field":
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.Replace(body, []byte("{\"schema_version\""), []byte("{\"unknown_authority\":true,\"schema_version\""), 1)
				manualHostUpgradeLinuxWriteFile(t, path, body, 0o600)
			case "bad_filename":
				if os.Rename(path, filepath.Join(filepath.Dir(path), "wrong.json")) != nil {
					t.Fatal("bad filename fixture")
				}
			case "unsafe_ledger_mode":
				if os.Chmod(path, 0o644) != nil {
					t.Fatal("unsafe ledger mode")
				}
			case "ledger_symlink":
				if os.Rename(path, path+".original") != nil || os.Symlink(path+".original", path) != nil {
					t.Fatal("ledger symlink fixture")
				}
			}
			roots := []string{root, fixture.runtime.paths.hostStateRoot, fixture.policyPath, fixture.runtime.paths.identityPath}
			before := ui185Snapshot(t, roots...)
			var proof SoftwareClaimRecoveryProof
			var err error
			if strings.HasSuffix(name, "_owner") {
				rt := fixture.runtime
				rt.allowTestPaths = false
				err = scanSoftwareClaimRecoveryRemoteRecords(job, root, rt)
			} else {
				proof, err = inspectSoftwareClaimRecoveryRoot(context.Background(), policy, request, runtime)
			}
			if (err == nil) != accepted || (accepted && (!proof.NoMutation || proof.Validate() != nil)) {
				t.Fatalf("stage reference acceptance=%t expected=%t", err == nil, accepted)
			}
			ui185RequireSnapshot(t, before, roots...)
			if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
				t.Fatal("inspect changed service state")
			}
		})
	}
}

// Compiled against the fixed UI185 base, with only this test file overlaid.
// The parent passes the exact generated input; this process never mutates it.
func TestUI185FixedBaseStageInspectionProcess(t *testing.T) {
	if os.Getenv("AUTOSTREAM_UI185_BASE_PROCESS") != "1" {
		t.Skip("fixed-base comparison process is not selected")
	}
	if os.Geteuid() != 0 || os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_FULL_CHAIN") != "1" {
		t.Fatal("isolated privileged comparison only")
	}
	root, job := os.Getenv("AUTOSTREAM_UI185_RECORD_ROOT"), os.Getenv("AUTOSTREAM_UI185_JOB")
	if root != LocalExecutorMutationStateDir || !identifierPattern.MatchString(job) {
		t.Fatal("invalid bounded baseline input")
	}
	before := ui185Snapshot(t, root)
	err := scanSoftwareClaimRecoveryRemoteRecords(job, root, defaultManualHostUpgradeRuntime())
	if err == nil || err.Error() != "software claim recovery has an orphan or unsafe root stage" {
		t.Fatal("fixed base did not reproduce the stage reference refusal")
	}
	ui185RequireSnapshot(t, before, root)
	proof, _ := json.Marshal(map[string]any{"base": "1569e55db8c76cab24739fc971765c8aac11c840", "same_generated_input": true, "refused": true, "refusal_class": "orphan_or_unsafe_root_stage", "bytes_metadata_preserved": true, "input_snapshot_sha256": ui185SnapshotDigest(before)})
	t.Logf("UI185_BASE=%s", proof)
}
