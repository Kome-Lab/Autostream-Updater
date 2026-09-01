package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ApplyPlan struct {
	JobID                  string `json:"job_id"`
	HostID                 string `json:"host_id,omitempty"`
	TargetID               string `json:"target_id"`
	ServiceType            string `json:"service_type"`
	DeploymentMode         string `json:"deployment_mode"`
	TargetVersion          string `json:"target_version"`
	CurrentVersion         string `json:"current_version,omitempty"`
	ConfigSHA256           string `json:"config_sha256,omitempty"`
	LeaseToken             string `json:"lease_token"`
	LeaseGeneration        uint64 `json:"lease_generation"`
	StageDir               string `json:"stage_dir,omitempty"`
	ArtifactDigest         string `json:"artifact_digest,omitempty"`
	ExpectedVersion        string `json:"expected_version,omitempty"`
	ExpectedImageDigest    string `json:"expected_image_digest,omitempty"`
	ExpectedPlatformDigest string `json:"expected_platform_digest,omitempty"`
}

type ApplyResult struct {
	Status         string `json:"status"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	RolledBack     bool   `json:"rolled_back,omitempty"`
	Message        string `json:"message,omitempty"`
}

type CommandRunner interface {
	Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error)
}

type OSCommandRunner struct {
	NewProcessGroup bool
}

func (r OSCommandRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	processDone := configureProcessGroup(cmd, r.NewProcessGroup)
	cmd.Dir = dir
	cmd.Env = sanitizedCommandEnv(env)
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	processDone()
	if err != nil {
		return output.String(), fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return output.String(), nil
}

func sanitizedCommandEnv(extra []string) []string {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	if runtime.GOOS == "windows" {
		env = nil
		for _, key := range []string{"SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"} {
			if value, ok := os.LookupEnv(key); ok {
				env = append(env, key+"="+value)
			}
		}
	}
	for _, value := range extra {
		if strings.ContainsRune(value, '\x00') || !strings.Contains(value, "=") {
			continue
		}
		env = append(env, value)
	}
	return env
}

func dockerCommandEnv() []string {
	return []string{"HOME=/", "DOCKER_CONFIG=" + localExecutorDockerConfigDir}
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	const max = 1 << 20
	if b.Len() < max {
		remaining := max - b.Len()
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

// ComputeComposeConfigDigest resolves and safety-checks the same canonical
// Compose model used by privileged apply, then returns its approval digest.
func applySystemd(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner) (ApplyResult, error) {
	return applySystemdWithGate(ctx, target, plan, runner, nil)
}

func applySystemdWithGate(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner, mutationGate func(context.Context) error) (ApplyResult, error) {
	systemd := target.Systemd
	if plan.StageDir == "" || !filepath.IsAbs(plan.StageDir) || len(plan.ArtifactDigest) != sha256.Size*2 {
		return ApplyResult{}, errors.New("systemd apply plan requires a staged artifact and SHA256")
	}
	stageResolved, err := filepath.EvalSymlinks(plan.StageDir)
	if err != nil {
		return ApplyResult{}, errors.New("staged artifact path is invalid")
	}
	if err := VerifyInnerChecksums(stageResolved); err != nil {
		return ApplyResult{}, fmt.Errorf("reverify staged artifact: %w", err)
	}
	for _, rel := range append([]string{systemd.BinaryPath}, systemd.RequiredPaths...) {
		if info, err := os.Stat(filepath.Join(stageResolved, filepath.FromSlash(rel))); err != nil || (rel == systemd.BinaryPath && !info.Mode().IsRegular()) {
			return ApplyResult{}, fmt.Errorf("staged artifact is missing required path %q", rel)
		}
	}
	releaseDir := filepath.Join(systemd.ReleaseRoot, plan.TargetVersion+"-"+strings.ToLower(plan.ArtifactDigest[:12]))
	if !pathWithin(systemd.ReleaseRoot, releaseDir) {
		return ApplyResult{}, errors.New("release directory escaped release_root")
	}
	if err := installReleaseTree(stageResolved, releaseDir, plan.ArtifactDigest, plan.TargetVersion); err != nil {
		return ApplyResult{}, err
	}
	if err := verifyManagedReleaseChecksums(releaseDir); err != nil {
		return ApplyResult{}, fmt.Errorf("installed release integrity check failed: %w", err)
	}
	for _, rel := range append([]string{systemd.BinaryPath}, systemd.RequiredPaths...) {
		if info, err := os.Stat(filepath.Join(releaseDir, filepath.FromSlash(rel))); err != nil || (rel == systemd.BinaryPath && !info.Mode().IsRegular()) {
			return ApplyResult{}, fmt.Errorf("installed release is missing required path %q", rel)
		}
	}
	binary := filepath.Join(releaseDir, filepath.FromSlash(systemd.BinaryPath))
	smokeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	output, smokeErr := runner.Run(smokeCtx, releaseDir, nil, systemd.RunuserPath, "-u", systemd.SmokeUser, "--", binary, "--version")
	cancel()
	if smokeErr != nil || !versionMatches(output, plan.TargetVersion) {
		return ApplyResult{}, errors.New("staged binary version smoke check failed")
	}
	if err := runFixedCommand(ctx, runner, target.BackupArgv); err != nil {
		return ApplyResult{}, fmt.Errorf("backup failed: %w", err)
	}
	previousTarget, previousDigest, previousVersion, err := currentRelease(systemd.CurrentLink, systemd.ReleaseRoot)
	if err != nil {
		return ApplyResult{}, err
	}
	if previousTarget == "" {
		return ApplyResult{}, errors.New("managed release bootstrap required before the first update")
	}
	if err := verifyManagedReleaseChecksums(previousTarget); err != nil {
		return ApplyResult{}, fmt.Errorf("previous managed release is not rollback-safe: %w", err)
	}
	for _, rel := range append([]string{systemd.BinaryPath}, systemd.RequiredPaths...) {
		if info, err := os.Stat(filepath.Join(previousTarget, filepath.FromSlash(rel))); err != nil || (rel == systemd.BinaryPath && !info.Mode().IsRegular()) {
			return ApplyResult{}, fmt.Errorf("previous managed release is missing required path %q", rel)
		}
	}
	if err := firstError(verifySystemdProcess(ctx, target, previousTarget, runner), verifyTarget(ctx, target, previousVersion)); err != nil {
		return ApplyResult{}, fmt.Errorf("previous managed release is not healthy enough for rollback: %w", err)
	}
	if mutationGate != nil {
		if err := mutationGate(ctx); err != nil {
			return ApplyResult{}, err
		}
	}
	checkpoint := updateCheckpoint{JobID: plan.JobID, TargetID: target.TargetID, DeploymentMode: ModeSystemd, Phase: "prepared", TargetVersion: plan.TargetVersion, TargetDigest: normalizeDigest(plan.ArtifactDigest), NewRelease: releaseDir, PreviousRelease: previousTarget, PreviousDigest: normalizeDigest(previousDigest), PreviousVersion: previousVersion}
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{}, fmt.Errorf("persist systemd update checkpoint: %w", err)
	}
	if _, err := runner.Run(ctx, "", nil, systemd.SystemctlPath, "stop", systemd.Unit); err != nil {
		return ApplyResult{}, err
	}
	checkpoint.Phase = "stopped"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		_, _ = runner.Run(context.Background(), "", nil, systemd.SystemctlPath, "start", systemd.Unit)
		return ApplyResult{}, fmt.Errorf("persist stopped checkpoint: %w", err)
	}
	if err := switchSymlink(systemd.CurrentLink, releaseDir, plan.JobID); err != nil {
		_, _ = runner.Run(ctx, "", nil, systemd.SystemctlPath, "start", systemd.Unit)
		return ApplyResult{}, err
	}
	checkpoint.Phase = "switched"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{}, fmt.Errorf("persist switched checkpoint: %w", err)
	}
	startOutput, startErr := runner.Run(ctx, "", nil, systemd.SystemctlPath, "start", systemd.Unit)
	checkpoint.Phase = "started"
	checkpointErr := saveCheckpoint(target, checkpoint)
	verifyErr := error(nil)
	if startErr == nil {
		verifyErr = firstError(checkpointErr, verifySystemdProcess(ctx, target, releaseDir, runner), verifyTarget(ctx, target, plan.TargetVersion))
	}
	if startErr == nil && verifyErr == nil {
		checkpoint.Phase = "succeeded"
		if err := saveCheckpoint(target, checkpoint); err != nil {
			return ApplyResult{}, fmt.Errorf("updated release is healthy but terminal checkpoint failed: %w", err)
		}
		return ApplyResult{Status: "succeeded", ArtifactDigest: normalizeDigest(plan.ArtifactDigest), PreviousDigest: normalizeDigest(previousDigest)}, nil
	}
	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer rollbackCancel()
	rollbackErr := rollbackSystemd(rollbackCtx, target, previousTarget, previousVersion, plan.JobID, runner)
	if rollbackErr != nil {
		return ApplyResult{Status: "failed", ArtifactDigest: normalizeDigest(plan.ArtifactDigest), PreviousDigest: normalizeDigest(previousDigest)}, fmt.Errorf("new release failed (%v %s); rollback failed: %w", firstError(startErr, verifyErr), strings.TrimSpace(startOutput), rollbackErr)
	}
	checkpoint.Phase = "rolled_back"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{Status: "failed", ArtifactDigest: normalizeDigest(plan.ArtifactDigest), PreviousDigest: normalizeDigest(previousDigest)}, fmt.Errorf("rollback succeeded but terminal checkpoint failed: %w", err)
	}
	return ApplyResult{Status: "rolled_back", ArtifactDigest: normalizeDigest(plan.ArtifactDigest), PreviousDigest: normalizeDigest(previousDigest), RolledBack: true, Message: firstError(startErr, verifyErr).Error()}, nil
}

func installReleaseTree(source, dest, digest, version string) error {
	if info, err := os.Lstat(dest); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("release destination already exists and is not a directory")
		}
		if err := verifyManagedReleaseChecksums(dest); err != nil {
			return errors.New("existing release destination failed integrity verification")
		}
		existing, _ := os.ReadFile(filepath.Join(dest, ".artifact-sha256"))
		existingVersion, _ := os.ReadFile(filepath.Join(dest, ".version"))
		if strings.TrimSpace(string(existing)) != strings.ToLower(digest) || strings.TrimSpace(string(existingVersion)) != version {
			return errors.New("release destination already exists with a different digest")
		}
		// A release produced by an older helper may have correct immutable
		// contents but UMask-restricted 0700/0600 modes. Re-normalizing a
		// checksum-verified, identity-matched tree is safe and makes retries
		// self-healing instead of requiring operator deletion.
		if err := normalizeInstalledReleaseTreeModes(dest); err != nil {
			return err
		}
		return firstError(syncDirectoryTreeBottomUp(dest), syncDirectory(filepath.Dir(dest)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tempDest := dest + ".partial-" + shortID(digest+version)
	if !pathWithin(parent, tempDest) || filepath.Clean(tempDest) == filepath.Clean(parent) {
		return errors.New("partial release directory escaped release root")
	}
	if _, err := os.Lstat(tempDest); err == nil {
		if err := removeStaleReleasePartial(parent, tempDest); err != nil {
			return errors.New("stale partial release directory is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(tempDest, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tempDest, 0o755); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tempDest)
		}
	}()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || rel == "." {
			return err
		}
		out := filepath.Join(tempDest, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("staged release contains a symlink")
		}
		if entry.IsDir() {
			if err := os.Mkdir(out, 0o755); err != nil {
				return err
			}
			return os.Chmod(out, 0o755)
		}
		if !entry.Type().IsRegular() {
			return errors.New("staged release contains a non-regular file")
		}
		return copyRegularFile(path, out, info.Mode().Perm())
	})
	if err != nil {
		return err
	}
	if err := writeSyncedFile(filepath.Join(tempDest, ".artifact-sha256"), []byte(strings.ToLower(digest)+"\n"), 0o444); err != nil {
		return err
	}
	if err := writeSyncedFile(filepath.Join(tempDest, ".version"), []byte(version+"\n"), 0o444); err != nil {
		return err
	}
	// Do not publish a final release directory until the copied tree itself is
	// checksum-complete. The staged source was already verified, but this fence
	// prevents a partial copy or local I/O fault from stranding the deterministic
	// final destination and wedging every retry.
	if err := verifyManagedReleaseChecksums(tempDest); err != nil {
		return errors.New("copied release failed integrity verification")
	}
	if err := syncDirectoryTreeBottomUp(tempDest); err != nil {
		return err
	}
	if err := os.Rename(tempDest, dest); err != nil {
		return err
	}
	committed = true
	return syncDirectory(parent)
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	chmodErr := f.Chmod(mode)
	syncErr := f.Sync()
	closeErr := f.Close()
	return firstError(writeErr, chmodErr, syncErr, closeErr)
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func copyRegularFile(source, dest string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	mode = normalizedReleaseFileMode(mode)
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	chmodErr := out.Chmod(mode)
	syncErr := out.Sync()
	closeErr := out.Close()
	return firstError(copyErr, chmodErr, syncErr, closeErr)
}

func normalizedReleaseFileMode(source os.FileMode) os.FileMode {
	if source.Perm()&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

func normalizeInstalledReleaseTreeModes(root string) error {
	root = filepath.Clean(root)
	digestMarker := filepath.Join(root, ".artifact-sha256")
	versionMarker := filepath.Join(root, ".version")
	directories := make([]string, 0, 8)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("installed release contains a symlink")
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("installed release contains a non-regular file")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := os.FileMode(0o444)
		cleanPath := filepath.Clean(path)
		if cleanPath != digestMarker && cleanPath != versionMarker {
			mode = normalizedReleaseFileMode(info.Mode())
		}
		return chmodAndSyncRegularFile(path, info, mode)
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := os.Chmod(directories[index], 0o755); err != nil {
			return err
		}
	}
	return nil
}

func chmodAndSyncRegularFile(path string, expected os.FileInfo, mode os.FileMode) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	opened, statErr := f.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		_ = f.Close()
		return errors.New("installed release file changed during mode repair")
	}
	chmodErr := f.Chmod(mode)
	syncErr := f.Sync()
	closeErr := f.Close()
	return firstError(chmodErr, syncErr, closeErr)
}

func removeStaleReleasePartial(parent, partial string) error {
	parent = filepath.Clean(parent)
	partial = filepath.Clean(partial)
	if partial == parent || !pathWithin(parent, partial) {
		return errors.New("stale partial path escaped release root")
	}
	rootInfo, err := os.Lstat(partial)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !isRootOwner(rootInfo) {
		return errors.New("stale partial root is unsafe")
	}
	if err := filepath.WalkDir(partial, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("stale partial contains a symlink")
		}
		info, err := entry.Info()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) || !isRootOwner(info) {
			return errors.New("stale partial contains an unsafe entry")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := os.RemoveAll(partial); err != nil {
		return err
	}
	if _, err := os.Lstat(partial); !errors.Is(err, os.ErrNotExist) {
		return errors.New("stale partial removal was incomplete")
	}
	return syncDirectory(parent)
}

func syncDirectoryTreeBottomUp(root string) error {
	root = filepath.Clean(root)
	directories := make([]string, 0, 8)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("release tree contains a symlink")
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("release tree contains a non-regular file")
		}
		return nil
	}); err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}

func currentRelease(link, releaseRoot string) (string, string, string, error) {
	target, err := os.Readlink(link)
	if errors.Is(err, os.ErrNotExist) {
		return "", "", "", nil
	}
	if err != nil {
		return "", "", "", errors.New("current_link must be a symlink managed by autostream-updater")
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(link), target)
	}
	target, err = filepath.EvalSymlinks(target)
	if err != nil || !pathWithin(releaseRoot, target) {
		return "", "", "", errors.New("current_link target is outside release_root")
	}
	digestBytes, digestErr := os.ReadFile(filepath.Join(target, ".artifact-sha256"))
	versionBytes, versionErr := os.ReadFile(filepath.Join(target, ".version"))
	digest := strings.ToLower(strings.TrimSpace(string(digestBytes)))
	version := strings.TrimSpace(string(versionBytes))
	if digestErr != nil || versionErr != nil || len(digest) != 64 || !versionPattern.MatchString(version) {
		return "", "", "", errors.New("current release markers are invalid")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", "", "", errors.New("current release digest marker is invalid")
	}
	return filepath.Clean(target), digest, version, nil
}

func switchSymlink(link, target, jobID string) error {
	tmp := link + ".next-" + shortID(jobID)
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirectory(filepath.Dir(link))
}

func rollbackSystemd(ctx context.Context, target Target, previous, previousVersion, jobID string, runner CommandRunner) error {
	s := target.Systemd
	if previous == "" || !versionPattern.MatchString(previousVersion) {
		return errors.New("no valid previous managed release is available")
	}
	if _, err := runner.Run(ctx, "", nil, s.SystemctlPath, "stop", s.Unit); err != nil {
		return fmt.Errorf("stop failed during rollback: %w", err)
	}
	if previous == "" {
		if err := os.Remove(s.CurrentLink); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if err := switchSymlink(s.CurrentLink, previous, jobID+"-rollback"); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "", nil, s.SystemctlPath, "start", s.Unit); err != nil {
		return err
	}
	return firstError(verifySystemdProcess(ctx, target, previous, runner), verifyTarget(ctx, target, previousVersion))
}

func verifySystemdProcess(ctx context.Context, target Target, releaseDir string, runner CommandRunner) error {
	out, err := runner.Run(ctx, "", nil, target.Systemd.SystemctlPath, "show", "--property=MainPID", "--value", target.Systemd.Unit)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || pid <= 0 {
		return errors.New("systemd service has no MainPID")
	}
	running, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return errors.New("could not resolve systemd MainPID executable")
	}
	expected, err := filepath.EvalSymlinks(filepath.Join(releaseDir, filepath.FromSlash(target.Systemd.BinaryPath)))
	if err != nil || filepath.Clean(running) != filepath.Clean(expected) {
		return errors.New("systemd MainPID is not executing the selected release binary")
	}
	return nil
}

// dockerMutationBaseline is a secret-free fingerprint of the complete
// rollback baseline observed on a Docker host. VersionEnvSHA256 binds the
// entire version env file without copying unrelated credentials into the
// remote ledger.
type dockerMutationBaseline struct {
	VersionEnvSHA256  string `json:"version_env_sha256"`
	VersionEnvMode    uint32 `json:"version_env_mode"`
	VersionEnvExisted bool   `json:"version_env_existed"`
	BundleVersion     string `json:"bundle_version"`
	ManifestDigest    string `json:"manifest_digest"`
	SourceVersion     string `json:"source_version"`
	ContainerID       string `json:"container_id"`
	ImageID           string `json:"image_id"`
	RepositoryDigest  string `json:"repository_digest"`
}

type dockerMutationObservation struct {
	Baseline   dockerMutationBaseline
	VersionEnv []byte
	EnvMode    os.FileMode
}

func observeDockerMutationBaseline(ctx context.Context, target Target, runner CommandRunner) (dockerMutationObservation, error) {
	d := target.Docker
	if d == nil {
		return dockerMutationObservation{}, errors.New("Docker target is unavailable")
	}
	envBytes, envMode, envExisted, err := readVersionEnv(d.VersionEnvFile)
	if err != nil {
		return dockerMutationObservation{}, err
	}
	bundleVersion, manifestDigest := strings.TrimSpace(d.CurrentVersion), ""
	if envExisted {
		bundleVersion, manifestDigest, err = parseVersionEnvPin(envBytes, d.ImageVariable)
		if err != nil {
			return dockerMutationObservation{}, err
		}
	}
	if !versionPattern.MatchString(bundleVersion) {
		return dockerMutationObservation{}, errors.New("current Docker bundle version is unavailable")
	}
	sourceVersion, err := readHealthyTargetVersion(ctx, target)
	if err != nil || !versionPattern.MatchString(strings.TrimSpace(sourceVersion)) {
		return dockerMutationObservation{}, errors.New("current Docker target is not healthy enough for rollback")
	}
	sourceVersion = strings.TrimSpace(sourceVersion)
	containerID, err := managedContainerID(ctx, runner, d)
	if err != nil || len(containerID) > 128 || strings.ContainsAny(containerID, " \t\r\n\x00") {
		return dockerMutationObservation{}, errors.New("managed compose service has no stable running container")
	}
	imageOut, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "inspect", "--format={{.Image}}", containerID)
	imageID := strings.ToLower(strings.TrimSpace(imageOut))
	if err != nil || !digestPattern.MatchString(imageID) {
		return dockerMutationObservation{}, errors.New("current container image ID is not a canonical SHA256 digest")
	}
	repoOut, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "image", "inspect", "--format={{json .RepoDigests}}", imageID)
	if err != nil {
		return dockerMutationObservation{}, errors.New("could not resolve the current image repository digest")
	}
	repoDigest, err := repositoryDigest(repoOut, d.ImageRepo)
	if err != nil {
		return dockerMutationObservation{}, err
	}
	if !envExisted {
		manifestDigest = repoDigest
	}
	hash := sha256.Sum256(envBytes)
	baseline := dockerMutationBaseline{
		VersionEnvSHA256: "sha256:" + hex.EncodeToString(hash[:]), VersionEnvMode: uint32(envMode.Perm()), VersionEnvExisted: envExisted,
		BundleVersion: bundleVersion, ManifestDigest: strings.ToLower(manifestDigest), SourceVersion: sourceVersion,
		ContainerID: containerID, ImageID: imageID, RepositoryDigest: strings.ToLower(repoDigest),
	}
	if err := baseline.validate(); err != nil {
		return dockerMutationObservation{}, err
	}
	return dockerMutationObservation{Baseline: baseline, VersionEnv: envBytes, EnvMode: envMode}, nil
}

func (b dockerMutationBaseline) validate() error {
	if !digestPattern.MatchString(b.VersionEnvSHA256) || b.VersionEnvMode > 0o777 || !versionPattern.MatchString(b.BundleVersion) || !digestPattern.MatchString(b.ManifestDigest) || !versionPattern.MatchString(b.SourceVersion) || b.ContainerID == "" || len(b.ContainerID) > 128 || strings.ContainsAny(b.ContainerID, " \t\r\n\x00") || !digestPattern.MatchString(b.ImageID) || !digestPattern.MatchString(b.RepositoryDigest) {
		return errors.New("Docker rollback baseline is invalid")
	}
	return nil
}

func (b dockerMutationBaseline) matches(actual dockerMutationBaseline) bool {
	return b == actual
}

func applyDocker(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner) (ApplyResult, error) {
	return applyDockerWithGate(ctx, target, plan, runner, nil, false)
}

func applyDockerWithGate(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner, mutationGate func(context.Context) error, trustedImageStaged bool) (ApplyResult, error) {
	return applyDockerWithGateAndBaseline(ctx, target, plan, runner, mutationGate, trustedImageStaged, nil, "")
}

func applyDockerWithGateAndBaseline(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner, mutationGate func(context.Context) error, trustedImageStaged bool, stagedBaseline *dockerMutationBaseline, expectedStagedImageID string) (ApplyResult, error) {
	return applyDockerWithGateAndBaselineWithOwnerCheck(ctx, target, plan, runner, mutationGate, trustedImageStaged, stagedBaseline, expectedStagedImageID, isRootOwner)
}

func applyDockerWithGateAndBaselineWithOwnerCheck(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner, mutationGate func(context.Context) error, trustedImageStaged bool, stagedBaseline *dockerMutationBaseline, expectedStagedImageID string, trustedOwner func(os.FileInfo) bool) (ApplyResult, error) {
	if trustedOwner == nil {
		return ApplyResult{}, errors.New("trusted Docker owner policy is missing")
	}
	if !versionPattern.MatchString(plan.ExpectedVersion) || !digestPattern.MatchString(plan.ExpectedImageDigest) || !digestPattern.MatchString(plan.ExpectedPlatformDigest) {
		return ApplyResult{}, errors.New("trusted Docker release metadata is missing")
	}
	d := target.Docker
	if plan.StageDir == "" || !filepath.IsAbs(plan.StageDir) {
		return ApplyResult{}, errors.New("trusted Docker working directory is missing")
	}
	if planned := strings.TrimSpace(plan.CurrentVersion); planned != "" {
		current, currentErr := managedRemoteCurrentVersion(target)
		if currentErr != nil {
			return ApplyResult{}, errors.New("could not verify the planned current version")
		}
		if err := requirePlannedCurrentVersion(planned, current); err != nil {
			return ApplyResult{}, err
		}
	}
	observation, err := observeDockerMutationBaseline(ctx, target, runner)
	if err != nil {
		return ApplyResult{}, err
	}
	baseline := observation.Baseline
	if stagedBaseline != nil {
		if err := stagedBaseline.validate(); err != nil || !stagedBaseline.matches(baseline) {
			return ApplyResult{}, errors.New("Docker target changed after staging")
		}
	}
	if err := requirePlannedCurrentVersion(plan.CurrentVersion, baseline.BundleVersion); err != nil {
		return ApplyResult{}, err
	}
	originalEnv, envMode, envExisted := observation.VersionEnv, observation.EnvMode, baseline.VersionEnvExisted
	previousVersion, previousID := baseline.SourceVersion, baseline.ImageID
	previousRepoDigest, previousBundle, previousManifest := baseline.RepositoryDigest, baseline.BundleVersion, baseline.ManifestDigest
	overridePath := filepath.Join(plan.StageDir, "compose-override.json")
	frozenPath := filepath.Join(plan.StageDir, "compose-frozen.json")
	digestRef := d.ImageRepo + "@" + plan.ExpectedPlatformDigest
	if err := writeDockerOverride(overridePath, d.Service, digestRef); err != nil {
		return ApplyResult{}, err
	}
	newEnv, err := updateVersionEnv(originalEnv, d.ImageVariable, plan.TargetVersion+"@"+plan.ExpectedImageDigest)
	if err != nil {
		return ApplyResult{}, err
	}
	base := composeArgs(d, overridePath)
	newID := ""
	if trustedImageStaged {
		if !digestPattern.MatchString(expectedStagedImageID) {
			return ApplyResult{}, errors.New("staged Docker image binding is missing")
		}
		newID, err = verifyTrustedStagedDockerInputsWithOwnerCheck(ctx, runner, d, frozenPath, digestRef, plan.ExpectedPlatformDigest, trustedOwner)
		if err != nil {
			return ApplyResult{}, err
		}
		if newID != normalizeDigest(expectedStagedImageID) {
			return ApplyResult{}, errors.New("staged Docker image ID changed after staging")
		}
		base = composeFrozenArgs(d, frozenPath)
		if mutationGate != nil {
			if err := mutationGate(ctx); err != nil {
				return ApplyResult{}, err
			}
			// The grant call is an external round trip. Re-read the entire rollback
			// baseline after it returns and before the first checkpoint/env write so
			// a concurrent host change cannot be adopted as an authorized baseline.
			baselineCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			afterGrant, baselineErr := observeDockerMutationBaseline(baselineCtx, target, runner)
			cancel()
			if baselineErr != nil || !baseline.matches(afterGrant.Baseline) {
				return ApplyResult{}, errors.New("Docker target changed while consuming the mutation grant")
			}
			stagedCtx, stagedCancel := context.WithTimeout(ctx, 10*time.Second)
			afterGrantID, stagedErr := verifyTrustedStagedDockerInputsWithOwnerCheck(stagedCtx, runner, d, frozenPath, digestRef, plan.ExpectedPlatformDigest, trustedOwner)
			stagedCancel()
			if stagedErr != nil || afterGrantID != newID || afterGrantID != normalizeDigest(expectedStagedImageID) {
				return ApplyResult{}, errors.New("staged Docker inputs changed while consuming the mutation grant")
			}
		}
		if err := preflightTrustedDockerComposePorts(ctx, runner, d, frozenPath, baseline.ContainerID); err != nil {
			return ApplyResult{}, err
		}
	} else if mutationGate != nil {
		return ApplyResult{}, errors.New("a mutation gate requires a pre-staged Docker image")
	}
	checkpoint := updateCheckpoint{JobID: plan.JobID, TargetID: target.TargetID, DeploymentMode: ModeDocker, Phase: "prepared", TargetVersion: plan.TargetVersion, TargetDigest: plan.ExpectedImageDigest, TargetPlatform: plan.ExpectedPlatformDigest, TargetSourceVersion: plan.ExpectedVersion, PreviousDigest: previousID, PreviousVersion: previousVersion, PreviousImageID: previousID, PreviousRepoDigest: previousRepoDigest, PreviousBundleVersion: previousBundle, PreviousManifestDigest: previousManifest, VersionEnvExisted: envExisted, VersionEnvMode: envMode, PreviousVersionEnv: originalEnv}
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{}, fmt.Errorf("persist Docker update checkpoint: %w", err)
	}
	envCommitted := false
	serviceMayHaveMutated := false
	defer func() {
		if !envCommitted {
			if restoreErr := restoreVersionEnv(d.VersionEnvFile, originalEnv, envMode, envExisted); restoreErr == nil && !serviceMayHaveMutated {
				_ = clearCheckpoint(target)
			}
		}
	}()
	if err := writeAtomicFile(d.VersionEnvFile, newEnv, envMode); err != nil {
		return ApplyResult{}, err
	}
	checkpoint.Phase = "env_written"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{}, fmt.Errorf("persist Docker env checkpoint: %w", err)
	}
	if !trustedImageStaged {
		if err := verifyComposeModel(ctx, runner, d, composeArgs(d, "")); err != nil {
			return ApplyResult{}, err
		}
		if err := verifyComposeConfig(ctx, runner, d, base, digestRef, frozenPath); err != nil {
			return ApplyResult{}, err
		}
		if err := preflightTrustedDockerComposePorts(ctx, runner, d, frozenPath, baseline.ContainerID); err != nil {
			return ApplyResult{}, err
		}
		base = composeFrozenArgs(d, frozenPath)
		if err := runFixedCommand(ctx, runner, target.BackupArgv); err != nil {
			return ApplyResult{}, fmt.Errorf("backup failed: %w", err)
		}
		if _, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, append(base, "pull", d.Service)...); err != nil {
			return ApplyResult{}, err
		}
		newIDOut, inspectErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "image", "inspect", "--format={{.Id}}", digestRef)
		if inspectErr != nil || !digestPattern.MatchString(strings.ToLower(strings.TrimSpace(newIDOut))) {
			return ApplyResult{}, errors.New("pulled Docker image ID is not a canonical SHA256 digest")
		}
		newID = strings.ToLower(strings.TrimSpace(newIDOut))
		repoDigests, inspectErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "image", "inspect", "--format={{json .RepoDigests}}", digestRef)
		if inspectErr != nil || !repositoryHasDigest(repoDigests, d.ImageRepo, plan.ExpectedPlatformDigest) {
			return ApplyResult{}, errors.New("pulled Docker image RepoDigest does not match trusted release manifest")
		}
	}
	checkpoint.Phase = "starting"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{}, fmt.Errorf("persist Docker starting checkpoint: %w", err)
	}
	serviceMayHaveMutated = true
	_, upErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, append(base, "up", "-d", "--no-deps", "--no-build", "--pull", "never", d.Service)...)
	verifyErr := error(nil)
	if upErr == nil {
		checkpoint.Phase = "started"
		verifyErr = saveCheckpoint(target, checkpoint)
		newCID, cidErr := managedContainerID(ctx, runner, d)
		if verifyErr != nil {
			// A durable terminal state is required before reporting success.
		} else if cidErr != nil {
			verifyErr = errors.New("updated compose service has no running container")
		} else {
			containerImage, inspectErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "inspect", "--format={{.Image}}", newCID)
			if inspectErr != nil || strings.TrimSpace(containerImage) != newID {
				verifyErr = errors.New("updated container is not running the trusted image ID")
			} else {
				verifyErr = verifyTarget(ctx, target, plan.ExpectedVersion)
			}
		}
	}
	if upErr == nil && verifyErr == nil {
		checkpoint.Phase = "succeeded"
		if err := saveCheckpoint(target, checkpoint); err != nil {
			return ApplyResult{}, fmt.Errorf("updated Docker target is healthy but terminal checkpoint failed: %w", err)
		}
		envCommitted = true
		return ApplyResult{Status: "succeeded", ArtifactDigest: normalizeDigest(plan.ExpectedImageDigest), PreviousDigest: normalizeDigest(previousID)}, nil
	}
	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer rollbackCancel()
	rollbackBytes := originalEnv
	if !envExisted {
		rollbackBytes, _ = updateVersionEnv(nil, d.ImageVariable, previousBundle+"@"+previousManifest)
	}
	restoreErr := writeAtomicFile(d.VersionEnvFile, rollbackBytes, envMode)
	overrideErr := writeDockerOverride(overridePath, d.Service, previousID)
	configErr := error(nil)
	if restoreErr == nil && overrideErr == nil {
		rollbackSource := composeArgs(d, overridePath)
		frozenRollback := filepath.Join(plan.StageDir, "compose-frozen-rollback.json")
		configErr = verifyComposeConfig(rollbackCtx, runner, d, rollbackSource, previousID, frozenRollback)
		if configErr == nil {
			base = composeFrozenArgs(d, frozenRollback)
		}
	}
	rollbackErr := firstError(restoreErr, overrideErr, configErr)
	if rollbackErr == nil {
		_, rollbackErr = runner.Run(rollbackCtx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, append(base, "up", "-d", "--no-deps", "--no-build", "--pull", "never", d.Service)...)
	}
	if rollbackErr == nil {
		rolledCID, cidErr := managedContainerID(rollbackCtx, runner, d)
		if cidErr != nil {
			rollbackErr = cidErr
		} else if imageOut, inspectErr := runner.Run(rollbackCtx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "inspect", "--format={{.Image}}", rolledCID); inspectErr != nil || strings.ToLower(strings.TrimSpace(imageOut)) != previousID {
			rollbackErr = errors.New("rollback container is not running the preserved image ID")
		} else {
			rollbackErr = verifyTarget(rollbackCtx, target, previousVersion)
		}
	}
	if rollbackErr != nil {
		return ApplyResult{Status: "failed", ArtifactDigest: normalizeDigest(plan.ExpectedImageDigest), PreviousDigest: normalizeDigest(previousID)}, fmt.Errorf("new image failed: %v; rollback failed: %w", firstError(upErr, verifyErr), rollbackErr)
	}
	checkpoint.Phase = "rolled_back"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{Status: "failed", ArtifactDigest: normalizeDigest(plan.ExpectedImageDigest), PreviousDigest: normalizeDigest(previousID)}, fmt.Errorf("rollback succeeded but terminal checkpoint failed: %w", err)
	}
	serviceMayHaveMutated = true // terminal checkpoint now owns reconciliation cleanup
	return ApplyResult{Status: "rolled_back", ArtifactDigest: normalizeDigest(plan.ExpectedImageDigest), PreviousDigest: normalizeDigest(previousID), RolledBack: true, Message: firstError(upErr, verifyErr).Error()}, nil
}

func verifyTrustedStagedDockerInputsWithOwnerCheck(ctx context.Context, runner CommandRunner, d *DockerTarget, frozenPath, digestRef, expectedPlatformDigest string, trustedOwner func(os.FileInfo) bool) (string, error) {
	if err := validateTrustedFrozenComposeWithOwnerCheck(frozenPath, d, digestRef, trustedOwner); err != nil {
		return "", err
	}
	newIDOut, inspectErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "image", "inspect", "--format={{.Id}}", digestRef)
	if inspectErr != nil || !digestPattern.MatchString(strings.ToLower(strings.TrimSpace(newIDOut))) {
		return "", errors.New("staged Docker image ID is not a canonical SHA256 digest")
	}
	newID := strings.ToLower(strings.TrimSpace(newIDOut))
	repoDigests, inspectErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "image", "inspect", "--format={{json .RepoDigests}}", digestRef)
	if inspectErr != nil || !repositoryHasDigest(repoDigests, d.ImageRepo, expectedPlatformDigest) {
		return "", errors.New("staged Docker image RepoDigest does not match trusted release manifest")
	}
	return newID, nil
}

func composeArgs(d *DockerTarget, overridePath string) []string {
	args := []string{"compose"}
	if d.BaseEnvFile != "" {
		args = append(args, "--env-file", d.BaseEnvFile)
	}
	args = append(args, "--env-file", d.VersionEnvFile)
	if d.PortEnvFile != "" {
		args = append(args, "--env-file", d.PortEnvFile)
	}
	args = append(args, "--project-directory", d.ProjectDir, "-p", d.ComposeProject)
	for _, file := range d.ComposeFiles {
		args = append(args, "-f", file)
	}
	if overridePath != "" {
		args = append(args, "-f", overridePath)
	}
	return args
}

func composeFrozenArgs(d *DockerTarget, frozenPath string) []string {
	args := []string{"compose"}
	if d.BaseEnvFile != "" {
		args = append(args, "--env-file", d.BaseEnvFile)
	}
	args = append(args, "--env-file", d.VersionEnvFile)
	if d.PortEnvFile != "" {
		args = append(args, "--env-file", d.PortEnvFile)
	}
	return append(args, "--project-directory", d.ProjectDir, "-p", d.ComposeProject, "-f", frozenPath)
}

func writeDockerOverride(path, service, image string) error {
	if !identifierPattern.MatchString(service) || !(digestPattern.MatchString(image) || strings.Contains(image, "@sha256:")) {
		return errors.New("Docker override identity is invalid")
	}
	payload, err := json.Marshal(map[string]any{"services": map[string]any{service: map[string]string{"image": image}}})
	if err != nil {
		return err
	}
	return writeAtomicFile(path, append(payload, '\n'), 0o600)
}

func verifyComposeConfig(ctx context.Context, runner CommandRunner, d *DockerTarget, base []string, expectedImage, frozenPath string) error {
	out, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, append(base, "config", "--format", "json", "--no-env-resolution")...)
	if err != nil {
		return fmt.Errorf("compose configuration validation failed: %w", err)
	}
	var cfg struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if json.Unmarshal([]byte(out), &cfg) != nil || cfg.Services[d.Service].Image != expectedImage {
		return errors.New("compose configuration did not resolve the managed service to the trusted image digest")
	}
	if err := validateComposeModelSecurity([]byte(out), d); err != nil {
		return err
	}
	if digest, err := composeModelHash([]byte(out), d.Service); err != nil || digest != d.ComposeConfigSHA256 {
		return errors.New("resolved compose project differs from the root-approved configuration digest")
	}
	if err := writeAtomicFile(frozenPath, []byte(out), 0o600); err != nil {
		return fmt.Errorf("freeze validated compose model: %w", err)
	}
	return nil
}

func validateTrustedFrozenCompose(path string, d *DockerTarget, expectedImage string) error {
	return validateTrustedFrozenComposeWithOwnerCheck(path, d, expectedImage, isRootOwner)
}

func validateTrustedFrozenComposeWithOwnerCheck(path string, d *DockerTarget, expectedImage string, trustedOwner func(os.FileInfo) bool) error {
	if trustedOwner == nil {
		return errors.New("trusted frozen compose model is unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 16<<20 || !trustedOwner(info) {
		return errors.New("trusted frozen compose model is unavailable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read trusted frozen compose model")
	}
	var cfg struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if json.Unmarshal(raw, &cfg) != nil || cfg.Services[d.Service].Image != expectedImage {
		return errors.New("trusted frozen compose image binding is invalid")
	}
	if err := validateComposeModelSecurity(raw, d); err != nil {
		return err
	}
	digest, err := composeModelHash(raw, d.Service)
	if err != nil || digest != d.ComposeConfigSHA256 {
		return errors.New("trusted frozen compose model differs from root policy")
	}
	return nil
}

func verifyComposeModel(ctx context.Context, runner CommandRunner, d *DockerTarget, args []string) error {
	out, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, append(args, "config", "--format", "json", "--no-env-resolution")...)
	if err != nil {
		return fmt.Errorf("base compose configuration validation failed: %w", err)
	}
	digest, err := composeModelHash([]byte(out), d.Service)
	if err != nil || digest != d.ComposeConfigSHA256 {
		return errors.New("base compose project differs from the root-approved configuration digest")
	}
	if err := validateComposeModelSecurity([]byte(out), d); err != nil {
		return err
	}
	return nil
}

func composeModelHash(raw []byte, service string) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model map[string]any
	if err := decoder.Decode(&model); err != nil {
		return "", err
	}
	services, ok := model["services"].(map[string]any)
	if !ok {
		return "", errors.New("compose model has no services")
	}
	if _, ok := services[service].(map[string]any); !ok {
		return "", errors.New("compose model has no managed service")
	}
	canonicalRepos := map[string]bool{
		"ghcr.io/kome-lab/autostream-docker/control-panel":    true,
		"ghcr.io/kome-lab/autostream-docker/worker":           true,
		"ghcr.io/kome-lab/autostream-docker/encoder-recorder": true,
		"ghcr.io/kome-lab/autostream-docker/discord-bot":      true,
		"ghcr.io/kome-lab/autostream-docker/observability":    true,
	}
	for name, rawService := range services {
		serviceModel, ok := rawService.(map[string]any)
		if !ok {
			return "", errors.New("compose service model is invalid")
		}
		image, _ := serviceModel["image"].(string)
		if name == service {
			if image == "" {
				return "", errors.New("managed compose service has no image")
			}
			serviceModel["image"] = "__AUTOSTREAM_MANAGED_IMAGE__"
		} else if repo := strings.ToLower(dockerImageBase(image)); strings.HasPrefix(repo, "ghcr.io/kome-lab/autostream-docker/") {
			if !canonicalRepos[repo] {
				return "", errors.New("compose model contains a noncanonical AutoStream image repository")
			}
			serviceModel["image"] = repo + ":__AUTOSTREAM_BUNDLE__"
		}
	}
	canonical, err := json.Marshal(model)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func validateComposeModelSecurity(raw []byte, d *DockerTarget) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model map[string]any
	if err := decoder.Decode(&model); err != nil {
		return errors.New("compose model is invalid JSON")
	}
	canonical, _ := json.Marshal(model)
	if strings.Contains(strings.ToLower(string(canonical)), "docker.sock") {
		return errors.New("compose model may not reference the Docker socket")
	}
	services, ok := model["services"].(map[string]any)
	if !ok || len(services) > 64 {
		return errors.New("compose model service set is invalid")
	}
	managed, ok := services[d.Service].(map[string]any)
	if !ok {
		return errors.New("compose model has no managed service")
	}
	if _, err := validateDockerComposePortMappings(raw, d); err != nil {
		return err
	}
	managedImage, _ := managed["image"].(string)
	if !strings.EqualFold(dockerImageBase(managedImage), d.ImageRepo) && !digestPattern.MatchString(strings.ToLower(managedImage)) {
		return errors.New("managed compose service image repository differs from fixed image_repo")
	}
	if value, _ := managed["privileged"].(bool); value {
		return errors.New("managed compose service may not be privileged")
	}
	for _, field := range []string{"cap_add", "devices"} {
		if values, ok := managed[field].([]any); ok && len(values) > 0 {
			return fmt.Errorf("managed compose service may not set %s", field)
		}
	}
	for _, field := range []string{"pid", "ipc", "network_mode"} {
		if value, _ := managed[field].(string); strings.EqualFold(value, "host") {
			return fmt.Errorf("managed compose service may not use host %s", field)
		}
	}
	if options, ok := managed["security_opt"].([]any); ok {
		for _, option := range options {
			if strings.Contains(strings.ToLower(fmt.Sprint(option)), "unconfined") {
				return errors.New("managed compose service may not disable confinement")
			}
		}
	}
	pathCount := 0
	if path, ok := managed["env_file"].(string); ok {
		if err := validateComposeHostReference(path, false, &pathCount); err != nil {
			return fmt.Errorf("compose env_file: %w", err)
		}
	} else if envFiles, ok := managed["env_file"].([]any); ok {
		for _, item := range envFiles {
			path := ""
			switch value := item.(type) {
			case string:
				path = value
			case map[string]any:
				path, _ = value["path"].(string)
			}
			if err := validateComposeHostReference(path, false, &pathCount); err != nil {
				return fmt.Errorf("compose env_file: %w", err)
			}
		}
	}
	if volumes, ok := managed["volumes"].([]any); ok {
		for _, item := range volumes {
			volume, ok := item.(map[string]any)
			if !ok || volume["type"] != "bind" {
				continue
			}
			source, _ := volume["source"].(string)
			readOnly, _ := volume["read_only"].(bool)
			if !readOnly || filepath.Clean(source) == filepath.Clean(string(filepath.Separator)) {
				return errors.New("managed compose bind mounts must be read-only and may not mount the host root")
			}
			if err := validateComposeHostReference(source, true, &pathCount); err != nil {
				return fmt.Errorf("compose bind mount: %w", err)
			}
		}
	}
	for _, kind := range []string{"configs", "secrets"} {
		refs, _ := managed[kind].([]any)
		definitions, _ := model[kind].(map[string]any)
		for _, item := range refs {
			ref, _ := item.(map[string]any)
			source, _ := ref["source"].(string)
			definition, _ := definitions[source].(map[string]any)
			path, _ := definition["file"].(string)
			if err := validateComposeHostReference(path, false, &pathCount); err != nil {
				return fmt.Errorf("compose %s reference: %w", kind, err)
			}
		}
	}
	return nil
}

func validateComposeHostReference(path string, allowDirectory bool, count *int) error {
	*count++
	if *count > 64 || !filepath.IsAbs(path) {
		return errors.New("host reference is missing, relative, or exceeds the bounded path count")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("host reference must exist and may not be a symlink")
	}
	if info.IsDir() {
		if !allowDirectory {
			return errors.New("host reference must be a regular file")
		}
	} else if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return errors.New("host reference must be a bounded regular file")
	}
	if err := validateSecureRootPath(path, info.IsDir()); err != nil {
		return err
	}
	if info.IsDir() {
		return validateComposeHostTree(path)
	}
	return nil
}

func validateComposeHostTree(root string) error {
	entries := 0
	var total int64
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 256 || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("bind source tree is too large or contains a symlink")
		}
		info, err := entry.Info()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) || !isRootOwner(info) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("bind source tree must contain only root-owned non-writable regular files and directories")
		}
		if info.Mode().IsRegular() {
			total += info.Size()
			if total > 64<<20 {
				return errors.New("bind source tree exceeds the size limit")
			}
		}
		return nil
	})
}

func managedContainerID(ctx context.Context, runner CommandRunner, d *DockerTarget) (string, error) {
	out, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "ps", "-q", "--filter", "label=com.docker.compose.project="+d.ComposeProject, "--filter", "label=com.docker.compose.service="+d.Service)
	lines := strings.Fields(out)
	if err != nil || len(lines) != 1 {
		return "", errors.New("expected exactly one managed Docker container")
	}
	return lines[0], nil
}

func readVersionEnv(path string) ([]byte, os.FileMode, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0o600, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, 0, false, errors.New("version_env_file must be a small regular file")
	}
	data, err := os.ReadFile(path)
	return data, info.Mode().Perm(), true, err
}

func updateVersionEnv(original []byte, name, value string) ([]byte, error) {
	parts := strings.Split(value, "@")
	if name != "AUTOSTREAM_DOCKER_VERSION" || len(parts) != 2 || !versionPattern.MatchString(parts[0]) || !digestPattern.MatchString(parts[1]) {
		return nil, errors.New("version env update is invalid")
	}
	lines := strings.Split(strings.ReplaceAll(string(original), "\r\n", "\n"), "\n")
	found := 0
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), name+"=") {
			found++
			lines[i] = name + "=" + value
		}
	}
	if found > 1 {
		return nil, errors.New("version_env_file contains duplicate version assignments")
	}
	if found == 0 {
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		lines = append(lines, name+"="+value)
	}
	return []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"), nil
}

func parseVersionEnvPin(data []byte, name string) (string, string, error) {
	found := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, name+"=") {
			if found != "" {
				return "", "", errors.New("version_env_file contains duplicate version assignments")
			}
			found = strings.TrimPrefix(line, name+"=")
		}
	}
	parts := strings.Split(found, "@")
	if len(parts) != 2 || !versionPattern.MatchString(parts[0]) || !digestPattern.MatchString(parts[1]) {
		return "", "", errors.New("version_env_file must contain a canonical bundle@sha256 pin")
	}
	return parts[0], parts[1], nil
}

func repositoryDigest(rawJSON, imageRepo string) (string, error) {
	var values []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(rawJSON)), &values); err != nil {
		return "", errors.New("image RepoDigests output is invalid")
	}
	for _, value := range values {
		parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "@")
		if len(parts) == 2 && strings.EqualFold(parts[0], imageRepo) && digestPattern.MatchString(parts[1]) {
			return parts[1], nil
		}
	}
	return "", errors.New("current image does not have a digest for the fixed image repository")
}

func repositoryHasDigest(rawJSON, imageRepo, expectedDigest string) bool {
	if !digestPattern.MatchString(strings.ToLower(strings.TrimSpace(expectedDigest))) {
		return false
	}
	var values []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(rawJSON)), &values); err != nil {
		return false
	}
	wantRepo := strings.ToLower(strings.TrimSpace(imageRepo))
	wantDigest := strings.ToLower(strings.TrimSpace(expectedDigest))
	for _, value := range values {
		parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "@")
		if len(parts) == 2 && parts[0] == wantRepo && parts[1] == wantDigest {
			return true
		}
	}
	return false
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".autostream-updater-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstError(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func restoreVersionEnv(path string, original []byte, mode os.FileMode, existed bool) error {
	if existed {
		return writeAtomicFile(path, original, mode)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func readHealthyTargetVersion(ctx context.Context, target Target) (string, error) {
	return readHealthyTargetVersionWithClient(ctx, target, nil)
}

func readHealthyTargetVersionWithClient(ctx context.Context, target Target, baseClient *http.Client) (string, error) {
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := http.Client{}
	if baseClient != nil {
		client = *baseClient
	}
	if client.Timeout <= 0 || client.Timeout > 3*time.Second {
		client.Timeout = 3 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err := checkHealth(checkCtx, &client, target.HealthURL); err != nil {
		return "", err
	}
	return fetchVersion(checkCtx, &client, target.VersionURL)
}

func reconcileSystemd(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner) (ApplyResult, error) {
	return reconcileSystemdWithGate(ctx, target, plan, runner, nil)
}

func reconcileSystemdWithGate(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner, mutationGate func(context.Context) error) (ApplyResult, error) {
	checkpoint, err := loadCheckpoint(target)
	if err != nil {
		return ApplyResult{Status: "failed"}, err
	}
	if checkpoint != nil && (checkpoint.JobID != plan.JobID || checkpoint.TargetVersion != plan.TargetVersion || checkpoint.NewRelease == "" || checkpoint.PreviousRelease == "" || requirePlannedCurrentVersion(plan.CurrentVersion, checkpoint.PreviousVersion) != nil) {
		return ApplyResult{Status: "failed"}, errors.New("systemd checkpoint does not match the recovered job")
	}
	current, digest, version, err := currentRelease(target.Systemd.CurrentLink, target.Systemd.ReleaseRoot)
	if err == nil && current != "" {
		actualErr := firstError(verifyManagedReleaseChecksums(current), verifySystemdProcess(ctx, target, current, runner), verifyTarget(ctx, target, version))
		if actualErr == nil && versionsEqual(version, plan.TargetVersion) && systemdRequestedReleaseDigestMatches(checkpoint, digest, plan.ArtifactDigest) {
			if checkpoint != nil {
				if current != filepath.Clean(checkpoint.NewRelease) || normalizeDigest(digest) != checkpoint.TargetDigest {
					return ApplyResult{Status: "failed"}, errors.New("running target release does not match the durable checkpoint")
				}
				if mutationGate != nil {
					if err := mutationGate(ctx); err != nil {
						return ApplyResult{Status: "failed"}, err
					}
				}
				if err := clearCheckpoint(target); err != nil {
					return ApplyResult{Status: "failed"}, err
				}
			}
			return ApplyResult{Status: "succeeded", ArtifactDigest: normalizeDigest(digest), Message: "interrupted update is running the requested release"}, nil
		}
		if planned := strings.TrimSpace(plan.CurrentVersion); actualErr == nil && checkpoint == nil && versionPattern.MatchString(planned) && version == planned {
			return ApplyResult{Status: "rolled_back", PreviousDigest: normalizeDigest(digest), RolledBack: true, Message: "apply had not changed the verified previous managed release"}, nil
		}
		if actualErr == nil && checkpoint != nil && current == filepath.Clean(checkpoint.PreviousRelease) && normalizeDigest(digest) == checkpoint.PreviousDigest && versionsEqual(version, checkpoint.PreviousVersion) {
			if mutationGate != nil {
				if err := mutationGate(ctx); err != nil {
					return ApplyResult{Status: "failed"}, err
				}
			}
			if err := clearCheckpoint(target); err != nil {
				return ApplyResult{Status: "failed"}, err
			}
			return ApplyResult{Status: "rolled_back", PreviousDigest: normalizeDigest(digest), RolledBack: true, Message: "previous managed release is healthy"}, nil
		}
	}
	if checkpoint == nil || !pathWithin(target.Systemd.ReleaseRoot, checkpoint.PreviousRelease) || checkpoint.PreviousDigest == "" || !versionPattern.MatchString(checkpoint.PreviousVersion) {
		return ApplyResult{Status: "failed", ArtifactDigest: normalizeDigest(digest)}, errors.New("interrupted systemd update has no trustworthy rollback checkpoint")
	}
	if err := verifyManagedReleaseChecksums(checkpoint.PreviousRelease); err != nil {
		return ApplyResult{Status: "failed"}, fmt.Errorf("checkpoint rollback release failed integrity validation: %w", err)
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if mutationGate != nil {
		if err := mutationGate(ctx); err != nil {
			return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousDigest}, err
		}
	}
	if err := rollbackSystemd(rollbackCtx, target, checkpoint.PreviousRelease, checkpoint.PreviousVersion, plan.JobID, runner); err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousDigest}, err
	}
	if err := clearCheckpoint(target); err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousDigest}, err
	}
	return ApplyResult{Status: "rolled_back", ArtifactDigest: checkpoint.TargetDigest, PreviousDigest: checkpoint.PreviousDigest, RolledBack: true, Message: "interrupted systemd cutover was rolled back from its durable checkpoint"}, nil
}

func systemdRequestedReleaseDigestMatches(checkpoint *updateCheckpoint, actualDigest, plannedDigest string) bool {
	if checkpoint != nil {
		return true
	}
	return normalizeDigest(actualDigest) == normalizeDigest(plannedDigest)
}

func reconcileDocker(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner) (ApplyResult, error) {
	return reconcileDockerWithGate(ctx, target, plan, runner, nil)
}

func reconcileDockerWithGate(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner, mutationGate func(context.Context) error) (ApplyResult, error) {
	d := target.Docker
	checkpoint, err := loadCheckpoint(target)
	if err != nil {
		return ApplyResult{Status: "failed"}, err
	}
	if checkpoint != nil && (checkpoint.JobID != plan.JobID || checkpoint.TargetVersion != plan.TargetVersion || checkpoint.TargetDigest != plan.ExpectedImageDigest || checkpoint.TargetPlatform != plan.ExpectedPlatformDigest || checkpoint.TargetSourceVersion != plan.ExpectedVersion || !versionPattern.MatchString(checkpoint.TargetSourceVersion) || !digestPattern.MatchString(checkpoint.PreviousImageID) || !versionPattern.MatchString(checkpoint.PreviousBundleVersion) || !digestPattern.MatchString(checkpoint.PreviousManifestDigest) || requirePlannedCurrentVersion(plan.CurrentVersion, checkpoint.PreviousBundleVersion) != nil) {
		return ApplyResult{Status: "failed"}, errors.New("Docker checkpoint does not match the recovered job")
	}
	cid, err := managedContainerID(ctx, runner, d)
	imageID := ""
	if err == nil {
		imageOut, inspectErr := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "inspect", "--format={{.Image}}", cid)
		if inspectErr == nil && digestPattern.MatchString(strings.ToLower(strings.TrimSpace(imageOut))) {
			imageID = strings.ToLower(strings.TrimSpace(imageOut))
		}
	}
	repoDigests := ""
	digestErr := error(nil)
	if imageID != "" {
		repoDigests, digestErr = runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "image", "inspect", "--format={{json .RepoDigests}}", imageID)
	}
	runningRepoTrusted := repositoryHasDigest(repoDigests, d.ImageRepo, plan.ExpectedPlatformDigest)
	if imageID != "" && digestErr == nil && runningRepoTrusted {
		if err := verifyTarget(ctx, target, plan.ExpectedVersion); err == nil {
			envBytes, envMode := checkpointEnv(checkpoint), checkpointMode(checkpoint)
			if checkpoint == nil {
				var readErr error
				envBytes, envMode, _, readErr = readVersionEnv(d.VersionEnvFile)
				if readErr != nil {
					return ApplyResult{Status: "failed"}, readErr
				}
			}
			pinned, pinErr := updateVersionEnv(envBytes, d.ImageVariable, plan.TargetVersion+"@"+plan.ExpectedImageDigest)
			if pinErr != nil {
				return ApplyResult{Status: "failed"}, errors.New("requested image is running but its durable version pin could not be restored")
			}
			if mutationGate != nil {
				if err := mutationGate(ctx); err != nil {
					return ApplyResult{Status: "failed"}, err
				}
			}
			if writeAtomicFile(d.VersionEnvFile, pinned, envMode) != nil {
				return ApplyResult{Status: "failed"}, errors.New("requested image is running but its durable version pin could not be restored")
			}
			if checkpoint != nil {
				if err := clearCheckpoint(target); err != nil {
					return ApplyResult{Status: "failed"}, err
				}
			}
			return ApplyResult{Status: "succeeded", ArtifactDigest: normalizeDigest(plan.ExpectedImageDigest), PreviousDigest: normalizeDigest(imageID), Message: "interrupted update is running the requested image"}, nil
		}
	}
	if checkpoint == nil {
		envBytes, _, existed, envErr := readVersionEnv(d.VersionEnvFile)
		bundle, _, pinErr := parseVersionEnvPin(envBytes, d.ImageVariable)
		_, healthErr := readHealthyTargetVersion(ctx, target)
		_, repoErr := repositoryDigest(repoDigests, d.ImageRepo)
		if planned := strings.TrimSpace(plan.CurrentVersion); imageID != "" && digestErr == nil && repoErr == nil && existed && envErr == nil && pinErr == nil && versionPattern.MatchString(planned) && bundle == planned && healthErr == nil {
			return ApplyResult{Status: "rolled_back", PreviousDigest: normalizeDigest(imageID), RolledBack: true, Message: "apply had not changed the verified previous Docker target"}, nil
		}
		return ApplyResult{Status: "failed", PreviousDigest: normalizeDigest(imageID)}, errors.New("interrupted Docker update has no trustworthy rollback checkpoint")
	}
	version, healthErr := readHealthyTargetVersion(ctx, target)
	if healthErr == nil && imageID == checkpoint.PreviousImageID && versionsEqual(version, checkpoint.PreviousVersion) {
		if mutationGate != nil {
			if err := mutationGate(ctx); err != nil {
				return ApplyResult{Status: "failed", PreviousDigest: normalizeDigest(imageID)}, err
			}
		}
		if err := restoreVersionEnv(d.VersionEnvFile, checkpoint.PreviousVersionEnv, checkpoint.VersionEnvMode, checkpoint.VersionEnvExisted); err != nil {
			return ApplyResult{Status: "failed", PreviousDigest: normalizeDigest(imageID)}, err
		}
		if err := clearCheckpoint(target); err != nil {
			return ApplyResult{Status: "failed", PreviousDigest: normalizeDigest(imageID)}, err
		}
		return ApplyResult{Status: "rolled_back", PreviousDigest: normalizeDigest(imageID), RolledBack: true, Message: "previous Docker image is healthy"}, nil
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rollbackBytes := checkpoint.PreviousVersionEnv
	if !checkpoint.VersionEnvExisted {
		rollbackBytes, _ = updateVersionEnv(nil, d.ImageVariable, checkpoint.PreviousBundleVersion+"@"+checkpoint.PreviousManifestDigest)
	}
	if mutationGate != nil {
		if err := mutationGate(ctx); err != nil {
			return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
		}
	}
	overridePath := filepath.Join(plan.StageDir, "compose-reconcile-rollback.json")
	if err := firstError(writeAtomicFile(d.VersionEnvFile, rollbackBytes, checkpoint.VersionEnvMode), writeDockerOverride(overridePath, d.Service, checkpoint.PreviousImageID)); err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
	}
	base := composeArgs(d, overridePath)
	if err := verifyComposeModel(rollbackCtx, runner, d, composeArgs(d, "")); err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
	}
	frozenPath := filepath.Join(plan.StageDir, "compose-reconcile-frozen.json")
	if err := verifyComposeConfig(rollbackCtx, runner, d, base, checkpoint.PreviousImageID, frozenPath); err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
	}
	base = composeFrozenArgs(d, frozenPath)
	if _, err := runner.Run(rollbackCtx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, append(base, "up", "-d", "--no-deps", "--no-build", "--pull", "never", d.Service)...); err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
	}
	rolledCID, err := managedContainerID(rollbackCtx, runner, d)
	if err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
	}
	rolledImage, inspectErr := runner.Run(rollbackCtx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "inspect", "--format={{.Image}}", rolledCID)
	if inspectErr != nil || strings.ToLower(strings.TrimSpace(rolledImage)) != checkpoint.PreviousImageID || verifyTarget(rollbackCtx, target, checkpoint.PreviousVersion) != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, errors.New("checkpoint Docker rollback did not restore the verified previous target")
	}
	if !checkpoint.VersionEnvExisted {
		if err := restoreVersionEnv(d.VersionEnvFile, nil, checkpoint.VersionEnvMode, false); err != nil {
			return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
		}
	}
	if err := clearCheckpoint(target); err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
	}
	return ApplyResult{Status: "rolled_back", ArtifactDigest: plan.ExpectedImageDigest, PreviousDigest: checkpoint.PreviousImageID, RolledBack: true, Message: "interrupted Docker cutover was rolled back from its durable checkpoint"}, nil
}

func checkpointEnv(checkpoint *updateCheckpoint) []byte {
	if checkpoint == nil {
		return nil
	}
	return checkpoint.PreviousVersionEnv
}

func checkpointMode(checkpoint *updateCheckpoint) os.FileMode {
	if checkpoint == nil || checkpoint.VersionEnvMode == 0 {
		return 0o600
	}
	return checkpoint.VersionEnvMode
}

func runFixedCommand(ctx context.Context, runner CommandRunner, argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	_, err := runner.Run(commandCtx, "", nil, argv[0], argv[1:]...)
	return err
}

func verifyTarget(ctx context.Context, target Target, expectedVersion string) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var lastErr error
	for {
		if err := checkHealth(deadlineCtx, client, target.HealthURL); err == nil {
			if actual, err := fetchVersion(deadlineCtx, client, target.VersionURL); err == nil && versionsEqual(actual, expectedVersion) {
				return nil
			} else if err != nil {
				lastErr = err
			} else {
				lastErr = fmt.Errorf("reported version %q does not match %q", actual, expectedVersion)
			}
		} else {
			lastErr = err
		}
		select {
		case <-deadlineCtx.Done():
			return fmt.Errorf("post-update verification failed: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func checkHealth(ctx context.Context, client *http.Client, raw string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("health endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func fetchVersion(ctx context.Context, client *http.Client, raw string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("version endpoint returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Version) == "" {
		return "", errors.New("version endpoint returned no version")
	}
	return body.Version, nil
}

func versionMatches(output, expected string) bool {
	for _, field := range strings.Fields(output) {
		if versionsEqual(strings.Trim(field, ",;()"), expected) {
			return true
		}
	}
	return false
}

func versionsEqual(a, b string) bool {
	return strings.TrimPrefix(strings.TrimSpace(a), "v") == strings.TrimPrefix(strings.TrimSpace(b), "v")
}

func shortID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:6])
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
