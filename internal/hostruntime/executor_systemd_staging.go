package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"
)

func preflightRemoteSystemdStage(ctx context.Context, target Target, plan MutationPlan, artifactRoot string, stage *remoteStage, runner CommandRunner) error {
	systemd := target.Systemd
	resolved, err := resolveRemoteArtifactRoot(artifactRoot)
	if err != nil {
		return errors.New("staged systemd artifact path is invalid")
	}
	if err := VerifyInnerChecksums(resolved); err != nil {
		return errors.New("staged systemd artifact checksum verification failed")
	}
	for _, rel := range append([]string{systemd.BinaryPath}, systemd.RequiredPaths...) {
		info, err := os.Stat(filepath.Join(resolved, filepath.FromSlash(rel)))
		if err != nil || (rel == systemd.BinaryPath && !info.Mode().IsRegular()) {
			return errors.New("staged systemd artifact is incomplete")
		}
	}
	// The state tree intentionally remains root-only. The root helper chdirs to
	// the already-verified artifact root before runuser drops privileges, so a
	// safe relative binary path lets the smoke user execute the artifact without
	// granting traversal into state_dir, ledger, requests, or results.
	smokeBinary := "." + string(filepath.Separator) + filepath.FromSlash(systemd.BinaryPath)
	smokeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	output, smokeErr := runner.Run(smokeCtx, resolved, nil, systemd.RunuserPath, "-u", systemd.SmokeUser, "--", smokeBinary, "--version")
	cancel()
	if smokeErr != nil {
		return errors.New("staged systemd binary smoke execution failed")
	}
	if !versionMatches(output, plan.TargetVersion) {
		return errors.New("staged systemd binary version output mismatch")
	}
	previous, previousDigest, previousVersion, err := currentRelease(systemd.CurrentLink, systemd.ReleaseRoot)
	if err != nil || previous == "" {
		return errors.New("managed systemd release bootstrap is required")
	}
	if err := requirePlannedCurrentVersion(plan.CurrentVersion, previousVersion); err != nil {
		return err
	}
	if err := runFixedCommand(ctx, runner, target.BackupArgv); err != nil {
		return errors.New("backup configured systemd target")
	}
	if err := verifyManagedReleaseChecksums(previous); err != nil {
		return errors.New("previous systemd release is not rollback-safe")
	}
	for _, rel := range append([]string{systemd.BinaryPath}, systemd.RequiredPaths...) {
		info, err := os.Stat(filepath.Join(previous, filepath.FromSlash(rel)))
		if err != nil || (rel == systemd.BinaryPath && !info.Mode().IsRegular()) {
			return errors.New("previous systemd release is incomplete")
		}
	}
	if err := firstError(verifySystemdProcess(ctx, target, previous, runner), verifyTarget(ctx, target, previousVersion)); err != nil {
		return errors.New("previous systemd release is not healthy")
	}
	newRelease := filepath.Join(systemd.ReleaseRoot, plan.TargetVersion+"-"+strings.ToLower(plan.ArtifactDigest[:12]))
	if !pathWithin(systemd.ReleaseRoot, newRelease) {
		return errors.New("systemd release path is invalid")
	}
	stage.NewRelease = newRelease
	stage.PreviousRelease = previous
	stage.PreviousDigest = normalizeDigest(previousDigest)
	stage.PreviousVersion = previousVersion
	return nil
}

func resolveRemoteArtifactRoot(artifactRoot string) (string, error) {
	if runtime.GOOS == "windows" {
		// The privileged helper is Linux-only. Windows executes these pure
		// planning tests under ACLs where EvalSymlinks can fail even for a
		// non-link temp directory, so retain the structural non-link check
		// without weakening the Linux runtime boundary.
		resolved, err := filepath.Abs(filepath.Clean(artifactRoot))
		info, statErr := os.Lstat(resolved)
		if err != nil || statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("artifact root is unavailable")
		}
		return resolved, nil
	}
	resolved, err := filepath.EvalSymlinks(artifactRoot)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errors.New("artifact root is unavailable")
	}
	return resolved, nil
}

func applyRemoteStagedSystemd(ctx context.Context, target Target, plan ApplyPlan, stage remoteStage, runner CommandRunner, mutationGate func(context.Context) error) (ApplyResult, error) {
	return applyRemoteStagedSystemdWithVerifier(ctx, target, plan, stage, runner, mutationGate, verifyRemoteSystemdBaseline)
}

type remoteSystemdBaselineVerifier func(context.Context, Target, remoteStage, CommandRunner) error

func applyRemoteStagedSystemdWithVerifier(ctx context.Context, target Target, plan ApplyPlan, stage remoteStage, runner CommandRunner, mutationGate func(context.Context) error, verifyBaseline remoteSystemdBaselineVerifier) (ApplyResult, error) {
	if plan.StageDir == "" || !filepath.IsAbs(plan.StageDir) || filepath.Clean(plan.StageDir) != filepath.Clean(stage.RootDir) || len(plan.ArtifactDigest) != 64 || mutationGate == nil {
		return ApplyResult{}, errors.New("remote systemd stage is incomplete")
	}
	if verifyBaseline == nil {
		return ApplyResult{}, errors.New("remote systemd baseline verifier is unavailable")
	}
	if err := requirePlannedCurrentVersion(plan.CurrentVersion, stage.PreviousVersion); err != nil {
		return ApplyResult{}, err
	}
	preflightCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := verifyBaseline(preflightCtx, target, stage, runner)
	cancel()
	if err != nil {
		return ApplyResult{}, err
	}
	checkpoint, err := loadCheckpoint(target)
	if err != nil {
		return ApplyResult{}, err
	}
	if checkpoint != nil && checkpoint.Phase != "succeeded" && checkpoint.Phase != "rolled_back" {
		return ApplyResult{}, errors.New("an interrupted systemd checkpoint requires reconcile")
	}
	if err := mutationGate(ctx); err != nil {
		return ApplyResult{}, err
	}
	// Grant consumption is an external round trip. Re-read both the durable
	// checkpoint state and the complete running rollback baseline immediately
	// afterward, before installing a release or touching the service.
	afterGrantCheckpoint, err := loadCheckpoint(target)
	if err != nil || !reflect.DeepEqual(checkpoint, afterGrantCheckpoint) {
		return ApplyResult{}, errors.New("systemd checkpoint changed while consuming the mutation grant")
	}
	postGrantCtx, postGrantCancel := context.WithTimeout(ctx, 10*time.Second)
	err = verifyBaseline(postGrantCtx, target, stage, runner)
	postGrantCancel()
	if err != nil {
		return ApplyResult{}, errors.New("systemd target changed while consuming the mutation grant")
	}
	afterVerifyCheckpoint, err := loadCheckpoint(target)
	if err != nil || !reflect.DeepEqual(checkpoint, afterVerifyCheckpoint) {
		return ApplyResult{}, errors.New("systemd checkpoint changed while verifying the mutation baseline")
	}
	if checkpoint != nil {
		if err := clearCheckpoint(target); err != nil {
			return ApplyResult{}, err
		}
	}
	if err := installReleaseTree(plan.StageDir, stage.NewRelease, plan.ArtifactDigest, plan.TargetVersion); err != nil {
		return ApplyResult{}, err
	}
	if err := verifyManagedReleaseChecksums(stage.NewRelease); err != nil {
		return ApplyResult{}, errors.New("installed systemd release integrity check failed")
	}
	for _, rel := range append([]string{target.Systemd.BinaryPath}, target.Systemd.RequiredPaths...) {
		info, err := os.Stat(filepath.Join(stage.NewRelease, filepath.FromSlash(rel)))
		if err != nil || (rel == target.Systemd.BinaryPath && !info.Mode().IsRegular()) {
			return ApplyResult{}, errors.New("installed systemd release is incomplete")
		}
	}
	// Installing and checksumming a large tree can outlive the earlier
	// post-grant observation. Perform one final short baseline/checkpoint check
	// immediately before commitRemoteSystemdMutation persists a new checkpoint
	// and stops the service.
	finalCheckpoint, err := loadCheckpoint(target)
	if err != nil || finalCheckpoint != nil {
		return ApplyResult{}, errors.New("systemd checkpoint changed before service mutation")
	}
	finalCtx, finalCancel := context.WithTimeout(ctx, 10*time.Second)
	err = verifyBaseline(finalCtx, target, stage, runner)
	finalCancel()
	if err != nil {
		return ApplyResult{}, errors.New("systemd target changed before service mutation")
	}
	finalCheckpoint, err = loadCheckpoint(target)
	if err != nil || finalCheckpoint != nil {
		return ApplyResult{}, errors.New("systemd checkpoint changed during final baseline verification")
	}
	return commitRemoteSystemdMutation(ctx, target, plan, stage, runner)
}

func verifyRemoteSystemdBaseline(ctx context.Context, target Target, stage remoteStage, runner CommandRunner) error {
	if err := verifyRemoteSystemdStagedArtifact(ctx, target, stage, runner); err != nil {
		return errors.New("staged systemd artifact changed after staging")
	}
	current, digest, version, err := currentRelease(target.Systemd.CurrentLink, target.Systemd.ReleaseRoot)
	if err != nil || current != filepath.Clean(stage.PreviousRelease) || normalizeDigest(digest) != normalizeDigest(stage.PreviousDigest) || version != stage.PreviousVersion {
		return errors.New("systemd target changed after staging")
	}
	if err := firstError(
		verifyManagedReleaseChecksums(current),
		verifySystemdProcess(ctx, target, current, runner),
		verifyRemoteHealthyVersionExact(ctx, target, version),
	); err != nil {
		return errors.New("staged systemd rollback baseline is no longer healthy and exact")
	}
	return nil
}

func verifyRemoteSystemdStagedArtifact(ctx context.Context, target Target, stage remoteStage, runner CommandRunner) error {
	if target.Systemd == nil || runner == nil || !filepath.IsAbs(stage.RootDir) || !versionPattern.MatchString(stage.ExpectedVersion) {
		return errors.New("staged systemd artifact binding is invalid")
	}
	resolved, err := filepath.EvalSymlinks(stage.RootDir)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(stage.RootDir) {
		return errors.New("staged systemd artifact path changed")
	}
	if err := VerifyInnerChecksums(resolved); err != nil {
		return errors.New("staged systemd artifact integrity changed")
	}
	for _, rel := range append([]string{target.Systemd.BinaryPath}, target.Systemd.RequiredPaths...) {
		path := filepath.Join(resolved, filepath.FromSlash(rel))
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("staged systemd artifact required path changed")
		}
		if rel == target.Systemd.BinaryPath && (!info.Mode().IsRegular() || info.Mode().Perm() != 0o755) {
			return errors.New("staged systemd binary mode changed")
		}
	}
	smokeBinary := "." + string(filepath.Separator) + filepath.FromSlash(target.Systemd.BinaryPath)
	output, err := runner.Run(ctx, resolved, nil, target.Systemd.RunuserPath, "-u", target.Systemd.SmokeUser, "--", smokeBinary, "--version")
	if err != nil || !versionMatches(output, stage.ExpectedVersion) {
		return errors.New("staged systemd binary smoke check changed")
	}
	return nil
}

func verifyRemoteHealthyVersionExact(ctx context.Context, target Target, expected string) error {
	actual, err := readHealthyTargetVersion(ctx, target)
	if err != nil || strings.TrimSpace(actual) != expected {
		return errors.New("managed target health version does not exactly match its release marker")
	}
	return nil
}

func commitRemoteSystemdMutation(ctx context.Context, target Target, plan ApplyPlan, stage remoteStage, runner CommandRunner) (ApplyResult, error) {
	systemd := target.Systemd
	checkpoint := updateCheckpoint{
		JobID: plan.JobID, TargetID: target.TargetID, DeploymentMode: ModeSystemd, Phase: "prepared",
		TargetVersion: plan.TargetVersion, TargetDigest: normalizeDigest(plan.ArtifactDigest), NewRelease: stage.NewRelease,
		PreviousRelease: stage.PreviousRelease, PreviousDigest: normalizeDigest(stage.PreviousDigest), PreviousVersion: stage.PreviousVersion,
	}
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{}, errors.New("persist systemd update checkpoint")
	}
	if _, err := runner.Run(ctx, "", nil, systemd.SystemctlPath, "stop", systemd.Unit); err != nil {
		return ApplyResult{}, err
	}
	checkpoint.Phase = "stopped"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		_, _ = runner.Run(context.Background(), "", nil, systemd.SystemctlPath, "start", systemd.Unit)
		return ApplyResult{}, errors.New("persist stopped systemd checkpoint")
	}
	if err := switchSymlink(systemd.CurrentLink, stage.NewRelease, plan.JobID); err != nil {
		_, _ = runner.Run(ctx, "", nil, systemd.SystemctlPath, "start", systemd.Unit)
		return ApplyResult{}, err
	}
	checkpoint.Phase = "switched"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{}, errors.New("persist switched systemd checkpoint")
	}
	startOutput, startErr := runner.Run(ctx, "", nil, systemd.SystemctlPath, "start", systemd.Unit)
	checkpoint.Phase = "started"
	checkpointErr := saveCheckpoint(target, checkpoint)
	var verifyErr error
	if startErr == nil {
		verifyErr = firstError(checkpointErr, verifySystemdProcess(ctx, target, stage.NewRelease, runner), verifyTarget(ctx, target, plan.TargetVersion))
	}
	if startErr == nil && verifyErr == nil {
		checkpoint.Phase = "succeeded"
		if err := saveCheckpoint(target, checkpoint); err != nil {
			return ApplyResult{}, errors.New("persist terminal systemd checkpoint")
		}
		return ApplyResult{Status: "succeeded", ArtifactDigest: normalizeDigest(plan.ArtifactDigest), PreviousDigest: normalizeDigest(stage.PreviousDigest)}, nil
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := rollbackSystemd(rollbackCtx, target, stage.PreviousRelease, stage.PreviousVersion, plan.JobID, runner); err != nil {
		return ApplyResult{Status: "failed", ArtifactDigest: normalizeDigest(plan.ArtifactDigest), PreviousDigest: normalizeDigest(stage.PreviousDigest)}, errors.New("systemd update and rollback failed")
	}
	checkpoint.Phase = "rolled_back"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{Status: "failed"}, errors.New("persist rolled-back systemd checkpoint")
	}
	_ = startOutput
	return ApplyResult{Status: "rolled_back", ArtifactDigest: normalizeDigest(plan.ArtifactDigest), PreviousDigest: normalizeDigest(stage.PreviousDigest), RolledBack: true, Message: "systemd update was rolled back"}, nil
}
