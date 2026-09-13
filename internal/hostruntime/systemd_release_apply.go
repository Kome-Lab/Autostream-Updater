package hostruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
