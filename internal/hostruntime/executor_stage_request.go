package hostruntime

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func executorStageRequest(ctx context.Context, cfg HelperConfig, target Target, plan MutationPlan, releaseToken BoundedSecret, ledger *executorMutationLedger, rt executorMutationRuntime) executorMutationOutcome {
	var previousTerminalStage *remoteStage
	if ledger != nil {
		if ledger.JobID == plan.JobID && ledger.PlanSHA256 != plan.PlanSHA256 {
			return executorFailure("plan_conflict")
		}
		if ledger.JobID == plan.JobID && ledger.PlanSHA256 == plan.PlanSHA256 {
			if ledger.State == remoteLedgerStaged && validateExecutorStage(cfg, target, plan, ledger.Stage) == nil {
				if err := verifyMutationPlanCurrentVersion(target, plan); err != nil {
					return executorFailureWithMessage("stage_failed", remoteStageFailureMessage(err))
				}
				stage := remoteStageResult(plan, *ledger.Stage)
				return executorMutationOutcome{Stage: &stage}
			}
			if ledger.State == remoteLedgerTerminal {
				return executorFailure("already_terminal")
			}
			return executorFailure("reconcile_required")
		}
		if ledger.State != remoteLedgerTerminal {
			return executorFailure("reconcile_required")
		}
		previousTerminalStage = ledger.Stage
	}
	stage, err := prepareExecutorStage(ctx, cfg, target, plan, releaseToken, rt)
	if err != nil {
		return executorFailureWithMessage("stage_failed", remoteStageFailureMessage(err))
	}
	record := executorMutationLedger{
		SchemaVersion: remoteLedgerSchemaVersion, JobID: plan.JobID, TargetID: plan.TargetID,
		PlanSHA256: plan.PlanSHA256, SessionID: plan.SessionID, LeaseGeneration: plan.LeaseGeneration,
		Intent: newRemoteMutationIntent(plan), Operation: "stage",
		State: remoteLedgerStaged, Stage: &stage,
	}
	if err := saveExecutorMutationLedger(cfg, record); err != nil {
		return executorFailure("state_unavailable")
	}
	cleanupRemoteTerminalStage(cfg, previousTerminalStage, stage.RootDir)
	result := remoteStageResult(plan, stage)
	return executorMutationOutcome{Stage: &result}
}

func cleanupRemoteTerminalStage(cfg HelperConfig, oldStage *remoteStage, currentRoot string) {
	if oldStage == nil || oldStage.RootDir == "" || oldStage.RootDir == currentRoot {
		return
	}
	stagesRoot := filepath.Join(cfg.StateDir, "stages")
	relative, err := filepath.Rel(stagesRoot, oldStage.RootDir)
	if err != nil || relative == "." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return
	}
	component := strings.Split(filepath.ToSlash(relative), "/")[0]
	if !mutationPlanHashPattern.MatchString(component) {
		return
	}
	oldRoot := filepath.Join(stagesRoot, component)
	if pathWithin(stagesRoot, oldRoot) && !pathWithin(oldRoot, currentRoot) {
		_ = os.RemoveAll(oldRoot)
		_ = syncDirectory(stagesRoot)
	}
}

func cleanupRemoteOrphanStage(cfg HelperConfig, plan MutationPlan) error {
	stagesRoot := filepath.Clean(filepath.Join(cfg.StateDir, "stages"))
	orphanRoots, err := remoteOrphanStageRoots(cfg, plan)
	if err != nil {
		return err
	}
	for _, orphanRoot := range orphanRoots {
		if filepath.Dir(orphanRoot) != stagesRoot || !pathWithin(stagesRoot, orphanRoot) {
			return errors.New("orphan remote stage path escaped state directory")
		}
		if _, err := os.Lstat(orphanRoot); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return errors.New("inspect orphan remote stage")
		}
		// A stage is not apply-authorized until its target ledger has been
		// durably committed. A failed ledger persistence can therefore leave
		// this exact immutable-intent directory behind. Remove only the
		// root-controlled tree and fsync stagesRoot before reporting the
		// absence of ledger-backed mutation state.
		if err := removeStaleReleasePartial(stagesRoot, orphanRoot); err != nil {
			return errors.New("remove orphan remote stage")
		}
	}
	return nil
}

func remoteOrphanStageRoots(cfg HelperConfig, plan MutationPlan) ([]string, error) {
	stableRoot, err := remoteStageRoot(cfg, plan)
	if err != nil {
		return nil, errors.New("derive stable remote stage path")
	}
	roots := []string{stableRoot}
	seen := map[string]bool{stableRoot: true}
	legacy := plan.ApplyPlan()
	oldest := uint64(1)
	if plan.LeaseGeneration > remoteLegacyStageGenerationScanLimit {
		oldest = plan.LeaseGeneration - remoteLegacyStageGenerationScanLimit + 1
	}
	for generation := plan.LeaseGeneration; generation >= oldest; generation-- {
		legacy.LeaseGeneration = generation
		digest, err := MutationPlanSHA256(legacy)
		if err != nil {
			return nil, errors.New("derive legacy remote stage path")
		}
		root := filepath.Join(cfg.StateDir, "stages", remoteStableKey(plan.JobID, digest))
		if !seen[root] {
			roots = append(roots, root)
			seen[root] = true
		}
		if generation == oldest {
			break
		}
	}
	return roots, nil
}

// remoteStageRoot is deliberately stable across lease generations. A fresh
// recovery lease changes the grant-bound plan hash, but it must still identify
// a stage committed immediately before ledger persistence failed. Canonical
// generation one retains every immutable mutation field while removing only
// the lease-generation variance from the root name.
func remoteStageRoot(cfg HelperConfig, plan MutationPlan) (string, error) {
	stable := plan.ApplyPlan()
	stable.LeaseGeneration = 1
	digest, err := MutationPlanSHA256(stable)
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg.StateDir, "stages", remoteStableKey(plan.JobID, digest)), nil
}

func remoteStageResult(plan MutationPlan, stage remoteStage) MutationStageResult {
	return MutationStageResult{
		Status: "staged", SessionID: plan.SessionID, PlanSHA256: plan.PlanSHA256,
		ArtifactDigest: strings.TrimPrefix(normalizeDigest(stage.ArtifactDigest), "sha256:"),
	}
}

func prepareExecutorStage(ctx context.Context, cfg HelperConfig, target Target, plan MutationPlan, releaseToken BoundedSecret, rt executorMutationRuntime) (remoteStage, error) {
	if err := verifyMutationPlanCurrentVersion(target, plan); err != nil {
		return remoteStage{}, err
	}
	if err := gcAgedRemoteStagePartials(cfg, time.Now()); err != nil {
		return remoteStage{}, err
	}
	stageRoot, err := remoteStageRoot(cfg, plan)
	if err != nil {
		return remoteStage{}, errors.New("derive release stage path")
	}
	if !pathWithin(filepath.Join(cfg.StateDir, "stages"), stageRoot) {
		return remoteStage{}, errors.New("stage path escaped state directory")
	}
	if err := os.RemoveAll(stageRoot); err != nil {
		return remoteStage{}, errors.New("clear incomplete stage")
	}
	partial, err := os.MkdirTemp(filepath.Join(cfg.StateDir, "stages"), ".partial-")
	if err != nil {
		return remoteStage{}, errors.New("create stage")
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(partial)
		}
	}()
	downloader := ReleaseDownloader{
		Client: rt.httpClient, Token: releaseToken.Reveal(),
		TrustedPublicOnly: rt.publicArtifactsOnly,
	}
	var stage remoteStage
	switch target.DeploymentMode {
	case ModeSystemd:
		downloaded, err := downloader.Download(ctx, target.ServiceType, plan.TargetVersion, cfg.Arch, filepath.Join(partial, "artifact"))
		if err != nil || normalizeDigest(downloaded.SHA256) != normalizeDigest(plan.ArtifactDigest) {
			return remoteStage{}, errors.New("systemd release digest mismatch")
		}
		rel, err := filepath.Rel(partial, downloaded.RootDir)
		if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return remoteStage{}, errors.New("systemd release stage is invalid")
		}
		stage = remoteStage{RootDir: filepath.Join(stageRoot, rel), ArtifactDigest: downloaded.SHA256, ExpectedVersion: plan.ExpectedVersion}
		if err := preflightRemoteSystemdStage(ctx, target, plan, downloaded.RootDir, &stage, rt.runner); err != nil {
			return remoteStage{}, err
		}
	case ModeDocker:
		resolved, err := downloader.ResolveDockerRelease(ctx, plan.TargetVersion, target.ServiceType, target.Docker.ImageRepo, target.Docker.Channel, partial)
		if err != nil || resolved.SourceVersion != plan.ExpectedVersion || normalizeDigest(resolved.ManifestDigest) != normalizeDigest(plan.ExpectedImageDigest) || normalizeDigest(resolved.PlatformDigest) != normalizeDigest(plan.ExpectedPlatformDigest) || normalizeDigest(resolved.ManifestSHA256) != normalizeDigest(plan.ArtifactDigest) {
			return remoteStage{}, errors.New("Docker release binding mismatch")
		}
		if err := verifyComposeModel(ctx, rt.runner, target.Docker, composeArgs(target.Docker, "")); err != nil {
			return remoteStage{}, err
		}
		digestRef := target.Docker.ImageRepo + "@" + plan.ExpectedPlatformDigest
		overridePath := filepath.Join(partial, "compose-override.json")
		if err := writeDockerOverride(overridePath, target.Docker.Service, digestRef); err != nil {
			return remoteStage{}, err
		}
		base := composeArgs(target.Docker, overridePath)
		if err := verifyComposeConfig(ctx, rt.runner, target.Docker, base, digestRef, filepath.Join(partial, "compose-frozen.json")); err != nil {
			return remoteStage{}, err
		}
		// Release resolution and compose validation can be slow. Capture the
		// complete rollback baseline immediately before the remaining stage side
		// effects; apply must see this exact baseline again.
		baselineCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		baseline, baselineErr := observeDockerMutationBaseline(baselineCtx, target, rt.runner)
		cancel()
		if baselineErr != nil {
			return remoteStage{}, baselineErr
		}
		if err := requirePlannedCurrentVersion(plan.CurrentVersion, baseline.Baseline.BundleVersion); err != nil {
			return remoteStage{}, err
		}
		if err := runFixedCommand(ctx, rt.runner, target.BackupArgv); err != nil {
			return remoteStage{}, errors.New("backup configured Docker target")
		}
		if _, err := rt.runner.Run(ctx, target.Docker.ProjectDir, dockerCommandEnv(), target.Docker.DockerPath, "pull", digestRef); err != nil {
			return remoteStage{}, errors.New("pull trusted Docker image")
		}
		imageOut, err := rt.runner.Run(ctx, target.Docker.ProjectDir, dockerCommandEnv(), target.Docker.DockerPath, "image", "inspect", "--format={{.Id}}", digestRef)
		imageID := strings.ToLower(strings.TrimSpace(imageOut))
		if err != nil || !digestPattern.MatchString(imageID) {
			return remoteStage{}, errors.New("inspect trusted Docker image")
		}
		repoDigests, err := rt.runner.Run(ctx, target.Docker.ProjectDir, dockerCommandEnv(), target.Docker.DockerPath, "image", "inspect", "--format={{json .RepoDigests}}", digestRef)
		if err != nil || !repositoryHasDigest(repoDigests, target.Docker.ImageRepo, plan.ExpectedPlatformDigest) {
			return remoteStage{}, errors.New("trusted Docker image digest mismatch")
		}
		stage = remoteStage{
			RootDir: stageRoot, ArtifactDigest: resolved.ManifestSHA256,
			ExpectedVersion: resolved.SourceVersion, ExpectedImageDigest: resolved.ManifestDigest,
			ExpectedPlatformDigest: resolved.PlatformDigest, ImageID: imageID, DockerBaseline: &baseline.Baseline,
		}
	default:
		return remoteStage{}, errors.New("unsupported deployment mode")
	}
	if err := os.Rename(partial, stageRoot); err != nil {
		return remoteStage{}, errors.New("commit release stage")
	}
	committed = true
	if err := syncDirectory(filepath.Dir(stageRoot)); err != nil {
		return remoteStage{}, errors.New("sync release stage")
	}
	return stage, nil
}

func gcAgedRemoteStagePartials(cfg HelperConfig, now time.Time) error {
	stagesRoot := filepath.Join(cfg.StateDir, "stages")
	dir, err := os.Open(stagesRoot)
	if err != nil {
		return errors.New("open remote stage directory for cleanup")
	}
	defer dir.Close()
	const maxScanned, maxRemoved = 256, 32
	entries, err := dir.ReadDir(maxScanned + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("scan remote stage directory for cleanup")
	}
	if len(entries) > maxScanned {
		entries = entries[:maxScanned]
	}
	removed := 0
	for _, entry := range entries {
		if removed >= maxRemoved || !strings.HasPrefix(entry.Name(), ".partial-") {
			continue
		}
		candidate := filepath.Join(stagesRoot, entry.Name())
		if !pathWithin(stagesRoot, candidate) {
			continue
		}
		info, statErr := os.Lstat(candidate)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !isRootOwner(info) || (!now.IsZero() && now.Sub(info.ModTime()) <= remoteMutationWaitLimit+5*time.Minute) {
			continue
		}
		// A transient worker is force-stopped at remoteMutationWaitLimit, and a
		// committed/ledger-referenced stage never retains the .partial- prefix.
		// Therefore only an aged, structurally uncommitted directory reaches this
		// removal path. Root ownership prevents an unprivileged swap during GC.
		if err := os.RemoveAll(candidate); err != nil {
			return errors.New("remove abandoned remote stage")
		}
		removed++
	}
	if removed > 0 {
		return syncDirectory(stagesRoot)
	}
	return nil
}

func validateExecutorStage(cfg HelperConfig, target Target, plan MutationPlan, stage *remoteStage) error {
	if stage == nil || !filepath.IsAbs(stage.RootDir) || !pathWithin(filepath.Join(cfg.StateDir, "stages"), stage.RootDir) || normalizeDigest(stage.ArtifactDigest) != normalizeDigest(plan.ArtifactDigest) {
		return errors.New("staged release binding is invalid")
	}
	info, err := os.Lstat(stage.RootDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !isRootOwner(info) {
		return errors.New("staged release is unavailable")
	}
	if target.DeploymentMode == ModeDocker {
		if stage.ExpectedVersion != plan.ExpectedVersion || normalizeDigest(stage.ExpectedImageDigest) != normalizeDigest(plan.ExpectedImageDigest) || normalizeDigest(stage.ExpectedPlatformDigest) != normalizeDigest(plan.ExpectedPlatformDigest) || !digestPattern.MatchString(stage.ImageID) || stage.DockerBaseline == nil || stage.DockerBaseline.validate() != nil || requirePlannedCurrentVersion(plan.CurrentVersion, stage.DockerBaseline.BundleVersion) != nil {
			return errors.New("staged Docker release binding is invalid")
		}
	}
	if target.DeploymentMode == ModeSystemd {
		if stage.ExpectedVersion != plan.ExpectedVersion || !filepath.IsAbs(stage.NewRelease) || !filepath.IsAbs(stage.PreviousRelease) || !digestPattern.MatchString(normalizeDigest(stage.PreviousDigest)) || !versionPattern.MatchString(stage.PreviousVersion) || requirePlannedCurrentVersion(plan.CurrentVersion, stage.PreviousVersion) != nil {
			return errors.New("staged systemd release binding is invalid")
		}
	}
	return nil
}
