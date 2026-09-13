package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
	return applyDockerWithListenerStore(ctx, target, plan, runner, mutationGate, trustedImageStaged, stagedBaseline, expectedStagedImageID, trustedOwner, defaultDockerNodeListenerStore())
}

func applyDockerWithListenerStore(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner, mutationGate func(context.Context) error, trustedImageStaged bool, stagedBaseline *dockerMutationBaseline, expectedStagedImageID string, trustedOwner func(os.FileInfo) bool, listenerStore dockerNodeListenerStore) (ApplyResult, error) {
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
	var execution dockerFrozenExecution
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
		// Preparation/staging stays inline. Materialize only after the grant,
		// baseline and port preconditions, before changing the live target.
		execution, err = listenerStore.freeze(frozenPath, d)
		if err != nil {
			return ApplyResult{}, err
		}
		base = composeFrozenArgs(d, execution.path)
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
		execution, err = listenerStore.freeze(frozenPath, d)
		if err != nil {
			return ApplyResult{}, err
		}
		base = composeFrozenArgs(d, execution.path)
	}
	checkpoint.Phase = "starting"
	if err := saveCheckpoint(target, checkpoint); err != nil {
		return ApplyResult{}, fmt.Errorf("persist Docker starting checkpoint: %w", err)
	}
	if err := listenerStore.validateFrozen(execution, d); err != nil {
		return ApplyResult{}, err
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
			execution, configErr = listenerStore.freeze(frozenRollback, d)
			base = composeFrozenArgs(d, execution.path)
		}
	}
	rollbackErr := firstError(restoreErr, overrideErr, configErr)
	if rollbackErr == nil {
		rollbackErr = listenerStore.validateFrozen(execution, d)
	}
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
