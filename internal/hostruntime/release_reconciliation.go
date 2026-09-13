package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

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
	return fetchApplicationIdentityVersion(checkCtx, &client, target)
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
	return reconcileDockerWithListenerStore(ctx, target, plan, runner, mutationGate, defaultDockerNodeListenerStore())
}

func reconcileDockerWithListenerStore(ctx context.Context, target Target, plan ApplyPlan, runner CommandRunner, mutationGate func(context.Context) error, listenerStore dockerNodeListenerStore) (ApplyResult, error) {
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
	execution, err := listenerStore.freeze(frozenPath, d)
	if err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
	}
	base = composeFrozenArgs(d, execution.path)
	if err := listenerStore.validateFrozen(execution, d); err != nil {
		return ApplyResult{Status: "failed", PreviousDigest: checkpoint.PreviousImageID}, err
	}
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
