package hostruntime

import (
	"context"
	"errors"
	"github.com/Kome-Lab/Autostream-Updater/internal/controlplane"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const remoteLegacyStageGenerationScanLimit uint64 = 256
const remoteMutationWaitLimit = 30 * time.Minute

type executorMutationRuntime struct {
	runner                      CommandRunner
	httpClient                  *http.Client
	platformOS                  string
	platformArch                string
	ownershipEpoch              int64
	policyRevision              int64
	transportMode               string
	publicArtifactsOnly         bool
	localStateDir               string
	consumeGrant                func(context.Context, string, string, string, MutationGrantBinding, *http.Client) error
	consumeV2Grant              func(context.Context, string, string, string, contracts.UpdaterMutationGrantConsumeRequest, *http.Client, time.Time) error
	v2GrantBinding              *contracts.UpdaterMutationGrantBinding
	portPolicyStore             portPolicyStore
	now                         func() time.Time
	dockerPortCrashPointForTest func(string) error
}

func defaultExecutorMutationRuntime() executorMutationRuntime {
	return executorMutationRuntime{
		runner:         OSCommandRunner{NewProcessGroup: true},
		platformOS:     runtime.GOOS,
		platformArch:   runtime.GOARCH,
		consumeGrant:   ConsumeMutationGrant,
		consumeV2Grant: controlplane.ConsumeMutationGrant,
		now:            time.Now,
	}
}

func probeRemoteTargetVersion(target Target) string {
	if target.DeploymentMode == ModeSystemd && target.Systemd != nil {
		_, _, current, err := currentRelease(target.Systemd.CurrentLink, target.Systemd.ReleaseRoot)
		if err == nil && versionPattern.MatchString(current) {
			return current
		}
		return ""
	}
	if target.DeploymentMode == ModeDocker && target.Docker != nil {
		if data, _, exists, err := readVersionEnv(target.Docker.VersionEnvFile); err == nil && exists {
			if current, _, err := parseVersionEnvPin(data, target.Docker.ImageVariable); err == nil {
				return current
			}
		}
		if versionPattern.MatchString(target.Docker.CurrentVersion) {
			return target.Docker.CurrentVersion
		}
	}
	return ""
}

// verifyMutationPlanCurrentVersion fences a remote operation to the exact
// deployed version observed when the immutable plan was issued. Remote plans
// never permit an unknown baseline because that could authorize a downgrade.
func verifyMutationPlanCurrentVersion(target Target, plan MutationPlan) error {
	planned := strings.TrimSpace(plan.CurrentVersion)
	if planned == "" {
		return errors.New("remote plan is missing its current version baseline")
	}
	actual, err := managedRemoteCurrentVersion(target)
	if err != nil {
		return errors.New("could not verify the planned current version")
	}
	return requirePlannedCurrentVersion(planned, actual)
}

func managedRemoteCurrentVersion(target Target) (string, error) {
	switch target.DeploymentMode {
	case ModeSystemd:
		if target.Systemd == nil {
			return "", errors.New("systemd target is unavailable")
		}
		current, _, version, err := currentRelease(target.Systemd.CurrentLink, target.Systemd.ReleaseRoot)
		if err != nil || current == "" || !versionPattern.MatchString(version) {
			return "", errors.New("managed systemd current release is unavailable")
		}
		return version, nil
	case ModeDocker:
		if target.Docker == nil {
			return "", errors.New("Docker target is unavailable")
		}
		data, _, exists, err := readVersionEnv(target.Docker.VersionEnvFile)
		if err != nil {
			return "", errors.New("read Docker version pin")
		}
		if exists {
			version, _, err := parseVersionEnvPin(data, target.Docker.ImageVariable)
			if err != nil {
				return "", errors.New("Docker version pin is invalid")
			}
			return version, nil
		}
		version := strings.TrimSpace(target.Docker.CurrentVersion)
		if !versionPattern.MatchString(version) {
			return "", errors.New("Docker current version is unavailable")
		}
		return version, nil
	default:
		return "", errors.New("unsupported deployment mode")
	}
}

func requirePlannedCurrentVersion(planned, actual string) error {
	planned = strings.TrimSpace(planned)
	if planned == "" {
		return nil
	}
	if !versionPattern.MatchString(planned) || !versionPattern.MatchString(strings.TrimSpace(actual)) || strings.TrimSpace(actual) != planned {
		return errors.New("managed target current version does not match the immutable plan")
	}
	return nil
}
