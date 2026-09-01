package hostruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

const mutationPlanSchemaVersion = 2

// MutationPlanSHA256 binds a short-lived Control Panel grant to the complete
// immutable update intent. Local staging paths and bearer secrets are
// deliberately excluded; neither is accepted as authority by a remote host.
func MutationPlanSHA256(plan ApplyPlan) (string, error) {
	currentVersion := strings.TrimSpace(plan.CurrentVersion)
	configSHA256 := strings.TrimSpace(strings.ToLower(plan.ConfigSHA256))
	if !identifierPattern.MatchString(strings.TrimSpace(plan.JobID)) ||
		!identifierPattern.MatchString(strings.TrimSpace(plan.HostID)) ||
		!identifierPattern.MatchString(strings.TrimSpace(plan.TargetID)) ||
		!versionPattern.MatchString(strings.TrimSpace(plan.TargetVersion)) ||
		!versionPattern.MatchString(currentVersion) || currentVersion != plan.CurrentVersion ||
		!digestPattern.MatchString(configSHA256) || configSHA256 != plan.ConfigSHA256 ||
		(plan.DeploymentMode != ModeSystemd && plan.DeploymentMode != ModeDocker) ||
		plan.LeaseGeneration == 0 {
		return "", errors.New("mutation plan identity is incomplete")
	}
	payload := struct {
		SchemaVersion          int    `json:"schema_version"`
		JobID                  string `json:"job_id"`
		HostID                 string `json:"host_id"`
		TargetID               string `json:"target_id"`
		ServiceType            string `json:"service_type"`
		DeploymentMode         string `json:"deployment_mode"`
		TargetVersion          string `json:"target_version"`
		CurrentVersion         string `json:"current_version"`
		ConfigSHA256           string `json:"config_sha256"`
		LeaseGeneration        uint64 `json:"lease_generation"`
		ArtifactDigest         string `json:"artifact_digest,omitempty"`
		ExpectedVersion        string `json:"expected_version,omitempty"`
		ExpectedImageDigest    string `json:"expected_image_digest,omitempty"`
		ExpectedPlatformDigest string `json:"expected_platform_digest,omitempty"`
	}{
		SchemaVersion: mutationPlanSchemaVersion,
		JobID:         strings.TrimSpace(plan.JobID), HostID: strings.TrimSpace(plan.HostID),
		TargetID: strings.TrimSpace(plan.TargetID), ServiceType: strings.TrimSpace(plan.ServiceType),
		DeploymentMode: strings.TrimSpace(plan.DeploymentMode), TargetVersion: strings.TrimSpace(plan.TargetVersion),
		CurrentVersion: currentVersion, ConfigSHA256: configSHA256, LeaseGeneration: plan.LeaseGeneration,
		ArtifactDigest: normalizeDigest(plan.ArtifactDigest), ExpectedVersion: strings.TrimSpace(plan.ExpectedVersion),
		ExpectedImageDigest: normalizeDigest(plan.ExpectedImageDigest), ExpectedPlatformDigest: normalizeDigest(plan.ExpectedPlatformDigest),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
