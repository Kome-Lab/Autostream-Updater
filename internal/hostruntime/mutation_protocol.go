package hostruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var (
	mutationPlanHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	mutationSessionPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)
)

func validExecutorFailureCode(code string) bool {
	switch code {
	case "invalid_request", "target_mismatch", "target_unavailable", "target_busy",
		"config_mismatch", "state_unavailable", "state_invalid", "stage_failed", "stage_required",
		"stage_invalid", "plan_conflict", "reconcile_required", "already_terminal",
		"mutation_precondition_failed", "launcher_unavailable", "operation_continues",
		"internal_error":
		return true
	default:
		return false
	}
}

// BoundedSecret is deliberately redacted by fmt. Reveal should only be used at
// the final HTTP/credential boundary; callers must never include it in errors.
type BoundedSecret string

func NewBoundedSecret(value string) BoundedSecret { return BoundedSecret(value) }
func (s BoundedSecret) Reveal() string            { return string(s) }
func (s BoundedSecret) Empty() bool               { return len(s) == 0 }
func (BoundedSecret) String() string              { return "[REDACTED]" }
func (BoundedSecret) GoString() string            { return "updateagent.BoundedSecret([REDACTED])" }
func (BoundedSecret) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}

// MarshalJSON deliberately redacts the credential so structured logging can
// never serialize bearer secrets.
func (BoundedSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal("[REDACTED]")
}

func (s *BoundedSecret) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("remote secret must be a string")
	}
	if value != "" && !validBoundedSecret(value) {
		return errors.New("remote secret is invalid")
	}
	*s = BoundedSecret(value)
	return nil
}

func validBoundedSecret(value string) bool {
	if len(value) == 0 || len(value) > 16<<10 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// MutationPlan contains only job and target identity. Privileged paths, units,
// image repositories, commands and endpoints are always reloaded from the
// root-owned HelperConfig on the destination host.
type MutationPlan struct {
	JobID                  string `json:"job_id"`
	HostID                 string `json:"host_id"`
	TargetID               string `json:"target_id"`
	ServiceType            string `json:"service_type"`
	DeploymentMode         string `json:"deployment_mode"`
	CurrentVersion         string `json:"current_version"`
	ConfigSHA256           string `json:"config_sha256"`
	TargetVersion          string `json:"target_version"`
	LeaseGeneration        uint64 `json:"lease_generation"`
	ArtifactDigest         string `json:"artifact_digest,omitempty"`
	ExpectedVersion        string `json:"expected_version,omitempty"`
	ExpectedImageDigest    string `json:"expected_image_digest,omitempty"`
	ExpectedPlatformDigest string `json:"expected_platform_digest,omitempty"`
	SessionID              string `json:"session_id"`
	PlanSHA256             string `json:"plan_sha256"`
}

func (p MutationPlan) Validate() error {
	if !identifierPattern.MatchString(p.JobID) || !identifierPattern.MatchString(p.HostID) || !identifierPattern.MatchString(p.TargetID) {
		return errors.New("remote plan contains an invalid identity")
	}
	switch p.ServiceType {
	case "control_panel", "worker", "encoder_recorder", "discord_bot", "observability":
	default:
		return errors.New("remote plan contains an unsupported service type")
	}
	if p.DeploymentMode != ModeSystemd && p.DeploymentMode != ModeDocker {
		return errors.New("remote plan contains an unsupported deployment mode")
	}
	if !versionPattern.MatchString(strings.TrimSpace(p.TargetVersion)) {
		return errors.New("remote plan contains an invalid target version")
	}
	if current := strings.TrimSpace(p.CurrentVersion); !versionPattern.MatchString(current) || current != p.CurrentVersion {
		return errors.New("remote plan contains an invalid current version")
	}
	if configSHA256 := strings.TrimSpace(strings.ToLower(p.ConfigSHA256)); !digestPattern.MatchString(configSHA256) || configSHA256 != p.ConfigSHA256 {
		return errors.New("remote plan contains an invalid helper config digest")
	}
	if p.LeaseGeneration == 0 {
		return errors.New("remote plan is missing its lease generation")
	}
	if !mutationSessionPattern.MatchString(p.SessionID) || !mutationPlanHashPattern.MatchString(p.PlanSHA256) {
		return errors.New("remote plan authorization binding is invalid")
	}
	switch p.DeploymentMode {
	case ModeSystemd:
		if !mutationPlanHashPattern.MatchString(p.ArtifactDigest) || p.ExpectedVersion != p.TargetVersion || p.ExpectedImageDigest != "" || p.ExpectedPlatformDigest != "" {
			return errors.New("remote systemd plan release binding is invalid")
		}
	case ModeDocker:
		if !mutationPlanHashPattern.MatchString(p.ArtifactDigest) || !versionPattern.MatchString(p.ExpectedVersion) || !digestPattern.MatchString(p.ExpectedImageDigest) || !digestPattern.MatchString(p.ExpectedPlatformDigest) {
			return errors.New("remote Docker plan release binding is invalid")
		}
	}
	computed, err := p.ComputePlanSHA256()
	if err != nil || computed != p.PlanSHA256 {
		return errors.New("remote plan digest does not match its immutable fields")
	}
	return nil
}

// ApplyPlan returns the exact secret-free input consumed by the canonical
// MutationPlanSHA256 function. Root-only paths and the control-plane lease token
// are deliberately absent and must be resolved independently by each side.
func (p MutationPlan) ApplyPlan() ApplyPlan {
	return ApplyPlan{
		JobID: p.JobID, HostID: p.HostID, TargetID: p.TargetID, ServiceType: p.ServiceType,
		DeploymentMode: p.DeploymentMode, TargetVersion: p.TargetVersion, CurrentVersion: p.CurrentVersion,
		ConfigSHA256:    p.ConfigSHA256,
		LeaseGeneration: p.LeaseGeneration, ArtifactDigest: p.ArtifactDigest, ExpectedVersion: p.ExpectedVersion,
		ExpectedImageDigest: p.ExpectedImageDigest, ExpectedPlatformDigest: p.ExpectedPlatformDigest,
	}
}

func (p MutationPlan) ComputePlanSHA256() (string, error) {
	return MutationPlanSHA256(p.ApplyPlan())
}

// ResultArtifactDigest is the canonical requested-target digest carried by
// both succeeded and rolled_back results. PreviousDigest identifies the state
// that was restored when a rollback occurs.
func (p MutationPlan) ResultArtifactDigest() string {
	if p.DeploymentMode == ModeDocker {
		return normalizeDigest(p.ExpectedImageDigest)
	}
	return normalizeDigest(p.ArtifactDigest)
}

type executorMutationFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type MutationStageResult struct {
	Status         string `json:"status"`
	SessionID      string `json:"session_id"`
	PlanSHA256     string `json:"plan_sha256"`
	ArtifactDigest string `json:"artifact_digest"`
}

func (r MutationStageResult) Validate() error {
	if r.Status != "staged" || !mutationSessionPattern.MatchString(r.SessionID) || !mutationPlanHashPattern.MatchString(r.PlanSHA256) || !mutationPlanHashPattern.MatchString(r.ArtifactDigest) {
		return errors.New("remote stage result is invalid")
	}
	return nil
}

type executorMutationOutcome struct {
	Stage      *MutationStageResult     `json:"stage,omitempty"`
	Result     *ApplyResult             `json:"result,omitempty"`
	SessionID  string                   `json:"session_id,omitempty"`
	PlanSHA256 string                   `json:"plan_sha256,omitempty"`
	Error      *executorMutationFailure `json:"error,omitempty"`
}

func (r executorMutationOutcome) Validate() error {
	fields := 0
	if r.Stage != nil {
		fields++
		if err := r.Stage.Validate(); err != nil {
			return err
		}
	}
	if r.Result != nil {
		fields++
		if !mutationSessionPattern.MatchString(r.SessionID) || !mutationPlanHashPattern.MatchString(r.PlanSHA256) {
			return errors.New("executor mutation result binding is invalid")
		}
		if r.Result.Status != "succeeded" && r.Result.Status != "rolled_back" {
			return errors.New("executor mutation result status is invalid")
		}
		if (r.Result.ArtifactDigest != "" && !digestPattern.MatchString(normalizeDigest(r.Result.ArtifactDigest))) ||
			(r.Result.PreviousDigest != "" && !digestPattern.MatchString(normalizeDigest(r.Result.PreviousDigest))) ||
			(r.Result.Message != "" && !safeExecutorMessage(r.Result.Message)) {
			return errors.New("executor mutation result is invalid")
		}
	}
	if r.Error != nil {
		fields++
		if !validExecutorFailureCode(r.Error.Code) || !safeExecutorMessage(r.Error.Message) {
			return errors.New("executor mutation failure is invalid")
		}
	}
	if r.Result == nil && (r.SessionID != "" || r.PlanSHA256 != "") {
		return errors.New("executor mutation result binding is unexpected")
	}
	if fields != 1 {
		return errors.New("executor mutation must contain exactly one outcome")
	}
	return nil
}

func safeExecutorMessage(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > 500 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
