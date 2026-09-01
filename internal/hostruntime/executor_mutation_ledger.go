package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	remoteLedgerSchemaVersion = 1

	remoteLedgerStaged         = "staged"
	remoteLedgerGrantConsuming = "grant_consuming"
	remoteLedgerGrantConsumed  = "consumed_before_mutation"
	remoteLedgerMutating       = "mutating"
	remoteLedgerAmbiguous      = "ambiguous"
	remoteLedgerTerminal       = "terminal"
)

// executorMutationLedger is deliberately secret-free. It is the host-side
// replay fence for a target and survives both a UDS disconnect and an executor
// process crash. Any non-terminal record is treated as ambiguous and may only
// be settled by reconcile.
type executorMutationLedger struct {
	SchemaVersion   int                  `json:"schema_version"`
	JobID           string               `json:"job_id"`
	TargetID        string               `json:"target_id"`
	PlanSHA256      string               `json:"plan_sha256"`
	SessionID       string               `json:"session_id"`
	LeaseGeneration uint64               `json:"lease_generation"`
	Intent          remoteMutationIntent `json:"intent"`
	Operation       string               `json:"operation"`
	State           string               `json:"state"`
	UpdatedAt       time.Time            `json:"updated_at"`
	Stage           *remoteStage         `json:"stage,omitempty"`
	Result          *ApplyResult         `json:"result,omitempty"`
}

type remoteStage struct {
	RootDir                string                  `json:"root_dir"`
	ArtifactDigest         string                  `json:"artifact_digest"`
	ExpectedVersion        string                  `json:"expected_version,omitempty"`
	ExpectedImageDigest    string                  `json:"expected_image_digest,omitempty"`
	ExpectedPlatformDigest string                  `json:"expected_platform_digest,omitempty"`
	ImageID                string                  `json:"image_id,omitempty"`
	NewRelease             string                  `json:"new_release,omitempty"`
	PreviousRelease        string                  `json:"previous_release,omitempty"`
	PreviousDigest         string                  `json:"previous_digest,omitempty"`
	PreviousVersion        string                  `json:"previous_version,omitempty"`
	DockerBaseline         *dockerMutationBaseline `json:"docker_baseline,omitempty"`
}

type remoteMutationIntent struct {
	HostID                 string `json:"host_id"`
	TargetID               string `json:"target_id"`
	ServiceType            string `json:"service_type"`
	DeploymentMode         string `json:"deployment_mode"`
	CurrentVersion         string `json:"current_version"`
	ConfigSHA256           string `json:"config_sha256"`
	TargetVersion          string `json:"target_version"`
	ArtifactDigest         string `json:"artifact_digest"`
	ExpectedVersion        string `json:"expected_version,omitempty"`
	ExpectedImageDigest    string `json:"expected_image_digest,omitempty"`
	ExpectedPlatformDigest string `json:"expected_platform_digest,omitempty"`
}

func newRemoteMutationIntent(plan MutationPlan) remoteMutationIntent {
	return remoteMutationIntent{
		HostID: plan.HostID, TargetID: plan.TargetID, ServiceType: plan.ServiceType,
		DeploymentMode: plan.DeploymentMode, CurrentVersion: plan.CurrentVersion, ConfigSHA256: plan.ConfigSHA256,
		TargetVersion: plan.TargetVersion, ArtifactDigest: normalizeDigest(plan.ArtifactDigest),
		ExpectedVersion: plan.ExpectedVersion, ExpectedImageDigest: normalizeDigest(plan.ExpectedImageDigest),
		ExpectedPlatformDigest: normalizeDigest(plan.ExpectedPlatformDigest),
	}
}

func (i remoteMutationIntent) matches(plan MutationPlan) bool {
	return i == newRemoteMutationIntent(plan)
}

func remoteLedgerPath(cfg HelperConfig, targetID string) string {
	return filepath.Join(cfg.StateDir, "ledger", "target-"+remoteStableKey(targetID)+".json")
}

func remoteStableKey(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func loadExecutorMutationLedger(cfg HelperConfig, targetID string) (*executorMutationLedger, error) {
	path := remoteLedgerPath(cfg, targetID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !remotePrivateFileMode(info) || info.Size() <= 0 || info.Size() > 64<<10 || !isRootOwner(info) {
		return nil, errors.New("remote mutation ledger is not a private root-owned regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read remote mutation ledger")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ledger executorMutationLedger
	if err := decoder.Decode(&ledger); err != nil {
		return nil, errors.New("decode remote mutation ledger")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("remote mutation ledger contains trailing data")
	}
	if err := ledger.validate(targetID); err != nil {
		return nil, err
	}
	return &ledger, nil
}

func remotePrivateFileMode(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0
}

func saveExecutorMutationLedger(cfg HelperConfig, ledger executorMutationLedger) error {
	if err := ensureExecutorStateDirectories(cfg); err != nil {
		return err
	}
	ledger.SchemaVersion = remoteLedgerSchemaVersion
	ledger.UpdatedAt = time.Now().UTC()
	if err := ledger.validate(ledger.TargetID); err != nil {
		return err
	}
	payload, err := json.Marshal(ledger)
	if err != nil {
		return errors.New("encode remote mutation ledger")
	}
	return writeAtomicFile(remoteLedgerPath(cfg, ledger.TargetID), append(payload, '\n'), 0o600)
}

func (l executorMutationLedger) validate(targetID string) error {
	if l.SchemaVersion != remoteLedgerSchemaVersion || l.TargetID != targetID || !identifierPattern.MatchString(l.JobID) || !identifierPattern.MatchString(l.TargetID) || !mutationPlanHashPattern.MatchString(l.PlanSHA256) || !mutationSessionPattern.MatchString(l.SessionID) || l.LeaseGeneration == 0 || l.Intent.TargetID != l.TargetID || !versionPattern.MatchString(l.Intent.CurrentVersion) || !digestPattern.MatchString(l.Intent.ConfigSHA256) || normalizeDigest(l.Intent.ConfigSHA256) != l.Intent.ConfigSHA256 || !digestPattern.MatchString(l.Intent.ArtifactDigest) {
		return errors.New("remote mutation ledger identity is invalid")
	}
	if l.Operation != "stage" && l.Operation != "apply" && l.Operation != "reconcile" {
		return errors.New("remote mutation ledger operation is invalid")
	}
	switch l.State {
	case remoteLedgerStaged:
		if l.Operation != "stage" || l.Stage == nil || l.Result != nil {
			return errors.New("staged remote mutation ledger is invalid")
		}
	case remoteLedgerGrantConsuming, remoteLedgerGrantConsumed, remoteLedgerMutating, remoteLedgerAmbiguous:
		if l.Result != nil {
			return errors.New("non-terminal remote mutation ledger contains a result")
		}
	case remoteLedgerTerminal:
		if l.Result == nil || (l.Result.Status != "succeeded" && l.Result.Status != "rolled_back") {
			return errors.New("terminal remote mutation ledger result is invalid")
		}
	default:
		return errors.New("remote mutation ledger state is invalid")
	}
	if l.State != remoteLedgerStaged && l.Stage == nil {
		return errors.New("remote mutation ledger is missing its staged release")
	}
	if l.Stage != nil && (!filepath.IsAbs(l.Stage.RootDir) || !digestPattern.MatchString(normalizeDigest(l.Stage.ArtifactDigest))) {
		return errors.New("remote mutation ledger stage binding is invalid")
	}
	if l.Stage != nil && l.Stage.DockerBaseline != nil {
		if err := l.Stage.DockerBaseline.validate(); err != nil {
			return errors.New("remote mutation ledger Docker baseline is invalid")
		}
	}
	if l.Stage != nil {
		if l.Intent.DeploymentMode == ModeDocker && l.Stage.DockerBaseline == nil {
			return errors.New("remote Docker mutation ledger is missing its rollback baseline")
		}
		if l.Intent.DeploymentMode == ModeSystemd && l.Stage.DockerBaseline != nil {
			return errors.New("remote systemd mutation ledger contains a Docker baseline")
		}
	}
	return nil
}

func ensureExecutorStateDirectories(cfg HelperConfig) error {
	if !filepath.IsAbs(cfg.StateDir) || filepath.Clean(cfg.StateDir) == string(filepath.Separator) {
		return errors.New("executor mutation state directory is invalid")
	}
	for _, dir := range []string{cfg.StateDir, filepath.Join(cfg.StateDir, "ledger"), filepath.Join(cfg.StateDir, "requests"), filepath.Join(cfg.StateDir, "results"), filepath.Join(cfg.StateDir, "stages")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return errors.New("create executor mutation state directory")
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return errors.New("secure executor mutation state directory")
		}
		if runtime.GOOS != "windows" {
			if err := validateSecureRootPath(dir, true); err != nil {
				return errors.New("executor mutation state directory is not root-controlled")
			}
		}
	}
	return nil
}
