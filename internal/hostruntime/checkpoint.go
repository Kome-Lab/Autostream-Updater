package hostruntime

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const checkpointSchemaVersion = 1

type updateCheckpoint struct {
	SchemaVersion          int         `json:"schema_version"`
	JobID                  string      `json:"job_id"`
	TargetID               string      `json:"target_id"`
	DeploymentMode         string      `json:"deployment_mode"`
	Phase                  string      `json:"phase"`
	TargetVersion          string      `json:"target_version"`
	TargetDigest           string      `json:"target_digest,omitempty"`
	TargetPlatform         string      `json:"target_platform_digest,omitempty"`
	TargetSourceVersion    string      `json:"target_source_version,omitempty"`
	NewRelease             string      `json:"new_release,omitempty"`
	PreviousRelease        string      `json:"previous_release,omitempty"`
	PreviousDigest         string      `json:"previous_digest,omitempty"`
	PreviousVersion        string      `json:"previous_version,omitempty"`
	PreviousImageID        string      `json:"previous_image_id,omitempty"`
	PreviousRepoDigest     string      `json:"previous_repo_digest,omitempty"`
	PreviousBundleVersion  string      `json:"previous_bundle_version,omitempty"`
	PreviousManifestDigest string      `json:"previous_manifest_digest,omitempty"`
	VersionEnvExisted      bool        `json:"version_env_existed,omitempty"`
	VersionEnvMode         os.FileMode `json:"version_env_mode,omitempty"`
	PreviousVersionEnv     []byte      `json:"previous_version_env,omitempty"`
}

func checkpointPath(target Target) string {
	if target.DeploymentMode == ModeSystemd {
		return filepath.Join(target.Systemd.ReleaseRoot, ".autostream-updater-"+shortID(target.Systemd.Unit)+".checkpoint.json")
	}
	if matchesLocalExecutorDockerProfile(target.ServiceType, target.Docker) {
		key := target.TargetID + "\x00" + target.Docker.Service
		return filepath.Join(LocalExecutorMutationStateDir, ".autostream-updater-"+shortID(key)+".checkpoint.json")
	}
	return filepath.Join(target.Docker.ProjectDir, ".autostream-updater-"+shortID(filepath.Clean(target.Docker.ProjectDir)+"\x00"+target.Docker.ComposeProject)+".checkpoint.json")
}

func saveCheckpoint(target Target, checkpoint updateCheckpoint) error {
	checkpoint.SchemaVersion = checkpointSchemaVersion
	payload, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	return writeAtomicFile(checkpointPath(target), append(payload, '\n'), 0o600)
}

func loadCheckpoint(target Target) (*updateCheckpoint, error) {
	path := checkpointPath(target)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 1<<20 || !isRootOwner(info) {
		return nil, errors.New("update checkpoint is not a private regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	var checkpoint updateCheckpoint
	if err := decoder.Decode(&checkpoint); err != nil || checkpoint.SchemaVersion != checkpointSchemaVersion || !identifierPattern.MatchString(checkpoint.JobID) || checkpoint.TargetID != target.TargetID || checkpoint.DeploymentMode != target.DeploymentMode || !versionPattern.MatchString(checkpoint.TargetVersion) {
		return nil, errors.New("update checkpoint is invalid")
	}
	return &checkpoint, nil
}

func clearCheckpoint(target Target) error {
	path := checkpointPath(target)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
