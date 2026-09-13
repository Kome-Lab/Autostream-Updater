package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func managedContainerID(ctx context.Context, runner CommandRunner, d *DockerTarget) (string, error) {
	out, err := runner.Run(ctx, d.ProjectDir, dockerCommandEnv(), d.DockerPath, "ps", "-q", "--filter", "label=com.docker.compose.project="+d.ComposeProject, "--filter", "label=com.docker.compose.service="+d.Service)
	lines := strings.Fields(out)
	if err != nil || len(lines) != 1 {
		return "", errors.New("expected exactly one managed Docker container")
	}
	return lines[0], nil
}

func readVersionEnv(path string) ([]byte, os.FileMode, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0o600, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, 0, false, errors.New("version_env_file must be a small regular file")
	}
	data, err := os.ReadFile(path)
	return data, info.Mode().Perm(), true, err
}

func updateVersionEnv(original []byte, name, value string) ([]byte, error) {
	parts := strings.Split(value, "@")
	if name != "AUTOSTREAM_DOCKER_VERSION" || len(parts) != 2 || !versionPattern.MatchString(parts[0]) || !digestPattern.MatchString(parts[1]) {
		return nil, errors.New("version env update is invalid")
	}
	lines := strings.Split(strings.ReplaceAll(string(original), "\r\n", "\n"), "\n")
	found := 0
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), name+"=") {
			found++
			lines[i] = name + "=" + value
		}
	}
	if found > 1 {
		return nil, errors.New("version_env_file contains duplicate version assignments")
	}
	if found == 0 {
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		lines = append(lines, name+"="+value)
	}
	return []byte(strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"), nil
}

func parseVersionEnvPin(data []byte, name string) (string, string, error) {
	found := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, name+"=") {
			if found != "" {
				return "", "", errors.New("version_env_file contains duplicate version assignments")
			}
			found = strings.TrimPrefix(line, name+"=")
		}
	}
	parts := strings.Split(found, "@")
	if len(parts) != 2 || !versionPattern.MatchString(parts[0]) || !digestPattern.MatchString(parts[1]) {
		return "", "", errors.New("version_env_file must contain a canonical bundle@sha256 pin")
	}
	return parts[0], parts[1], nil
}

func repositoryDigest(rawJSON, imageRepo string) (string, error) {
	var values []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(rawJSON)), &values); err != nil {
		return "", errors.New("image RepoDigests output is invalid")
	}
	for _, value := range values {
		parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "@")
		if len(parts) == 2 && strings.EqualFold(parts[0], imageRepo) && digestPattern.MatchString(parts[1]) {
			return parts[1], nil
		}
	}
	return "", errors.New("current image does not have a digest for the fixed image repository")
}

func repositoryHasDigest(rawJSON, imageRepo, expectedDigest string) bool {
	if !digestPattern.MatchString(strings.ToLower(strings.TrimSpace(expectedDigest))) {
		return false
	}
	var values []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(rawJSON)), &values); err != nil {
		return false
	}
	wantRepo := strings.ToLower(strings.TrimSpace(imageRepo))
	wantDigest := strings.ToLower(strings.TrimSpace(expectedDigest))
	for _, value := range values {
		parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "@")
		if len(parts) == 2 && parts[0] == wantRepo && parts[1] == wantDigest {
			return true
		}
	}
	return false
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".autostream-updater-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := firstError(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func restoreVersionEnv(path string, original []byte, mode os.FileMode, existed bool) error {
	if existed {
		return writeAtomicFile(path, original, mode)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
