package hostruntime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const localExecutorDockerConfigDir = "/etc/autostream-local-executor/docker"

func securePrivilegedTarget(target Target) (Target, error) {
	if runtime.GOOS == "windows" {
		return target, nil
	}
	if len(target.BackupArgv) > 0 {
		resolved, err := resolveSecureExecutable(target.BackupArgv[0])
		if err != nil {
			return Target{}, fmt.Errorf("backup executable: %w", err)
		}
		target.BackupArgv[0] = resolved
	}
	if target.DeploymentMode == ModeSystemd {
		// Runtime validation must never create a production release path. The
		// installer/bootstrap owns directory creation; stage/apply/reconcile only
		// accept an existing root-controlled directory.
		if err := validateSecureRootPath(target.Systemd.ReleaseRoot, true); err != nil {
			return Target{}, fmt.Errorf("release_root: %w", err)
		}
		var err error
		target.Systemd.SystemctlPath, err = resolveSecureExecutable(target.Systemd.SystemctlPath)
		if err != nil {
			return Target{}, fmt.Errorf("systemctl executable: %w", err)
		}
		target.Systemd.RunuserPath, err = resolveSecureExecutable(target.Systemd.RunuserPath)
		if err != nil {
			return Target{}, fmt.Errorf("runuser executable: %w", err)
		}
		if err := validateSecureRootPath(filepath.Dir(target.Systemd.CurrentLink), true); err != nil {
			return Target{}, fmt.Errorf("current_link parent: %w", err)
		}
		if info, err := os.Lstat(target.Systemd.CurrentLink); err == nil {
			if info.Mode()&os.ModeSymlink == 0 || !isRootOwner(info) {
				return Target{}, errors.New("current_link must be a root-owned symlink")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return Target{}, err
		}
	} else {
		var err error
		target.Docker.DockerPath, err = resolveSecureExecutable(target.Docker.DockerPath)
		if err != nil {
			return Target{}, fmt.Errorf("docker executable: %w", err)
		}
		for _, path := range append([]string{target.Docker.ProjectDir}, target.Docker.ComposeFiles...) {
			if err := validateSecureRootPath(path, filepath.Clean(path) == filepath.Clean(target.Docker.ProjectDir)); err != nil {
				return Target{}, fmt.Errorf("privileged Docker path %q: %w", path, err)
			}
		}
		if target.Docker.BaseEnvFile != "" {
			if err := validateSecureRootPath(target.Docker.BaseEnvFile, false); err != nil {
				return Target{}, fmt.Errorf("base_env_file: %w", err)
			}
		}
		if err := validateOptionalSecureRootFile(target.Docker.VersionEnvFile); err != nil {
			return Target{}, fmt.Errorf("version_env_file: %w", err)
		}
		if err := validateRootDockerCredentials(); err != nil {
			return Target{}, fmt.Errorf("root Docker credentials: %w", err)
		}
	}
	return target, nil
}

func validateRootDockerCredentials() error {
	info, err := os.Lstat(localExecutorDockerConfigDir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("/etc/autostream-local-executor/docker/config.json is required for deterministic GHCR authentication")
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("/etc/autostream-local-executor/docker must be a root-owned 0700 non-symlink directory")
	}
	if err := validateSecureRootPath(localExecutorDockerConfigDir, true); err != nil {
		return err
	}
	configPath := filepath.Join(localExecutorDockerConfigDir, "config.json")
	configInfo, err := os.Lstat(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("/etc/autostream-local-executor/docker/config.json is required for deterministic GHCR authentication")
	}
	if err != nil || configInfo.Mode()&os.ModeSymlink != 0 ||
		!configInfo.Mode().IsRegular() || configInfo.Mode().Perm() != 0o600 {
		return errors.New("/etc/autostream-local-executor/docker/config.json must be a root-owned 0600 regular non-symlink file")
	}
	return validateSecureRootPath(configPath, false)
}

func validateOptionalSecureRootFile(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return validateSecureRootPath(filepath.Dir(path), true)
	} else if err != nil {
		return err
	}
	return validateSecureRootPath(path, false)
}

func resolveSecureExecutable(command string) (string, error) {
	resolved, err := filepath.EvalSymlinks(command)
	if err != nil {
		return "", fmt.Errorf("%q is unavailable", command)
	}
	if err := validateSecureRootPath(resolved, false); err != nil {
		return "", fmt.Errorf("%q: %w", command, err)
	}
	return resolved, nil
}

// validateSecureRootPath rejects operator inputs that a non-root user could
// replace between validation and privileged execution. Symlinks are rejected
// for data paths; executable symlinks are resolved by the caller first.
func validateSecureRootPath(path string, wantDir bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("path is not absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlinks are not allowed")
	}
	if wantDir && !info.IsDir() {
		return errors.New("expected a directory")
	}
	if !wantDir && !info.Mode().IsRegular() {
		return errors.New("expected a regular file")
	}
	if !isRootOwner(info) || info.Mode().Perm()&0o022 != 0 {
		return errors.New("must be root-owned and not writable by group or other users")
	}
	parent := filepath.Dir(filepath.Clean(path))
	for parent != filepath.Dir(parent) {
		parentInfo, err := os.Lstat(parent)
		if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || !isRootOwner(parentInfo) || parentInfo.Mode().Perm()&0o022 != 0 {
			return errors.New("parent directories must be root-owned, non-symlink directories not writable by group or other users")
		}
		parent = filepath.Dir(parent)
	}
	return nil
}
