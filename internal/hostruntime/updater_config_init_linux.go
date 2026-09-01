//go:build linux

package hostruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// InitializeUpdaterConfig installs an explicit root-controlled legacy policy
// only when updater.json is missing. Managed configuration does not use this
// initializer; PrepareUpdaterConfig creates its four-field identity directly.
// Existing operator-owned configuration is never opened or changed here;
// PrepareUpdaterConfig validates it in the next configure phase.
func InitializeUpdaterConfig(path, examplePath string) (bool, error) {
	installGID, err := updaterConfigInstallGID(updaterConfigInstallGroup)
	if err != nil {
		return false, err
	}
	return initializeUpdaterConfig(path, examplePath, installGID)
}

func initializeUpdaterConfig(path, examplePath string, installGID int) (bool, error) {
	return initializeUpdaterConfigWithInstaller(path, examplePath, installGID, installUpdaterConfigNoReplace)
}

func initializeUpdaterConfigWithInstaller(path, examplePath string, installGID int, install func(string, string) error) (bool, error) {
	if install == nil {
		return false, errors.New("updater config installer is unavailable")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false, errors.New("updater config path must be a clean absolute path")
	}
	parent := filepath.Dir(path)
	if err := validateSecureRootPath(parent, true); err != nil {
		return false, fmt.Errorf("updater config parent: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat updater config destination: %w", err)
	}

	example, err := updaterConfigInitializationExample(examplePath)
	if err != nil {
		return false, err
	}
	temp, err := os.CreateTemp(parent, ".updater.json.initialize-*")
	if err != nil {
		return false, errors.New("create updater config initialization file")
	}
	tempPath := temp.Name()
	installed := false
	defer func() {
		if temp == nil {
			return
		}
		if !installed {
			wipeOpenUpdaterConfigFile(temp)
		}
		_ = temp.Close()
		if !installed {
			_ = os.Remove(tempPath)
			_ = syncDirectory(parent)
		}
	}()

	if err := temp.Chown(0, installGID); err != nil {
		return false, errors.New("set initialized updater config ownership")
	}
	if err := temp.Chmod(0o640); err != nil {
		return false, errors.New("set initialized updater config mode")
	}
	if _, err := temp.Write(example); err != nil {
		return false, errors.New("write initialized updater config")
	}
	if err := temp.Sync(); err != nil {
		return false, errors.New("sync initialized updater config")
	}
	tempInfo, err := temp.Stat()
	if err != nil || !tempInfo.Mode().IsRegular() || tempInfo.Mode().Perm() != 0o640 || !updaterConfigHasInstallOwner(tempInfo, installGID) {
		return false, errors.New("initialized updater config ownership or mode is unsafe")
	}
	if err := validateSecureRootPath(parent, true); err != nil {
		return false, fmt.Errorf("updater config parent changed during initialization: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		return false, errors.New("updater config destination appeared during initialization")
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("recheck updater config destination")
	}
	var installErr error
	if err := install(tempPath, path); err != nil {
		destinationInfo, destinationErr := os.Lstat(path)
		if destinationErr == nil && os.SameFile(destinationInfo, tempInfo) {
			installed = true
			installErr = fmt.Errorf("initialized updater config was installed but the no-replace operation reported an error: %w", err)
		} else {
			tempPathInfo, tempPathErr := os.Lstat(tempPath)
			if tempPathErr == nil && os.SameFile(tempPathInfo, tempInfo) {
				if errors.Is(err, unix.EEXIST) {
					return false, fmt.Errorf("updater config destination appeared during initialization: %w", err)
				}
				return false, fmt.Errorf("install initialized updater config without replacing an existing destination: %w", err)
			}
			// The rename outcome cannot be proven. Do not wipe the still-open
			// inode because it may already be the installed configuration.
			installed = true
			installErr = fmt.Errorf("initialized updater config install result is uncertain; inspect %s and %s before retrying: %w", path, tempPath, err)
		}
	} else {
		installed = true
	}
	pathInfo, err := os.Lstat(path)
	finalErr := installErr
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(pathInfo, tempInfo) || pathInfo.Mode().Perm() != 0o640 || !updaterConfigHasInstallOwner(pathInfo, installGID) {
		finalErr = errors.Join(finalErr, errors.New("initialized updater config installed but final identity is unsafe"))
	}
	if closeErr := temp.Close(); closeErr != nil {
		finalErr = errors.Join(finalErr, errors.New("initialized updater config installed but close failed"))
	}
	temp = nil
	if err := syncDirectory(parent); err != nil {
		finalErr = errors.Join(finalErr, errors.New("initialized updater config installed but directory sync failed"))
	}
	if finalErr != nil {
		return true, finalErr
	}
	return true, nil
}

func installUpdaterConfigNoReplace(tempPath, path string) error {
	return unix.Renameat2(unix.AT_FDCWD, tempPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
}

func updaterConfigInitializationExample(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("explicit updater config example path is required")
	}
	return readUpdaterConfigInitializationExample(path)
}

func readUpdaterConfigInitializationExample(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("updater config example path must be a clean absolute path")
	}
	resolved, err := resolveRootControlledExamplePath(path)
	if err != nil {
		return nil, err
	}
	if err := validateSecureRootPath(resolved, false); err != nil {
		return nil, fmt.Errorf("updater config example must be root-owned and not writable by group or other users: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > configMaxBytes {
		return nil, errors.New("updater config example must be a bounded regular file")
	}
	file, _, err := openVerifiedConfig(resolved, info)
	if err != nil {
		return nil, errors.New("open updater config example")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, configMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > configMaxBytes {
		return nil, errors.New("read updater config example")
	}
	return validateUpdaterConfigInitializationExample(data)
}

func validateUpdaterConfigInitializationExample(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > configMaxBytes {
		return nil, errors.New("updater config example must be non-empty and bounded")
	}
	template, err := prepareUpdaterConfigTemplate(data)
	if err != nil {
		return nil, fmt.Errorf("decode updater config example: %w", err)
	}
	var githubToken string
	githubTokenJSON, ok := template.fields["github_token"]
	if !ok || json.Unmarshal(githubTokenJSON, &githubToken) != nil || strings.TrimSpace(githubToken) != "" {
		return nil, errors.New("updater config example github_token must be empty so local policy validation fails closed")
	}
	return data, nil
}

func resolveRootControlledExamplePath(path string) (string, error) {
	remaining := splitAbsolutePath(path)
	current := string(filepath.Separator)
	for followedLinks := 0; len(remaining) > 0; {
		part := remaining[0]
		remaining = remaining[1:]
		candidate := filepath.Join(current, part)
		info, err := os.Lstat(candidate)
		if err != nil {
			return "", fmt.Errorf("stat updater config example path: %w", err)
		}
		isSymlink := info.Mode()&os.ModeSymlink != 0
		// Linux reports symlinks as 0777 because their permission bits are not
		// used for access control. A root-owned link below protected parents is
		// safe to resolve; the resolved target is validated separately below.
		if !isRootOwner(info) || (!isSymlink && info.Mode().Perm()&0o022 != 0) {
			return "", errors.New("updater config example path must be root-owned and not writable by group or other users")
		}
		if isSymlink {
			followedLinks++
			if followedLinks > 40 {
				return "", errors.New("updater config example has too many symlink hops")
			}
			target, err := os.Readlink(candidate)
			if err != nil {
				return "", fmt.Errorf("read updater config example symlink: %w", err)
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(current, target)
			}
			if len(remaining) > 0 {
				target = filepath.Join(target, filepath.Join(remaining...))
			}
			target = filepath.Clean(target)
			if !filepath.IsAbs(target) {
				return "", errors.New("updater config example symlink target must resolve to an absolute path")
			}
			remaining = splitAbsolutePath(target)
			current = string(filepath.Separator)
			continue
		}
		if len(remaining) > 0 && !info.IsDir() {
			return "", errors.New("updater config example parent must be a directory or root-owned symlink")
		}
		current = candidate
	}
	return current, nil
}

func splitAbsolutePath(path string) []string {
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
