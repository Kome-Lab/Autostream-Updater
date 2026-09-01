package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	HelperConfigSchemaVersion = 1
	helperConfigMaxBytes      = 1 << 20
)

// HelperConfig is the complete long-lived state installed on a managed host.
// It intentionally contains no Control Panel runtime token, repository token,
// remote credential, or release credential. One-time grants are never
// persisted by this loader.
type HelperConfig struct {
	SchemaVersion int      `json:"schema_version"`
	HostID        string   `json:"host_id"`
	PanelURL      string   `json:"panel_url"`
	Arch          string   `json:"arch"`
	StateDir      string   `json:"state_dir"`
	Targets       []Target `json:"targets"`
}

func LoadHelperConfig(path string, requireRootOwned bool) (HelperConfig, error) {
	if !filepath.IsAbs(path) {
		return HelperConfig{}, errors.New("helper config path must be absolute")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return HelperConfig{}, fmt.Errorf("stat helper config: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Size() <= 0 || pathInfo.Size() > helperConfigMaxBytes {
		return HelperConfig{}, errors.New("helper config must be a bounded regular non-symlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return HelperConfig{}, fmt.Errorf("open helper config: %w", err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) || pathInfo.Size() != openedInfo.Size() || pathInfo.Mode() != openedInfo.Mode() || !pathInfo.ModTime().Equal(openedInfo.ModTime()) || openedInfo.Size() <= 0 || openedInfo.Size() > helperConfigMaxBytes {
		return HelperConfig{}, errors.New("helper config changed during secure open")
	}
	if requireRootOwned {
		if openedInfo.Mode().Perm()&0o007 != 0 || openedInfo.Mode().Perm()&0o022 != 0 {
			return HelperConfig{}, errors.New("helper config must be root-owned, not writable by group, and inaccessible to other users")
		}
		if err := validateRootOwnedFileAndParents(path, openedInfo, "helper config"); err != nil {
			return HelperConfig{}, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, helperConfigMaxBytes+1))
	if err != nil || len(data) > helperConfigMaxBytes {
		return HelperConfig{}, errors.New("read helper config")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg HelperConfig
	if err := decoder.Decode(&cfg); err != nil {
		return HelperConfig{}, errors.New("decode helper config")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return HelperConfig{}, errors.New("helper config contains trailing data")
	}
	if err := cfg.Validate(); err != nil {
		return HelperConfig{}, err
	}
	return cfg, nil
}

// validateRootOwnedFileAndParents ensures an unprivileged process can read a
// root-installed policy or credential but cannot replace either the file or
// any path component between validation and use.
func validateRootOwnedFileAndParents(path string, fileInfo os.FileInfo, label string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if !isRootOwner(fileInfo) {
		return fmt.Errorf("%s must be owned by root", label)
	}
	for directory := filepath.Dir(filepath.Clean(path)); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("stat %s parent: %w", label, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !isRootOwner(info) || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s parent directories must be root-owned, non-symlink, and not writable by group or other users", label)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
	}
	return nil
}

func (c HelperConfig) Validate() error {
	return c.validateForArchitecture(runtime.GOARCH)
}

// validateForArchitecture binds an executor policy to the architecture on
// which it will run. LoadHelperConfig also uses the actual runtime value.
func (c HelperConfig) validateForArchitecture(expectedArch string) error {
	if c.SchemaVersion != HelperConfigSchemaVersion {
		return errors.New("unsupported helper config schema_version")
	}
	if !identifierPattern.MatchString(strings.TrimSpace(c.HostID)) {
		return errors.New("helper host_id is invalid")
	}
	if err := validatePanelURL(strings.TrimSpace(c.PanelURL)); err != nil {
		return err
	}
	if c.Arch != "amd64" && c.Arch != "arm64" {
		return errors.New("helper arch must be amd64 or arm64")
	}
	if (expectedArch == "amd64" || expectedArch == "arm64") && c.Arch != expectedArch {
		return fmt.Errorf("helper arch %q does not match runtime architecture", c.Arch)
	}
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) == string(filepath.Separator) {
		return errors.New("helper state_dir must be a non-root absolute path")
	}
	if len(c.Targets) == 0 {
		return errors.New("helper config requires at least one target")
	}
	seen := make(map[string]bool, len(c.Targets))
	versionFiles := make(map[string]bool)
	for i, target := range c.Targets {
		if target.HostID != c.HostID {
			return fmt.Errorf("targets[%d]: host_id must match helper host_id", i)
		}
		if err := target.Validate(); err != nil {
			return fmt.Errorf("targets[%d]: %w", i, err)
		}
		if seen[target.TargetID] {
			return fmt.Errorf("duplicate target_id %q", target.TargetID)
		}
		seen[target.TargetID] = true
		if docker := target.Docker; docker != nil {
			if docker.ComposeConfigSHA256 == strings.Repeat("0", 64) {
				return fmt.Errorf("targets[%d]: compose_config_sha256 bootstrap sentinel is not allowed at runtime", i)
			}
			path := filepath.Clean(docker.VersionEnvFile)
			if versionFiles[path] {
				return fmt.Errorf("targets[%d]: version_env_file must be unique per Docker target", i)
			}
			versionFiles[path] = true
		}
	}
	return nil
}

func (c HelperConfig) Target(id string) (Target, bool) {
	for _, target := range c.Targets {
		if target.TargetID == id {
			return target, true
		}
	}
	return Target{}, false
}

// SHA256 returns a canonical digest suitable for comparing a central probe
// with the exact root-owned helper policy that was loaded on the host.
func (c HelperConfig) SHA256() (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", errors.New("encode helper config digest")
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
