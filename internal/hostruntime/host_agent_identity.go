package hostruntime

import (
	"errors"
	"os"
	"path/filepath"
)

const (
	HostAgentIdentityDir        = "/etc/autostream/updater"
	HostAgentIdentityPath       = "/etc/autostream/updater/agent.yaml"
	HostAgentStagedIdentityPath = "/etc/autostream/updater/agent.staged.yaml"
	HostAgentWipingIdentityPath = "/etc/autostream/updater/.agent.staged.wipe"
)

func LoadHostAgentIdentity(path string, requireRootOwned bool) (Config, error) {
	return LoadManagedBootstrapConfig(path, requireRootOwned)
}

func validateHostAgentIdentityWriteLayout(
	identityPath string,
	lstat func(string) (os.FileInfo, error),
) error {
	if lstat == nil || !filepath.IsAbs(identityPath) ||
		filepath.Clean(identityPath) != identityPath ||
		filepath.Dir(identityPath) == identityPath {
		return errors.New("Host Agent identity layout verifier is unavailable")
	}
	// Validate every directory before looking at the optional destination. A
	// missing identity is valid during configure, but a missing or replaceable
	// parent is never safe. The injected stat seam also supports isolated roots.
	for directory := filepath.Dir(identityPath); ; directory = filepath.Dir(directory) {
		info, err := lstat(directory)
		if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 ||
			!info.IsDir() || !isRootOwner(info) || info.Mode().Perm()&0o022 != 0 {
			return errors.New("Host Agent identity parents must be root-owned non-symlink directories without group or other write access")
		}
		if filepath.Dir(directory) == directory {
			break
		}
	}
	info, err := lstat(identityPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info == nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || !isRootOwner(info) ||
		info.Mode().Perm() != 0o600 && info.Mode().Perm() != 0o640 {
		return errors.New("Host Agent identity must be a root-owned non-symlink 0600 or 0640 regular file")
	}
	return nil
}
