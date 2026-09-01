package hostruntime

import (
	"errors"
	"os"
	"path"
)

const (
	HostAgentIdentityDir        = "/etc/autostream-host-agent"
	HostAgentIdentityPath       = "/etc/autostream-host-agent/identity.json"
	HostAgentStagedIdentityPath = "/etc/autostream-host-agent/identity.staged.json"
	HostAgentWipingIdentityPath = "/etc/autostream-host-agent/.identity.staged.wipe"
	LegacyHostAgentIdentityPath = "/etc/autostream/host-agent.json"
)

type hostAgentIdentityDependencies struct {
	load  func(string, bool) (Config, error)
	lstat func(string) (os.FileInfo, error)
}

// LoadHostAgentIdentity keeps one read-only bridge for hosts installed before
// the dedicated identity directory existed. New writes and runtime rotations
// always target HostAgentIdentityPath.
func LoadHostAgentIdentity(path string, requireRootOwned bool) (Config, error) {
	return loadHostAgentIdentity(
		path,
		requireRootOwned,
		hostAgentIdentityDependencies{
			load:  LoadManagedBootstrapConfig,
			lstat: os.Lstat,
		},
	)
}

func loadHostAgentIdentity(
	identityPath string,
	requireRootOwned bool,
	dependencies hostAgentIdentityDependencies,
) (Config, error) {
	if dependencies.load == nil || dependencies.lstat == nil {
		return Config{}, errors.New("Host Agent identity dependencies are incomplete")
	}
	if !path.IsAbs(identityPath) || path.Clean(identityPath) != identityPath {
		return Config{}, errors.New("Host Agent identity path must be a clean absolute path")
	}
	if identityPath != HostAgentIdentityPath {
		return dependencies.load(identityPath, requireRootOwned)
	}

	current, currentErr := dependencies.load(
		HostAgentIdentityPath,
		requireRootOwned,
	)
	if currentErr == nil {
		_, legacyErr := dependencies.lstat(LegacyHostAgentIdentityPath)
		switch {
		case legacyErr == nil:
			return Config{}, errors.New(
				"both current and legacy Host Agent identities exist; remove the legacy secret through the managed migration",
			)
		case errors.Is(legacyErr, os.ErrNotExist):
			return current, nil
		case errors.Is(legacyErr, os.ErrPermission):
			// Existing application services deliberately keep /etc/autostream
			// root-only. Once the canonical identity has been securely loaded,
			// an unreachable legacy path cannot influence this non-root runtime.
			// Root-owned install and configure transactions still require the
			// legacy identity to be absent before they mutate managed state.
			return current, nil
		default:
			return Config{}, errors.New("stat legacy Host Agent identity")
		}
	}
	if !errors.Is(currentErr, os.ErrNotExist) {
		return Config{}, currentErr
	}

	_, legacyErr := dependencies.lstat(LegacyHostAgentIdentityPath)
	if legacyErr == nil {
		return dependencies.load(
			LegacyHostAgentIdentityPath,
			requireRootOwned,
		)
	}
	if !errors.Is(legacyErr, os.ErrNotExist) {
		return Config{}, errors.New("stat legacy Host Agent identity")
	}
	return Config{}, &os.PathError{
		Op: "stat", Path: HostAgentIdentityPath, Err: os.ErrNotExist,
	}
}

// validateHostAgentIdentityWriteLayout is called only from root-owned
// configuration lifecycle operations. Runtime may accept an inaccessible
// legacy parent after securely loading the canonical identity, but writers
// must prove that the legacy identity is absent before changing durable state.
func validateHostAgentIdentityWriteLayout(
	identityPath string,
	lstat func(string) (os.FileInfo, error),
) error {
	if identityPath != HostAgentIdentityPath {
		return nil
	}
	if lstat == nil {
		return errors.New("Host Agent identity layout verifier is unavailable")
	}
	_, err := lstat(LegacyHostAgentIdentityPath)
	if err == nil {
		return errors.New(
			"legacy Host Agent identity already exists; remove it through the managed migration",
		)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.New("stat legacy Host Agent identity")
}
