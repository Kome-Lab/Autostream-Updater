package hostruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

func marshalRuntimeCredentialIdentity(identity Config) ([]byte, error) {
	return marshalManagedBootstrapConfig(identity)
}

func decodeRuntimeCredentialIdentity(data []byte) (Config, error) {
	return decodeManagedBootstrapConfig(data)
}

func runtimeCredentialDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func runtimeCredentialTokenDigest(token string) string {
	return runtimeCredentialDigest([]byte(token))
}

func (rt runtimeCredentialExecutorRuntime) secureMode(
	actual os.FileMode,
	expected os.FileMode,
) bool {
	// Windows does not faithfully round-trip Unix permission bits. Production
	// execution always uses the fixed Linux paths, so only explicit test roots
	// may skip that platform-inapplicable assertion.
	return actual.Perm() == expected ||
		(rt.allowTestPaths && !snapshotModeEnforced())
}

func (rt runtimeCredentialExecutorRuntime) validateIdentityDirectory(
	agentGID uint32,
) error {
	info, err := os.Lstat(rt.identityDir)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		!rt.secureMode(info.Mode(), 0o750) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, agentGID)) {
		return errors.New(
			"Host Agent identity directory must be root:agent-group 0750",
		)
	}
	return nil
}

func (rt runtimeCredentialExecutorRuntime) loadIdentity(
	path string,
	agentGID uint32,
) (Config, []byte, os.FileInfo, error) {
	if err := rt.validateIdentityDirectory(agentGID); err != nil {
		return Config{}, nil, nil, err
	}
	info, err := os.Lstat(path)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!rt.secureMode(info.Mode(), 0o640) ||
		info.Size() <= 0 ||
		info.Size() > configMaxBytes ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, agentGID)) {
		return Config{}, nil, nil, errors.New(
			"Host Agent identity must be a bounded root:agent-group 0640 regular file",
		)
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil {
		return Config{}, nil, nil, err
	}
	defer file.Close()
	if (!rt.allowTestPaths &&
		!runtimeCredentialOwnedBy(openedInfo, 0, agentGID)) ||
		!rt.secureMode(openedInfo.Mode(), 0o640) {
		return Config{}, nil, nil, errors.New(
			"Host Agent identity owner or mode changed during secure open",
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, configMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > configMaxBytes {
		return Config{}, nil, nil, errors.New("read Host Agent identity")
	}
	identity, err := decodeRuntimeCredentialIdentity(data)
	if err != nil {
		return Config{}, nil, nil, err
	}
	return identity, data, openedInfo, nil
}

func (rt runtimeCredentialExecutorRuntime) writeIdentityAtomic(
	path string,
	data []byte,
	agentGID uint32,
	replace bool,
) error {
	if err := rt.validateIdentityDirectory(agentGID); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > configMaxBytes {
		return errors.New("runtime credential identity payload is invalid")
	}
	if existing, err := os.Lstat(path); err == nil {
		if !replace {
			return errRuntimeCredentialBusy
		}
		if existing.Mode()&os.ModeSymlink != 0 ||
			!existing.Mode().IsRegular() ||
			!rt.secureMode(existing.Mode(), 0o640) ||
			(!rt.allowTestPaths &&
				!runtimeCredentialOwnedBy(existing, 0, agentGID)) {
			return errors.New("existing Host Agent identity is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("stat Host Agent identity destination")
	}
	temp, err := os.CreateTemp(rt.identityDir, ".identity.runtime-*")
	if err != nil {
		return errRuntimeCredentialStateUnavailable
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if !rt.allowTestPaths {
		if err := temp.Chown(0, int(agentGID)); err != nil {
			_ = temp.Close()
			return errRuntimeCredentialStateUnavailable
		}
	}
	if err := temp.Chmod(0o640); err != nil {
		_ = temp.Close()
		return errRuntimeCredentialStateUnavailable
	}
	if _, err := temp.Write(data); err != nil ||
		temp.Sync() != nil {
		_ = temp.Close()
		return errRuntimeCredentialStateUnavailable
	}
	tempInfo, err := temp.Stat()
	if err != nil ||
		!rt.secureMode(tempInfo.Mode(), 0o640) ||
		(!rt.allowTestPaths &&
			!runtimeCredentialOwnedBy(tempInfo, 0, agentGID)) {
		_ = temp.Close()
		return errors.New("runtime credential temporary identity is unsafe")
	}
	if err := temp.Close(); err != nil {
		return errRuntimeCredentialStateUnavailable
	}
	if err := rt.validateIdentityDirectory(agentGID); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		switch inspectPreparedRenameOutcome(tempPath, path, tempInfo) {
		case preparedRenameInstalled:
			if syncErr := syncDirectory(rt.identityDir); syncErr != nil {
				return errors.Join(err, syncErr)
			}
			return fmt.Errorf(
				"runtime credential identity installed but rename reported an error: %w",
				err,
			)
		case preparedRenameNotInstalled:
			return fmt.Errorf("install runtime credential identity: %w", err)
		default:
			return fmt.Errorf(
				"runtime credential identity install result is uncertain: %w",
				err,
			)
		}
	}
	return syncDirectory(rt.identityDir)
}
