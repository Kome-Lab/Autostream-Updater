package hostruntime

import (
	"errors"
	"io"
	"os"
)

func (rt runtimeCredentialExecutorRuntime) wipeAndRemoveIdentity(
	path string,
	agentGID uint32,
	expectedDigest string,
) error {
	if path != rt.stagedIdentity {
		return errors.New("runtime credential cleanup path is invalid")
	}
	stagedInfo, stagedErr := os.Lstat(rt.stagedIdentity)
	wipingInfo, wipingErr := os.Lstat(rt.wipingIdentity)
	if stagedErr != nil && !errors.Is(stagedErr, os.ErrNotExist) {
		return errors.New("stat staged Host Agent identity for cleanup")
	}
	if wipingErr != nil && !errors.Is(wipingErr, os.ErrNotExist) {
		return errors.New("stat quarantined Host Agent identity for cleanup")
	}
	if stagedErr == nil && wipingErr == nil {
		return errors.New(
			"staged and quarantined Host Agent identities both exist",
		)
	}
	if errors.Is(wipingErr, os.ErrNotExist) {
		if errors.Is(stagedErr, os.ErrNotExist) {
			return nil
		}
		if !rt.secureStagedIdentityInfo(stagedInfo, agentGID, false) {
			return errors.New("staged Host Agent identity is unsafe")
		}
		file, openedInfo, err := openVerifiedConfig(
			rt.stagedIdentity,
			stagedInfo,
		)
		if err != nil ||
			!rt.secureStagedIdentityInfo(openedInfo, agentGID, false) {
			if file != nil {
				_ = file.Close()
			}
			return errors.New(
				"staged Host Agent identity changed before cleanup",
			)
		}
		data, readErr := io.ReadAll(
			io.LimitReader(file, configMaxBytes+1),
		)
		closeErr := file.Close()
		if readErr != nil ||
			closeErr != nil ||
			len(data) == 0 ||
			len(data) > configMaxBytes ||
			runtimeCredentialDigest(data) != expectedDigest {
			return errors.New(
				"staged Host Agent identity digest changed before cleanup",
			)
		}
		if err := os.Rename(
			rt.stagedIdentity,
			rt.wipingIdentity,
		); err != nil {
			return errors.New(
				"quarantine staged Host Agent identity for cleanup",
			)
		}
		if err := syncDirectory(rt.identityDir); err != nil {
			return errors.New(
				"sync Host Agent identity quarantine",
			)
		}
		wipingInfo, wipingErr = os.Lstat(rt.wipingIdentity)
		if wipingErr != nil ||
			!os.SameFile(stagedInfo, wipingInfo) {
			return errors.New(
				"quarantined Host Agent identity changed during cleanup",
			)
		}
	}
	if !rt.secureStagedIdentityInfo(wipingInfo, agentGID, true) {
		return errors.New("quarantined Host Agent identity is unsafe")
	}
	file, err := os.OpenFile(rt.wipingIdentity, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil ||
		!os.SameFile(wipingInfo, openedInfo) ||
		!rt.secureStagedIdentityInfo(openedInfo, agentGID, true) {
		_ = file.Close()
		return errors.New(
			"quarantined Host Agent identity changed before cleanup",
		)
	}
	var wipeErr error
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		wipeErr = errors.Join(wipeErr, errors.New("seek staged Host Agent identity for cleanup"))
	} else {
		zeroes := make([]byte, 32*1024)
		remaining := openedInfo.Size()
		for remaining > 0 {
			chunk := int64(len(zeroes))
			if remaining < chunk {
				chunk = remaining
			}
			if _, err := file.Write(zeroes[:int(chunk)]); err != nil {
				wipeErr = errors.Join(
					wipeErr,
					errors.New("overwrite staged Host Agent identity during cleanup"),
				)
				break
			}
			remaining -= chunk
		}
		if err := file.Sync(); err != nil {
			wipeErr = errors.Join(
				wipeErr,
				errors.New("sync staged Host Agent identity overwrite"),
			)
		}
		if err := file.Truncate(0); err != nil {
			wipeErr = errors.Join(
				wipeErr,
				errors.New("truncate staged Host Agent identity during cleanup"),
			)
		}
		if err := file.Sync(); err != nil {
			wipeErr = errors.Join(
				wipeErr,
				errors.New("sync staged Host Agent identity truncation"),
			)
		}
	}
	if err := file.Close(); err != nil {
		wipeErr = errors.Join(
			wipeErr,
			errors.New("close staged Host Agent identity during cleanup"),
		)
	}
	current, err := os.Lstat(rt.wipingIdentity)
	if err != nil || !os.SameFile(wipingInfo, current) {
		return errors.New(
			"quarantined Host Agent identity changed before unlink",
		)
	}
	if err := os.Remove(rt.wipingIdentity); err != nil {
		return err
	}
	if err := syncDirectory(rt.identityDir); err != nil {
		wipeErr = errors.Join(
			wipeErr,
			errors.New("sync Host Agent identity directory after cleanup"),
		)
	}
	return wipeErr
}

func (rt runtimeCredentialExecutorRuntime) secureStagedIdentityInfo(
	info os.FileInfo,
	agentGID uint32,
	allowEmpty bool,
) bool {
	if info == nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!rt.secureMode(info.Mode(), 0o640) ||
		info.Size() > configMaxBytes ||
		(!allowEmpty && info.Size() <= 0) {
		return false
	}
	return rt.allowTestPaths ||
		runtimeCredentialOwnedBy(info, 0, agentGID)
}

func (rt runtimeCredentialExecutorRuntime) identityCleanupComplete() bool {
	_, stagedErr := os.Lstat(rt.stagedIdentity)
	_, wipingErr := os.Lstat(rt.wipingIdentity)
	return errors.Is(stagedErr, os.ErrNotExist) &&
		errors.Is(wipingErr, os.ErrNotExist)
}
