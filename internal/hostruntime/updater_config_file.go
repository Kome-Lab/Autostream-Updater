package hostruntime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const updaterConfigInstallGroup = "autostream-updater"

type preparedRenameOutcome uint8

const (
	preparedRenameNotInstalled preparedRenameOutcome = iota
	preparedRenameInstalled
	preparedRenameUncertain
)

// inspectPreparedRenameOutcome distinguishes a failed-before-rename result from
// a rename that took effect (or can no longer be proven either way). Callers
// must preserve the staged configuration whenever the outcome is uncertain.
func inspectPreparedRenameOutcome(
	tempPath, destinationPath string,
	tempInfo os.FileInfo,
) preparedRenameOutcome {
	if destinationInfo, err := os.Lstat(destinationPath); err == nil &&
		tempInfo != nil &&
		destinationInfo.Mode()&os.ModeSymlink == 0 &&
		destinationInfo.Mode().IsRegular() &&
		os.SameFile(destinationInfo, tempInfo) {
		return preparedRenameInstalled
	}
	if currentTempInfo, err := os.Lstat(tempPath); err == nil &&
		tempInfo != nil &&
		currentTempInfo.Mode()&os.ModeSymlink == 0 &&
		currentTempInfo.Mode().IsRegular() &&
		os.SameFile(currentTempInfo, tempInfo) {
		return preparedRenameNotInstalled
	}
	return preparedRenameUncertain
}

// PreparedUpdaterConfig reserves and validates every local resource needed to
// update agent.yaml before a one-time Configure Token is consumed.
type PreparedUpdaterConfig struct {
	path         string
	parent       string
	tempPath     string
	temp         *os.File
	tempInfo     os.FileInfo
	existing     []byte
	existingFile *os.File
	existingInfo os.FileInfo
	existed      bool
	template     updaterConfigTemplate
	installGID   int
	renamePath   func(string, string) error
	committed    bool
}

// PrepareUpdaterConfig validates the root-controlled destination and creates
// the final root:autostream-updater 0640 temporary file before any network
// request can consume the one-time Configure Token.
func PrepareUpdaterConfig(path string) (*PreparedUpdaterConfig, error) {
	return PrepareManagedIdentityConfig(path, updaterConfigInstallGroup)
}

// PrepareManagedIdentityConfig reserves an atomic root-owned 0640 identity
// file for a dedicated service group. The portless Agent persists only its
// four-field identity; policy, endpoints, and transport fencing stay server-owned.
func PrepareManagedIdentityConfig(path, installGroup string) (*PreparedUpdaterConfig, error) {
	installGID, err := updaterConfigInstallGID(installGroup)
	if err != nil {
		return nil, err
	}
	return prepareUpdaterConfig(path, installGID)
}

func prepareUpdaterConfig(path string, installGID int) (*PreparedUpdaterConfig, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("updater config path must be a clean absolute path")
	}
	parent := filepath.Dir(path)
	if err := validateSecureRootPath(parent, true); err != nil {
		return nil, fmt.Errorf("updater config parent: %w", err)
	}

	existing, existingInfo, existingFile, existed, err := openUpdaterConfigSnapshot(path)
	if err != nil {
		return nil, err
	}
	template := updaterConfigTemplate{}
	if existed {
		template, err = prepareUpdaterConfigTemplate(existing)
		if err != nil {
			if existingFile != nil {
				_ = existingFile.Close()
			}
			return nil, err
		}
	}

	temp, err := os.CreateTemp(parent, ".agent.yaml.configure-*")
	if err != nil {
		if existingFile != nil {
			_ = existingFile.Close()
		}
		return nil, errors.New("create updater config temporary file")
	}
	prepared := &PreparedUpdaterConfig{
		path: path, parent: parent, tempPath: temp.Name(), temp: temp,
		existing: existing, existingFile: existingFile, existingInfo: existingInfo, existed: existed,
		template: template, installGID: installGID, renamePath: os.Rename,
	}
	prepared.tempInfo, err = temp.Stat()
	if err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		if existingFile != nil {
			_ = existingFile.Close()
		}
		return nil, errors.New("stat updater config temporary file")
	}
	failed := true
	defer func() {
		if failed {
			prepared.Abort()
		}
	}()
	if err := temp.Chown(0, installGID); err != nil {
		return nil, errors.New("set updater config temporary file ownership")
	}
	if err := temp.Chmod(0o640); err != nil {
		return nil, errors.New("set updater config temporary file mode")
	}
	// Preflight proves the final owner, mode and filesystem durability without
	// duplicating runtime or release credentials into a second pathname.
	if _, err := temp.Write([]byte("# Identity transaction preflight; no credentials.\n")); err != nil {
		return nil, errors.New("write updater config preflight file")
	}
	if err := temp.Sync(); err != nil {
		return nil, errors.New("sync updater config preflight file")
	}
	prepared.tempInfo, err = temp.Stat()
	if err != nil || !prepared.tempInfo.Mode().IsRegular() || prepared.tempInfo.Mode().Perm() != 0o640 || !updaterConfigHasInstallOwner(prepared.tempInfo, installGID) {
		return nil, errors.New("updater config temporary file ownership or mode is unsafe")
	}
	if err := prepared.verifyDestination(); err != nil {
		return nil, err
	}
	if err := syncDirectory(parent); err != nil {
		return nil, errors.New("sync updater config directory during preflight")
	}
	failed = false
	return prepared, nil
}

// Commit installs the four-field managed identity after rechecking that
// neither the destination nor its
// root-controlled parent changed since Prepare.
func (p *PreparedUpdaterConfig) Commit(identity UpdaterConfigureIdentity) error {
	if p == nil || p.temp == nil || p.committed {
		return errors.New("updater config update is not prepared")
	}
	merged, err := p.template.merge(identity)
	if err != nil {
		return err
	}
	if len(merged) == 0 || len(merged) > configMaxBytes {
		return errors.New("merged updater config is empty or too large")
	}
	if err := p.verifyTemporaryFile(); err != nil {
		return err
	}
	if err := p.verifyDestination(); err != nil {
		return err
	}
	if err := p.temp.Truncate(0); err != nil {
		return errors.New("truncate updater config temporary file")
	}
	if _, err := p.temp.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind updater config temporary file")
	}
	if _, err := io.Copy(p.temp, bytes.NewReader(merged)); err != nil {
		return errors.New("write configured updater identity")
	}
	if err := p.temp.Chown(0, p.installGID); err != nil {
		return errors.New("restore updater config temporary file ownership")
	}
	if err := p.temp.Chmod(0o640); err != nil {
		return errors.New("restore updater config temporary file mode")
	}
	if err := p.temp.Sync(); err != nil {
		return errors.New("sync configured updater identity")
	}
	if err := p.verifyTemporaryFile(); err != nil {
		return err
	}
	if err := p.verifyDestination(); err != nil {
		return err
	}
	if p.renamePath == nil {
		return errors.New("updater config update is not prepared")
	}
	if err := p.renamePath(p.tempPath, p.path); err != nil {
		switch inspectPreparedRenameOutcome(p.tempPath, p.path, p.tempInfo) {
		case preparedRenameNotInstalled:
			return fmt.Errorf("install configured updater identity: %w", err)
		case preparedRenameInstalled:
			return p.finishCommittedInstall(fmt.Errorf(
				"configured updater identity was installed but rename reported an error: %w",
				err,
			))
		default:
			return p.finishCommittedInstall(fmt.Errorf(
				"configured updater identity install result is uncertain; inspect %s and %s before retrying: %w",
				p.path,
				p.tempPath,
				err,
			))
		}
	}
	// The final pathname is now authoritative even if the durability fence
	// fails. Abort must never remove a successfully renamed configuration.
	return p.finishCommittedInstall(nil)
}

func (p *PreparedUpdaterConfig) finishCommittedInstall(finalErr error) error {
	p.committed = true
	tempCloseErr := p.temp.Close()
	existingCloseErr := error(nil)
	if p.existingFile != nil {
		existingCloseErr = p.existingFile.Close()
		p.existingFile = nil
	}
	if tempCloseErr != nil || existingCloseErr != nil {
		p.temp = nil
		finalErr = errors.Join(
			finalErr,
			errors.New("configured updater identity installed but close failed"),
		)
	} else {
		p.temp = nil
	}
	if err := syncDirectory(p.parent); err != nil {
		finalErr = errors.Join(
			finalErr,
			errors.New("configured updater identity installed but directory sync failed"),
		)
	}
	return finalErr
}

// Abort best-effort wipes and unlinks the reserved temporary file. It is safe
// to call after either success or failure.
func (p *PreparedUpdaterConfig) Abort() {
	if p == nil || p.committed {
		return
	}
	if p.temp != nil {
		wipeOpenUpdaterConfigFile(p.temp)
		_ = p.temp.Close()
		p.temp = nil
	}
	if p.existingFile != nil {
		_ = p.existingFile.Close()
		p.existingFile = nil
	}
	if info, err := os.Lstat(p.tempPath); err == nil && info.Mode().IsRegular() && p.tempInfo != nil && os.SameFile(info, p.tempInfo) {
		_ = os.Remove(p.tempPath)
		_ = syncDirectory(p.parent)
	}
}

func readUpdaterConfigSnapshot(path string) ([]byte, os.FileInfo, bool, error) {
	data, info, file, existed, err := openUpdaterConfigSnapshot(path)
	if file != nil {
		_ = file.Close()
	}
	return data, info, existed, err
}

func openUpdaterConfigSnapshot(path string) ([]byte, os.FileInfo, *os.File, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("stat updater config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > configMaxBytes {
		return nil, nil, nil, false, errors.New("updater config must be a bounded regular non-symlink file")
	}
	if info.Mode().Perm()&0o007 != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, nil, nil, false, errors.New("updater config must not be writable by group or accessible to other users")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if err := validateRootOwnedFileAndParents(path, openedInfo, "updater config"); err != nil {
		_ = file.Close()
		return nil, nil, nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(file, configMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > configMaxBytes {
		_ = file.Close()
		return nil, nil, nil, false, errors.New("read updater config")
	}
	return data, openedInfo, file, true, nil
}

func (p *PreparedUpdaterConfig) verifyDestination() error {
	if err := validateSecureRootPath(p.parent, true); err != nil {
		return fmt.Errorf("updater config parent changed after preflight: %w", err)
	}
	if !p.existed {
		if _, err := os.Lstat(p.path); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return errors.New("recheck updater config destination")
		}
		return errors.New("updater config destination appeared after preflight")
	}
	current, currentInfo, existed, err := readUpdaterConfigSnapshot(p.path)
	if err != nil || !existed || !os.SameFile(p.existingInfo, currentInfo) || !bytes.Equal(current, p.existing) {
		return errors.New("updater config changed after preflight")
	}
	return nil
}

func (p *PreparedUpdaterConfig) verifyTemporaryFile() error {
	pathInfo, err := os.Lstat(p.tempPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return errors.New("updater config temporary file changed after preflight")
	}
	openedInfo, err := p.temp.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) || !os.SameFile(p.tempInfo, openedInfo) || openedInfo.Mode().Perm() != 0o640 || !updaterConfigHasInstallOwner(openedInfo, p.installGID) {
		return errors.New("updater config temporary file changed after preflight")
	}
	return nil
}

func wipeOpenUpdaterConfigFile(file *os.File) {
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > configMaxBytes {
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return
	}
	zeroes := make([]byte, 32*1024)
	remaining := info.Size()
	for remaining > 0 {
		chunk := int64(len(zeroes))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := file.Write(zeroes[:int(chunk)]); err != nil {
			return
		}
		remaining -= chunk
	}
	_ = file.Sync()
	_ = file.Truncate(0)
	_ = file.Sync()
}
