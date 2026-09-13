package hostruntime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type preparedLocalExecutorPolicy struct {
	path          string
	parent        string
	tempPath      string
	temp          *os.File
	tempInfo      os.FileInfo
	existing      []byte
	existingInfo  os.FileInfo
	existed       bool
	renamePath    func(string, string) error
	committed     bool
	committedInfo os.FileInfo
}

func prepareLocalExecutorPolicy(path string) (*preparedLocalExecutorPolicy, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Local Executor policy path must be a clean absolute path")
	}
	if _, err := updaterConfigInstallGID("root"); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	if err := validateSecureRootPath(parent, true); err != nil {
		return nil, fmt.Errorf("Local Executor policy parent: %w", err)
	}
	existing, existingInfo, existed, err := readRootPolicySnapshotOptional(path)
	if err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(parent, ".executor-policy.json.configure-*")
	if err != nil {
		return nil, errors.New("create Local Executor policy temporary file")
	}
	prepared := &preparedLocalExecutorPolicy{
		path: path, parent: parent, tempPath: temp.Name(), temp: temp,
		existing: existing, existingInfo: existingInfo, existed: existed,
		renamePath: os.Rename,
	}
	failed := true
	defer func() {
		if failed {
			prepared.Abort()
		}
	}()
	if err := temp.Chown(0, 0); err != nil {
		return nil, errors.New("set Local Executor policy temporary file ownership")
	}
	if err := temp.Chmod(0o600); err != nil {
		return nil, errors.New("set Local Executor policy temporary file mode")
	}
	if _, err := temp.Write([]byte("{}")); err != nil {
		return nil, errors.New("write Local Executor policy preflight file")
	}
	if err := temp.Sync(); err != nil {
		return nil, errors.New("sync Local Executor policy preflight file")
	}
	prepared.tempInfo, err = temp.Stat()
	if err != nil || !prepared.tempInfo.Mode().IsRegular() ||
		prepared.tempInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(prepared.tempInfo, 0) {
		return nil, errors.New("Local Executor policy temporary file ownership or mode is unsafe")
	}
	if err := prepared.verifyDestination(); err != nil {
		return nil, err
	}
	if err := syncDirectory(parent); err != nil {
		return nil, errors.New("sync Local Executor policy directory during preflight")
	}
	failed = false
	return prepared, nil
}

func (p *preparedLocalExecutorPolicy) Commit(projection ConfigurePolicyProjection) error {
	if p == nil || p.temp == nil || p.committed {
		return errors.New("Local Executor policy update is not prepared")
	}
	if err := ValidateConfigurePolicyActivation(
		projection.Policy,
		projection.SHA256,
		projection.SourcePolicyRevision,
		projection.ProjectionRevision,
		projection.PolicyRevision,
	); err != nil {
		return err
	}
	if err := p.verifyTemporaryFile(); err != nil {
		return err
	}
	if err := p.verifyDestination(); err != nil {
		return err
	}
	if err := p.temp.Truncate(0); err != nil {
		return errors.New("truncate Local Executor policy temporary file")
	}
	if _, err := p.temp.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind Local Executor policy temporary file")
	}
	if _, err := io.Copy(p.temp, bytes.NewReader(projection.Policy)); err != nil {
		return errors.New("write canonical Local Executor policy")
	}
	if err := p.temp.Chown(0, 0); err != nil {
		return errors.New("restore Local Executor policy temporary file ownership")
	}
	if err := p.temp.Chmod(0o600); err != nil {
		return errors.New("restore Local Executor policy temporary file mode")
	}
	if err := p.temp.Sync(); err != nil {
		return errors.New("sync canonical Local Executor policy")
	}
	if err := p.verifyTemporaryFile(); err != nil {
		return err
	}
	if err := p.verifyDestination(); err != nil {
		return err
	}
	if p.renamePath == nil {
		return errors.New("Local Executor policy update is not prepared")
	}
	if err := p.renamePath(p.tempPath, p.path); err != nil {
		switch inspectPreparedRenameOutcome(p.tempPath, p.path, p.tempInfo) {
		case preparedRenameNotInstalled:
			return fmt.Errorf("install canonical Local Executor policy: %w", err)
		case preparedRenameInstalled:
			return p.finishCommittedInstall(
				p.tempInfo,
				fmt.Errorf(
					"canonical Local Executor policy was installed but rename reported an error: %w",
					err,
				),
			)
		default:
			return p.finishCommittedInstall(
				nil,
				fmt.Errorf(
					"canonical Local Executor policy install result is uncertain; inspect %s and %s before retrying: %w",
					p.path,
					p.tempPath,
					err,
				),
			)
		}
	}
	return p.finishCommittedInstall(p.tempInfo, nil)
}

func (p *preparedLocalExecutorPolicy) finishCommittedInstall(
	committedInfo os.FileInfo,
	finalErr error,
) error {
	p.committed = true
	p.committedInfo = committedInfo
	closeErr := p.temp.Close()
	p.temp = nil
	if closeErr != nil {
		finalErr = errors.Join(
			finalErr,
			errors.New("Local Executor policy installed but close failed"),
		)
	}
	if err := syncDirectory(p.parent); err != nil {
		finalErr = errors.Join(
			finalErr,
			errors.New("Local Executor policy installed but directory sync failed"),
		)
	}
	return finalErr
}

func (p *preparedLocalExecutorPolicy) Rollback() error {
	if p == nil || !p.committed {
		return nil
	}
	current, currentInfo, existed, err := readRootPolicySnapshotOptional(p.path)
	if err != nil || !existed || p.committedInfo == nil ||
		!os.SameFile(currentInfo, p.committedInfo) {
		return errors.New("installed Local Executor policy changed before rollback")
	}
	if !p.existed {
		if err := os.Remove(p.path); err != nil {
			return errors.New("remove newly installed Local Executor policy during rollback")
		}
		p.committed = false
		return syncDirectory(p.parent)
	}
	_ = current
	temp, err := os.CreateTemp(p.parent, ".executor-policy.json.rollback-*")
	if err != nil {
		return errors.New("create Local Executor policy rollback file")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chown(0, 0); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(p.existing); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, p.path); err != nil {
		return errors.New("restore previous Local Executor policy")
	}
	p.committed = false
	return syncDirectory(p.parent)
}

func (p *preparedLocalExecutorPolicy) Abort() {
	if p == nil || p.committed {
		return
	}
	if p.temp != nil {
		_ = p.temp.Close()
		p.temp = nil
	}
	if p.tempPath != "" {
		_ = os.Remove(p.tempPath)
	}
}

func (p *preparedLocalExecutorPolicy) verifyDestination() error {
	if err := validateSecureRootPath(p.parent, true); err != nil {
		return fmt.Errorf("Local Executor policy parent changed after preflight: %w", err)
	}
	current, currentInfo, existed, err := readRootPolicySnapshotOptional(p.path)
	if err != nil {
		return err
	}
	if !p.existed {
		if existed {
			return errors.New("Local Executor policy destination appeared after preflight")
		}
		return nil
	}
	if !existed || !os.SameFile(currentInfo, p.existingInfo) ||
		!bytes.Equal(current, p.existing) {
		return errors.New("Local Executor policy changed after preflight")
	}
	return nil
}

func (p *preparedLocalExecutorPolicy) verifyTemporaryFile() error {
	pathInfo, err := os.Lstat(p.tempPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() {
		return errors.New("Local Executor policy temporary file changed after preflight")
	}
	openedInfo, err := p.temp.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) ||
		!os.SameFile(p.tempInfo, openedInfo) ||
		openedInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(openedInfo, 0) {
		return errors.New("Local Executor policy temporary file changed after preflight")
	}
	return nil
}

func readRootPolicySnapshot(path string) ([]byte, error) {
	data, _, existed, err := readRootPolicySnapshotOptional(path)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, errors.New("installed Local Executor policy is missing")
	}
	return data, nil
}

func readRootPolicySnapshotOptional(path string) ([]byte, os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("stat Local Executor policy: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() <= 0 || info.Size() > localExecutorPolicyMaxBytes ||
		info.Mode().Perm() != 0o600 {
		return nil, nil, false, errors.New("Local Executor policy must be a bounded root:root 0600 regular non-symlink file")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil {
		return nil, nil, false, err
	}
	defer file.Close()
	if !updaterConfigHasInstallOwner(openedInfo, 0) {
		return nil, nil, false, errors.New("Local Executor policy must be owned by root")
	}
	if err := validateRootOwnedFileAndParents(path, openedInfo, "Local Executor policy"); err != nil {
		return nil, nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(file, localExecutorPolicyMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > localExecutorPolicyMaxBytes {
		return nil, nil, false, errors.New("read Local Executor policy")
	}
	return data, openedInfo, true, nil
}
