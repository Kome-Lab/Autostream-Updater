package hostruntime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func (p *preparedSystemdPortSidecars) verifyDestinations() error {
	if p == nil {
		return errors.New("initial systemd port sidecar update is not prepared")
	}
	if err := validateSystemdPortSidecarDirectory(p.parent); err != nil {
		return err
	}
	for _, entry := range p.entries {
		if p.replaced && entry == p.replacedEntry {
			body, info, existed, err := readRootSystemdPortSidecarOptional(entry.path)
			if err != nil || !existed ||
				!os.SameFile(info, p.replacementTempInfo) ||
				!bytes.Equal(body, p.replacementBody) {
				return errors.New("adopted systemd sidecar changed after exchange")
			}
			backup, backupInfo, backupExists, err := readRootSystemdPortSidecarOptional(
				p.replacementTempPath,
			)
			if err != nil || !backupExists ||
				!os.SameFile(backupInfo, entry.existingInfo) ||
				!bytes.Equal(backup, entry.existing) {
				return errors.New("adopted systemd sidecar backup changed after exchange")
			}
			continue
		}
		body, info, existed, err := readRootSystemdPortSidecarOptional(entry.path)
		if err != nil {
			return err
		}
		if entry.created {
			if !existed ||
				entry.createdInfo == nil ||
				!os.SameFile(info, entry.createdInfo) ||
				!bytes.Equal(body, entry.installedBody) {
				return errors.New("new systemd port sidecar changed during configuration")
			}
			continue
		}
		if !entry.existed {
			if existed {
				return errors.New("systemd port sidecar destination appeared after preflight")
			}
			if err := entry.verifyTemporaryFile(); err != nil {
				return err
			}
			continue
		}
		if !existed ||
			!os.SameFile(info, entry.existingInfo) ||
			!bytes.Equal(body, entry.existing) {
			return errors.New("existing systemd port sidecar changed after preflight")
		}
	}
	if p.replacementTempPath != "" && !p.replaced {
		if err := p.verifyReplacementTemporaryFile(); err != nil {
			return err
		}
	}
	return nil
}

func (p *preparedSystemdPortSidecars) verifyReplacementTemporaryFile() error {
	if p == nil || p.replacementTemp == nil || p.replacementTempPath == "" ||
		p.replacementTempInfo == nil || p.replaced {
		return errors.New("systemd sidecar adoption file is unavailable")
	}
	pathInfo, err := os.Lstat(p.replacementTempPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() ||
		pathInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(pathInfo, 0) {
		return errors.New("systemd sidecar adoption file changed after preflight")
	}
	openedInfo, err := p.replacementTemp.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) ||
		!os.SameFile(p.replacementTempInfo, openedInfo) {
		return errors.New("systemd sidecar adoption file changed after preflight")
	}
	return nil
}

func (e *preparedSystemdPortSidecar) verifyTemporaryFile() error {
	if e == nil || e.temp == nil || e.tempPath == "" || e.tempInfo == nil {
		return errors.New("initial systemd port sidecar temporary file is unavailable")
	}
	pathInfo, err := os.Lstat(e.tempPath)
	if err != nil ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() {
		return errors.New("initial systemd port sidecar temporary file changed after preflight")
	}
	openedInfo, err := e.temp.Stat()
	if err != nil ||
		!os.SameFile(pathInfo, openedInfo) ||
		!os.SameFile(e.tempInfo, openedInfo) ||
		openedInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(openedInfo, 0) {
		return errors.New("initial systemd port sidecar temporary file changed after preflight")
	}
	return nil
}

func validateInstalledSystemdPortSidecars(
	policy LocalExecutorPolicy,
	parent string,
) error {
	if err := validateSystemdPortSidecarDirectory(parent); err != nil {
		return err
	}
	plans, err := initialSystemdPortSidecarPlans(policy, parent)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		body, _, existed, err := readRootSystemdPortSidecarOptional(plan.Path)
		if err != nil {
			return err
		}
		if !existed || !bytes.Equal(body, plan.Body) {
			return fmt.Errorf(
				"installed systemd port sidecar for %s does not match the staged policy",
				plan.ServiceID,
			)
		}
	}
	return nil
}

func validateSystemdPortSidecarDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("systemd port sidecar directory must be a clean absolute path")
	}
	if err := validateSecureRootPath(path, true); err != nil {
		return fmt.Errorf("systemd port sidecar directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm() != 0o700 ||
		!updaterConfigHasInstallOwner(info, 0) {
		return errors.New("systemd port sidecar directory must be root:root 0700")
	}
	return nil
}

func readRootSystemdPortSidecarOptional(
	path string,
) ([]byte, os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, errors.New("stat systemd port sidecar")
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Size() <= 0 ||
		info.Size() > systemdPortSidecarConfigureMaxBytes ||
		info.Mode().Perm() != 0o600 {
		return nil, nil, false, errors.New("systemd port sidecar must be a bounded root:root 0600 regular non-symlink file")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil {
		return nil, nil, false, errors.New("open systemd port sidecar")
	}
	defer file.Close()
	if !updaterConfigHasInstallOwner(openedInfo, 0) {
		return nil, nil, false, errors.New("systemd port sidecar must be owned by root")
	}
	if err := validateRootOwnedFileAndParents(
		path,
		openedInfo,
		"systemd port sidecar",
	); err != nil {
		return nil, nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(
		file,
		systemdPortSidecarConfigureMaxBytes+1,
	))
	if err != nil ||
		len(data) == 0 ||
		len(data) > systemdPortSidecarConfigureMaxBytes {
		return nil, nil, false, errors.New("read systemd port sidecar")
	}
	return data, openedInfo, true, nil
}
