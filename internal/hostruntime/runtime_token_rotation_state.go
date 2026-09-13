package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func (rt runtimeCredentialExecutorRuntime) loadStatus() (
	RuntimeCredentialStatus,
	bool,
	error,
) {
	info, err := os.Lstat(rt.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return RuntimeCredentialStatus{}, false, nil
	}
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!rt.secureMode(info.Mode(), 0o600) ||
		info.Size() <= 0 ||
		info.Size() > runtimeCredentialStateMaxBytes ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, 0)) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential metadata is unsafe",
		)
	}
	file, openedInfo, err := openVerifiedConfig(rt.statePath, info)
	if err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	defer file.Close()
	if !rt.secureMode(openedInfo.Mode(), 0o600) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(openedInfo, 0, 0)) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential metadata owner changed during secure open",
		)
	}
	data, err := io.ReadAll(io.LimitReader(
		file, runtimeCredentialStateMaxBytes+1,
	))
	if err != nil ||
		len(data) == 0 ||
		len(data) > runtimeCredentialStateMaxBytes {
		return RuntimeCredentialStatus{}, false, errors.New(
			"read runtime credential metadata",
		)
	}
	var persisted runtimeCredentialStateFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return RuntimeCredentialStatus{}, false, errors.New(
			"decode runtime credential metadata",
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential metadata contains trailing data",
		)
	}
	status := persisted.RuntimeCredentialStatus
	status.previousRuntimeTokenSHA256 =
		persisted.PreviousRuntimeTokenSHA256
	status.stagedRuntimeTokenSHA256 =
		persisted.StagedRuntimeTokenSHA256
	status.activeRuntimeTokenSHA256 =
		persisted.ActiveRuntimeTokenSHA256
	status.serviceName = persisted.ServiceName
	if err := status.Validate(); err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	if err := status.validateRootTokenBindings(); err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	return status, true, nil
}

func (rt runtimeCredentialExecutorRuntime) saveStatus(
	status RuntimeCredentialStatus,
) error {
	if err := status.Validate(); err != nil {
		return err
	}
	if err := status.validateRootTokenBindings(); err != nil {
		return err
	}
	parent := filepath.Dir(rt.statePath)
	info, err := os.Lstat(parent)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		!rt.secureMode(info.Mode(), 0o700) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, 0)) {
		return errors.New("runtime credential state directory is unsafe")
	}
	data, err := json.Marshal(runtimeCredentialStateFile{
		RuntimeCredentialStatus:    status,
		PreviousRuntimeTokenSHA256: status.previousRuntimeTokenSHA256,
		StagedRuntimeTokenSHA256:   status.stagedRuntimeTokenSHA256,
		ActiveRuntimeTokenSHA256:   status.activeRuntimeTokenSHA256,
		ServiceName:                status.serviceName,
	})
	if err != nil || len(data) == 0 ||
		len(data)+1 > runtimeCredentialStateMaxBytes {
		return errors.New("encode runtime credential metadata")
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(parent, ".runtime-credential-*")
	if err != nil {
		return errRuntimeCredentialStateUnavailable
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if !rt.allowTestPaths {
		if err := temp.Chown(0, 0); err != nil {
			_ = temp.Close()
			return errRuntimeCredentialStateUnavailable
		}
	}
	if err := temp.Chmod(0o600); err != nil {
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
		!rt.secureMode(tempInfo.Mode(), 0o600) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(tempInfo, 0, 0)) {
		_ = temp.Close()
		return errors.New("runtime credential temporary metadata is unsafe")
	}
	if err := temp.Close(); err != nil {
		return errRuntimeCredentialStateUnavailable
	}
	if err := os.Rename(tempPath, rt.statePath); err != nil {
		switch inspectPreparedRenameOutcome(tempPath, rt.statePath, tempInfo) {
		case preparedRenameInstalled:
			if syncErr := syncDirectory(parent); syncErr != nil {
				return errors.Join(err, syncErr)
			}
			return fmt.Errorf(
				"runtime credential metadata installed but rename reported an error: %w",
				err,
			)
		case preparedRenameNotInstalled:
			return fmt.Errorf("install runtime credential metadata: %w", err)
		default:
			return fmt.Errorf(
				"runtime credential metadata install result is uncertain: %w",
				err,
			)
		}
	}
	return syncDirectory(parent)
}

func (rt runtimeCredentialExecutorRuntime) removeState() error {
	info, err := os.Lstat(rt.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!rt.secureMode(info.Mode(), 0o600) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, 0)) {
		return errors.New("runtime credential metadata is unsafe")
	}
	if err := os.Remove(rt.statePath); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(rt.statePath))
}
