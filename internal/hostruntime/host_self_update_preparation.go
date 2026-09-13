package hostruntime

import (
	"context"
	"errors"
	"fmt"
	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func (rt *hostSelfUpdateExecutorRuntime) prepare() error {
	if rt.arch == "" {
		rt.arch = runtime.GOARCH
	}
	if rt.executorVersion == "" {
		rt.executorVersion = controlversion.Current()
	}
	if rt.downloader == nil {
		rt.downloader = ReleaseDownloader{TrustedPublicOnly: true}
	}
	if rt.runner == nil {
		rt.runner = OSCommandRunner{NewProcessGroup: true}
	}
	if rt.now == nil {
		rt.now = time.Now
	}
	if rt.verificationTimeout == 0 {
		rt.verificationTimeout = defaultHostSelfUpdateVerificationTimeout
	}
	if rt.grantStatePath == "" && rt.allowTestPaths {
		rt.grantStatePath = filepath.Join(rt.stateRoot, "grant.json")
	}
	if rt.verificationTimeout < 30*time.Second ||
		rt.verificationTimeout > 30*time.Minute {
		return errors.New("host self-update verification timeout is invalid")
	}
	if rt.consumeGrant == nil {
		rt.consumeGrant = consumeHostSelfUpdateGrant
	}
	if rt.resolveProcessExe == nil {
		rt.resolveProcessExe = func(pid int) (string, error) {
			return filepath.EvalSymlinks(
				fmt.Sprintf("/proc/%d/exe", pid),
			)
		}
	}
	if rt.waitExecutorStable == nil {
		rt.waitExecutorStable = func(ctx context.Context) error {
			timer := time.NewTimer(250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	if rt.watchdogStatus == nil {
		rt.watchdogStatus = (LocalExecutorClient{
			SocketPath: LocalExecutorSocketPath,
		}).HostSelfUpdateWatchdogStatus
	}
	if rt.syncDir == nil {
		rt.syncDir = syncDirectory
	}
	if !rt.allowTestPaths {
		if rt.installRoot != HostSelfUpdateInstallRoot ||
			rt.currentLink != HostSelfUpdateCurrentLink ||
			rt.slotsRoot != HostSelfUpdateSlotsRoot ||
			rt.stateRoot != HostSelfUpdateStateRoot ||
			rt.statePath != HostSelfUpdateStatePath ||
			rt.grantStatePath != HostSelfUpdateGrantStatePath ||
			rt.downloadRoot != filepath.Join(HostSelfUpdateStateRoot, "downloads") {
			return errors.New("host self-update paths are not the fixed production roots")
		}
	}
	for _, candidate := range []string{
		rt.installRoot, rt.currentLink, rt.slotsRoot,
		rt.stateRoot, rt.statePath, rt.grantStatePath, rt.downloadRoot,
	} {
		if !filepath.IsAbs(candidate) ||
			filepath.Clean(candidate) == string(filepath.Separator) {
			return errors.New("host self-update path is invalid")
		}
	}
	if filepath.Dir(rt.currentLink) != filepath.Clean(rt.installRoot) ||
		filepath.Dir(rt.slotsRoot) != filepath.Clean(rt.installRoot) ||
		filepath.Dir(rt.statePath) != filepath.Clean(rt.stateRoot) ||
		filepath.Dir(rt.grantStatePath) != filepath.Clean(rt.stateRoot) ||
		filepath.Dir(rt.downloadRoot) != filepath.Clean(rt.stateRoot) {
		return errors.New("host self-update paths escaped their fixed roots")
	}
	if rt.arch != "amd64" && rt.arch != "arm64" {
		return errors.New("host self-update architecture is unsupported")
	}
	if !versionPattern.MatchString(rt.executorVersion) {
		return errors.New("host self-update executor version is invalid")
	}
	if err := rt.ensureRoots(); err != nil {
		return err
	}
	return rt.recoverHostSelfUpdateSlotArtifacts()
}

func (rt hostSelfUpdateExecutorRuntime) ensureRoots() error {
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{rt.installRoot, 0o755},
		{rt.slotsRoot, 0o755},
		{rt.stateRoot, 0o700},
		{rt.downloadRoot, 0o700},
	} {
		if _, err := missingHostSelfUpdateDirectories(directory.path); err != nil {
			return err
		}
		if err := os.MkdirAll(directory.path, directory.mode); err != nil {
			return err
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return err
		}
		info, err := os.Lstat(directory.path)
		if err != nil || !info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != directory.mode.Perm() {
			return errors.New("host self-update directory is unsafe")
		}
		if !rt.allowTestPaths && !isRootOwner(info) {
			return errors.New("host self-update directory is not root-owned")
		}
		for current := filepath.Clean(directory.path); ; {
			if err := rt.syncHostSelfUpdateDirectory(current); err != nil {
				return fmt.Errorf(
					"sync host self-update directory %s: %w",
					filepath.Base(current),
					err,
				)
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	return nil
}

func missingHostSelfUpdateDirectories(path string) ([]string, error) {
	path = filepath.Clean(path)
	missing := make([]string, 0, 4)
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New(
					"host self-update directory ancestor is unsafe",
				)
			}
			return missing, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return nil, errors.New(
				"host self-update directory has no durable ancestor",
			)
		}
	}
}
