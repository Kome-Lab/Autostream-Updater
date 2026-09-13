package hostruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func currentRelease(link, releaseRoot string) (string, string, string, error) {
	target, err := os.Readlink(link)
	if errors.Is(err, os.ErrNotExist) {
		return "", "", "", nil
	}
	if err != nil {
		return "", "", "", errors.New("current_link must be a symlink managed by autostream-updater")
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(link), target)
	}
	target, err = filepath.EvalSymlinks(target)
	if err != nil || !pathWithin(releaseRoot, target) {
		return "", "", "", errors.New("current_link target is outside release_root")
	}
	digestBytes, digestErr := os.ReadFile(filepath.Join(target, ".artifact-sha256"))
	versionBytes, versionErr := os.ReadFile(filepath.Join(target, ".version"))
	digest := strings.ToLower(strings.TrimSpace(string(digestBytes)))
	version := strings.TrimSpace(string(versionBytes))
	if digestErr != nil || versionErr != nil || len(digest) != 64 || !versionPattern.MatchString(version) {
		return "", "", "", errors.New("current release markers are invalid")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", "", "", errors.New("current release digest marker is invalid")
	}
	return filepath.Clean(target), digest, version, nil
}

func switchSymlink(link, target, jobID string) error {
	tmp := link + ".next-" + shortID(jobID)
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirectory(filepath.Dir(link))
}

func rollbackSystemd(ctx context.Context, target Target, previous, previousVersion, jobID string, runner CommandRunner) error {
	s := target.Systemd
	if previous == "" || !versionPattern.MatchString(previousVersion) {
		return errors.New("no valid previous managed release is available")
	}
	if _, err := runner.Run(ctx, "", nil, s.SystemctlPath, "stop", s.Unit); err != nil {
		return fmt.Errorf("stop failed during rollback: %w", err)
	}
	if previous == "" {
		if err := os.Remove(s.CurrentLink); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else if err := switchSymlink(s.CurrentLink, previous, jobID+"-rollback"); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "", nil, s.SystemctlPath, "start", s.Unit); err != nil {
		return err
	}
	return firstError(verifySystemdProcess(ctx, target, previous, runner), verifyTarget(ctx, target, previousVersion))
}

func verifySystemdProcess(ctx context.Context, target Target, releaseDir string, runner CommandRunner) error {
	out, err := runner.Run(ctx, "", nil, target.Systemd.SystemctlPath, "show", "--property=MainPID", "--value", target.Systemd.Unit)
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || pid <= 0 {
		return errors.New("systemd service has no MainPID")
	}
	running, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return errors.New("could not resolve systemd MainPID executable")
	}
	expected, err := filepath.EvalSymlinks(filepath.Join(releaseDir, filepath.FromSlash(target.Systemd.BinaryPath)))
	if err != nil || filepath.Clean(running) != filepath.Clean(expected) {
		return errors.New("systemd MainPID is not executing the selected release binary")
	}
	return nil
}
