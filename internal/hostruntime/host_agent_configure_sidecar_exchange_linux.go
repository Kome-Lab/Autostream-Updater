//go:build linux

package hostruntime

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func exchangeHostAgentSystemdSidecar(left, right string) error {
	if filepath.Dir(left) != filepath.Dir(right) ||
		filepath.Clean(left) != left || filepath.Clean(right) != right {
		return errors.New("systemd sidecar exchange paths are invalid")
	}
	if err := unix.Renameat2(
		unix.AT_FDCWD,
		left,
		unix.AT_FDCWD,
		right,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return errors.New("atomic systemd sidecar exchange is unavailable")
	}
	return nil
}

func prepareHostAgentSystemdSidecarExchange(
	parent string,
) (*os.File, string, os.FileInfo, error) {
	if os.Geteuid() != 0 {
		return nil, "", nil, errors.New("live systemd sidecar adoption requires root")
	}
	if err := validateSystemdPortSidecarDirectory(parent); err != nil {
		return nil, "", nil, err
	}
	replacement, err := os.CreateTemp(parent, ".host-sidecar-adopt-*")
	if err != nil {
		return nil, "", nil, errors.New("create systemd sidecar adoption file")
	}
	replacementPath := replacement.Name()
	failed := true
	defer func() {
		if failed {
			_ = replacement.Close()
			_ = os.Remove(replacementPath)
			_ = syncDirectory(parent)
		}
	}()
	if err := initializeHostAgentSidecarExchangeFile(
		replacement,
		[]byte("replacement-preflight\n"),
	); err != nil {
		return nil, "", nil, err
	}
	replacementInfo, err := replacement.Stat()
	if err != nil {
		return nil, "", nil, errors.New("stat systemd sidecar adoption file")
	}
	probe, err := os.CreateTemp(parent, ".host-sidecar-exchange-probe-*")
	if err != nil {
		return nil, "", nil, errors.New("create systemd sidecar exchange probe")
	}
	probePath := probe.Name()
	defer func() {
		_ = probe.Close()
		_ = os.Remove(probePath)
	}()
	if err := initializeHostAgentSidecarExchangeFile(
		probe,
		[]byte("exchange-probe\n"),
	); err != nil {
		return nil, "", nil, err
	}
	probeInfo, err := probe.Stat()
	if err != nil {
		return nil, "", nil, errors.New("stat systemd sidecar exchange probe")
	}
	if err := exchangeHostAgentSystemdSidecar(replacementPath, probePath); err != nil {
		return nil, "", nil, err
	}
	if err := verifyHostAgentSidecarExchangePair(
		replacementPath,
		probeInfo,
		probePath,
		replacementInfo,
	); err != nil {
		return nil, "", nil, err
	}
	if err := exchangeHostAgentSystemdSidecar(replacementPath, probePath); err != nil {
		return nil, "", nil, errors.New("restore systemd sidecar exchange preflight files")
	}
	if err := verifyHostAgentSidecarExchangePair(
		replacementPath,
		replacementInfo,
		probePath,
		probeInfo,
	); err != nil {
		return nil, "", nil, err
	}
	if err := os.Remove(probePath); err != nil {
		return nil, "", nil, errors.New("remove systemd sidecar exchange probe")
	}
	probePath = ""
	if err := syncDirectory(parent); err != nil {
		return nil, "", nil, errors.New("sync systemd sidecar directory after exchange preflight")
	}
	failed = false
	return replacement, replacementPath, replacementInfo, nil
}

func initializeHostAgentSidecarExchangeFile(file *os.File, body []byte) error {
	if err := file.Chown(0, 0); err != nil {
		return errors.New("set systemd sidecar exchange file ownership")
	}
	if err := file.Chmod(0o600); err != nil {
		return errors.New("set systemd sidecar exchange file mode")
	}
	if _, err := file.Write(body); err != nil {
		return errors.New("write systemd sidecar exchange file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync systemd sidecar exchange file")
	}
	return nil
}

func verifyHostAgentSidecarExchangePair(
	left string,
	leftInfo os.FileInfo,
	right string,
	rightInfo os.FileInfo,
) error {
	observedLeft, leftErr := os.Lstat(left)
	observedRight, rightErr := os.Lstat(right)
	if leftErr != nil || rightErr != nil ||
		leftInfo == nil || rightInfo == nil ||
		!os.SameFile(observedLeft, leftInfo) ||
		!os.SameFile(observedRight, rightInfo) ||
		!observedLeft.Mode().IsRegular() ||
		!observedRight.Mode().IsRegular() ||
		observedLeft.Mode().Perm() != 0o600 ||
		observedRight.Mode().Perm() != 0o600 ||
		!isRootOwner(observedLeft) || !isRootOwner(observedRight) {
		return errors.New("systemd sidecar exchange result is unsafe")
	}
	return nil
}
