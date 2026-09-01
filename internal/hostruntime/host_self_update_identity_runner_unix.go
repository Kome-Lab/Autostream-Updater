//go:build !windows

package hostruntime

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const hostSelfUpdateIdentityWaitDelay = 250 * time.Millisecond

func configureHostSelfUpdateIdentityProcess(cmd *exec.Cmd) func() {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = hostSelfUpdateIdentityWaitDelay
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return func() {
		if cmd.Process == nil {
			return
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		killRemainingSessionMembers(cmd.Process.Pid)
	}
}
