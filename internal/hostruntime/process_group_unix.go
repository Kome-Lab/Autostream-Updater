//go:build !windows

package hostruntime

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func configureProcessGroup(cmd *exec.Cmd, newGroup bool) func() {
	if !newGroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		return func() {}
	}
	done := make(chan struct{})
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.WaitDelay = 130 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		pid := cmd.Process.Pid
		err := syscall.Kill(-pid, syscall.SIGTERM)
		go func() {
			// The helper traps SIGTERM and may need its bounded two-minute
			// rollback window before the final process-tree fence fires.
			timer := time.NewTimer(125 * time.Second)
			defer timer.Stop()
			select {
			case <-done:
				return
			case <-timer.C:
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		}()
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return func() {
		close(done)
		if cmd.Process != nil {
			killRemainingSessionMembers(cmd.Process.Pid)
		}
	}
}

func killRemainingSessionMembers(sessionID int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		end := strings.LastIndexByte(string(data), ')')
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) < 4 {
			continue
		}
		session, err := strconv.Atoi(fields[3])
		if err == nil && session == sessionID {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}
