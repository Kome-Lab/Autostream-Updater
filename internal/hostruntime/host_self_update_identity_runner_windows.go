//go:build windows

package hostruntime

import (
	"os/exec"
	"time"
)

const hostSelfUpdateIdentityWaitDelay = 250 * time.Millisecond

func configureHostSelfUpdateIdentityProcess(cmd *exec.Cmd) func() {
	// exec.CommandContext terminates the direct process immediately on context
	// cancellation. WaitDelay keeps inherited output handles bounded.
	cmd.WaitDelay = hostSelfUpdateIdentityWaitDelay
	return func() {}
}
