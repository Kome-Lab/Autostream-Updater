//go:build windows

package hostruntime

import "os/exec"

func configureProcessGroup(*exec.Cmd, bool) func() { return func() {} }
