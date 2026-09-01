package hostruntime

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
)

type hostSelfUpdateIdentityCommandRunner struct{}

func (hostSelfUpdateIdentityCommandRunner) Run(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	processDone := configureHostSelfUpdateIdentityProcess(cmd)
	cmd.Dir = dir
	cmd.Env = sanitizedCommandEnv(env)
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	processDone()
	if err != nil {
		return output.String(), fmt.Errorf(
			"%s failed: %w",
			filepath.Base(name),
			err,
		)
	}
	return output.String(), nil
}

func hostSelfUpdateIdentityRunner(
	configured CommandRunner,
	fallback CommandRunner,
) CommandRunner {
	if configured != nil {
		return configured
	}
	switch fallback.(type) {
	case nil, OSCommandRunner, *OSCommandRunner:
		return hostSelfUpdateIdentityCommandRunner{}
	default:
		// Tests and fault-injection runners own their process lifecycle.
		return fallback
	}
}
