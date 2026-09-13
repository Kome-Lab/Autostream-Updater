package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (rt hostSelfUpdateExecutorRuntime) restartHostAgent(
	ctx context.Context,
) error {
	_, err := rt.runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl",
		"restart", hostSelfUpdateServiceUnit,
	)
	if err != nil {
		return errors.New("restart Host Agent")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) restartLocalExecutor(
	ctx context.Context,
) error {
	_, err := rt.runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl",
		"restart", hostSelfUpdateExecutorServiceUnit,
	)
	if err != nil {
		return errors.New("restart Local Executor")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) verifyHealthyLocalExecutor(
	ctx context.Context,
	healthySlot string,
	state HostSelfUpdateState,
) error {
	if !validHostSelfUpdateSlot(healthySlot) ||
		state.HealthySlot != healthySlot ||
		state.ActiveExecutorVersion == "" {
		return errors.New("healthy Local Executor identity is invalid")
	}
	if err := rt.validateHostSelfUpdateSlotTree(healthySlot); err != nil {
		return errors.New("healthy host self-update slot is unsafe")
	}
	expected := filepath.Join(
		rt.slotsRoot,
		healthySlot,
		"bin",
		"autostream-local-executor",
	)
	info, err := os.Lstat(expected)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 {
		return errors.New("healthy Local Executor binary is unsafe")
	}
	firstPID, err := rt.acquireHealthyLocalExecutorPID(ctx, expected)
	if err != nil {
		return err
	}
	if err := rt.waitExecutorStable(ctx); err != nil {
		return fmt.Errorf("wait for healthy Local Executor stability: %w", err)
	}
	secondPID, err := rt.healthyLocalExecutorPID(ctx, expected)
	if err != nil {
		return err
	}
	if firstPID != secondPID {
		return errors.New(
			"healthy Local Executor MainPID changed during stability probe",
		)
	}
	identityContext, cancel := context.WithTimeout(
		ctx,
		hostSelfUpdateBinaryIdentityTimeout,
	)
	defer cancel()
	versionOutput, err := hostSelfUpdateIdentityRunner(
		rt.identityRunner,
		rt.runner,
	).Run(
		identityContext,
		"/",
		nil,
		expected,
		"--version",
	)
	if err != nil ||
		!strings.Contains(
			versionOutput,
			"autostream-local-executor "+
				state.ActiveExecutorVersion+"\n",
		) ||
		!strings.Contains(
			versionOutput,
			fmt.Sprintf(
				"mutation_protocol: %d\n",
				LocalExecutorMutationProtocolVersion,
			),
		) ||
		!strings.Contains(
			versionOutput,
			fmt.Sprintf(
				"recovery_protocol: %d\n",
				state.RecoveryProtocolVersion,
			),
		) {
		return errors.New(
			"healthy Local Executor version or protocol is invalid",
		)
	}
	socketStatus, err := rt.watchdogStatus(ctx)
	if err != nil ||
		socketStatus.State != state ||
		socketStatus.CurrentSlot != healthySlot ||
		socketStatus.ExecutorVersion != state.ActiveExecutorVersion ||
		socketStatus.ExecutorProtocolVersion !=
			LocalExecutorMutationProtocolVersion ||
		socketStatus.State.RecoveryProtocolVersion !=
			HostSelfUpdateRecoveryProtocolVersion ||
		socketStatus.LastAction != HostSelfUpdateActionNone ||
		socketStatus.RollbackRequested ||
		socketStatus.RestartRequested {
		return errors.New(
			"healthy Local Executor watchdog status handshake is invalid",
		)
	}
	return nil
}

func isHostRuntimeSystemdExecutor(executable string) bool {
	switch filepath.Clean(executable) {
	case "/usr/lib/systemd/systemd-executor",
		"/lib/systemd/systemd-executor":
		return true
	default:
		return false
	}
}

func (rt hostSelfUpdateExecutorRuntime) acquireHealthyLocalExecutorPID(
	ctx context.Context,
	expected string,
) (int, error) {
	pinnedPID := 0
	for probe := 0; probe < hostSelfUpdateSystemdExecutorProbes; probe++ {
		pid, running, err := rt.healthyLocalExecutorProcess(ctx)
		if err != nil {
			return 0, err
		}
		if pinnedPID == 0 {
			pinnedPID = pid
		} else if pid != pinnedPID {
			return 0, errors.New(
				"healthy Local Executor MainPID changed during systemd-executor transition",
			)
		}
		if filepath.Clean(running) == filepath.Clean(expected) {
			return pid, nil
		}
		if !isHostRuntimeSystemdExecutor(running) {
			return 0, errors.New(
				"Local Executor is not running the healthy slot binary",
			)
		}
		if probe+1 == hostSelfUpdateSystemdExecutorProbes {
			return 0, errors.New(
				"healthy Local Executor remained in systemd-executor beyond the startup probe limit",
			)
		}
		if err := rt.waitExecutorStable(ctx); err != nil {
			return 0, fmt.Errorf(
				"wait for healthy Local Executor systemd-executor transition: %w",
				err,
			)
		}
	}
	return 0, errors.New("healthy Local Executor startup probe limit is invalid")
}

func (rt hostSelfUpdateExecutorRuntime) healthyLocalExecutorPID(
	ctx context.Context,
	expected string,
) (int, error) {
	pid, running, err := rt.healthyLocalExecutorProcess(ctx)
	if err != nil {
		return 0, err
	}
	if filepath.Clean(running) != filepath.Clean(expected) {
		return 0, errors.New(
			"Local Executor is not running the healthy slot binary",
		)
	}
	return pid, nil
}

func (rt hostSelfUpdateExecutorRuntime) healthyLocalExecutorProcess(
	ctx context.Context,
) (int, string, error) {
	if err := ctx.Err(); err != nil {
		return 0, "", fmt.Errorf(
			"verify healthy Local Executor process: %w",
			err,
		)
	}
	for _, unit := range []string{
		hostSelfUpdateExecutorSocketUnit,
		hostSelfUpdateExecutorServiceUnit,
	} {
		if _, err := rt.runner.Run(
			ctx,
			"/",
			nil,
			"/usr/bin/systemctl",
			"is-active",
			"--quiet",
			unit,
		); err != nil {
			return 0, "", fmt.Errorf("%s is not active", unit)
		}
	}
	output, err := rt.runner.Run(
		ctx,
		"/",
		nil,
		"/usr/bin/systemctl",
		"show",
		"--property=MainPID",
		"--value",
		hostSelfUpdateExecutorServiceUnit,
	)
	if err != nil {
		return 0, "", errors.New("read healthy Local Executor MainPID")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil || pid <= 0 {
		return 0, "", errors.New("healthy Local Executor has no MainPID")
	}
	running, err := rt.resolveProcessExe(pid)
	if err != nil {
		return 0, "", errors.New("resolve healthy Local Executor executable")
	}
	return pid, running, nil
}
