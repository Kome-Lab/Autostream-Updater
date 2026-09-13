//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

func restartManualHostUpgradeLocalExecutor(
	ctx context.Context,
	slot string,
	expected manualHostBinaryIdentity,
	rt manualHostUpgradeRuntime,
) error {
	if err := rt.selfUpdate.restartLocalExecutor(ctx); err != nil {
		return errors.New("restart Local Executor after unit migration")
	}
	actual, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			slot,
			"bin",
			"autostream-local-executor",
		),
		"autostream-local-executor",
		rt,
	)
	if err != nil || actual != expected {
		return errors.New("Local Executor identity after unit migration is invalid")
	}
	return nil
}

func validateManualHostUpgradeCoreServicePreconditions(
	ctx context.Context,
	rt manualHostUpgradeRuntime,
	agentStoppedForRecovery bool,
) error {
	if agentStoppedForRecovery {
		state, pid, err := readManualHostUpgradeRecoveryServiceState(
			ctx,
			rt.runner,
			hostSelfUpdateServiceUnit,
		)
		if err != nil || state != "inactive" || pid != 0 {
			return errors.New(
				"Host Agent stopped-recovery handoff is not safely quiescent",
			)
		}
	} else if err := requireManualHostSystemdState(
		ctx,
		rt.runner,
		"is-active",
		hostSelfUpdateServiceUnit,
		"active",
	); err != nil {
		return err
	}
	for _, unit := range []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateExecutorSocketUnit,
		"autostream-host-self-update-recovery@a.timer",
		"autostream-host-self-update-recovery@b.timer",
	} {
		if err := requireManualHostSystemdState(
			ctx, rt.runner, "is-active", unit, "active",
		); err != nil {
			return err
		}
	}
	for _, unit := range []string{
		hostSelfUpdateServiceUnit,
		hostSelfUpdateExecutorSocketUnit,
		"autostream-host-self-update-recovery@a.timer",
		"autostream-host-self-update-recovery@b.timer",
	} {
		if err := requireManualHostSystemdState(
			ctx, rt.runner, "is-enabled", unit, "enabled",
		); err != nil {
			return err
		}
	}
	return nil
}

func validateManualHostUpgradeRecoveryServicePreconditions(
	ctx context.Context,
	rt manualHostUpgradeRuntime,
	allowFailedBootstrap bool,
) error {
	for _, unit := range manualHostRecoveryUnitInstances {
		state, pid, err := readManualHostUpgradeRecoveryServiceState(
			ctx, rt.runner, unit,
		)
		if err != nil {
			return err
		}
		if pid != 0 ||
			(state != "inactive" && !(allowFailedBootstrap && state == "failed")) {
			return fmt.Errorf("%s must be inactive and have no MainPID", unit)
		}
	}
	return nil
}

func readManualHostUpgradeRecoveryServiceState(
	ctx context.Context,
	runner CommandRunner,
	unit string,
) (string, int, error) {
	output, _ := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "is-active", unit,
	)
	state := strings.TrimSpace(output)
	if state == "" {
		return "", 0, fmt.Errorf("read %s active state", unit)
	}
	pidOutput, err := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "show",
		"--property=MainPID", "--value", unit,
	)
	if err != nil {
		return "", 0, fmt.Errorf("read %s MainPID", unit)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidOutput))
	if err != nil || pid < 0 {
		return "", 0, fmt.Errorf("%s MainPID is invalid", unit)
	}
	return state, pid, nil
}

func normalizeManualHostUpgradeRecoveryServices(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	if snapshot.recoveryUnitConfig == nil || !snapshot.recoveryUnitFinal {
		return errors.New("corrected Host recovery unit is unavailable for bootstrap")
	}
	for _, unit := range manualHostRecoveryUnitInstances {
		state, pid, err := readManualHostUpgradeRecoveryServiceState(
			ctx, rt.runner, unit,
		)
		if err != nil || pid != 0 {
			return fmt.Errorf("%s is not safely quiescent", unit)
		}
		if state == "failed" {
			if _, err := rt.runner.Run(
				ctx, "/", nil, "/usr/bin/systemctl", "reset-failed", unit,
			); err != nil {
				return fmt.Errorf("reset failed bootstrap recovery unit %s", unit)
			}
		} else if state != "inactive" {
			return fmt.Errorf("%s is not inactive", unit)
		}
	}
	return validateManualHostUpgradeRecoveryServicePreconditions(ctx, rt, false)
}

func requireManualHostSystemdState(
	ctx context.Context,
	runner CommandRunner,
	operation, unit, expected string,
) error {
	output, err := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", operation, unit,
	)
	actual := strings.TrimSpace(output)
	if expected == "inactive" {
		if actual == expected {
			return nil
		}
	} else if err == nil && actual == expected {
		return nil
	}
	return fmt.Errorf("%s must be %s", unit, expected)
}
