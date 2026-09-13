//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func ensureManualHostUpgradeDeadline(
	state HostSelfUpdateState,
	now time.Time,
) error {
	if state.ActivationDeadline.IsZero() ||
		!now.UTC().Before(state.ActivationDeadline) {
		return errors.New("manual Host runtime activation deadline expired")
	}
	return nil
}

func observeManualHostRuntime(
	ctx context.Context,
	slot string,
	rt manualHostUpgradeRuntime,
) (manualHostRuntimeObservation, error) {
	return observeManualHostRuntimeForUpgrade(ctx, slot, false, rt)
}

func observeManualHostRuntimeForUpgrade(
	ctx context.Context,
	slot string,
	agentStoppedForRecovery bool,
	rt manualHostUpgradeRuntime,
) (manualHostRuntimeObservation, error) {
	if err := rt.selfUpdate.validateHostSelfUpdateSlotTree(slot); err != nil {
		return manualHostRuntimeObservation{}, errors.New(
			"managed Host runtime active slot is unsafe",
		)
	}
	root := filepath.Join(rt.selfUpdate.slotsRoot, slot, "bin")
	agentPath := filepath.Join(root, "autostream-host-agent")
	var agent manualHostBinaryIdentity
	var err error
	if agentStoppedForRecovery {
		agent, err = verifyStoppedManualHostAgentIdentity(ctx, agentPath, rt)
	} else {
		agent, err = verifyManualHostUnitProcess(
			ctx,
			hostSelfUpdateServiceUnit,
			agentPath,
			"autostream-host-agent",
			rt,
		)
	}
	if err != nil {
		return manualHostRuntimeObservation{}, err
	}
	executor, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		filepath.Join(root, "autostream-local-executor"),
		"autostream-local-executor",
		rt,
	)
	if err != nil {
		return manualHostRuntimeObservation{}, err
	}
	if executor.MutationProtocol != LocalExecutorMutationProtocolVersion ||
		executor.RecoveryProtocol != HostSelfUpdateRecoveryProtocolVersion {
		return manualHostRuntimeObservation{}, errors.New(
			"installed Local Executor protocol identity is incompatible",
		)
	}
	if agent.Version != executor.Version ||
		agent.Commit != executor.Commit ||
		!agent.BuildDate.Equal(executor.BuildDate) {
		return manualHostRuntimeObservation{}, errors.New(
			"installed Host Agent and Local Executor are a mixed runtime",
		)
	}
	return manualHostRuntimeObservation{
		Slot: slot, Agent: agent, Executor: executor,
	}, nil
}

func verifyStoppedManualHostAgentIdentity(
	ctx context.Context,
	expectedPath string,
	rt manualHostUpgradeRuntime,
) (manualHostBinaryIdentity, error) {
	readInfo := func() (os.FileInfo, error) {
		info, err := os.Lstat(expectedPath)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o755 ||
			(!rt.allowTestPaths && !isRootOwner(info)) {
			return nil, errors.New("stopped Host Agent binary is unsafe")
		}
		return info, nil
	}
	sameInfo := func(first, second os.FileInfo) bool {
		return os.SameFile(first, second) &&
			first.Mode() == second.Mode() &&
			first.Size() == second.Size() &&
			first.ModTime().Equal(second.ModTime())
	}

	firstInfo, err := readInfo()
	if err != nil {
		return manualHostBinaryIdentity{}, err
	}
	first, err := readManualHostBinaryIdentity(
		ctx,
		expectedPath,
		"autostream-host-agent",
		rt.identityRunner,
	)
	if err != nil {
		return manualHostBinaryIdentity{}, err
	}
	if err := rt.waitStable(ctx); err != nil {
		return manualHostBinaryIdentity{}, fmt.Errorf(
			"wait for stopped Host Agent identity stability: %w",
			err,
		)
	}
	secondInfo, err := readInfo()
	if err != nil || !sameInfo(firstInfo, secondInfo) {
		return manualHostBinaryIdentity{}, errors.New(
			"stopped Host Agent binary changed during identity verification",
		)
	}
	second, err := readManualHostBinaryIdentity(
		ctx,
		expectedPath,
		"autostream-host-agent",
		rt.identityRunner,
	)
	if err != nil {
		return manualHostBinaryIdentity{}, err
	}
	finalInfo, err := readInfo()
	if err != nil || !sameInfo(firstInfo, finalInfo) || first != second {
		return manualHostBinaryIdentity{}, errors.New(
			"stopped Host Agent identity changed during verification",
		)
	}
	return first, nil
}

func verifyManualHostUnitProcess(
	ctx context.Context,
	unit, expectedPath, binaryName string,
	rt manualHostUpgradeRuntime,
) (manualHostBinaryIdentity, error) {
	type processObservation struct {
		pid        int
		executable string
	}
	readProcess := func() (processObservation, error) {
		if err := ctx.Err(); err != nil {
			return processObservation{}, fmt.Errorf(
				"verify Host runtime process: %w",
				err,
			)
		}
		if err := requireManualHostSystemdState(
			ctx, rt.runner, "is-active", unit, "active",
		); err != nil {
			return processObservation{}, err
		}
		output, err := rt.runner.Run(
			ctx, "/", nil, "/usr/bin/systemctl", "show",
			"--property=MainPID", "--value", unit,
		)
		if err != nil {
			return processObservation{}, errors.New("read Host runtime MainPID")
		}
		pid, err := strconv.Atoi(strings.TrimSpace(output))
		if err != nil || pid <= 0 {
			return processObservation{}, errors.New("Host runtime unit has no MainPID")
		}
		executable, err := rt.resolveProcessExe(pid)
		if err != nil {
			return processObservation{}, errors.New(
				"resolve Host runtime unit executable",
			)
		}
		return processObservation{pid: pid, executable: executable}, nil
	}
	expectedPath = filepath.Clean(expectedPath)
	pinnedPID := 0
	first := processObservation{}
	for probe := 0; probe < hostSelfUpdateSystemdExecutorProbes; probe++ {
		observed, err := readProcess()
		if err != nil {
			return manualHostBinaryIdentity{}, err
		}
		if pinnedPID == 0 {
			pinnedPID = observed.pid
		} else if observed.pid != pinnedPID {
			return manualHostBinaryIdentity{}, errors.New(
				"Host runtime MainPID changed during systemd-executor transition",
			)
		}
		if filepath.Clean(observed.executable) == expectedPath {
			first = observed
			break
		}
		if !isHostRuntimeSystemdExecutor(observed.executable) {
			return manualHostBinaryIdentity{}, errors.New(
				"Host runtime unit is executing outside the selected slot",
			)
		}
		if probe+1 == hostSelfUpdateSystemdExecutorProbes {
			return manualHostBinaryIdentity{}, errors.New(
				"Host runtime unit remained in systemd-executor beyond the startup probe limit",
			)
		}
		if err := rt.waitStable(ctx); err != nil {
			return manualHostBinaryIdentity{}, fmt.Errorf(
				"wait for Host runtime systemd-executor transition: %w",
				err,
			)
		}
	}
	if err := rt.waitStable(ctx); err != nil {
		return manualHostBinaryIdentity{}, fmt.Errorf(
			"wait for Host runtime process stability: %w",
			err,
		)
	}
	second, err := readProcess()
	if err != nil {
		return manualHostBinaryIdentity{}, err
	}
	if first.pid != second.pid {
		return manualHostBinaryIdentity{}, errors.New(
			"Host runtime MainPID changed during stability verification",
		)
	}
	if filepath.Clean(second.executable) != expectedPath {
		return manualHostBinaryIdentity{}, errors.New(
			"Host runtime unit is executing outside the selected slot",
		)
	}
	return readManualHostBinaryIdentity(
		ctx, expectedPath, binaryName, rt.identityRunner,
	)
}
