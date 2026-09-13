//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func activateManualHostUpgrade(
	ctx context.Context,
	state HostSelfUpdateState,
	request HostSelfUpdateRequest,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ensureManualHostUpgradeDeadline(state, rt.now()); err != nil {
		return err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return err
	}
	if err := rt.selfUpdate.switchCurrent(state.PendingSlot); err != nil {
		return fmt.Errorf("switch manual Host runtime current slot: %w", err)
	}
	if err := rt.selfUpdate.restartLocalExecutor(ctx); err != nil {
		return err
	}
	executor, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			state.PendingSlot,
			"bin",
			"autostream-local-executor",
		),
		"autostream-local-executor",
		rt,
	)
	if err != nil {
		return fmt.Errorf(
			"new Local Executor failed live binary verification: %w",
			err,
		)
	}
	if executor.Version != request.ExecutorVersion ||
		executor.Commit != request.Commit ||
		executor.MutationProtocol != request.MutationProtocolVersion ||
		executor.RecoveryProtocol != request.RecoveryProtocolVersion {
		return errors.New(
			"new Local Executor failed live binary verification: runtime identity mismatch",
		)
	}
	if rt.selfUpdate.watchdogStatus == nil {
		return errors.New("Local Executor watchdog verification is unavailable")
	}
	watchdog, err := rt.selfUpdate.watchdogStatus(ctx)
	if err != nil || watchdog.State != state ||
		watchdog.CurrentSlot != state.PendingSlot ||
		watchdog.ExecutorVersion != request.ExecutorVersion ||
		watchdog.ExecutorProtocolVersion != request.ExecutorProtocolVersion {
		return errors.New("new Local Executor watchdog handshake is invalid")
	}
	if err := rt.selfUpdate.restartHostAgent(ctx); err != nil {
		return err
	}
	agent, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			state.PendingSlot,
			"bin",
			"autostream-host-agent",
		),
		"autostream-host-agent",
		rt,
	)
	if err != nil {
		return fmt.Errorf(
			"new Host Agent failed live binary verification: %w",
			err,
		)
	}
	if agent.Version != request.AgentVersion ||
		agent.Commit != request.Commit {
		return errors.New(
			"new Host Agent failed live binary verification: runtime identity mismatch",
		)
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return err
	}
	if err := ensureManualHostUpgradeDeadline(state, rt.now()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	committed := commitHostSelfUpdate(state)
	if err := rt.selfUpdate.saveState(committed); err != nil {
		return errors.New("commit manual Host runtime state")
	}
	return nil
}

func rollbackManualHostUpgrade(
	ctx context.Context,
	state HostSelfUpdateState,
	healthy manualHostRuntimeObservation,
	rt manualHostUpgradeRuntime,
) error {
	rollback := beginHostSelfUpdateRollback(state)
	if err := rt.selfUpdate.saveState(rollback); err != nil {
		return errors.New("persist manual Host runtime rollback fence")
	}
	if err := rt.selfUpdate.switchCurrent(rollback.HealthySlot); err != nil {
		return errors.New("restore healthy Host runtime current slot")
	}
	if err := rt.selfUpdate.restartLocalExecutor(ctx); err != nil {
		return errors.New("restart healthy Local Executor during rollback")
	}
	if err := rt.selfUpdate.verifyHealthyLocalExecutor(
		ctx, rollback.HealthySlot, rollback,
	); err != nil {
		return errors.New("verify healthy Local Executor during rollback")
	}
	if err := rt.selfUpdate.restartHostAgent(ctx); err != nil {
		return errors.New("restart healthy Host Agent during rollback")
	}
	actualAgent, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			rollback.HealthySlot,
			"bin",
			"autostream-host-agent",
		),
		"autostream-host-agent",
		rt,
	)
	if err != nil || actualAgent != healthy.Agent {
		return errors.New("verify healthy Host Agent during rollback")
	}
	restored := clearRolledBackHostSelfUpdate(rollback)
	if err := rt.selfUpdate.saveState(restored); err != nil {
		return errors.New("commit manual Host runtime rollback")
	}
	if err := rt.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return errors.New("clean manual Host runtime rollback artifacts")
	}
	if restored.ActiveAgentVersion != healthy.Agent.Version ||
		restored.ActiveExecutorVersion != healthy.Executor.Version {
		return errors.New("manual Host runtime rollback identity is inconsistent")
	}
	return nil
}

func acquireManualHostUpgradeLocks() (func(), error) {
	directory := privilegedLockDir()
	setupUnlock, err := AcquireHostRuntimeSetupLock()
	if err != nil {
		return func() {}, err
	}
	lifecycleUnlock, err := lockManualHostUpgradeFile(
		filepath.Join(directory, ".autostream-host-lifecycle.lock"),
	)
	if err != nil {
		setupUnlock()
		return func() {}, err
	}
	legacyInstallerUnlock, err := lockManualHostUpgradeFile(
		legacyUpdateHostInstallLockPath,
	)
	if err != nil {
		lifecycleUnlock()
		setupUnlock()
		return func() {}, err
	}
	return func() {
		legacyInstallerUnlock()
		lifecycleUnlock()
		setupUnlock()
	}, nil
}

func lockManualHostUpgradeFile(path string) (func(), error) {
	fd, err := syscall.Open(
		path,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return func() {}, err
	}
	file := os.NewFile(uintptr(fd), path)
	failure := func(err error) (func(), error) {
		_ = file.Close()
		return func() {}, err
	}
	var opened syscall.Stat_t
	if err := syscall.Fstat(fd, &opened); err != nil ||
		opened.Uid != 0 || opened.Gid != 0 || opened.Nlink != 1 ||
		opened.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		opened.Mode&0o777 != 0o600 {
		return failure(errors.New("privileged Host lifecycle lock file is unsafe"))
	}
	var named syscall.Stat_t
	if err := syscall.Lstat(path, &named); err != nil ||
		named.Dev != opened.Dev || named.Ino != opened.Ino {
		return failure(errors.New("privileged Host lifecycle lock identity changed"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return failure(errors.New("another privileged Host lifecycle operation is active"))
	}
	if err := syscall.Lstat(path, &named); err != nil ||
		named.Dev != opened.Dev || named.Ino != opened.Ino ||
		named.Uid != 0 || named.Gid != 0 || named.Nlink != 1 ||
		named.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		named.Mode&0o777 != 0o600 {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return failure(errors.New("privileged Host lifecycle lock changed after acquisition"))
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
