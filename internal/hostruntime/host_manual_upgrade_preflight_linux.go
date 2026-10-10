//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const manualHostUpgradePreflightAttempts = 3

type manualHostUpgradeRecoveryHandoff struct {
	cause     error
	preflight manualHostUpgradePreflight
}

func (e *manualHostUpgradeRecoveryHandoff) Error() string { return e.cause.Error() }
func (e *manualHostUpgradeRecoveryHandoff) Unwrap() error { return e.cause }

type manualHostUpgradePreflight struct {
	artifact    manualHostUpgradeArtifact
	snapshot    manualHostUpgradeSnapshot
	current     manualHostRuntimeObservation
	state       HostSelfUpdateState
	persisted   bool
	currentLink os.FileInfo
	slotFiles   []secureManualHostUpgradeFile
	locks       []manualHostUpgradePreflightLock
}

type manualHostUpgradePreflightLock struct {
	path string
	info os.FileInfo
}

func upgradeHostRuntimeWithRuntime(
	ctx context.Context,
	input ManualHostUpgradeRequest,
	rt manualHostUpgradeRuntime,
) (ManualHostUpgradeResult, error) {
	if err := prepareManualHostUpgradeRuntime(&rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	// This bounds preflight and its handoffs, within the existing CLI deadline.
	// The successful attempt keeps its locks and uses the original context for
	// the existing activation/rollback transaction; that transaction never retries.
	preflightCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var previous *manualHostUpgradePreflight
	for attempt := 1; attempt <= manualHostUpgradePreflightAttempts; attempt++ {
		if err := preflightCtx.Err(); err != nil {
			return ManualHostUpgradeResult{}, err
		}
		result, err := upgradeHostRuntimeAttempt(ctx, preflightCtx, input, rt, previous)
		var handoff *manualHostUpgradeRecoveryHandoff
		if !errors.As(err, &handoff) {
			return result, err
		}
		if attempt == manualHostUpgradePreflightAttempts {
			return ManualHostUpgradeResult{}, fmt.Errorf("Host recovery preflight attempt limit: %w", err)
		}
		// The attempt has returned through both deferred unlocks: target locks
		// first, then legacy/lifecycle/setup locks. No installation was changed.
		if err := waitManualHostUpgradeRecoveryQuiescent(
			preflightCtx, rt, !handoff.preflight.persisted &&
				handoff.preflight.snapshot.recoveryUnitConfig != nil,
		); err != nil {
			return ManualHostUpgradeResult{}, fmt.Errorf("Host recovery preflight did not settle: %w", err)
		}
		previous = &handoff.preflight
	}
	return ManualHostUpgradeResult{}, errors.New("Host recovery preflight attempt limit")
}

func waitManualHostUpgradeRecoveryQuiescent(
	ctx context.Context,
	rt manualHostUpgradeRuntime,
	allowFailedBootstrap bool,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := validateManualHostUpgradeRecoveryServicePreconditions(ctx, rt, allowFailedBootstrap)
		if err == nil {
			return nil
		}
		if !manualHostUpgradeRecoveryCanSettle(err) {
			return err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func captureManualHostUpgradePreflight(
	artifact manualHostUpgradeArtifact,
	snapshot manualHostUpgradeSnapshot,
	current manualHostRuntimeObservation,
	state HostSelfUpdateState,
	persisted bool,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradePreflight, error) {
	p := manualHostUpgradePreflight{
		artifact: artifact, snapshot: snapshot, current: current,
		state: state, persisted: persisted,
	}
	info, err := os.Lstat(rt.selfUpdate.currentLink)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return p, errors.New("Host current link is unavailable before preflight handoff")
	}
	p.currentLink = info
	if persisted {
		file, err := snapshotManualHostUpgradeFile(rt.selfUpdate.statePath)
		if err != nil {
			return p, err
		}
		p.slotFiles = append(p.slotFiles, file)
	} else {
		p.slotFiles = append(p.slotFiles, secureManualHostUpgradeFile{path: rt.selfUpdate.statePath})
	}
	// Retain fingerprints only as drift guards, never as the next attempt's
	// authority. Every attempt re-reads the archive, pair, units, policy, state,
	// blockers and target locks before reaching the mutation boundary.
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		root := filepath.Join(rt.selfUpdate.slotsRoot, slot)
		if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
			p.slotFiles = append(p.slotFiles, secureManualHostUpgradeFile{path: root})
			continue
		} else if err != nil {
			return p, errors.New("Host slot is unavailable before preflight handoff")
		}
		for _, binary := range []string{"autostream-host-agent", "autostream-local-executor"} {
			file, err := snapshotManualHostUpgradeFile(filepath.Join(root, "bin", binary))
			if err != nil {
				return p, err
			}
			p.slotFiles = append(p.slotFiles, file)
		}
	}
	if !rt.allowTestPaths {
		paths := append([]string{
			privilegedLockDir(),
			filepath.Join(privilegedLockDir(), ".autostream-runtime-host-setup.lock"),
			filepath.Join(privilegedLockDir(), ".autostream-host-lifecycle.lock"),
			legacyUpdateHostInstallLockPath,
		}, manualHostUpgradeTargetLockPaths(privilegedLockDir(), snapshot.executorPolicy,
			snapshot.legacyHelperConfig.Targets)...)
		for _, path := range paths {
			info, err := os.Lstat(path)
			if err != nil {
				return p, errors.New("Host preflight lock is unavailable")
			}
			p.locks = append(p.locks, manualHostUpgradePreflightLock{path: path, info: info})
		}
	}
	return p, nil
}

func verifyManualHostUpgradePreflightLocks(locks []manualHostUpgradePreflightLock) error {
	for _, lock := range locks {
		info, err := os.Lstat(lock.path)
		if err != nil || !os.SameFile(lock.info, info) || info.Mode() != lock.info.Mode() ||
			!isRootOwner(info) {
			return errors.New("Host preflight lock identity changed during handoff")
		}
	}
	return nil
}

func (p manualHostUpgradePreflight) verify(
	ctx context.Context,
	artifact manualHostUpgradeArtifact,
	snapshot manualHostUpgradeSnapshot,
	current manualHostRuntimeObservation,
	state HostSelfUpdateState,
	persisted bool,
	rt manualHostUpgradeRuntime,
) error {
	if artifact != p.artifact || current != p.current || state != p.state || persisted != p.persisted {
		return errors.New("Host archive, pair, slot or durable state changed during preflight handoff")
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, p.snapshot, rt); err != nil {
		return err
	}
	// Also verify the fresh snapshot; old fingerprints above can only reject.
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return err
	}
	info, err := os.Lstat(rt.selfUpdate.currentLink)
	if err != nil || !os.SameFile(p.currentLink, info) {
		return errors.New("Host current link changed during preflight handoff")
	}
	for _, file := range p.slotFiles {
		if file.info == nil {
			if _, err := os.Lstat(file.path); !errors.Is(err, os.ErrNotExist) {
				return errors.New("Host slot appeared during preflight handoff")
			}
		} else if !manualHostUpgradeProtectedFileMatches(file) {
			return errors.New("Host slot binary changed during preflight handoff")
		}
	}
	return verifyManualHostUpgradePreflightLocks(p.locks)
}
