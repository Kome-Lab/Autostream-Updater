//go:build linux

package hostruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const softwareClaimRecoveryBootstrapCommit = "b1c94afe2ee2fe8854abb12e2c85565a1bd448dc"

type softwareClaimWatchdogAuthorityError struct{ reason string }

func (e softwareClaimWatchdogAuthorityError) Error() string {
	return "software claim watchdog authority is unconfirmed"
}
func softwareClaimWatchdogRefusal(reason string) error {
	return softwareClaimWatchdogAuthorityError{reason: reason}
}

// This snapshot is private to one read-only operation under the actual held
// permanent lifecycle lock. A service state label never mints this authority.
type softwareClaimRecoveryWatchdogSnapshot struct {
	unit         softwareClaimRecoveryUnitSnapshot
	files        []secureManualHostUpgradeFile
	directories  []secureManualHostUpgradeDirectory
	absentSlots  []string
	unboundSlots []string
	current      secureManualHostUpgradeLink
	state        HostSelfUpdateState
}

func inspectSoftwareClaimRecoveryWatchdogs(ctx context.Context, rt manualHostUpgradeRuntime, observed manualHostRuntimeObservation, held *heldHostLifecycleLock) (softwareClaimRecoveryWatchdogSnapshot, error) {
	var result softwareClaimRecoveryWatchdogSnapshot
	if ctx.Err() != nil || held == nil || held.Verify() != nil || held.allowTestPaths != rt.allowTestPaths {
		return result, softwareClaimWatchdogRefusal("lifecycle_capability")
	}
	if !rt.allowTestPaths && (rt.selfUpdate.installRoot != HostSelfUpdateInstallRoot || rt.selfUpdate.slotsRoot != HostSelfUpdateSlotsRoot || rt.selfUpdate.currentLink != HostSelfUpdateCurrentLink || rt.selfUpdate.statePath != HostSelfUpdateStatePath) {
		return result, softwareClaimWatchdogRefusal("slot_paths")
	}
	state, err := rt.selfUpdate.loadPersistedState()
	if err != nil || state.validate() != nil || state.Phase != HostSelfUpdatePhaseStable || state.ActiveSlot != observed.Slot || state.HealthySlot != observed.Slot || state.ActiveAgentVersion != observed.Agent.Version || state.ActiveExecutorVersion != observed.Executor.Version || observed.Agent.Commit != observed.Executor.Commit || !observed.Agent.BuildDate.Equal(observed.Executor.BuildDate) {
		return result, softwareClaimWatchdogRefusal("slot_state")
	}
	result.state = state
	for _, path := range []string{rt.selfUpdate.installRoot, rt.selfUpdate.slotsRoot} {
		directory, err := snapshotManualHostUpgradeDirectory(path, 0o755, rt.allowTestPaths)
		if err != nil {
			return result, softwareClaimWatchdogRefusal("slot_directory")
		}
		result.directories = append(result.directories, directory)
	}
	currentSlot, err := rt.selfUpdate.readCurrentSlot()
	if err != nil || currentSlot != observed.Slot {
		return result, softwareClaimWatchdogRefusal("slot_current")
	}
	currentTarget, err := os.Readlink(rt.selfUpdate.currentLink)
	if err != nil {
		return result, softwareClaimWatchdogRefusal("slot_current")
	}
	result.current, err = snapshotManualHostUpgradePublicLink(rt.selfUpdate.currentLink, currentTarget, rt.allowTestPaths)
	if err != nil {
		return result, softwareClaimWatchdogRefusal("slot_current")
	}
	stateFile, err := snapshotSoftwareClaimWatchdogFile(ctx, rt.selfUpdate.statePath, 0o600, rt.allowTestPaths)
	if err != nil {
		return result, err
	}
	result.files = append(result.files, stateFile)
	if err := rejectManualHostUpgradeTransitionResidue(rt.selfUpdate); err != nil {
		return result, softwareClaimWatchdogRefusal("slot_residue")
	}
	result.unit, err = inspectSoftwareClaimRecoveryWatchdogUnit(ctx, rt)
	if err != nil {
		return result, err
	}
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		root := filepath.Join(rt.selfUpdate.slotsRoot, slot)
		if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
			if slot == observed.Slot || state.RollbackSlot == slot {
				return result, softwareClaimWatchdogRefusal("slot_missing")
			}
			result.absentSlots = append(result.absentSlots, root)
			continue
		} else if err != nil || rt.selfUpdate.validateHostSelfUpdateSlotTree(slot) != nil {
			return result, softwareClaimWatchdogRefusal("slot_directory")
		}
		for _, path := range []string{root, filepath.Join(root, "bin")} {
			directory, err := snapshotManualHostUpgradeDirectory(path, 0o755, rt.allowTestPaths)
			if err != nil {
				return result, softwareClaimWatchdogRefusal("slot_directory")
			}
			result.directories = append(result.directories, directory)
		}
		pair := []manualHostBinaryIdentity{observed.Agent, observed.Executor}
		binaryDigests := map[string]string{}
		for _, name := range []string{"autostream-host-agent", "autostream-local-executor"} {
			file, err := snapshotSoftwareClaimWatchdogFile(ctx, filepath.Join(root, "bin", name), 0o755, rt.allowTestPaths)
			if err != nil {
				return result, err
			}
			result.files = append(result.files, file)
			binaryDigests[name] = file.digest
		}
		if slot != observed.Slot {
			identityCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
			pair[0], err = readManualHostBinaryIdentity(identityCtx, filepath.Join(root, "bin", "autostream-host-agent"), "autostream-host-agent", rt.identityRunner)
			if err == nil {
				pair[1], err = readManualHostBinaryIdentity(identityCtx, filepath.Join(root, "bin", "autostream-local-executor"), "autostream-local-executor", rt.identityRunner)
			}
			cancel()
			if err != nil {
				return result, softwareClaimWatchdogRefusal("slot_identity")
			}
		}
		if pair[0].Version != pair[1].Version || pair[0].Commit != pair[1].Commit || !pair[0].BuildDate.Equal(pair[1].BuildDate) || pair[1].MutationProtocol != LocalExecutorMutationProtocolVersion || pair[1].RecoveryProtocol != HostSelfUpdateRecoveryProtocolVersion {
			return result, softwareClaimWatchdogRefusal("slot_identity")
		}
		bound, err := rt.selfUpdate.hostSelfUpdateSlotHasBinding(slot)
		if err != nil {
			return result, softwareClaimWatchdogRefusal("slot_binding")
		}
		if !bound {
			if slot != HostSelfUpdateSlotA || pair[0].Version != "v2.0.0" || pair[0].Commit != softwareClaimRecoveryBootstrapCommit || (slot != observed.Slot && (state.RollbackSlot != slot || state.RollbackAgentVersion != pair[0].Version || state.RollbackExecutorVersion != pair[1].Version)) {
				return result, softwareClaimWatchdogRefusal("slot_bootstrap")
			}
			result.unboundSlots = append(result.unboundSlots, slot)
		} else {
			request, digests, err := readManualHostUpdateSlotBinding(slot, rt.selfUpdate)
			if err != nil || request.AgentVersion != pair[0].Version || request.ExecutorVersion != pair[1].Version || request.Commit != pair[0].Commit {
				return result, softwareClaimWatchdogRefusal("slot_binding")
			}
			// Retain the existing request/protocol, pair identity, binary digest
			// and every marker check using these actual bounded FD snapshots.
			// Reopening the files through the manual path would hash without
			// this read-only operation's deadline.
			if request.validate() != nil || digests.validate() != nil || binaryDigests["autostream-host-agent"] != digests.AgentSHA256 || binaryDigests["autostream-local-executor"] != digests.ExecutorSHA256 {
				return result, softwareClaimWatchdogRefusal("slot_binding")
			}
			markers, err := hostSelfUpdateSlotMarkers(request, map[string]string{"autostream-host-agent": digests.AgentSHA256, "autostream-local-executor": digests.ExecutorSHA256})
			if err != nil {
				return result, softwareClaimWatchdogRefusal("slot_binding")
			}
			for name, body := range markers {
				file, err := snapshotSoftwareClaimWatchdogFile(ctx, filepath.Join(root, name), 0o444, rt.allowTestPaths)
				if err != nil || file.digest != fmt.Sprintf("%x", sha256.Sum256(body)) {
					return result, softwareClaimWatchdogRefusal("slot_binding")
				}
				result.files = append(result.files, file)
			}
		}
	}
	if err := verifySoftwareClaimRecoveryWatchdogProcesses(ctx, rt, result.unit.units, held, result.absentSlots, result.files); err != nil {
		return result, err
	}
	if ctx.Err() != nil || held.Verify() != nil {
		return result, softwareClaimWatchdogRefusal("lifecycle_capability")
	}
	return result, nil
}

func (s softwareClaimRecoveryWatchdogSnapshot) Verify(ctx context.Context, rt manualHostUpgradeRuntime, held *heldHostLifecycleLock) error {
	if ctx.Err() != nil || held == nil || held.Verify() != nil || held.allowTestPaths != rt.allowTestPaths {
		return softwareClaimWatchdogRefusal("lifecycle_capability")
	}
	for _, file := range s.files {
		if ctx.Err() != nil {
			return softwareClaimWatchdogRefusal("slot_snapshot")
		}
		current, err := snapshotSoftwareClaimWatchdogFile(ctx, file.path, file.info.Mode().Perm(), rt.allowTestPaths)
		if err != nil || !os.SameFile(file.info, current.info) || file.info.Mode() != current.info.Mode() || file.info.Size() != current.info.Size() || file.digest != current.digest {
			return softwareClaimWatchdogRefusal("slot_snapshot")
		}
	}
	for _, directory := range s.directories {
		if !manualHostUpgradeDirectoryMatches(directory, rt.allowTestPaths) {
			return softwareClaimWatchdogRefusal("slot_snapshot")
		}
	}
	for _, path := range s.absentSlots {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return softwareClaimWatchdogRefusal("slot_snapshot")
		}
	}
	for _, slot := range s.unboundSlots {
		if bound, err := rt.selfUpdate.hostSelfUpdateSlotHasBinding(slot); err != nil || bound {
			return softwareClaimWatchdogRefusal("slot_binding")
		}
	}
	current, err := snapshotManualHostUpgradePublicLink(s.current.path, s.current.target, rt.allowTestPaths)
	if err != nil || !os.SameFile(current.info, s.current.info) {
		return softwareClaimWatchdogRefusal("slot_current")
	}
	state, err := rt.selfUpdate.loadPersistedState()
	if err != nil || state != s.state {
		return softwareClaimWatchdogRefusal("slot_state")
	}
	if err := s.unit.Verify(ctx, rt); err != nil {
		return err
	}
	units, err := readSoftwareClaimRecoveryWatchdogUnits(ctx, rt)
	if err != nil {
		return err
	}
	if err := verifySoftwareClaimRecoveryWatchdogProcesses(ctx, rt, units, held, s.absentSlots, s.files); err != nil {
		return err
	}
	return held.Verify()
}
