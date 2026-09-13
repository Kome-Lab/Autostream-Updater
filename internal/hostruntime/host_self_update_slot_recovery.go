package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (rt hostSelfUpdateExecutorRuntime) recoverHostSelfUpdateSlotArtifacts() error {
	entries, err := os.ReadDir(rt.slotsRoot)
	if err != nil {
		return err
	}
	type artifacts struct {
		newPaths []string
		oldPaths []string
	}
	bySlot := map[string]*artifacts{
		HostSelfUpdateSlotA: {},
		HostSelfUpdateSlotB: {},
	}
	for _, entry := range entries {
		slot, suffix, ok := parseHostSelfUpdateSlotArtifactName(entry.Name())
		if !ok {
			if looksLikeReservedHostSelfUpdateSlotArtifactName(entry.Name()) {
				return errors.New(
					"host self-update slot artifact name is malformed",
				)
			}
			continue
		}
		info, err := entry.Info()
		if err != nil ||
			!info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			(runtime.GOOS != "windows" &&
				info.Mode().Perm()&0o022 != 0) ||
			(!rt.allowTestPaths && !isRootOwner(info)) {
			return errors.New("host self-update slot artifact is unsafe")
		}
		path := filepath.Join(rt.slotsRoot, entry.Name())
		if !pathWithin(rt.slotsRoot, path) {
			return errors.New("host self-update slot artifact escaped the slots root")
		}
		if suffix == "new" {
			bySlot[slot].newPaths = append(bySlot[slot].newPaths, path)
		} else {
			bySlot[slot].oldPaths = append(bySlot[slot].oldPaths, path)
		}
	}
	for _, slot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		if len(bySlot[slot].newPaths) > 1 ||
			len(bySlot[slot].oldPaths) > 1 {
			return errors.New(
				"multiple host self-update slot artifacts require manual recovery",
			)
		}
	}
	var (
		recoveryState       *HostSelfUpdateState
		recoveryStateLoaded bool
	)
	loadRecoveryState := func() (*HostSelfUpdateState, error) {
		if recoveryStateLoaded {
			return recoveryState, nil
		}
		recoveryStateLoaded = true
		state, err := rt.loadPersistedState()
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		recoveryState = &state
		return recoveryState, nil
	}
	for _, slot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		slotArtifacts := bySlot[slot]
		slotRoot := filepath.Join(rt.slotsRoot, slot)
		info, slotErr := os.Lstat(slotRoot)
		switch {
		case slotErr == nil:
			if !info.IsDir() ||
				info.Mode()&os.ModeSymlink != 0 ||
				(runtime.GOOS != "windows" &&
					info.Mode().Perm()&0o022 != 0) ||
				(!rt.allowTestPaths && !isRootOwner(info)) {
				return errors.New("host self-update slot is unsafe")
			}
			if len(slotArtifacts.oldPaths) == 1 {
				state, err := loadRecoveryState()
				if err != nil {
					return fmt.Errorf(
						"load host self-update state for slot recovery: %w",
						err,
					)
				}
				if state == nil {
					return errors.New(
						"host self-update slot backup requires durable state",
					)
				}
				switch {
				case state.Phase == HostSelfUpdatePhaseStable &&
					slot != state.ActiveSlot:
					if len(slotArtifacts.newPaths) != 0 {
						return errors.New(
							"ambiguous host self-update candidate recovery requires manual recovery",
						)
					}
					if err := rt.restoreUncommittedHostSelfUpdateSlot(
						slotRoot,
						slotArtifacts.oldPaths[0],
					); err != nil {
						return err
					}
					slotArtifacts.oldPaths = nil
				case state.Phase != HostSelfUpdatePhaseStable &&
					slot == state.PendingSlot:
					if err := rt.verifyPendingHostSelfUpdateSlotForRecovery(
						*state,
						slotRoot,
					); err != nil {
						return fmt.Errorf(
							"pending host self-update slot cannot release its backup: %w",
							err,
						)
					}
				case slot == state.ActiveSlot &&
					slot == state.HealthySlot:
					// A live healthy slot is authoritative. The backup is a
					// stale artifact from an already durable prior transaction.
				default:
					return errors.New(
						"host self-update slot backup contradicts durable state",
					)
				}
			} else {
				state, err := loadRecoveryState()
				if err != nil {
					return fmt.Errorf(
						"load host self-update state for slot recovery: %w",
						err,
					)
				}
				if state != nil &&
					state.Phase != HostSelfUpdatePhaseStable &&
					slot == state.PendingSlot {
					if err := rt.verifyPendingHostSelfUpdateSlotForRecovery(
						*state,
						slotRoot,
					); err != nil {
						return fmt.Errorf(
							"pending host self-update slot is invalid: %w",
							err,
						)
					}
				}
			}
		case errors.Is(slotErr, os.ErrNotExist):
			if len(slotArtifacts.oldPaths) == 1 {
				if err := os.Rename(
					slotArtifacts.oldPaths[0],
					slotRoot,
				); err != nil {
					return err
				}
				if err := rt.syncHostSelfUpdateDirectory(
					rt.slotsRoot,
				); err != nil {
					return err
				}
				slotArtifacts.oldPaths = nil
			} else {
				state, err := loadRecoveryState()
				if err != nil {
					return fmt.Errorf(
						"load host self-update state for slot recovery: %w",
						err,
					)
				}
				if state != nil &&
					state.Phase != HostSelfUpdatePhaseStable &&
					slot == state.PendingSlot {
					if len(slotArtifacts.newPaths) != 1 {
						return errors.New(
							"pending host self-update slot candidate is unavailable",
						)
					}
					temporary := filepath.Join(
						rt.slotsRoot,
						"."+slot+"-"+shortID(state.PendingGeneration)+".new",
					)
					if filepath.Clean(slotArtifacts.newPaths[0]) !=
						filepath.Clean(temporary) {
						return errors.New(
							"pending host self-update slot candidate contradicts durable state",
						)
					}
					if err := rt.verifyPendingHostSelfUpdateSlotForRecovery(
						*state,
						temporary,
					); err != nil {
						return fmt.Errorf(
							"pending host self-update slot candidate is invalid: %w",
							err,
						)
					}
					if err := os.Rename(temporary, slotRoot); err != nil {
						return err
					}
					if err := rt.syncHostSelfUpdateDirectory(
						rt.slotsRoot,
					); err != nil {
						return fmt.Errorf(
							"sync promoted host self-update slot: %w",
							err,
						)
					}
					if err := rt.verifyPendingHostSelfUpdateSlotForRecovery(
						*state,
						slotRoot,
					); err != nil {
						return fmt.Errorf(
							"promoted host self-update slot is invalid: %w",
							err,
						)
					}
					slotArtifacts.newPaths = nil
				}
			}
		default:
			return slotErr
		}
		for _, artifact := range append(
			slotArtifacts.newPaths,
			slotArtifacts.oldPaths...,
		) {
			if err := rt.removeHostSelfUpdateSlotArtifact(artifact); err != nil {
				return err
			}
		}
	}
	return rt.syncHostSelfUpdateDirectory(rt.slotsRoot)
}

func (rt hostSelfUpdateExecutorRuntime) restoreUncommittedHostSelfUpdateSlot(
	slotRoot string,
	backup string,
) error {
	if filepath.Dir(filepath.Clean(slotRoot)) != filepath.Clean(rt.slotsRoot) ||
		filepath.Dir(filepath.Clean(backup)) != filepath.Clean(rt.slotsRoot) ||
		!strings.HasSuffix(backup, ".old") {
		return errors.New("host self-update recovery paths are invalid")
	}
	temporary := strings.TrimSuffix(backup, ".old") + ".new"
	if _, err := os.Lstat(temporary); err == nil {
		return errors.New(
			"host self-update recovery quarantine already exists",
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := rt.restoreHostSelfUpdateSlot(
		slotRoot,
		temporary,
		backup,
		true,
	); err != nil {
		return err
	}
	return rt.removeHostSelfUpdateSlotArtifact(temporary)
}

func (rt hostSelfUpdateExecutorRuntime) verifyPendingHostSelfUpdateSlotForRecovery(
	state HostSelfUpdateState,
	slotRoot string,
) error {
	if state.Phase == HostSelfUpdatePhaseStable ||
		!validHostSelfUpdateSlot(state.PendingSlot) ||
		!pathWithin(rt.slotsRoot, slotRoot) ||
		(filepath.Clean(slotRoot) !=
			filepath.Join(rt.slotsRoot, state.PendingSlot) &&
			filepath.Dir(filepath.Clean(slotRoot)) !=
				filepath.Clean(rt.slotsRoot)) {
		return errors.New("pending host self-update recovery state is invalid")
	}
	request := HostSelfUpdateRequest{
		Generation:              state.PendingGeneration,
		AgentVersion:            state.PendingAgentVersion,
		ExecutorVersion:         state.PendingExecutorVersion,
		Commit:                  state.PendingCommit,
		ArtifactSHA256:          state.PendingArtifactSHA256,
		AgentProtocolVersion:    state.PendingAgentProtocol,
		ExecutorProtocolVersion: state.PendingExecutorProtocol,
		MutationProtocolVersion: state.PendingMutationProtocol,
		RecoveryProtocolVersion: state.PendingRecoveryProtocol,
		Release:                 state.PendingRelease,
	}
	ctx, cancel := rt.hostSelfUpdateDetachedVerificationContext()
	defer cancel()
	return rt.verifyHostSelfUpdateSlot(
		ctx,
		state.PendingSlot,
		slotRoot,
		request,
		hostSelfUpdateSlotDigests{
			AgentSHA256:    state.PendingAgentSHA256,
			ExecutorSHA256: state.PendingExecutorSHA256,
		},
	)
}

func (rt hostSelfUpdateExecutorRuntime) hostSelfUpdateDetachedVerificationContext() (
	context.Context,
	context.CancelFunc,
) {
	parent := rt.verificationParent
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, hostSelfUpdateDetachedVerifyTimeout)
}

func parseHostSelfUpdateSlotArtifactName(
	name string,
) (string, string, bool) {
	for _, slot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		prefix := "." + slot + "-"
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		for _, suffix := range []string{"new", "old"} {
			ending := "." + suffix
			if !strings.HasSuffix(name, ending) {
				continue
			}
			digest := strings.TrimSuffix(
				strings.TrimPrefix(name, prefix),
				ending,
			)
			if len(digest) != 12 {
				return "", "", false
			}
			for _, character := range digest {
				if (character < '0' || character > '9') &&
					(character < 'a' || character > 'f') {
					return "", "", false
				}
			}
			return slot, suffix, true
		}
	}
	return "", "", false
}

func looksLikeReservedHostSelfUpdateSlotArtifactName(name string) bool {
	for _, slot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		if strings.HasPrefix(name, "."+slot+"-") &&
			(strings.HasSuffix(name, ".new") ||
				strings.HasSuffix(name, ".old")) {
			return true
		}
	}
	return false
}
