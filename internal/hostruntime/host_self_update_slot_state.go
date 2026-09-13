package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func (rt hostSelfUpdateExecutorRuntime) switchCurrent(slot string) error {
	return rt.replaceCurrent(slot, false)
}

// reconstructCurrent is reserved for the root-owned fixed-slot watchdog. It
// deliberately does not inspect or follow the existing current path: recovery
// must remain possible when a power loss leaves that path missing, malformed,
// dangling, or replaced by a non-symlink. The final rename is atomic.
func (rt hostSelfUpdateExecutorRuntime) reconstructCurrent(slot string) error {
	return rt.replaceCurrent(slot, true)
}

func (rt hostSelfUpdateExecutorRuntime) replaceCurrent(
	slot string,
	replaceMalformed bool,
) error {
	if rt.switchCurrentHook != nil {
		return rt.switchCurrentHook(slot)
	}
	if !validHostSelfUpdateSlot(slot) {
		return errors.New("host self-update target slot is invalid")
	}
	if err := rt.validateHostSelfUpdateSlotTree(slot); err != nil {
		return err
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	temporary := filepath.Join(
		rt.installRoot, ".current-"+slot+"-"+shortID(slotRoot)+".new",
	)
	if !pathWithin(rt.installRoot, temporary) {
		return errors.New("host self-update temporary link escaped install root")
	}
	_ = os.Remove(temporary)
	relativeTarget, err := filepath.Rel(rt.installRoot, slotRoot)
	if err != nil || strings.HasPrefix(relativeTarget, "..") {
		return errors.New("host self-update slot cannot be linked")
	}
	if err := os.Symlink(relativeTarget, temporary); err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if !replaceMalformed {
		if current, err := os.Lstat(rt.currentLink); err == nil {
			if current.Mode()&os.ModeSymlink == 0 {
				return errors.New("host self-update current path is not a symlink")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(temporary, rt.currentLink); err != nil {
		return err
	}
	remove = false
	return syncDirectory(rt.installRoot)
}

func (rt hostSelfUpdateExecutorRuntime) readCurrentSlot() (string, error) {
	info, err := os.Lstat(rt.currentLink)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("host self-update current symlink is unavailable")
	}
	if !rt.allowTestPaths && !isRootOwner(info) {
		return "", errors.New("host self-update current symlink is not root-owned")
	}
	target, err := os.Readlink(rt.currentLink)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(rt.currentLink), target)
	}
	target = filepath.Clean(target)
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if target == filepath.Join(rt.slotsRoot, slot) {
			if err := rt.validateHostSelfUpdateSlotDirectory(
				slot,
			); err != nil {
				return "", err
			}
			return slot, nil
		}
	}
	return "", errors.New("host self-update current symlink points outside fixed slots")
}

func (rt hostSelfUpdateExecutorRuntime) validateHostSelfUpdateSlotDirectory(
	slot string,
) error {
	if !validHostSelfUpdateSlot(slot) {
		return errors.New("host self-update target slot is invalid")
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	if !pathWithin(rt.slotsRoot, slotRoot) {
		return errors.New("host self-update target slot escaped the slots root")
	}
	info, err := os.Lstat(slotRoot)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" &&
			info.Mode().Perm() != 0o755) {
		return errors.New("host self-update target slot is unavailable or unsafe")
	}
	if !rt.allowTestPaths && !isRootOwner(info) {
		return errors.New("host self-update target slot is not root-owned")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) validateHostSelfUpdateSlotTree(
	slot string,
) error {
	if err := rt.validateHostSelfUpdateSlotDirectory(slot); err != nil {
		return err
	}
	return rt.validateHostSelfUpdateSlotTreeRoot(
		filepath.Join(rt.slotsRoot, slot),
	)
}

func (rt hostSelfUpdateExecutorRuntime) validateHostSelfUpdateSlotTreeRoot(
	slotRoot string,
) error {
	info, err := os.Lstat(slotRoot)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o755) ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return errors.New("host self-update slot directory is unsafe")
	}
	binRoot := filepath.Join(slotRoot, "bin")
	if !pathWithin(slotRoot, binRoot) {
		return errors.New("host self-update slot bin escaped its root")
	}
	info, err = os.Lstat(binRoot)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o755) ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return errors.New("host self-update slot bin directory is unsafe")
	}
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		if err := validateHostSelfUpdateSlotBinary(
			filepath.Join(binRoot, binary),
			!rt.allowTestPaths,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateHostSelfUpdateSlotBinary(
	path string,
	requireRootOwner bool,
) error {
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o755) ||
		(requireRootOwner && !isRootOwner(info)) {
		return errors.New("host self-update slot binary is unsafe")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) loadState(
	currentSlot string,
) (HostSelfUpdateState, error) {
	state, err := rt.loadPersistedState()
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return HostSelfUpdateState{}, err
	}
	if currentSlot != HostSelfUpdateSlotA {
		return HostSelfUpdateState{}, errors.New(
			"host self-update state is unavailable for a non-bootstrap slot",
		)
	}
	hasBinding, err := rt.hostSelfUpdateSlotHasBinding(currentSlot)
	if err != nil {
		return HostSelfUpdateState{}, err
	}
	if hasBinding {
		return HostSelfUpdateState{}, errors.New(
			"host self-update state is unavailable for a bound slot",
		)
	}
	state, stateErr := NewHostSelfUpdateState(
		rt.executorVersion, rt.executorVersion,
	)
	if stateErr != nil {
		return HostSelfUpdateState{}, stateErr
	}
	state.ActiveSlot = currentSlot
	state.HealthySlot = currentSlot
	if err := rt.saveState(state); err != nil {
		return HostSelfUpdateState{}, err
	}
	return state, nil
}

func (rt hostSelfUpdateExecutorRuntime) hostSelfUpdateSlotHasBinding(
	slot string,
) (bool, error) {
	if !validHostSelfUpdateSlot(slot) {
		return false, errors.New("host self-update slot is invalid")
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	for _, name := range []string{
		".generation",
		".agent-version",
		".executor-version",
		".commit",
		".artifact-sha256",
		".agent-protocol",
		".executor-protocol",
		".mutation-protocol",
		".recovery-protocol",
		".agent-sha256",
		".local-executor-sha256",
		".release-binding.json",
	} {
		path := filepath.Join(slotRoot, name)
		if !pathWithin(slotRoot, path) {
			return false, errors.New(
				"host self-update slot binding escaped its root",
			)
		}
		if _, err := os.Lstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func (rt hostSelfUpdateExecutorRuntime) loadPersistedState() (HostSelfUpdateState, error) {
	info, err := os.Lstat(rt.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return HostSelfUpdateState{}, os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > 64<<10 ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return HostSelfUpdateState{}, errors.New("host self-update state is unsafe")
	}
	payload, err := os.ReadFile(rt.statePath)
	if err != nil {
		return HostSelfUpdateState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state HostSelfUpdateState
	if err := decoder.Decode(&state); err != nil {
		return HostSelfUpdateState{}, errors.New("decode host self-update state")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return HostSelfUpdateState{}, errors.New("host self-update state contains trailing data")
	}
	if err := state.validate(); err != nil {
		return HostSelfUpdateState{}, err
	}
	return state, nil
}

func (rt hostSelfUpdateExecutorRuntime) saveState(
	state HostSelfUpdateState,
) error {
	if err := state.validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode host self-update state")
	}
	writer := rt.writeState
	if writer == nil {
		writer = writeAtomicFile
	}
	if err := writer(
		rt.statePath, append(payload, '\n'), 0o600,
	); err != nil {
		return err
	}
	info, err := os.Lstat(rt.statePath)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return errors.New("host self-update state security verification failed")
	}
	return nil
}
