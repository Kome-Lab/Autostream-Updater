//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManualHostUpgradeRecoversCandidateWhenBeginActivationFails(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		t.Run(fmt.Sprintf("preexisting=%v", preexisting), func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			rootBefore, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot)
			if err != nil {
				t.Fatal(err)
			}
			if !preexisting {
				removeManualHostUpgradeLinuxStateRoot(t, fixture)
			}
			fixture.runtime.now = func() time.Time { return time.Time{} }

			if _, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			); err == nil || !strings.Contains(err.Error(), "activation clock") {
				t.Fatalf("BeginActivation failure err=%v", err)
			}
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
			after, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot)
			if preexisting {
				if err != nil || !os.SameFile(rootBefore, after) {
					t.Fatalf("preexisting state root changed: info=%v err=%v", after, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("created state root survived pre-fence failure: %v", err)
			}
		})
	}
}

func TestManualHostUpgradeRollsBackAmbiguousActivationStateWrite(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	injected := false
	fixture.runtime.selfUpdate.writeState = func(
		path string,
		payload []byte,
		mode os.FileMode,
	) error {
		var state HostSelfUpdateState
		if err := json.Unmarshal(payload, &state); err != nil {
			return err
		}
		if state.Phase != HostSelfUpdatePhaseActivating || injected {
			return writeAtomicFile(path, payload, mode)
		}
		injected = true
		directory := filepath.Dir(path)
		file, err := os.CreateTemp(directory, ".manual-upgrade-state-*")
		if err != nil {
			return err
		}
		temporary := file.Name()
		defer os.Remove(temporary)
		if err := file.Chmod(mode); err != nil {
			_ = file.Close()
			return err
		}
		if _, err := file.Write(payload); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(temporary, path); err != nil {
			return err
		}
		return errors.New("injected state directory sync ambiguity")
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "activation fence") {
		t.Fatalf("ambiguous state write err=%v", err)
	}
	if !injected || !fixture.runner.agentActive || fixture.runner.stopCalls != 0 {
		t.Fatalf("rollback injection=%v active=%v stops=%d", injected, fixture.runner.agentActive, fixture.runner.stopCalls)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA || state.FailedGeneration == "" {
		t.Fatalf("rollback state=%+v err=%v", state, err)
	}
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
}

func TestManualHostUpgradeRollsBackWhenActivationFenceDisappears(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	fixture.runner.stopHook = func() error {
		if err := os.Remove(fixture.runtime.selfUpdate.statePath); err != nil {
			return err
		}
		return syncDirectory(fixture.runtime.selfUpdate.stateRoot)
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "state changed") {
		t.Fatalf("missing activation fence err=%v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA || !fixture.runner.agentActive {
		t.Fatalf("rollback current=%q active=%v err=%v", current, fixture.runner.agentActive, err)
	}
}

func TestManualHostUpgradeRejectsProtectedInstallationDriftBeforeSwitch(
	t *testing.T,
) {
	tests := []struct {
		name      string
		wantError string
		mutate    func(*manualHostUpgradeLinuxFixture) error
	}{
		{
			name:      "installed unit",
			wantError: "installed Host runtime unit changed",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				return os.WriteFile(
					fixture.runtime.paths.installedAgentUnit,
					[]byte("old-installer unit drift\n"),
					0o644,
				)
			},
		},
		{
			name:      "public binary link",
			wantError: "public binary link changed",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				if err := os.Remove(fixture.publicAgentPath); err != nil {
					return err
				}
				return os.Symlink(
					filepath.Join(fixture.root, "old-installer-current"),
					fixture.publicAgentPath,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			fixture.runner.stopHook = func() error { return test.mutate(fixture) }

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) ||
				result != (ManualHostUpgradeResult{}) {
				t.Fatalf("protected drift result=%+v err=%v", result, err)
			}
			current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
			if currentErr != nil || current != HostSelfUpdateSlotA ||
				!fixture.runner.agentActive || fixture.runner.stopCalls != 1 {
				t.Fatalf(
					"protected drift rollback current=%q active=%v stops=%d err=%v",
					current,
					fixture.runner.agentActive,
					fixture.runner.stopCalls,
					currentErr,
				)
			}
		})
	}
}
