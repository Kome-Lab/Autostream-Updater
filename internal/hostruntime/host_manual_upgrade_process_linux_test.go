//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyManualHostUnitProcessWaitsForTransientSystemdExecutor(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	var resolvedPIDs []int
	fixture.runtime.resolveProcessExe = func(pid int) (string, error) {
		resolvedPIDs = append(resolvedPIDs, pid)
		if len(resolvedPIDs) == 1 {
			return "/usr/lib/systemd/systemd-executor", nil
		}
		return expected, nil
	}

	identity, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err != nil {
		t.Fatalf("verifyManualHostUnitProcess: %v", err)
	}
	if identity.Version != manualHostUpgradeTestOldVersion {
		t.Fatalf("identity version=%q", identity.Version)
	}
	if len(resolvedPIDs) != 3 || fixture.waitStableCalls != 2 ||
		fixture.runner.mainPIDReads[hostSelfUpdateExecutorServiceUnit] != 3 ||
		fixture.runner.identityReads["autostream-local-executor"] != 1 {
		t.Fatalf("executable resolutions=%v, want transient plus stable pair", resolvedPIDs)
	}
	for _, pid := range resolvedPIDs {
		if pid != 3102 {
			t.Fatalf("resolved PIDs=%v, want one stable MainPID", resolvedPIDs)
		}
	}
}

func TestVerifyManualHostUnitProcessRejectsUntrustedSystemdExecutorPath(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	resolves := 0
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		resolves++
		return "/tmp/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		return nil
	}

	_, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"executing outside the selected slot",
	) {
		t.Fatalf("untrusted systemd-executor path err=%v", err)
	}
	if resolves != 1 || waits != 0 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"untrusted path resolves=%d waits=%d identity_reads=%d",
			resolves,
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessBoundsPersistentSystemdExecutor(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	resolves := 0
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		resolves++
		return "/usr/lib/systemd/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		return nil
	}

	_, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "startup probe limit") {
		t.Fatalf("persistent systemd-executor err=%v", err)
	}
	if resolves != hostSelfUpdateSystemdExecutorProbes ||
		waits != hostSelfUpdateSystemdExecutorProbes-1 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"persistent helper resolves=%d waits=%d identity_reads=%d",
			resolves,
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessHonorsCanceledTransitionWait(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		return "/usr/lib/systemd/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		cancel()
		return ctx.Err()
	}

	_, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transition err=%v", err)
	}
	if waits != 1 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"canceled transition waits=%d identity_reads=%d",
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessRejectsPIDChurn(t *testing.T) {
	for _, test := range []struct {
		name             string
		transientFirst   bool
		wantError        string
		wantStableWaits  int
		wantResolveCalls int
	}{
		{
			name:             "during_systemd_executor_transition",
			transientFirst:   true,
			wantError:        "MainPID changed during systemd-executor transition",
			wantStableWaits:  1,
			wantResolveCalls: 2,
		},
		{
			name:             "after_expected_executable",
			wantError:        "MainPID changed during stability verification",
			wantStableWaits:  1,
			wantResolveCalls: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			expected := filepath.Join(
				fixture.runtime.selfUpdate.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				"autostream-local-executor",
			)
			fixture.runner.mainPIDSequence = map[string][]int{
				hostSelfUpdateExecutorServiceUnit: {3102, 4102},
			}
			resolves := 0
			fixture.runtime.resolveProcessExe = func(int) (string, error) {
				resolves++
				if test.transientFirst && resolves == 1 {
					return "/usr/lib/systemd/systemd-executor", nil
				}
				return expected, nil
			}

			_, err := verifyManualHostUnitProcess(
				context.Background(),
				hostSelfUpdateExecutorServiceUnit,
				expected,
				"autostream-local-executor",
				fixture.runtime,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("PID churn err=%v", err)
			}
			if resolves != test.wantResolveCalls ||
				fixture.waitStableCalls != test.wantStableWaits ||
				fixture.runner.identityReads["autostream-local-executor"] != 0 {
				t.Fatalf(
					"PID churn resolves=%d waits=%d identity_reads=%d",
					resolves,
					fixture.waitStableCalls,
					fixture.runner.identityReads["autostream-local-executor"],
				)
			}
		})
	}
}
