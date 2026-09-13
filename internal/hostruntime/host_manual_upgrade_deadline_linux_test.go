//go:build linux

package hostruntime

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestManualHostUpgradeDeadlineExpiryRollsBackBeforeStop(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	calls := 0
	fixture.runtime.now = func() time.Time {
		calls++
		if calls == 1 {
			return manualHostUpgradeTestActivationNow
		}
		return manualHostUpgradeTestActivationNow.Add(2 * time.Minute)
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "deadline expired") {
		t.Fatalf("deadline expiry err=%v", err)
	}
	if fixture.runner.stopCalls != 0 || !fixture.runner.agentActive {
		t.Fatalf("expired activation stopped Agent: stops=%d active=%v", fixture.runner.stopCalls, fixture.runner.agentActive)
	}
}

func TestManualHostUpgradeDeadlineCancelsBlockedPostStopRunnerAndRollsBack(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	fixture.runner.blockPostStopRestart = true
	logicalNow := manualHostUpgradeTestActivationNow
	nowCalls := 0
	fixture.runtime.now = func() time.Time {
		nowCalls++
		if nowCalls == 1 {
			return logicalNow
		}
		return logicalNow.Add(30*time.Second - 300*time.Millisecond)
	}
	fixture.runtime.selfUpdate.verificationTimeout = 30 * time.Second
	setupUnlocks := 0
	lifecycleUnlocks := 0
	targetUnlocks := 0
	fixture.runtime.acquireLocks = func() (func(), error) {
		return func() {
			lifecycleUnlocks++
			setupUnlocks++
		}, nil
	}
	fixture.runtime.acquireTargetLocks = func(
		LocalExecutorPolicy,
		[]Target,
	) (func(), error) {
		return func() { targetUnlocks++ }, nil
	}

	started := time.Now()
	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked post-stop runner result=%+v err=%v", result, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("deadline cancellation took %s", elapsed)
	}
	if !fixture.runner.postStopRestartBlocked ||
		!fixture.runner.postStopRestartCanceled {
		t.Fatalf(
			"post-stop runner was not canceled: blocked=%v canceled=%v err=%v",
			fixture.runner.postStopRestartBlocked,
			fixture.runner.postStopRestartCanceled,
			err,
		)
	}
	current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
	if currentErr != nil || current != HostSelfUpdateSlotA ||
		!fixture.runner.agentActive || !fixture.runner.executorActive {
		t.Fatalf(
			"detached rollback current=%q agent=%v executor=%v err=%v",
			current,
			fixture.runner.agentActive,
			fixture.runner.executorActive,
			currentErr,
		)
	}
	state, stateErr := fixture.runtime.selfUpdate.loadPersistedState()
	if stateErr != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA || state.FailedGeneration == "" {
		t.Fatalf("detached rollback state=%+v err=%v", state, stateErr)
	}
	for index, canceled := range fixture.runner.restartContextCanceled {
		if canceled {
			t.Fatalf("rollback restart %d inherited canceled context", index)
		}
	}
	if setupUnlocks != 1 || lifecycleUnlocks != 1 || targetUnlocks != 1 {
		t.Fatalf(
			"deadline rollback lock release setup=%d lifecycle=%d targets=%d",
			setupUnlocks,
			lifecycleUnlocks,
			targetUnlocks,
		)
	}
}

func TestEnsureManualHostUpgradeDeadlineBoundaries(t *testing.T) {
	deadline := time.Date(2026, 8, 2, 7, 9, 9, 0, time.UTC)
	tests := []struct {
		name    string
		state   HostSelfUpdateState
		now     time.Time
		wantErr bool
	}{
		{
			name:    "zero deadline",
			state:   HostSelfUpdateState{},
			now:     deadline.Add(-time.Nanosecond),
			wantErr: true,
		},
		{
			name: "one nanosecond before deadline",
			state: HostSelfUpdateState{
				ActivationDeadline: deadline,
			},
			now: deadline.Add(-time.Nanosecond),
		},
		{
			name: "exactly at deadline",
			state: HostSelfUpdateState{
				ActivationDeadline: deadline,
			},
			now:     deadline,
			wantErr: true,
		},
		{
			name: "after deadline",
			state: HostSelfUpdateState{
				ActivationDeadline: deadline,
			},
			now:     deadline.Add(time.Nanosecond),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ensureManualHostUpgradeDeadline(tt.state, tt.now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ensureManualHostUpgradeDeadline() err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestManualHostUpgradeCommitDeadlineExpiryRollsBackVerifiedRuntime(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	calls := 0
	fixture.runtime.now = func() time.Time {
		calls++
		if calls == 4 {
			return manualHostUpgradeTestActivationNow.Add(
				fixture.runtime.selfUpdate.verificationTimeout,
			)
		}
		return manualHostUpgradeTestActivationNow
	}

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "deadline expired") {
		t.Fatalf("commit deadline expiry result=%+v err=%v", result, err)
	}
	if result != (ManualHostUpgradeResult{}) {
		t.Fatalf("failed upgrade returned a result: %+v", result)
	}
	if calls != 4 {
		t.Fatalf("deadline checks=%d want=4", calls)
	}

	current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
	if currentErr != nil || current != HostSelfUpdateSlotA ||
		!fixture.runner.agentActive || !fixture.runner.executorActive {
		t.Fatalf(
			"rollback current=%q agent_active=%v executor_active=%v err=%v",
			current,
			fixture.runner.agentActive,
			fixture.runner.executorActive,
			currentErr,
		)
	}
	state, stateErr := fixture.runtime.selfUpdate.loadPersistedState()
	if stateErr != nil {
		t.Fatalf("load rollback state: %v", stateErr)
	}
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestOldVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestOldVersion ||
		!strings.HasPrefix(
			state.FailedGeneration,
			manualHostUpgradeBindingVersion+"-",
		) ||
		state.PendingGeneration != "" || state.RollbackSlot != "" ||
		!state.ActivationStartedAt.IsZero() ||
		!state.ActivationDeadline.IsZero() {
		t.Fatalf("rollback state=%+v", state)
	}

	wantRestartOrder := []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
	}
	if fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(wantRestartOrder) {
		t.Fatalf(
			"rollback restart order=%v want=%v",
			fixture.runner.restartOrder,
			wantRestartOrder,
		)
	}
	if fixture.runner.stopCalls != 1 || fixture.watchdogCalls != 2 ||
		fixture.runner.agentIdentityAfterRestart < 2 {
		t.Fatalf(
			"verified activation did not complete before rollback: stops=%d watchdog=%d agent_identity_after_restart=%d",
			fixture.runner.stopCalls,
			fixture.watchdogCalls,
			fixture.runner.agentIdentityAfterRestart,
		)
	}
	assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)
}
