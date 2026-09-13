//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestManualHostUpgradeStopFailureUsesDetachedAgentRecovery(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	fixture.runner.stopAfterSideEffectErr = true
	ctx, cancel := context.WithCancel(context.Background())
	fixture.runner.stopCancel = cancel
	defer cancel()

	result, err := upgradeHostRuntimeWithRuntime(
		ctx, fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"stop Host Agent for manual runtime upgrade",
	) {
		t.Fatalf("side-effecting stop failure result=%+v err=%v", result, err)
	}
	if !fixture.runner.agentActive || fixture.runner.stopCalls != 1 {
		t.Fatalf("old Agent was not restored: active=%v stops=%d", fixture.runner.agentActive, fixture.runner.stopCalls)
	}
	if len(fixture.runner.restartContextCanceled) != 2 ||
		fixture.runner.restartContextCanceled[0] ||
		fixture.runner.restartContextCanceled[1] {
		t.Fatalf(
			"Agent recovery inherited canceled context: %v",
			fixture.runner.restartContextCanceled,
		)
	}
}

func TestManualHostUpgradeSameArchiveRetryUsesFreshGeneration(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)
	fixture.runner.failTargetAgent = true
	firstResult, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "restart Host Agent") ||
		firstResult != (ManualHostUpgradeResult{}) {
		t.Fatalf(
			"first activation failure result=%+v err=%v",
			firstResult,
			err,
		)
	}
	if !fixture.runner.targetAgentFailed || fixture.runner.stopCalls != 1 {
		t.Fatalf(
			"first request did not cross the activation fence: target_failed=%v stops=%d",
			fixture.runner.targetAgentFailed,
			fixture.runner.stopCalls,
		)
	}
	failed, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || failed.Phase != HostSelfUpdatePhaseStable ||
		failed.ActiveSlot != HostSelfUpdateSlotA ||
		failed.HealthySlot != HostSelfUpdateSlotA ||
		failed.ActiveAgentVersion != manualHostUpgradeTestOldVersion ||
		failed.ActiveExecutorVersion != manualHostUpgradeTestOldVersion ||
		failed.FailedGeneration == "" || failed.PendingGeneration != "" ||
		failed.PendingSlot != "" || failed.RollbackSlot != "" {
		t.Fatalf("failed state=%+v err=%v", failed, err)
	}
	firstBinding, _, err := readManualHostUpdateSlotBinding(
		HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
	)
	if err != nil || firstBinding.Generation != failed.FailedGeneration {
		t.Fatalf(
			"failed slot generation=%q failed_generation=%q err=%v",
			firstBinding.Generation,
			failed.FailedGeneration,
			err,
		)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("rollback current slot=%q err=%v", current, err)
	}
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil {
		t.Fatalf("same archive retry: %v", err)
	}
	if result.PreviousSlot != HostSelfUpdateSlotA ||
		result.ActiveSlot != HostSelfUpdateSlotB ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("retry result=%+v", result)
	}
	committed, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || committed.Phase != HostSelfUpdatePhaseStable ||
		committed.ActiveSlot != HostSelfUpdateSlotB ||
		committed.HealthySlot != HostSelfUpdateSlotB ||
		committed.RollbackSlot != HostSelfUpdateSlotA ||
		committed.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		committed.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion ||
		committed.RollbackAgentVersion != manualHostUpgradeTestOldVersion ||
		committed.RollbackExecutorVersion != manualHostUpgradeTestOldVersion ||
		committed.FailedGeneration != failed.FailedGeneration ||
		committed.PendingGeneration != "" || committed.PendingSlot != "" {
		t.Fatalf("retry state=%+v err=%v", committed, err)
	}
	retryBinding, _, err := readManualHostUpdateSlotBinding(
		HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
	)
	if err != nil || retryBinding.Generation == failed.FailedGeneration ||
		!sameManualHostUpgradeArchiveContent(firstBinding, retryBinding) {
		t.Fatalf(
			"retry binding generation=%q failed_generation=%q same_content=%v err=%v",
			retryBinding.Generation,
			failed.FailedGeneration,
			sameManualHostUpgradeArchiveContent(firstBinding, retryBinding),
			err,
		)
	}
	current, err = fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("committed current slot=%q err=%v", current, err)
	}
	if fixture.runner.stopCalls != 2 {
		t.Fatalf("retry stop calls=%d want=2", fixture.runner.stopCalls)
	}
	assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)

	stateBeforeNoOp := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.selfUpdate.statePath,
	)
	stopsBeforeNoOp := fixture.runner.stopCalls
	restartsBeforeNoOp := append([]string(nil), fixture.runner.restartOrder...)
	noOp, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || noOp.PreviousSlot != HostSelfUpdateSlotB ||
		noOp.ActiveSlot != HostSelfUpdateSlotB ||
		noOp.Version != manualHostUpgradeTestTargetVersion ||
		!noOp.AlreadyCurrent {
		t.Fatalf("already-current result=%+v err=%v", noOp, err)
	}
	if fixture.runner.stopCalls != stopsBeforeNoOp ||
		fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(restartsBeforeNoOp) {
		t.Fatalf(
			"already-current request mutated services: stops=%d want=%d restarts=%v want=%v",
			fixture.runner.stopCalls,
			stopsBeforeNoOp,
			fixture.runner.restartOrder,
			restartsBeforeNoOp,
		)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.selfUpdate.statePath, stateBeforeNoOp,
	)
	current, err = fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("already-current current slot=%q err=%v", current, err)
	}
	assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
}

func TestManualHostUpgradeSameVersionStillRejectsDurableBlocker(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err != nil {
		t.Fatalf("seed current target runtime: %v", err)
	}
	checkpoint := writeManualHostUpgradeLinuxCheckpoint(t, fixture, "started")
	before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)
	stops := fixture.runner.stopCalls

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked same-version result=%+v err=%v", result, err)
	}
	if fixture.runner.stopCalls != stops {
		t.Fatalf("blocked same-version retry stopped Agent: %d -> %d", stops, fixture.runner.stopCalls)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(t, checkpoint, before)
}

func TestManualHostUpgradeBlocksOnTerminalGrantWithoutMutation(t *testing.T) {
	for _, phase := range []string{
		hostSelfUpdateGrantPhaseApplied,
		hostSelfUpdateGrantPhaseFailed,
	} {
		t.Run(phase, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			if _, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			); err != nil {
				t.Fatalf("seed current target runtime: %v", err)
			}
			request, _, err := readManualHostUpdateSlotBinding(
				HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
			)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := LoadLocalExecutorPolicy(fixture.policyPath, false)
			if err != nil {
				t.Fatal(err)
			}
			policySHA256, err := policy.SHA256()
			if err != nil {
				t.Fatal(err)
			}
			authorization := validHostSelfUpdateGrantAuthorization(
				"stage",
				request,
				LocalExecutorMutationFence{
					SourcePolicyRevision:    policy.SourcePolicyRevision,
					OwnershipEpoch:          3,
					OwnershipPolicyRevision: policy.ProjectionRevision,
					ExecutorPolicyRevision:  policy.PolicyRevision,
				},
				policySHA256,
			)
			grant := newHostSelfUpdateGrantState(authorization)
			grant.Phase = phase
			if phase == hostSelfUpdateGrantPhaseApplied {
				receipt := consumedHostSelfUpdateGrant(authorization).Grant
				grant.Receipt = &receipt
			}
			if err := saveHostSelfUpdateGrantState(
				fixture.runtime.selfUpdate.grantStatePath, grant, false,
			); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(fixture.runtime.selfUpdate.grantStatePath)
			if err != nil {
				t.Fatal(err)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil ||
				!strings.Contains(err.Error(), "existing Host self-update grant blocks") ||
				result != (ManualHostUpgradeResult{}) {
				t.Fatalf("terminal grant result=%+v err=%v", result, err)
			}
			after, err := os.ReadFile(fixture.runtime.selfUpdate.grantStatePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("terminal Host self-update grant changed while blocking upgrade")
			}
		})
	}
}

func TestManualHostUpgradeLoadsLegacyHelperTargetsBeforeLocking(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	legacy := validHelperTestConfig(t)
	legacy.Targets[0].Systemd.Unit = "custom-legacy-worker.service"
	legacyPath := writeHelperTestConfig(t, legacy)
	fixture.runtime.paths.legacyHelperConfigPath = legacyPath
	var lockedLegacy []Target
	fixture.runtime.acquireTargetLocks = func(
		_ LocalExecutorPolicy,
		targets []Target,
	) (func(), error) {
		lockedLegacy = append([]Target(nil), targets...)
		return func() {}, nil
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err != nil {
		t.Fatalf("upgrade with legacy helper policy: %v", err)
	}
	if len(lockedLegacy) != 1 || lockedLegacy[0].Systemd == nil ||
		lockedLegacy[0].Systemd.Unit != "custom-legacy-worker.service" {
		t.Fatalf("legacy targets were not fenced: %+v", lockedLegacy)
	}
}
