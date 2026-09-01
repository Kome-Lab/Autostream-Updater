package hostruntime

import (
	"strings"
	"testing"
	"time"
)

func TestHostSelfUpdateRequiresHeartbeatAndExecutorProbeBeforeCommit(t *testing.T) {
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatalf("new state: %v", err)
	}
	staged, err := StageHostSelfUpdate(
		state,
		validHostSelfUpdateRequest(),
		HostLifecycleBlockers{},
		validHostSelfUpdateSlotDigests(),
	)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	activating, err := beginHostSelfUpdateActivationForTest(staged)
	if err != nil {
		t.Fatalf("begin activation: %v", err)
	}

	verifying, action, err := ReconcileHostSelfUpdate(activating, HostSelfUpdateObservation{
		CurrentSlot:         HostSelfUpdateSlotB,
		RunningAgentVersion: "v1.8.0",
		ExecutorVersion:     "v1.8.0",
		ExecutorProtocol:    2,
		ExecutorHealthy:     true,
	})
	if err != nil {
		t.Fatalf("reconcile switched slot: %v", err)
	}
	if action != HostSelfUpdateActionAwaitProof || verifying.Phase != HostSelfUpdatePhaseVerifying {
		t.Fatalf("without panel proof action=%q state=%#v", action, verifying)
	}

	heartbeatOnly := validHostSelfUpdateObservation()
	heartbeatOnly.ExecutorProbeGeneration = ""
	stillVerifying, action, err := ReconcileHostSelfUpdate(verifying, heartbeatOnly)
	if err != nil {
		t.Fatalf("reconcile heartbeat only: %v", err)
	}
	if action != HostSelfUpdateActionProbeExecutor || stillVerifying.Phase != HostSelfUpdatePhaseVerifying {
		t.Fatalf("heartbeat-only update committed: action=%q state=%#v", action, stillVerifying)
	}

	committed, action, err := ReconcileHostSelfUpdate(stillVerifying, validHostSelfUpdateObservation())
	if err != nil {
		t.Fatalf("commit reconciliation: %v", err)
	}
	if action != HostSelfUpdateActionCommit ||
		committed.Phase != HostSelfUpdatePhaseStable ||
		committed.ActiveSlot != HostSelfUpdateSlotB ||
		committed.HealthySlot != HostSelfUpdateSlotB ||
		committed.RollbackSlot != HostSelfUpdateSlotA ||
		committed.ActiveAgentVersion != "v1.8.0" ||
		committed.ActiveExecutorVersion != "v1.8.0" {
		t.Fatalf("unexpected commit: action=%q state=%#v", action, committed)
	}
}

func TestHostSelfUpdateExecutorFailureRestoresOldHealthySlot(t *testing.T) {
	state := activatingHostSelfUpdateState(t)
	failed := validHostSelfUpdateObservation()
	failed.ExecutorHealthy = false
	failed.ExecutorFailureCode = "probe_failed"

	rollingBack, action, err := ReconcileHostSelfUpdate(state, failed)
	if err != nil {
		t.Fatalf("record executor failure: %v", err)
	}
	if action != HostSelfUpdateActionRestoreHealthy ||
		rollingBack.Phase != HostSelfUpdatePhaseRollingBack ||
		rollingBack.HealthySlot != HostSelfUpdateSlotA {
		t.Fatalf("executor failure did not request rollback: action=%q state=%#v", action, rollingBack)
	}

	restored, action, err := ReconcileHostSelfUpdate(rollingBack, HostSelfUpdateObservation{
		CurrentSlot:             HostSelfUpdateSlotA,
		RunningAgentVersion:     "v1.7.8",
		ExecutorVersion:         "v1.7.8",
		ExecutorProtocol:        2,
		ExecutorHealthy:         true,
		ExecutorProbeGeneration: validHostSelfUpdateRequest().Generation,
	})
	if err != nil {
		t.Fatalf("reconcile restored slot: %v", err)
	}
	if action != HostSelfUpdateActionRollbackComplete ||
		restored.Phase != HostSelfUpdatePhaseStable ||
		restored.ActiveSlot != HostSelfUpdateSlotA ||
		restored.ActiveAgentVersion != "v1.7.8" ||
		restored.FailedGeneration != validHostSelfUpdateRequest().Generation {
		t.Fatalf("old healthy version was not restored: action=%q state=%#v", action, restored)
	}
	if _, err := StageHostSelfUpdate(
		restored,
		validHostSelfUpdateRequest(),
		HostLifecycleBlockers{},
		validHostSelfUpdateSlotDigests(),
	); err == nil || !strings.Contains(err.Error(), "cannot be replayed") {
		t.Fatalf("failed generation replay was accepted: %v", err)
	}
}

func TestHostSelfUpdateKillReconcileIsIdempotent(t *testing.T) {
	state := activatingHostSelfUpdateState(t)

	unchanged, action, err := ReconcileHostSelfUpdate(state, HostSelfUpdateObservation{
		CurrentSlot: HostSelfUpdateSlotA,
	})
	if err != nil {
		t.Fatalf("reconcile before switch: %v", err)
	}
	if action != HostSelfUpdateActionSwitchCurrent || unchanged.PendingSlot != HostSelfUpdateSlotB {
		t.Fatalf("unexpected pre-switch reconciliation: action=%q state=%#v", action, unchanged)
	}

	afterSwitch, action, err := ReconcileHostSelfUpdate(unchanged, HostSelfUpdateObservation{
		CurrentSlot: HostSelfUpdateSlotB,
	})
	if err != nil {
		t.Fatalf("reconcile after switch: %v", err)
	}
	if action != HostSelfUpdateActionRestartAgent || afterSwitch.Phase != HostSelfUpdatePhaseVerifying {
		t.Fatalf("unexpected post-switch reconciliation: action=%q state=%#v", action, afterSwitch)
	}

	rebooted, action, err := ReconcileHostSelfUpdate(afterSwitch, HostSelfUpdateObservation{
		CurrentSlot: HostSelfUpdateSlotB,
	})
	if err != nil {
		t.Fatalf("reconcile after reboot: %v", err)
	}
	if action != HostSelfUpdateActionAwaitProof ||
		rebooted.Phase != HostSelfUpdatePhaseVerifying ||
		rebooted.PendingSlot != HostSelfUpdateSlotB {
		t.Fatalf("reboot caused a second stage or commit: action=%q state=%#v", action, rebooted)
	}
}

func TestHostRuntimeCompatibilityGatesClaim(t *testing.T) {
	requirement := HostRuntimeRequirement{
		MinimumAgentVersion:     "v1.7.8",
		MinimumExecutorVersion:  "v1.7.8",
		AgentProtocolVersion:    2,
		ExecutorProtocolVersion: 2,
		MutationProtocolVersion: 2,
		RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
	}
	current := HostRuntimeCompatibility{
		AgentVersion:            "v1.7.8",
		ExecutorVersion:         "v1.7.8",
		AgentProtocolVersion:    2,
		ExecutorProtocolVersion: 2,
		MutationProtocolVersion: 2,
		RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
	}
	if err := ValidateHostRuntimeCompatibility(current, requirement); err != nil {
		t.Fatalf("compatible runtime rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*HostRuntimeCompatibility)
	}{
		{"agent version", func(value *HostRuntimeCompatibility) { value.AgentVersion = "v1.7.7" }},
		{"executor version", func(value *HostRuntimeCompatibility) { value.ExecutorVersion = "v1.7.7" }},
		{"agent protocol", func(value *HostRuntimeCompatibility) { value.AgentProtocolVersion = 1 }},
		{"executor protocol", func(value *HostRuntimeCompatibility) { value.ExecutorProtocolVersion = 1 }},
		{"mutation protocol", func(value *HostRuntimeCompatibility) { value.MutationProtocolVersion = 1 }},
		{
			"recovery protocol",
			func(value *HostRuntimeCompatibility) {
				value.RecoveryProtocolVersion =
					HostSelfUpdateRecoveryProtocolVersion - 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := current
			test.mutate(&changed)
			if err := ValidateHostRuntimeCompatibility(changed, requirement); err == nil {
				t.Fatal("incompatible runtime was allowed to claim")
			}
		})
	}
}

func TestHostSelfUpdateRejectsLegacyRecoveryProtocol(t *testing.T) {
	if HostSelfUpdateRecoveryProtocolVersion <= 1 {
		t.Fatalf(
			"digest-bound state requires a new recovery protocol, got %d",
			HostSelfUpdateRecoveryProtocolVersion,
		)
	}
	request := validHostSelfUpdateRequest()
	request.RecoveryProtocolVersion = 1
	request.Release.RecoveryProtocolVersion = 1
	if err := request.validate(); err == nil {
		t.Fatal("legacy recovery protocol accepted digest-bound state")
	}
}

func TestHostLifecycleMutationsRejectActiveWork(t *testing.T) {
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatalf("new state: %v", err)
	}
	for _, blockers := range []HostLifecycleBlockers{
		{ActiveJob: true},
		{MutationInProgress: true},
		{RecoveryPending: true},
		{TokenRotationPending: true},
	} {
		if _, err := StageHostSelfUpdate(
			state,
			validHostSelfUpdateRequest(),
			blockers,
			validHostSelfUpdateSlotDigests(),
		); err == nil {
			t.Fatalf("active lifecycle work was ignored: %#v", blockers)
		}
	}
}

func TestHostSelfUpdateNeverAcceptsPathsCommandsUnitsOrURLs(t *testing.T) {
	for _, field := range []string{
		HostSelfUpdateInstallRoot,
		HostSelfUpdateCurrentLink,
		HostSelfUpdateSlotsRoot,
		HostSelfUpdateStatePath,
	} {
		if field != HostSelfUpdateInstallRoot &&
			!strings.HasPrefix(field, HostSelfUpdateInstallRoot+"/") &&
			!strings.HasPrefix(field, HostSelfUpdateStateRoot+"/") {
			t.Fatalf("self-update path is outside the fixed roots: %q", field)
		}
	}
	request := validHostSelfUpdateRequest()
	if strings.Contains(strings.ToLower(strings.Join([]string{
		request.AgentVersion,
		request.ExecutorVersion,
		request.Commit,
		request.ArtifactSHA256,
		request.Generation,
	}, " ")), "http") {
		t.Fatal("self-update request unexpectedly carries a URL")
	}
}

func activatingHostSelfUpdateState(t *testing.T) HostSelfUpdateState {
	t.Helper()
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatalf("new state: %v", err)
	}
	state, err = StageHostSelfUpdate(
		state,
		validHostSelfUpdateRequest(),
		HostLifecycleBlockers{},
		validHostSelfUpdateSlotDigests(),
	)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	state, err = beginHostSelfUpdateActivationForTest(state)
	if err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	return state
}

func validHostSelfUpdateRequest() HostSelfUpdateRequest {
	return HostSelfUpdateRequest{
		Generation:              "update-20260728-001",
		AgentVersion:            "v1.8.0",
		ExecutorVersion:         "v1.8.0",
		Commit:                  strings.Repeat("a", 40),
		ArtifactSHA256:          "sha256:" + strings.Repeat("b", 64),
		AgentProtocolVersion:    2,
		ExecutorProtocolVersion: 2,
		MutationProtocolVersion: 2,
		RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
		Release: HostSelfUpdateReleaseIdentity{
			Tag:                     "v1.8.0",
			Commit:                  strings.Repeat("a", 40),
			PublishedAt:             time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC),
			ManifestAssetID:         101,
			ManifestAssetName:       hostAgentManifestName,
			ManifestSHA256:          strings.Repeat("1", 64),
			ManifestChecksumAssetID: 102,
			ManifestChecksumSHA256:  strings.Repeat("2", 64),
			ArchiveAssetID:          103,
			ArchiveAssetName: hostAgentReleaseAssetName(
				"v1.8.0",
				"amd64",
			),
			ArchiveSize:             4096,
			ArchiveSHA256:           strings.Repeat("b", 64),
			ArchiveChecksumAssetID:  104,
			ArchiveChecksumSHA256:   strings.Repeat("4", 64),
			Arch:                    "amd64",
			AgentProtocolVersion:    2,
			ExecutorProtocolVersion: 2,
			MutationProtocolVersion: 2,
			RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
			MinimumPanelVersion:     "v1.8.0",
		},
	}
}

func validHostSelfUpdateSlotDigests() hostSelfUpdateSlotDigests {
	return hostSelfUpdateSlotDigests{
		AgentSHA256:    strings.Repeat("c", 64),
		ExecutorSHA256: strings.Repeat("d", 64),
	}
}

func beginHostSelfUpdateActivationForTest(
	state HostSelfUpdateState,
) (HostSelfUpdateState, error) {
	return BeginHostSelfUpdateActivation(
		state,
		time.Date(2026, 7, 28, 1, 2, 3, 0, time.UTC),
		defaultHostSelfUpdateVerificationTimeout,
	)
}

func validHostSelfUpdateObservation() HostSelfUpdateObservation {
	request := validHostSelfUpdateRequest()
	return HostSelfUpdateObservation{
		CurrentSlot:             HostSelfUpdateSlotB,
		RunningAgentVersion:     request.AgentVersion,
		PanelHeartbeatVersion:   request.AgentVersion,
		HeartbeatGeneration:     request.Generation,
		ExecutorVersion:         request.ExecutorVersion,
		ExecutorProtocol:        request.ExecutorProtocolVersion,
		ExecutorHealthy:         true,
		ExecutorProbeGeneration: request.Generation,
	}
}
