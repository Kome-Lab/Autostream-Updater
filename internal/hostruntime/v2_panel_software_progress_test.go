package hostruntime

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

func TestV2SoftwareProgressKeepsPreApplyVerificationPreparing(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	lease := v2PanelSoftwareLease(t, now)
	for index, step := range []struct {
		status   string
		progress int
		phase    string
	}{
		{"claimed", 5, "accepted"},
		{"downloading", 20, "preparing"},
		{"verifying", 40, "preparing"},
		{"staging", 55, "preparing"},
		{"installing", 65, "executing"},
		{"health_checking", 90, "verifying"},
	} {
		t.Run(step.status, func(t *testing.T) {
			report := JobReport{ServiceID: lease.Command.MutationAuthorization.UpdaterID,
				Sequence: uint64(index + 1), LeaseGeneration: uint64(lease.LeaseGeneration),
				Status: step.status, Progress: step.progress, Message: "synthetic software phase observation"}
			assertV2ProgressWirePhase(t, lease, report, now, step.phase)
		})
	}
	// The internal status identifies artifact preparation. Percentages do not
	// select authorization or turn metadata verification into application health.
	for _, percent := range []int{0, 40, 99} {
		t.Run(fmt.Sprintf("metadata_verification_%d", percent), func(t *testing.T) {
			report := JobReport{ServiceID: lease.Command.MutationAuthorization.UpdaterID,
				Sequence: 1, LeaseGeneration: uint64(lease.LeaseGeneration), Status: "verifying", Progress: percent}
			assertV2ProgressWirePhase(t, lease, report, now, "preparing")
		})
	}
}

func TestV2ProgressVerificationMappingPreservesOtherOperations(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	portV2, _, _, _ := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	for _, operation := range []struct {
		name  string
		lease contracts.UpdaterLeaseEnvelope
	}{
		{"port", v2PanelPortLease(t, now)},
		{"port_v2", portV2},
		{"bootstrap", v2PanelBootstrapLease(t, now)},
		{"host_self_update", v2PanelSelfUpdateLease(t, now)},
	} {
		for _, status := range []string{"verifying", "health_checking"} {
			t.Run(operation.name+"/"+status, func(t *testing.T) {
				report := JobReport{ServiceID: operation.lease.Command.MutationAuthorization.UpdaterID,
					Sequence: 1, LeaseGeneration: uint64(operation.lease.LeaseGeneration), Status: status, Progress: 90}
				observedAt := operation.lease.LeaseExpiresAt.Add(-time.Minute)
				assertV2ProgressWirePhase(t, operation.lease, report, observedAt, "verifying")
			})
		}
	}
}

func assertV2ProgressWirePhase(t *testing.T, lease contracts.UpdaterLeaseEnvelope, report JobReport, observedAt time.Time, phase string) {
	t.Helper()
	originalLease, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapV2JobReport(lease, report, observedAt)
	if err != nil || mapped.progress == nil || mapped.result != nil {
		t.Fatalf("progress mapping failed: %v", err)
	}
	payload, err := json.Marshal(mapped.progress)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.ValidateUpdaterProgressEnvelope(lease, payload); err != nil {
		t.Fatalf("official progress contract rejected mapping: %v", err)
	}
	if mapped.progress.Phase != phase {
		t.Errorf("wire phase=%s, expected=%s for local status=%s progress=%d", mapped.progress.Phase, phase, report.Status, report.Progress)
	}
	if mapped.source.Status != report.Status || mapped.source.Progress != report.Progress {
		t.Fatal("wire adaptation replaced the local journal status or percentage")
	}
	unchangedLease, err := json.Marshal(lease)
	if err != nil || string(originalLease) != string(unchangedLease) {
		t.Fatal("progress mapping changed the frozen lease, command, revision, or ownership fence")
	}
}
