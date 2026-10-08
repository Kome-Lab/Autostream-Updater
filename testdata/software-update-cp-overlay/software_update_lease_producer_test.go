package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
	"github.com/example/autostream-control-panel/internal/store"
)

// This test-only file is overlaid on an immutable CP checkout. It calls the
// actual store and CP lease producer; it never constructs an Updater lease.
// The output contains only synthetic authorization IDs, not runtime/lease
// credentials. Its SHA and the unchanged CP product tree are recorded apart.
func TestSoftwareUpdateCPLeaseProducer(t *testing.T) {
	output := os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_CP_LEASE_OUTPUT")
	if output == "" {
		t.Skip("selected only by the fixed-source software update reproduction")
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		t.Fatal("an absolute private lease fixture output is required")
	}
	sha := os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_CONTROL_PANEL_SHA")
	if sha != "0315845e3af01eff6b97c6164db3ddc3109b55af" && sha != "9c75188147daf8435d005651a8266ae31ce39653" {
		t.Fatal("the immutable accepted CP source identity is required")
	}
	t.Setenv("AUTOSTREAM_BIND_ADDR", "127.0.0.1:18080")
	t.Setenv("AUTOSTREAM_CONFIG_REVISION", "1")
	ctx := t.Context()
	packets := make([]map[string]any, 0, 2)
	for _, revisions := range [][3]int64{{8, 8, 8}, {11, 13, 17}} {
		updates := store.NewMemorySystemUpdateStore()
		var owner store.SystemUpdateExecutionHost
		var err error
		for epoch := int64(0); epoch < 3; epoch++ {
			owner, err = updates.SwitchSystemUpdateExecutionHost(ctx, "host-software-chain", epoch,
				store.SystemUpdateTransportPullV2, "agent-software-chain", revisions[1])
			if err != nil || owner.OwnershipEpoch != epoch+1 {
				t.Fatal("seed isolated ownership through the actual CAS store")
			}
		}
		job, created, err := updates.CreateSystemUpdateJob(ctx, store.CreateSystemUpdateJobParams{
			TargetID: "control-panel", TargetServiceType: "control_panel", Operation: store.SystemUpdateOperationSoftwareUpdate,
			AgentServiceID: "agent-software-chain", ExecutionHostID: owner.ExecutionHostID, DeploymentMode: "systemd",
			CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", Strategy: store.SystemUpdateStrategyWhenIdle,
			IdempotencyKey: "software-chain-c1-distinct-policy", RequestedByUserID: "software-chain-operator",
		})
		if err != nil || !created || job.Status != store.SystemUpdateStatusQueued {
			t.Fatal("create isolated software job through the actual store")
		}
		claim, clear, err := updates.ClaimSystemUpdateJobV2(ctx, "agent-software-chain", owner.ExecutionHostID,
			"", 1, owner.OwnershipEpoch, map[string]string{"control-panel": "systemd"}, time.Now().UTC(), 45*time.Minute)
		if err != nil || clear || claim.Job.ID != job.ID || claim.Job.PolicyRevision != revisions[1] ||
			claim.Job.Status != store.SystemUpdateStatusClaimed || claim.Job.Progress != 0 || claim.Job.Sequence != 0 {
			t.Fatal("actual CP claim did not preserve the claimed zero-progress policy projection")
		}
		handler := NewServer(store.NewMemoryStreamStore(), WithAuthStore(store.NewMemoryAuthStore()), WithSystemUpdateStore(updates))
		lease, err := handler.systemUpdateV2Lease(ctx, claim.Job)
		if err != nil || contracts.ValidateUpdaterLease(time.Now().UTC(), lease) != nil {
			t.Fatal("actual CP software lease production failed")
		}
		if lease.Command.MutationAuthorization.DesiredRevision != 1 || lease.Command.MutationAuthorization.Target.ExpectedConfigRevision != 1 ||
			lease.Command.MutationAuthorization.Fence != 3 || lease.LeaseGeneration != 1 || claim.Job.PolicyRevision == 1 {
			t.Fatal("actual CP conflated configuration revision and the public job policy projection")
		}
		packets = append(packets, map[string]any{
			"control_panel_sha": sha, "producer": "actual_cp_store_and_systemUpdateV2Lease", "lease": lease,
			"config_revision": 1, "source_policy_revision": revisions[0], "projection_revision": revisions[1],
			"executor_policy_revision": revisions[2], "executor_policy_sha256": "sha256:" + strings.Repeat("a", 64),
			"public_job_policy_revision": claim.Job.PolicyRevision, "status": claim.Job.Status, "progress": claim.Job.Progress,
			"sequence": claim.Job.Sequence, "ownership_epoch": claim.Job.OwnershipEpoch,
		})
	}
	data, err := json.Marshal(packets)
	if err != nil {
		t.Fatal("encode actual CP reproduction packets")
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("private original CP lease output already exists or is unavailable")
	}
	_, writeErr := file.Write(append(data, '\n'))
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal("persist original CP reproduction packets")
	}
}
