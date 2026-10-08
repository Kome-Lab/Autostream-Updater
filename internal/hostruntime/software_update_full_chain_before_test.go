package hostruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/Kome-Lab/Autostream-Updater/internal/controlplane"
	"github.com/example/autostream-contracts/pkg/contracts"
)

// This red-capable oracle is copied to the original Updater tree before any
// product edits. CP produces the lease in a separate immutable-source test;
// this endpoint transports those bytes without manufacturing another lease.
func TestSoftwareUpdateActualCPLeaseClaimRevision(t *testing.T) {
	path := os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_CP_LEASE_OUTPUT")
	if path == "" {
		t.Skip("the separate actual CP producer output is required")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 1<<20 {
		t.Fatal("actual CP lease output is unavailable")
	}
	var packets []struct {
		CP         string                         `json:"control_panel_sha"`
		Producer   string                         `json:"producer"`
		Lease      contracts.UpdaterLeaseEnvelope `json:"lease"`
		Config     int64                          `json:"config_revision"`
		Source     int64                          `json:"source_policy_revision"`
		Projection int64                          `json:"projection_revision"`
		Executor   int64                          `json:"executor_policy_revision"`
		Digest     string                         `json:"executor_policy_sha256"`
		Public     int64                          `json:"public_job_policy_revision"`
		Status     string                         `json:"status"`
		Progress   int                            `json:"progress"`
		Sequence   int64                          `json:"sequence"`
		Epoch      int64                          `json:"ownership_epoch"`
	}
	if json.Unmarshal(data, &packets) != nil || len(packets) != 2 {
		t.Fatal("actual CP produced an incomplete revision matrix")
	}
	for _, packet := range packets {
		t.Run("C1_S"+strconv.FormatInt(packet.Source, 10)+"_P"+strconv.FormatInt(packet.Projection, 10)+"_E"+strconv.FormatInt(packet.Executor, 10)+"_F3", func(t *testing.T) {
			if packet.Producer != "actual_cp_store_and_systemUpdateV2Lease" || packet.Config != 1 || packet.Public != packet.Projection ||
				packet.Epoch != 3 || packet.Status != "claimed" || packet.Progress != 0 || packet.Sequence != 0 ||
				(packet.CP != "0315845e3af01eff6b97c6164db3ddc3109b55af" && packet.CP != "9c75188147daf8435d005651a8266ae31ce39653") {
				t.Fatal("CP producer did not establish the actual defect preconditions")
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/services/update-jobs/claim" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set(controlplane.ContractMajorHeader, controlplane.ContractMajorV2)
				_ = json.NewEncoder(w).Encode(packet.Lease)
			}))
			defer server.Close()
			client := NewV2PanelClient(PanelClient{BaseURL: server.URL, HTTP: server.Client(), Token: "synthetic-software-reproduction"})
			job, clear, err := client.ClaimHost(context.Background(), HostPullClaimRequest{UpdaterID: "agent-software-chain", HostID: "host-software-chain", LeaseGeneration: 1, Fence: 3})
			if err != nil || clear || job == nil {
				t.Fatalf("production V2 adapter could not receive the actual CP lease: clear=%t job_present=%t error=%v", clear, job != nil, err)
			}
			binding := HostAgentBinding{ServiceID: "agent-software-chain", ServiceType: ServiceTypeUpdateAgent, TransportMode: HostTransportPullV2, ExecutionHostID: "host-software-chain", OwnershipEpoch: 3}
			policy := HostAgentPolicy{ServiceID: binding.ServiceID, TransportMode: HostTransportPullV2, ExecutionHostID: binding.ExecutionHostID, OwnershipEpoch: 3,
				Revision: packet.Projection, SourcePolicyRevision: packet.Source, LocalExecutorPolicyRevision: packet.Executor,
				LocalExecutorPolicySHA256: packet.Digest, Targets: []HostAgentPolicyTarget{{ServiceID: "control-panel", ServiceType: "control_panel", DeploymentMode: ModeSystemd, AppliedConfigRevision: 1}}}
			agent := &HostPullAgent{Bootstrap: Config{NodeID: binding.ServiceID}}
			// The original source tree lacks this method. Keeping the oracle
			// compilable there establishes the same actual lease red result,
			// while the candidate must use its production binding implementation.
			if binder, ok := any(agent).(interface {
				bindSoftwareClaim(HostPullExecutionControlPlane, HostAgentBinding, HostAgentPolicy, *UpdateJob, *UpdateJob) error
			}); ok {
				if err := binder.bindSoftwareClaim(client, binding, policy, nil, job); err != nil {
					t.Fatalf("actual CP wire intent could not bind to the authenticated policy: %v", err)
				}
			}
			if err := validateHostPullClaim(*job, "agent-software-chain", binding, policy); err != nil {
				t.Fatalf("actual CP lease desired configuration=%d public policy=%d internal projection=%d: %s", packet.Config, packet.Public, job.PolicyRevision, err)
			}
		})
	}
}
