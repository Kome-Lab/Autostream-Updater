package hostruntime

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestSoftwareClaimPreservesPendingReportsUntilFreshIntentIsValidated(t *testing.T) {
	for _, failure := range []string{"claim_api_error", "configuration_drift", "foreign_host", "changed_version", "generation_jump"} {
		t.Run(failure, func(t *testing.T) {
			agent, _, executor, binding, policy := newHostPullExecutionHarness(t, false)
			lease := v2PanelSoftwareLease(t, time.Now().UTC())
			lease.LeaseGeneration = 1
			authorization := &lease.Command.MutationAuthorization
			authorization.UpdaterID, authorization.HostID, authorization.Fence = agent.Bootstrap.NodeID, binding.ExecutionHostID, binding.OwnershipEpoch
			authorization.DesiredRevision, authorization.Target.ExpectedConfigRevision = 1, 1
			hostPullRefreshV2CommandDigest(t, &lease.Command)
			status := http.StatusOK
			reports := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/services/update-jobs/claim" {
					reports++
					writeV2PanelJSON(t, w, http.StatusServiceUnavailable, nil)
					return
				}
				writeV2PanelJSON(t, w, status, lease)
			}))
			defer server.Close()
			newClient := func() *V2PanelClient {
				return NewV2PanelClient(PanelClient{BaseURL: server.URL, HTTP: server.Client(), Token: "synthetic-runtime-token"})
			}
			client := newClient()
			job, clear, err := client.ClaimHost(context.Background(), HostPullClaimRequest{UpdaterID: agent.Bootstrap.NodeID, HostID: binding.ExecutionHostID, LeaseGeneration: 1, Fence: binding.OwnershipEpoch})
			if err != nil || clear || job == nil {
				t.Fatalf("initial valid lease: %v", err)
			}
			if err := agent.bindSoftwareClaim(client, binding, policy, nil, job); err != nil {
				t.Fatal(err)
			}
			if err := agent.Journal.SetActive(job); err != nil {
				t.Fatal(err)
			}
			plan, err := agent.prepareExecutionPlan(context.Background(), policy, *job)
			if err != nil {
				t.Fatal(err)
			}
			if err := agent.Journal.SetActivePlan(plan); err != nil {
				t.Fatal(err)
			}
			if _, err := agent.Journal.Queue(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "claimed", "", "claim validated", 5, "", ""); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(agent.Journal.path)
			if err != nil {
				t.Fatal(err)
			}
			pending := agent.Journal.Pending()
			lease.LeaseGeneration++
			lease.Command.CommandID = "command-fresh-pending"
			switch failure {
			case "claim_api_error":
				status = http.StatusServiceUnavailable
			case "configuration_drift":
				authorization.DesiredRevision, authorization.Target.ExpectedConfigRevision = 2, 2
			case "foreign_host":
				authorization.HostID = "host-other"
			case "changed_version":
				lease.Command.DesiredOperation.SoftwareUpdate.TargetVersion = "v1.2.5"
			case "generation_jump":
				lease.LeaseGeneration++
			}
			hostPullRefreshV2CommandDigest(t, &lease.Command)
			// A fresh adapter has no ephemeral lease, as after process restart.
			agent.ControlPlane = newClient()
			if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
				t.Fatal("invalid fresh recovery claim was accepted")
			}
			after, err := os.ReadFile(agent.Journal.path)
			if err != nil || !bytes.Equal(before, after) || !reflect.DeepEqual(pending, agent.Journal.Pending()) ||
				!reflect.DeepEqual(job, agent.Journal.Active()) || !reflect.DeepEqual(&plan, agent.Journal.ActivePlan()) {
				t.Fatalf("unvalidated claim changed pending reports, cursor, plan, or durable bytes: %v", err)
			}
			if reports != 0 || executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 0 || executor.v2ApplyCalls != 0 {
				t.Fatal("unvalidated fresh claim reported or mutated the active job")
			}
		})
	}
}
