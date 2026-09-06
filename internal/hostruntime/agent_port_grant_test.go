package hostruntime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

func TestSTPortAgentGrantSeparatesImmutableIntentFromRuntimeSession(t *testing.T) {
	for _, mode := range []contracts.SystemUpdatePortMode{contracts.SystemUpdatePortModeLocalOnly, contracts.SystemUpdatePortModeLocalAndAdvertised} {
		t.Run(string(mode), func(t *testing.T) {
			lease, job, _, plan := agentPortV2Fixture(t, mode, false)
			now := lease.LeaseExpiresAt.Add(-4 * time.Minute)
			issues := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/services/update-jobs/claim" {
					writeV2PanelJSON(t, w, http.StatusOK, lease)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || contracts.ValidateUpdaterMutationGrantIssueRequest(now, body) != nil {
					t.Error("port grant wire is invalid")
				}
				var issue contracts.UpdaterMutationGrantIssueRequest
				if json.Unmarshal(body, &issue) != nil || issue.Binding.Lease.Command.DesiredOperation.PortReconfigure.PortPlanSHA256 != plan.PortIntentSHA256 ||
					issue.Binding.SessionID != plan.SessionID || issue.Binding.Lease.Command.MutationAuthorization.DesiredRevision != plan.Target.ConfigRevision {
					t.Error("grant changed stable intent or runtime session")
				}
				issues++
				writeV2PanelJSON(t, w, http.StatusCreated, contracts.UpdaterMutationGrantIssueResponse{GrantToken: strings.Repeat("g", 32), ExpiresAt: now.Add(2 * time.Minute)})
			}))
			defer server.Close()
			client := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
			client.Now = func() time.Time { return now }
			if _, _, err := client.ClaimHost(context.Background(), v2PanelClaimRequest("")); err != nil {
				t.Fatal(err)
			}
			request := MutationGrantRequest{ServiceID: job.AgentServiceID, MutationGrantBinding: MutationGrantBinding{
				LeaseGeneration: job.LeaseGeneration, HostID: job.HostID, TransportMode: HostTransportPullV2, OwnershipEpoch: job.OwnershipEpoch,
				PolicyRevision: job.PolicyRevision, TargetID: job.TargetID, ServiceType: job.EffectiveType(), DeploymentMode: job.DeploymentMode,
				Operation: "port_reconfigure", JobOperation: updateJobOperationPortReconfigure, PlanSHA256: plan.PortPlanSHA256, SessionID: plan.SessionID,
				PortReconfigure: plan.mutationGrantBinding(),
			}}
			if request.PlanSHA256 == request.PortReconfigure.PortPlanSHA256 {
				t.Fatal("fixture does not separate runtime and intent digests")
			}
			if _, err := client.IssueMutationGrant(context.Background(), job.ID, request); err != nil || issues != 1 {
				t.Fatalf("valid port grant was blocked: %v", err)
			}
			for _, name := range []string{"runtime hash", "session", "JP", "desired plan"} {
				t.Run(name, func(t *testing.T) {
					mutant := request
					mutant.PortReconfigure = clonePortMutationBinding(request.PortReconfigure)
					switch name {
					case "runtime hash":
						mutant.PlanSHA256 = strings.Repeat("9", 64)
					case "session":
						mutant.SessionID = "session-2234567890abcdef"
					case "JP":
						mutant.PolicyRevision = plan.Target.ProjectionRevision
					case "desired plan":
						mutant.PortReconfigure.Target.LocalListenPort++
					}
					if _, err := client.IssueMutationGrant(context.Background(), job.ID, mutant); err == nil || issues != 1 {
						t.Fatal("changed grant authority reached the issuer")
					}
				})
			}
		})
	}
}
