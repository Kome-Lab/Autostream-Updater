package hostruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

// This focused adapter/Agent check complements the fixed-CP process oracle.
// Its HTTP lease fixture is not evidence of Control Panel lease generation.
func TestSoftwareClaimSeparatesConfigurationAndPolicyRevisions(t *testing.T) {
	for _, authorities := range []struct {
		name    string
		s, p, e int64
	}{
		{"configuration_one_policy_eight", 8, 8, 8},
		{"all_revision_authorities_differ", 11, 13, 17},
	} {
		t.Run(authorities.name, func(t *testing.T) {
			agent, _, executor, binding, policy := newHostPullExecutionHarness(t, false)
			binding.OwnershipEpoch = 3
			policy.OwnershipEpoch = 3
			policy.SourcePolicyRevision, policy.Revision, policy.LocalExecutorPolicyRevision = authorities.s, authorities.p, authorities.e
			now := time.Now().UTC()
			lease := v2PanelSoftwareLease(t, now)
			lease.LeaseGeneration = 1
			authorization := &lease.Command.MutationAuthorization
			authorization.UpdaterID, authorization.HostID, authorization.Fence = agent.Bootstrap.NodeID, binding.ExecutionHostID, 3
			authorization.DesiredRevision, authorization.Target.ExpectedConfigRevision = 1, 1
			hostPullRefreshV2CommandDigest(t, &lease.Command)
			var phases []string
			var outcomes []contracts.UpdaterOutcome
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				switch {
				case request.URL.Path == "/services/update-jobs/claim":
					writeV2PanelJSON(t, w, http.StatusOK, lease)
				case strings.HasSuffix(request.URL.Path, "/report"):
					var raw json.RawMessage
					if err := json.NewDecoder(request.Body).Decode(&raw); err != nil {
						t.Error(err)
						return
					}
					var discriminator map[string]json.RawMessage
					if err := json.Unmarshal(raw, &discriminator); err != nil {
						t.Error(err)
						return
					}
					if _, ok := discriminator["phase"]; ok {
						if err := contracts.ValidateUpdaterProgressEnvelope(lease, raw); err != nil {
							t.Error(err)
						}
						var progress contracts.UpdaterProgressEnvelope
						_ = json.Unmarshal(raw, &progress)
						if progress.DesiredRevision != 1 {
							t.Error("progress substituted policy for C")
						}
						phases = append(phases, progress.Phase)
					} else {
						if err := contracts.ValidateUpdaterResultEnvelope(lease, raw); err != nil {
							t.Error(err)
						}
						var result contracts.UpdaterResultEnvelope
						_ = json.Unmarshal(raw, &result)
						outcomes = append(outcomes, result.Outcome)
					}
					writeV2PanelJSON(t, w, http.StatusOK, nil)
				default:
					t.Error("unexpected execution endpoint")
					writeV2PanelJSON(t, w, http.StatusNotFound, nil)
				}
			}))
			defer server.Close()
			agent.ControlPlane = NewV2PanelClient(PanelClient{BaseURL: server.URL, HTTP: server.Client(), Token: "synthetic-runtime-token"})
			agent.Downloader = hostPullFailingDownloader{}
			if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
				t.Fatalf("C=1 S=%d P=%d E=%d F=3 failed before artifact verification: %v", authorities.s, authorities.p, authorities.e, err)
			}
			if strings.Join(phases, ",") != "accepted,preparing" || len(outcomes) != 1 || outcomes[0] != contracts.UpdaterOutcomeFailed {
				t.Fatalf("claim/progress/artifact-rejection convergence: phases=%v outcomes=%v", phases, outcomes)
			}
			if agent.Journal.Active() != nil || executor.stageCalls != 0 || executor.applyCalls != 0 || executor.v2ApplyCalls != 0 {
				t.Fatal("artifact failure did not terminate before root mutation")
			}
		})
	}
}
