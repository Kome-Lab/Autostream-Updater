package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

// The Agent, V2Panel, durable Journal, and HTTP disconnect are real. The CP
// acceptance and root result are fixtures, not a full CP/root integration run.
func TestSTPortAgentTerminalAcknowledgementLossResendsIdenticalResult(t *testing.T) {
	for _, mode := range []contracts.SystemUpdatePortMode{contracts.SystemUpdatePortModeLocalOnly, contracts.SystemUpdatePortModeLocalAndAdvertised} {
		for _, kind := range []contracts.SystemUpdatePortReconfigurationResult{contracts.SystemUpdatePortReconfigurationApplied, contracts.SystemUpdatePortReconfigurationUnchanged, contracts.SystemUpdatePortReconfigurationRolledBack} {
			t.Run(string(mode)+"/"+string(kind), func(t *testing.T) {
				lease, job, policy, plan := agentPortV2Fixture(t, mode, kind == contracts.SystemUpdatePortReconfigurationUnchanged)
				expectedGrants := 1
				if kind == contracts.SystemUpdatePortReconfigurationUnchanged {
					expectedGrants = 0
				}
				dir := t.TempDir()
				journal, err := OpenJournal(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, err := range []error{journal.SetActive(&job), journal.SetActivePortPlan(plan), journal.StagePortPolicy(policy, job, plan)} {
					if err != nil {
						t.Fatal(err)
					}
				}
				rootRef := plan.Target
				if kind == contracts.SystemUpdatePortReconfigurationUnchanged {
					rootRef = plan.Before
				} else if kind == contracts.SystemUpdatePortReconfigurationRolledBack {
					rootRef = plan.Rollback
				}
				observedAt := lease.LeaseExpiresAt.Add(-4 * time.Minute)
				now := observedAt.Add(30 * time.Second)
				rootResult := agentPortObservedResult(plan, kind, observedAt, false)
				expected := clonePortResult(rootResult.PortResult)
				expected.Observation.AgentProjectionVerified = true
				executor := &hostPullExecutionTestExecutor{portReconResult: &rootResult}
				probe := LocalExecutorProbe{PortContractVersion: 2, PolicyTransitionVersion: 1,
					SourcePolicyRevision: rootRef.SourcePolicyRevision, ProjectionRevision: rootRef.ProjectionRevision,
					PolicyRevision: rootRef.ExecutorPolicyRevision, PolicySHA256: rootRef.ExecutorPolicySHA256,
					AgentUID: 1201, AgentGID: 1202, EndpointRevision: rootRef.AppliedEndpointRevision, ObservedAt: now,
					ServiceID: job.TargetID, ServiceType: job.EffectiveType(), DeploymentMode: job.DeploymentMode,
					ConfigRevision: rootRef.ConfigRevision, ConfigSHA256: rootRef.ConfigSHA256,
					CurrentVersion: "v1.2.3", MainPID: 51, ListenerPID: 51, ControlGroup: "/system.slice/worker.service",
					ListenerAddress: "127.0.0.1:" + strconv.Itoa(rootRef.LocalListenPort)}
				advanceSTPortLease(t, &lease)
				claims, grants, receipts, acceptances := 0, 0, 0, 0
				var firstBody []byte
				var firstPath string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/services/update-jobs/claim" {
						var claim contracts.UpdateAgentClaimRequest
						if json.NewDecoder(r.Body).Decode(&claim) != nil || claim.ActiveJobID != job.ID {
							t.Error("claim did not retain the saved job")
						}
						claims++
						writeV2PanelJSON(t, w, http.StatusOK, lease)
						return
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error("read acknowledgement-loss request")
						return
					}
					if strings.HasSuffix(r.URL.Path, "/mutation-grants") {
						var issue contracts.UpdaterMutationGrantIssueRequest
						if contracts.ValidateUpdaterMutationGrantIssueRequest(now, body) != nil || json.Unmarshal(body, &issue) != nil ||
							issue.Binding.Operation != contracts.UpdaterMutationPortReconfigureReconcile || issue.Binding.SessionID != plan.SessionID {
							t.Error("grant changed the saved recovery intent")
						}
						grants++
						writeV2PanelJSON(t, w, http.StatusCreated, contracts.UpdaterMutationGrantIssueResponse{GrantToken: strings.Repeat("g", 32), ExpiresAt: now.Add(time.Minute)})
						return
					}
					var fields map[string]json.RawMessage
					if json.Unmarshal(body, &fields) != nil {
						t.Error("decode acknowledgement-loss report")
						return
					}
					if _, progress := fields["phase"]; progress {
						if contracts.ValidateUpdaterProgressEnvelope(lease, body) != nil {
							t.Error("invalid progress before accepted terminal")
						}
						writeV2PanelJSON(t, w, http.StatusOK, nil)
						return
					}
					var result contracts.UpdaterResultEnvelope
					if contracts.ValidateUpdaterResultEnvelope(lease, body) != nil || json.Unmarshal(body, &result) != nil || result.PortReconfigure == nil ||
						!contracts.EqualSystemUpdatePortResults(*expected, *result.PortReconfigure) || !result.PortReconfigure.Observation.ObservedAt.Equal(observedAt) {
						t.Error("terminal changed the typed result or first observation")
					}
					receipts++
					if receipts == 1 {
						// Acceptance precedes the fault. Buffer the HTTP 200 response,
						// then close without flushing any response bytes to the Agent.
						firstBody, firstPath = append([]byte(nil), body...), r.URL.Path
						acceptances++
						conn, rw, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error("hijack terminal response")
							return
						}
						if _, err := rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); err != nil {
							t.Error("buffer terminal acknowledgement")
						}
						_ = conn.Close()
						return
					}
					if receipts != 2 || r.URL.Path != firstPath || !bytes.Equal(body, firstBody) {
						t.Error("retry changed the same-job terminal HTTP body")
					}
					writeV2PanelJSON(t, w, http.StatusOK, nil)
				}))
				defer server.Close()
				panel := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
				panel.Now = func() time.Time { return now }
				agent := &HostPullAgent{Bootstrap: Config{NodeID: job.AgentServiceID}, StateDir: dir, Journal: journal,
					ControlPlane: panel, PortExecutor: executor, ObserveTargets: NewLocalExecutorTargetObserver(agentPortProbeStub{probe})}
				binding := HostAgentBinding{ExecutionHostID: job.HostID, OwnershipEpoch: job.OwnershipEpoch, TransportMode: HostTransportPullV2}
				if err := agent.executeOnce(context.Background(), binding, policy); err == nil || IsPermanentReportError(err) {
					t.Fatal("lost HTTP 200 did not leave a retryable transport failure")
				}
				if claims != 1 || grants != expectedGrants || receipts != 1 || acceptances != 1 || executor.v2PortReconCalls != 1 {
					t.Fatal("initial recovery did not reach exactly one accepted terminal")
				}
				// This is a same-process transport retry. OpenJournal models a
				// process restart and deliberately drops lease-bound pending reports;
				// inspect the persisted state without replacing the live lease/cache.
				persistedBytes, err := os.ReadFile(journal.path)
				if err != nil {
					t.Fatal(err)
				}
				var persisted journalData
				if err := json.Unmarshal(persistedBytes, &persisted); err != nil {
					t.Fatal("decode persisted state after acknowledgement loss")
				}
				if persisted.ActiveJob == nil || persisted.ActiveJob.ID != job.ID || persisted.ActiveJob.PortResult == nil ||
					!contracts.EqualSystemUpdatePortResults(*persisted.ActiveJob.PortResult, *expected) || len(persisted.Pending) != 1 {
					t.Fatalf("accepted state was not durable: active_present=%t pending_count=%d", persisted.ActiveJob != nil, len(persisted.Pending))
				}
				active, pending := journal.Active(), journal.Pending()
				if active == nil || active.ID != job.ID || active.PortResult == nil || !contracts.EqualSystemUpdatePortResults(*active.PortResult, *expected) ||
					len(pending) != 1 || pending[0].JobID != job.ID || pending[0].Report.PortReconfigure == nil ||
					!pending[0].Report.PortReconfigure.Observation.ObservedAt.Equal(observedAt) {
					t.Fatalf("lost acknowledgement did not retain the same job and result: active_present=%t pending_count=%d", active != nil, len(pending))
				}
				now = now.Add(time.Minute)
				if err := agent.flushExecutionReports(context.Background(), panel); err != nil {
					t.Fatal(err)
				}
				if claims != 1 || grants != expectedGrants || receipts != 2 || acceptances != 1 || executor.v2PortReconCalls != 1 ||
					executor.v2PortApplyCalls != 0 || executor.portReconCalls != 0 || executor.portApplyCalls != 0 || executor.applyCalls != 0 || executor.v2ApplyCalls != 0 {
					t.Fatal("terminal resend acquired a new job or repeated a root execution")
				}
				if reopened, err := OpenJournal(dir); err != nil || reopened.Active() != nil || len(reopened.Pending()) != 0 {
					t.Fatal("delivered acknowledgement did not durably clear the cursor")
				}
			})
		}
	}
}
