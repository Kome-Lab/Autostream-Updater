//go:build linux

package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
	"github.com/example/autostream-control-panel/internal/store"
)

type softwareUpdateChainCPWire struct {
	mu                          sync.Mutex
	ClaimConfig                 int64  `json:"claim_config"`
	ExpectedConfig              int64  `json:"expected_config"`
	ProgressConfig              int64  `json:"progress_config"`
	ProgressCount               int    `json:"progress_count"`
	GrantConfig                 int64  `json:"grant_config"`
	GrantPolicy                 int64  `json:"grant_policy"`
	GrantCount                  int    `json:"grant_count"`
	TerminalConfig              int64  `json:"terminal_config"`
	TerminalStatus              string `json:"terminal_status"`
	ExpiredGrantStoreRejections int    `json:"expired_grant_store_rejections"`
	expiryProbe                 bool
}

func (m *softwareUpdateChainCPWire) snapshot() any {
	return struct {
		ClaimConfig                 int64  `json:"claim_config"`
		ExpectedConfig              int64  `json:"expected_config"`
		ProgressConfig              int64  `json:"progress_config"`
		ProgressCount               int    `json:"progress_count"`
		GrantConfig                 int64  `json:"grant_config"`
		GrantPolicy                 int64  `json:"grant_policy"`
		GrantCount                  int    `json:"grant_count"`
		TerminalConfig              int64  `json:"terminal_config"`
		TerminalStatus              string `json:"terminal_status"`
		ExpiredGrantStoreRejections int    `json:"expired_grant_store_rejections"`
	}{m.ClaimConfig, m.ExpectedConfig, m.ProgressConfig, m.ProgressCount, m.GrantConfig, m.GrantPolicy, m.GrantCount, m.TerminalConfig, m.TerminalStatus, m.ExpiredGrantStoreRejections}
}

// Failpoints affect delivery after the actual handler/store accepts a request.
// They never fabricate a lease, grant, applied version or accepted result.
func softwareUpdateChainTransport(f *stPortChainCP, wire *softwareUpdateChainCPWire) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); token != "" {
			f.rememberSecret(token)
		}
		for _, c := range r.Cookies() {
			f.rememberSecret(c.Value)
		}
		var payload []byte
		if r.Method == http.MethodPost && isSystemUpdateExecutionPath(r.URL.Path) {
			var err error
			payload, err = io.ReadAll(io.LimitReader(r.Body, stPortChainBound+1))
			if err != nil || len(payload) > stPortChainBound {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(payload))
			f.rememberWireSecrets(payload)
		}
		// The store's explicit clock argument is an existing production seam.
		// Check the unmodified incoming real grant intent just past the original
		// persisted expiry. No expiry, lease, grant or host clock is rewritten.
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/mutation-grants") {
			wire.mu.Lock()
			probe := wire.expiryProbe
			wire.mu.Unlock()
			if probe {
				var request contracts.UpdaterMutationGrantIssueRequest
				if json.Unmarshal(payload, &request) != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				jobID := request.Binding.Lease.Command.MutationAuthorization.JobID
				job, err := f.updates.GetSystemUpdateJob(r.Context(), jobID)
				binding, bindingErr := systemUpdateV2StoreGrantBinding(job, request.Binding)
				if err != nil || bindingErr != nil || job.LeaseExpiresAt == nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				_, issueErr := f.updates.IssueSystemUpdateMutationGrant(r.Context(), jobID,
					store.IssueSystemUpdateMutationGrantParams{ProtocolVersion: 2, AgentServiceID: job.AgentServiceID,
						ExecutionHostID: job.ExecutionHostID, LeaseGeneration: job.LeaseGeneration, Binding: binding},
					job.LeaseExpiresAt.Add(time.Microsecond), store.SystemUpdateMutationGrantMaxTTL)
				if !errors.Is(issueErr, store.ErrSystemUpdateLeaseInvalid) {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				wire.mu.Lock()
				wire.ExpiredGrantStoreRejections++
				wire.expiryProbe = false
				wire.mu.Unlock()
			}
		}
		buffer := httptest.NewRecorder()
		f.handler.ServeHTTP(buffer, r)
		if buffer.Body.Len() > stPortChainBound {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		f.rememberWireSecrets(buffer.Body.Bytes())
		claim := r.Method == http.MethodPost && r.URL.Path == "/services/update-jobs/claim" && buffer.Code == http.StatusOK
		consume := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/consume") && buffer.Code == http.StatusNoContent
		grant := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/mutation-grants") && buffer.Code == http.StatusCreated
		report := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/report") && buffer.Code == http.StatusOK
		terminal := false
		progressPhase := ""
		jobID := ""
		wire.mu.Lock()
		if claim {
			var lease contracts.UpdaterLeaseEnvelope
			if json.Unmarshal(buffer.Body.Bytes(), &lease) == nil && lease.Command.CommandID != "" {
				wire.ClaimConfig = lease.Command.MutationAuthorization.DesiredRevision
				wire.ExpectedConfig = lease.Command.MutationAuthorization.Target.ExpectedConfigRevision
			}
		}
		if grant {
			var request contracts.UpdaterMutationGrantIssueRequest
			if json.Unmarshal(payload, &request) == nil {
				wire.GrantConfig = request.Binding.Lease.Command.MutationAuthorization.DesiredRevision
				job, err := store.NewMariaDBSystemUpdateStore(f.reads).GetSystemUpdateJob(r.Context(), request.Binding.Lease.Command.MutationAuthorization.JobID)
				if err == nil {
					wire.GrantPolicy = job.PolicyRevision
				}
				wire.GrantCount++
			}
		}
		if report {
			var shape struct {
				Phase   string `json:"phase"`
				Outcome string `json:"outcome"`
			}
			if json.Unmarshal(payload, &shape) == nil && shape.Phase != "" {
				progressPhase = shape.Phase
				var progress contracts.UpdaterProgressEnvelope
				if json.Unmarshal(payload, &progress) == nil {
					wire.ProgressConfig = progress.DesiredRevision
					wire.ProgressCount++
				}
			} else if shape.Outcome != "" {
				var result contracts.UpdaterResultEnvelope
				if json.Unmarshal(payload, &result) == nil && result.PortReconfigure == nil {
					jobID = result.CommandID
					jobID = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/services/update-jobs/"), "/report")
					job, err := store.NewMariaDBSystemUpdateStore(f.reads).GetSystemUpdateJob(r.Context(), jobID)
					terminal = err == nil && (job.Status == store.SystemUpdateStatusSucceeded || job.Status == store.SystemUpdateStatusFailed || job.Status == store.SystemUpdateStatusRolledBack)
					if terminal {
						wire.TerminalConfig = result.DesiredRevision
						wire.TerminalStatus = job.Status
					}
				}
			}
		}
		wire.mu.Unlock()
		f.mu.Lock()
		if claim {
			f.claims++
		}
		if consume {
			f.consumes++
		}
		if terminal {
			f.terminals++
			sha := contracts.ComputeSystemUpdatePortBytesSHA256(payload)
			if f.terminalJob != jobID {
				f.terminalJob, f.firstTerminalSHA = jobID, sha
			}
			f.lastTerminalSHA = sha
		}
		drop := (f.fault == "claim_after" && claim) || (f.fault == "terminal_after" && terminal) ||
			(f.fault == "progress_claimed_after" && progressPhase == "claimed") ||
			(f.fault == "progress_verifying_after" && progressPhase == "verifying")
		if drop {
			f.fault = ""
			f.dropped++
		}
		f.mu.Unlock()
		if drop {
			if h, ok := w.(http.Hijacker); ok {
				if conn, _, err := h.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
			panic(http.ErrAbortHandler)
		}
		for k, v := range buffer.Header() {
			w.Header()[k] = append([]string(nil), v...)
		}
		w.WriteHeader(buffer.Code)
		_, _ = w.Write(buffer.Body.Bytes())
	})
}
