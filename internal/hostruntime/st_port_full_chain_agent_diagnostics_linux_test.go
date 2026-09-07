//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/controlplane"
)

const stPortChainPanelFailureLimit = 4

// These records contain only fixed protocol classifications and bounded counts.
// Job IDs, URLs, request/response bodies and error strings never enter them.
type stPortChainPanelFailure struct {
	Operation  string `json:"operation"`
	Route      string `json:"route"`
	Step       string `json:"step"`
	Class      string `json:"class"`
	HTTPStatus int    `json:"http_status"`
	Code       string `json:"code"`
	RootCalls  int64  `json:"root_calls"`
}

// Embed the actual client to retain all of its host-control interfaces. Only
// execution calls are observed, after delegation and before recovery can replace
// their errors. Root failures join this same ordered recorder. Labels mean first
// or subsequent observed boundary failure, not an unobserved internal cause.
// No request, return value or production recovery path is changed.
type stPortChainObservedPanel struct {
	*V2PanelClient
	execution HostPullExecutionControlPlane
	rootCalls func() int64
	mu        sync.Mutex
	records   []stPortChainPanelFailure
}

func (p *stPortChainObservedPanel) ClaimHost(ctx context.Context, request HostPullClaimRequest) (*UpdateJob, bool, error) {
	ctx, wire := stPortChainWireContext(ctx)
	job, clear, err := p.execution.ClaimHost(ctx, request)
	p.recordWire("claim", "claim", "none", err, wire)
	return job, clear, err
}

func (p *stPortChainObservedPanel) Report(ctx context.Context, jobID string, report JobReport) error {
	ctx, wire := stPortChainWireContext(ctx)
	err := p.execution.Report(ctx, jobID, report)
	operation := "progress"
	if report.PortReconfigure != nil {
		operation = "result"
	}
	p.recordWire(operation, "report", report.Status, err, wire)
	return err
}

func (p *stPortChainObservedPanel) IssueMutationGrant(ctx context.Context, jobID string, request MutationGrantRequest) (MutationGrant, error) {
	ctx, wire := stPortChainWireContext(ctx)
	grant, err := p.execution.IssueMutationGrant(ctx, jobID, request)
	p.recordWire("grant_issue", "mutation_grants", request.Operation, err, wire)
	return grant, err
}

func (p *stPortChainObservedPanel) record(operation, route, step string, err error) {
	p.recordWire(operation, route, step, err, nil)
}

func (p *stPortChainObservedPanel) recordWire(operation, route, step string, err error, wire *stPortChainWireFailure) {
	if err == nil {
		return
	}
	record := stPortChainPanelFailure{Operation: operation, Route: route, Step: step,
		Class: stPortChainClassifyError(err), Code: "unknown", RootCalls: p.rootCalls()}
	var panelErr *PanelHTTPError
	if errors.As(err, &panelErr) {
		record.HTTPStatus = panelErr.Status
		record.Code = panelErr.Code
		if wire != nil && wire.status == panelErr.Status && wire.code != "" {
			record.Code = wire.code
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.records) < stPortChainPanelFailureLimit {
		p.records = append(p.records, stPortChainSafePanelFailure(record))
	}
}

func (p *stPortChainObservedPanel) resetFailures() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = nil
}

func (p *stPortChainObservedPanel) failures() []stPortChainPanelFailure {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]stPortChainPanelFailure(nil), p.records...)
}

func stPortChainSafePanelFailure(v stPortChainPanelFailure) stPortChainPanelFailure {
	v.Operation = stPortChainPanelEnum(v.Operation, "claim", "progress", "grant_issue", "result", "root_apply", "root_reconcile")
	v.Route = stPortChainPanelEnum(v.Route, "claim", "report", "mutation_grants", "root_socket")
	v.Step = stPortChainPanelEnum(v.Step, "none", "claimed", "installing", "reconciling", "succeeded", "failed", "rolled_back", "port_reconfigure", "port_reconfigure_reconcile", "root_apply", "root_reconcile")
	v.Class = stPortChainSafeFailureClass(v.Class)
	if v.HTTPStatus < 100 || v.HTTPStatus > 599 {
		v.HTTPStatus = 0
	}
	if v.Code = stPortChainSafeWireCode(v.Code); v.Code == "" {
		v.Code = "unknown"
	}
	if v.RootCalls < 0 || v.RootCalls > 1000000 {
		v.RootCalls = -1
	}
	return v
}

// Preserve known CP boundary codes before the production adapter intentionally
// reduces unknown codes. Only the ordinary client's reads are observed: no
// eager body read, retry, request modification, or changed HTTP error is used.
type stPortChainWireKey struct{}
type stPortChainWireFailure struct {
	status int
	code   string
}

func stPortChainWireContext(ctx context.Context) (context.Context, *stPortChainWireFailure) {
	value := &stPortChainWireFailure{}
	return context.WithValue(ctx, stPortChainWireKey{}, value), value
}

type stPortChainWireTransport struct{ base http.RoundTripper }

func (transport stPortChainWireTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if wire, ok := request.Context().Value(stPortChainWireKey{}).(*stPortChainWireFailure); ok &&
		err == nil && response != nil && response.Body != nil && response.StatusCode >= 400 {
		wire.status = response.StatusCode
		response.Body = &stPortChainWireBody{ReadCloser: response.Body, wire: wire}
	}
	return response, err
}

type stPortChainWireBody struct {
	io.ReadCloser
	wire     *stPortChainWireFailure
	body     []byte
	complete bool
	oversize bool
}

func (body *stPortChainWireBody) Read(destination []byte) (int, error) {
	n, err := body.ReadCloser.Read(destination)
	if !body.oversize && len(body.body)+n <= 1<<20 {
		body.body = append(body.body, destination[:n]...)
	} else {
		body.oversize = true
		body.body = nil
	}
	if err == io.EOF {
		body.complete = true
	}
	return n, err
}

func (body *stPortChainWireBody) Close() error {
	if body.complete && !body.oversize {
		var value struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(body.body, &value) == nil {
			body.wire.code = stPortChainSafeWireCode(value.Code)
		}
	}
	body.body = nil
	return body.ReadCloser.Close()
}

func stPortChainSafeWireCode(code string) string {
	if safe := safeV2PanelHTTPErrorCode(code); safe != "" {
		return safe
	}
	// Literal errors at the real CP v2 lease, mutation and ownership boundaries.
	switch code {
	case "updater_v2_lease_binding_mismatch", "updater_v2_mutation_binding_mismatch",
		"system_update_ownership_conflict", "system_update_endpoint_revision_conflict":
		return code
	default:
		return ""
	}
}

func stPortChainObserveWire(panel *V2PanelClient) {
	// The embedded legacy Panel client uses this timeout when HTTP is nil.
	client := &http.Client{Timeout: 15 * time.Second}
	if panel.HTTP != nil {
		client = panel.HTTP
	}
	copy := *client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	copy.Transport = stPortChainWireTransport{base: transport}
	panel.HTTP = &copy
}

func stPortChainPanelEnum(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return candidate
		}
	}
	return "unknown"
}

// Exercise the real Agent's grant-failure -> reconciling-report-failure path.
// The existing unit fixture supplies distinct failures; the full-chain runtime
// still delegates to the actual V2PanelClient and real CP without substitution.
func TestSTPortAgentDiagnosticsRetainPrimaryGrantBeforeRecoveryReportFailure(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	primary := &PanelHTTPError{Status: 409, Code: "stale_fence"}
	secondary := &PanelHTTPError{Status: 409, Code: "revision_conflict"}
	panel.grantErrors = []error{primary}
	panel.reportErrors = []error{nil, nil, secondary}
	observed := &stPortChainObservedPanel{execution: panel, rootCalls: func() int64 {
		return int64(executor.portApplyCalls + executor.portReconCalls)
	}}
	err := agent.processPortReconfigurationJob(context.Background(), observed, binding, policy, *panel.job)
	if err != secondary {
		t.Fatal("observer changed the production recovery error")
	}
	got := observed.failures()
	if len(got) != 2 || got[0].Operation != "grant_issue" || got[0].Route != "mutation_grants" ||
		got[0].Step != "port_reconfigure" || got[0].Code != "stale_fence" || got[0].HTTPStatus != 409 || got[0].RootCalls != 0 ||
		got[1].Operation != "progress" || got[1].Route != "report" || got[1].Step != "reconciling" ||
		got[1].Code != "revision_conflict" || got[1].HTTPStatus != 409 || got[1].RootCalls != 0 {
		t.Fatal("primary and secondary failures were not preserved independently")
	}
	if executor.portApplyCalls != 0 || executor.portReconCalls != 0 || agent.Journal.ActivePortPlan() == nil {
		t.Fatal("failure observation changed port mutation or durable recovery state")
	}
	observed.resetFailures()
	if len(observed.failures()) != 0 {
		t.Fatal("diagnostics leaked across process commands")
	}
}

func TestSTPortAgentDiagnosticsBoundAndSanitizeAllPublishedFields(t *testing.T) {
	observed := &stPortChainObservedPanel{rootCalls: func() int64 { return 1000001 }}
	for i := 0; i < stPortChainPanelFailureLimit+2; i++ {
		observed.record("untrusted", "untrusted", "untrusted", &PanelHTTPError{Status: 999, Code: "untrusted"})
	}
	got := observed.failures()
	if len(got) != stPortChainPanelFailureLimit {
		t.Fatal("failure records exceeded the bounded command budget")
	}
	for _, v := range got {
		if v.Operation != "unknown" || v.Route != "unknown" || v.Step != "unknown" || v.HTTPStatus != 0 || v.Code != "unknown" || v.RootCalls != -1 {
			t.Fatal("untrusted diagnostic field was retained")
		}
	}
}

type stPortChainDiagnosticReadCloser struct {
	*strings.Reader
	closed int
}

func (reader *stPortChainDiagnosticReadCloser) Close() error {
	reader.closed++
	return nil
}

func TestSTPortAgentDiagnosticsPreserveWireCodeWithoutChangingProductionError(t *testing.T) {
	for _, item := range []struct {
		name, payload, code string
		partial             bool
	}{
		{"known_cp_boundary", `{"code":"updater_v2_lease_binding_mismatch"}`, "updater_v2_lease_binding_mismatch", false},
		{"unknown_code", `{"code":"untrusted_marker"}`, "", false},
		{"invalid_body", `{"code":`, "", false},
		{"oversize_body", strings.Repeat(" ", (1<<20)+1), "", false},
		{"incomplete_read", `{"code":"updater_v2_lease_binding_mismatch"}`, "", true},
	} {
		t.Run(item.name, func(t *testing.T) {
			wire := &stPortChainWireFailure{status: http.StatusConflict}
			original := &stPortChainDiagnosticReadCloser{Reader: strings.NewReader(item.payload)}
			body := &stPortChainWireBody{ReadCloser: original, wire: wire}
			if item.partial {
				buffer := make([]byte, 1)
				if n, err := body.Read(buffer); n != 1 || err != nil || buffer[0] != item.payload[0] {
					t.Fatal("observation changed a partial body read")
				}
			} else if got, err := io.ReadAll(body); err != nil || string(got) != item.payload {
				t.Fatal("observation changed response bytes or read completion")
			}
			if body.Close() != nil || original.closed != 1 || wire.code != item.code || len(body.body) != 0 {
				t.Fatal("wire observation retained an invalid code/body or changed close")
			}
			// The production adapter still strips its unsupported CP code; the
			// test observer alone retains the explicitly permitted wire code.
			productionErr := v2PanelControlPlaneError("mutation grant", &controlplane.HTTPError{
				Status: http.StatusConflict, Code: "updater_v2_lease_binding_mismatch",
			})
			panelErr, ok := productionErr.(*PanelHTTPError)
			if !ok || panelErr.Code != "" || panelErr.Status != http.StatusConflict {
				t.Fatal("production error classification changed")
			}
			observed := &stPortChainObservedPanel{rootCalls: func() int64 { return 0 }}
			observed.recordWire("grant_issue", "mutation_grants", "port_reconfigure", productionErr, wire)
			want := item.code
			if want == "" {
				want = "unknown"
			}
			if records := observed.failures(); len(records) != 1 || records[0].Code != want || records[0].RootCalls != 0 {
				t.Fatal("wire code was lost or an unknown value escaped")
			}
		})
	}
}
