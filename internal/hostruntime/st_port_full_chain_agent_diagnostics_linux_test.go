//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
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
	job, clear, err := p.execution.ClaimHost(ctx, request)
	p.record("claim", "claim", "none", err)
	return job, clear, err
}

func (p *stPortChainObservedPanel) Report(ctx context.Context, jobID string, report JobReport) error {
	err := p.execution.Report(ctx, jobID, report)
	operation := "progress"
	if report.PortReconfigure != nil {
		operation = "result"
	}
	p.record(operation, "report", report.Status, err)
	return err
}

func (p *stPortChainObservedPanel) IssueMutationGrant(ctx context.Context, jobID string, request MutationGrantRequest) (MutationGrant, error) {
	grant, err := p.execution.IssueMutationGrant(ctx, jobID, request)
	p.record("grant_issue", "mutation_grants", request.Operation, err)
	return grant, err
}

func (p *stPortChainObservedPanel) record(operation, route, step string, err error) {
	if err == nil {
		return
	}
	record := stPortChainPanelFailure{Operation: operation, Route: route, Step: step,
		Class: stPortChainClassifyError(err), Code: "unknown", RootCalls: p.rootCalls()}
	var panelErr *PanelHTTPError
	if errors.As(err, &panelErr) {
		record.HTTPStatus = panelErr.Status
		record.Code = panelErr.Code
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
	if v.Code = safeV2PanelHTTPErrorCode(v.Code); v.Code == "" {
		v.Code = "unknown"
	}
	if v.RootCalls < 0 || v.RootCalls > 1000000 {
		v.RootCalls = -1
	}
	return v
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
