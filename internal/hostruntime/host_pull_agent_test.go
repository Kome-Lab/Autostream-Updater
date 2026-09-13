package hostruntime

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestObserveOnlyHostAgentUsesEndpointlessOutboundControlLoop(t *testing.T) {
	var mu sync.Mutex
	var registration map[string]any
	var heartbeats []map[string]any
	var policyRequests []map[string]any
	var forbiddenCalls atomic.Int32
	heartbeatObserved := make(chan struct{}, 1)

	statusPort, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot reserve local socket for listener-free proof: %v", err)
	}
	defer statusPort.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "update-jobs") ||
			strings.Contains(r.URL.Path, "authorize") ||
			strings.Contains(r.URL.Path, "mutation-grants") {
			forbiddenCalls.Add(1)
			http.Error(w, "mutation endpoint must not be used", http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/services/register":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			mu.Lock()
			registration = body
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"service_id":"host-agent-a","service_type":"update_agent","transport_mode":"pull_v2","execution_host_id":"host-a","ownership_epoch":0}`))
		case "/services/host-agent/policy":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			mu.Lock()
			policyRequests = append(policyRequests, body)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{
				"service_id":"host-agent-a",
				"transport_mode":"pull_v2",
				"execution_host_id":"host-a",
				"ownership_epoch":0,
				"revision":7,
				"source_policy_revision":3,
				"local_executor_policy_revision":0,
				"observe_only":true,
				"targets":[{
					"service_id":"worker-a",
					"service_type":"worker",
					"deployment_mode":"systemd",
					"desired_endpoint":{"host":"127.0.0.1","port":18082,"ssl_enabled":false,"public_url":"http://127.0.0.1:18082"},
					"applied_endpoint":{"host":"127.0.0.1","port":18081,"ssl_enabled":false,"public_url":"http://127.0.0.1:18081"},
					"local_listen_endpoint":{"host":"127.0.0.1","port":18082,"ssl_enabled":false,"public_url":"http://127.0.0.1:18082"}
				}]
			}`))
		case "/services/heartbeat":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			mu.Lock()
			heartbeats = append(heartbeats, body)
			mu.Unlock()
			select {
			case heartbeatObserved <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer server.Close()

	bootstrap := managedHostAgentBootstrap(server.URL)
	agent, err := NewHostPullAgent(bootstrap, HostPullAgentOptions{
		StateDir:          t.TempDir(),
		HTTPClient:        server.Client(),
		PollInterval:      5 * time.Millisecond,
		HeartbeatInterval: 5 * time.Millisecond,
		ObserveTargets: func(_ context.Context, policy HostAgentPolicy) ([]HostTargetObservation, error) {
			if len(policy.Targets) != 1 || policy.Targets[0].ServiceID != "worker-a" {
				t.Fatalf("unexpected policy: %#v", policy)
			}
			return []HostTargetObservation{{
				ServiceID:        "worker-a",
				Availability:     TargetAvailabilityAvailable,
				ReportedPort:     18081,
				AvailabilityCode: "healthy",
			}}, nil
		},
		Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	select {
	case <-heartbeatObserved:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("observe-only heartbeat was not sent")
	}
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatal(err)
	}

	if forbiddenCalls.Load() != 0 {
		t.Fatalf("observe-only agent called %d mutation endpoints", forbiddenCalls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if registration == nil {
		t.Fatal("registration was not sent")
	}
	for _, forbidden := range []string{"host", "port", "ssl_enabled", "public_url", "execution_host_id", "ownership_epoch"} {
		if _, exists := registration[forbidden]; exists {
			t.Fatalf("endpointless registration included %q: %#v", forbidden, registration)
		}
	}
	if registration["transport_mode"] != HostTransportPullV2 {
		t.Fatalf("transport_mode = %#v", registration["transport_mode"])
	}
	if len(policyRequests) == 0 {
		t.Fatal("policy request was not captured")
	}
	for _, forbidden := range []string{"execution_host_id", "ownership_epoch", "host_id"} {
		if _, exists := policyRequests[0][forbidden]; exists {
			t.Fatalf("policy request self-asserted %q: %#v", forbidden, policyRequests[0])
		}
	}
	if policyRequests[0]["service_id"] != "host-agent-a" || policyRequests[0]["current_revision"] != float64(0) {
		t.Fatalf("policy request = %#v", policyRequests[0])
	}
	if len(heartbeats) == 0 {
		t.Fatal("heartbeat was not captured")
	}
	capabilities, ok := heartbeats[len(heartbeats)-1]["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("heartbeat capabilities = %#v", heartbeats[len(heartbeats)-1]["capabilities"])
	}
	if capabilities["observe_only"] != true ||
		capabilities["agent_protocol_version"] != HostAgentProtocolVersion ||
		capabilities["execution_host_id"] != "host-a" ||
		capabilities["ownership_epoch"] != float64(0) ||
		capabilities["policy_revision"] != float64(7) {
		t.Fatalf("unexpected host capabilities: %#v", capabilities)
	}
	availability, ok := capabilities["target_availability"].(map[string]any)
	if !ok || availability["worker-a"] != TargetAvailabilityAvailable {
		t.Fatalf("target availability = %#v", capabilities["target_availability"])
	}
	drift, ok := capabilities["port_drift"].(map[string]any)
	if !ok || drift["worker-a"] != true {
		t.Fatalf("port drift = %#v", capabilities["port_drift"])
	}
	if _, exists := heartbeats[len(heartbeats)-1]["api"]; exists {
		t.Fatalf("portless heartbeat included api endpoint: %#v", heartbeats[len(heartbeats)-1])
	}
}

func TestObserveOnlyHostAgentPreservesInterruptedJournalWithoutClaimOrReport(t *testing.T) {
	stateDir := t.TempDir()
	journal, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActive(&UpdateJob{
		ID: "job-awaiting-pull-v2", TargetID: "worker-a", ServiceType: "worker",
		DeploymentMode: ModeSystemd, TargetVersion: "v2.0.0", ReportSequence: 3,
	}); err != nil {
		t.Fatal(err)
	}

	var forbiddenCalls atomic.Int32
	heartbeatObserved := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/services/register":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"service_id":"host-agent-a","service_type":"update_agent","transport_mode":"pull_v2","execution_host_id":"host-a","ownership_epoch":1}`))
		case "/services/host-agent/policy":
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		case "/services/heartbeat":
			select {
			case heartbeatObserved <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			forbiddenCalls.Add(1)
			http.Error(w, "observe-only attempted a job operation", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	agent, err := NewHostPullAgent(managedHostAgentBootstrap(server.URL), HostPullAgentOptions{
		StateDir:          stateDir,
		HTTPClient:        server.Client(),
		PollInterval:      5 * time.Millisecond,
		HeartbeatInterval: 5 * time.Millisecond,
		Logf:              func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	select {
	case <-heartbeatObserved:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("heartbeat was not observed")
	}
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatal(err)
	}
	if forbiddenCalls.Load() != 0 {
		t.Fatalf("observe-only agent attempted %d job operations", forbiddenCalls.Load())
	}
	reopened, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if active := reopened.Active(); active == nil || active.ID != "job-awaiting-pull-v2" {
		t.Fatalf("recovery cursor was changed: %#v", active)
	}
}
