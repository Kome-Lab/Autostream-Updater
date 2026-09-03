package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestFetchHostAgentPolicyRejectsUnknownFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{
			"service_id":"host-agent-a",
			"transport_mode":"pull_v2",
			"execution_host_id":"host-a",
			"ownership_epoch":1,
			"revision":1,
			"source_policy_revision":1,
			"local_executor_policy_revision":1,
			"observe_only":false,
			"targets":[],
			"unexpected":"must fail closed"
		}`))
	}))
	defer server.Close()

	client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
	if _, _, err := client.FetchHostAgentPolicy(context.Background(), "host-agent-a", 0); err == nil || !strings.Contains(err.Error(), "decode host agent policy") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestFetchHostAgentPolicyRejectsCrossHostBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{
			"service_id":"different-host-agent",
			"transport_mode":"pull_v2",
			"execution_host_id":"host-b",
			"ownership_epoch":1,
			"revision":1,
			"source_policy_revision":1,
			"local_executor_policy_revision":1,
			"observe_only":false,
			"targets":[]
		}`))
	}))
	defer server.Close()

	client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
	if _, _, err := client.FetchHostAgentPolicy(context.Background(), "host-agent-a", 0); err == nil ||
		!strings.Contains(err.Error(), "identity, revision, or mode is invalid") {
		t.Fatalf("cross-host policy error = %v", err)
	}
}

func TestFetchHostAgentPolicyAcceptsSamePolicyRevisionWithRefreshedTargetConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(`{
			"service_id":"host-agent-a",
			"transport_mode":"pull_v2",
			"execution_host_id":"host-a",
			"ownership_epoch":1,
			"revision":4,
			"source_policy_revision":2,
			"local_executor_policy_revision":3,
			"local_executor_policy_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"observe_only":false,
			"targets":[{
				"service_id":"worker-a",
				"service_type":"worker",
				"deployment_mode":"systemd",
				"applied_config_revision":2,
				"desired_endpoint":{"host":"127.0.0.1","port":28084,"public_url":"http://127.0.0.1:28084"},
				"applied_endpoint":{"host":"127.0.0.1","port":28084,"public_url":"http://127.0.0.1:28084"},
				"local_listen_endpoint":{"host":"127.0.0.1","port":28084,"public_url":"http://127.0.0.1:28084"},
				"local_health_endpoint":{"host":"127.0.0.1","port":28084,"public_url":"http://127.0.0.1:28084"}
			}]
		}`))
	}))
	defer server.Close()

	client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
	policy, changed, err := client.FetchHostAgentPolicy(context.Background(), "host-agent-a", 4)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || policy == nil || len(policy.Targets) != 1 ||
		policy.Targets[0].AppliedConfigRevision != 2 ||
		policy.Targets[0].AppliedEndpoint == nil ||
		policy.Targets[0].AppliedEndpoint.Port != 28084 {
		t.Fatalf("same-revision refreshed policy = %#v changed=%v", policy, changed)
	}
}

func TestHostAgentPolicyRejectsNonHTTPURLAndPaddedDuplicateTarget(t *testing.T) {
	base := HostAgentPolicy{
		ServiceID:                   "host-agent-a",
		TransportMode:               HostTransportPullV2,
		ExecutionHostID:             "host-a",
		OwnershipEpoch:              1,
		Revision:                    1,
		SourcePolicyRevision:        1,
		LocalExecutorPolicyRevision: 1,
		LocalExecutorPolicySHA256:   "sha256:" + strings.Repeat("a", 64),
		ObserveOnly:                 false,
	}
	t.Run("non HTTP endpoint", func(t *testing.T) {
		policy := base
		policy.Targets = []HostAgentPolicyTarget{{
			ServiceID:       "worker-a",
			ServiceType:     "worker",
			DeploymentMode:  ModeSystemd,
			DesiredEndpoint: &HostAgentEndpoint{Host: "127.0.0.1", Port: 18081, PublicURL: "file:///tmp/fake-health"},
		}}
		if err := policy.validateForService("host-agent-a", 0); err == nil {
			t.Fatal("non-HTTP endpoint was accepted")
		}
	})
	t.Run("padded duplicate", func(t *testing.T) {
		policy := base
		policy.Targets = []HostAgentPolicyTarget{
			{ServiceID: "worker-a", ServiceType: "worker", DeploymentMode: ModeSystemd},
			{ServiceID: " worker-a ", ServiceType: "worker", DeploymentMode: ModeSystemd},
		}
		if err := policy.validateForService("host-agent-a", 0); err == nil {
			t.Fatal("padded duplicate target was accepted")
		}
	})
}

func TestHostAgentPolicyObserveOnlyMatchesOwnershipEpochExactly(t *testing.T) {
	base := HostAgentPolicy{
		ServiceID: "host-agent-a", TransportMode: HostTransportPullV2,
		ExecutionHostID: "host-a", Revision: 1,
		SourcePolicyRevision: 1, LocalExecutorPolicyRevision: 1,
		LocalExecutorPolicySHA256: "sha256:" + strings.Repeat("a", 64),
	}
	for name, policy := range map[string]HostAgentPolicy{
		"observer active flag": func() HostAgentPolicy {
			value := base
			value.OwnershipEpoch = 0
			value.ObserveOnly = false
			return value
		}(),
		"owner observer flag": func() HostAgentPolicy {
			value := base
			value.OwnershipEpoch = 1
			value.ObserveOnly = true
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.validateForService("host-agent-a", 0); err == nil {
				t.Fatal("inconsistent observe_only/ownership_epoch was accepted")
			}
		})
	}
	observer := base
	observer.OwnershipEpoch, observer.ObserveOnly = 0, true
	if err := observer.validateForService("host-agent-a", 0); err != nil {
		t.Fatalf("valid observer policy rejected: %v", err)
	}
	active := base
	active.OwnershipEpoch, active.ObserveOnly = 1, false
	if err := active.validateForService("host-agent-a", 0); err != nil {
		t.Fatalf("valid active policy rejected: %v", err)
	}
}

func TestHostAgentPolicyObserverExecutorBindingIsAllOrNothing(t *testing.T) {
	base := HostAgentPolicy{
		ServiceID: "host-agent-a", TransportMode: HostTransportPullV2,
		ExecutionHostID: "host-a", OwnershipEpoch: 0,
		Revision: 3, SourcePolicyRevision: 2, ObserveOnly: true,
	}
	if err := base.validateForService("host-agent-a", 0); err != nil {
		t.Fatalf("valid unpinned observer rejected: %v", err)
	}

	ready := base
	ready.LocalExecutorPolicyRevision = 5
	ready.LocalExecutorPolicySHA256 = "sha256:" + strings.Repeat("b", 64)
	if err := ready.validateForService("host-agent-a", 0); err != nil {
		t.Fatalf("valid ready observer rejected: %v", err)
	}

	revisionOnly := base
	revisionOnly.LocalExecutorPolicyRevision = 5
	if err := revisionOnly.validateForService("host-agent-a", 0); err == nil {
		t.Fatal("observer executor revision without digest was accepted")
	}
	digestOnly := base
	digestOnly.LocalExecutorPolicySHA256 = "sha256:" + strings.Repeat("b", 64)
	if err := digestOnly.validateForService("host-agent-a", 0); err == nil {
		t.Fatal("observer executor digest without revision was accepted")
	}
}

func TestRegisterHostAgentDoesNotFollowRedirect(t *testing.T) {
	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		if r.Header.Get("Authorization") == "Bearer runtime-token" {
			t.Error("runtime token reached redirect destination")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"service_id":"host-agent-a","service_type":"update_agent","transport_mode":"pull_v2","execution_host_id":"host-a","ownership_epoch":1}`))
	}))
	defer redirected.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirected.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	client := PanelClient{BaseURL: redirector.URL, Token: "runtime-token", HTTP: redirector.Client()}
	if _, err := client.RegisterHostAgent(context.Background(), managedHostAgentBootstrap(redirector.URL), nil); err == nil {
		t.Fatal("redirected registration unexpectedly succeeded")
	}
	if redirectedCalls.Load() != 0 {
		t.Fatalf("registration followed %d redirects", redirectedCalls.Load())
	}
}

func TestNewHostPullAgentUsesDedicatedStateDirectory(t *testing.T) {
	bootstrap := managedHostAgentBootstrap("https://panel.example.com")
	agent, err := NewHostPullAgent(bootstrap, HostPullAgentOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if agent.StateDir != HostPullAgentStateDir {
		t.Fatalf("state dir = %q, want %q", agent.StateDir, HostPullAgentStateDir)
	}
	if _, ok := agent.ControlPlane.(*V2PanelClient); !ok {
		t.Fatalf("default control plane = %T, want strict v2 adapter", agent.ControlPlane)
	}
}

func TestObserveOnlyHostAgentFailsClosedWhenJournalCannotOpen(t *testing.T) {
	agent, err := NewHostPullAgent(managedHostAgentBootstrap("https://panel.example.com"), HostPullAgentOptions{
		StateDir: t.TempDir(),
		OpenJournal: func(string) (*Journal, error) {
			return nil, errors.New("unavailable")
		},
		Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "open host pull agent journal") {
		t.Fatalf("journal open error = %v", err)
	}
}

func TestHostAgentCapabilitiesAdvertiseSelfUpdateRecoveryProtocol(t *testing.T) {
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	agent := &HostPullAgent{AgentVersion: "v1.7.8"}
	agent.selfUpdateStatus.Store(&HostSelfUpdateRuntimeStatus{
		State:                   state,
		CurrentSlot:             HostSelfUpdateSlotA,
		ExecutorVersion:         "v1.7.8",
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
	})
	capabilities := agent.capabilities(
		HostAgentBinding{},
		nil,
		nil,
		false,
	)
	if got := capabilities["recovery_protocol_version"]; got != HostSelfUpdateRecoveryProtocolVersion {
		t.Fatalf(
			"recovery_protocol_version = %#v, want %d",
			got,
			HostSelfUpdateRecoveryProtocolVersion,
		)
	}
	if capabilities["self_update_ready"] != true ||
		capabilities["self_update_phase"] != HostSelfUpdatePhaseStable ||
		capabilities["self_update_active_agent_version"] != "v1.7.8" ||
		capabilities["self_update_active_executor_version"] != "v1.7.8" {
		t.Fatalf(
			"stable self-update runtime was not emitted: %#v",
			capabilities,
		)
	}
}

func TestHostAgentCapabilitiesDoNotTreatAppliedPortAsLocalObservation(t *testing.T) {
	agent := &HostPullAgent{}
	policy := &HostAgentPolicy{
		Revision: 1,
		Targets: []HostAgentPolicyTarget{{
			ServiceID:       "worker-a",
			ServiceType:     "worker",
			DeploymentMode:  ModeSystemd,
			DesiredEndpoint: &HostAgentEndpoint{Host: "127.0.0.1", Port: 18082, PublicURL: "http://127.0.0.1:18082"},
			AppliedEndpoint: &HostAgentEndpoint{Host: "127.0.0.1", Port: 18081, PublicURL: "http://127.0.0.1:18081"},
		}},
	}
	for name, testCase := range map[string]struct {
		observations []HostTargetObservation
		failed       bool
	}{
		"no observer":     {},
		"observer failed": {failed: true},
		"partial result":  {observations: []HostTargetObservation{{ServiceID: "different-target", Availability: TargetAvailabilityAvailable, ReportedPort: 19000}}},
	} {
		t.Run(name, func(t *testing.T) {
			capabilities := agent.capabilities(HostAgentBinding{}, policy, testCase.observations, testCase.failed)
			reportedPorts := capabilities["reported_ports"].(map[string]int)
			if _, exists := reportedPorts["worker-a"]; exists {
				t.Fatalf("applied endpoint was synthesized as locally reported: %#v", reportedPorts)
			}
			portDrift := capabilities["port_drift"].(map[string]bool)
			if _, exists := portDrift["worker-a"]; exists {
				t.Fatalf("unknown local port was reported as drift=false: %#v", portDrift)
			}
		})
	}
}

func TestHostAgentPortDriftNeverComparesLocalPortToAdvertisedEndpoint(t *testing.T) {
	agent := &HostPullAgent{}
	policy := &HostAgentPolicy{
		Revision: 1,
		Targets: []HostAgentPolicyTarget{{
			ServiceID:       "worker-a",
			ServiceType:     "worker",
			DeploymentMode:  ModeDocker,
			DesiredEndpoint: &HostAgentEndpoint{Host: "worker.example.com", Port: 443, SSLEnabled: true, PublicURL: "https://worker.example.com"},
			AppliedEndpoint: &HostAgentEndpoint{Host: "worker.example.com", Port: 443, SSLEnabled: true, PublicURL: "https://worker.example.com"},
		}},
	}
	observation := []HostTargetObservation{{
		ServiceID: "worker-a", Availability: TargetAvailabilityAvailable, ReportedPort: 18081,
	}}
	capabilities := agent.capabilities(HostAgentBinding{}, policy, observation, false)
	if drift := capabilities["port_drift"].(map[string]bool); len(drift) != 0 {
		t.Fatalf("advertised :443 was compared with local :18081: %#v", drift)
	}

	policy.Targets[0].LocalListenEndpoint = &HostAgentEndpoint{
		Host: "127.0.0.1", Port: 18082, PublicURL: "http://127.0.0.1:18082",
	}
	capabilities = agent.capabilities(HostAgentBinding{}, policy, observation, false)
	if drift := capabilities["port_drift"].(map[string]bool); drift["worker-a"] != true {
		t.Fatalf("explicit local listen :18082 was not compared with local :18081: %#v", drift)
	}
}

func TestObserveOnlyHostAgentBacksOffAfterPanelOutage(t *testing.T) {
	controlPlane := &failingHostPullControlPlane{}
	agent, err := NewHostPullAgent(managedHostAgentBootstrap("https://panel.example.com"), HostPullAgentOptions{
		StateDir:          t.TempDir(),
		ControlPlane:      controlPlane,
		PollInterval:      5 * time.Millisecond,
		HeartbeatInterval: 5 * time.Millisecond,
		Logf:              func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Millisecond)
	defer cancel()
	if err := agent.Run(ctx); err != context.DeadlineExceeded {
		t.Fatalf("Run error = %v", err)
	}
	if calls := controlPlane.registerCalls.Load(); calls < 2 || calls > 6 {
		t.Fatalf("register calls during outage = %d, want bounded exponential retry", calls)
	}
	if calls := controlPlane.heartbeatCalls.Load(); calls < 2 || calls > 6 {
		t.Fatalf("heartbeat calls during outage = %d, want bounded exponential retry", calls)
	}
}

func TestHostPullAgentRefreshesTargetReadinessBeforeActiveRecovery(t *testing.T) {
	agent, originalPanel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	observation := configureHostPullRecoveryProbe(&policy)
	interrupted := *originalPanel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	recovered := *originalPanel.job
	recovered.RecoveryRequired = true
	recovered.LeaseGeneration = interrupted.LeaseGeneration + 1
	recovered.LeaseToken = strings.Repeat("r", 48)
	recovered.ReportSequence = interrupted.ReportSequence + 1
	policy.RuntimeTokenRotation = &HostAgentRuntimeTokenRotation{}
	panel := &hostPullRecoveryLoopPanel{
		binding:                     binding,
		policy:                      policy,
		job:                         &recovered,
		requireHeartbeatBeforeClaim: true,
		requireEligibleHeartbeat:    true,
		terminalReported:            make(chan struct{}),
	}
	agent.ControlPlane = panel
	agent.PollInterval = time.Hour
	agent.HeartbeatInterval = time.Hour
	var observationCalls atomic.Int32
	agent.ObserveTargets = func(context.Context, HostAgentPolicy) ([]HostTargetObservation, error) {
		observationCalls.Add(1)
		return []HostTargetObservation{observation}, nil
	}
	var logMu sync.Mutex
	var logs []string
	agent.Logf = func(format string, args ...any) {
		logMu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		logMu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	select {
	case <-panel.terminalReported:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("interrupted update was not reconciled")
	}
	deadline := time.Now().Add(3 * time.Second)
	for agent.Journal.Active() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active := agent.Journal.Active(); active != nil {
		cancel()
		t.Fatalf("recovery left active cursor: %+v", active)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf(
			"executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if observationCalls.Load() != 2 {
		t.Fatalf("active recovery performed %d target observations, want 2", observationCalls.Load())
	}
	logMu.Lock()
	defer logMu.Unlock()
	for _, entry := range logs {
		if strings.Contains(entry, "runtime token rotation") {
			t.Fatalf("active recovery was delayed by runtime-token rotation: %q", entry)
		}
	}
	if activeIDs := panel.activeJobIDs(); len(activeIDs) != 1 || activeIDs[0] != interrupted.ID {
		t.Fatalf("recovery claim active_job_id values = %#v", activeIDs)
	}
	_, status, capabilities, events := panel.heartbeatSnapshot()
	if status != "online" || !hostPullHeartbeatReportsEligiblePolicy(capabilities, policy) {
		t.Fatalf("active recovery heartbeat capabilities = %#v", capabilities)
	}
	if len(events) < 4 || strings.Join(events[:4], ",") != "register,fetch,heartbeat,claim" {
		t.Fatalf("active recovery control-plane order = %q", strings.Join(events, ","))
	}
}

func TestHostPullRecoveryReadinessDoesNotEnableNewClaims(t *testing.T) {
	agent, panel, _, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	policy.ObserveOnly = true
	policy.RuntimeTokenRotation = &HostAgentRuntimeTokenRotation{}
	if !agent.recoveryExecutionReady(binding, &policy) {
		t.Fatal("active recovery was blocked by normal mutation readiness")
	}
	if agent.mutationReady(binding, &policy, nil, true) {
		t.Fatal("normal claim bypassed target and runtime-token readiness")
	}
	if err := agent.Journal.ClearActive(); err != nil {
		t.Fatal(err)
	}
	if agent.recoveryExecutionReady(binding, &policy) {
		t.Fatal("recovery readiness remained true without an active cursor")
	}
	if agent.mutationReady(binding, &policy, nil, true) {
		t.Fatal("new claim became ready after the recovery cursor cleared")
	}
}

func TestRecoveryOnlyHostPullAgentReturnsWithoutClaimWhenCursorIsAbsent(t *testing.T) {
	panel := &hostPullRecoveryLoopPanel{}
	agent, err := NewHostPullAgent(
		managedHostAgentBootstrap("https://panel.example.com"),
		HostPullAgentOptions{
			StateDir:     t.TempDir(),
			ControlPlane: panel,
			RecoveryOnly: true,
			Logf:         func(string, ...any) {},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := agent.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if activeIDs := panel.activeJobIDs(); len(activeIDs) != 0 {
		t.Fatalf("recovery-only agent claimed without a cursor: %#v", activeIDs)
	}
	if panel.registerCalls.Load() != 0 || panel.fetchCalls.Load() != 0 {
		t.Fatalf(
			"empty recovery contacted Panel: register=%d fetch=%d",
			panel.registerCalls.Load(), panel.fetchCalls.Load(),
		)
	}
}

func TestRecoveryOnlyHostPullAgentPreservesCursorOnUnprovenClear(t *testing.T) {
	agent, originalPanel, _, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *originalPanel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	panel := &hostPullRecoveryLoopPanel{
		binding:     binding,
		policy:      policy,
		clearActive: true,
	}
	agent.ControlPlane = recoveryOnlyHostPullControlPlane{
		HostPullControlPlane: agentControlPlane(panel),
		execution:            panel,
	}
	agent.RecoveryOnly = true
	agent.PollInterval = time.Millisecond
	agent.Logf = func(string, ...any) {}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := agent.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("recovery-only unproven clear error = %v", err)
	}
	if active := agent.Journal.Active(); active == nil || active.ID != interrupted.ID {
		t.Fatalf("unproven clear removed recovery cursor: %+v", active)
	}
	for _, activeID := range panel.activeJobIDs() {
		if activeID != interrupted.ID {
			t.Fatalf("recovery-only claim used active_job_id %q", activeID)
		}
	}
}

func TestRecoveryOnlyHostPullAgentRefreshesStaleHeartbeatBeforeClaim(t *testing.T) {
	agent, originalPanel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	observation := configureHostPullRecoveryProbe(&policy)
	interrupted := *originalPanel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePlan(plan); err != nil {
		t.Fatal(err)
	}
	recovered := *originalPanel.job
	recovered.RecoveryRequired = true
	recovered.LeaseGeneration = interrupted.LeaseGeneration + 1
	recovered.LeaseToken = strings.Repeat("r", 48)
	recovered.ReportSequence = interrupted.ReportSequence + 1
	panel := &hostPullRecoveryLoopPanel{
		binding:                     binding,
		policy:                      policy,
		job:                         &recovered,
		requireHeartbeatBeforeClaim: true,
		requireEligibleHeartbeat:    true,
		terminalReported:            make(chan struct{}),
	}
	agent.ControlPlane = recoveryOnlyHostPullControlPlane{
		HostPullControlPlane: agentControlPlane(panel),
		execution:            panel,
	}
	agent.RecoveryOnly = true
	agent.AgentVersion = "v1.9.11"
	agent.PollInterval = time.Millisecond
	agent.Logf = func(string, ...any) {}
	var observationCalls atomic.Int32
	agent.ObserveTargets = func(context.Context, HostAgentPolicy) ([]HostTargetObservation, error) {
		observationCalls.Add(1)
		return []HostTargetObservation{observation}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()
	select {
	case <-panel.terminalReported:
	case <-ctx.Done():
		cancel()
		t.Fatal("stale-heartbeat recovery did not reach a terminal report")
	}
	deadline := time.Now().Add(time.Second)
	for agent.Journal.Active() != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active := agent.Journal.Active(); active != nil {
		cancel()
		t.Fatalf("stale-heartbeat recovery left active cursor: %+v", active)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf(
			"executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if observationCalls.Load() != 1 {
		t.Fatalf("recovery-only mode performed %d target observations, want 1", observationCalls.Load())
	}
	if calls := panel.heartbeatCalls.Load(); calls != 1 {
		t.Fatalf("recovery heartbeat calls = %d, want 1", calls)
	}
	identity, status, capabilities, events := panel.heartbeatSnapshot()
	if identity.NodeID != agent.Bootstrap.NodeID ||
		identity.RuntimeToken != agent.Bootstrap.RuntimeToken {
		t.Fatalf("recovery heartbeat identity = %+v", identity)
	}
	if status != "online" {
		t.Fatalf("recovery heartbeat status = %q, want online", status)
	}
	if capabilities["agent_version"] != "v1.9.11" ||
		capabilities["agent_protocol_version"] != HostAgentProtocolVersion ||
		capabilities["recovery_pending"] != true ||
		!hostPullHeartbeatReportsEligiblePolicy(capabilities, policy) ||
		capabilities["execution_host_id"] != binding.ExecutionHostID ||
		capabilities["ownership_epoch"] != binding.OwnershipEpoch {
		t.Fatalf("recovery heartbeat capabilities = %#v", capabilities)
	}
	if len(events) < 5 || strings.Join(events[:4], ",") != "register,fetch,heartbeat,claim" {
		t.Fatalf("recovery control-plane order = %q", strings.Join(events, ","))
	}
	for _, event := range events[4:] {
		if event != "report" {
			t.Fatalf("recovery control-plane order = %q", strings.Join(events, ","))
		}
	}
}

func TestRecoveryOnlyHostPullAgentDoesNotClaimWhenHeartbeatFails(t *testing.T) {
	agent, originalPanel, _, binding, policy := newHostPullExecutionHarness(t, true)
	observation := configureHostPullRecoveryProbe(&policy)
	interrupted := *originalPanel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	panel := &hostPullRecoveryLoopPanel{
		binding:      binding,
		policy:       policy,
		job:          originalPanel.job,
		heartbeatErr: errors.New("heartbeat unavailable"),
	}
	agent.ControlPlane = recoveryOnlyHostPullControlPlane{
		HostPullControlPlane: agentControlPlane(panel),
		execution:            panel,
	}
	agent.RecoveryOnly = true
	agent.PollInterval = time.Millisecond
	agent.Logf = func(string, ...any) {}
	var observationCalls atomic.Int32
	agent.ObserveTargets = func(context.Context, HostAgentPolicy) ([]HostTargetObservation, error) {
		observationCalls.Add(1)
		return []HostTargetObservation{observation}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := agent.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("recovery-only heartbeat failure error = %v", err)
	}
	if calls := panel.heartbeatCalls.Load(); calls == 0 {
		t.Fatal("recovery-only mode did not attempt a heartbeat")
	}
	if activeIDs := panel.activeJobIDs(); len(activeIDs) != 0 {
		t.Fatalf("recovery-only mode claimed after failed heartbeat: %#v", activeIDs)
	}
	if calls := panel.fetchCalls.Load(); calls == 0 {
		t.Fatal("recovery-only mode did not fetch policy before heartbeat")
	}
	if observationCalls.Load() == 0 {
		t.Fatal("recovery-only mode did not probe targets before heartbeat")
	}
	if active := agent.Journal.Active(); active == nil || active.ID != interrupted.ID {
		t.Fatalf("failed heartbeat changed recovery cursor: %+v", active)
	}
}

func TestHostAgentRetryCadenceIsDeterministicallyJitteredPerIdentity(t *testing.T) {
	base := 30 * time.Second
	a := hostAgentJitteredInterval(base, "host-agent-a", "heartbeat")
	b := hostAgentJitteredInterval(base, "host-agent-b", "heartbeat")
	if a == b {
		t.Fatalf("different host identities received the same cadence: %s", a)
	}
	for name, interval := range map[string]time.Duration{"a": a, "b": b} {
		if interval < 27*time.Second || interval > 33*time.Second {
			t.Fatalf("%s jitter = %s, outside 10%% bound", name, interval)
		}
	}
	if again := hostAgentJitteredInterval(base, "host-agent-a", "heartbeat"); again != a {
		t.Fatalf("jitter is not stable across restarts: first=%s second=%s", a, again)
	}
}

type failingHostPullControlPlane struct {
	registerCalls  atomic.Int32
	heartbeatCalls atomic.Int32
}

type hostPullRecoveryLoopPanel struct {
	binding HostAgentBinding
	policy  HostAgentPolicy
	job     *UpdateJob

	registerCalls               atomic.Int32
	heartbeatCalls              atomic.Int32
	fetchCalls                  atomic.Int32
	mu                          sync.Mutex
	events                      []string
	heartbeatIdentity           Config
	heartbeatStatus             string
	heartbeatCapabilities       map[string]any
	heartbeatErr                error
	heartbeatFresh              bool
	heartbeatEligible           bool
	requireHeartbeatBeforeClaim bool
	requireEligibleHeartbeat    bool
	claimActive                 []string
	reports                     []JobReport
	clearActive                 bool
	terminalOnce                sync.Once
	terminalReported            chan struct{}
}

func (p *hostPullRecoveryLoopPanel) RegisterHostAgent(context.Context, Config, map[string]any) (HostAgentBinding, error) {
	p.registerCalls.Add(1)
	p.mu.Lock()
	p.events = append(p.events, "register")
	p.heartbeatFresh = false
	p.heartbeatEligible = false
	p.mu.Unlock()
	return p.binding, nil
}

func (p *hostPullRecoveryLoopPanel) HeartbeatHostAgent(_ context.Context, identity Config, status string, capabilities map[string]any) error {
	p.heartbeatCalls.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, "heartbeat")
	p.heartbeatIdentity = identity
	p.heartbeatStatus = status
	p.heartbeatCapabilities = make(map[string]any, len(capabilities))
	for key, value := range capabilities {
		p.heartbeatCapabilities[key] = value
	}
	if p.heartbeatErr != nil {
		return p.heartbeatErr
	}
	p.heartbeatFresh = true
	p.heartbeatEligible = hostPullHeartbeatReportsEligiblePolicy(capabilities, p.policy)
	return nil
}

func (p *hostPullRecoveryLoopPanel) FetchHostAgentPolicy(context.Context, string, int64) (*HostAgentPolicy, bool, error) {
	p.fetchCalls.Add(1)
	p.mu.Lock()
	p.events = append(p.events, "fetch")
	p.mu.Unlock()
	copy := p.policy
	copy.Targets = append([]HostAgentPolicyTarget(nil), p.policy.Targets...)
	return &copy, true, nil
}

func (p *hostPullRecoveryLoopPanel) ClaimHost(_ context.Context, _, _, activeJobID string) (*UpdateJob, bool, error) {
	p.mu.Lock()
	p.events = append(p.events, "claim")
	p.claimActive = append(p.claimActive, activeJobID)
	if p.requireHeartbeatBeforeClaim && !p.heartbeatFresh {
		p.mu.Unlock()
		return nil, false, errors.New("updater_offline")
	}
	if p.requireEligibleHeartbeat && !p.heartbeatEligible {
		p.mu.Unlock()
		return nil, false, errors.New("system_update_active_target_unavailable")
	}
	clearActive := p.clearActive
	var job *UpdateJob
	if p.job != nil {
		copy := *p.job
		job = &copy
	}
	p.mu.Unlock()
	return job, clearActive, nil
}

func (p *hostPullRecoveryLoopPanel) Report(_ context.Context, _ string, report JobReport) error {
	p.mu.Lock()
	p.events = append(p.events, "report")
	p.reports = append(p.reports, report)
	p.mu.Unlock()
	if isTerminalUpdateStatus(report.Status) && p.terminalReported != nil {
		p.terminalOnce.Do(func() { close(p.terminalReported) })
	}
	return nil
}

func (*hostPullRecoveryLoopPanel) IssueMutationGrant(context.Context, string, MutationGrantRequest) (MutationGrant, error) {
	return MutationGrant{
		Token:     "ast_mutation_" + strings.Repeat("a", 43),
		ExpiresAt: "2099-01-01T00:00:00Z",
	}, nil
}

func (p *hostPullRecoveryLoopPanel) activeJobIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.claimActive...)
}

func (p *hostPullRecoveryLoopPanel) heartbeatSnapshot() (Config, string, map[string]any, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	capabilities := make(map[string]any, len(p.heartbeatCapabilities))
	for key, value := range p.heartbeatCapabilities {
		capabilities[key] = value
	}
	return p.heartbeatIdentity, p.heartbeatStatus, capabilities, append([]string(nil), p.events...)
}

func configureHostPullRecoveryProbe(policy *HostAgentPolicy) HostTargetObservation {
	configSHA256 := "sha256:" + strings.Repeat("d", 64)
	target := &policy.Targets[0]
	target.AppliedConfigSHA256 = configSHA256
	target.LocalListenEndpoint = &HostAgentEndpoint{
		Host: "127.0.0.1", Port: 8084, PublicURL: "http://127.0.0.1:8084",
	}
	return HostTargetObservation{
		ServiceID:              target.ServiceID,
		Availability:           TargetAvailabilityAvailable,
		AvailabilityCode:       "executor_verified",
		ReportedPort:           target.LocalListenEndpoint.Port,
		ReportedServiceType:    target.ServiceType,
		ReportedDeploymentMode: target.DeploymentMode,
		PolicyRevision:         policy.LocalExecutorPolicyRevision,
		PolicySHA256:           policy.LocalExecutorPolicySHA256,
		ConfigRevision:         target.appliedConfigRevision(),
		ConfigSHA256:           configSHA256,
	}
}

func hostPullHeartbeatReportsEligiblePolicy(capabilities map[string]any, policy HostAgentPolicy) bool {
	if len(policy.Targets) != 1 ||
		capabilities["host_agent"] != true ||
		capabilities["observe_only"] != false ||
		capabilities["update_executor"] != true ||
		capabilities["mutation_enabled"] != true ||
		capabilities["policy_revision"] != policy.Revision ||
		capabilities["source_policy_revision"] != policy.SourcePolicyRevision ||
		capabilities["local_executor_policy_revision"] != policy.LocalExecutorPolicyRevision ||
		capabilities["policy_status"] != PolicyStatusApplied {
		return false
	}
	target := policy.Targets[0]
	availability, ok := capabilities["target_availability"].(map[string]string)
	if !ok || availability[target.ServiceID] != TargetAvailabilityAvailable {
		return false
	}
	availabilityCodes, ok := capabilities["target_availability_codes"].(map[string]string)
	if !ok || availabilityCodes[target.ServiceID] != "executor_verified" {
		return false
	}
	serviceTypes, ok := capabilities["reported_service_types"].(map[string]string)
	if !ok || serviceTypes[target.ServiceID] != target.ServiceType {
		return false
	}
	deploymentModes, ok := capabilities["reported_deployment_modes"].(map[string]string)
	if !ok || deploymentModes[target.ServiceID] != target.DeploymentMode {
		return false
	}
	policyRevisions, ok := capabilities["reported_executor_policy_revisions"].(map[string]int64)
	if !ok || policyRevisions[target.ServiceID] != policy.LocalExecutorPolicyRevision {
		return false
	}
	policyDigests, ok := capabilities["reported_executor_policy_sha256"].(map[string]string)
	if !ok || policyDigests[target.ServiceID] != policy.LocalExecutorPolicySHA256 {
		return false
	}
	configRevisions, ok := capabilities["reported_config_revisions"].(map[string]int64)
	if !ok || configRevisions[target.ServiceID] != target.appliedConfigRevision() {
		return false
	}
	configDigests, ok := capabilities["reported_config_sha256"].(map[string]string)
	if !ok || configDigests[target.ServiceID] != target.AppliedConfigSHA256 {
		return false
	}
	reportedPorts, ok := capabilities["reported_ports"].(map[string]int)
	if !ok || target.LocalListenEndpoint == nil ||
		reportedPorts[target.ServiceID] != target.LocalListenEndpoint.Port {
		return false
	}
	portDrift, ok := capabilities["port_drift"].(map[string]bool)
	return ok && !portDrift[target.ServiceID]
}

func agentControlPlane(panel *hostPullRecoveryLoopPanel) HostPullControlPlane {
	return panel
}

func (f *failingHostPullControlPlane) RegisterHostAgent(context.Context, Config, map[string]any) (HostAgentBinding, error) {
	f.registerCalls.Add(1)
	return HostAgentBinding{}, fmt.Errorf("panel unavailable")
}

func (f *failingHostPullControlPlane) HeartbeatHostAgent(context.Context, Config, string, map[string]any) error {
	f.heartbeatCalls.Add(1)
	return fmt.Errorf("panel unavailable")
}

func (*failingHostPullControlPlane) FetchHostAgentPolicy(context.Context, string, int64) (*HostAgentPolicy, bool, error) {
	return nil, false, fmt.Errorf("panel unavailable")
}

func managedHostAgentBootstrap(panelURL string) Config {
	return Config{
		PanelURL: panelURL, NodeID: "host-agent-a", RuntimeToken: "runtime-token", ServiceName: "Host Agent A",
		configFields: map[string]bool{
			"panel_url": true, "node_id": true, "runtime_token": true, "service_name": true,
		},
	}
}
