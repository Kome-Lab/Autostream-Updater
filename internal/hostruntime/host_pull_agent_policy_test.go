package hostruntime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

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
