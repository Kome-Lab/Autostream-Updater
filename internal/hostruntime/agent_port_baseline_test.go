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

type agentPortProbeStub struct{ probe LocalExecutorProbe }

func (s agentPortProbeStub) Probe(context.Context, string) (LocalExecutorProbe, error) {
	return s.probe, nil
}

func TestSTPortAgentBaselineRequiresActualVersionedRootObservation(t *testing.T) {
	_, _, policy, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalOnly, false)
	probe := LocalExecutorProbe{PortContractVersion: 2, PolicyTransitionVersion: 1, SourcePolicyRevision: plan.Before.SourcePolicyRevision,
		ProjectionRevision: plan.Before.ProjectionRevision, PolicyRevision: plan.Before.ExecutorPolicyRevision, PolicySHA256: plan.Before.ExecutorPolicySHA256,
		AgentUID: 1201, AgentGID: 1202, EndpointRevision: plan.Before.AppliedEndpointRevision, ObservedAt: time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC),
		ServiceID: "worker-01", ServiceType: "worker", DeploymentMode: ModeSystemd, ConfigRevision: plan.Before.ConfigRevision, ConfigSHA256: plan.Before.ConfigSHA256,
		CurrentVersion: "v1.2.3", MainPID: 51, ListenerPID: 51, ControlGroup: "/system.slice/worker.service", ListenerAddress: "127.0.0.1:18081"}
	observe := func(probe LocalExecutorProbe) *contracts.UpdaterPortPolicyBaseline {
		observations, err := NewLocalExecutorTargetObserver(agentPortProbeStub{probe})(context.Background(), policy)
		if err != nil {
			t.Fatal(err)
		}
		return portPolicyBaseline(policy, observations)
	}
	baseline := observe(probe)
	if baseline == nil || baseline.AgentUID != 1201 || baseline.AgentGID != 1202 || baseline.Targets[0].EndpointRevision != plan.Before.AppliedEndpointRevision ||
		!baseline.ObservedAt.Equal(probe.ObservedAt) {
		t.Fatal("verified root baseline was not preserved")
	}
	observations, err := NewLocalExecutorTargetObserver(agentPortProbeStub{probe})(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	agent := &HostPullAgent{Bootstrap: Config{NodeID: policy.ServiceID}}
	capabilities := agent.capabilities(HostAgentBinding{ExecutionHostID: policy.ExecutionHostID, OwnershipEpoch: policy.OwnershipEpoch, TransportMode: HostTransportPullV2}, &policy, observations, false)
	heartbeats := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Capabilities map[string]json.RawMessage `json:"capabilities"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || string(request.Capabilities["port_contract_version"]) != "2" ||
			string(request.Capabilities["policy_transition_version"]) != "1" || contracts.ValidateUpdaterPortPolicyBaselineJSON(request.Capabilities["port_policy_baseline"]) != nil {
			t.Error("verified baseline was lost on heartbeat wire")
		}
		heartbeats++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	panel := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
	if err := panel.HeartbeatHostAgent(context.Background(), Config{NodeID: policy.ServiceID}, "online", capabilities); err != nil || heartbeats != 1 {
		t.Fatal("versioned baseline heartbeat did not complete")
	}
	for _, test := range []struct {
		name   string
		change func(*LocalExecutorProbe)
	}{
		{"old pair", func(p *LocalExecutorProbe) { p.PortContractVersion = 0; p.PolicyTransitionVersion = 0 }},
		{"different projection", func(p *LocalExecutorProbe) { p.ProjectionRevision++ }},
		{"different applied endpoint", func(p *LocalExecutorProbe) { p.EndpointRevision++ }},
		{"missing peer", func(p *LocalExecutorProbe) { p.AgentUID = 0 }},
		{"different root", func(p *LocalExecutorProbe) { p.PolicySHA256 = "sha256:" + strings.Repeat("9", 64) }},
		{"different listener", func(p *LocalExecutorProbe) { p.ListenerAddress = "127.0.0.1:18084" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := probe
			test.change(&changed)
			if observe(changed) != nil {
				t.Fatal("unverified baseline was advertised")
			}
		})
	}
}

func TestSTPortAgentProbeCapabilityRequiresExactRootDiskAndMemory(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion, policy.ProtocolVersion = LocalExecutorMutationPolicySchemaVersion, LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.test"}
	policy.SourcePolicyRevision, policy.ProjectionRevision = 5, 11
	policy.Targets[0].EndpointRevision = 3
	policy.Targets[0].ConfigSHA256 = "sha256:" + strings.Repeat("a", 64)
	target := policy.Targets[0]
	server := newLocalExecutorProbeServer(t, target, "v1.2.3", target.ConfigRevision)
	defer server.Close()
	target.LocalListen = endpointFromServer(t, server)
	policy.Targets[0] = target
	canonical, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"canonical", "pretty disk", "different memory", "no manager"} {
		t.Run(name, func(t *testing.T) {
			manager := &stPortTestPolicyStore{disk: canonical, memory: canonical}
			ctx := context.Background()
			switch name {
			case "pretty disk":
				manager.disk = pretty
			case "different memory":
				manager.memory = pretty
			}
			if name != "no manager" {
				ctx = context.WithValue(ctx, portPolicyContextKey{}, manager)
			}
			verifier := &fakeLocalTargetVerifier{observations: []LocalProcessObservation{
				validLocalProcessObservation(target, "v1.2.3"), validLocalProcessObservation(target, "v1.2.3"),
			}}
			response := handleLocalExecutorRequest(ctx, policy,
				LocalExecutorRequest{Version: LocalExecutorProtocolVersion, Operation: "probe", ServiceID: target.ServiceID}, verifier, server.Client())
			if response.Error != nil || response.Probe == nil || verifier.calls != 2 {
				t.Fatal("legacy observation did not complete")
			}
			versioned := response.Probe.PortContractVersion == 2 && response.Probe.PolicyTransitionVersion == 1
			if versioned != (name == "canonical") || manager.writes != 0 || manager.reloads != 0 {
				t.Fatal("unverified root state advertised transition capability or mutated policy")
			}
		})
	}
}

func TestSTPortAgentDockerBaselineRetainsInstalledProfileMetadata(t *testing.T) {
	_, _, policy, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalOnly, false)
	policy.Targets[0].DeploymentMode = ModeDocker
	policy.Targets[0].LocalHealthEndpoint = &HostAgentEndpoint{Host: "127.0.0.1", Port: 18081, PublicURL: "http://127.0.0.1:18081"}
	probe := LocalExecutorProbe{PortContractVersion: 2, PolicyTransitionVersion: 1, SourcePolicyRevision: plan.Before.SourcePolicyRevision, ProjectionRevision: plan.Before.ProjectionRevision,
		PolicyRevision: plan.Before.ExecutorPolicyRevision, PolicySHA256: plan.Before.ExecutorPolicySHA256, AgentUID: 1201, AgentGID: 1202, EndpointRevision: 3,
		ObservedAt: time.Date(2026, 9, 6, 17, 0, 0, 0, time.UTC), ServiceID: "worker-01", ServiceType: "worker", DeploymentMode: ModeDocker,
		ConfigRevision: plan.Before.ConfigRevision, ConfigSHA256: plan.Before.ConfigSHA256, CurrentVersion: "v1.3.0", MainPID: 51, ListenerPID: 51, ControlGroup: "/system.slice/docker.service", ListenerAddress: "127.0.0.1:18081",
		Docker: &LocalExecutorDockerPortProbe{CapabilityVersion: dockerPortCapabilityVersion, PublishedPort: 18081, ContainerPort: 18081, HealthPort: 18081,
			ComposePolicySHA256: strings.Repeat("a", 64), ComposeConfigSHA256: strings.Repeat("b", 64), ComposeRevision: 23, VersionEnvSHA256: "sha256:" + strings.Repeat("c", 64),
			ContainerID: strings.Repeat("d", 64), ImageID: "sha256:" + strings.Repeat("e", 64), RepositoryDigest: "sha256:" + strings.Repeat("f", 64)},
		DockerRoot: &contracts.UpdaterPortDockerRootBaseline{ComposeConfigSHA256: strings.Repeat("1", 64), CurrentVersion: "v1.2.3"},
	}
	observations, err := NewLocalExecutorTargetObserver(agentPortProbeStub{probe})(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	baseline := portPolicyBaseline(policy, observations)
	if baseline == nil || baseline.Targets[0].DockerRoot == nil || baseline.Targets[0].DockerRoot.ComposeConfigSHA256 != probe.DockerRoot.ComposeConfigSHA256 ||
		baseline.Targets[0].DockerRoot.CurrentVersion != "v1.2.3" || baseline.Targets[0].Docker.ComposePolicySHA256 != "sha256:"+strings.Repeat("a", 64) ||
		observations[0].Docker == nil || observations[0].Docker.ComposeConfigSHA256 != probe.Docker.ComposeConfigSHA256 {
		t.Fatal("dynamic Docker observation replaced installed root profile metadata")
	}
	observations[0].DockerRoot = nil
	if portPolicyBaseline(policy, observations) != nil {
		t.Fatal("incomplete installed Docker profile was accepted")
	}
}

func TestSTPortAgentAdvertisedEndpointPreservesOriginalAndChangesOnlyPort(t *testing.T) {
	before := HostAgentEndpoint{Host: "worker.example.test", Port: 443, SSLEnabled: true, PublicURL: "https://worker.example.test:443/runtime?mode=one"}
	unchanged, err := portAdvertisedEndpoint(before, 443)
	if err != nil || unchanged != before {
		t.Fatal("unchanged endpoint normalization changed original bytes")
	}
	target, err := portAdvertisedEndpoint(before, 8443)
	if err != nil || target.PublicURL != "https://worker.example.test:8443/runtime?mode=one" || target.Host != before.Host || target.SSLEnabled != before.SSLEnabled {
		t.Fatal("advertised transition changed another field")
	}
	back, err := portAdvertisedEndpoint(target, 443)
	if err != nil || back.PublicURL != before.PublicURL {
		t.Fatal("explicit default port differs from CP transition")
	}
}
