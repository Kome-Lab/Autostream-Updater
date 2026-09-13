package hostruntime

import (
	"context"
	"testing"
	"time"
)

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
