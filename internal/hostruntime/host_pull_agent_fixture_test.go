package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

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

func (p *hostPullRecoveryLoopPanel) ClaimHost(_ context.Context, request HostPullClaimRequest) (*UpdateJob, bool, error) {
	p.mu.Lock()
	p.events = append(p.events, "claim")
	p.claimActive = append(p.claimActive, request.ActiveJobID)
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
