package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
