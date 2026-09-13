package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostPullPortReconfigureSkipsReleaseAndStagesNoSoftware(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	agent.Downloader = hostPullFailingDownloader{}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 0 {
		t.Fatalf("software executor calls stage=%d apply=%d reconcile=%d", executor.stageCalls, executor.applyCalls, executor.reconcileCalls)
	}
	if executor.portApplyCalls != 1 || executor.portReconCalls != 0 {
		t.Fatalf("port executor calls apply=%d reconcile=%d", executor.portApplyCalls, executor.portReconCalls)
	}
	if len(panel.grants) != 1 {
		t.Fatalf("grants=%+v", panel.grants)
	}
	grant := panel.grants[0]
	intentHash := panel.job.PortReconfigure.PortPlanSHA256
	if grant.JobOperation != updateJobOperationPortReconfigure ||
		grant.Operation != "port_reconfigure" ||
		grant.ServiceType != panel.job.EffectiveType() ||
		grant.PortReconfigure == nil ||
		grant.PlanSHA256 == intentHash ||
		grant.PortReconfigure.PortPlanSHA256 != grant.PlanSHA256 ||
		grant.PlanSHA256 != executor.portApplyPlans[0].PortPlanSHA256 {
		t.Fatalf("grant=%+v intent_hash=%q plan=%+v", grant, intentHash, executor.portApplyPlans)
	}
	if len(executor.portFences) != 1 ||
		executor.portFences[0].SourcePolicyRevision != policy.SourcePolicyRevision ||
		executor.portFences[0].OwnershipPolicyRevision != policy.Revision ||
		executor.portFences[0].ExecutorPolicyRevision != policy.LocalExecutorPolicyRevision {
		t.Fatalf("port fences=%+v", executor.portFences)
	}
	for index, report := range panel.reports {
		terminal := index == len(panel.reports)-1
		if terminal {
			if report.Status != "succeeded" ||
				report.PortReconfigure == nil ||
				report.PortReconfigure.Result != systemdPortResultApplied {
				t.Fatalf("terminal report=%+v", report)
			}
		} else if report.PortReconfigure != nil {
			t.Fatalf("non-terminal report leaked a result: %+v", report)
		}
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("terminal port report left active job: %+v", active)
	}
	payload, err := os.ReadFile(filepath.Join(agent.StateDir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "ast_mutation_") ||
		strings.Contains(string(payload), strings.Repeat("l", 48)) {
		t.Fatalf("journal persisted a bearer secret: %s", payload)
	}
}

func TestHostPullPortReconfigureUncertainResultReconcilesWithoutReapply(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	executor.portApplyErr = errors.New("UDS result lost")

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.portApplyCalls != 1 || executor.portReconCalls != 1 {
		t.Fatalf("port calls apply=%d reconcile=%d", executor.portApplyCalls, executor.portReconCalls)
	}
	if len(panel.grants) != 2 ||
		panel.grants[0].Operation != "port_reconfigure" ||
		panel.grants[1].Operation != "port_reconfigure_reconcile" {
		t.Fatalf("grants=%+v", panel.grants)
	}
	if panel.grants[0].PlanSHA256 != panel.grants[1].PlanSHA256 ||
		panel.grants[0].SessionID != panel.grants[1].SessionID {
		t.Fatalf("apply and reconcile grants changed runtime intent: %+v", panel.grants)
	}
	foundReconciling := false
	for _, report := range panel.reports {
		if report.Status == "reconciling" {
			foundReconciling = true
		}
	}
	if !foundReconciling {
		t.Fatalf("reports=%+v", panel.reports)
	}
}

func TestHostPullPortGrantResponseFailureReconcilesUnstartedMutationAsUnchanged(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	panel.grantErrors = []error{errors.New("grant response lost")}
	plan, err := agent.preparePortExecutionPlan(policy, *panel.job)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := unchangedPortExecutionResult(plan)
	executor.portReconResult = &unchanged

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.portApplyCalls != 0 || executor.portReconCalls != 1 {
		t.Fatalf(
			"grant failure reached apply or skipped reconcile: apply=%d reconcile=%d",
			executor.portApplyCalls,
			executor.portReconCalls,
		)
	}
	if len(panel.grants) != 2 ||
		panel.grants[0].Operation != "port_reconfigure" ||
		panel.grants[1].Operation != "port_reconfigure_reconcile" ||
		panel.grants[0].PlanSHA256 != panel.grants[1].PlanSHA256 ||
		panel.grants[0].SessionID != panel.grants[1].SessionID {
		t.Fatalf("grants=%+v", panel.grants)
	}
	terminal := panel.reports[len(panel.reports)-1]
	if terminal.Status != "succeeded" ||
		terminal.PortReconfigure == nil ||
		terminal.PortReconfigure.Result != systemdPortResultUnchanged {
		t.Fatalf("terminal report=%+v", terminal)
	}
}

func TestHostPullPortRecoveryRebindsLeaseAndPreservesSessionAndIntent(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	original, err := agent.preparePortExecutionPlan(policy, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePortPlan(original); err != nil {
		t.Fatal(err)
	}
	panel.job.LeaseGeneration++
	agent.Downloader = hostPullFailingDownloader{}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.portApplyCalls != 0 || executor.portReconCalls != 1 {
		t.Fatalf("port calls apply=%d reconcile=%d", executor.portApplyCalls, executor.portReconCalls)
	}
	rebound := executor.portReconPlans[0]
	if rebound.LeaseGeneration != panel.job.LeaseGeneration ||
		rebound.SessionID != original.SessionID ||
		rebound.PortPlanSHA256 == original.PortPlanSHA256 ||
		panel.job.PortReconfigure.PortPlanSHA256 != interrupted.PortReconfigure.PortPlanSHA256 {
		t.Fatalf("original=%+v rebound=%+v recovered_job=%+v", original, rebound, panel.job)
	}
	if len(panel.grants) != 1 ||
		panel.grants[0].Operation != "port_reconfigure_reconcile" ||
		panel.grants[0].PlanSHA256 != rebound.PortPlanSHA256 {
		t.Fatalf("grants=%+v", panel.grants)
	}
}

func TestHostPullPortRecoveryReconstructsMissingPreMutationPlanAndReconciles(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, true)
	interrupted := *panel.job
	interrupted.RecoveryRequired = false
	if err := agent.Journal.SetActive(&interrupted); err != nil {
		t.Fatal(err)
	}
	reconstructed, err := agent.preparePortExecutionPlan(policy, *panel.job)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := unchangedPortExecutionResult(reconstructed)
	executor.portReconResult = &unchanged

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.portApplyCalls != 0 || executor.portReconCalls != 1 ||
		len(panel.grants) != 1 ||
		panel.grants[0].Operation != "port_reconfigure_reconcile" {
		t.Fatalf(
			"recovery calls apply=%d reconcile=%d grants=%+v",
			executor.portApplyCalls,
			executor.portReconCalls,
			panel.grants,
		)
	}
	terminal := panel.reports[len(panel.reports)-1]
	if terminal.Status != "succeeded" ||
		terminal.PortReconfigure == nil ||
		terminal.PortReconfigure.Result != systemdPortResultUnchanged {
		t.Fatalf("terminal=%+v", terminal)
	}
}

func TestHostPullPortPlanGenerationFailureNeverSendsInvalidTerminalResult(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullPortExecutionHarness(t, false)
	agent.NewSessionID = func() (string, error) {
		return "", errors.New("entropy unavailable")
	}
	if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
		t.Fatal("plan generation failure was hidden")
	}
	for _, report := range panel.reports {
		if isTerminalUpdateStatus(report.Status) {
			t.Fatalf("unverified terminal report was emitted: %+v", report)
		}
	}
	if agent.Journal.Active() == nil || agent.Journal.ActivePortPlan() != nil ||
		executor.portApplyCalls != 0 || executor.portReconCalls != 0 {
		t.Fatalf(
			"failed plan state active=%+v plan=%+v apply=%d reconcile=%d",
			agent.Journal.Active(),
			agent.Journal.ActivePortPlan(),
			executor.portApplyCalls,
			executor.portReconCalls,
		)
	}

	agent.NewSessionID = func() (string, error) {
		return "recovered-session-0123456789", nil
	}
	panel.job.RecoveryRequired = true
	panel.job.LeaseGeneration++
	reconstructed, err := agent.preparePortExecutionPlan(policy, *panel.job)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := unchangedPortExecutionResult(reconstructed)
	executor.portReconResult = &unchanged
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("recovery executeOnce: %v", err)
	}
	terminal := panel.reports[len(panel.reports)-1]
	if terminal.PortReconfigure == nil ||
		terminal.PortReconfigure.Result != systemdPortResultUnchanged {
		t.Fatalf("recovery terminal=%+v", terminal)
	}
}

func TestHostPullPortClaimRejectsUnionAndPolicyDrift(t *testing.T) {
	_, panel, _, binding, policy := newHostPullPortExecutionHarness(t, false)
	for name, mutate := range map[string]func(*UpdateJob){
		"software with port plan": func(job *UpdateJob) {
			job.Operation = updateJobOperationSoftwareUpdate
		},
		"port without nested plan": func(job *UpdateJob) {
			job.PortReconfigure = nil
		},
		"intent hash missing": func(job *UpdateJob) {
			job.PortReconfigure.PortPlanSHA256 = ""
		},
		"source policy stale": func(job *UpdateJob) {
			job.PortReconfigure.ExpectedSourcePolicyRevision--
		},
		"executor digest stale": func(job *UpdateJob) {
			job.PortReconfigure.ExpectedExecutorPolicySHA256 = "sha256:" + strings.Repeat("f", 64)
		},
		"old port mismatch": func(job *UpdateJob) {
			job.PortReconfigure.OldPort++
		},
		"new port mismatch": func(job *UpdateJob) {
			job.PortReconfigure.NewPort++
		},
		"software version mixed in": func(job *UpdateJob) {
			job.TargetVersion = "v1.1.0"
		},
	} {
		t.Run(name, func(t *testing.T) {
			job := *panel.job
			nested := *panel.job.PortReconfigure
			job.PortReconfigure = &nested
			mutate(&job)
			if err := validateHostPullClaim(job, panel.job.AgentServiceID, binding, policy); err == nil {
				t.Fatalf("invalid port claim was accepted: %+v", job)
			}
		})
	}
}

func TestHostPullPortJournalRejectsTamperedRuntimePlan(t *testing.T) {
	agent, panel, _, _, policy := newHostPullPortExecutionHarness(t, false)
	job := *panel.job
	if err := agent.Journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.preparePortExecutionPlan(policy, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePortPlan(plan); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(agent.StateDir, "journal.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var data journalData
	if err := json.Unmarshal(payload, &data); err != nil {
		t.Fatal(err)
	}
	data.ActivePortPlan.NewPort++
	tampered, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(agent.StateDir); err == nil ||
		!strings.Contains(err.Error(), "active plan binding") {
		t.Fatalf("tampered port journal error=%v", err)
	}
}
