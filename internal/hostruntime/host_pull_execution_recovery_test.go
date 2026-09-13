package hostruntime

import (
	"context"
	"errors"
	"testing"
)

func TestHostPullRecoveryOnlyReconcilesDurableExecutorState(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
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
	panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
	agent.Downloader = hostPullFailingDownloader{}
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf("executor calls stage=%d apply=%d reconcile=%d", executor.stageCalls, executor.applyCalls, executor.reconcileCalls)
	}
	if len(executor.reconcileFences) != 1 || executor.reconcileFences[0].SourcePolicyRevision != policy.SourcePolicyRevision {
		t.Fatalf("recovery reconcile fences=%+v policy source revision=%d", executor.reconcileFences, policy.SourcePolicyRevision)
	}
	if len(panel.grants) != 1 || panel.grants[0].Operation != "reconcile" {
		t.Fatalf("grants=%+v", panel.grants)
	}
	if len(executor.reconcilePlans) != 1 ||
		executor.reconcilePlans[0].LeaseGeneration != panel.job.LeaseGeneration ||
		panel.grants[0].LeaseGeneration != panel.job.LeaseGeneration {
		t.Fatalf("plan=%+v grant=%+v", executor.reconcilePlans, panel.grants)
	}
}

func TestHostPullRecoveryWithoutExecutorStageTerminates(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
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
	panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
	agent.Downloader = hostPullFailingDownloader{}
	executor.reconcileErr = &LocalExecutorClientError{Code: "stage_required"}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Errorf("executeOnce: %v", err)
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf(
			"executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if len(panel.grants) != 1 || panel.grants[0].Operation != "reconcile" {
		t.Fatalf("grants=%+v", panel.grants)
	}
	if len(executor.reconcilePlans) != 1 ||
		executor.reconcilePlans[0].LeaseGeneration != panel.job.LeaseGeneration ||
		panel.grants[0].LeaseGeneration != panel.job.LeaseGeneration {
		t.Fatalf("plan=%+v grant=%+v", executor.reconcilePlans, panel.grants)
	}
	if len(panel.reports) != 2 {
		t.Fatalf("reports=%+v", panel.reports)
	}
	reconciling := panel.reports[0]
	terminal := panel.reports[1]
	if reconciling.Status != "reconciling" ||
		reconciling.Progress != 99 ||
		reconciling.Message != "inspecting interrupted host update state without reapplying" {
		t.Fatalf("reconciling report=%+v", reconciling)
	}
	if terminal.Status != "failed" ||
		terminal.Progress != 100 ||
		terminal.Code != "remote_stage_missing" ||
		terminal.Message != "interrupted job has no durable mutation state to reconcile" {
		t.Fatalf("terminal report=%+v", terminal)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("stage-required recovery left active job: %+v", active)
	}
	if plan := agent.Journal.ActivePlan(); plan != nil {
		t.Fatalf("stage-required recovery left active plan: %+v", plan)
	}
	if pending := agent.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("stage-required recovery left pending reports: %+v", pending)
	}
}

func TestHostPullRecoveryReportsRecordedStageFailureCategory(t *testing.T) {
	for _, test := range []struct {
		name       string
		failure    stageFailureRecord
		reportCode string
	}{
		{
			name: "smoke execution",
			failure: stageFailureRecord{
				Code:    stageFailureCodeSmokeExecution,
				Message: stageFailureMessageSmokeExecution,
			},
			reportCode: stageFailureReportCodeSmokeExecution,
		},
		{
			name: "version mismatch",
			failure: stageFailureRecord{
				Code:    stageFailureCodeVersionMismatch,
				Message: stageFailureMessageVersionMismatch,
			},
			reportCode: stageFailureReportCodeVersionMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
			interrupted := *panel.job
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
			test.failure.JobID = interrupted.ID
			if err := agent.Journal.SetActiveStageFailure(test.failure); err != nil {
				t.Fatal(err)
			}
			panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
			agent.Downloader = hostPullFailingDownloader{}
			executor.reconcileErr = &LocalExecutorClientError{Code: "stage_required"}

			if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
				t.Fatalf("executeOnce: %v", err)
			}
			if len(panel.reports) != 2 {
				t.Fatalf("reports=%+v", panel.reports)
			}
			terminal := panel.reports[1]
			if terminal.Status != "failed" || terminal.Progress != 100 || terminal.Code != test.reportCode || terminal.Message != test.failure.Message {
				t.Fatalf("terminal report=%+v", terminal)
			}
			if active := agent.Journal.Active(); active != nil {
				t.Fatalf("active job survived precise stage failure terminalization: %+v", active)
			}
			if failure := agent.Journal.ActiveStageFailure(); failure != nil {
				t.Fatalf("stage failure survived precise terminalization: %+v", failure)
			}
		})
	}
}

func TestHostPullRecoveryReconcileResponseLossPreservesPlan(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
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
	panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
	agent.Downloader = hostPullFailingDownloader{}
	executor.reconcileErr = errors.New("read local executor mutation response")

	if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
		t.Fatal("lost reconcile response unexpectedly became terminal")
	}
	if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf(
			"executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if len(panel.reports) != 1 || panel.reports[0].Status != "reconciling" || panel.reports[0].Progress != 99 {
		t.Fatalf("reports=%+v", panel.reports)
	}
	if active := agent.Journal.Active(); active == nil || active.ID != panel.job.ID {
		t.Fatalf("lost reconcile response active job=%+v", active)
	}
	if activePlan := agent.Journal.ActivePlan(); activePlan == nil || activePlan.JobID != panel.job.ID {
		t.Fatalf("lost reconcile response active plan=%+v", activePlan)
	}
}

func TestHostPullRecoveryRolledBackTerminatesAtOneHundred(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, true)
	interrupted := *panel.job
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
	panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
	agent.Downloader = hostPullFailingDownloader{}
	executor.reconcileResult = &ApplyResult{Status: "rolled_back", RolledBack: true}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if len(panel.reports) != 2 {
		t.Fatalf("reports=%+v", panel.reports)
	}
	reconciling := panel.reports[0]
	terminal := panel.reports[1]
	if reconciling.Status != "reconciling" ||
		reconciling.Progress != 99 ||
		terminal.Status != "rolled_back" ||
		terminal.Progress != 100 ||
		terminal.Code != "post_update_verification_failed" {
		t.Fatalf("reconciling=%+v terminal=%+v", reconciling, terminal)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("rolled-back recovery left active job: %+v", active)
	}
}
