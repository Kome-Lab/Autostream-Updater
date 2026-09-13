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

func TestHostPullExecutionPostUpdateRollbackReportsRollingBackBeforeTerminal(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	executor.applyResult = &ApplyResult{
		Status:     "rolled_back",
		RolledBack: true,
		Message:    "expected worker version was not healthy",
	}

	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}

	wantStatuses := []string{
		"claimed", "downloading", "verifying", "staging", "installing",
		"health_checking", "rolling_back", "rolled_back",
	}
	if len(panel.reports) != len(wantStatuses) {
		t.Fatalf("reports=%+v, want statuses=%v", panel.reports, wantStatuses)
	}
	for i, want := range wantStatuses {
		if got := panel.reports[i].Status; got != want {
			t.Fatalf("report[%d]=%+v, want status=%q", i, panel.reports[i], want)
		}
	}
	rollingBack := panel.reports[len(panel.reports)-2]
	if rollingBack.Progress != 95 || rollingBack.Code != "" {
		t.Fatalf("rolling_back report=%+v", rollingBack)
	}
	terminal := panel.reports[len(panel.reports)-1]
	if terminal.Progress != 100 || terminal.Code != "post_update_verification_failed" {
		t.Fatalf("terminal report=%+v", terminal)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("rolled-back job left active: %+v", active)
	}
}

func TestHostPullExecutionExplicitStageFailurePreservesPlanForRecovery(t *testing.T) {
	for _, code := range []string{"stage_failed", "state_unavailable"} {
		t.Run(code, func(t *testing.T) {
			agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
			executor.stageErr = &LocalExecutorClientError{Code: code}

			if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
				t.Fatal("explicit stage failure unexpectedly became terminal")
			}
			if executor.stageCalls != 1 || executor.applyCalls != 0 || executor.reconcileCalls != 0 {
				t.Fatalf(
					"executor calls stage=%d apply=%d reconcile=%d",
					executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
				)
			}
			if len(panel.grants) != 0 {
				t.Fatalf("stage failure issued grants before recovery: %+v", panel.grants)
			}
			if len(panel.reports) == 0 {
				t.Fatal("stage failure emitted no reports")
			}
			last := panel.reports[len(panel.reports)-1]
			if last.Status != "staging" || last.Progress != 55 {
				t.Fatalf("last report=%+v", last)
			}
			for _, report := range panel.reports {
				if isTerminalUpdateStatus(report.Status) {
					t.Fatalf("stage failure emitted terminal report before reconcile: %+v", report)
				}
			}
			if active := agent.Journal.Active(); active == nil || active.ID != panel.job.ID {
				t.Fatalf("stage failure active job=%+v", active)
			}
			if plan := agent.Journal.ActivePlan(); plan == nil || plan.JobID != panel.job.ID {
				t.Fatalf("stage failure active plan=%+v", plan)
			}
		})
	}
}

func TestHostPullExecutionRecordsPreciseStageFailureForRecovery(t *testing.T) {
	for _, test := range []struct {
		name    string
		message string
		code    string
	}{
		{
			name:    "smoke execution",
			message: stageFailureMessageSmokeExecution,
			code:    stageFailureCodeSmokeExecution,
		},
		{
			name:    "version mismatch",
			message: stageFailureMessageVersionMismatch,
			code:    stageFailureCodeVersionMismatch,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
			executor.stageErr = &LocalExecutorClientError{Code: "stage_failed", Message: test.message}

			if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
				t.Fatal("stage failure unexpectedly completed")
			}
			failure := agent.Journal.ActiveStageFailure()
			if failure == nil || failure.JobID != panel.job.ID || failure.Code != test.code || failure.Message != test.message {
				t.Fatalf("recorded failure=%+v", failure)
			}
			if active := agent.Journal.Active(); active == nil || active.ID != panel.job.ID {
				t.Fatalf("active job=%+v", active)
			}
		})
	}
}

func TestHostPullJournalRejectsTamperedDurablePlan(t *testing.T) {
	agent, panel, _, _, policy := newHostPullExecutionHarness(t, false)
	job := *panel.job
	if err := agent.Journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	plan, err := agent.prepareExecutionPlan(context.Background(), policy, job)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Journal.SetActivePlan(plan); err != nil {
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
	data.ActivePlan.TargetID = "different-target"
	tampered, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(agent.StateDir); err == nil ||
		!strings.Contains(err.Error(), "active plan binding") {
		t.Fatalf("tampered journal error=%v", err)
	}
}

func TestHostPullExecutionUncertainApplyReconcilesWithoutReapplying(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	executor.applyErr = errors.New("UDS result lost")
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("executeOnce: %v", err)
	}
	if executor.applyCalls != 1 || executor.reconcileCalls != 1 {
		t.Fatalf("apply=%d reconcile=%d", executor.applyCalls, executor.reconcileCalls)
	}
	if len(executor.reconcileFences) != 1 || executor.reconcileFences[0].SourcePolicyRevision != policy.SourcePolicyRevision {
		t.Fatalf("reconcile fences=%+v policy source revision=%d", executor.reconcileFences, policy.SourcePolicyRevision)
	}
	if len(panel.grants) != 2 ||
		panel.grants[0].Operation != "apply" ||
		panel.grants[1].Operation != "reconcile" {
		t.Fatalf("grants=%+v", panel.grants)
	}
	reconcilingIndex := -1
	previousProgress := -1
	for index, report := range panel.reports {
		if report.Progress < previousProgress {
			t.Errorf(
				"report progress decreased at index %d: previous=%d report=%+v",
				index, previousProgress, report,
			)
		}
		previousProgress = report.Progress
		if report.Status == "health_checking" {
			t.Errorf("uncertain apply emitted post-reconcile health_checking report: %+v", report)
		}
		if report.Status == "reconciling" {
			reconcilingIndex = index
		}
	}
	if reconcilingIndex < 0 {
		t.Fatalf("reports=%+v", panel.reports)
	}
	if reconcilingIndex+1 >= len(panel.reports) {
		t.Fatalf("reconciling report was not followed by a terminal report: %+v", panel.reports)
	}
	reconciling := panel.reports[reconcilingIndex]
	terminal := panel.reports[reconcilingIndex+1]
	if reconciling.Progress != 99 || terminal.Status != "succeeded" || terminal.Progress != 100 {
		t.Fatalf("reconciling=%+v terminal=%+v", reconciling, terminal)
	}
}

func TestHostPullExecutionUncertainStagePreservesPlanAndRecoversWithoutRestaging(t *testing.T) {
	agent, panel, executor, binding, policy := newHostPullExecutionHarness(t, false)
	executor.stageErr = errors.New("read local executor mutation response")

	if err := agent.executeOnce(context.Background(), binding, policy); err == nil {
		t.Fatal("uncertain stage result unexpectedly became terminal")
	}
	if executor.stageCalls != 1 || executor.applyCalls != 0 || executor.reconcileCalls != 0 {
		t.Fatalf(
			"first executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if len(panel.grants) != 0 {
		t.Fatalf("uncertain stage issued grants before recovery: %+v", panel.grants)
	}
	if len(panel.reports) == 0 {
		t.Fatal("uncertain stage emitted no reports")
	}
	lastInitial := panel.reports[len(panel.reports)-1]
	if lastInitial.Status != "staging" || lastInitial.Progress != 55 {
		t.Fatalf("last initial report=%+v", lastInitial)
	}
	for _, report := range panel.reports {
		if isTerminalUpdateStatus(report.Status) {
			t.Fatalf("uncertain stage emitted terminal report: %+v", report)
		}
	}
	if active := agent.Journal.Active(); active == nil || active.ID != panel.job.ID {
		t.Fatalf("uncertain stage active job=%+v", active)
	}
	if plan := agent.Journal.ActivePlan(); plan == nil || plan.JobID != panel.job.ID {
		t.Fatalf("uncertain stage active plan=%+v", plan)
	}
	executor.stageErr = nil
	panel.job.RecoveryRequired = true
	panel.job.LeaseGeneration++
	panel.job.Status = "staging"
	panel.job.Progress = 55
	panel.job.Sequence = uint64(len(panel.reports))
	panel.job.ReportSequence = panel.job.Sequence + 1
	if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
		t.Fatalf("recovery executeOnce: %v", err)
	}
	if executor.stageCalls != 1 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
		t.Fatalf(
			"recovered executor calls stage=%d apply=%d reconcile=%d",
			executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
		)
	}
	if len(panel.grants) != 1 || panel.grants[0].Operation != "reconcile" {
		t.Fatalf("recovery grants=%+v", panel.grants)
	}
	if len(panel.reports) < 2 {
		t.Fatalf("recovery reports=%+v", panel.reports)
	}
	reconciling := panel.reports[len(panel.reports)-2]
	terminal := panel.reports[len(panel.reports)-1]
	if reconciling.Status != "reconciling" ||
		reconciling.Progress != 99 ||
		terminal.Status != "succeeded" ||
		terminal.Progress != 100 {
		t.Fatalf("reconciling=%+v terminal=%+v", reconciling, terminal)
	}
	if active := agent.Journal.Active(); active != nil {
		t.Fatalf("recovered uncertain stage left active job: %+v", active)
	}
}

func TestHostPullPermanentStaleReportPreservesPlanForFreshRecovery(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		status    string
		code      string
		message   string
		progress  int
		errorCode string
	}{
		{
			name: "reconciling", status: "reconciling",
			message:  "inspecting interrupted host update state without reapplying",
			progress: 99, errorCode: "system_update_lease_invalid",
		},
		{
			name: "terminal", status: "failed", code: "remote_stage_missing",
			message:  "interrupted job has no durable mutation state to reconcile",
			progress: 100, errorCode: "system_update_sequence_stale",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
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
			if _, err := agent.Journal.Queue(
				interrupted.ID, agent.Bootstrap.NodeID, interrupted.LeaseToken,
				interrupted.LeaseGeneration, testCase.status, testCase.code,
				testCase.message, testCase.progress, "", "",
			); err != nil {
				t.Fatal(err)
			}
			panel.reportErrors = []error{&PanelHTTPError{
				Status: 409,
				Code:   testCase.errorCode,
			}}

			if err := agent.flushExecutionReports(context.Background(), panel); !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("stale report error=%v", err)
			}
			if pending := agent.Journal.Pending(); len(pending) != 0 {
				t.Fatalf("stale reports were not dropped: %+v", pending)
			}
			if active := agent.Journal.Active(); active == nil || active.ID != interrupted.ID {
				t.Fatalf("stale report cleared active job: %+v", active)
			}
			if activePlan := agent.Journal.ActivePlan(); activePlan == nil ||
				activePlan.JobID != interrupted.ID || activePlan.PlanSHA256 != plan.PlanSHA256 {
				t.Fatalf("stale report cleared or changed active plan: %+v", activePlan)
			}

			panel.job.RecoveryRequired = true
			panel.job.LeaseGeneration = interrupted.LeaseGeneration + 1
			panel.job.LeaseToken = strings.Repeat("r", 48)
			panel.job.Status = testCase.status
			panel.job.Progress = testCase.progress
			panel.job.Sequence = 7
			panel.job.ReportSequence = 8
			agent.Downloader = hostPullFailingDownloader{}

			if err := agent.executeOnce(context.Background(), binding, policy); err != nil {
				t.Fatalf("fresh recovery executeOnce: %v", err)
			}
			if executor.stageCalls != 0 || executor.applyCalls != 0 || executor.reconcileCalls != 1 {
				t.Fatalf(
					"fresh recovery calls stage=%d apply=%d reconcile=%d",
					executor.stageCalls, executor.applyCalls, executor.reconcileCalls,
				)
			}
			if len(panel.reports) != 2 ||
				panel.reports[0].Status != "reconciling" || panel.reports[0].Progress != 99 ||
				panel.reports[1].Status != "succeeded" || panel.reports[1].Progress != 100 {
				t.Fatalf("fresh recovery reports=%+v", panel.reports)
			}
			if active := agent.Journal.Active(); active != nil {
				t.Fatalf("fresh recovery left active job: %+v", active)
			}
			if activePlan := agent.Journal.ActivePlan(); activePlan != nil {
				t.Fatalf("fresh recovery left active plan: %+v", activePlan)
			}
			if pending := agent.Journal.Pending(); len(pending) != 0 {
				t.Fatalf("fresh recovery left pending reports: %+v", pending)
			}
		})
	}
}
