package hostruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStageFailureFromLocalExecutorErrorSeparatesSmokeAndVersionCategories(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		code        string
		wantMessage string
	}{
		{
			name:        "smoke execution",
			message:     stageFailureMessageSmokeExecution,
			code:        stageFailureCodeSmokeExecution,
			wantMessage: stageFailureMessageSmokeExecution,
		},
		{
			name:        "version mismatch",
			message:     stageFailureMessageVersionMismatch,
			code:        stageFailureCodeVersionMismatch,
			wantMessage: stageFailureMessageVersionMismatch,
		},
		{
			name:        "generic",
			message:     "release staging failed",
			code:        stageFailureCodeReleaseStaging,
			wantMessage: stageFailureMessageReleaseStaging,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failure, ok := stageFailureFromLocalExecutorError(
				"job-stage-failure",
				&LocalExecutorClientError{Code: "stage_failed", Message: test.message},
			)
			if !ok || failure.Code != test.code || failure.Message != test.wantMessage {
				t.Fatalf("failure=%+v ok=%t", failure, ok)
			}
			if err := failure.validate(); err != nil {
				t.Fatalf("failure.validate: %v", err)
			}
		})
	}

	if _, ok := stageFailureFromLocalExecutorError(
		"job-stage-failure",
		&LocalExecutorClientError{Code: "state_unavailable", Message: "durable executor state is unavailable"},
	); ok {
		t.Fatal("non-stage failure was recorded as a stage failure")
	}
	if _, ok := stageFailureFromLocalExecutorError("job-stage-failure", errors.New("stage_failed")); ok {
		t.Fatal("untyped stage failure was recorded as a durable category")
	}
}

func TestJournalPersistsCredentialFreeActiveStageFailure(t *testing.T) {
	stateDir := t.TempDir()
	journal, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	job := &UpdateJob{ID: "job-stage-failure", LeaseToken: "lease-must-not-persist", LeaseGeneration: 1, ReportSequence: 1}
	if err := journal.SetActive(job); err != nil {
		t.Fatal(err)
	}
	failure := stageFailureRecord{
		JobID:   job.ID,
		Code:    stageFailureCodeVersionMismatch,
		Message: stageFailureMessageVersionMismatch,
	}
	if err := journal.SetActiveStageFailure(failure); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join(stateDir, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "active_stage_failure") ||
		!strings.Contains(string(payload), stageFailureMessageVersionMismatch) ||
		strings.Contains(string(payload), job.LeaseToken) {
		t.Fatalf("journal payload=%s", payload)
	}
	reopened, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.ActiveStageFailure()
	if got == nil || *got != failure {
		t.Fatalf("reopened failure=%+v want=%+v", got, failure)
	}
	if err := reopened.ClearActive(); err != nil {
		t.Fatal(err)
	}
	if got := reopened.ActiveStageFailure(); got != nil {
		t.Fatalf("active stage failure survived clear: %+v", got)
	}
}
