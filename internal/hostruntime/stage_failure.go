package hostruntime

import (
	"errors"
	"strings"
)

// Stage failure categories are deliberately fixed and credential-free. They
// are persisted in the Host Agent journal so a stage error that later becomes
// stage_required during recovery does not get collapsed into a generic
// remote_stage_missing result.
const (
	stageFailureCodeReleaseStaging        = "release_staging_failed"
	stageFailureCodeSmokeExecution        = "candidate_binary_smoke_execution_failed"
	stageFailureCodeVersionMismatch       = "candidate_binary_version_mismatch"
	stageFailureMessageReleaseStaging     = "release staging failed"
	stageFailureMessageSmokeExecution     = "candidate binary smoke execution failed"
	stageFailureMessageVersionMismatch    = "candidate binary version output mismatch"
	stageFailureReportCodeReleaseStaging  = "remote_stage_failed"
	stageFailureReportCodeSmokeExecution  = "remote_stage_smoke_execution_failed"
	stageFailureReportCodeVersionMismatch = "remote_stage_version_mismatch"
)

type stageFailureRecord struct {
	JobID   string `json:"job_id"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (f stageFailureRecord) validate() error {
	if !identifierPattern.MatchString(strings.TrimSpace(f.JobID)) {
		return errors.New("stage failure job identity is invalid")
	}
	switch f.Code {
	case stageFailureCodeReleaseStaging:
		if f.Message != stageFailureMessageReleaseStaging && f.Message != "candidate binary smoke check failed" {
			return errors.New("generic stage failure message is invalid")
		}
	case stageFailureCodeSmokeExecution:
		if f.Message != stageFailureMessageSmokeExecution {
			return errors.New("smoke execution failure message is invalid")
		}
	case stageFailureCodeVersionMismatch:
		if f.Message != stageFailureMessageVersionMismatch {
			return errors.New("version mismatch failure message is invalid")
		}
	default:
		return errors.New("stage failure code is invalid")
	}
	if !safeExecutorMessage(f.Message) {
		return errors.New("stage failure message is invalid")
	}
	return nil
}

func (f stageFailureRecord) reportCode() string {
	switch f.Code {
	case stageFailureCodeSmokeExecution:
		return stageFailureReportCodeSmokeExecution
	case stageFailureCodeVersionMismatch:
		return stageFailureReportCodeVersionMismatch
	default:
		return stageFailureReportCodeReleaseStaging
	}
}

func stageFailureFromLocalExecutorError(jobID string, err error) (stageFailureRecord, bool) {
	var executorErr *LocalExecutorClientError
	if !errors.As(err, &executorErr) || executorErr.Code != "stage_failed" {
		return stageFailureRecord{}, false
	}
	record := stageFailureRecord{
		JobID:   jobID,
		Code:    stageFailureCodeReleaseStaging,
		Message: stageFailureMessageReleaseStaging,
	}
	switch strings.TrimSpace(executorErr.Message) {
	case stageFailureMessageSmokeExecution:
		record.Code = stageFailureCodeSmokeExecution
		record.Message = stageFailureMessageSmokeExecution
	case stageFailureMessageVersionMismatch:
		record.Code = stageFailureCodeVersionMismatch
		record.Message = stageFailureMessageVersionMismatch
	case "candidate binary smoke check failed":
		// Preserve a safe generic category from pre-v1.9.15 helpers without
		// misclassifying it as either of the new precise categories.
		record.Message = "candidate binary smoke check failed"
	}
	return record, true
}
