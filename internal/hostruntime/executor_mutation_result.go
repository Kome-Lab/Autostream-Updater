package hostruntime

import (
	"fmt"
	"strings"
)

func remoteLedgerRequestFailure(ledger executorMutationLedger, plan MutationPlan, operation string) string {
	if ledger.JobID != plan.JobID {
		if ledger.State != remoteLedgerTerminal {
			return "reconcile_required"
		}
		return "stage_required"
	}
	if !ledger.Intent.matches(plan) {
		return "plan_conflict"
	}
	if operation == "apply" {
		if ledger.PlanSHA256 != plan.PlanSHA256 || ledger.SessionID != plan.SessionID || ledger.LeaseGeneration != plan.LeaseGeneration {
			return "plan_conflict"
		}
	} else if operation == "reconcile" {
		if plan.LeaseGeneration < ledger.LeaseGeneration {
			return "plan_conflict"
		}
	} else {
		return "invalid_request"
	}
	return ""
}

func sanitizeRemoteApplyResult(result ApplyResult) ApplyResult {
	clean := ApplyResult{
		Status: result.Status, ArtifactDigest: normalizeDigest(result.ArtifactDigest),
		PreviousDigest: normalizeDigest(result.PreviousDigest), RolledBack: result.RolledBack,
	}
	switch clean.Status {
	case "succeeded":
		clean.Message = "target update completed and was verified"
	case "rolled_back":
		clean.Message = "previous target state was restored and verified"
	}
	return clean
}

func bindRemoteApplyResult(plan MutationPlan, result ApplyResult) (ApplyResult, bool) {
	expected := normalizeDigest(plan.ResultArtifactDigest())
	if expected == "" || (result.ArtifactDigest != "" && normalizeDigest(result.ArtifactDigest) != expected) {
		return ApplyResult{}, false
	}
	result.ArtifactDigest = expected
	return sanitizeRemoteApplyResult(result), true
}

func executorFailure(code string) executorMutationOutcome {
	messages := map[string]string{
		"invalid_request":              "remote request was rejected",
		"target_mismatch":              "request does not match this host target",
		"config_mismatch":              "request does not match the current helper policy",
		"target_unavailable":           "configured target is unavailable",
		"target_busy":                  "another target operation is active",
		"state_unavailable":            "durable host state is unavailable",
		"state_invalid":                "durable host state requires operator review",
		"stage_failed":                 "release staging failed",
		"stage_required":               "no durable mutation ledger or apply-authorized state exists for the immutable release plan",
		"stage_invalid":                "the staged release no longer matches the plan",
		"plan_conflict":                "job identity was reused with a different plan",
		"reconcile_required":           "host state is ambiguous and requires reconcile",
		"already_terminal":             "the update plan is already terminal",
		"mutation_precondition_failed": "target precondition validation failed",
		"launcher_unavailable":         "detached host execution is unavailable",
		"operation_continues":          "host operation continues and must be recovered by status or reconcile",
	}
	message, ok := messages[code]
	if !ok {
		code, message = "internal_error", "local executor could not complete the request"
	}
	return executorMutationOutcome{Error: &executorMutationFailure{Code: code, Message: message}}
}

// executorFailureWithMessage preserves only an already-sanitized, fixed-contract
// message. It is used for diagnostics where the generic failure code alone is
// insufficient, while keeping raw command output, paths, and credentials out
// of the RPC response.
func executorFailureWithMessage(code, message string) executorMutationOutcome {
	response := executorFailure(code)
	if response.Error != nil && safeExecutorMessage(message) {
		response.Error.Message = message
	}
	return response
}

func remoteStageFailureMessage(err error) string {
	if err == nil {
		return "release staging failed"
	}
	for _, failure := range []struct {
		marker  string
		message string
	}{
		{"systemd release digest mismatch", "release artifact digest mismatch"},
		{"staged systemd artifact path is invalid", "staged release path validation failed"},
		{"staged systemd artifact checksum verification failed", "staged release checksum verification failed"},
		{"staged systemd artifact is incomplete", "staged release is incomplete"},
		{"staged systemd binary smoke execution failed", "candidate binary smoke execution failed"},
		{"staged systemd binary version output mismatch", "candidate binary version output mismatch"},
		// Keep the pre-v1.9.15 category readable when a newer Host Agent
		// reconciles a stage failure produced by an older helper.
		{"staged systemd binary smoke check failed", "candidate binary smoke check failed"},
		{"managed systemd release bootstrap is required", "managed current release is unavailable"},
		{"managed target current version does not match the immutable plan", "current version does not match the update plan"},
		{"backup configured systemd target", "configured target backup failed"},
		{"previous systemd release is not rollback-safe", "current release rollback check failed"},
		{"previous systemd release is incomplete", "current release is incomplete"},
		{"previous systemd release is not healthy", "current service health or process verification failed"},
		{"systemd release path is invalid", "new release path validation failed"},
	} {
		if strings.Contains(err.Error(), failure.marker) {
			return failure.message
		}
	}
	return "release staging failed"
}

func (r executorMutationRuntime) String() string {
	return fmt.Sprintf("executorMutationRuntime{platform:%s/%s}", r.platformOS, r.platformArch)
}
