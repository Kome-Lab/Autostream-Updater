package hostruntime

import (
	"context"
	"errors"
	"strings"
)

func (a *HostPullAgent) processExecutionJob(
	ctx context.Context,
	panel HostPullExecutionControlPlane,
	binding HostAgentBinding,
	policy HostAgentPolicy,
	job UpdateJob,
) error {
	if job.EffectiveOperation() == updateJobOperationPortReconfigure {
		return a.processPortReconfigurationJob(ctx, panel, binding, policy, job)
	}
	if err := a.Journal.SetActive(&job); err != nil {
		return err
	}
	terminal := func(status, code, message string, result ApplyResult) error {
		_, err := a.emitExecutionReport(ctx, panel, job, status, code, message, 100, result.ArtifactDigest, result.PreviousDigest)
		return err
	}
	if job.RecoveryRequired {
		plan, err := a.recoverExecutionPlan(policy, job)
		if err != nil {
			return terminal("failed", "recovery_plan_unavailable", "interrupted job has no trusted durable plan to reconcile", ApplyResult{})
		}
		if _, err := a.emitExecutionReport(ctx, panel, job, "reconciling", "", "inspecting interrupted host update state without reapplying", 99, "", ""); err != nil {
			return err
		}
		result, err := a.invokeExecutionMutation(ctx, panel, binding, policy, job, plan, "reconcile")
		if err != nil {
			if localExecutorErrorCode(err) == "stage_required" {
				if failure := a.Journal.ActiveStageFailure(); failure != nil && failure.JobID == job.ID {
					return terminal(
						"failed", failure.reportCode(), failure.Message,
						ApplyResult{},
					)
				}
				return terminal(
					"failed", "remote_stage_missing",
					"interrupted job has no durable mutation state to reconcile",
					ApplyResult{},
				)
			}
			return err
		}
		return a.finishExecutionResult(terminal, result)
	}

	if _, err := a.emitExecutionReport(ctx, panel, job, "claimed", "", "update job claimed and fixed target validated", 5, "", ""); err != nil {
		return err
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "downloading", "", "resolving immutable public release metadata", 20, "", ""); err != nil {
		return err
	}
	plan, err := a.prepareExecutionPlan(ctx, policy, job)
	if err != nil {
		return terminal("failed", "artifact_verification_failed", "immutable public release metadata could not be verified", ApplyResult{})
	}
	if err := a.Journal.SetActivePlan(plan); err != nil {
		return err
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "verifying", "", "release tag, manifest and artifact identity verified", 40, normalizeDigest(plan.ArtifactDigest), ""); err != nil {
		return err
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "staging", "", "root executor is staging the immutable release", 55, normalizeDigest(plan.ArtifactDigest), ""); err != nil {
		return err
	}
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          binding.OwnershipEpoch,
		OwnershipPolicyRevision: job.PolicyRevision,
		ExecutorPolicyRevision:  policy.LocalExecutorPolicyRevision,
	}
	if _, err := a.Executor.Stage(ctx, plan, fence); err != nil {
		if failure, ok := stageFailureFromLocalExecutorError(job.ID, err); ok {
			if journalErr := a.Journal.SetActiveStageFailure(failure); journalErr != nil {
				return journalErr
			}
		}
		// Stage is non-mutating. Preserve the active cursor because a lost UDS
		// result or an explicit failure after an uncertain ledger commit may have
		// left durable state, so recovery must prove and settle it.
		return err
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "installing", "", "root executor is applying the fixed target", 65, normalizeDigest(plan.ArtifactDigest), ""); err != nil {
		return err
	}
	result, err := a.invokeExecutionMutation(ctx, panel, binding, policy, job, plan, "apply")
	if err != nil {
		if _, reportErr := a.emitExecutionReport(ctx, panel, job, "reconciling", "", "apply result is uncertain; reconciling without reapplying", 99, "", ""); reportErr != nil {
			return reportErr
		}
		result, err = a.invokeExecutionMutation(ctx, panel, binding, policy, job, plan, "reconcile")
		if err != nil {
			return err
		}
		// Reconciling is reported at 99%, and the server accepts only a terminal
		// transition from that state. Do not regress to health_checking/90 after
		// the executor has already returned its durable verified result.
		return a.finishExecutionResult(terminal, result)
	}
	if _, err := a.emitExecutionReport(ctx, panel, job, "health_checking", "", "root executor completed bounded health and version checks", 90, result.ArtifactDigest, result.PreviousDigest); err != nil {
		return err
	}
	if result.Status == "rolled_back" || result.RolledBack {
		if _, err := a.emitExecutionReport(
			ctx, panel, job, "rolling_back", "",
			"post-update checks failed; previous release was restored", 95,
			result.ArtifactDigest, result.PreviousDigest,
		); err != nil {
			return err
		}
	}
	return a.finishExecutionResult(terminal, result)
}

func localExecutorErrorCode(err error) string {
	var executorErr *LocalExecutorClientError
	if errors.As(err, &executorErr) {
		return strings.TrimSpace(executorErr.Code)
	}
	return ""
}
