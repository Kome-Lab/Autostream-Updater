package hostruntime

import (
	"context"
	"errors"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"strings"
	"time"
)

func executorMutationRequest(ctx context.Context, cfg HelperConfig, target Target, plan MutationPlan, operation string, grant BoundedSecret, ledger *executorMutationLedger, rt executorMutationRuntime) executorMutationOutcome {
	if ledger == nil {
		if operation == "reconcile" {
			if err := cleanupRemoteOrphanStage(cfg, plan); err != nil {
				return executorFailure("state_unavailable")
			}
		}
		return executorFailure("stage_required")
	}
	if failure := remoteLedgerRequestFailure(*ledger, plan, operation); failure != "" {
		// A new job can commit its stage and then fail while atomically replacing
		// the previous job's terminal target ledger. In that state the terminal
		// ledger remains authoritative for the previous job, while only the new
		// job's exact stage roots are unledgered orphans. Reconcile may clean those
		// roots before returning stage_required; apply and every non-terminal or
		// conflicting ledger continue to fail without touching stage state.
		if failure == "stage_required" && operation == "reconcile" &&
			ledger.State == remoteLedgerTerminal && ledger.JobID != plan.JobID {
			if err := cleanupRemoteOrphanStage(cfg, plan); err != nil {
				return executorFailure("state_unavailable")
			}
		}
		return executorFailure(failure)
	}
	if ledger.State == remoteLedgerTerminal {
		result, ok := bindRemoteApplyResult(plan, *ledger.Result)
		if !ok {
			return executorFailure("state_invalid")
		}
		return executorMutationOutcome{Result: &result, SessionID: plan.SessionID, PlanSHA256: plan.PlanSHA256}
	}
	if err := validateExecutorStage(cfg, target, plan, ledger.Stage); err != nil {
		return executorFailure("stage_invalid")
	}
	if operation == "apply" && ledger.State != remoteLedgerStaged {
		return executorFailure("reconcile_required")
	}
	if operation == "reconcile" && ledger.State == remoteLedgerStaged {
		result, _ := bindRemoteApplyResult(plan, ApplyResult{Status: "rolled_back", RolledBack: true, Message: "staged release was not applied"})
		terminal := *ledger
		terminal.Operation, terminal.SessionID, terminal.State, terminal.Result = operation, plan.SessionID, remoteLedgerTerminal, &result
		terminal.PlanSHA256, terminal.LeaseGeneration = plan.PlanSHA256, plan.LeaseGeneration
		if err := saveExecutorMutationLedger(cfg, terminal); err != nil {
			return executorFailure("state_unavailable")
		}
		return executorMutationOutcome{Result: &result, SessionID: plan.SessionID, PlanSHA256: plan.PlanSHA256}
	}

	working := *ledger
	working.Operation = operation
	working.SessionID = plan.SessionID
	working.PlanSHA256 = plan.PlanSHA256
	working.LeaseGeneration = plan.LeaseGeneration
	gateCalled := false
	gateDeadline := time.Now().Add(30 * time.Second)
	gate := func(gateCtx context.Context) error {
		if gateCalled {
			return errors.New("mutation gate was invoked more than once")
		}
		remaining := time.Until(gateDeadline)
		if remaining <= 0 {
			return errors.New("mutation grant preflight deadline exceeded")
		}
		gateCalled = true
		working.State = remoteLedgerGrantConsuming
		working.Result = nil
		if err := saveExecutorMutationLedger(cfg, working); err != nil {
			return errors.New("persist grant consumption fence")
		}
		consumeCtx, cancel := context.WithTimeout(gateCtx, remaining)
		defer cancel()
		if err := consumeExecutorMutationGrant(
			consumeCtx, cfg.PanelURL, plan, operation, grant, rt,
		); err != nil {
			return err
		}
		working.State = remoteLedgerGrantConsumed
		if err := saveExecutorMutationLedger(cfg, working); err != nil {
			return errors.New("persist consumed mutation grant")
		}
		working.State = remoteLedgerMutating
		if err := saveExecutorMutationLedger(cfg, working); err != nil {
			return errors.New("persist mutation fence")
		}
		return nil
	}

	applyPlan := plan.ApplyPlan()
	applyPlan.StageDir = ledger.Stage.RootDir
	applyPlan.ArtifactDigest = strings.TrimPrefix(normalizeDigest(ledger.Stage.ArtifactDigest), "sha256:")
	var result ApplyResult
	var err error
	if operation == "apply" {
		if target.DeploymentMode == ModeSystemd {
			result, err = applyRemoteStagedSystemd(ctx, target, applyPlan, *ledger.Stage, rt.runner, gate)
		} else {
			result, err = applyDockerWithGateAndBaseline(ctx, target, applyPlan, rt.runner, gate, true, ledger.Stage.DockerBaseline, ledger.Stage.ImageID)
		}
	} else {
		// Recovery grants are consumed before potentially slow unhealthy-state
		// inspection. The inspection itself is hard-bounded so rollback begins
		// within 30 seconds of consumption; the grant is never allowed to expire
		// while a 90-second health loop is still deciding whether to mutate.
		if err = gate(ctx); err == nil {
			inspectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			if target.DeploymentMode == ModeSystemd {
				result, err = reconcileSystemdWithGate(inspectCtx, target, applyPlan, rt.runner, nil)
			} else {
				result, err = reconcileDockerWithGate(inspectCtx, target, applyPlan, rt.runner, nil)
			}
		}
	}
	if err != nil {
		if gateCalled {
			working.State = remoteLedgerAmbiguous
			working.Result = nil
			_ = saveExecutorMutationLedger(cfg, working)
			return executorFailure("reconcile_required")
		}
		return executorFailure("mutation_precondition_failed")
	}
	var bound bool
	result, bound = bindRemoteApplyResult(plan, result)
	if !bound {
		if gateCalled {
			working.State = remoteLedgerAmbiguous
			working.Result = nil
			_ = saveExecutorMutationLedger(cfg, working)
		}
		return executorFailure("reconcile_required")
	}
	if result.Status != "succeeded" && result.Status != "rolled_back" {
		if gateCalled {
			working.State = remoteLedgerAmbiguous
			working.Result = nil
			_ = saveExecutorMutationLedger(cfg, working)
		}
		return executorFailure("reconcile_required")
	}
	working.State = remoteLedgerTerminal
	working.Result = &result
	if err := saveExecutorMutationLedger(cfg, working); err != nil {
		return executorFailure("reconcile_required")
	}
	return executorMutationOutcome{Result: &result, SessionID: plan.SessionID, PlanSHA256: plan.PlanSHA256}
}

func consumeExecutorMutationGrant(
	ctx context.Context,
	panelURL string,
	plan MutationPlan,
	operation string,
	grant BoundedSecret,
	rt executorMutationRuntime,
) error {
	if rt.v2GrantBinding != nil {
		if rt.consumeV2Grant == nil || rt.now == nil {
			return errors.New("v2 mutation grant consumer is unavailable")
		}
		if err := rt.consumeV2Grant(
			ctx,
			panelURL,
			plan.JobID,
			grant.Reveal(),
			contracts.UpdaterMutationGrantConsumeRequest{Binding: *rt.v2GrantBinding},
			rt.httpClient,
			rt.now().UTC(),
		); err != nil {
			return errors.New("mutation grant rejected")
		}
		return nil
	}
	binding := MutationGrantBinding{
		LeaseGeneration: plan.LeaseGeneration, HostID: plan.HostID, TargetID: plan.TargetID,
		TransportMode: rt.transportMode,
		ServiceType:   plan.ServiceType, TargetVersion: plan.TargetVersion, DeploymentMode: plan.DeploymentMode,
		Operation: operation, PlanSHA256: plan.PlanSHA256, SessionID: plan.SessionID,
		OwnershipEpoch: rt.ownershipEpoch, PolicyRevision: rt.policyRevision,
	}
	if rt.consumeGrant == nil ||
		rt.consumeGrant(ctx, panelURL, plan.JobID, grant.Reveal(), binding, rt.httpClient) != nil {
		return errors.New("mutation grant rejected")
	}
	return nil
}
