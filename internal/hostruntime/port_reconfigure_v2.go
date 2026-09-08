package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

type portV2Journal struct {
	Plan           SystemdPortReconfigurePlan
	State          string
	Transition     *portPolicyTransitionState
	Result         *SystemdPortReconfigureResult
	CurrentVersion string
}

var errPortPolicyStartExpired = errors.New("port policy first-write deadline expired")

// These drivers use the existing systemd/Docker ledgers and runtime adapters.
// The shared coordinator owns policy-first ordering and recovery semantics.
type portV2Driver interface {
	load(SystemdPortReconfigurePlan) (*portV2Journal, error)
	prepare(context.Context, LocalExecutorPolicy, SystemdPortReconfigurePlan, portPolicyCandidates) (*portV2Journal, error)
	save(*portV2Journal, bool) error
	verify(context.Context, LocalExecutorPolicy, contracts.SystemUpdatePortSnapshotRef) (*contracts.SystemUpdatePortRuntimeInstance, error)
	write(context.Context, LocalExecutorPolicy, contracts.SystemUpdatePortSnapshotRef) error
	restart(context.Context, LocalExecutorPolicy, contracts.SystemUpdatePortSnapshotRef) error
	consume(context.Context, SystemdPortReconfigurePlan, string, string, BoundedSecret) error
	crash(string) error
	now() time.Time
	policyStore() portPolicyStore
}

func executePortV2(ctx context.Context, policy LocalExecutorPolicy, request LocalExecutorRequest, driver portV2Driver) LocalExecutorResponse {
	failure := func(code string) LocalExecutorResponse {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, code)
	}
	if request.PortPlan == nil || request.PortPlan.PortContractVersion != 2 || request.Validate() != nil ||
		driver == nil || driver.policyStore() == nil || request.MutationGrantV2Binding == nil {
		return failure("config_mismatch")
	}
	plan := *request.PortPlan
	rootTarget, ok := policy.Target(plan.TargetID)
	if !ok || validatePortV2GrantBinding(driver.now().UTC(), *request.MutationGrantV2Binding, request.Operation, plan,
		LocalExecutorMutationFence{SourcePolicyRevision: request.SourcePolicyRevision, OwnershipEpoch: request.OwnershipEpoch,
			OwnershipPolicyRevision: request.OwnershipPolicyRevision, ExecutorPolicyRevision: request.ExecutorPolicyRevision}, &policy, &rootTarget) != nil {
		return failure("config_mismatch")
	}
	journal, err := driver.load(plan)
	if err != nil {
		return failure("state_invalid")
	}
	if journal != nil {
		if !sameSystemdPortIntent(journal.Plan, plan) || journal.Transition.validate(plan) != nil {
			return failure("plan_conflict")
		}
		// Immutable result content (including the first observation time) is
		// preserved when the transport obtains a new lease or session.
		if journal.Result != nil {
			if journal.Result.Result == systemdPortResultRollbackFailed {
				return failure("state_invalid")
			}
			ref := portV2ResultSnapshot(plan, journal.Result.Result)
			if ref == nil || verifyPortV2Root(ctx, driver, journal, *ref) != nil {
				return failure("reconcile_required")
			}
			if journal.State != systemdPortLedgerTerminal {
				journal.State = systemdPortLedgerTerminal
				if driver.save(journal, false) != nil {
					return failure("state_unavailable")
				}
			}
			return localExecutorPortResponse(plan, *journal.Result)
		}
	}
	if journal == nil {
		if request.Operation == "port_reconfigure_reconcile" && !reflect.DeepEqual(plan.Before, plan.Target) {
			// No durable mutation intent is not proof that the CP never consumed
			// a grant. Neither an unchanged success nor a new forward is allowed.
			return failure("reconcile_required")
		}
		candidates, err := buildSystemUpdatePortPolicyCandidates(policy, plan)
		if err != nil || driver.policyStore().Verify(candidates.Before) != nil {
			return failure("config_mismatch")
		}
		journal, err = driver.prepare(ctx, policy, plan, candidates)
		if err != nil {
			return failure("mutation_precondition_failed")
		}
		if err := driver.save(journal, true); err != nil {
			return failure("state_unavailable")
		}
	}
	if reflect.DeepEqual(plan.Before, plan.Target) {
		if journal.Transition.Consumed || journal.Transition.RollbackLatched || !reflect.DeepEqual(plan.Before, plan.Rollback) {
			return failure("state_invalid")
		}
		return finishPortV2(ctx, driver, journal, plan, systemdPortResultUnchanged)
	}
	if request.Operation == "port_reconfigure_reconcile" {
		// A restart never reconstructs a monotonic forward budget. An already
		// running exact T may be observed; every new write goes only toward R.
		if !journal.Transition.RollbackLatched && journal.Transition.Consumed &&
			verifyPortV2Root(ctx, driver, journal, *plan.Target) == nil {
			return finishPortV2(ctx, driver, journal, plan, systemdPortResultApplied)
		}
		journal.Plan = plan
		if driver.consume(ctx, plan, request.Operation, journal.CurrentVersion, request.MutationGrant) != nil {
			journal.Transition.RecoveryRequired = true
			_ = driver.save(journal, false)
			return failure("reconcile_required")
		}
		// A reconcile consume is a distinct CP transition: the CP records the
		// fresh grant and fence without applying B->T a second time. Canonical
		// unconsumed B and canceled K cannot authorize this write boundary.
		journal.Transition.Consumed = true
		return rollbackPortV2(ctx, driver, journal, plan)
	}
	if request.Operation != "port_reconfigure" || journal.State != systemdPortLedgerStaged ||
		journal.Transition.Consumed || journal.Transition.RollbackLatched || journal.Transition.RecoveryRequired {
		return failure("reconcile_required")
	}
	journal.Plan = plan
	journal.State = systemdPortLedgerGrantConsuming
	if driver.save(journal, false) != nil {
		return failure("state_unavailable")
	}
	// M0 is observed immediately before sending consume. A 204 has no body
	// and cannot reveal the CP's audit timestamp.
	m0 := driver.now()
	startDeadline := portStartDeadline(m0, *request.MutationGrantV2Binding)
	if driver.consume(ctx, plan, request.Operation, journal.CurrentVersion, request.MutationGrant) != nil {
		journal.State = systemdPortLedgerAmbiguous
		journal.Transition.RecoveryRequired = true
		_ = driver.save(journal, false)
		return failure("reconcile_required")
	}
	journal.Transition.Consumed = true
	journal.State = systemdPortLedgerGrantConsumed
	if driver.save(journal, false) != nil {
		return failure("reconcile_required")
	}
	if driver.crash("after_grant_consume") != nil {
		return failure("reconcile_required")
	}
	if !driver.now().Before(startDeadline) {
		journal.Transition.RecoveryRequired = true
		_ = driver.save(journal, false)
		return failure("reconcile_required")
	}
	// Authorization may take most of the start window. Re-observe B after
	// consume so external runtime drift cannot cross the first write boundary.
	if verifyPortV2Root(ctx, driver, journal, *plan.Before) != nil {
		journal.Transition.RecoveryRequired = true
		_ = driver.save(journal, false)
		return failure("reconcile_required")
	}
	forwardCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), portPolicyForwardTimeout)
	defer cancel()
	forwardDeadline := driver.now().Add(portPolicyForwardTimeout)
	if err := applyPortV2Policy(forwardCtx, driver, journal, *plan.Target, startDeadline); err != nil {
		if errors.Is(err, errSystemdPortSimulatedCrash) {
			return failure("reconcile_required")
		}
		if errors.Is(err, errPortPolicyStartExpired) {
			journal.Transition.RecoveryRequired = true
			_ = driver.save(journal, false)
			return failure("reconcile_required")
		}
		return rollbackPortV2(ctx, driver, journal, plan)
	}
	targetPolicy, _ := decodePortPolicy(journal.Transition.TargetPolicy)
	if !driver.now().Before(forwardDeadline) || forwardCtx.Err() != nil {
		observeLocalExecutionFailure(forwardCtx, localFailureForwardBudget, context.DeadlineExceeded)
		return rollbackPortV2(ctx, driver, journal, plan)
	}
	if err := driver.write(forwardCtx, targetPolicy, *plan.Target); err != nil {
		observeLocalExecutionFailure(forwardCtx, localFailureForwardWrite, err)
		return rollbackPortV2(ctx, driver, journal, plan)
	}
	journal.State = systemdPortLedgerSidecarWritten
	if driver.save(journal, false) != nil {
		return failure("reconcile_required")
	}
	if driver.crash("after_sidecar_write") != nil {
		return failure("reconcile_required")
	}
	if !driver.now().Before(forwardDeadline) || forwardCtx.Err() != nil {
		observeLocalExecutionFailure(forwardCtx, localFailureForwardBudget, context.DeadlineExceeded)
		return rollbackPortV2(ctx, driver, journal, plan)
	}
	if err := driver.restart(forwardCtx, targetPolicy, *plan.Target); err != nil {
		observeLocalExecutionFailure(forwardCtx, localFailureForwardRestart, err)
		return rollbackPortV2(ctx, driver, journal, plan)
	}
	journal.State = systemdPortLedgerRestarted
	if driver.save(journal, false) != nil {
		return failure("reconcile_required")
	}
	if driver.crash("after_restart") != nil {
		return failure("reconcile_required")
	}
	if !driver.now().Before(forwardDeadline) || forwardCtx.Err() != nil {
		observeLocalExecutionFailure(forwardCtx, localFailureForwardBudget, context.DeadlineExceeded)
		return rollbackPortV2(ctx, driver, journal, plan)
	}
	if err := verifyPortV2Root(forwardCtx, driver, journal, *plan.Target); err != nil {
		observeLocalExecutionFailure(forwardCtx, localFailureForwardProbe, err)
		return rollbackPortV2(ctx, driver, journal, plan)
	}
	return finishPortV2(forwardCtx, driver, journal, plan, systemdPortResultApplied)
}

func portV2ResultSnapshot(plan SystemdPortReconfigurePlan, result string) *contracts.SystemUpdatePortSnapshotRef {
	switch result {
	case systemdPortResultApplied:
		return plan.Target
	case systemdPortResultUnchanged:
		return plan.Before
	case systemdPortResultRolledBack:
		return plan.Rollback
	default:
		return nil
	}
}

func portV2PolicyBytes(journal *portV2Journal, ref contracts.SystemUpdatePortSnapshotRef) []byte {
	for i, snapshot := range []*contracts.SystemUpdatePortSnapshotRef{journal.Plan.Before, journal.Plan.Target, journal.Plan.Rollback} {
		if reflect.DeepEqual(snapshot, &ref) {
			return [][]byte{journal.Transition.BeforePolicy, journal.Transition.TargetPolicy, journal.Transition.RollbackPolicy}[i]
		}
	}
	return nil
}

func verifyPortV2Root(ctx context.Context, driver portV2Driver, journal *portV2Journal, ref contracts.SystemUpdatePortSnapshotRef) error {
	payload := portV2PolicyBytes(journal, ref)
	policy, err := decodePortPolicy(payload)
	if err != nil {
		observeLocalExecutionFailure(ctx, localFailurePolicyVerify, err)
		return errors.New("port policy is not verified")
	}
	if err := driver.policyStore().Verify(payload); err != nil {
		observeLocalExecutionFailure(ctx, localFailurePolicyVerify, err)
		return errors.New("port policy is not verified")
	}
	_, err = driver.verify(ctx, policy, ref)
	return err
}

type portPolicyPhasedStore interface {
	Write(portPolicyCandidates, []byte) error
	Reload([]byte) error
}

func applyPortV2Policy(ctx context.Context, driver portV2Driver, journal *portV2Journal, ref contracts.SystemUpdatePortSnapshotRef, firstWriteDeadline time.Time) error {
	payload := portV2PolicyBytes(journal, ref)
	if len(payload) == 0 {
		observeLocalExecutionFailure(ctx, localFailurePolicySelect, nil)
		return errors.New("port policy target is not in the immutable plan")
	}
	journal.State = portPolicyWritePending
	if err := driver.save(journal, false); err != nil {
		observeLocalExecutionFailure(ctx, localFailurePolicySave, err)
		return err
	}
	if err := driver.crash("before_policy_write"); err != nil {
		return err
	}
	// Saving the latch can itself be delayed. Check at the actual first
	// privileged write boundary, using the original pre-consume M0.
	if !firstWriteDeadline.IsZero() && !driver.now().Before(firstWriteDeadline) {
		observeLocalExecutionFailure(ctx, localFailureForwardBudget, context.DeadlineExceeded)
		return errPortPolicyStartExpired
	}
	if phased, ok := driver.policyStore().(portPolicyPhasedStore); ok {
		if err := phased.Write(journal.Transition.candidates(), payload); err != nil {
			observeLocalExecutionFailure(ctx, localFailurePolicyWrite, err)
			return err
		}
		journal.State = portPolicyWritten
		if err := driver.save(journal, false); err != nil {
			observeLocalExecutionFailure(ctx, localFailurePolicySave, err)
			return err
		}
		if err := driver.crash("after_policy_write"); err != nil {
			return err
		}
		if err := phased.Reload(payload); err != nil {
			observeLocalExecutionFailure(ctx, localFailurePolicyReload, err)
			return err
		}
	} else if err := driver.policyStore().Replace(journal.Transition.candidates(), payload); err != nil {
		observeLocalExecutionFailure(ctx, localFailurePolicyWrite, err)
		return err
	}
	journal.State = portPolicyLoaded
	if err := driver.save(journal, false); err != nil {
		observeLocalExecutionFailure(ctx, localFailurePolicySave, err)
		return err
	}
	if err := driver.crash("after_policy_reload"); err != nil {
		return err
	}
	err := driver.policyStore().Verify(payload)
	if err != nil {
		observeLocalExecutionFailure(ctx, localFailurePolicyVerify, err)
	}
	return err
}

func rollbackPortV2(ctx context.Context, driver portV2Driver, journal *portV2Journal, plan SystemdPortReconfigurePlan) LocalExecutorResponse {
	failure := func(code string) LocalExecutorResponse {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, code)
	}
	journal.Transition.RollbackLatched = true
	journal.Transition.RecoveryRequired = true
	journal.State = portPolicyRollbackLatched
	if driver.save(journal, false) != nil {
		return failure("state_unavailable")
	}
	if driver.crash("after_rollback_latch") != nil {
		return failure("reconcile_required")
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), portPolicyRollbackTimeout)
	defer cancel()
	deadline := driver.now().Add(portPolicyRollbackTimeout)
	if err := applyPortV2Policy(rollbackCtx, driver, journal, *plan.Rollback, time.Time{}); err != nil {
		if errors.Is(err, errSystemdPortSimulatedCrash) {
			return failure("reconcile_required")
		}
		return failPortV2Recovery(driver, journal, plan)
	}
	rollbackPolicy, _ := decodePortPolicy(journal.Transition.RollbackPolicy)
	// Re-observation makes recovery idempotent after a response loss. It does
	// not restart or rewrite an already exact R runtime.
	if verifyPortV2Root(rollbackCtx, driver, journal, *plan.Rollback) != nil {
		if !driver.now().Before(deadline) || rollbackCtx.Err() != nil {
			return failure("reconcile_required")
		}
		if err := driver.write(rollbackCtx, rollbackPolicy, *plan.Rollback); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return failure("reconcile_required")
			}
			return failPortV2Recovery(driver, journal, plan)
		}
		if driver.crash("after_rollback_runtime_write") != nil {
			return failure("reconcile_required")
		}
		if !driver.now().Before(deadline) || rollbackCtx.Err() != nil {
			return failure("reconcile_required")
		}
		if err := driver.restart(rollbackCtx, rollbackPolicy, *plan.Rollback); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return failure("reconcile_required")
			}
			return failPortV2Recovery(driver, journal, plan)
		}
	}
	if !driver.now().Before(deadline) || rollbackCtx.Err() != nil || verifyPortV2Root(rollbackCtx, driver, journal, *plan.Rollback) != nil {
		// A missed probe or communication deadline is an unknown state, not
		// confirmation that rollback itself failed.
		return failure("reconcile_required")
	}
	return finishPortV2(rollbackCtx, driver, journal, plan, systemdPortResultRolledBack)
}

func failPortV2Recovery(driver portV2Driver, journal *portV2Journal, plan SystemdPortReconfigurePlan) LocalExecutorResponse {
	result := SystemdPortReconfigureResult{PortContractVersion: 2, DeploymentMode: plan.DeploymentMode,
		Status: "failed", Result: systemdPortResultRollbackFailed, RecoveryRequired: true,
		Message: "local recovery remains incomplete and requires the same job to reconcile",
		PortResult: &contracts.SystemUpdatePortResultV2{Result: contracts.SystemUpdatePortReconfigurationRollbackFailed,
			Observation: contracts.SystemUpdatePortObservation{ObservedAt: driver.now().UTC()}},
	}
	journal.State = portPolicyRollbackLatched
	journal.Transition.RecoveryRequired = true
	journal.Transition.LastRecoveryObservation = &result
	// A failed attempt never occupies the accepted result slot.
	journal.Result = nil
	if driver.save(journal, false) != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	return localExecutorPortResponse(plan, result)
}

func finishPortV2(ctx context.Context, driver portV2Driver, journal *portV2Journal, plan SystemdPortReconfigurePlan, kind string) LocalExecutorResponse {
	failure := func(code string) LocalExecutorResponse {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, code)
	}
	ref := portV2ResultSnapshot(plan, kind)
	if ref == nil || kind == systemdPortResultUnchanged && !reflect.DeepEqual(plan.Before, plan.Target) ||
		journal.Transition.RollbackLatched && kind != systemdPortResultRolledBack {
		return failure("state_invalid")
	}
	payload := portV2PolicyBytes(journal, *ref)
	policy, err := decodePortPolicy(payload)
	if err != nil || driver.policyStore().Verify(payload) != nil {
		return failure("reconcile_required")
	}
	instance, err := driver.verify(ctx, policy, *ref)
	if err != nil {
		return failure("reconcile_required")
	}
	result := SystemdPortReconfigureResult{PortContractVersion: 2, DeploymentMode: plan.DeploymentMode,
		Status: "succeeded", Result: kind, StateKnown: true, AppliedPort: ref.LocalListenPort,
		OldPort: plan.Before.LocalListenPort, NewPort: plan.Target.LocalListenPort,
		EndpointRevision: ref.AppliedEndpointRevision, ConfigRevision: ref.ConfigRevision, ConfigSHA256: ref.ConfigSHA256,
		Message: "local port policy and runtime are verified",
		PortResult: &contracts.SystemUpdatePortResultV2{Result: contracts.SystemUpdatePortReconfigurationResult(kind),
			ObservedSnapshotID: ref.SnapshotID, ObservedSnapshotSHA256: ref.SnapshotSHA256,
			ObservedConfigRevision: ref.ConfigRevision, ObservedConfigSHA256: ref.ConfigSHA256,
			ObservedExecutorPolicyRevision: ref.ExecutorPolicyRevision, ObservedExecutorPolicySHA256: ref.ExecutorPolicySHA256,
			Observation:     contracts.SystemUpdatePortObservation{PolicyDiskVerified: true, PolicyMemoryVerified: true, ListenerVerified: true, ObservedAt: driver.now().UTC()},
			RuntimeInstance: instance},
	}
	if kind == systemdPortResultRolledBack {
		result.Status = "rolled_back"
	}
	if journal.Result != nil {
		if !reflect.DeepEqual(journal.Result.PortResult, result.PortResult) {
			return failure("state_invalid")
		}
		result = *journal.Result
	}
	journal.Result = &result
	journal.State = systemdPortLedgerCommitting
	journal.Transition.RecoveryRequired = false
	journal.Transition.LastRecoveryObservation = nil
	if driver.save(journal, false) != nil {
		return failure("state_unavailable")
	}
	if driver.crash("after_result_save") != nil {
		return failure("reconcile_required")
	}
	journal.State = systemdPortLedgerTerminal
	if driver.save(journal, false) != nil {
		return failure("state_unavailable")
	}
	return localExecutorPortResponse(plan, result)
}

func validPortV2LedgerState(state string, transition *portPolicyTransitionState, result *SystemdPortReconfigureResult) bool {
	if transition == nil {
		return false
	}
	switch state {
	case systemdPortLedgerStaged, systemdPortLedgerGrantConsuming, systemdPortLedgerGrantConsumed,
		portPolicyWritePending, portPolicyWritten, portPolicyLoaded, portPolicyRollbackLatched,
		systemdPortLedgerSidecarWritten, systemdPortLedgerRestarted, systemdPortLedgerAmbiguous:
		return result == nil
	case systemdPortLedgerCommitting, systemdPortLedgerTerminal:
		return result != nil && result.Validate() == nil && result.Result != systemdPortResultRollbackFailed && !transition.RecoveryRequired
	default:
		return false
	}
}

func portV2SnapshotPayloadMatches(payload []byte, ref contracts.SystemUpdatePortSnapshotRef) bool {
	return len(payload) > 0 && len(payload) <= 64<<10 && systemdPortSidecarSHA256(payload) == ref.ConfigSHA256
}

func portV2RuntimeBytesAllowed(current []byte, before, target, rollback []byte) bool {
	return bytes.Equal(current, before) || bytes.Equal(current, target) || bytes.Equal(current, rollback)
}
