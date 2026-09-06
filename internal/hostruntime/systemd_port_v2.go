package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

type portV2RuntimeEnvironment interface {
	PortPolicyStore() portPolicyStore
	PortNow() time.Time
}

type systemdPortV2Driver struct {
	runtime systemdPortRuntime
	state   systemdPortStateStore
	store   portPolicyStore
	clock   func() time.Time
	ledger  *systemdPortLedger
	adapter systemdPortAdapter
}

func executeSystemdPortV2Request(ctx context.Context, policy LocalExecutorPolicy, request LocalExecutorRequest, runtime systemdPortRuntime, state systemdPortStateStore) LocalExecutorResponse {
	driver := &systemdPortV2Driver{runtime: runtime, state: state, store: portPolicyFromContext(ctx), clock: time.Now}
	if environment, ok := runtime.(portV2RuntimeEnvironment); ok {
		driver.store, driver.clock = environment.PortPolicyStore(), environment.PortNow
	}
	if request.PortPlan == nil || state == nil || runtime == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	target, ok := policy.Target(request.PortPlan.TargetID)
	if !ok || target.Systemd == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}
	adapter, err := systemdPortAdapterFor(target.ServiceType, target.Systemd.Unit)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}
	driver.adapter = adapter
	return executePortV2(ctx, policy, request, driver)
}

func (d *systemdPortV2Driver) load(plan SystemdPortReconfigurePlan) (*portV2Journal, error) {
	active, err := d.state.LoadActive(plan.TargetID)
	if err != nil {
		return nil, err
	}
	if active != nil && active.Plan.JobID != plan.JobID && active.State != systemdPortLedgerTerminal {
		return nil, errors.New("port target has an unfinished transaction")
	}
	ledger, err := d.state.LoadJob(plan.TargetID, plan.JobID)
	if err != nil || ledger == nil {
		return nil, err
	}
	if ledger.validatePortV2(plan.TargetID) != nil {
		return nil, errors.New("saved versioned port ledger is invalid")
	}
	d.ledger = ledger
	return &portV2Journal{Plan: ledger.Plan, State: ledger.State, Transition: ledger.PolicyTransition, Result: ledger.Result, CurrentVersion: ledger.CurrentVersion}, nil
}

func (d *systemdPortV2Driver) prepare(ctx context.Context, policy LocalExecutorPolicy, plan SystemdPortReconfigurePlan, candidates portPolicyCandidates) (*portV2Journal, error) {
	target, ok := policy.Target(plan.TargetID)
	if !ok {
		return nil, errors.New("port target is missing")
	}
	checkpoint, err := d.runtime.Checkpoint(d.adapter)
	beforeBytes := systemdPortSidecarBytes(plan.ServiceType, target.LocalListen.Host, plan.Before.LocalListenPort, plan.Before.ConfigRevision)
	if err != nil || checkpoint.validate() != nil || !checkpoint.Existed || checkpoint.Mode != 0o600 ||
		checkpoint.SHA256 != plan.Before.ConfigSHA256 || !bytes.Equal(checkpoint.Bytes, beforeBytes) {
		return nil, errors.New("port runtime baseline does not match B")
	}
	version, err := d.runtime.Verify(ctx, policy, target)
	if err != nil || !versionPattern.MatchString(version) {
		return nil, errors.New("port runtime baseline is unverified")
	}
	if plan.Before.LocalListenPort != plan.Target.LocalListenPort {
		endpoint := target.LocalListen
		endpoint.Port = plan.Target.LocalListenPort
		if err := d.runtime.EnsurePortAvailable(endpoint); err != nil {
			return nil, err
		}
	}
	targetBytes := systemdPortSidecarBytes(plan.ServiceType, target.LocalListen.Host, plan.Target.LocalListenPort, plan.Target.ConfigRevision)
	rollbackBytes := systemdPortSidecarBytes(plan.ServiceType, target.LocalListen.Host, plan.Rollback.LocalListenPort, plan.Rollback.ConfigRevision)
	if !portV2SnapshotPayloadMatches(targetBytes, *plan.Target) || !portV2SnapshotPayloadMatches(rollbackBytes, *plan.Rollback) {
		return nil, errors.New("port runtime candidate digest mismatch")
	}
	transition := &portPolicyTransitionState{Version: 1, BeforePolicy: candidates.Before, TargetPolicy: candidates.Target,
		RollbackPolicy: candidates.Rollback, RollbackRuntimeBytes: rollbackBytes}
	d.ledger = &systemdPortLedger{SchemaVersion: 2, Plan: plan, State: systemdPortLedgerStaged, Checkpoint: checkpoint,
		TargetBytes: targetBytes, CurrentVersion: version, PolicyTransition: transition}
	return &portV2Journal{Plan: plan, State: systemdPortLedgerStaged, Transition: transition, CurrentVersion: version}, nil
}

func (d *systemdPortV2Driver) save(j *portV2Journal, stage bool) error {
	if d.ledger == nil {
		return errors.New("port runtime ledger is missing")
	}
	previous, err := d.state.LoadJob(j.Plan.TargetID, j.Plan.JobID)
	if err != nil {
		return err
	}
	if previous != nil && previous.Result != nil && (j.Result == nil || !reflect.DeepEqual(previous.Result, j.Result)) {
		return errors.New("accepted port result is immutable")
	}
	d.ledger.Plan, d.ledger.State, d.ledger.PolicyTransition, d.ledger.Result = j.Plan, j.State, j.Transition, j.Result
	if stage {
		err = d.state.Stage(*d.ledger)
	} else {
		err = d.state.Save(*d.ledger)
	}
	if err != nil {
		return err
	}
	if j.Result != nil {
		return d.state.SaveApplied(systemdPortAppliedStateForResult(j.Plan, *j.Result))
	}
	return nil
}

func (d *systemdPortV2Driver) verify(ctx context.Context, policy LocalExecutorPolicy, ref contracts.SystemUpdatePortSnapshotRef) (*contracts.SystemUpdatePortRuntimeInstance, error) {
	if d.ledger == nil {
		return nil, errors.New("port ledger is missing")
	}
	target, ok := policy.Target(d.ledger.Plan.TargetID)
	if !ok || !portPolicySnapshotMatches(policy, target, ref) {
		return nil, errors.New("port runtime policy mismatch")
	}
	checkpoint, err := d.runtime.Checkpoint(d.adapter)
	expected := systemdPortSidecarBytes(target.ServiceType, target.LocalListen.Host, ref.LocalListenPort, ref.ConfigRevision)
	if err != nil || checkpoint.validate() != nil || !checkpoint.Existed || checkpoint.Mode != 0o600 ||
		checkpoint.SHA256 != ref.ConfigSHA256 || !bytes.Equal(checkpoint.Bytes, expected) {
		return nil, errors.New("port runtime config is not verified")
	}
	version, err := d.runtime.Verify(ctx, policy, target)
	if err != nil || version != d.ledger.CurrentVersion {
		return nil, errors.New("port runtime version or listener is not verified")
	}
	return nil, nil
}

func (d *systemdPortV2Driver) write(ctx context.Context, policy LocalExecutorPolicy, ref contracts.SystemUpdatePortSnapshotRef) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	current, err := d.runtime.Checkpoint(d.adapter)
	if err != nil || current.validate() != nil || !current.Existed || current.Mode != 0o600 ||
		!portV2RuntimeBytesAllowed(current.Bytes, d.ledger.Checkpoint.Bytes, d.ledger.TargetBytes, d.ledger.PolicyTransition.RollbackRuntimeBytes) {
		return errors.New("port runtime is outside its saved B/T/R payloads")
	}
	target, ok := policy.Target(d.ledger.Plan.TargetID)
	if !ok {
		return errors.New("port runtime target is missing")
	}
	payload := systemdPortSidecarBytes(target.ServiceType, target.LocalListen.Host, ref.LocalListenPort, ref.ConfigRevision)
	if !portV2SnapshotPayloadMatches(payload, ref) {
		return errors.New("port runtime payload mismatch")
	}
	if bytes.Equal(current.Bytes, payload) {
		return nil
	}
	return d.runtime.Write(d.adapter, current, payload)
}

func (d *systemdPortV2Driver) restart(ctx context.Context, policy LocalExecutorPolicy, ref contracts.SystemUpdatePortSnapshotRef) error {
	target, ok := policy.Target(d.ledger.Plan.TargetID)
	if !ok || !portPolicySnapshotMatches(policy, target, ref) {
		return errors.New("port restart target mismatch")
	}
	return d.runtime.Restart(ctx, target)
}
func (d *systemdPortV2Driver) consume(ctx context.Context, plan SystemdPortReconfigurePlan, operation, version string, grant BoundedSecret) error {
	return d.runtime.ConsumeGrant(ctx, plan, operation, version, grant)
}
func (d *systemdPortV2Driver) crash(phase string) error     { return d.runtime.CrashPoint(phase) }
func (d *systemdPortV2Driver) now() time.Time               { return d.clock() }
func (d *systemdPortV2Driver) policyStore() portPolicyStore { return d.store }

func (l systemdPortLedger) validatePortV2(targetID string) error {
	if l.SchemaVersion != 2 || l.Plan.TargetID != targetID || l.Plan.DeploymentMode != ModeSystemd || l.Plan.Validate() != nil ||
		l.Checkpoint.validate() != nil || !l.Checkpoint.Existed || l.Checkpoint.Mode != 0o600 ||
		l.Checkpoint.SHA256 != l.Plan.Before.ConfigSHA256 || !portV2SnapshotPayloadMatches(l.TargetBytes, *l.Plan.Target) ||
		!versionPattern.MatchString(l.CurrentVersion) || l.PolicyTransition.validate(l.Plan) != nil ||
		!validPortV2LedgerState(l.State, l.PolicyTransition, l.Result) {
		return errors.New("versioned systemd port ledger is invalid")
	}
	if l.Result != nil && !portV2AcceptedResultMatchesPlan(l.Plan, *l.Result) {
		return errors.New("accepted systemd port result snapshot mismatch")
	}
	return nil
}

func portV2AcceptedResultMatchesPlan(plan SystemdPortReconfigurePlan, result SystemdPortReconfigureResult) bool {
	if result.PortResult == nil || result.Result == systemdPortResultRollbackFailed {
		return false
	}
	proof := *result.PortResult
	// Root verifies its own boundaries. The shared final validator is used
	// after projecting the Agent's separately required proof bit.
	proof.Observation.AgentProjectionVerified = true
	return contracts.ValidateSystemUpdatePortResult(plan.SharedPortPlan(), proof) == nil
}

func validatePortV2Startup(policy LocalExecutorPolicy, systemdState systemdPortStateStore, dockerState dockerPortStateStore) error {
	for _, target := range policy.Targets {
		var transition *portPolicyTransitionState
		var plan SystemdPortReconfigurePlan
		if target.DeploymentMode == ModeSystemd {
			ledger, err := systemdState.LoadActive(target.ServiceID)
			if err != nil {
				return err
			}
			if ledger == nil || ledger.Plan.PortContractVersion != 2 || ledger.State == systemdPortLedgerTerminal {
				continue
			}
			transition, plan = ledger.PolicyTransition, ledger.Plan
		} else if target.DeploymentMode == ModeDocker {
			ledger, err := dockerState.LoadActive(target.ServiceID)
			if err != nil {
				return err
			}
			if ledger == nil || ledger.Plan.PortContractVersion != 2 || ledger.State == dockerPortLedgerTerminal {
				continue
			}
			transition, plan = ledger.PolicyTransition, ledger.Plan
		} else {
			continue
		}
		if transition.validate(plan) != nil {
			return errors.New("port recovery ledger is invalid at executor startup")
		}
		if !portPolicySnapshotMatches(policy, target, *plan.Before) && !portPolicySnapshotMatches(policy, target, *plan.Target) && !portPolicySnapshotMatches(policy, target, *plan.Rollback) {
			return errors.New("installed policy is outside the saved port recovery transaction")
		}
	}
	return nil
}

func portV2HostLaneAllows(policy LocalExecutorPolicy, request LocalExecutorRequest, systemdState systemdPortStateStore, dockerState dockerPortStateStore) bool {
	for _, target := range policy.Targets {
		var plan *SystemdPortReconfigurePlan
		if target.DeploymentMode == ModeSystemd {
			ledger, err := systemdState.LoadActive(target.ServiceID)
			if err != nil {
				return false
			}
			if ledger != nil && ledger.Plan.PortContractVersion == 2 && ledger.State != systemdPortLedgerTerminal {
				plan = &ledger.Plan
			}
		} else if target.DeploymentMode == ModeDocker {
			ledger, err := dockerState.LoadActive(target.ServiceID)
			if err != nil {
				return false
			}
			if ledger != nil && ledger.Plan.PortContractVersion == 2 && ledger.State != dockerPortLedgerTerminal {
				plan = &ledger.Plan
			}
		}
		if plan != nil && (request.PortPlan == nil || request.PortPlan.JobID != plan.JobID ||
			!sameSystemdPortIntent(*plan, *request.PortPlan) || request.Operation != "port_reconfigure_reconcile" && request.Operation != "port_reconfigure") {
			return false
		}
	}
	return true
}
