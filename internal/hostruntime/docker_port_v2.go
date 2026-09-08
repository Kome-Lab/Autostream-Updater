package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

type portV2DockerCheckpoint interface {
	PortCheckpoint() (dockerPortMappingCheckpoint, error)
}
type dockerPortV2Driver struct {
	runtime dockerPortRuntime
	state   dockerPortStateStore
	store   portPolicyStore
	clock   func() time.Time
	ledger  *dockerPortLedger
	adapter dockerPortAdapter
}

func executeDockerPortV2Request(ctx context.Context, policy LocalExecutorPolicy, request LocalExecutorRequest, runtime dockerPortRuntime, state dockerPortStateStore) LocalExecutorResponse {
	driver := &dockerPortV2Driver{runtime: runtime, state: state, store: portPolicyFromContext(ctx), clock: time.Now}
	if environment, ok := runtime.(portV2RuntimeEnvironment); ok {
		driver.store, driver.clock = environment.PortPolicyStore(), environment.PortNow
	}
	if request.PortPlan == nil || runtime == nil || state == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	target, ok := policy.Target(request.PortPlan.TargetID)
	if !ok || target.Docker == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "config_mismatch")
	}
	driver.adapter = adapter
	return executePortV2(ctx, policy, request, driver)
}

func (d *dockerPortV2Driver) load(plan SystemdPortReconfigurePlan) (*portV2Journal, error) {
	active, err := d.state.LoadActive(plan.TargetID)
	if err != nil {
		return nil, err
	}
	if active != nil && active.Plan.JobID != plan.JobID && active.State != dockerPortLedgerTerminal {
		return nil, errors.New("Docker port target has an unfinished transaction")
	}
	ledger, err := d.state.LoadJob(plan.TargetID, plan.JobID)
	if err != nil || ledger == nil {
		return nil, err
	}
	if ledger.validatePortV2(plan.TargetID) != nil {
		return nil, errors.New("saved versioned Docker port ledger is invalid")
	}
	d.ledger = ledger
	return &portV2Journal{Plan: ledger.Plan, State: ledger.State, Transition: ledger.PolicyTransition, Result: ledger.Result, CurrentVersion: ledger.Baseline.CurrentVersion}, nil
}

func (d *dockerPortV2Driver) prepare(ctx context.Context, policy LocalExecutorPolicy, plan SystemdPortReconfigurePlan, candidates portPolicyCandidates) (*portV2Journal, error) {
	target, ok := policy.Target(plan.TargetID)
	if !ok {
		observeLocalExecutionFailure(ctx, localFailureDockerPrepareTarget, nil)
		return nil, errors.New("Docker port target is missing")
	}
	// Existing applied overlays carry the verified resolved Compose hash.
	// The immutable policy retains its non-port canonical profile authority.
	target, err := resolveDockerPortAppliedTarget(policy, target, d.state)
	if err != nil {
		observeLocalExecutionFailure(ctx, localFailureDockerPrepareApplied, err)
		return nil, err
	}
	before, err := d.runtime.Observe(ctx, policy, target)
	if err != nil || before.validate() != nil || !dockerPortV2ObservationMatches(before, *plan.Before) ||
		before.Runtime.ContainerID != plan.DockerBaseline.ExpectedContainerID ||
		before.Runtime.ImageID != plan.DockerBaseline.ExpectedImageID ||
		before.Runtime.RepositoryDigest != plan.DockerBaseline.ExpectedRepositoryDigest ||
		before.Runtime.VersionEnvSHA256 != plan.DockerBaseline.ExpectedVersionEnvSHA256 ||
		before.ComposeConfigSHA256 != plan.DockerBaseline.ApprovedComposeConfigSHA256 {
		phase := localFailureDockerPrepareObserve
		if err == nil {
			switch {
			case before.validate() != nil:
				phase = localFailureDockerPrepareObservation
			case !dockerPortV2ObservationMatches(before, *plan.Before):
				phase = localFailureDockerPrepareSnapshot
			case before.Runtime.ContainerID != plan.DockerBaseline.ExpectedContainerID:
				phase = localFailureDockerPrepareContainer
			case before.Runtime.ImageID != plan.DockerBaseline.ExpectedImageID:
				phase = localFailureDockerPrepareImage
			case before.Runtime.RepositoryDigest != plan.DockerBaseline.ExpectedRepositoryDigest:
				phase = localFailureDockerPrepareRepository
			case before.Runtime.VersionEnvSHA256 != plan.DockerBaseline.ExpectedVersionEnvSHA256:
				phase = localFailureDockerPrepareVersionEnv
			default:
				phase = localFailureDockerPrepareCompose
			}
		}
		observeLocalExecutionFailure(ctx, phase, err)
		return nil, errors.New("Docker runtime baseline does not match the immutable plan")
	}
	targetBytes, err := dockerPortEnvBytes(d.adapter, plan.Target.Docker.PublishedPort, plan.Target.Docker.ContainerPort, plan.Target.ConfigRevision)
	if err != nil {
		observeLocalExecutionFailure(ctx, localFailureDockerPrepareTargetPayload, err)
		return nil, err
	}
	rollbackBytes, err := dockerPortEnvBytes(d.adapter, plan.Rollback.Docker.PublishedPort, plan.Rollback.Docker.ContainerPort, plan.Rollback.ConfigRevision)
	if err != nil || !portV2SnapshotPayloadMatches(targetBytes, *plan.Target) || !portV2SnapshotPayloadMatches(rollbackBytes, *plan.Rollback) {
		phase := localFailureDockerPrepareRollbackPayload
		if err == nil && !portV2SnapshotPayloadMatches(targetBytes, *plan.Target) {
			phase = localFailureDockerPrepareTargetPayload
		}
		observeLocalExecutionFailure(ctx, phase, err)
		return nil, errors.New("Docker port candidate payload mismatch")
	}
	targetPolicy, _ := decodePortPolicy(candidates.Target)
	targetCandidate, _ := targetPolicy.Target(plan.TargetID)
	prepared, err := d.runtime.Prepare(ctx, targetCandidate, targetBytes)
	if err != nil || !dockerPortV2PreparedMatches(prepared, *plan.Target) {
		observeLocalExecutionFailure(ctx, localFailureDockerPrepareTargetModel, err)
		return nil, errors.New("Docker target canonical model mismatch")
	}
	rollbackPolicy, _ := decodePortPolicy(candidates.Rollback)
	rollbackTarget, _ := rollbackPolicy.Target(plan.TargetID)
	rollbackPrepared, err := d.runtime.Prepare(ctx, rollbackTarget, rollbackBytes)
	if err != nil || !dockerPortV2PreparedMatches(rollbackPrepared, *plan.Rollback) {
		observeLocalExecutionFailure(ctx, localFailureDockerPrepareRollbackModel, err)
		return nil, errors.New("Docker rollback canonical model mismatch")
	}
	if !reflect.DeepEqual(plan.Before, plan.Target) {
		if err := d.runtime.EnsureAvailable(ctx, target, prepared, before.Runtime.ContainerID); err != nil {
			observeLocalExecutionFailure(ctx, localFailureDockerPrepareAvailability, err)
			return nil, err
		}
	}
	transition := &portPolicyTransitionState{Version: 1, BeforePolicy: candidates.Before, TargetPolicy: candidates.Target,
		RollbackPolicy: candidates.Rollback, RollbackRuntimeBytes: rollbackBytes, RollbackComposeSHA256: rollbackPrepared.ComposeConfigSHA256}
	d.ledger = &dockerPortLedger{SchemaVersion: 2, Plan: plan, State: systemdPortLedgerStaged, Checkpoint: before.MappingEnv,
		TargetBytes: targetBytes, Baseline: before.Runtime, OldComposeSHA256: before.ComposeConfigSHA256,
		TargetComposeSHA256: prepared.ComposeConfigSHA256, PolicyTransition: transition}
	return &portV2Journal{Plan: plan, State: systemdPortLedgerStaged, Transition: transition, CurrentVersion: before.Runtime.CurrentVersion}, nil
}

func (d *dockerPortV2Driver) save(j *portV2Journal, stage bool) error {
	if d.ledger == nil {
		return errors.New("Docker port ledger is missing")
	}
	previous, err := d.state.LoadJob(j.Plan.TargetID, j.Plan.JobID)
	if err != nil {
		return err
	}
	if previous != nil && previous.Result != nil && (j.Result == nil || !reflect.DeepEqual(previous.Result, j.Result)) {
		return errors.New("accepted Docker port result is immutable")
	}
	d.ledger.Plan, d.ledger.State, d.ledger.PolicyTransition, d.ledger.Result = j.Plan, j.State, j.Transition, j.Result
	if stage {
		err = d.state.Stage(*d.ledger)
	} else {
		err = d.state.Save(*d.ledger)
	}
	if err != nil || j.Result == nil {
		return err
	}
	ref := portV2ResultSnapshot(j.Plan, j.Result.Result)
	if ref == nil || ref.Docker == nil {
		return errors.New("Docker accepted result snapshot is invalid")
	}
	return d.state.SaveApplied(dockerPortAppliedState{PortContractVersion: 2, PortJobID: j.Plan.JobID, SchemaVersion: 1, TargetID: j.Plan.TargetID, ServiceType: j.Plan.ServiceType,
		PublishedPort: ref.Docker.PublishedPort, ContainerPort: ref.Docker.ContainerPort, HealthPort: ref.Docker.HealthPort,
		EndpointRevision: ref.AppliedEndpointRevision, ConfigRevision: ref.ConfigRevision, ConfigSHA256: ref.ConfigSHA256,
		ComposeConfigSHA256: d.composeHash(*ref), SourcePolicyRevision: ref.SourcePolicyRevision,
		UpdaterPolicyRevision: ref.ProjectionRevision, ExecutorPolicyRevision: ref.ExecutorPolicyRevision,
		ExecutorPolicySHA256: ref.ExecutorPolicySHA256, OwnershipEpoch: j.Plan.OwnershipEpoch})
}

func (d *dockerPortV2Driver) composeHash(ref contracts.SystemUpdatePortSnapshotRef) string {
	if reflect.DeepEqual(d.ledger.Plan.Before, &ref) {
		return d.ledger.OldComposeSHA256
	}
	if reflect.DeepEqual(d.ledger.Plan.Target, &ref) {
		return d.ledger.TargetComposeSHA256
	}
	if reflect.DeepEqual(d.ledger.Plan.Rollback, &ref) {
		return d.ledger.PolicyTransition.RollbackComposeSHA256
	}
	return ""
}

func (d *dockerPortV2Driver) effectiveTarget(policy LocalExecutorPolicy, ref contracts.SystemUpdatePortSnapshotRef) (LocalExecutorTarget, error) {
	target, ok := policy.Target(d.ledger.Plan.TargetID)
	if !ok || target.Docker == nil || !portPolicySnapshotMatches(policy, target, ref) {
		return LocalExecutorTarget{}, errors.New("Docker port effective target mismatch")
	}
	docker := *target.Docker
	docker.ComposeConfigSHA256 = d.composeHash(ref)
	if !mutationPlanHashPattern.MatchString(docker.ComposeConfigSHA256) {
		return LocalExecutorTarget{}, errors.New("Docker resolved model digest is missing")
	}
	target.Docker = &docker
	return target, nil
}

func (d *dockerPortV2Driver) verify(ctx context.Context, policy LocalExecutorPolicy, ref contracts.SystemUpdatePortSnapshotRef) (*contracts.SystemUpdatePortRuntimeInstance, error) {
	target, err := d.effectiveTarget(policy, ref)
	if err != nil {
		return nil, err
	}
	observed, err := d.runtime.Observe(ctx, policy, target)
	if err != nil || observed.validate() != nil || !dockerPortV2ObservationMatches(observed, ref) ||
		observed.ComposeConfigSHA256 != d.composeHash(ref) || observed.Runtime.CurrentVersion != d.ledger.Baseline.CurrentVersion ||
		observed.Runtime.VersionEnvSHA256 != d.ledger.Baseline.VersionEnvSHA256 || observed.Runtime.ImageID != d.ledger.Baseline.ImageID ||
		observed.Runtime.RepositoryDigest != d.ledger.Baseline.RepositoryDigest ||
		reflect.DeepEqual(d.ledger.Plan.Before, &ref) && observed.Runtime.ContainerID != d.ledger.Baseline.ContainerID {
		return nil, errors.New("Docker port mapping, image or runtime identity is not verified")
	}
	return &contracts.SystemUpdatePortRuntimeInstance{ContainerID: observed.Runtime.ContainerID, ImageID: observed.Runtime.ImageID, RepositoryDigest: observed.Runtime.RepositoryDigest}, nil
}

func (d *dockerPortV2Driver) write(ctx context.Context, policy LocalExecutorPolicy, ref contracts.SystemUpdatePortSnapshotRef) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	checkpointRuntime, ok := d.runtime.(portV2DockerCheckpoint)
	if !ok {
		return errors.New("Docker port checkpoint capability is unavailable")
	}
	current, err := checkpointRuntime.PortCheckpoint()
	if err != nil || current.validate() != nil || !current.Existed || current.Mode != 0o600 ||
		!portV2RuntimeBytesAllowed(current.Bytes, d.ledger.Checkpoint.Bytes, d.ledger.TargetBytes, d.ledger.PolicyTransition.RollbackRuntimeBytes) {
		return errors.New("Docker port runtime is outside the saved B/T/R payloads")
	}
	payload, err := dockerPortEnvBytes(d.adapter, ref.Docker.PublishedPort, ref.Docker.ContainerPort, ref.ConfigRevision)
	if err != nil || !portV2SnapshotPayloadMatches(payload, ref) {
		return errors.New("Docker port payload mismatch")
	}
	if bytes.Equal(current.Bytes, payload) {
		return nil
	}
	return d.runtime.Write(current, payload)
}

func (d *dockerPortV2Driver) restart(ctx context.Context, policy LocalExecutorPolicy, ref contracts.SystemUpdatePortSnapshotRef) error {
	target, err := d.effectiveTarget(policy, ref)
	if err != nil {
		return err
	}
	payload, err := dockerPortEnvBytes(d.adapter, ref.Docker.PublishedPort, ref.Docker.ContainerPort, ref.ConfigRevision)
	if err != nil {
		return err
	}
	prepared, err := d.runtime.Prepare(ctx, target, payload)
	if err != nil || !dockerPortV2PreparedMatches(prepared, ref) || prepared.ComposeConfigSHA256 != d.composeHash(ref) {
		return errors.New("Docker port prepared model changed during recovery")
	}
	return d.runtime.Recreate(ctx, target, prepared)
}
func (d *dockerPortV2Driver) consume(ctx context.Context, plan SystemdPortReconfigurePlan, operation, version string, grant BoundedSecret) error {
	return d.runtime.ConsumeGrant(ctx, plan, operation, version, grant)
}
func (d *dockerPortV2Driver) crash(phase string) error     { return d.runtime.CrashPoint(phase) }
func (d *dockerPortV2Driver) now() time.Time               { return d.clock() }
func (d *dockerPortV2Driver) policyStore() portPolicyStore { return d.store }

func dockerPortV2ObservationMatches(observed dockerPortObservation, ref contracts.SystemUpdatePortSnapshotRef) bool {
	return ref.Docker != nil && observed.PublishedHostIP == ref.Docker.PublishedHostIP && observed.PublishedPort == ref.Docker.PublishedPort &&
		observed.ContainerPort == ref.Docker.ContainerPort && observed.HealthPort == ref.Docker.HealthPort &&
		observed.ConfigRevision == ref.ConfigRevision && observed.ConfigSHA256 == ref.ConfigSHA256 &&
		observed.ComposePolicySHA256 == strings.TrimPrefix(ref.Docker.ComposePolicySHA256, "sha256:")
}
func dockerPortV2PreparedMatches(prepared dockerPortPreparedModel, ref contracts.SystemUpdatePortSnapshotRef) bool {
	return prepared.validate() == nil && ref.Docker != nil && prepared.PublishedHostIP == ref.Docker.PublishedHostIP &&
		prepared.PublishedPort == ref.Docker.PublishedPort && prepared.ContainerPort == ref.Docker.ContainerPort &&
		prepared.HealthPort == ref.Docker.HealthPort && prepared.ComposePolicySHA256 == strings.TrimPrefix(ref.Docker.ComposePolicySHA256, "sha256:")
}

func (l dockerPortLedger) validatePortV2(targetID string) error {
	if l.SchemaVersion != 2 || l.Plan.TargetID != targetID || l.Plan.DeploymentMode != ModeDocker || l.Plan.Validate() != nil ||
		l.Checkpoint.validate() != nil || !l.Checkpoint.Existed || l.Checkpoint.Mode != 0o600 || l.Baseline.validate() != nil ||
		l.Checkpoint.SHA256 != l.Plan.Before.ConfigSHA256 || !portV2SnapshotPayloadMatches(l.TargetBytes, *l.Plan.Target) ||
		!mutationPlanHashPattern.MatchString(l.OldComposeSHA256) || !mutationPlanHashPattern.MatchString(l.TargetComposeSHA256) ||
		l.PolicyTransition.validate(l.Plan) != nil || !mutationPlanHashPattern.MatchString(l.PolicyTransition.RollbackComposeSHA256) ||
		!validPortV2LedgerState(l.State, l.PolicyTransition, l.Result) {
		return errors.New("versioned Docker port ledger is invalid")
	}
	if l.Result != nil && !portV2AcceptedResultMatchesPlan(l.Plan, *l.Result) {
		return errors.New("accepted Docker port result snapshot mismatch")
	}
	return nil
}

func loadDockerPortV2AppliedJob(state dockerPortAppliedStateReader, targetID, jobID string) (*dockerPortLedger, error) {
	if store, ok := state.(interface {
		LoadJob(string, string) (*dockerPortLedger, error)
	}); ok {
		return store.LoadJob(targetID, jobID)
	}
	if combined, ok := state.(localExecutorAppliedPortState); ok {
		return loadDockerPortV2AppliedJob(combined.docker, targetID, jobID)
	}
	return nil, errors.New("Docker port applied transaction authority is unavailable")
}

func validateDockerPortV2AppliedAuthority(policy LocalExecutorPolicy, target LocalExecutorTarget, applied dockerPortAppliedState, state dockerPortAppliedStateReader) (bool, error) {
	if applied.validateRecord(target) != nil || policy.Validate() != nil {
		return false, errors.New("Docker applied port record is invalid")
	}
	if applied.matchesTarget(target) {
		return false, nil
	}
	ledger, err := loadDockerPortV2AppliedJob(state, target.ServiceID, applied.PortJobID)
	if err != nil || ledger == nil || ledger.validatePortV2(target.ServiceID) != nil || ledger.Result == nil ||
		ledger.Plan.HostID != policy.HostID {
		return false, errors.New("Docker applied port result is not verified")
	}
	ref := portV2ResultSnapshot(ledger.Plan, ledger.Result.Result)
	if ref == nil || ref.Docker == nil {
		return false, errors.New("Docker applied port result has no snapshot")
	}
	driver := dockerPortV2Driver{ledger: ledger}
	journal := &portV2Journal{Plan: ledger.Plan, Transition: ledger.PolicyTransition}
	savedPolicy, err := decodePortPolicy(portV2PolicyBytes(journal, *ref))
	savedTarget, ok := savedPolicy.Target(target.ServiceID)
	// Other target transitions may advance the host's S/P/X. An overlay can
	// survive only when this entire privileged target remains byte-equivalent
	// to its verified saved snapshot; a changed profile is never inherited.
	if err != nil || !ok || !reflect.DeepEqual(savedTarget, target) ||
		applied.SourcePolicyRevision != ref.SourcePolicyRevision || applied.UpdaterPolicyRevision != ref.ProjectionRevision ||
		applied.ExecutorPolicyRevision != ref.ExecutorPolicyRevision || applied.ExecutorPolicySHA256 != ref.ExecutorPolicySHA256 ||
		applied.PublishedPort != ref.Docker.PublishedPort || applied.ContainerPort != ref.Docker.ContainerPort || applied.HealthPort != ref.Docker.HealthPort ||
		applied.EndpointRevision != ref.AppliedEndpointRevision || applied.ConfigRevision != ref.ConfigRevision || applied.ConfigSHA256 != ref.ConfigSHA256 ||
		applied.ComposeConfigSHA256 != driver.composeHash(*ref) || applied.OwnershipEpoch != ledger.Plan.OwnershipEpoch {
		return false, errors.New("Docker applied port snapshot or canonical profile changed")
	}
	return true, nil
}

func localExecutorSoftwareRuntimeTarget(policy LocalExecutorPolicy, rootTarget LocalExecutorTarget, state dockerPortAppliedStateReader) (Target, error) {
	installed, ok := policy.Target(rootTarget.ServiceID)
	if policy.Validate() != nil || !ok || !reflect.DeepEqual(installed, rootTarget) {
		return Target{}, errors.New("software runtime target differs from installed root policy")
	}
	if rootTarget.DeploymentMode != ModeDocker {
		return rootTarget.runtimeTarget(policy.HostID), nil
	}
	if state == nil {
		return Target{}, errors.New("Docker port state is unavailable")
	}
	applied, err := state.LoadDockerApplied(rootTarget.ServiceID)
	if err != nil {
		return Target{}, err
	}
	if applied == nil || applied.PortContractVersion != 2 {
		// Legacy root software behavior is unchanged. Versioned port jobs are
		// the only source of the new immutable accepted-result authority.
		return rootTarget.runtimeTarget(policy.HostID), nil
	}
	effective, err := resolveDockerPortAppliedTarget(policy, rootTarget, state)
	if err != nil {
		return Target{}, err
	}
	return effective.runtimeTarget(policy.HostID), nil
}
