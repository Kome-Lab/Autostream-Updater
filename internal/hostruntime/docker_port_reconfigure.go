package hostruntime

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"sync"
)

const (
	dockerPortCapabilityVersion = "v1"

	dockerPortLedgerStaged         = "staged"
	dockerPortLedgerGrantConsuming = "grant_consuming"
	dockerPortLedgerGrantConsumed  = "grant_consumed"
	dockerPortLedgerEnvWritten     = "env_written"
	dockerPortLedgerRecreated      = "recreated"
	dockerPortLedgerAmbiguous      = "ambiguous"
	dockerPortLedgerCommitting     = "committing"
	dockerPortLedgerTerminal       = "terminal"
)

type dockerPortMappingCheckpoint struct {
	Existed bool   `json:"existed"`
	Mode    uint32 `json:"mode"`
	Bytes   []byte `json:"bytes,omitempty"`
	SHA256  string `json:"sha256"`
}

func newDockerPortMappingCheckpoint(
	existed bool,
	mode uint32,
	body []byte,
) dockerPortMappingCheckpoint {
	if !existed {
		mode = 0
		body = nil
	}
	return dockerPortMappingCheckpoint{
		Existed: existed, Mode: mode, Bytes: append([]byte(nil), body...),
		SHA256: dockerPortEnvSHA256(body),
	}
}

func (c dockerPortMappingCheckpoint) validate() error {
	if c.SHA256 != dockerPortEnvSHA256(c.Bytes) {
		return errors.New("Docker port mapping checkpoint digest is invalid")
	}
	if !c.Existed {
		if c.Mode != 0 || len(c.Bytes) != 0 {
			return errors.New("absent Docker port mapping checkpoint is invalid")
		}
		return nil
	}
	if c.Mode != 0o600 || len(c.Bytes) == 0 || len(c.Bytes) > 64<<10 {
		return errors.New("Docker port mapping checkpoint is not a private bounded file")
	}
	return nil
}

type dockerPortRuntimeBaseline struct {
	VersionEnvSHA256 string `json:"version_env_sha256"`
	ContainerID      string `json:"container_id"`
	ImageID          string `json:"image_id"`
	RepositoryDigest string `json:"repository_digest"`
	CurrentVersion   string `json:"current_version"`
}

func (b dockerPortRuntimeBaseline) validate() error {
	if !digestPattern.MatchString(b.VersionEnvSHA256) ||
		!dockerContainerIDPattern.MatchString(b.ContainerID) ||
		!digestPattern.MatchString(b.ImageID) ||
		!digestPattern.MatchString(b.RepositoryDigest) ||
		!versionPattern.MatchString(b.CurrentVersion) {
		return errors.New("Docker port runtime baseline is invalid")
	}
	return nil
}

type dockerPortObservation struct {
	MappingEnv          dockerPortMappingCheckpoint
	PublishedHostIP     string
	PublishedPort       int
	ContainerPort       int
	HealthPort          int
	ConfigRevision      int64
	ConfigSHA256        string
	ComposePolicySHA256 string
	ComposeConfigSHA256 string
	Runtime             dockerPortRuntimeBaseline
}

func (o dockerPortObservation) validate() error {
	if o.MappingEnv.validate() != nil ||
		o.PublishedHostIP != "127.0.0.1" ||
		!validSystemdPort(o.PublishedPort) ||
		!validSystemdPort(o.ContainerPort) ||
		o.HealthPort != o.PublishedPort ||
		o.ConfigRevision < 1 ||
		!digestPattern.MatchString(o.ConfigSHA256) ||
		o.ConfigSHA256 != o.MappingEnv.SHA256 ||
		!mutationPlanHashPattern.MatchString(o.ComposePolicySHA256) ||
		!mutationPlanHashPattern.MatchString(o.ComposeConfigSHA256) ||
		o.Runtime.validate() != nil {
		return errors.New("Docker port observation is invalid")
	}
	return nil
}

type dockerPortPreparedModel struct {
	ComposePolicySHA256 string
	ComposeConfigSHA256 string
	PublishedHostIP     string
	PublishedPort       int
	ContainerPort       int
	HealthPort          int
}

func (m dockerPortPreparedModel) validate() error {
	if !mutationPlanHashPattern.MatchString(m.ComposePolicySHA256) ||
		!mutationPlanHashPattern.MatchString(m.ComposeConfigSHA256) ||
		m.PublishedHostIP != "127.0.0.1" ||
		!validSystemdPort(m.PublishedPort) ||
		!validSystemdPort(m.ContainerPort) ||
		m.HealthPort != m.PublishedPort {
		return errors.New("prepared Docker port model is invalid")
	}
	return nil
}

type dockerPortLedger struct {
	SchemaVersion       int                           `json:"schema_version"`
	Plan                SystemdPortReconfigurePlan    `json:"plan"`
	State               string                        `json:"state"`
	Checkpoint          dockerPortMappingCheckpoint   `json:"checkpoint"`
	TargetBytes         []byte                        `json:"target_bytes"`
	Baseline            dockerPortRuntimeBaseline     `json:"baseline"`
	OldComposeSHA256    string                        `json:"old_compose_sha256"`
	TargetComposeSHA256 string                        `json:"target_compose_sha256"`
	Result              *SystemdPortReconfigureResult `json:"result,omitempty"`
}

func (l dockerPortLedger) validate(targetID string) error {
	if l.SchemaVersion != 1 ||
		l.Plan.TargetID != targetID ||
		l.Plan.effectiveDeploymentMode() != ModeDocker ||
		l.Plan.Validate() != nil ||
		l.Checkpoint.validate() != nil ||
		l.Baseline.validate() != nil ||
		l.Checkpoint.SHA256 != l.Plan.ExpectedConfigSHA256 ||
		dockerPortEnvSHA256(l.TargetBytes) != l.Plan.TargetConfigSHA256 ||
		!mutationPlanHashPattern.MatchString(l.OldComposeSHA256) ||
		!mutationPlanHashPattern.MatchString(l.TargetComposeSHA256) {
		return errors.New("Docker port ledger binding is invalid")
	}
	switch l.State {
	case dockerPortLedgerStaged, dockerPortLedgerGrantConsuming,
		dockerPortLedgerGrantConsumed, dockerPortLedgerEnvWritten,
		dockerPortLedgerRecreated, dockerPortLedgerAmbiguous:
		if l.Result != nil {
			return errors.New("non-terminal Docker port ledger contains a result")
		}
	case dockerPortLedgerCommitting:
		if l.Result == nil || l.Result.Validate() != nil ||
			l.Result.Result == systemdPortResultRollbackFailed {
			return errors.New("committing Docker port ledger result is invalid")
		}
	case dockerPortLedgerTerminal:
		if l.Result == nil || l.Result.Validate() != nil {
			return errors.New("terminal Docker port ledger result is invalid")
		}
	default:
		return errors.New("Docker port ledger state is invalid")
	}
	return nil
}

type dockerPortAppliedState struct {
	SchemaVersion          int    `json:"schema_version"`
	TargetID               string `json:"target_id"`
	ServiceType            string `json:"service_type"`
	PublishedPort          int    `json:"published_port"`
	ContainerPort          int    `json:"container_port"`
	HealthPort             int    `json:"health_port"`
	EndpointRevision       int64  `json:"endpoint_revision"`
	ConfigRevision         int64  `json:"config_revision"`
	ConfigSHA256           string `json:"config_sha256"`
	ComposeConfigSHA256    string `json:"compose_config_sha256"`
	SourcePolicyRevision   int64  `json:"source_policy_revision"`
	UpdaterPolicyRevision  int64  `json:"updater_policy_revision"`
	ExecutorPolicyRevision int64  `json:"executor_policy_revision"`
	ExecutorPolicySHA256   string `json:"executor_policy_sha256"`
	OwnershipEpoch         int64  `json:"ownership_epoch"`
}

type dockerPortAppliedStateReader interface {
	LoadDockerApplied(string) (*dockerPortAppliedState, error)
}

type dockerPortAppliedSidecarVerifier interface {
	VerifyAppliedDockerSidecar(LocalExecutorTarget, dockerPortAppliedState) error
}

func (a dockerPortAppliedState) validate(targetID string) error {
	if a.SchemaVersion != 1 ||
		a.TargetID != targetID ||
		!identifierPattern.MatchString(a.TargetID) ||
		!validSystemdPortServiceType(a.ServiceType) ||
		!validSystemdPort(a.PublishedPort) ||
		!validSystemdPort(a.ContainerPort) ||
		a.HealthPort != a.PublishedPort ||
		a.EndpointRevision < 1 ||
		a.ConfigRevision < 1 ||
		!digestPattern.MatchString(a.ConfigSHA256) ||
		!mutationPlanHashPattern.MatchString(a.ComposeConfigSHA256) ||
		a.SourcePolicyRevision < 1 ||
		a.UpdaterPolicyRevision < 1 ||
		a.ExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(a.ExecutorPolicySHA256) ||
		a.OwnershipEpoch < 1 {
		return errors.New("Docker applied port state is invalid")
	}
	return nil
}

func (a dockerPortAppliedState) validateRecord(
	target LocalExecutorTarget,
) error {
	if err := a.validate(target.ServiceID); err != nil ||
		a.ServiceType != target.ServiceType ||
		target.DeploymentMode != ModeDocker ||
		target.Docker == nil ||
		!digestPattern.MatchString(target.ConfigSHA256) {
		return errors.New("Docker applied port state is invalid")
	}
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil {
		return errors.New("Docker applied port state adapter is invalid")
	}
	expected, err := dockerPortEnvBytes(
		adapter, a.PublishedPort, a.ContainerPort, a.ConfigRevision,
	)
	if err != nil || dockerPortEnvSHA256(expected) != a.ConfigSHA256 {
		return errors.New("Docker applied port state config digest is invalid")
	}
	return nil
}

func (a dockerPortAppliedState) validateForPolicy(
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
) (bool, error) {
	if err := a.validateRecord(target); err != nil {
		return false, err
	}
	policySHA256, err := policy.SHA256()
	if err != nil {
		return false, errors.New("Docker applied port policy digest is unavailable")
	}
	lineageMatches :=
		a.SourcePolicyRevision == policy.SourcePolicyRevision &&
			a.UpdaterPolicyRevision == policy.ProjectionRevision &&
			a.ExecutorPolicyRevision == policy.PolicyRevision &&
			a.ExecutorPolicySHA256 == policySHA256
	if !lineageMatches {
		if a.matchesTarget(target) {
			return false, nil
		}
		return false, errors.New("Docker applied port state policy lineage is stale")
	}
	if a.EndpointRevision < target.EndpointRevision ||
		a.ConfigRevision < target.ConfigRevision {
		return false, errors.New("Docker applied port state revision regresses")
	}
	if a.EndpointRevision == target.EndpointRevision &&
		(a.HealthPort != target.LocalListen.Port ||
			a.ConfigRevision != target.ConfigRevision ||
			a.ConfigSHA256 != target.ConfigSHA256 ||
			a.ComposeConfigSHA256 != target.Docker.ComposeConfigSHA256) {
		return false, errors.New("Docker applied port state reuses an endpoint revision")
	}
	if a.ConfigRevision == target.ConfigRevision &&
		(a.HealthPort != target.LocalListen.Port ||
			a.ConfigSHA256 != target.ConfigSHA256 ||
			a.ComposeConfigSHA256 != target.Docker.ComposeConfigSHA256) {
		return false, errors.New("Docker applied port state reuses a config revision")
	}
	return true, nil
}

func (a dockerPortAppliedState) matchesTarget(
	target LocalExecutorTarget,
) bool {
	return target.Docker != nil &&
		a.TargetID == target.ServiceID &&
		a.ServiceType == target.ServiceType &&
		a.HealthPort == target.LocalListen.Port &&
		a.EndpointRevision == target.EndpointRevision &&
		a.ConfigRevision == target.ConfigRevision &&
		a.ConfigSHA256 == target.ConfigSHA256 &&
		a.ComposeConfigSHA256 == target.Docker.ComposeConfigSHA256
}

type dockerPortStateStore interface {
	LoadActive(string) (*dockerPortLedger, error)
	LoadJob(string, string) (*dockerPortLedger, error)
	Stage(dockerPortLedger) error
	Save(dockerPortLedger) error
	LoadDockerApplied(string) (*dockerPortAppliedState, error)
	SaveApplied(dockerPortAppliedState) error
}

type memoryDockerPortStateStore struct {
	mu      sync.Mutex
	ledgers map[string]map[string]dockerPortLedger
	active  map[string]string
	applied map[string]dockerPortAppliedState
}

func newMemoryDockerPortStateStore() *memoryDockerPortStateStore {
	return &memoryDockerPortStateStore{
		ledgers: make(map[string]map[string]dockerPortLedger),
		active:  make(map[string]string),
		applied: make(map[string]dockerPortAppliedState),
	}
}

func (s *memoryDockerPortStateStore) LoadActive(targetID string) (*dockerPortLedger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, ok := s.ledgers[targetID][s.active[targetID]]
	if !ok {
		return nil, nil
	}
	copy := cloneDockerPortLedger(ledger)
	return &copy, nil
}

func (s *memoryDockerPortStateStore) LoadJob(targetID, jobID string) (*dockerPortLedger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, ok := s.ledgers[targetID][jobID]
	if !ok {
		return nil, nil
	}
	copy := cloneDockerPortLedger(ledger)
	return &copy, nil
}

func (s *memoryDockerPortStateStore) Stage(ledger dockerPortLedger) error {
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	targetID := ledger.Plan.TargetID
	if activeID := s.active[targetID]; activeID != "" && activeID != ledger.Plan.JobID {
		if active, ok := s.ledgers[targetID][activeID]; ok &&
			active.State != dockerPortLedgerTerminal {
			return errors.New("Docker port target already has a non-terminal transaction")
		}
	}
	if s.ledgers[targetID] == nil {
		s.ledgers[targetID] = make(map[string]dockerPortLedger)
	}
	s.ledgers[targetID][ledger.Plan.JobID] = cloneDockerPortLedger(ledger)
	s.active[targetID] = ledger.Plan.JobID
	return nil
}

func (s *memoryDockerPortStateStore) Save(ledger dockerPortLedger) error {
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ledgers[ledger.Plan.TargetID] == nil {
		s.ledgers[ledger.Plan.TargetID] = make(map[string]dockerPortLedger)
	}
	s.ledgers[ledger.Plan.TargetID][ledger.Plan.JobID] = cloneDockerPortLedger(ledger)
	if s.active[ledger.Plan.TargetID] == "" {
		s.active[ledger.Plan.TargetID] = ledger.Plan.JobID
	}
	return nil
}

func (s *memoryDockerPortStateStore) LoadDockerApplied(targetID string) (*dockerPortAppliedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	applied, ok := s.applied[targetID]
	if !ok {
		return nil, nil
	}
	copy := applied
	return &copy, nil
}

func (s *memoryDockerPortStateStore) SaveApplied(applied dockerPortAppliedState) error {
	if err := applied.validate(applied.TargetID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied[applied.TargetID] = applied
	return nil
}

func cloneDockerPortLedger(ledger dockerPortLedger) dockerPortLedger {
	copy := ledger
	copy.Plan.Docker = cloneDockerPortMutationGrantBinding(ledger.Plan.Docker)
	copy.Checkpoint.Bytes = append([]byte(nil), ledger.Checkpoint.Bytes...)
	copy.TargetBytes = append([]byte(nil), ledger.TargetBytes...)
	if ledger.Result != nil {
		result := *ledger.Result
		if ledger.Result.Docker != nil {
			docker := *ledger.Result.Docker
			result.Docker = &docker
		}
		copy.Result = &result
	}
	return copy
}

type dockerPortRuntime interface {
	Observe(context.Context, LocalExecutorPolicy, LocalExecutorTarget) (dockerPortObservation, error)
	Prepare(context.Context, LocalExecutorTarget, []byte) (dockerPortPreparedModel, error)
	EnsureAvailable(context.Context, LocalExecutorTarget, dockerPortPreparedModel, string) error
	ConsumeGrant(context.Context, SystemdPortReconfigurePlan, string, string, BoundedSecret) error
	Write(dockerPortMappingCheckpoint, []byte) error
	Restore(dockerPortMappingCheckpoint, []byte) error
	Recreate(context.Context, LocalExecutorTarget, dockerPortPreparedModel) error
	CrashPoint(string) error
}

func executeDockerPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	failure := func(code string) LocalExecutorResponse {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, code)
	}
	if runtime == nil || state == nil || request.PortPlan == nil {
		return failure("internal_error")
	}
	plan := *request.PortPlan
	target, adapter, err := validateDockerPortPolicyBinding(policy, request, plan)
	if err != nil {
		return failure("config_mismatch")
	}
	historical, err := state.LoadJob(plan.TargetID, plan.JobID)
	if err != nil {
		return failure("state_invalid")
	}
	if historical != nil {
		if historical.validate(plan.TargetID) != nil ||
			!sameSystemdPortIntent(historical.Plan, plan) {
			return failure("plan_conflict")
		}
		if historical.State == dockerPortLedgerTerminal {
			return localExecutorPortResponse(plan, *historical.Result)
		}
	}
	active, err := state.LoadActive(plan.TargetID)
	if err != nil {
		return failure("state_invalid")
	}
	if active != nil && active.Plan.JobID != plan.JobID &&
		active.State != dockerPortLedgerTerminal {
		return failure("target_busy")
	}
	ledger := historical
	if ledger == nil && active != nil && active.Plan.JobID == plan.JobID {
		ledger = active
	}
	if ledger != nil && ledger.State == dockerPortLedgerCommitting {
		if request.Operation != "port_reconfigure_reconcile" {
			return failure("reconcile_required")
		}
		return repairDockerPortCommit(
			ctx, policy, request, target, *ledger, runtime, state,
		)
	}
	target, err = resolveDockerPortAppliedTargetForTransaction(
		policy, target, state, ledger,
	)
	if err != nil || !dockerPortTargetMatchesExpected(target, plan) {
		return failure("config_mismatch")
	}
	if request.Operation == "port_reconfigure_reconcile" {
		return reconcileDockerPortRequest(
			ctx, policy, request, target, adapter, ledger, runtime, state,
		)
	}
	if request.Operation != "port_reconfigure" {
		return failure("invalid_request")
	}
	if ledger == nil {
		created, err := stageDockerPortLedger(ctx, policy, target, adapter, plan, runtime)
		if err != nil {
			return failure("mutation_precondition_failed")
		}
		if err := state.Stage(created); err != nil {
			return failure("state_unavailable")
		}
		ledger = &created
	}
	if ledger.State != dockerPortLedgerStaged {
		return failure("reconcile_required")
	}
	if err := recheckDockerPortStagedInputs(ctx, policy, target, *ledger, runtime); err != nil {
		return failure("mutation_precondition_failed")
	}
	working := cloneDockerPortLedger(*ledger)
	working.Plan = plan
	working.State = dockerPortLedgerGrantConsuming
	if err := state.Save(working); err != nil {
		return failure("state_unavailable")
	}
	if err := runtime.ConsumeGrant(
		ctx, plan, request.Operation, working.Baseline.CurrentVersion,
		request.MutationGrant,
	); err != nil {
		working.State = dockerPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	working.State = dockerPortLedgerGrantConsumed
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_grant_consume"); err != nil {
		working.State = dockerPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	if err := recheckDockerPortStagedInputs(ctx, policy, target, working, runtime); err != nil {
		return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
	}
	if err := runtime.Write(working.Checkpoint, working.TargetBytes); err != nil {
		return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
	}
	working.State = dockerPortLedgerEnvWritten
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_port_env_write"); err != nil {
		working.State = dockerPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	prepared := dockerPortPreparedModel{
		ComposePolicySHA256: plan.Docker.ApprovedComposeConfigSHA256,
		ComposeConfigSHA256: working.TargetComposeSHA256,
		PublishedHostIP:     plan.Docker.PublishedHostIP,
		PublishedPort:       plan.Docker.NewPublishedPort,
		ContainerPort:       plan.Docker.NewContainerPort,
		HealthPort:          plan.Docker.NewHealthPort,
	}
	newTarget := dockerPortTargetAfter(target, plan, working.TargetComposeSHA256)
	if err := runtime.Recreate(ctx, newTarget, prepared); err != nil {
		return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
	}
	working.State = dockerPortLedgerRecreated
	if err := state.Save(working); err != nil {
		return failure("reconcile_required")
	}
	if err := runtime.CrashPoint("after_docker_recreate"); err != nil {
		working.State = dockerPortLedgerAmbiguous
		_ = state.Save(working)
		return failure("reconcile_required")
	}
	observation, err := runtime.Observe(ctx, policy, newTarget)
	if err != nil || !dockerPortObservationMatchesTarget(
		observation, plan, working, true,
	) {
		return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
	}
	return commitDockerPortResult(
		plan, working, systemdPortResultApplied, observation.ComposeConfigSHA256,
		runtime, state,
	)
}

func validateDockerPortPolicyBinding(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	plan SystemdPortReconfigurePlan,
) (LocalExecutorTarget, dockerPortAdapter, error) {
	if request.Validate() != nil ||
		plan.Validate() != nil ||
		plan.effectiveDeploymentMode() != ModeDocker ||
		request.ServiceID != plan.TargetID ||
		request.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		request.OwnershipEpoch != plan.OwnershipEpoch ||
		request.OwnershipPolicyRevision != plan.ExpectedUpdaterPolicyRevision ||
		request.ExecutorPolicyRevision != plan.ExpectedExecutorPolicyRevision {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port request fence is invalid")
	}
	if policy.Validate() != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil ||
		policy.HostID != plan.HostID ||
		policy.SourcePolicyRevision != plan.ExpectedSourcePolicyRevision ||
		policy.ProjectionRevision != plan.ExpectedUpdaterPolicyRevision ||
		policy.PolicyRevision != plan.ExpectedExecutorPolicyRevision {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port root policy revision is stale")
	}
	policySHA256, err := policy.SHA256()
	if err != nil || policySHA256 != plan.ExpectedExecutorPolicySHA256 {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port root policy digest is stale")
	}
	target, ok := policy.Target(plan.TargetID)
	if !ok || target.DeploymentMode != ModeDocker ||
		target.Docker == nil ||
		target.ServiceType != plan.ServiceType ||
		target.LocalListen.Host != plan.Docker.PublishedHostIP ||
		target.Docker.PortComposePolicySHA256 != plan.Docker.ApprovedComposeConfigSHA256 ||
		target.Docker.PortComposeRevision != plan.Docker.ApprovedComposeRevision {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port root target does not match the plan")
	}
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil {
		return LocalExecutorTarget{}, dockerPortAdapter{}, err
	}
	targetBytes, err := dockerPortEnvBytes(
		adapter, plan.Docker.NewPublishedPort,
		plan.Docker.NewContainerPort, plan.TargetConfigRevision,
	)
	if err != nil || dockerPortEnvSHA256(targetBytes) != plan.TargetConfigSHA256 {
		return LocalExecutorTarget{}, dockerPortAdapter{}, errors.New("Docker port target env digest is invalid")
	}
	return target, adapter, nil
}

func resolveDockerPortAppliedTarget(
	policy LocalExecutorPolicy,
	policyTarget LocalExecutorTarget,
	state dockerPortAppliedStateReader,
) (LocalExecutorTarget, error) {
	return resolveDockerPortAppliedTargetBound(
		policy, policyTarget, state, true,
	)
}

func resolveDockerPortAppliedTargetForTransaction(
	policy LocalExecutorPolicy,
	policyTarget LocalExecutorTarget,
	state dockerPortAppliedStateReader,
	ledger *dockerPortLedger,
) (LocalExecutorTarget, error) {
	// Once a durable transaction has crossed the staged boundary, the mapping
	// sidecar may legitimately contain either the checkpoint or target bytes.
	// Requiring it to still match the preceding applied overlay would make a
	// process restart after Write or Recreate impossible to reconcile. The
	// ledger remains root-bound and reconciliation immediately observes both
	// exact old and target models before committing either outcome.
	verifySidecar := ledger == nil || ledger.State == dockerPortLedgerStaged
	return resolveDockerPortAppliedTargetBound(
		policy, policyTarget, state, verifySidecar,
	)
}

func resolveDockerPortAppliedTargetBound(
	policy LocalExecutorPolicy,
	policyTarget LocalExecutorTarget,
	state dockerPortAppliedStateReader,
	verifySidecar bool,
) (LocalExecutorTarget, error) {
	applied, err := state.LoadDockerApplied(policyTarget.ServiceID)
	if err != nil {
		return LocalExecutorTarget{}, err
	}
	if applied == nil {
		return policyTarget, nil
	}
	useOverlay, err := applied.validateForPolicy(policy, policyTarget)
	if err != nil {
		return LocalExecutorTarget{}, err
	}
	if verifier, ok := state.(dockerPortAppliedSidecarVerifier); ok &&
		verifySidecar {
		if err := verifier.VerifyAppliedDockerSidecar(
			policyTarget, *applied,
		); err != nil {
			return LocalExecutorTarget{}, err
		}
	}
	if !useOverlay {
		return policyTarget, nil
	}
	target := policyTarget
	target.LocalListen.Port = applied.HealthPort
	target.EndpointRevision = applied.EndpointRevision
	target.ConfigRevision = applied.ConfigRevision
	target.ConfigSHA256 = applied.ConfigSHA256
	docker := *target.Docker
	docker.ComposeConfigSHA256 = applied.ComposeConfigSHA256
	target.Docker = &docker
	return target, nil
}

func dockerPortTargetMatchesExpected(
	target LocalExecutorTarget,
	plan SystemdPortReconfigurePlan,
) bool {
	return target.Docker != nil &&
		target.LocalListen.Port == plan.Docker.OldHealthPort &&
		target.EndpointRevision > 0 &&
		target.EndpointRevision <= plan.ExpectedEndpointRevision &&
		target.ConfigRevision == plan.ExpectedConfigRevision &&
		target.ConfigSHA256 == plan.ExpectedConfigSHA256 &&
		target.Docker.PortComposePolicySHA256 ==
			plan.Docker.ApprovedComposeConfigSHA256 &&
		target.Docker.PortComposeRevision ==
			plan.Docker.ApprovedComposeRevision
}

func stageDockerPortLedger(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
	adapter dockerPortAdapter,
	plan SystemdPortReconfigurePlan,
	runtime dockerPortRuntime,
) (dockerPortLedger, error) {
	observation, err := runtime.Observe(ctx, policy, target)
	if err != nil || !dockerPortObservationMatchesPlanBaseline(observation, plan) {
		return dockerPortLedger{}, errors.New("Docker port baseline changed")
	}
	oldBytes, err := dockerPortEnvBytes(
		adapter, plan.Docker.OldPublishedPort,
		plan.Docker.OldContainerPort, plan.ExpectedConfigRevision,
	)
	if err != nil ||
		!observation.MappingEnv.Existed ||
		!reflect.DeepEqual(observation.MappingEnv.Bytes, oldBytes) {
		return dockerPortLedger{}, errors.New("Docker port mapping env differs from the plan")
	}
	targetBytes, err := dockerPortEnvBytes(
		adapter, plan.Docker.NewPublishedPort,
		plan.Docker.NewContainerPort, plan.TargetConfigRevision,
	)
	if err != nil || dockerPortEnvSHA256(targetBytes) != plan.TargetConfigSHA256 {
		return dockerPortLedger{}, errors.New("Docker port target env differs from the plan")
	}
	prepared, err := runtime.Prepare(ctx, target, targetBytes)
	if err != nil || !dockerPortPreparedMatchesPlan(prepared, plan) {
		return dockerPortLedger{}, errors.New("Docker port target Compose model is not approved")
	}
	if err := runtime.EnsureAvailable(
		ctx, target, prepared, observation.Runtime.ContainerID,
	); err != nil {
		return dockerPortLedger{}, err
	}
	return dockerPortLedger{
		SchemaVersion: 1, Plan: plan, State: dockerPortLedgerStaged,
		Checkpoint: observation.MappingEnv, TargetBytes: targetBytes,
		Baseline:            observation.Runtime,
		OldComposeSHA256:    observation.ComposeConfigSHA256,
		TargetComposeSHA256: prepared.ComposeConfigSHA256,
	}, nil
}

func recheckDockerPortStagedInputs(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
	ledger dockerPortLedger,
	runtime dockerPortRuntime,
) error {
	observation, err := runtime.Observe(ctx, policy, target)
	if err != nil ||
		!dockerPortObservationMatchesPlanBaseline(observation, ledger.Plan) ||
		!reflect.DeepEqual(observation.MappingEnv, ledger.Checkpoint) ||
		observation.ComposeConfigSHA256 != ledger.OldComposeSHA256 ||
		observation.Runtime != ledger.Baseline {
		return errors.New("Docker port baseline changed while authorizing the mutation")
	}
	prepared, err := runtime.Prepare(ctx, target, ledger.TargetBytes)
	if err != nil ||
		!dockerPortPreparedMatchesPlan(prepared, ledger.Plan) ||
		prepared.ComposeConfigSHA256 != ledger.TargetComposeSHA256 {
		return errors.New("Docker port staged inputs changed while authorizing the mutation")
	}
	return runtime.EnsureAvailable(
		ctx, target, prepared, observation.Runtime.ContainerID,
	)
}

func dockerPortObservationMatchesPlanBaseline(
	observation dockerPortObservation,
	plan SystemdPortReconfigurePlan,
) bool {
	return observation.validate() == nil &&
		observation.PublishedHostIP == plan.Docker.PublishedHostIP &&
		observation.PublishedPort == plan.Docker.OldPublishedPort &&
		observation.ContainerPort == plan.Docker.OldContainerPort &&
		observation.HealthPort == plan.Docker.OldHealthPort &&
		observation.ConfigRevision == plan.ExpectedConfigRevision &&
		observation.ConfigSHA256 == plan.ExpectedConfigSHA256 &&
		observation.ComposePolicySHA256 == plan.Docker.ApprovedComposeConfigSHA256 &&
		observation.Runtime.VersionEnvSHA256 == plan.Docker.ExpectedVersionEnvSHA256 &&
		dockerContainerIDsMatch(observation.Runtime.ContainerID, plan.Docker.ExpectedContainerID) &&
		observation.Runtime.ImageID == plan.Docker.ExpectedImageID &&
		observation.Runtime.RepositoryDigest == plan.Docker.ExpectedRepositoryDigest
}

func dockerPortPreparedMatchesPlan(
	prepared dockerPortPreparedModel,
	plan SystemdPortReconfigurePlan,
) bool {
	return prepared.validate() == nil &&
		prepared.ComposePolicySHA256 == plan.Docker.ApprovedComposeConfigSHA256 &&
		prepared.PublishedHostIP == plan.Docker.PublishedHostIP &&
		prepared.PublishedPort == plan.Docker.NewPublishedPort &&
		prepared.ContainerPort == plan.Docker.NewContainerPort &&
		prepared.HealthPort == plan.Docker.NewHealthPort
}

func dockerPortObservationMatchesTarget(
	observation dockerPortObservation,
	plan SystemdPortReconfigurePlan,
	ledger dockerPortLedger,
	targetSide bool,
) bool {
	if observation.validate() != nil ||
		observation.ComposePolicySHA256 != plan.Docker.ApprovedComposeConfigSHA256 ||
		observation.Runtime.VersionEnvSHA256 != ledger.Baseline.VersionEnvSHA256 ||
		observation.Runtime.ImageID != ledger.Baseline.ImageID ||
		observation.Runtime.RepositoryDigest != ledger.Baseline.RepositoryDigest ||
		observation.Runtime.CurrentVersion != ledger.Baseline.CurrentVersion {
		return false
	}
	if targetSide {
		return observation.PublishedHostIP == plan.Docker.PublishedHostIP &&
			observation.PublishedPort == plan.Docker.NewPublishedPort &&
			observation.ContainerPort == plan.Docker.NewContainerPort &&
			observation.HealthPort == plan.Docker.NewHealthPort &&
			observation.ConfigRevision == plan.TargetConfigRevision &&
			observation.ConfigSHA256 == plan.TargetConfigSHA256 &&
			observation.ComposeConfigSHA256 == ledger.TargetComposeSHA256 &&
			!dockerContainerIDsMatch(observation.Runtime.ContainerID, ledger.Baseline.ContainerID)
	}
	return observation.PublishedHostIP == plan.Docker.PublishedHostIP &&
		observation.PublishedPort == plan.Docker.OldPublishedPort &&
		observation.ContainerPort == plan.Docker.OldContainerPort &&
		observation.HealthPort == plan.Docker.OldHealthPort &&
		observation.ConfigRevision == plan.ExpectedConfigRevision &&
		observation.ConfigSHA256 == plan.ExpectedConfigSHA256 &&
		observation.ComposeConfigSHA256 == ledger.OldComposeSHA256
}

func dockerPortTargetAfter(
	target LocalExecutorTarget,
	plan SystemdPortReconfigurePlan,
	composeSHA256 string,
) LocalExecutorTarget {
	updated := target
	updated.LocalListen.Port = plan.Docker.NewHealthPort
	updated.EndpointRevision = plan.TargetEndpointRevision
	updated.ConfigRevision = plan.TargetConfigRevision
	updated.ConfigSHA256 = plan.TargetConfigSHA256
	docker := *target.Docker
	docker.ComposeConfigSHA256 = composeSHA256
	updated.Docker = &docker
	return updated
}

func repairDockerPortCommit(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	policyTarget LocalExecutorTarget,
	ledger dockerPortLedger,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	if ledger.Result == nil ||
		ledger.Result.Validate() != nil ||
		ledger.Result.Result == systemdPortResultRollbackFailed {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_invalid",
		)
	}
	plan := *request.PortPlan
	result := *ledger.Result
	effective := policyTarget
	effective.LocalListen.Port = result.Docker.AppliedHealthPort
	effective.EndpointRevision = result.EndpointRevision
	effective.ConfigRevision = result.ConfigRevision
	effective.ConfigSHA256 = result.ConfigSHA256
	docker := *effective.Docker
	docker.ComposeConfigSHA256 = result.Docker.ComposeConfigSHA256
	effective.Docker = &docker
	observation, err := runtime.Observe(ctx, policy, effective)
	targetSide := result.Result == systemdPortResultApplied
	if err != nil ||
		!dockerPortObservationMatchesTarget(
			observation, plan, ledger, targetSide,
		) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	if err := runtime.ConsumeGrant(
		ctx,
		plan,
		request.Operation,
		observation.Runtime.CurrentVersion,
		request.MutationGrant,
	); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "reconcile_required",
		)
	}
	applied := dockerPortAppliedState{
		SchemaVersion: 1, TargetID: plan.TargetID,
		ServiceType:            plan.ServiceType,
		PublishedPort:          result.Docker.AppliedPublishedPort,
		ContainerPort:          result.Docker.AppliedContainerPort,
		HealthPort:             result.Docker.AppliedHealthPort,
		EndpointRevision:       result.EndpointRevision,
		ConfigRevision:         result.ConfigRevision,
		ConfigSHA256:           result.ConfigSHA256,
		ComposeConfigSHA256:    result.Docker.ComposeConfigSHA256,
		SourcePolicyRevision:   plan.ExpectedSourcePolicyRevision,
		UpdaterPolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision: plan.ExpectedExecutorPolicyRevision,
		ExecutorPolicySHA256:   plan.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:         plan.OwnershipEpoch,
	}
	if err := state.SaveApplied(applied); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	ledger.Plan = plan
	ledger.State = dockerPortLedgerTerminal
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}

func rollbackDockerPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	oldTarget LocalExecutorTarget,
	ledger dockerPortLedger,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	plan := ledger.Plan
	// A post-grant recheck can fail before the mapping sidecar is written. In
	// that case the verified old state is already the safe terminal outcome;
	// attempting Restore would incorrectly require the not-yet-written target
	// bytes and turn a known unchanged state into rollback_failed.
	if observation, err := runtime.Observe(ctx, policy, oldTarget); err == nil &&
		dockerPortObservationMatchesTarget(observation, plan, ledger, false) {
		return commitDockerPortResult(
			plan, ledger, systemdPortResultUnchanged,
			observation.ComposeConfigSHA256, runtime, state,
		)
	}
	if err := runtime.Restore(ledger.Checkpoint, ledger.TargetBytes); err == nil {
		oldModel := dockerPortPreparedModel{
			ComposePolicySHA256: plan.Docker.ApprovedComposeConfigSHA256,
			ComposeConfigSHA256: ledger.OldComposeSHA256,
			PublishedHostIP:     plan.Docker.PublishedHostIP,
			PublishedPort:       plan.Docker.OldPublishedPort,
			ContainerPort:       plan.Docker.OldContainerPort,
			HealthPort:          plan.Docker.OldHealthPort,
		}
		if recreateErr := runtime.Recreate(ctx, oldTarget, oldModel); recreateErr == nil {
			if observation, observeErr := runtime.Observe(ctx, policy, oldTarget); observeErr == nil &&
				dockerPortObservationMatchesTarget(observation, plan, ledger, false) {
				return commitDockerPortResult(
					plan, ledger, systemdPortResultRolledBack,
					observation.ComposeConfigSHA256, runtime, state,
				)
			}
		}
	}
	return terminalDockerPortRollbackFailed(plan, ledger, state)
}

func reconcileDockerPortRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	target LocalExecutorTarget,
	adapter dockerPortAdapter,
	ledger *dockerPortLedger,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	plan := *request.PortPlan
	if ledger == nil {
		staged, err := stageDockerPortLedger(ctx, policy, target, adapter, plan, runtime)
		if err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "mutation_precondition_failed",
			)
		}
		if err := state.Stage(staged); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "state_unavailable",
			)
		}
		if err := runtime.ConsumeGrant(
			ctx, plan, request.Operation, staged.Baseline.CurrentVersion,
			request.MutationGrant,
		); err != nil {
			staged.State = dockerPortLedgerAmbiguous
			_ = state.Save(staged)
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "reconcile_required",
			)
		}
		return commitDockerPortResult(
			plan, staged, systemdPortResultUnchanged,
			staged.OldComposeSHA256, runtime, state,
		)
	}
	working := cloneDockerPortLedger(*ledger)
	observation, observeErr := runtime.Observe(ctx, policy, target)
	if observeErr == nil &&
		dockerPortObservationMatchesTarget(observation, plan, working, false) {
		return commitDockerPortResult(
			plan, working, systemdPortResultRolledBack,
			observation.ComposeConfigSHA256, runtime, state,
		)
	}
	newTarget := dockerPortTargetAfter(target, plan, working.TargetComposeSHA256)
	targetObservation, targetErr := runtime.Observe(ctx, policy, newTarget)
	if targetErr == nil &&
		dockerPortObservationMatchesTarget(targetObservation, plan, working, true) {
		return commitDockerPortResult(
			plan, working, systemdPortResultApplied,
			targetObservation.ComposeConfigSHA256, runtime, state,
		)
	}
	return rollbackDockerPortRequest(ctx, policy, target, working, runtime, state)
}

func commitDockerPortResult(
	plan SystemdPortReconfigurePlan,
	ledger dockerPortLedger,
	resultKind, composeSHA256 string,
	runtime dockerPortRuntime,
	state dockerPortStateStore,
) LocalExecutorResponse {
	result := SystemdPortReconfigureResult{
		DeploymentMode: ModeDocker,
		OldPort:        plan.OldPort, NewPort: plan.NewPort,
	}
	var publishedPort, containerPort, healthPort int
	switch resultKind {
	case systemdPortResultApplied:
		result.Status, result.Result = "succeeded", systemdPortResultApplied
		result.StateKnown, result.AppliedPort = true, plan.NewPort
		result.EndpointRevision = plan.TargetEndpointRevision
		result.ConfigRevision = plan.TargetConfigRevision
		result.ConfigSHA256 = plan.TargetConfigSHA256
		result.Message = "requested Docker port mapping is running and verified"
		publishedPort, containerPort, healthPort =
			plan.Docker.NewPublishedPort,
			plan.Docker.NewContainerPort,
			plan.Docker.NewHealthPort
	case systemdPortResultRolledBack:
		result.Status, result.Result = "rolled_back", systemdPortResultRolledBack
		result.StateKnown, result.AppliedPort = true, plan.OldPort
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "previous Docker port mapping was restored and verified"
		publishedPort, containerPort, healthPort =
			plan.Docker.OldPublishedPort,
			plan.Docker.OldContainerPort,
			plan.Docker.OldHealthPort
	case systemdPortResultUnchanged:
		result.Status, result.Result = "succeeded", systemdPortResultUnchanged
		result.StateKnown, result.AppliedPort = true, plan.OldPort
		result.EndpointRevision = plan.TargetEndpointRevision + 1
		result.ConfigRevision = plan.ExpectedConfigRevision
		result.ConfigSHA256 = plan.ExpectedConfigSHA256
		result.Message = "Docker port mutation had not changed the verified previous mapping"
		publishedPort, containerPort, healthPort =
			plan.Docker.OldPublishedPort,
			plan.Docker.OldContainerPort,
			plan.Docker.OldHealthPort
	default:
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "internal_error",
		)
	}
	result.Docker = &DockerPortReconfigureResultState{
		AppliedPublishedPort: publishedPort,
		AppliedContainerPort: containerPort,
		AppliedHealthPort:    healthPort,
		ComposeConfigSHA256:  composeSHA256,
	}
	if result.Validate() != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "internal_error",
		)
	}
	applied := dockerPortAppliedState{
		SchemaVersion: 1, TargetID: plan.TargetID, ServiceType: plan.ServiceType,
		PublishedPort: publishedPort, ContainerPort: containerPort,
		HealthPort: healthPort, EndpointRevision: result.EndpointRevision,
		ConfigRevision: result.ConfigRevision, ConfigSHA256: result.ConfigSHA256,
		ComposeConfigSHA256:    composeSHA256,
		SourcePolicyRevision:   plan.ExpectedSourcePolicyRevision,
		UpdaterPolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision: plan.ExpectedExecutorPolicyRevision,
		ExecutorPolicySHA256:   plan.ExpectedExecutorPolicySHA256,
		OwnershipEpoch:         plan.OwnershipEpoch,
	}
	ledger.Plan = plan
	ledger.State = dockerPortLedgerCommitting
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	if err := state.SaveApplied(applied); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	if runtime != nil {
		if err := runtime.CrashPoint("after_applied_state_save"); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "reconcile_required",
			)
		}
	}
	ledger.State = dockerPortLedgerTerminal
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}

func terminalDockerPortRollbackFailed(
	plan SystemdPortReconfigurePlan,
	ledger dockerPortLedger,
	state dockerPortStateStore,
) LocalExecutorResponse {
	result := SystemdPortReconfigureResult{
		DeploymentMode: ModeDocker,
		Status:         "failed", Result: systemdPortResultRollbackFailed,
		StateKnown: false, OldPort: plan.OldPort, NewPort: plan.NewPort,
		EndpointRevision: plan.TargetEndpointRevision,
		Message:          "local rollback could not determine a verified Docker port mapping",
	}
	ledger.Plan = plan
	ledger.State = dockerPortLedgerTerminal
	ledger.Result = &result
	if err := state.Save(ledger); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return localExecutorPortResponse(plan, result)
}

func handleLocalExecutorDockerPortMutation(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	remoteRuntime executorMutationRuntime,
) LocalExecutorResponse {
	if remoteRuntime.platformOS == "" {
		remoteRuntime.platformOS = runtime.GOOS
	}
	if remoteRuntime.platformOS != "linux" || request.PortPlan == nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "target_unavailable",
		)
	}
	target, ok := policy.Target(request.ServiceID)
	if !ok {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "target_not_found",
		)
	}
	if target.DeploymentMode != ModeDocker || target.Docker == nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "config_mismatch",
		)
	}
	secured, err := securePrivilegedTarget(target.runtimeTarget(policy.HostID))
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "target_unavailable",
		)
	}
	unlock, err := acquireTargetLock(secured)
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "target_busy",
		)
	}
	defer unlock()
	portRuntime, state, err := newPlatformDockerPortExecution(
		policy, target, secured, remoteRuntime,
	)
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	return executeDockerPortRequest(ctx, policy, request, portRuntime, state)
}
