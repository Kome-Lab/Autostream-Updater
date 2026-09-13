package hostruntime

import (
	"errors"
	"sync"
)

type systemdPortSidecarCheckpoint struct {
	Existed bool   `json:"existed"`
	Mode    uint32 `json:"mode"`
	Bytes   []byte `json:"bytes,omitempty"`
	SHA256  string `json:"sha256"`
}

func newSystemdPortSidecarCheckpoint(existed bool, mode uint32, body []byte) systemdPortSidecarCheckpoint {
	if !existed {
		body = nil
		mode = 0
	}
	return systemdPortSidecarCheckpoint{
		Existed: existed, Mode: mode, Bytes: append([]byte(nil), body...),
		SHA256: systemdPortSidecarSHA256(body),
	}
}

func (c systemdPortSidecarCheckpoint) validate() error {
	if c.SHA256 != systemdPortSidecarSHA256(c.Bytes) {
		return errors.New("systemd port sidecar checkpoint digest is invalid")
	}
	if !c.Existed {
		if c.Mode != 0 || len(c.Bytes) != 0 {
			return errors.New("absent systemd port sidecar checkpoint is invalid")
		}
		return nil
	}
	if c.Mode == 0 || c.Mode&0o022 != 0 || len(c.Bytes) == 0 || len(c.Bytes) > 64<<10 {
		return errors.New("present systemd port sidecar checkpoint is invalid")
	}
	return nil
}

type systemdPortLedger struct {
	SchemaVersion    int                           `json:"schema_version"`
	Plan             SystemdPortReconfigurePlan    `json:"plan"`
	State            string                        `json:"state"`
	Checkpoint       systemdPortSidecarCheckpoint  `json:"checkpoint"`
	TargetBytes      []byte                        `json:"target_bytes"`
	CurrentVersion   string                        `json:"current_version"`
	Result           *SystemdPortReconfigureResult `json:"result,omitempty"`
	PolicyTransition *portPolicyTransitionState    `json:"policy_transition,omitempty"`
}

type systemdPortAppliedState struct {
	SchemaVersion          int    `json:"schema_version"`
	TargetID               string `json:"target_id"`
	ServiceType            string `json:"service_type"`
	Port                   int    `json:"port"`
	EndpointRevision       int64  `json:"endpoint_revision"`
	ConfigRevision         int64  `json:"config_revision"`
	ConfigSHA256           string `json:"config_sha256"`
	SourcePolicyRevision   int64  `json:"source_policy_revision"`
	UpdaterPolicyRevision  int64  `json:"updater_policy_revision"`
	ExecutorPolicyRevision int64  `json:"executor_policy_revision"`
	ExecutorPolicySHA256   string `json:"executor_policy_sha256"`
	OwnershipEpoch         int64  `json:"ownership_epoch"`
}

func (s systemdPortAppliedState) validateRecord(target LocalExecutorTarget) error {
	if s.SchemaVersion != systemdPortPlanSchemaVersion ||
		s.TargetID != target.ServiceID ||
		s.ServiceType != target.ServiceType ||
		target.DeploymentMode != ModeSystemd ||
		target.Systemd == nil ||
		!validSystemdPort(s.Port) ||
		s.EndpointRevision < 1 ||
		s.ConfigRevision < 1 ||
		!digestPattern.MatchString(s.ConfigSHA256) ||
		s.SourcePolicyRevision < 1 ||
		s.UpdaterPolicyRevision < 1 ||
		s.ExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(s.ExecutorPolicySHA256) ||
		s.OwnershipEpoch < 1 ||
		!digestPattern.MatchString(target.ConfigSHA256) {
		return errors.New("systemd applied port state is invalid")
	}
	adapter, err := systemdPortAdapterFor(target.ServiceType, target.Systemd.Unit)
	if err != nil {
		return errors.New("systemd applied port state adapter is invalid")
	}
	expectedDigest := systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.ServiceType,
		target.LocalListen.Host,
		s.Port,
		s.ConfigRevision,
	))
	if s.ConfigSHA256 != expectedDigest {
		return errors.New("systemd applied port state digest is invalid")
	}
	return nil
}

func (s systemdPortAppliedState) validateForPolicy(
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
) (bool, error) {
	if err := s.validateRecord(target); err != nil {
		return false, err
	}
	policySHA, err := policy.SHA256()
	if err != nil {
		return false, errors.New("systemd applied port policy digest is unavailable")
	}
	lineageMatches := s.SourcePolicyRevision == policy.SourcePolicyRevision &&
		s.UpdaterPolicyRevision == policy.ProjectionRevision &&
		s.ExecutorPolicyRevision == policy.PolicyRevision &&
		s.ExecutorPolicySHA256 == policySHA
	if !lineageMatches {
		// A newly installed root policy may already contain the exact applied
		// endpoint. In that case the overlay is redundant and can be ignored
		// safely. Any other lineage mismatch is quarantined fail-closed.
		if s.matchesTarget(target) {
			return false, nil
		}
		return false, errors.New("systemd applied port state policy lineage is stale")
	}
	if s.EndpointRevision < target.EndpointRevision ||
		s.ConfigRevision < target.ConfigRevision {
		return false, errors.New("systemd applied port state revision regresses")
	}
	if s.EndpointRevision == target.EndpointRevision &&
		(s.Port != target.LocalListen.Port ||
			s.ConfigRevision != target.ConfigRevision ||
			s.ConfigSHA256 != target.ConfigSHA256) {
		return false, errors.New("systemd applied port state reuses an endpoint revision")
	}
	if s.ConfigRevision == target.ConfigRevision &&
		(s.Port != target.LocalListen.Port ||
			s.ConfigSHA256 != target.ConfigSHA256) {
		return false, errors.New("systemd applied port state reuses a config revision")
	}
	return true, nil
}

func (s systemdPortAppliedState) matchesTarget(target LocalExecutorTarget) bool {
	return s.TargetID == target.ServiceID &&
		s.ServiceType == target.ServiceType &&
		s.Port == target.LocalListen.Port &&
		s.EndpointRevision == target.EndpointRevision &&
		s.ConfigRevision == target.ConfigRevision &&
		s.ConfigSHA256 == target.ConfigSHA256
}

func (l systemdPortLedger) validate(targetID string) error {
	if l.Plan.PortContractVersion == 2 {
		return l.validatePortV2(targetID)
	}
	if l.SchemaVersion != systemdPortPlanSchemaVersion ||
		l.Plan.TargetID != targetID ||
		l.Plan.Validate() != nil ||
		l.Checkpoint.validate() != nil ||
		l.Plan.ExpectedConfigSHA256 != l.Checkpoint.SHA256 ||
		systemdPortSidecarSHA256(l.TargetBytes) != l.Plan.TargetConfigSHA256 {
		return errors.New("systemd port ledger binding is invalid")
	}
	if !versionPattern.MatchString(l.CurrentVersion) {
		return errors.New("systemd port ledger current version is invalid")
	}
	switch l.State {
	case systemdPortLedgerStaged, systemdPortLedgerGrantConsuming,
		systemdPortLedgerGrantConsumed, systemdPortLedgerSidecarWritten,
		systemdPortLedgerRestarted, systemdPortLedgerAmbiguous:
		if l.Result != nil {
			return errors.New("non-terminal systemd port ledger contains a result")
		}
	case systemdPortLedgerCommitting:
		if l.Result == nil || l.Result.Validate() != nil ||
			l.Result.Result == systemdPortResultRollbackFailed {
			return errors.New("committing systemd port ledger result is invalid")
		}
	case systemdPortLedgerTerminal:
		if l.Result == nil || l.Result.Validate() != nil {
			return errors.New("terminal systemd port ledger result is invalid")
		}
	default:
		return errors.New("systemd port ledger state is invalid")
	}
	return nil
}

type systemdPortStateStore interface {
	LoadActive(string) (*systemdPortLedger, error)
	LoadJob(string, string) (*systemdPortLedger, error)
	Stage(systemdPortLedger) error
	Save(systemdPortLedger) error
	LoadApplied(string) (*systemdPortAppliedState, error)
	SaveApplied(systemdPortAppliedState) error
}

type memorySystemdPortStateStore struct {
	mu      sync.Mutex
	ledgers map[string]map[string]systemdPortLedger
	active  map[string]string
	applied map[string]systemdPortAppliedState
}

func newMemorySystemdPortStateStore() *memorySystemdPortStateStore {
	return &memorySystemdPortStateStore{
		ledgers: make(map[string]map[string]systemdPortLedger),
		active:  make(map[string]string), applied: make(map[string]systemdPortAppliedState),
	}
}

func (s *memorySystemdPortStateStore) LoadActive(targetID string) (*systemdPortLedger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobID := s.active[targetID]
	ledger, ok := s.ledgers[targetID][jobID]
	if !ok {
		return nil, nil
	}
	copy := cloneSystemdPortLedger(ledger)
	return &copy, nil
}

func (s *memorySystemdPortStateStore) LoadJob(targetID, jobID string) (*systemdPortLedger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, ok := s.ledgers[targetID][jobID]
	if !ok {
		return nil, nil
	}
	copy := cloneSystemdPortLedger(ledger)
	return &copy, nil
}

func (s *memorySystemdPortStateStore) Stage(ledger systemdPortLedger) error {
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	targetID := ledger.Plan.TargetID
	if activeID := s.active[targetID]; activeID != "" && activeID != ledger.Plan.JobID {
		if active, ok := s.ledgers[targetID][activeID]; ok &&
			active.State != systemdPortLedgerTerminal {
			return errors.New("systemd port target already has a non-terminal transaction")
		}
	}
	if s.ledgers[targetID] == nil {
		s.ledgers[targetID] = make(map[string]systemdPortLedger)
	}
	s.ledgers[targetID][ledger.Plan.JobID] = cloneSystemdPortLedger(ledger)
	s.active[targetID] = ledger.Plan.JobID
	return nil
}

func (s *memorySystemdPortStateStore) Save(ledger systemdPortLedger) error {
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ledgers[ledger.Plan.TargetID] == nil {
		s.ledgers[ledger.Plan.TargetID] = make(map[string]systemdPortLedger)
	}
	s.ledgers[ledger.Plan.TargetID][ledger.Plan.JobID] = cloneSystemdPortLedger(ledger)
	if s.active[ledger.Plan.TargetID] == "" {
		s.active[ledger.Plan.TargetID] = ledger.Plan.JobID
	}
	return nil
}

func (s *memorySystemdPortStateStore) LoadApplied(targetID string) (*systemdPortAppliedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	applied, ok := s.applied[targetID]
	if !ok {
		return nil, nil
	}
	copy := applied
	return &copy, nil
}

func (s *memorySystemdPortStateStore) SaveApplied(applied systemdPortAppliedState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied[applied.TargetID] = applied
	return nil
}

func cloneSystemdPortLedger(ledger systemdPortLedger) systemdPortLedger {
	copy := ledger
	copy.Plan.Before = clonePortSnapshotRef(ledger.Plan.Before)
	copy.Plan.Target = clonePortSnapshotRef(ledger.Plan.Target)
	copy.Plan.Rollback = clonePortSnapshotRef(ledger.Plan.Rollback)
	copy.Plan.DockerBaseline = clonePortDockerBaseline(ledger.Plan.DockerBaseline)
	copy.Checkpoint.Bytes = append([]byte(nil), ledger.Checkpoint.Bytes...)
	copy.TargetBytes = append([]byte(nil), ledger.TargetBytes...)
	copy.PolicyTransition = clonePortPolicyTransition(ledger.PolicyTransition)
	if ledger.Result != nil {
		result := *ledger.Result
		result.PortResult = clonePortResult(ledger.Result.PortResult)
		copy.Result = &result
	}
	return copy
}
