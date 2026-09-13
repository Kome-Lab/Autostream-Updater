package hostruntime

import (
	"errors"
	"sync"
)

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
	copy.Plan.Before = clonePortSnapshotRef(ledger.Plan.Before)
	copy.Plan.Target = clonePortSnapshotRef(ledger.Plan.Target)
	copy.Plan.Rollback = clonePortSnapshotRef(ledger.Plan.Rollback)
	copy.Plan.DockerBaseline = clonePortDockerBaseline(ledger.Plan.DockerBaseline)
	copy.PolicyTransition = clonePortPolicyTransition(ledger.PolicyTransition)
	copy.Plan.Docker = cloneDockerPortMutationGrantBinding(ledger.Plan.Docker)
	copy.Checkpoint.Bytes = append([]byte(nil), ledger.Checkpoint.Bytes...)
	copy.TargetBytes = append([]byte(nil), ledger.TargetBytes...)
	if ledger.Result != nil {
		result := *ledger.Result
		result.PortResult = clonePortResult(ledger.Result.PortResult)
		if ledger.Result.Docker != nil {
			docker := *ledger.Result.Docker
			result.Docker = &docker
		}
		copy.Result = &result
	}
	return copy
}
