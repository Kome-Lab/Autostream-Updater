package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

const (
	localExecutorPortPolicyPath = "/etc/autostream/updater/executor-policy.json"
	portPolicyWritePending      = "policy_write_pending"
	portPolicyWritten           = "policy_written"
	portPolicyLoaded            = "policy_loaded"
	portPolicyRollbackLatched   = "rollback_latched"
	portPolicyForwardTimeout    = 120 * time.Second
	portPolicyRollbackTimeout   = 120 * time.Second
	portPolicyStartTimeout      = 30 * time.Second
)

// SharedPortPlan reconstructs only the immutable versioned contract. The
// separately bound runtime digest is never substituted for its intent digest.
func (p SystemdPortReconfigurePlan) SharedPortPlan() contracts.SystemUpdatePortReconfiguration {
	return contracts.SystemUpdatePortReconfiguration{
		PortContractVersion: p.PortContractVersion, Mode: p.Mode,
		Before: p.Before, Target: p.Target, Rollback: p.Rollback,
		DockerBaseline: p.DockerBaseline, NetworkNamespace: p.NetworkNamespace,
		Protocol: contracts.SystemUpdatePortProtocol(p.Protocol), PortPlanSHA256: p.PortIntentSHA256,
	}
}

func (p *SystemdPortReconfigurePlan) UnmarshalJSON(data []byte) error {
	type plainPlan SystemdPortReconfigurePlan
	if err := rejectPortDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded plainPlan
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("port IPC plan has invalid fields")
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return errors.New("port IPC plan must be an object")
	}
	if _, present := raw["port_contract_version"]; present {
		if decoded.PortContractVersion != 2 {
			return errors.New("port IPC contract version is unsupported")
		}
		for _, field := range []string{"old_port", "new_port", "expected_endpoint_revision", "target_endpoint_revision", "expected_config_revision", "target_config_revision", "expected_config_sha256", "target_config_sha256", "expected_source_policy_revision", "expected_updater_policy_revision", "expected_executor_policy_revision", "expected_executor_policy_sha256", "docker"} {
			if _, present := raw[field]; present {
				return errors.New("versioned port IPC plan contains a legacy field")
			}
		}
	}
	*p = SystemdPortReconfigurePlan(decoded)
	return nil
}

func rejectPortDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("port JSON contains a duplicate object field")
				}
				seen[name] = true
				if err := readValue(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
		default:
			return errors.New("port JSON delimiter is invalid")
		}
		_, err = decoder.Token()
		return err
	}
	if err := readValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("port JSON contains trailing data")
	}
	return nil
}

func (p SystemdPortReconfigurePlan) validatePortV2() error {
	if p.PortContractVersion != 2 || !identifierPattern.MatchString(p.JobID) || !validExecutionHostID(p.HostID) ||
		!identifierPattern.MatchString(p.TargetID) || !validSystemdPortServiceType(p.ServiceType) ||
		p.OwnershipEpoch < 1 || p.LeaseGeneration == 0 || !mutationSessionPattern.MatchString(p.SessionID) ||
		p.OldPort != 0 || p.NewPort != 0 || p.ExpectedEndpointRevision != 0 || p.TargetEndpointRevision != 0 ||
		p.ExpectedConfigRevision != 0 || p.TargetConfigRevision != 0 || p.ExpectedConfigSHA256 != "" || p.TargetConfigSHA256 != "" ||
		p.ExpectedSourcePolicyRevision != 0 || p.ExpectedUpdaterPolicyRevision != 0 || p.ExpectedExecutorPolicyRevision != 0 ||
		p.ExpectedExecutorPolicySHA256 != "" || p.Docker != nil {
		return errors.New("versioned port plan contains an invalid identity or legacy authority")
	}
	if err := contracts.ValidateSystemUpdatePortPlan(p.SharedPortPlan()); err != nil {
		return errors.New("versioned port snapshot plan is invalid")
	}
	if p.DeploymentMode != ModeSystemd && p.DeploymentMode != ModeDocker ||
		(p.DeploymentMode == ModeDocker) != (p.Before.Docker != nil) {
		return errors.New("versioned port deployment mode is invalid")
	}
	digest, err := p.ComputePortPlanSHA256()
	if err != nil || digest != p.PortPlanSHA256 {
		return errors.New("versioned port runtime plan digest mismatch")
	}
	return nil
}

func (p SystemdPortReconfigurePlan) sourcePolicyRevision() int64 {
	if p.PortContractVersion == 2 && p.Before != nil {
		return p.Before.SourcePolicyRevision
	}
	return p.ExpectedSourcePolicyRevision
}
func (p SystemdPortReconfigurePlan) projectionRevision() int64 {
	if p.PortContractVersion == 2 && p.Before != nil {
		return p.Before.ProjectionRevision
	}
	return p.ExpectedUpdaterPolicyRevision
}
func (p SystemdPortReconfigurePlan) executorPolicyRevision() int64 {
	if p.PortContractVersion == 2 && p.Before != nil {
		return p.Before.ExecutorPolicyRevision
	}
	return p.ExpectedExecutorPolicyRevision
}

func (r SystemdPortReconfigureResult) validatePortV2() error {
	if r.PortContractVersion != 2 || r.PortResult == nil || !safeExecutorMessage(r.Message) ||
		string(r.PortResult.Result) != r.Result || r.PortResult.Observation.ObservedAt.IsZero() {
		return errors.New("versioned port result is invalid")
	}
	if r.Result == systemdPortResultRollbackFailed {
		if r.Status != "failed" || r.StateKnown || !r.RecoveryRequired ||
			r.PortResult.ObservedSnapshotID != "" || r.PortResult.ObservedSnapshotSHA256 != "" ||
			r.PortResult.ObservedConfigRevision != 0 || r.PortResult.ObservedConfigSHA256 != "" ||
			r.PortResult.ObservedExecutorPolicyRevision != 0 || r.PortResult.ObservedExecutorPolicySHA256 != "" ||
			r.PortResult.RuntimeInstance != nil {
			return errors.New("failed recovery must not assert an accepted snapshot")
		}
		return nil
	}
	if r.Result != systemdPortResultApplied && r.Result != systemdPortResultUnchanged && r.Result != systemdPortResultRolledBack ||
		!r.StateKnown || r.RecoveryRequired || r.Result == systemdPortResultRolledBack && r.Status != "rolled_back" ||
		r.Result != systemdPortResultRolledBack && r.Status != "succeeded" ||
		!r.PortResult.Observation.PolicyDiskVerified || !r.PortResult.Observation.PolicyMemoryVerified ||
		!r.PortResult.Observation.ListenerVerified ||
		!digestPattern.MatchString(r.PortResult.ObservedConfigSHA256) ||
		!digestPattern.MatchString(r.PortResult.ObservedExecutorPolicySHA256) ||
		r.PortResult.ObservedConfigRevision < 1 || r.PortResult.ObservedExecutorPolicyRevision < 1 {
		return errors.New("versioned port result lacks exact root observation")
	}
	// Agent projection is deliberately absent from root authority. It is added
	// by the Agent after verifying its own active projection against this result.
	return nil
}

func validatePortV2GrantBinding(now time.Time, binding contracts.UpdaterMutationGrantBinding, operation string,
	plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, policy *LocalExecutorPolicy, target *LocalExecutorTarget) error {
	if contracts.ValidateUpdaterMutationGrantBinding(now, binding) != nil || plan.Validate() != nil ||
		binding.Operation != contracts.UpdaterMutationOperation(operation) || binding.SessionID != plan.SessionID ||
		(operation != "port_reconfigure" && operation != "port_reconfigure_reconcile") ||
		!reflect.DeepEqual(binding.Lease.Command.DesiredOperation.PortReconfigure, func() *contracts.SystemUpdatePortReconfiguration { p := plan.SharedPortPlan(); return &p }()) {
		return errors.New("versioned port grant does not bind its immutable plan")
	}
	auth := binding.Lease.Command.MutationAuthorization
	if auth.JobID != plan.JobID || auth.HostID != plan.HostID || auth.Fence != plan.OwnershipEpoch ||
		auth.DesiredRevision != plan.Target.ConfigRevision || auth.Target.ServiceID != plan.TargetID ||
		string(auth.Target.ServiceType) != plan.ServiceType || string(auth.Target.DeploymentMode) != plan.DeploymentMode ||
		auth.Target.TargetKind != contracts.UpdaterTargetApplication || auth.Target.ExpectedConfigRevision != plan.Before.ConfigRevision ||
		binding.Lease.LeaseGeneration != int64(plan.LeaseGeneration) ||
		fence.SourcePolicyRevision != plan.Before.SourcePolicyRevision || fence.OwnershipPolicyRevision != plan.Before.ProjectionRevision ||
		fence.ExecutorPolicyRevision != plan.Before.ExecutorPolicyRevision || fence.OwnershipEpoch != plan.OwnershipEpoch {
		return errors.New("versioned port grant identity or original fence mismatch")
	}
	if policy == nil && target == nil {
		return nil
	}
	if policy == nil || target == nil || policy.Validate() != nil || policy.HostID != plan.HostID ||
		target.ServiceID != plan.TargetID || target.ServiceType != plan.ServiceType || target.DeploymentMode != plan.DeploymentMode {
		return errors.New("versioned port root identity mismatch")
	}
	matched := portPolicySnapshotMatches(*policy, *target, *plan.Before)
	if operation == "port_reconfigure_reconcile" {
		matched = matched || portPolicySnapshotMatches(*policy, *target, *plan.Target) || portPolicySnapshotMatches(*policy, *target, *plan.Rollback)
	}
	if !matched {
		return errors.New("versioned port root policy is outside the saved transaction")
	}
	return nil
}

type portPolicyCandidates struct{ Before, Target, Rollback []byte }

func decodePortPolicy(payload []byte) (LocalExecutorPolicy, error) {
	if len(payload) == 0 || len(payload) > localExecutorPolicyMaxBytes {
		return LocalExecutorPolicy{}, errors.New("port policy payload size is invalid")
	}
	if rejectPortDuplicateJSONKeys(payload) != nil {
		return LocalExecutorPolicy{}, errors.New("port policy payload has duplicate fields")
	}
	var policy LocalExecutorPolicy
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil || decoder.Decode(new(any)) != io.EOF || policy.Validate() != nil {
		return LocalExecutorPolicy{}, errors.New("port policy payload is invalid")
	}
	encoded, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(encoded, payload) {
		return LocalExecutorPolicy{}, errors.New("port policy payload serializer mismatch")
	}
	return policy, nil
}

func buildSystemUpdatePortPolicyCandidates(policy LocalExecutorPolicy, plan SystemdPortReconfigurePlan) (portPolicyCandidates, error) {
	if plan.Validate() != nil || policy.Validate() != nil {
		return portPolicyCandidates{}, errors.New("port policy candidate input is invalid")
	}
	target, ok := policy.Target(plan.TargetID)
	if !ok || !portPolicySnapshotMatches(policy, target, *plan.Before) {
		return portPolicyCandidates{}, errors.New("port policy baseline mismatch")
	}
	before, err := json.Marshal(policy)
	if err != nil {
		return portPolicyCandidates{}, err
	}
	targetBytes, err := contracts.ApplySystemUpdatePortPolicyDelta(before, plan.TargetID, *plan.Before, *plan.Target)
	if err != nil {
		return portPolicyCandidates{}, err
	}
	rollback, err := contracts.ApplySystemUpdatePortPolicyDelta(before, plan.TargetID, *plan.Before, *plan.Rollback)
	if err != nil {
		return portPolicyCandidates{}, err
	}
	candidates := portPolicyCandidates{Before: before, Target: targetBytes, Rollback: rollback}
	if err := candidates.validate(plan); err != nil {
		return portPolicyCandidates{}, err
	}
	return candidates, nil
}

func (p portPolicyCandidates) validate(plan SystemdPortReconfigurePlan) error {
	for i, payload := range [][]byte{p.Before, p.Target, p.Rollback} {
		policy, err := decodePortPolicy(payload)
		if err != nil || policy.HostID != plan.HostID {
			return errors.New("saved port policy payload is invalid")
		}
		target, ok := policy.Target(plan.TargetID)
		ref := []*contracts.SystemUpdatePortSnapshotRef{plan.Before, plan.Target, plan.Rollback}[i]
		if !ok || ref == nil || !portPolicySnapshotMatches(policy, target, *ref) {
			return errors.New("saved port policy snapshot mismatch")
		}
	}
	for i, ref := range []*contracts.SystemUpdatePortSnapshotRef{plan.Target, plan.Rollback} {
		expected, err := contracts.ApplySystemUpdatePortPolicyDelta(p.Before, plan.TargetID, *plan.Before, *ref)
		actual := [][]byte{p.Target, p.Rollback}[i]
		if err != nil || !bytes.Equal(expected, actual) {
			return errors.New("saved port policy exceeds the authorized delta")
		}
	}
	return nil
}

func portPolicySnapshotMatches(policy LocalExecutorPolicy, target LocalExecutorTarget, ref contracts.SystemUpdatePortSnapshotRef) bool {
	digest, err := policy.SHA256()
	return err == nil && digest == ref.ExecutorPolicySHA256 && policy.SourcePolicyRevision == ref.SourcePolicyRevision &&
		policy.ProjectionRevision == ref.ProjectionRevision && policy.PolicyRevision == ref.ExecutorPolicyRevision &&
		target.EndpointRevision == ref.AppliedEndpointRevision && target.ConfigRevision == ref.ConfigRevision &&
		target.ConfigSHA256 == ref.ConfigSHA256 && target.LocalListen.Port == ref.LocalListenPort
}

// portPolicyTransitionState extends the existing per-target port ledger. It
// carries no grants, credentials, alternative paths, or independent job state.
type portPolicyTransitionState struct {
	Version                 int                           `json:"version"`
	BeforePolicy            []byte                        `json:"before_policy"`
	TargetPolicy            []byte                        `json:"target_policy"`
	RollbackPolicy          []byte                        `json:"rollback_policy"`
	RollbackRuntimeBytes    []byte                        `json:"rollback_runtime_bytes"`
	RollbackComposeSHA256   string                        `json:"rollback_compose_sha256,omitempty"`
	RollbackLatched         bool                          `json:"rollback_latched"`
	RecoveryRequired        bool                          `json:"recovery_required"`
	Consumed                bool                          `json:"consumed"`
	LastRecoveryObservation *SystemdPortReconfigureResult `json:"last_recovery_observation,omitempty"`
}

func (s *portPolicyTransitionState) candidates() portPolicyCandidates {
	return portPolicyCandidates{Before: s.BeforePolicy, Target: s.TargetPolicy, Rollback: s.RollbackPolicy}
}

func clonePortPolicyTransition(input *portPolicyTransitionState) *portPolicyTransitionState {
	if input == nil {
		return nil
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil
	}
	var result portPolicyTransitionState
	if json.Unmarshal(data, &result) != nil {
		return nil
	}
	return &result
}

func (s *portPolicyTransitionState) validate(plan SystemdPortReconfigurePlan) error {
	if s == nil || s.Version != 1 || s.candidates().validate(plan) != nil || len(s.RollbackRuntimeBytes) == 0 ||
		systemdPortSidecarSHA256(s.RollbackRuntimeBytes) != plan.Rollback.ConfigSHA256 {
		return errors.New("port transition ledger is invalid")
	}
	if s.LastRecoveryObservation != nil && (s.LastRecoveryObservation.Validate() != nil ||
		s.LastRecoveryObservation.Result != systemdPortResultRollbackFailed || !s.RollbackLatched || !s.RecoveryRequired) {
		return errors.New("port recovery observation is invalid")
	}
	return nil
}

type portPolicyContextKey struct{}
type portPolicyStore interface {
	Snapshot() (LocalExecutorPolicy, error)
	Verify([]byte) error
	Replace(portPolicyCandidates, []byte) error
}

// The policy pointer changes only after fixed-path secure disk reread. The
// host lifecycle lock serializes mutation callers; this mutex gives probes an
// immutable generation without exposing a partially decoded policy.
type filePortPolicyStore struct {
	mu               sync.RWMutex
	path             string
	requireRootOwned bool
	policy           LocalExecutorPolicy
}

func newFilePortPolicyStore(path string, requireRootOwned bool) (*filePortPolicyStore, error) {
	if requireRootOwned && filepath.Clean(path) != localExecutorPortPolicyPath {
		return nil, errors.New("port transition requires the fixed installed policy path")
	}
	policy, err := LoadLocalExecutorPolicy(path, requireRootOwned)
	if err != nil {
		return nil, err
	}
	return &filePortPolicyStore{path: path, requireRootOwned: requireRootOwned, policy: policy}, nil
}

func (s *filePortPolicyStore) Snapshot() (LocalExecutorPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	payload, err := json.Marshal(s.policy)
	if err != nil {
		return LocalExecutorPolicy{}, err
	}
	return decodePortPolicy(payload)
}

func (s *filePortPolicyStore) readExact() ([]byte, LocalExecutorPolicy, error) {
	info, err := os.Lstat(s.path)
	if err != nil || systemdPortLinkOrReparse(info) || !info.Mode().IsRegular() ||
		s.requireRootOwned && (info.Mode().Perm() != 0o600 || !isRootOwner(info)) {
		return nil, LocalExecutorPolicy{}, errors.New("port policy is not a private regular file")
	}
	policy, err := LoadLocalExecutorPolicy(s.path, s.requireRootOwned)
	if err != nil {
		return nil, LocalExecutorPolicy{}, err
	}
	file, opened, err := openVerifiedConfig(s.path, info)
	if err != nil {
		return nil, LocalExecutorPolicy{}, errors.New("port policy changed during secure read")
	}
	defer file.Close()
	if s.requireRootOwned && validateRootOwnedFileAndParents(s.path, opened, "port policy") != nil {
		return nil, LocalExecutorPolicy{}, errors.New("port policy parent is not secure")
	}
	payload, err := io.ReadAll(io.LimitReader(file, localExecutorPolicyMaxBytes+1))
	encoded, encodeErr := json.Marshal(policy)
	if err != nil || encodeErr != nil || !bytes.Equal(payload, encoded) {
		return nil, LocalExecutorPolicy{}, errors.New("port policy exact bytes mismatch")
	}
	return payload, policy, nil
}

func (s *filePortPolicyStore) Verify(expected []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	disk, _, err := s.readExact()
	memory, encodeErr := json.Marshal(s.policy)
	if err != nil || encodeErr != nil || !bytes.Equal(disk, expected) || !bytes.Equal(memory, expected) {
		return errors.New("port policy disk and memory are not verified")
	}
	return nil
}

func (s *filePortPolicyStore) Replace(allowed portPolicyCandidates, next []byte) error {
	if err := s.Write(allowed, next); err != nil {
		return err
	}
	return s.Reload(next)
}

func (s *filePortPolicyStore) Write(allowed portPolicyCandidates, next []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	match := func(payload []byte) bool {
		return bytes.Equal(payload, allowed.Before) || bytes.Equal(payload, allowed.Target) || bytes.Equal(payload, allowed.Rollback)
	}
	disk, _, err := s.readExact()
	memory, encodeErr := json.Marshal(s.policy)
	if err != nil || encodeErr != nil || !match(disk) || !match(memory) || !match(next) {
		return errors.New("port policy transition baseline is unknown")
	}
	if _, err := decodePortPolicy(next); err != nil {
		return err
	}
	if !bytes.Equal(disk, next) {
		if err := writeAtomicFile(s.path, next, 0o600); err != nil {
			return errors.New("port policy atomic replacement failed")
		}
	}
	return nil
}

func (s *filePortPolicyStore) Reload(next []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	readback, loaded, err := s.readExact()
	if err != nil || !bytes.Equal(readback, next) {
		return errors.New("port policy secure reload failed")
	}
	s.policy = loaded
	return nil
}

// The origin is fixed by the installed policy; candidates are accepted only
// after their full bytes have matched the saved immutable B/T/R identities.
func portPolicyFromContext(ctx context.Context) portPolicyStore {
	store, _ := ctx.Value(portPolicyContextKey{}).(portPolicyStore)
	return store
}

func portStartDeadline(m0 time.Time, binding contracts.UpdaterMutationGrantBinding) time.Time {
	deadline := m0.Add(portPolicyStartTimeout)
	for _, expiry := range []time.Time{binding.Lease.LeaseExpiresAt, binding.Lease.Command.MutationAuthorization.ExpiresAt} {
		// Attach the already observed wall-clock duration to M0's monotonic
		// component once. A later wall-clock change cannot reset the budget.
		candidate := m0.Add(expiry.Sub(m0))
		if candidate.Before(deadline) {
			deadline = candidate
		}
	}
	return deadline
}
