package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	HostSelfUpdateGrantStatePath = "/var/lib/autostream-local-executor/host-self-update/grant.json"

	hostSelfUpdateGrantStateSchemaVersion = 1
	hostSelfUpdateGrantPhasePrepared      = "prepared"
	hostSelfUpdateGrantPhaseConsumed      = "consumed"
	hostSelfUpdateGrantPhaseApplied       = "applied"
	hostSelfUpdateGrantPhaseFailed        = "failed"
)

var errHostSelfUpdateGrantUncertain = errors.New(
	"host self-update grant consume result is uncertain",
)

// HostSelfUpdateGrantBinding mirrors the public, credential-free Control
// Plane grant. The raw token is deliberately held separately in BoundedSecret.
type HostSelfUpdateGrantBinding struct {
	ID                                  string                        `json:"id"`
	SelfUpdateID                        string                        `json:"self_update_id"`
	AttemptGeneration                   string                        `json:"attempt_generation"`
	Operation                           string                        `json:"operation"`
	ExecutionHostID                     string                        `json:"execution_host_id"`
	AgentServiceID                      string                        `json:"agent_service_id"`
	ExpectedSelfUpdateRevision          int64                         `json:"expected_self_update_revision"`
	ExpectedOwnershipEpoch              int64                         `json:"expected_ownership_epoch"`
	ExpectedSourcePolicyRevision        int64                         `json:"expected_source_policy_revision"`
	ExpectedProjectionRevision          int64                         `json:"expected_projection_revision"`
	ExpectedLocalExecutorPolicyRevision int64                         `json:"expected_local_executor_policy_revision"`
	ExpectedLocalExecutorPolicySHA256   string                        `json:"expected_local_executor_policy_sha256"`
	AgentVersion                        string                        `json:"agent_version"`
	ExecutorVersion                     string                        `json:"executor_version"`
	ReleaseCommit                       string                        `json:"release_commit"`
	ArtifactSHA256                      string                        `json:"artifact_sha256"`
	AgentProtocolVersion                int                           `json:"agent_protocol_version"`
	ExecutorProtocolVersion             int                           `json:"executor_protocol_version"`
	MutationProtocolVersion             int                           `json:"mutation_protocol_version"`
	RecoveryProtocolVersion             int                           `json:"recovery_protocol_version"`
	Release                             HostSelfUpdateReleaseIdentity `json:"release"`
	DirectiveIssuedAt                   time.Time                     `json:"directive_issued_at"`
	PlanSHA256                          string                        `json:"plan_sha256"`
	SessionID                           string                        `json:"session_id"`
	Revision                            int64                         `json:"revision"`
	IssuedAt                            time.Time                     `json:"issued_at"`
	ExpiresAt                           time.Time                     `json:"expires_at"`
	ConsumedAt                          *time.Time                    `json:"consumed_at,omitempty"`
	StageClaimRevision                  int64                         `json:"stage_claim_revision,omitempty"`
	StageClaimedAt                      *time.Time                    `json:"stage_claimed_at,omitempty"`
	CreatedAt                           time.Time                     `json:"created_at,omitempty"`
	UpdatedAt                           time.Time                     `json:"updated_at,omitempty"`
}

type HostSelfUpdateGrantAuthorization struct {
	Binding HostSelfUpdateGrantBinding
	Token   BoundedSecret
}

type HostSelfUpdateGrantConsumeResult struct {
	Grant    HostSelfUpdateGrantBinding `json:"grant"`
	Consumed bool                       `json:"consumed"`
}

func (b HostSelfUpdateGrantBinding) validate(expectConsumed bool) error {
	for _, value := range []string{
		b.ID,
		b.SelfUpdateID,
		b.AttemptGeneration,
		b.ExecutionHostID,
		b.AgentServiceID,
		b.SessionID,
	} {
		if !identifierPattern.MatchString(value) ||
			value != strings.TrimSpace(value) {
			return errors.New("host self-update grant identity is invalid")
		}
	}
	if (b.Operation != "stage" && b.Operation != "reconcile") ||
		b.ExpectedSelfUpdateRevision < 1 ||
		b.ExpectedOwnershipEpoch < 1 ||
		b.ExpectedSourcePolicyRevision < 1 ||
		b.ExpectedProjectionRevision < 1 ||
		b.ExpectedLocalExecutorPolicyRevision < 1 {
		return errors.New("host self-update grant operation fence is invalid")
	}
	if !digestPattern.MatchString(b.ExpectedLocalExecutorPolicySHA256) ||
		!versionPattern.MatchString(b.AgentVersion) ||
		!versionPattern.MatchString(b.ExecutorVersion) ||
		!updaterReleaseCommitPattern.MatchString(b.ReleaseCommit) ||
		!digestPattern.MatchString(b.ArtifactSHA256) ||
		b.AgentProtocolVersion < 1 ||
		b.ExecutorProtocolVersion < 1 ||
		b.MutationProtocolVersion < 1 ||
		b.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion {
		return errors.New("host self-update grant runtime identity is invalid")
	}
	if err := b.Release.validate(); err != nil {
		return fmt.Errorf("host self-update grant release identity is invalid: %w", err)
	}
	if b.DirectiveIssuedAt.IsZero() ||
		b.DirectiveIssuedAt.Location() != time.UTC ||
		!mutationPlanHashPattern.MatchString(b.PlanSHA256) ||
		b.Revision < 1 ||
		b.IssuedAt.IsZero() ||
		b.IssuedAt.Location() != time.UTC ||
		b.ExpiresAt.Location() != time.UTC ||
		!b.ExpiresAt.After(b.IssuedAt) ||
		b.ExpiresAt.Sub(b.IssuedAt) > 5*time.Minute {
		return errors.New("host self-update grant time or plan binding is invalid")
	}
	if !b.Release.matchesRequest(HostSelfUpdateRequest{
		AgentVersion:            b.AgentVersion,
		Commit:                  b.ReleaseCommit,
		ArtifactSHA256:          b.ArtifactSHA256,
		AgentProtocolVersion:    b.AgentProtocolVersion,
		ExecutorProtocolVersion: b.ExecutorProtocolVersion,
		MutationProtocolVersion: b.MutationProtocolVersion,
		RecoveryProtocolVersion: b.RecoveryProtocolVersion,
	}) {
		return errors.New("host self-update grant release identity is inconsistent")
	}
	if expectConsumed {
		if b.ConsumedAt == nil ||
			b.ConsumedAt.IsZero() ||
			b.ConsumedAt.Location() != time.UTC ||
			b.ConsumedAt.Before(b.IssuedAt) {
			return errors.New("host self-update grant receipt is invalid")
		}
		if b.Operation == "stage" {
			if b.StageClaimRevision != b.ExpectedSelfUpdateRevision+1 ||
				b.StageClaimedAt == nil ||
				!b.StageClaimedAt.Equal(*b.ConsumedAt) {
				return errors.New("host self-update stage claim is invalid")
			}
		} else if b.StageClaimRevision != 0 ||
			b.StageClaimedAt != nil {
			return errors.New("reconcile grant contains a stage claim")
		}
	} else if b.ConsumedAt != nil ||
		b.StageClaimRevision != 0 ||
		b.StageClaimedAt != nil {
		return errors.New("unconsumed host self-update grant contains a receipt")
	}
	return nil
}

func (a HostSelfUpdateGrantAuthorization) validate() error {
	if err := a.Binding.validate(false); err != nil {
		return err
	}
	token := a.Token.Reveal()
	if !strings.HasPrefix(token, "ast_hsug_") ||
		!validBoundedSecret(token) {
		return errors.New("host self-update grant token is invalid")
	}
	return nil
}

func sameHostSelfUpdateGrantBinding(
	left, right HostSelfUpdateGrantBinding,
) bool {
	return left.ID == right.ID &&
		left.SelfUpdateID == right.SelfUpdateID &&
		left.AttemptGeneration == right.AttemptGeneration &&
		left.Operation == right.Operation &&
		left.ExecutionHostID == right.ExecutionHostID &&
		left.AgentServiceID == right.AgentServiceID &&
		left.ExpectedSelfUpdateRevision == right.ExpectedSelfUpdateRevision &&
		left.ExpectedOwnershipEpoch == right.ExpectedOwnershipEpoch &&
		left.ExpectedSourcePolicyRevision == right.ExpectedSourcePolicyRevision &&
		left.ExpectedProjectionRevision == right.ExpectedProjectionRevision &&
		left.ExpectedLocalExecutorPolicyRevision == right.ExpectedLocalExecutorPolicyRevision &&
		left.ExpectedLocalExecutorPolicySHA256 == right.ExpectedLocalExecutorPolicySHA256 &&
		left.AgentVersion == right.AgentVersion &&
		left.ExecutorVersion == right.ExecutorVersion &&
		left.ReleaseCommit == right.ReleaseCommit &&
		left.ArtifactSHA256 == right.ArtifactSHA256 &&
		left.AgentProtocolVersion == right.AgentProtocolVersion &&
		left.ExecutorProtocolVersion == right.ExecutorProtocolVersion &&
		left.MutationProtocolVersion == right.MutationProtocolVersion &&
		left.RecoveryProtocolVersion == right.RecoveryProtocolVersion &&
		sameHostSelfUpdateReleaseIdentity(left.Release, right.Release) &&
		left.DirectiveIssuedAt.Equal(right.DirectiveIssuedAt) &&
		left.PlanSHA256 == right.PlanSHA256 &&
		left.SessionID == right.SessionID &&
		left.Revision == right.Revision &&
		left.IssuedAt.Equal(right.IssuedAt) &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

type hostSelfUpdateGrantConsumer func(
	context.Context,
	string,
	HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateGrantConsumeResult, error)

func consumeHostSelfUpdateGrant(
	ctx context.Context,
	panelURL string,
	authorization HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateGrantConsumeResult, error) {
	if err := validatePanelURL(panelURL); err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("root self-update grant panel URL is invalid")
	}
	if err := authorization.validate(); err != nil {
		return HostSelfUpdateGrantConsumeResult{}, err
	}
	wire := struct {
		Token   string                     `json:"token"`
		Binding HostSelfUpdateGrantBinding `json:"binding"`
	}{
		Token:   authorization.Token.Reveal(),
		Binding: authorization.Binding,
	}
	payload, err := json.Marshal(wire)
	wire.Token = ""
	if err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("encode host self-update grant consume request")
	}
	endpoint := strings.TrimRight(panelURL, "/") +
		"/services/host-agent/self-update-grants/consume"
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("create host self-update grant consume request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("consume host self-update grant")
	}
	defer response.Body.Close()
	if !responseNoStore(response.Header.Values("Cache-Control")) {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("host self-update grant consume response must use Cache-Control no-store")
	}
	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusMultipleChoices {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("host self-update grant was rejected")
	}
	var result HostSelfUpdateGrantConsumeResult
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("decode host self-update grant consume response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("host self-update grant consume response contains trailing data")
	}
	if err := result.Grant.validate(true); err != nil ||
		!sameHostSelfUpdateGrantBinding(result.Grant, authorization.Binding) {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("host self-update grant receipt binding is invalid")
	}
	return result, nil
}

// ConsumeHostSelfUpdateGrant performs the root-side exact grant consumption
// exchange. It is exported only within this repository's internal boundary so
// the complete Host Agent -> Control Plane -> root contract can be exercised.
func ConsumeHostSelfUpdateGrant(
	ctx context.Context,
	panelURL string,
	authorization HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateGrantConsumeResult, error) {
	return consumeHostSelfUpdateGrant(ctx, panelURL, authorization)
}

type hostSelfUpdateGrantState struct {
	SchemaVersion int                         `json:"schema_version"`
	Phase         string                      `json:"phase"`
	TokenSHA256   string                      `json:"token_sha256"`
	Binding       HostSelfUpdateGrantBinding  `json:"binding"`
	Receipt       *HostSelfUpdateGrantBinding `json:"receipt,omitempty"`
}

func newHostSelfUpdateGrantState(
	authorization HostSelfUpdateGrantAuthorization,
) hostSelfUpdateGrantState {
	sum := sha256.Sum256([]byte(authorization.Token.Reveal()))
	return hostSelfUpdateGrantState{
		SchemaVersion: hostSelfUpdateGrantStateSchemaVersion,
		Phase:         hostSelfUpdateGrantPhasePrepared,
		TokenSHA256:   "sha256:" + hex.EncodeToString(sum[:]),
		Binding:       authorization.Binding,
	}
}

func (s hostSelfUpdateGrantState) validate() error {
	if s.SchemaVersion != hostSelfUpdateGrantStateSchemaVersion ||
		(s.Phase != hostSelfUpdateGrantPhasePrepared &&
			s.Phase != hostSelfUpdateGrantPhaseConsumed &&
			s.Phase != hostSelfUpdateGrantPhaseApplied &&
			s.Phase != hostSelfUpdateGrantPhaseFailed) ||
		!digestPattern.MatchString(s.TokenSHA256) ||
		s.Binding.validate(false) != nil {
		return errors.New("host self-update grant state is invalid")
	}
	if s.Phase == hostSelfUpdateGrantPhasePrepared ||
		s.Phase == hostSelfUpdateGrantPhaseFailed {
		if s.Receipt != nil {
			return errors.New("receipt-free host self-update grant phase contains a receipt")
		}
		return nil
	}
	if s.Receipt == nil ||
		s.Receipt.validate(true) != nil ||
		!sameHostSelfUpdateGrantBinding(*s.Receipt, s.Binding) {
		return errors.New("consumed host self-update grant receipt is invalid")
	}
	return nil
}

func (s hostSelfUpdateGrantState) matches(
	authorization HostSelfUpdateGrantAuthorization,
) bool {
	if !sameHostSelfUpdateGrantBinding(s.Binding, authorization.Binding) {
		return false
	}
	sum := sha256.Sum256([]byte(authorization.Token.Reveal()))
	return s.TokenSHA256 == "sha256:"+hex.EncodeToString(sum[:])
}

func loadHostSelfUpdateGrantState(path string, requireRoot bool) (
	*hostSelfUpdateGrantState,
	error,
) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 ||
		info.Size() > 64<<10 ||
		(requireRoot && !isRootOwner(info)) {
		return nil, errors.New("host self-update grant state is unsafe")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read host self-update grant state")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state hostSelfUpdateGrantState
	if err := decoder.Decode(&state); err != nil {
		return nil, errors.New("decode host self-update grant state")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("host self-update grant state contains trailing data")
	}
	if err := state.validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveHostSelfUpdateGrantState(
	path string,
	state hostSelfUpdateGrantState,
	requireRoot bool,
) error {
	if err := state.validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode host self-update grant state")
	}
	if err := writeAtomicFile(path, append(payload, '\n'), 0o600); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 ||
		info.Mode()&os.ModeSymlink != 0 ||
		(requireRoot && !isRootOwner(info)) {
		return errors.New("host self-update grant state security verification failed")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) failClosedUncertainStage(
	status HostSelfUpdateRuntimeStatus,
	request HostSelfUpdateRequest,
	authorization HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateRuntimeStatus, error) {
	if err := status.validate(); err != nil ||
		status.State.Phase != HostSelfUpdatePhaseStable ||
		status.CurrentSlot != status.State.ActiveSlot ||
		status.State.ActiveSlot != status.State.HealthySlot ||
		request.validate() != nil ||
		authorization.validate() != nil ||
		authorization.Binding.Operation != "stage" ||
		authorization.Binding.AttemptGeneration != request.Generation ||
		authorization.Binding.AgentVersion != request.AgentVersion ||
		authorization.Binding.ExecutorVersion != request.ExecutorVersion ||
		authorization.Binding.ReleaseCommit != request.Commit ||
		authorization.Binding.ArtifactSHA256 != request.ArtifactSHA256 ||
		authorization.Binding.AgentProtocolVersion != request.AgentProtocolVersion ||
		authorization.Binding.ExecutorProtocolVersion != request.ExecutorProtocolVersion ||
		authorization.Binding.MutationProtocolVersion != request.MutationProtocolVersion ||
		authorization.Binding.RecoveryProtocolVersion != request.RecoveryProtocolVersion ||
		!sameHostSelfUpdateReleaseIdentity(
			authorization.Binding.Release,
			request.Release,
		) {
		return HostSelfUpdateRuntimeStatus{},
			errors.New("uncertain host self-update stage binding is invalid")
	}
	grant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil ||
		grant == nil ||
		grant.Phase != hostSelfUpdateGrantPhasePrepared ||
		!grant.matches(authorization) {
		return HostSelfUpdateRuntimeStatus{},
			errors.New("uncertain host self-update stage fence is unavailable")
	}

	// Persist the generation failure before converting the prepared grant to
	// its receipt-free failed terminal. If the process stops between these
	// operations, status() observes the durable fence and completes the exact,
	// credential-free journal convergence on its next run.
	status.State.FailedGeneration = request.Generation
	if err := rt.saveState(status.State); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := rt.cleanFailedHostSelfUpdateGrant(status.State); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	status.LastAction = HostSelfUpdateActionNone
	return status, nil
}

func (rt *hostSelfUpdateExecutorRuntime) convergeHostSelfUpdateStageAfterError(
	request HostSelfUpdateRequest,
	authorization HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateRuntimeStatus, bool, error) {
	if err := rt.prepare(); err != nil {
		return HostSelfUpdateRuntimeStatus{}, false,
			fmt.Errorf("prepare host self-update stage error recovery: %w", err)
	}
	status, err := rt.status()
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, false,
			fmt.Errorf("recover host self-update stage error: %w", err)
	}
	phase, matches, err := rt.hostSelfUpdateGrantPhase(authorization)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, false, err
	}
	switch {
	case matches &&
		phase == hostSelfUpdateGrantPhaseApplied &&
		rt.hostSelfUpdateStateEffectMatchesGrant(
			status.State,
			authorization.Binding,
		):
		return status, true, nil
	case matches &&
		phase == hostSelfUpdateGrantPhaseFailed &&
		status.State.Phase == HostSelfUpdatePhaseStable &&
		status.State.FailedGeneration == request.Generation:
		return status, false, nil
	default:
		return HostSelfUpdateRuntimeStatus{}, false,
			errors.New("host self-update stage error did not durably converge")
	}
}

func (rt hostSelfUpdateExecutorRuntime) cleanFailedHostSelfUpdateGrant(
	state HostSelfUpdateState,
) error {
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.FailedGeneration == "" {
		return nil
	}
	grant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil || grant == nil {
		return err
	}
	if !failedHostSelfUpdateStateMatchesStageGrant(state, grant) {
		return nil
	}
	if grant.Phase == hostSelfUpdateGrantPhaseFailed {
		return nil
	}
	grant.Phase = hostSelfUpdateGrantPhaseFailed
	grant.Receipt = nil
	return saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		*grant,
		!rt.allowTestPaths,
	)
}

func failedHostSelfUpdateStateMatchesStageGrant(
	state HostSelfUpdateState,
	grant *hostSelfUpdateGrantState,
) bool {
	return grant != nil &&
		state.Phase == HostSelfUpdatePhaseStable &&
		state.FailedGeneration != "" &&
		grant.Binding.Operation == "stage" &&
		grant.Binding.AttemptGeneration == state.FailedGeneration &&
		(grant.Phase == hostSelfUpdateGrantPhasePrepared ||
			grant.Phase == hostSelfUpdateGrantPhaseConsumed ||
			grant.Phase == hostSelfUpdateGrantPhaseApplied ||
			grant.Phase == hostSelfUpdateGrantPhaseFailed)
}

func (rt hostSelfUpdateExecutorRuntime) removeHostSelfUpdateGrantState() error {
	if err := os.Remove(rt.grantStatePath); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return errors.New("remove failed host self-update grant state")
	}
	if err := syncDirectory(filepath.Dir(rt.grantStatePath)); err != nil {
		return errors.New("sync failed host self-update grant cleanup")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) recoverDurableHostSelfUpdateGrant(
	state HostSelfUpdateState,
) (HostSelfUpdateState, error) {
	grant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil || grant == nil {
		return state, err
	}
	if failedHostSelfUpdateStateMatchesStageGrant(state, grant) {
		if err := rt.cleanFailedHostSelfUpdateGrant(state); err != nil {
			return HostSelfUpdateState{}, err
		}
		return state, nil
	}
	if grant.Phase == hostSelfUpdateGrantPhaseApplied {
		if rt.hostSelfUpdateStateEffectMatchesGrant(state, grant.Binding) {
			return state, nil
		}
		return HostSelfUpdateState{},
			errors.New("applied host self-update grant contradicts runtime state")
	}

	switch grant.Binding.Operation {
	case "stage":
		if state.Phase == HostSelfUpdatePhaseStable {
			if grant.Phase == hostSelfUpdateGrantPhaseConsumed &&
				rt.hostSelfUpdateStateEffectMatchesGrant(
					state,
					grant.Binding,
				) {
				if err := rt.markDurableHostSelfUpdateGrantApplied(
					grant,
				); err != nil {
					return HostSelfUpdateState{}, err
				}
				return state, nil
			}
			if state.FailedGeneration != grant.Binding.AttemptGeneration {
				state.FailedGeneration = grant.Binding.AttemptGeneration
				if err := rt.saveState(state); err != nil {
					return HostSelfUpdateState{}, err
				}
			}
			if err := rt.cleanFailedHostSelfUpdateGrant(state); err != nil {
				return HostSelfUpdateState{}, err
			}
			return state, nil
		}
		if grant.Phase == hostSelfUpdateGrantPhaseConsumed &&
			rt.hostSelfUpdateStateEffectMatchesGrant(
				state,
				grant.Binding,
			) {
			if err := rt.markDurableHostSelfUpdateGrantApplied(
				grant,
			); err != nil {
				return HostSelfUpdateState{}, err
			}
			return state, nil
		}
	case "reconcile":
		if grant.Phase == hostSelfUpdateGrantPhasePrepared {
			if err := rt.removeHostSelfUpdateGrantState(); err != nil {
				return HostSelfUpdateState{}, err
			}
			return state, nil
		}
		if grant.Phase == hostSelfUpdateGrantPhaseConsumed &&
			rt.hostSelfUpdateStateEffectMatchesGrant(
				state,
				grant.Binding,
			) {
			if err := rt.markDurableHostSelfUpdateGrantApplied(
				grant,
			); err != nil {
				return HostSelfUpdateState{}, err
			}
			return state, nil
		}
	}
	return HostSelfUpdateState{},
		errors.New("durable host self-update grant contradicts runtime state")
}

func (rt hostSelfUpdateExecutorRuntime) markDurableHostSelfUpdateGrantApplied(
	state *hostSelfUpdateGrantState,
) error {
	if state == nil ||
		state.Phase != hostSelfUpdateGrantPhaseConsumed ||
		state.Receipt == nil {
		return errors.New("durable host self-update grant receipt is unavailable")
	}
	state.Phase = hostSelfUpdateGrantPhaseApplied
	return saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		*state,
		!rt.allowTestPaths,
	)
}

func validateHostSelfUpdateGrantReplayBinding(
	policy LocalExecutorPolicy,
	fence LocalExecutorMutationFence,
	operation string,
	request *HostSelfUpdateRequest,
	proof *HostSelfUpdateAgentProof,
	authorization HostSelfUpdateGrantAuthorization,
) error {
	if err := authorization.validate(); err != nil {
		return err
	}
	binding := authorization.Binding
	if binding.Operation != operation ||
		binding.ExecutionHostID != policy.HostID ||
		binding.ExpectedOwnershipEpoch != fence.OwnershipEpoch ||
		binding.ExpectedSourcePolicyRevision != policy.SourcePolicyRevision ||
		binding.ExpectedSourcePolicyRevision != fence.SourcePolicyRevision ||
		binding.ExpectedProjectionRevision != policy.ProjectionRevision ||
		binding.ExpectedProjectionRevision != fence.OwnershipPolicyRevision ||
		binding.ExpectedLocalExecutorPolicyRevision != policy.PolicyRevision ||
		binding.ExpectedLocalExecutorPolicyRevision != fence.ExecutorPolicyRevision {
		return errors.New("host self-update grant replay policy binding is invalid")
	}
	policySHA256, err := policy.SHA256()
	if err != nil ||
		binding.ExpectedLocalExecutorPolicySHA256 != policySHA256 {
		return errors.New("host self-update grant replay policy digest is invalid")
	}
	expected := hostSelfUpdateRequestForGrantBinding(binding)
	if err := expected.validate(); err != nil {
		return errors.New("host self-update grant replay release binding is invalid")
	}
	expectedPlanSHA256, err := hostSelfUpdateGrantPlanSHA256(
		operation,
		HostAgentPolicy{
			SelfUpdateID:       binding.SelfUpdateID,
			SelfUpdateRevision: binding.ExpectedSelfUpdateRevision,
		},
		expected,
		fence,
	)
	if err != nil || binding.PlanSHA256 != expectedPlanSHA256 {
		return errors.New("host self-update grant replay plan binding is invalid")
	}
	switch operation {
	case "stage":
		if request == nil ||
			proof != nil ||
			!sameHostSelfUpdateRequestIdentity(*request, expected) {
			return errors.New("host self-update stage replay binding is invalid")
		}
	case "reconcile":
		if request != nil || proof == nil || proof.validate() != nil {
			return errors.New("host self-update reconcile replay binding is invalid")
		}
		if proof.HeartbeatGeneration != "" &&
			proof.HeartbeatGeneration != expected.Generation {
			return errors.New("host self-update reconcile generation is invalid")
		}
		if proof.PanelHeartbeatVersion != "" &&
			proof.PanelHeartbeatVersion != expected.AgentVersion {
			return errors.New("host self-update reconcile heartbeat version is invalid")
		}
		if proof.FailureCode == "" &&
			proof.RunningAgentVersion != "" &&
			proof.RunningAgentVersion != expected.AgentVersion {
			return errors.New("host self-update reconcile running version is invalid")
		}
	default:
		return errors.New("host self-update grant replay operation is invalid")
	}
	return nil
}

func hostSelfUpdateRequestForGrantBinding(
	binding HostSelfUpdateGrantBinding,
) HostSelfUpdateRequest {
	return HostSelfUpdateRequest{
		Generation:              binding.AttemptGeneration,
		AgentVersion:            binding.AgentVersion,
		ExecutorVersion:         binding.ExecutorVersion,
		Commit:                  binding.ReleaseCommit,
		ArtifactSHA256:          binding.ArtifactSHA256,
		AgentProtocolVersion:    binding.AgentProtocolVersion,
		ExecutorProtocolVersion: binding.ExecutorProtocolVersion,
		MutationProtocolVersion: binding.MutationProtocolVersion,
		RecoveryProtocolVersion: binding.RecoveryProtocolVersion,
		Release:                 binding.Release,
	}
}

func sameHostSelfUpdateRequestIdentity(
	left HostSelfUpdateRequest,
	right HostSelfUpdateRequest,
) bool {
	return left.Generation == right.Generation &&
		left.AgentVersion == right.AgentVersion &&
		left.ExecutorVersion == right.ExecutorVersion &&
		left.Commit == right.Commit &&
		left.ArtifactSHA256 == right.ArtifactSHA256 &&
		left.AgentProtocolVersion == right.AgentProtocolVersion &&
		left.ExecutorProtocolVersion == right.ExecutorProtocolVersion &&
		left.MutationProtocolVersion == right.MutationProtocolVersion &&
		left.RecoveryProtocolVersion == right.RecoveryProtocolVersion &&
		sameHostSelfUpdateReleaseIdentity(left.Release, right.Release)
}

func (rt hostSelfUpdateExecutorRuntime) hostSelfUpdateStateEffectMatchesGrant(
	state HostSelfUpdateState,
	binding HostSelfUpdateGrantBinding,
) bool {
	if state.Phase == HostSelfUpdatePhaseStable &&
		state.FailedGeneration == binding.AttemptGeneration {
		return true
	}
	request := hostSelfUpdateRequestForGrantBinding(binding)
	if request.validate() != nil {
		return false
	}
	slot := state.PendingSlot
	digests := hostSelfUpdateSlotDigests{
		AgentSHA256:    state.PendingAgentSHA256,
		ExecutorSHA256: state.PendingExecutorSHA256,
	}
	if state.Phase == HostSelfUpdatePhaseStable {
		current, err := rt.readCurrentSlot()
		if err != nil ||
			current != state.ActiveSlot ||
			state.ActiveSlot != state.HealthySlot ||
			state.ActiveAgentVersion != binding.AgentVersion ||
			state.ActiveExecutorVersion != binding.ExecutorVersion {
			return false
		}
		slot = state.ActiveSlot
		digests, err = rt.hostSelfUpdateSlotMarkerDigests(slot)
		if err != nil {
			return false
		}
	} else if !hostSelfUpdatePendingMatchesGrant(state, binding) {
		return false
	}
	ctx, cancel := rt.hostSelfUpdateDetachedVerificationContext()
	defer cancel()
	return rt.verifyHostSelfUpdateSlot(
		ctx,
		slot,
		filepath.Join(rt.slotsRoot, slot),
		request,
		digests,
	) == nil
}

func (rt hostSelfUpdateExecutorRuntime) hostSelfUpdateSlotMarkerDigests(
	slot string,
) (hostSelfUpdateSlotDigests, error) {
	if !validHostSelfUpdateSlot(slot) {
		return hostSelfUpdateSlotDigests{},
			errors.New("host self-update grant slot is invalid")
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	var digests hostSelfUpdateSlotDigests
	for _, marker := range []struct {
		name        string
		destination *string
	}{
		{".agent-sha256", &digests.AgentSHA256},
		{".local-executor-sha256", &digests.ExecutorSHA256},
	} {
		body, err := readHostSelfUpdateSlotMarker(
			filepath.Join(slotRoot, marker.name),
			!rt.allowTestPaths,
		)
		if err != nil {
			return hostSelfUpdateSlotDigests{}, err
		}
		*marker.destination = strings.TrimSuffix(string(body), "\n")
	}
	if err := digests.validate(); err != nil {
		return hostSelfUpdateSlotDigests{}, err
	}
	return digests, nil
}

func validateHostSelfUpdateGrantForOperation(
	policy LocalExecutorPolicy,
	fence LocalExecutorMutationFence,
	operation string,
	request *HostSelfUpdateRequest,
	state HostSelfUpdateState,
	authorization HostSelfUpdateGrantAuthorization,
) error {
	if err := authorization.validate(); err != nil {
		return err
	}
	binding := authorization.Binding
	if binding.Operation != operation ||
		binding.ExecutionHostID != policy.HostID ||
		binding.ExpectedOwnershipEpoch != fence.OwnershipEpoch ||
		binding.ExpectedSourcePolicyRevision != policy.SourcePolicyRevision ||
		binding.ExpectedSourcePolicyRevision != fence.SourcePolicyRevision ||
		binding.ExpectedProjectionRevision != policy.ProjectionRevision ||
		binding.ExpectedProjectionRevision != fence.OwnershipPolicyRevision ||
		binding.ExpectedLocalExecutorPolicyRevision != policy.PolicyRevision ||
		binding.ExpectedLocalExecutorPolicyRevision != fence.ExecutorPolicyRevision {
		return errors.New("host self-update grant policy binding is invalid")
	}
	policySHA256, err := policy.SHA256()
	if err != nil ||
		binding.ExpectedLocalExecutorPolicySHA256 != policySHA256 {
		return errors.New("host self-update grant policy digest is invalid")
	}
	var expected HostSelfUpdateRequest
	switch operation {
	case "stage":
		if request == nil ||
			state.Phase != HostSelfUpdatePhaseStable ||
			request.Generation == state.FailedGeneration {
			return errors.New("host self-update stage grant state is invalid")
		}
		expected = *request
	case "reconcile":
		if request != nil ||
			state.Phase == HostSelfUpdatePhaseStable ||
			state.Phase == HostSelfUpdatePhaseStaged {
			return errors.New("host self-update reconcile grant state is invalid")
		}
		expected = HostSelfUpdateRequest{
			Generation:              state.PendingGeneration,
			AgentVersion:            state.PendingAgentVersion,
			ExecutorVersion:         state.PendingExecutorVersion,
			Commit:                  state.PendingCommit,
			ArtifactSHA256:          state.PendingArtifactSHA256,
			AgentProtocolVersion:    state.PendingAgentProtocol,
			ExecutorProtocolVersion: state.PendingExecutorProtocol,
			MutationProtocolVersion: state.PendingMutationProtocol,
			RecoveryProtocolVersion: state.PendingRecoveryProtocol,
			Release:                 state.PendingRelease,
		}
	default:
		return errors.New("host self-update grant operation is invalid")
	}
	if err := expected.validate(); err != nil ||
		binding.AttemptGeneration != expected.Generation ||
		binding.AgentVersion != expected.AgentVersion ||
		binding.ExecutorVersion != expected.ExecutorVersion ||
		binding.ReleaseCommit != expected.Commit ||
		binding.ArtifactSHA256 != expected.ArtifactSHA256 ||
		binding.AgentProtocolVersion != expected.AgentProtocolVersion ||
		binding.ExecutorProtocolVersion != expected.ExecutorProtocolVersion ||
		binding.MutationProtocolVersion != expected.MutationProtocolVersion ||
		binding.RecoveryProtocolVersion != expected.RecoveryProtocolVersion ||
		!sameHostSelfUpdateReleaseIdentity(
			binding.Release,
			expected.Release,
		) {
		return errors.New("host self-update grant release binding is invalid")
	}
	expectedPlanSHA256, err := hostSelfUpdateGrantPlanSHA256(
		operation,
		HostAgentPolicy{
			SelfUpdateID:       binding.SelfUpdateID,
			SelfUpdateRevision: binding.ExpectedSelfUpdateRevision,
		},
		expected,
		fence,
	)
	if err != nil || binding.PlanSHA256 != expectedPlanSHA256 {
		return errors.New("host self-update grant plan binding is invalid")
	}
	return nil
}

func hostSelfUpdatePendingMatchesGrant(
	state HostSelfUpdateState,
	binding HostSelfUpdateGrantBinding,
) bool {
	return state.PendingGeneration == binding.AttemptGeneration &&
		state.PendingAgentVersion == binding.AgentVersion &&
		state.PendingExecutorVersion == binding.ExecutorVersion &&
		state.PendingCommit == binding.ReleaseCommit &&
		state.PendingArtifactSHA256 == binding.ArtifactSHA256 &&
		state.PendingAgentProtocol == binding.AgentProtocolVersion &&
		state.PendingExecutorProtocol == binding.ExecutorProtocolVersion &&
		state.PendingMutationProtocol == binding.MutationProtocolVersion &&
		state.PendingRecoveryProtocol == binding.RecoveryProtocolVersion &&
		sameHostSelfUpdateReleaseIdentity(
			state.PendingRelease,
			binding.Release,
		)
}

func (rt *hostSelfUpdateExecutorRuntime) authorizeHostSelfUpdate(
	ctx context.Context,
	panelURL string,
	authorization HostSelfUpdateGrantAuthorization,
) error {
	next := newHostSelfUpdateGrantState(authorization)
	existing, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil {
		return err
	}
	if existing != nil && existing.matches(authorization) {
		if existing.Phase == hostSelfUpdateGrantPhaseConsumed ||
			existing.Phase == hostSelfUpdateGrantPhaseApplied ||
			existing.Phase == hostSelfUpdateGrantPhaseFailed {
			return nil
		}
		next = *existing
	} else if existing != nil {
		if existing.Phase == hostSelfUpdateGrantPhasePrepared &&
			rt.now().UTC().Before(existing.Binding.ExpiresAt) {
			return errors.New("another host self-update grant consume result is uncertain")
		}
		if existing.Phase == hostSelfUpdateGrantPhaseConsumed {
			return errors.New("a consumed host self-update grant is not durably applied")
		}
	}
	if err := saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		next,
		!rt.allowTestPaths,
	); err != nil {
		return err
	}
	result, err := rt.consumeGrant(ctx, panelURL, authorization)
	if err != nil {
		if ctx.Err() == nil {
			result, err = rt.consumeGrant(ctx, panelURL, authorization)
		}
		if err != nil {
			return errHostSelfUpdateGrantUncertain
		}
	}
	if err := result.Grant.validate(true); err != nil ||
		!sameHostSelfUpdateGrantBinding(
			result.Grant,
			authorization.Binding,
		) {
		return errors.New("host self-update grant consume receipt is invalid")
	}
	next.Phase = hostSelfUpdateGrantPhaseConsumed
	next.Receipt = &result.Grant
	return saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		next,
		!rt.allowTestPaths,
	)
}

func (rt *hostSelfUpdateExecutorRuntime) markHostSelfUpdateGrantApplied(
	authorization HostSelfUpdateGrantAuthorization,
) error {
	state, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil {
		return err
	}
	if state == nil ||
		!state.matches(authorization) {
		return errors.New("host self-update grant apply fence is unavailable")
	}
	if state.Phase == hostSelfUpdateGrantPhaseApplied {
		return nil
	}
	if state.Phase != hostSelfUpdateGrantPhaseConsumed {
		return errors.New("host self-update grant was not consumed")
	}
	state.Phase = hostSelfUpdateGrantPhaseApplied
	return saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		*state,
		!rt.allowTestPaths,
	)
}

func (rt *hostSelfUpdateExecutorRuntime) hostSelfUpdateGrantApplied(
	authorization HostSelfUpdateGrantAuthorization,
) (bool, error) {
	phase, matches, err := rt.hostSelfUpdateGrantPhase(authorization)
	return matches && phase == hostSelfUpdateGrantPhaseApplied, err
}

func (rt *hostSelfUpdateExecutorRuntime) hostSelfUpdateGrantPhase(
	authorization HostSelfUpdateGrantAuthorization,
) (string, bool, error) {
	state, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		!rt.allowTestPaths,
	)
	if err != nil {
		return "", false, err
	}
	if state == nil || !state.matches(authorization) {
		return "", false, nil
	}
	return state.Phase, true, nil
}
