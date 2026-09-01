package hostruntime

import (
	"errors"
	"strings"
	"time"
)

const (
	RuntimeCredentialPhaseClaimPrepared   = "claim_prepared"
	RuntimeCredentialPhaseStageBound      = "stage_bound"
	RuntimeCredentialPhaseStaged          = "staged"
	RuntimeCredentialPhaseLocalStaged     = "local_staged"
	RuntimeCredentialPhaseProofReady      = "proof_ready"
	RuntimeCredentialPhaseActivated       = "activated"
	RuntimeCredentialPhaseCancelReady     = "cancel_ready"
	RuntimeCredentialPhaseCancelled       = "cancelled"
	RuntimeCredentialPhaseExpired         = "expired"
	RuntimeCredentialPhaseManualRecovered = "manual_recovered"
)

const runtimeCredentialStateSchemaVersion = 2

// HostAgentRuntimeTokenRotation is the public, secret-free rotation directive
// returned in the Host Agent policy and by the dedicated rotation endpoints.
// Every revision and ownership field is server-owned.
type HostAgentRuntimeTokenRotation struct {
	ID                                  string     `json:"id"`
	ServiceID                           string     `json:"service_id"`
	ExecutionHostID                     string     `json:"execution_host_id"`
	Status                              string     `json:"status"`
	Revision                            int64      `json:"revision"`
	ExpectedOwnershipEpoch              int64      `json:"expected_ownership_epoch"`
	ExpectedSourcePolicyRevision        int64      `json:"expected_source_policy_revision"`
	ExpectedProjectionRevision          int64      `json:"expected_projection_revision"`
	ExpectedLocalExecutorPolicyRevision int64      `json:"expected_local_executor_policy_revision"`
	PreviousTokenID                     string     `json:"previous_token_id"`
	StagedTokenID                       string     `json:"staged_token_id"`
	CredentialClaimedAt                 *time.Time `json:"credential_claimed_at,omitempty"`
	LocalStageReceiptID                 string     `json:"local_stage_receipt_id,omitempty"`
	LocalStageAcknowledgedAt            *time.Time `json:"local_stage_acknowledged_at,omitempty"`
	LocalStagedAt                       *time.Time `json:"local_staged_at,omitempty"`
	HeartbeatProvedAt                   *time.Time `json:"heartbeat_proved_at,omitempty"`
	ActivatedAt                         *time.Time `json:"activated_at,omitempty"`
	CancelRequestedAt                   *time.Time `json:"cancel_requested_at,omitempty"`
	CanceledAt                          *time.Time `json:"canceled_at,omitempty"`
	EmergencyRevokedTokenID             string     `json:"emergency_revoked_token_id,omitempty"`
	EmergencyRevokedAt                  *time.Time `json:"emergency_revoked_at,omitempty"`
	CreatedAt                           *time.Time `json:"created_at,omitempty"`
	UpdatedAt                           *time.Time `json:"updated_at,omitempty"`
}

func (r HostAgentRuntimeTokenRotation) Validate() error {
	if !identifierPattern.MatchString(r.ID) ||
		!identifierPattern.MatchString(r.ServiceID) ||
		!validExecutionHostID(r.ExecutionHostID) ||
		!identifierPattern.MatchString(r.PreviousTokenID) ||
		!identifierPattern.MatchString(r.StagedTokenID) ||
		r.PreviousTokenID == r.StagedTokenID ||
		r.Revision < 1 ||
		r.ExpectedOwnershipEpoch < 1 ||
		r.ExpectedSourcePolicyRevision < 1 ||
		r.ExpectedProjectionRevision < 1 ||
		r.ExpectedLocalExecutorPolicyRevision < 1 {
		return errors.New("runtime token rotation directive binding is invalid")
	}
	for _, value := range []string{
		r.ID, r.ServiceID, r.ExecutionHostID, r.PreviousTokenID, r.StagedTokenID,
	} {
		if value != strings.TrimSpace(value) {
			return errors.New("runtime token rotation directive is not canonical")
		}
	}
	switch r.Status {
	case "staged":
	case "local_staged":
		if r.CredentialClaimedAt == nil ||
			r.LocalStageReceiptID == "" ||
			r.LocalStageAcknowledgedAt == nil {
			return errors.New("runtime token rotation local-stage proof is incomplete")
		}
	case "heartbeat_proved":
		if r.CredentialClaimedAt == nil ||
			r.LocalStageReceiptID == "" ||
			r.LocalStageAcknowledgedAt == nil {
			return errors.New("runtime token rotation heartbeat proof is incomplete")
		}
	case "activated":
		if r.CredentialClaimedAt == nil ||
			r.LocalStageReceiptID == "" ||
			r.LocalStageAcknowledgedAt == nil {
			return errors.New("activated runtime token rotation proof is incomplete")
		}
	case "cancel_requested":
		if r.CredentialClaimedAt == nil || r.CancelRequestedAt == nil {
			return errors.New("runtime token rotation cancel request is incomplete")
		}
	case "canceled":
	default:
		return errors.New("runtime token rotation directive status is invalid")
	}
	if (r.LocalStageReceiptID == "") != (r.LocalStageAcknowledgedAt == nil) ||
		(r.LocalStageReceiptID != "" && !identifierPattern.MatchString(r.LocalStageReceiptID)) {
		return errors.New("runtime token rotation local-stage receipt is invalid")
	}
	if (r.EmergencyRevokedTokenID == "") !=
		(r.EmergencyRevokedAt == nil) ||
		(r.EmergencyRevokedTokenID != "" &&
			r.EmergencyRevokedTokenID != r.PreviousTokenID &&
			r.EmergencyRevokedTokenID != r.StagedTokenID) {
		return errors.New("runtime token rotation emergency revoke proof is invalid")
	}
	for _, value := range []*time.Time{
		r.CredentialClaimedAt,
		r.LocalStageAcknowledgedAt,
		r.LocalStagedAt,
		r.HeartbeatProvedAt,
		r.ActivatedAt,
		r.CancelRequestedAt,
		r.CanceledAt,
		r.EmergencyRevokedAt,
		r.CreatedAt,
		r.UpdatedAt,
	} {
		if value != nil && (value.IsZero() || value.Location() != time.UTC) {
			return errors.New("runtime token rotation timestamp is invalid")
		}
	}
	if r.CredentialClaimedAt != nil &&
		r.LocalStageAcknowledgedAt != nil &&
		r.LocalStageAcknowledgedAt.Before(*r.CredentialClaimedAt) {
		return errors.New("runtime token rotation timestamps are out of order")
	}
	return nil
}

// RuntimeCredentialMutation is the bounded UDS binding for one fixed Host
// Agent identity rotation. RuntimeToken is used only by the stage operation;
// its custom formatting and JSON representation are redacted.
type RuntimeCredentialMutation struct {
	RotationID       string        `json:"rotation_id"`
	ExecutionHostID  string        `json:"execution_host_id"`
	PreviousTokenID  string        `json:"previous_token_id"`
	StagedTokenID    string        `json:"staged_token_id"`
	RotationRevision int64         `json:"rotation_revision"`
	RuntimeToken     BoundedSecret `json:"runtime_token,omitempty"`
}

func (m RuntimeCredentialMutation) validate(operation string) error {
	if !identifierPattern.MatchString(m.RotationID) ||
		!validExecutionHostID(m.ExecutionHostID) ||
		!identifierPattern.MatchString(m.PreviousTokenID) ||
		!identifierPattern.MatchString(m.StagedTokenID) ||
		m.PreviousTokenID == m.StagedTokenID ||
		m.RotationRevision < 1 {
		return errors.New("runtime credential mutation binding is invalid")
	}
	for _, value := range []string{
		m.RotationID, m.ExecutionHostID, m.PreviousTokenID, m.StagedTokenID,
	} {
		if value != strings.TrimSpace(value) {
			return errors.New("runtime credential mutation is not canonical")
		}
	}
	if operation == "runtime_credential_stage" {
		if !validBoundedSecret(m.RuntimeToken.Reveal()) {
			return errors.New("runtime credential stage requires a bounded credential")
		}
	} else if !m.RuntimeToken.Empty() {
		return errors.New("runtime credential operation must not include a credential")
	}
	return nil
}

// RuntimeCredentialStatus is durable secret-free Local Executor state. The
// raw current and staged runtime tokens exist only in their two fixed identity
// files and in bounded process memory.
type RuntimeCredentialStatus struct {
	SchemaVersion               int       `json:"schema_version"`
	Phase                       string    `json:"phase"`
	RotationID                  string    `json:"rotation_id"`
	ServiceID                   string    `json:"service_id"`
	ExecutionHostID             string    `json:"execution_host_id"`
	PreviousTokenID             string    `json:"previous_token_id"`
	StagedTokenID               string    `json:"staged_token_id"`
	RotationRevision            int64     `json:"rotation_revision"`
	OwnershipEpoch              int64     `json:"ownership_epoch"`
	SourcePolicyRevision        int64     `json:"source_policy_revision"`
	ProjectionRevision          int64     `json:"projection_revision"`
	LocalExecutorPolicyRevision int64     `json:"local_executor_policy_revision"`
	StagedIdentitySHA256        string    `json:"staged_identity_sha256"`
	PreviousIdentitySHA256      string    `json:"previous_identity_sha256"`
	ActiveIdentitySHA256        string    `json:"active_identity_sha256,omitempty"`
	LocalExecutorPolicySHA256   string    `json:"local_executor_policy_sha256"`
	ExecutorVersion             string    `json:"executor_version"`
	ExecutorProtocolVersion     int       `json:"executor_protocol_version"`
	MutationProtocolVersion     int       `json:"mutation_protocol_version"`
	LocalStageReceiptID         string    `json:"local_stage_receipt_id,omitempty"`
	StagedExpiresAt             time.Time `json:"staged_expires_at"`
	// These root-ledger-only bindings are intentionally omitted from the UDS
	// response. They prove that emergency replacement uses neither revoked
	// bearer even when the JSON bytes or service name are reformatted.
	previousRuntimeTokenSHA256 string
	stagedRuntimeTokenSHA256   string
	activeRuntimeTokenSHA256   string
	serviceName                string
}

func (s RuntimeCredentialStatus) Validate() error {
	if s.SchemaVersion != runtimeCredentialStateSchemaVersion ||
		!identifierPattern.MatchString(s.RotationID) ||
		!identifierPattern.MatchString(s.ServiceID) ||
		!validExecutionHostID(s.ExecutionHostID) ||
		!identifierPattern.MatchString(s.PreviousTokenID) ||
		!identifierPattern.MatchString(s.StagedTokenID) ||
		s.PreviousTokenID == s.StagedTokenID ||
		s.RotationRevision < 1 ||
		s.OwnershipEpoch < 1 ||
		s.SourcePolicyRevision < 1 ||
		s.ProjectionRevision < 1 ||
		s.LocalExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(s.StagedIdentitySHA256) ||
		!digestPattern.MatchString(s.PreviousIdentitySHA256) ||
		!digestPattern.MatchString(s.LocalExecutorPolicySHA256) ||
		!versionPattern.MatchString(s.ExecutorVersion) ||
		s.ExecutorProtocolVersion != LocalExecutorMutationProtocolVersion ||
		s.MutationProtocolVersion != LocalExecutorMutationProtocolVersion {
		return errors.New("runtime credential state binding is invalid")
	}
	if s.StagedExpiresAt.IsZero() ||
		s.StagedExpiresAt.Location() != time.UTC {
		return errors.New("runtime credential staged expiry is invalid")
	}
	for _, value := range []string{
		s.RotationID, s.ServiceID, s.ExecutionHostID,
		s.PreviousTokenID, s.StagedTokenID,
	} {
		if value != strings.TrimSpace(value) {
			return errors.New("runtime credential state is not canonical")
		}
	}
	switch s.Phase {
	case RuntimeCredentialPhaseClaimPrepared:
		if s.LocalStageReceiptID != "" ||
			s.ActiveIdentitySHA256 != "" ||
			s.StagedIdentitySHA256 != runtimeCredentialDigest(nil) {
			return errors.New(
				"prepared runtime credential state is invalid",
			)
		}
	case RuntimeCredentialPhaseStageBound,
		RuntimeCredentialPhaseStaged:
		if s.LocalStageReceiptID != "" {
			return errors.New("unacknowledged runtime credential has a receipt")
		}
		if s.ActiveIdentitySHA256 != "" {
			return errors.New("unactivated runtime credential state contains an active digest")
		}
	case RuntimeCredentialPhaseLocalStaged, RuntimeCredentialPhaseProofReady:
		if !identifierPattern.MatchString(s.LocalStageReceiptID) {
			return errors.New("runtime credential local-stage receipt is invalid")
		}
		if s.ActiveIdentitySHA256 != "" {
			return errors.New("unactivated runtime credential state contains an active digest")
		}
	case RuntimeCredentialPhaseActivated:
		if s.ActiveIdentitySHA256 != s.StagedIdentitySHA256 ||
			!identifierPattern.MatchString(s.LocalStageReceiptID) {
			return errors.New("activated runtime credential state digest is invalid")
		}
	case RuntimeCredentialPhaseCancelReady:
		if s.ActiveIdentitySHA256 != s.PreviousIdentitySHA256 {
			return errors.New("cancel-ready runtime credential active digest is invalid")
		}
	case RuntimeCredentialPhaseCancelled:
		if s.ActiveIdentitySHA256 != s.PreviousIdentitySHA256 {
			return errors.New("cancelled runtime credential active digest is invalid")
		}
	case RuntimeCredentialPhaseExpired:
		if s.ActiveIdentitySHA256 != s.PreviousIdentitySHA256 {
			return errors.New("expired runtime credential active digest is invalid")
		}
	case RuntimeCredentialPhaseManualRecovered:
		if !digestPattern.MatchString(s.ActiveIdentitySHA256) ||
			s.ActiveIdentitySHA256 == s.PreviousIdentitySHA256 ||
			s.ActiveIdentitySHA256 == s.StagedIdentitySHA256 {
			return errors.New(
				"manually recovered runtime credential active digest is invalid",
			)
		}
	default:
		return errors.New("runtime credential state phase is invalid")
	}
	return nil
}

func (s RuntimeCredentialStatus) validateRootTokenBindings() error {
	if !digestPattern.MatchString(s.previousRuntimeTokenSHA256) ||
		(s.stagedRuntimeTokenSHA256 != "" &&
			!digestPattern.MatchString(s.stagedRuntimeTokenSHA256)) ||
		len(s.serviceName) > 255 {
		return errors.New(
			"runtime credential root token binding is invalid",
		)
	}
	switch s.Phase {
	case RuntimeCredentialPhaseClaimPrepared:
	case RuntimeCredentialPhaseStageBound,
		RuntimeCredentialPhaseStaged,
		RuntimeCredentialPhaseLocalStaged,
		RuntimeCredentialPhaseProofReady,
		RuntimeCredentialPhaseActivated:
		if !digestPattern.MatchString(s.stagedRuntimeTokenSHA256) {
			return errors.New(
				"runtime credential staged token binding is invalid",
			)
		}
	}
	switch s.Phase {
	case RuntimeCredentialPhaseActivated:
		if s.activeRuntimeTokenSHA256 !=
			s.stagedRuntimeTokenSHA256 {
			return errors.New(
				"runtime credential active token binding is invalid",
			)
		}
	case RuntimeCredentialPhaseCancelReady,
		RuntimeCredentialPhaseCancelled,
		RuntimeCredentialPhaseExpired:
		if s.activeRuntimeTokenSHA256 !=
			s.previousRuntimeTokenSHA256 {
			return errors.New(
				"runtime credential previous token binding is invalid",
			)
		}
	case RuntimeCredentialPhaseManualRecovered:
		if !digestPattern.MatchString(s.activeRuntimeTokenSHA256) ||
			s.activeRuntimeTokenSHA256 ==
				s.previousRuntimeTokenSHA256 ||
			(s.stagedRuntimeTokenSHA256 != "" &&
				s.activeRuntimeTokenSHA256 ==
					s.stagedRuntimeTokenSHA256) {
			return errors.New(
				"manually recovered runtime token binding is invalid",
			)
		}
	}
	return nil
}
