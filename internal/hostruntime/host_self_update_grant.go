package hostruntime

import (
	"errors"
	"fmt"
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
