package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// SoftwareUpdateJobBinding keeps application configuration C separate from
// the authenticated host policy S/P/E/D. The command digest is the original
// Contracts digest; it is not the local mutation plan hash.
type SoftwareUpdateJobBinding struct {
	ConfigRevision         int64  `json:"config_revision"`
	ConfigSHA256           string `json:"config_sha256,omitempty"`
	CommandSHA256          string `json:"command_sha256"`
	SourcePolicyRevision   int64  `json:"source_policy_revision,omitempty"`
	ProjectionRevision     int64  `json:"projection_revision,omitempty"`
	ExecutorPolicyRevision int64  `json:"executor_policy_revision,omitempty"`
	ExecutorPolicySHA256   string `json:"executor_policy_sha256,omitempty"`
}

func (b *SoftwareUpdateJobBinding) UnmarshalJSON(data []byte) error {
	type binding SoftwareUpdateJobBinding
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded binding
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("software claim binding is invalid")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("software claim binding contains trailing data")
	}
	*b = SoftwareUpdateJobBinding(decoded)
	return b.validateIntent()
}

func (b SoftwareUpdateJobBinding) validateIntent() error {
	if b.ConfigRevision < 1 || !digestPattern.MatchString(b.CommandSHA256) ||
		(b.ConfigSHA256 != "" && !digestPattern.MatchString(b.ConfigSHA256)) {
		return errors.New("software configuration or command binding is invalid")
	}
	if b.SourcePolicyRevision == 0 && b.ProjectionRevision == 0 && b.ExecutorPolicyRevision == 0 && b.ExecutorPolicySHA256 == "" {
		return nil // A rejected, nonexecuting claim can retain its wire intent.
	}
	return b.Validate()
}

func (b SoftwareUpdateJobBinding) Validate() error {
	if b.ConfigRevision < 1 || !digestPattern.MatchString(b.CommandSHA256) ||
		(b.ConfigSHA256 != "" && !digestPattern.MatchString(b.ConfigSHA256)) ||
		b.SourcePolicyRevision < 1 || b.ProjectionRevision < 1 || b.ExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(b.ExecutorPolicySHA256) {
		return errors.New("software claim policy snapshot is incomplete")
	}
	return nil
}

func isV2SoftwareJob(job UpdateJob) bool {
	return job.ProtocolVersion == 2 && job.EffectiveOperation() == updateJobOperationSoftwareUpdate
}

func softwareClaimPolicyMatches(job UpdateJob, policy HostAgentPolicy, target HostAgentPolicyTarget) bool {
	b := job.SoftwareUpdate
	return b != nil && b.Validate() == nil && job.PolicyRevision == b.ProjectionRevision &&
		b.SourcePolicyRevision == policy.SourcePolicyRevision && b.ProjectionRevision == policy.Revision &&
		b.ExecutorPolicyRevision == policy.LocalExecutorPolicyRevision && b.ExecutorPolicySHA256 == policy.LocalExecutorPolicySHA256 &&
		b.ConfigRevision == target.appliedConfigRevision() && b.ConfigSHA256 == target.AppliedConfigSHA256
}

func softwareClaimFence(job UpdateJob, binding HostAgentBinding, policy HostAgentPolicy) LocalExecutorMutationFence {
	fence := LocalExecutorMutationFence{SourcePolicyRevision: policy.SourcePolicyRevision, OwnershipEpoch: binding.OwnershipEpoch,
		OwnershipPolicyRevision: job.PolicyRevision, ExecutorPolicyRevision: policy.LocalExecutorPolicyRevision}
	if isV2SoftwareJob(job) && job.SoftwareUpdate != nil {
		fence.SourcePolicyRevision = job.SoftwareUpdate.SourcePolicyRevision
		fence.OwnershipPolicyRevision = job.SoftwareUpdate.ProjectionRevision
		fence.ExecutorPolicyRevision = job.SoftwareUpdate.ExecutorPolicyRevision
		fence.OwnershipEpoch = job.OwnershipEpoch
	}
	return fence
}
