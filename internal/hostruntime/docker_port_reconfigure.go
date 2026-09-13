package hostruntime

import (
	"errors"
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
	PolicyTransition    *portPolicyTransitionState    `json:"policy_transition,omitempty"`
}

func (l dockerPortLedger) validate(targetID string) error {
	if l.Plan.PortContractVersion == 2 {
		return l.validatePortV2(targetID)
	}
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
	PortContractVersion    int    `json:"port_contract_version,omitempty"`
	PortJobID              string `json:"port_job_id,omitempty"`
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
	if a.PortContractVersion != 0 && (a.PortContractVersion != 2 || !identifierPattern.MatchString(a.PortJobID)) || a.PortContractVersion == 0 && a.PortJobID != "" {
		return errors.New("Docker applied port transaction reference is invalid")
	}
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
