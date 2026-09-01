package hostruntime

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	HostSelfUpdateInstallRoot = "/opt/autostream/host-agent"
	HostSelfUpdateCurrentLink = "/opt/autostream/host-agent/current"
	HostSelfUpdateSlotsRoot   = "/opt/autostream/host-agent/slots"
	HostSelfUpdateStateRoot   = "/var/lib/autostream-local-executor/host-self-update"
	HostSelfUpdateStatePath   = "/var/lib/autostream-local-executor/host-self-update/state.json"

	HostSelfUpdateSlotA = "a"
	HostSelfUpdateSlotB = "b"

	HostSelfUpdatePhaseStable      = "stable"
	HostSelfUpdatePhaseStaged      = "staged"
	HostSelfUpdatePhaseActivating  = "activating"
	HostSelfUpdatePhaseVerifying   = "verifying"
	HostSelfUpdatePhaseRollingBack = "rolling_back"

	HostSelfUpdateActionNone             = "none"
	HostSelfUpdateActionSwitchCurrent    = "switch_current"
	HostSelfUpdateActionRestartAgent     = "restart_agent"
	HostSelfUpdateActionAwaitProof       = "await_proof"
	HostSelfUpdateActionProbeExecutor    = "probe_executor"
	HostSelfUpdateActionCommit           = "commit"
	HostSelfUpdateActionRestoreHealthy   = "restore_healthy"
	HostSelfUpdateActionRestartHealthy   = "restart_healthy"
	HostSelfUpdateActionRollbackComplete = "rollback_complete"
)

const (
	hostSelfUpdateStateSchemaVersion      = 2
	HostSelfUpdateRecoveryProtocolVersion = 2
)

// HostLifecycleBlockers is the shared fail-closed gate for identity and binary
// lifecycle changes. ConsumedMutationRollbackPending is deliberately not a
// blocker for an emergency credential revoke: rollback is authorized by the
// already-consumed root-local grant, not by a live Control Panel credential.
type HostLifecycleBlockers struct {
	ActiveJob                       bool
	MutationInProgress              bool
	RecoveryPending                 bool
	TokenRotationPending            bool
	SelfUpdatePending               bool
	ConsumedMutationRollbackPending bool
}

func (b HostLifecycleBlockers) mutationBlocked() bool {
	return b.ActiveJob ||
		b.MutationInProgress ||
		b.RecoveryPending ||
		b.TokenRotationPending ||
		b.SelfUpdatePending
}

type HostRuntimeCompatibility struct {
	AgentVersion            string `json:"agent_version"`
	ExecutorVersion         string `json:"executor_version"`
	AgentProtocolVersion    int    `json:"agent_protocol_version"`
	ExecutorProtocolVersion int    `json:"executor_protocol_version"`
	MutationProtocolVersion int    `json:"mutation_protocol_version"`
	RecoveryProtocolVersion int    `json:"recovery_protocol_version"`
}

type HostRuntimeRequirement struct {
	MinimumAgentVersion     string `json:"minimum_agent_version"`
	MinimumExecutorVersion  string `json:"minimum_executor_version"`
	AgentProtocolVersion    int    `json:"agent_protocol_version"`
	ExecutorProtocolVersion int    `json:"executor_protocol_version"`
	MutationProtocolVersion int    `json:"mutation_protocol_version"`
	RecoveryProtocolVersion int    `json:"recovery_protocol_version"`
}

func (r HostRuntimeRequirement) validate() error {
	if !versionPattern.MatchString(strings.TrimSpace(r.MinimumAgentVersion)) ||
		!versionPattern.MatchString(strings.TrimSpace(r.MinimumExecutorVersion)) ||
		r.MinimumAgentVersion != strings.TrimSpace(r.MinimumAgentVersion) ||
		r.MinimumExecutorVersion != strings.TrimSpace(r.MinimumExecutorVersion) ||
		r.AgentProtocolVersion < 1 ||
		r.ExecutorProtocolVersion < 1 ||
		r.MutationProtocolVersion < 1 ||
		r.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion {
		return errors.New("host runtime requirement is invalid")
	}
	return nil
}

// ValidateHostRuntimeCompatibility is intended to run before a Host Agent is
// considered claim-capable. A process version alone is insufficient: the
// root-local executor and both privileged protocol generations must match.
func ValidateHostRuntimeCompatibility(
	current HostRuntimeCompatibility,
	requirement HostRuntimeRequirement,
) error {
	if err := requirement.validate(); err != nil {
		return err
	}
	if !versionPattern.MatchString(strings.TrimSpace(current.AgentVersion)) ||
		!versionPattern.MatchString(strings.TrimSpace(current.ExecutorVersion)) ||
		!versionPattern.MatchString(strings.TrimSpace(requirement.MinimumAgentVersion)) ||
		!versionPattern.MatchString(strings.TrimSpace(requirement.MinimumExecutorVersion)) {
		return errors.New("host runtime version compatibility is invalid")
	}
	if !updaterReleaseSemverAtLeast(current.AgentVersion, requirement.MinimumAgentVersion) {
		return fmt.Errorf("host agent %s is older than required %s", current.AgentVersion, requirement.MinimumAgentVersion)
	}
	if !updaterReleaseSemverAtLeast(current.ExecutorVersion, requirement.MinimumExecutorVersion) {
		return fmt.Errorf("local executor %s is older than required %s", current.ExecutorVersion, requirement.MinimumExecutorVersion)
	}
	if requirement.AgentProtocolVersion < 1 ||
		requirement.ExecutorProtocolVersion < 1 ||
		requirement.MutationProtocolVersion < 1 ||
		requirement.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion ||
		current.AgentProtocolVersion != requirement.AgentProtocolVersion ||
		current.ExecutorProtocolVersion != requirement.ExecutorProtocolVersion ||
		current.MutationProtocolVersion != requirement.MutationProtocolVersion ||
		current.RecoveryProtocolVersion != requirement.RecoveryProtocolVersion {
		return errors.New("host runtime protocol compatibility is not satisfied")
	}
	return nil
}

// HostSelfUpdateReleaseIdentity is the immutable, credential-free release
// projection resolved by the Control Panel and independently re-resolved by
// the root executor. Asset URLs are intentionally absent.
type HostSelfUpdateReleaseIdentity struct {
	Tag                     string    `json:"tag"`
	Commit                  string    `json:"commit"`
	PublishedAt             time.Time `json:"published_at"`
	ManifestAssetID         int64     `json:"manifest_asset_id"`
	ManifestAssetName       string    `json:"manifest_asset_name"`
	ManifestSHA256          string    `json:"manifest_sha256"`
	ManifestChecksumAssetID int64     `json:"manifest_checksum_asset_id"`
	ManifestChecksumSHA256  string    `json:"manifest_checksum_sha256"`
	ArchiveAssetID          int64     `json:"archive_asset_id"`
	ArchiveAssetName        string    `json:"archive_asset_name"`
	ArchiveSize             int64     `json:"archive_size"`
	ArchiveSHA256           string    `json:"archive_sha256"`
	ArchiveChecksumAssetID  int64     `json:"archive_checksum_asset_id"`
	ArchiveChecksumSHA256   string    `json:"archive_checksum_sha256"`
	Arch                    string    `json:"arch"`
	AgentProtocolVersion    int       `json:"agent_protocol_version"`
	ExecutorProtocolVersion int       `json:"executor_protocol_version"`
	MutationProtocolVersion int       `json:"mutation_protocol_version"`
	RecoveryProtocolVersion int       `json:"recovery_protocol_version"`
	MinimumPanelVersion     string    `json:"minimum_panel_version"`
}

func (r HostSelfUpdateReleaseIdentity) validate() error {
	assetIDs := []int64{
		r.ManifestAssetID,
		r.ManifestChecksumAssetID,
		r.ArchiveAssetID,
		r.ArchiveChecksumAssetID,
	}
	seenAssetIDs := make(map[int64]struct{}, len(assetIDs))
	for _, id := range assetIDs {
		if id < 1 {
			return errors.New("host self-update release asset identity is invalid")
		}
		if _, exists := seenAssetIDs[id]; exists {
			return errors.New("host self-update release asset identity is duplicated")
		}
		seenAssetIDs[id] = struct{}{}
	}
	if !versionPattern.MatchString(r.Tag) ||
		!updaterReleaseCommitPattern.MatchString(r.Commit) ||
		r.PublishedAt.IsZero() ||
		r.PublishedAt.Location() != time.UTC ||
		r.ManifestAssetName != hostAgentManifestName ||
		r.ArchiveAssetName != hostAgentReleaseAssetName(r.Tag, r.Arch) ||
		!mutationPlanHashPattern.MatchString(r.ManifestSHA256) ||
		!mutationPlanHashPattern.MatchString(r.ManifestChecksumSHA256) ||
		r.ArchiveSize < 1 ||
		r.ArchiveSize > defaultMaxArtifactBytes ||
		!mutationPlanHashPattern.MatchString(r.ArchiveSHA256) ||
		!mutationPlanHashPattern.MatchString(r.ArchiveChecksumSHA256) ||
		(r.Arch != "amd64" && r.Arch != "arm64") ||
		r.AgentProtocolVersion < 1 ||
		r.ExecutorProtocolVersion < 1 ||
		r.MutationProtocolVersion < 1 ||
		r.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion ||
		!versionPattern.MatchString(r.MinimumPanelVersion) {
		return errors.New("host self-update release identity is invalid")
	}
	return nil
}

func (r HostSelfUpdateReleaseIdentity) matchesRequest(
	request HostSelfUpdateRequest,
) bool {
	return r.Tag == request.AgentVersion &&
		r.Commit == request.Commit &&
		r.ArchiveSHA256 == strings.TrimPrefix(
			request.ArtifactSHA256,
			"sha256:",
		) &&
		r.AgentProtocolVersion == request.AgentProtocolVersion &&
		r.ExecutorProtocolVersion == request.ExecutorProtocolVersion &&
		r.MutationProtocolVersion == request.MutationProtocolVersion &&
		r.RecoveryProtocolVersion == request.RecoveryProtocolVersion
}

func sameHostSelfUpdateReleaseIdentity(
	left, right HostSelfUpdateReleaseIdentity,
) bool {
	return left.Tag == right.Tag &&
		left.Commit == right.Commit &&
		left.PublishedAt.Equal(right.PublishedAt) &&
		left.ManifestAssetID == right.ManifestAssetID &&
		left.ManifestAssetName == right.ManifestAssetName &&
		left.ManifestSHA256 == right.ManifestSHA256 &&
		left.ManifestChecksumAssetID == right.ManifestChecksumAssetID &&
		left.ManifestChecksumSHA256 == right.ManifestChecksumSHA256 &&
		left.ArchiveAssetID == right.ArchiveAssetID &&
		left.ArchiveAssetName == right.ArchiveAssetName &&
		left.ArchiveSize == right.ArchiveSize &&
		left.ArchiveSHA256 == right.ArchiveSHA256 &&
		left.ArchiveChecksumAssetID == right.ArchiveChecksumAssetID &&
		left.ArchiveChecksumSHA256 == right.ArchiveChecksumSHA256 &&
		left.Arch == right.Arch &&
		left.AgentProtocolVersion == right.AgentProtocolVersion &&
		left.ExecutorProtocolVersion == right.ExecutorProtocolVersion &&
		left.MutationProtocolVersion == right.MutationProtocolVersion &&
		left.RecoveryProtocolVersion == right.RecoveryProtocolVersion &&
		left.MinimumPanelVersion == right.MinimumPanelVersion
}

type HostSelfUpdateRequest struct {
	Generation              string                        `json:"generation"`
	AgentVersion            string                        `json:"agent_version"`
	ExecutorVersion         string                        `json:"executor_version"`
	Commit                  string                        `json:"commit"`
	ArtifactSHA256          string                        `json:"artifact_sha256"`
	AgentProtocolVersion    int                           `json:"agent_protocol_version"`
	ExecutorProtocolVersion int                           `json:"executor_protocol_version"`
	MutationProtocolVersion int                           `json:"mutation_protocol_version"`
	RecoveryProtocolVersion int                           `json:"recovery_protocol_version"`
	Release                 HostSelfUpdateReleaseIdentity `json:"release"`
}

func (r HostSelfUpdateRequest) validate() error {
	if !identifierPattern.MatchString(strings.TrimSpace(r.Generation)) ||
		!versionPattern.MatchString(strings.TrimSpace(r.AgentVersion)) ||
		!versionPattern.MatchString(strings.TrimSpace(r.ExecutorVersion)) ||
		!updaterReleaseCommitPattern.MatchString(strings.TrimSpace(r.Commit)) ||
		!digestPattern.MatchString(strings.TrimSpace(r.ArtifactSHA256)) ||
		r.AgentProtocolVersion < 1 ||
		r.ExecutorProtocolVersion < 1 ||
		r.MutationProtocolVersion < 1 ||
		r.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion ||
		r.Release.validate() != nil ||
		!r.Release.matchesRequest(r) {
		return errors.New("host self-update request is invalid")
	}
	if r.Generation != strings.TrimSpace(r.Generation) ||
		r.AgentVersion != strings.TrimSpace(r.AgentVersion) ||
		r.ExecutorVersion != strings.TrimSpace(r.ExecutorVersion) ||
		r.Commit != strings.TrimSpace(r.Commit) ||
		r.ArtifactSHA256 != strings.TrimSpace(r.ArtifactSHA256) {
		return errors.New("host self-update request is not canonical")
	}
	return nil
}

type HostSelfUpdateState struct {
	SchemaVersion           int    `json:"schema_version"`
	RecoveryProtocolVersion int    `json:"recovery_protocol_version"`
	Phase                   string `json:"phase"`

	ActiveSlot              string `json:"active_slot"`
	HealthySlot             string `json:"healthy_slot"`
	RollbackSlot            string `json:"rollback_slot,omitempty"`
	ActiveAgentVersion      string `json:"active_agent_version"`
	ActiveExecutorVersion   string `json:"active_executor_version"`
	RollbackAgentVersion    string `json:"rollback_agent_version,omitempty"`
	RollbackExecutorVersion string `json:"rollback_executor_version,omitempty"`
	FailedGeneration        string `json:"failed_generation,omitempty"`

	PendingSlot             string                        `json:"pending_slot,omitempty"`
	PendingGeneration       string                        `json:"pending_generation,omitempty"`
	PendingAgentVersion     string                        `json:"pending_agent_version,omitempty"`
	PendingExecutorVersion  string                        `json:"pending_executor_version,omitempty"`
	PendingCommit           string                        `json:"pending_commit,omitempty"`
	PendingArtifactSHA256   string                        `json:"pending_artifact_sha256,omitempty"`
	PendingAgentSHA256      string                        `json:"pending_agent_sha256,omitempty"`
	PendingExecutorSHA256   string                        `json:"pending_executor_sha256,omitempty"`
	PendingAgentProtocol    int                           `json:"pending_agent_protocol,omitempty"`
	PendingExecutorProtocol int                           `json:"pending_executor_protocol,omitempty"`
	PendingMutationProtocol int                           `json:"pending_mutation_protocol,omitempty"`
	PendingRecoveryProtocol int                           `json:"pending_recovery_protocol,omitempty"`
	PendingRelease          HostSelfUpdateReleaseIdentity `json:"pending_release,omitempty"`
	ActivationStartedAt     time.Time                     `json:"activation_started_at,omitempty"`
	ActivationDeadline      time.Time                     `json:"activation_deadline,omitempty"`
}

type hostSelfUpdateSlotDigests struct {
	AgentSHA256    string
	ExecutorSHA256 string
}

func (d hostSelfUpdateSlotDigests) validate() error {
	if !isCanonicalBareSHA256(d.AgentSHA256) ||
		!isCanonicalBareSHA256(d.ExecutorSHA256) {
		return errors.New("host self-update slot digests are invalid")
	}
	return nil
}

type HostSelfUpdateObservation struct {
	CurrentSlot             string `json:"current_slot"`
	RunningAgentVersion     string `json:"running_agent_version,omitempty"`
	PanelHeartbeatVersion   string `json:"panel_heartbeat_version,omitempty"`
	HeartbeatGeneration     string `json:"heartbeat_generation,omitempty"`
	ExecutorVersion         string `json:"executor_version,omitempty"`
	ExecutorProtocol        int    `json:"executor_protocol,omitempty"`
	ExecutorHealthy         bool   `json:"executor_healthy"`
	ExecutorProbeGeneration string `json:"executor_probe_generation,omitempty"`
	ExecutorFailureCode     string `json:"executor_failure_code,omitempty"`
}

func NewHostSelfUpdateState(agentVersion, executorVersion string) (HostSelfUpdateState, error) {
	if !versionPattern.MatchString(strings.TrimSpace(agentVersion)) ||
		!versionPattern.MatchString(strings.TrimSpace(executorVersion)) {
		return HostSelfUpdateState{}, errors.New("initial host runtime versions are invalid")
	}
	state := HostSelfUpdateState{
		SchemaVersion:           hostSelfUpdateStateSchemaVersion,
		RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
		Phase:                   HostSelfUpdatePhaseStable,
		ActiveSlot:              HostSelfUpdateSlotA,
		HealthySlot:             HostSelfUpdateSlotA,
		ActiveAgentVersion:      strings.TrimSpace(agentVersion),
		ActiveExecutorVersion:   strings.TrimSpace(executorVersion),
	}
	return state, nil
}

func StageHostSelfUpdate(
	state HostSelfUpdateState,
	request HostSelfUpdateRequest,
	blockers HostLifecycleBlockers,
	slotDigests hostSelfUpdateSlotDigests,
) (HostSelfUpdateState, error) {
	if err := state.validate(); err != nil {
		return HostSelfUpdateState{}, err
	}
	if state.Phase != HostSelfUpdatePhaseStable || blockers.mutationBlocked() {
		return HostSelfUpdateState{}, errors.New("host lifecycle mutation is active")
	}
	if err := request.validate(); err != nil {
		return HostSelfUpdateState{}, err
	}
	if err := slotDigests.validate(); err != nil {
		return HostSelfUpdateState{}, err
	}
	if request.AgentVersion == state.ActiveAgentVersion &&
		request.ExecutorVersion == state.ActiveExecutorVersion {
		return HostSelfUpdateState{}, errors.New("host self-update target is already active")
	}
	if request.Generation == state.FailedGeneration {
		return HostSelfUpdateState{}, errors.New("host self-update generation previously failed and cannot be replayed")
	}
	state.Phase = HostSelfUpdatePhaseStaged
	state.PendingSlot = otherHostSelfUpdateSlot(state.HealthySlot)
	state.PendingGeneration = request.Generation
	state.PendingAgentVersion = request.AgentVersion
	state.PendingExecutorVersion = request.ExecutorVersion
	state.PendingCommit = request.Commit
	state.PendingArtifactSHA256 = request.ArtifactSHA256
	state.PendingAgentSHA256 = slotDigests.AgentSHA256
	state.PendingExecutorSHA256 = slotDigests.ExecutorSHA256
	state.PendingAgentProtocol = request.AgentProtocolVersion
	state.PendingExecutorProtocol = request.ExecutorProtocolVersion
	state.PendingMutationProtocol = request.MutationProtocolVersion
	state.PendingRecoveryProtocol = request.RecoveryProtocolVersion
	state.PendingRelease = request.Release
	state.ActivationStartedAt = time.Time{}
	state.ActivationDeadline = time.Time{}
	return state, nil
}

func BeginHostSelfUpdateActivation(
	state HostSelfUpdateState,
	startedAt time.Time,
	verificationTimeout time.Duration,
) (HostSelfUpdateState, error) {
	if err := state.validate(); err != nil {
		return HostSelfUpdateState{}, err
	}
	if state.Phase != HostSelfUpdatePhaseStaged {
		return HostSelfUpdateState{}, errors.New("host self-update is not staged")
	}
	if startedAt.IsZero() ||
		verificationTimeout < 30*time.Second ||
		verificationTimeout > 30*time.Minute {
		return HostSelfUpdateState{}, errors.New("host self-update activation clock is invalid")
	}
	state.Phase = HostSelfUpdatePhaseActivating
	state.ActivationStartedAt = startedAt.UTC()
	state.ActivationDeadline = state.ActivationStartedAt.Add(verificationTimeout)
	return state, nil
}

func ReconcileHostSelfUpdate(
	state HostSelfUpdateState,
	observation HostSelfUpdateObservation,
) (HostSelfUpdateState, string, error) {
	if err := state.validate(); err != nil {
		return HostSelfUpdateState{}, "", err
	}
	if !validHostSelfUpdateSlot(observation.CurrentSlot) {
		return HostSelfUpdateState{}, "", errors.New("observed current host slot is invalid")
	}
	switch state.Phase {
	case HostSelfUpdatePhaseStable:
		if observation.CurrentSlot != state.ActiveSlot {
			return state, HostSelfUpdateActionRestoreHealthy, nil
		}
		return state, HostSelfUpdateActionNone, nil
	case HostSelfUpdatePhaseStaged:
		return state, HostSelfUpdateActionNone, nil
	case HostSelfUpdatePhaseActivating:
		if observation.ExecutorFailureCode != "" {
			state = beginHostSelfUpdateRollback(state)
			if observation.CurrentSlot == state.PendingSlot {
				return state, HostSelfUpdateActionRestoreHealthy, nil
			}
			if observation.CurrentSlot == state.HealthySlot {
				return state, HostSelfUpdateActionRestartHealthy, nil
			}
			return HostSelfUpdateState{}, "", errors.New("current slot is outside the failed activation transition")
		}
		switch observation.CurrentSlot {
		case state.HealthySlot:
			return state, HostSelfUpdateActionSwitchCurrent, nil
		case state.PendingSlot:
			state.Phase = HostSelfUpdatePhaseVerifying
			if observation.RunningAgentVersion == "" {
				return state, HostSelfUpdateActionRestartAgent, nil
			}
			return reconcileHostSelfUpdateVerification(state, observation)
		default:
			return HostSelfUpdateState{}, "", errors.New("current slot is outside the staged A/B transition")
		}
	case HostSelfUpdatePhaseVerifying:
		return reconcileHostSelfUpdateVerification(state, observation)
	case HostSelfUpdatePhaseRollingBack:
		if observation.CurrentSlot == state.PendingSlot {
			return state, HostSelfUpdateActionRestoreHealthy, nil
		}
		if observation.CurrentSlot != state.HealthySlot {
			return HostSelfUpdateState{}, "", errors.New("current slot is outside the rollback transition")
		}
		if observation.RunningAgentVersion == "" {
			return state, HostSelfUpdateActionRestartHealthy, nil
		}
		if observation.RunningAgentVersion != state.ActiveAgentVersion ||
			!observation.ExecutorHealthy ||
			observation.ExecutorVersion != state.ActiveExecutorVersion {
			return state, HostSelfUpdateActionRestartHealthy, nil
		}
		return clearRolledBackHostSelfUpdate(state), HostSelfUpdateActionRollbackComplete, nil
	default:
		return HostSelfUpdateState{}, "", errors.New("host self-update phase is invalid")
	}
}

func reconcileHostSelfUpdateVerification(
	state HostSelfUpdateState,
	observation HostSelfUpdateObservation,
) (HostSelfUpdateState, string, error) {
	if observation.CurrentSlot != state.PendingSlot {
		state = beginHostSelfUpdateRollback(state)
		return state, HostSelfUpdateActionRestoreHealthy, nil
	}
	if observation.RunningAgentVersion != "" &&
		observation.RunningAgentVersion != state.PendingAgentVersion {
		state = beginHostSelfUpdateRollback(state)
		return state, HostSelfUpdateActionRestoreHealthy, nil
	}
	heartbeatPresent := observation.HeartbeatGeneration != "" ||
		observation.PanelHeartbeatVersion != ""
	heartbeatValid := observation.HeartbeatGeneration == state.PendingGeneration &&
		observation.PanelHeartbeatVersion == state.PendingAgentVersion
	if heartbeatPresent && !heartbeatValid {
		state = beginHostSelfUpdateRollback(state)
		return state, HostSelfUpdateActionRestoreHealthy, nil
	}
	probePresent := observation.ExecutorProbeGeneration != "" ||
		observation.ExecutorFailureCode != ""
	probeValid := observation.ExecutorProbeGeneration == state.PendingGeneration &&
		observation.ExecutorHealthy &&
		observation.ExecutorVersion == state.PendingExecutorVersion &&
		observation.ExecutorProtocol == state.PendingExecutorProtocol
	if probePresent && !probeValid {
		state = beginHostSelfUpdateRollback(state)
		return state, HostSelfUpdateActionRestoreHealthy, nil
	}
	if !heartbeatValid {
		return state, HostSelfUpdateActionAwaitProof, nil
	}
	if !probeValid {
		return state, HostSelfUpdateActionProbeExecutor, nil
	}
	return commitHostSelfUpdate(state), HostSelfUpdateActionCommit, nil
}

func beginHostSelfUpdateRollback(state HostSelfUpdateState) HostSelfUpdateState {
	state.Phase = HostSelfUpdatePhaseRollingBack
	state.FailedGeneration = state.PendingGeneration
	return state
}

func commitHostSelfUpdate(state HostSelfUpdateState) HostSelfUpdateState {
	previousSlot := state.HealthySlot
	previousAgent := state.ActiveAgentVersion
	previousExecutor := state.ActiveExecutorVersion
	state.Phase = HostSelfUpdatePhaseStable
	state.ActiveSlot = state.PendingSlot
	state.HealthySlot = state.PendingSlot
	state.RollbackSlot = previousSlot
	state.ActiveAgentVersion = state.PendingAgentVersion
	state.ActiveExecutorVersion = state.PendingExecutorVersion
	state.RollbackAgentVersion = previousAgent
	state.RollbackExecutorVersion = previousExecutor
	return clearPendingHostSelfUpdate(state)
}

func clearRolledBackHostSelfUpdate(state HostSelfUpdateState) HostSelfUpdateState {
	state.FailedGeneration = state.PendingGeneration
	state.Phase = HostSelfUpdatePhaseStable
	state.ActiveSlot = state.HealthySlot
	state.RollbackSlot = ""
	state.RollbackAgentVersion = ""
	state.RollbackExecutorVersion = ""
	return clearPendingHostSelfUpdate(state)
}

func clearPendingHostSelfUpdate(state HostSelfUpdateState) HostSelfUpdateState {
	state.PendingSlot = ""
	state.PendingGeneration = ""
	state.PendingAgentVersion = ""
	state.PendingExecutorVersion = ""
	state.PendingCommit = ""
	state.PendingArtifactSHA256 = ""
	state.PendingAgentSHA256 = ""
	state.PendingExecutorSHA256 = ""
	state.PendingAgentProtocol = 0
	state.PendingExecutorProtocol = 0
	state.PendingMutationProtocol = 0
	state.PendingRecoveryProtocol = 0
	state.PendingRelease = HostSelfUpdateReleaseIdentity{}
	state.ActivationStartedAt = time.Time{}
	state.ActivationDeadline = time.Time{}
	return state
}

func (s HostSelfUpdateState) validate() error {
	if s.SchemaVersion != hostSelfUpdateStateSchemaVersion ||
		s.RecoveryProtocolVersion != HostSelfUpdateRecoveryProtocolVersion ||
		!validHostSelfUpdateSlot(s.ActiveSlot) ||
		!validHostSelfUpdateSlot(s.HealthySlot) ||
		!versionPattern.MatchString(s.ActiveAgentVersion) ||
		!versionPattern.MatchString(s.ActiveExecutorVersion) {
		return errors.New("host self-update state is invalid")
	}
	if s.FailedGeneration != "" &&
		(!identifierPattern.MatchString(s.FailedGeneration) ||
			s.FailedGeneration != strings.TrimSpace(s.FailedGeneration)) {
		return errors.New("host self-update failed generation is invalid")
	}
	if s.Phase == HostSelfUpdatePhaseStable {
		if s.ActiveSlot != s.HealthySlot || s.PendingSlot != "" ||
			s.PendingAgentSHA256 != "" ||
			s.PendingExecutorSHA256 != "" ||
			!s.ActivationStartedAt.IsZero() ||
			!s.ActivationDeadline.IsZero() {
			return errors.New("stable host self-update state is inconsistent")
		}
		return nil
	}
	if s.Phase != HostSelfUpdatePhaseStaged &&
		s.Phase != HostSelfUpdatePhaseActivating &&
		s.Phase != HostSelfUpdatePhaseVerifying &&
		s.Phase != HostSelfUpdatePhaseRollingBack {
		return errors.New("host self-update state phase is invalid")
	}
	request := HostSelfUpdateRequest{
		Generation:              s.PendingGeneration,
		AgentVersion:            s.PendingAgentVersion,
		ExecutorVersion:         s.PendingExecutorVersion,
		Commit:                  s.PendingCommit,
		ArtifactSHA256:          s.PendingArtifactSHA256,
		AgentProtocolVersion:    s.PendingAgentProtocol,
		ExecutorProtocolVersion: s.PendingExecutorProtocol,
		MutationProtocolVersion: s.PendingMutationProtocol,
		RecoveryProtocolVersion: s.PendingRecoveryProtocol,
		Release:                 s.PendingRelease,
	}
	if err := request.validate(); err != nil ||
		(hostSelfUpdateSlotDigests{
			AgentSHA256:    s.PendingAgentSHA256,
			ExecutorSHA256: s.PendingExecutorSHA256,
		}).validate() != nil ||
		!validHostSelfUpdateSlot(s.PendingSlot) ||
		s.PendingSlot == s.HealthySlot {
		return errors.New("pending host self-update state is invalid")
	}
	if s.Phase == HostSelfUpdatePhaseStaged {
		if !s.ActivationStartedAt.IsZero() || !s.ActivationDeadline.IsZero() {
			return errors.New("staged host self-update activation clock is inconsistent")
		}
		return nil
	}
	if s.ActivationStartedAt.IsZero() ||
		s.ActivationDeadline.IsZero() ||
		s.ActivationStartedAt.Location() != time.UTC ||
		s.ActivationDeadline.Location() != time.UTC ||
		!s.ActivationDeadline.After(s.ActivationStartedAt) {
		return errors.New("active host self-update deadline is invalid")
	}
	verificationTimeout := s.ActivationDeadline.Sub(s.ActivationStartedAt)
	if verificationTimeout < 30*time.Second ||
		verificationTimeout > 30*time.Minute {
		return errors.New("active host self-update deadline is outside the fixed bounds")
	}
	return nil
}

func validHostSelfUpdateSlot(slot string) bool {
	return slot == HostSelfUpdateSlotA || slot == HostSelfUpdateSlotB
}

func otherHostSelfUpdateSlot(slot string) string {
	if slot == HostSelfUpdateSlotA {
		return HostSelfUpdateSlotB
	}
	if slot == HostSelfUpdateSlotB {
		return HostSelfUpdateSlotA
	}
	return ""
}
