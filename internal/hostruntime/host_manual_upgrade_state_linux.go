//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func inspectHostUpdateRecovery() (bool, error) {
	if os.Geteuid() != 0 {
		return false, errors.New(
			"Host update recovery inspection requires root",
		)
	}
	rt := defaultManualHostUpgradeRuntime()
	if err := validateManualHostUpgradeStateRoots(rt); err != nil {
		return false, err
	}
	journal, err := readManualHostUpgradeJournal(rt)
	if err != nil {
		return false, err
	}
	return manualHostUpgradeJournalRecoveryActive(journal)
}

func manualHostUpgradeJournalRecoveryActive(
	journal journalData,
) (bool, error) {
	if journal.ActiveJob == nil {
		if journal.ActivePlan != nil || journal.ActivePortPlan != nil {
			return false, errors.New(
				"Host Agent journal has a plan without an active job",
			)
		}
		return false, nil
	}
	if journal.ActiveJob.validateOperationUnion() != nil ||
		(journal.ActivePlan != nil && journal.ActivePortPlan != nil) {
		return false, errors.New("Host Agent recovery journal is invalid")
	}
	switch journal.ActiveJob.EffectiveOperation() {
	case updateJobOperationSoftwareUpdate:
		if journal.ActivePortPlan != nil || journal.ActivePlan == nil ||
			journal.ActivePlan.JobID != journal.ActiveJob.ID ||
			journal.ActivePlan.Validate() != nil {
			return false, errors.New(
				"Host Agent software recovery plan is invalid",
			)
		}
	case updateJobOperationPortReconfigure:
		if journal.ActivePlan != nil || journal.ActivePortPlan == nil ||
			journal.ActivePortPlan.JobID != journal.ActiveJob.ID ||
			journal.ActivePortPlan.Validate() != nil {
			return false, errors.New(
				"Host Agent port recovery plan is invalid",
			)
		}
	default:
		return false, errors.New("Host Agent recovery operation is invalid")
	}
	return true, nil
}

func loadManualHostUpgradeState(
	current manualHostRuntimeObservation,
	rt manualHostUpgradeRuntime,
) (HostSelfUpdateState, bool, error) {
	state, err := rt.selfUpdate.loadPersistedState()
	if err == nil {
		return state, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) || current.Slot != HostSelfUpdateSlotA {
		return HostSelfUpdateState{}, false, errors.New(
			"managed Host runtime self-update state is unavailable",
		)
	}
	hasBinding, err := rt.selfUpdate.hostSelfUpdateSlotHasBinding(current.Slot)
	if err != nil || hasBinding {
		return HostSelfUpdateState{}, false, errors.New(
			"bootstrap Host runtime state is missing or ambiguously bound",
		)
	}
	state, err = NewHostSelfUpdateState(
		current.Agent.Version, current.Executor.Version,
	)
	if err != nil {
		return HostSelfUpdateState{}, false, err
	}
	state.ActiveSlot = current.Slot
	state.HealthySlot = current.Slot
	return state, false, nil
}

func validateManualHostUpgradeCurrentState(
	ctx context.Context,
	current manualHostRuntimeObservation,
	state HostSelfUpdateState,
	persisted bool,
	rt manualHostUpgradeRuntime,
) error {
	if err := state.validate(); err != nil ||
		state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != current.Slot ||
		state.HealthySlot != current.Slot ||
		state.ActiveAgentVersion != current.Agent.Version ||
		state.ActiveExecutorVersion != current.Executor.Version {
		return errors.New(
			"managed Host runtime state is not a stable healthy current pair",
		)
	}
	hasBinding, err := rt.selfUpdate.hostSelfUpdateSlotHasBinding(current.Slot)
	if err != nil {
		return errors.New("inspect active Host runtime slot binding")
	}
	if !hasBinding {
		if current.Slot != HostSelfUpdateSlotA || !persisted &&
			state.RollbackSlot != "" {
			return errors.New("unbound Host runtime is not the bootstrap slot")
		}
		return nil
	}
	request, digests, err := readManualHostUpdateSlotBinding(
		current.Slot, rt.selfUpdate,
	)
	if err != nil || request.AgentVersion != current.Agent.Version ||
		request.ExecutorVersion != current.Executor.Version ||
		request.Commit != current.Agent.Commit ||
		rt.selfUpdate.verifyHostSelfUpdateSlot(
			ctx,
			current.Slot,
			filepath.Join(rt.selfUpdate.slotsRoot, current.Slot),
			request,
			digests,
		) != nil {
		return errors.New("active Host runtime slot binding is invalid")
	}
	return nil
}

func readManualHostUpdateSlotBinding(
	slot string,
	rt hostSelfUpdateExecutorRuntime,
) (HostSelfUpdateRequest, hostSelfUpdateSlotDigests, error) {
	root := filepath.Join(rt.slotsRoot, slot)
	read := func(name string) (string, error) {
		payload, err := readHostSelfUpdateSlotMarker(
			filepath.Join(root, name), !rt.allowTestPaths,
		)
		if err != nil {
			return "", err
		}
		return strings.TrimSuffix(string(payload), "\n"), nil
	}
	values := make(map[string]string)
	for _, name := range []string{
		".generation", ".agent-version", ".executor-version", ".commit",
		".artifact-sha256", ".agent-protocol", ".executor-protocol",
		".mutation-protocol", ".recovery-protocol", ".agent-sha256",
		".local-executor-sha256",
	} {
		value, err := read(name)
		if err != nil {
			return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
		}
		values[name] = value
	}
	parseProtocol := func(name string) (int, error) {
		return strconv.Atoi(values[name])
	}
	agentProtocol, err := parseProtocol(".agent-protocol")
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	executorProtocol, err := parseProtocol(".executor-protocol")
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	mutationProtocol, err := parseProtocol(".mutation-protocol")
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	recoveryProtocol, err := parseProtocol(".recovery-protocol")
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	releasePayload, err := readHostSelfUpdateSlotMarker(
		filepath.Join(root, ".release-binding.json"), !rt.allowTestPaths,
	)
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	var release HostSelfUpdateReleaseIdentity
	decoder := json.NewDecoder(bytes.NewReader(releasePayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&release); err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	request := HostSelfUpdateRequest{
		Generation:              values[".generation"],
		AgentVersion:            values[".agent-version"],
		ExecutorVersion:         values[".executor-version"],
		Commit:                  values[".commit"],
		ArtifactSHA256:          values[".artifact-sha256"],
		AgentProtocolVersion:    agentProtocol,
		ExecutorProtocolVersion: executorProtocol,
		MutationProtocolVersion: mutationProtocol,
		RecoveryProtocolVersion: recoveryProtocol,
		Release:                 release,
	}
	digests := hostSelfUpdateSlotDigests{
		AgentSHA256:    values[".agent-sha256"],
		ExecutorSHA256: values[".local-executor-sha256"],
	}
	if err := request.validate(); err != nil || digests.validate() != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, errors.New(
			"Host runtime slot binding is invalid",
		)
	}
	return request, digests, nil
}

func manualHostUpgradeAlreadyCurrent(
	slot string,
	current manualHostRuntimeObservation,
	target HostSelfUpdateRequest,
	targetDigests hostSelfUpdateSlotDigests,
	rt manualHostUpgradeRuntime,
) (bool, error) {
	if current.Agent.Commit != target.Commit ||
		current.Executor.Commit != target.Commit {
		return false, nil
	}
	currentDigests, err := hostSelfUpdateArtifactBinaryDigests(
		filepath.Join(rt.selfUpdate.slotsRoot, slot),
	)
	if err != nil || currentDigests != targetDigests {
		return false, nil
	}
	hasBinding, err := rt.selfUpdate.hostSelfUpdateSlotHasBinding(slot)
	if err != nil {
		return false, err
	}
	if !hasBinding {
		return true, nil
	}
	bound, _, err := readManualHostUpdateSlotBinding(slot, rt.selfUpdate)
	if err != nil {
		return false, err
	}
	return sameManualHostUpgradeArchiveContent(bound, target), nil
}

func sameManualHostUpgradeArchiveContent(
	bound HostSelfUpdateRequest,
	target HostSelfUpdateRequest,
) bool {
	return bound.validate() == nil && target.validate() == nil &&
		bound.AgentVersion == target.AgentVersion &&
		bound.ExecutorVersion == target.ExecutorVersion &&
		bound.Commit == target.Commit &&
		bound.ArtifactSHA256 == target.ArtifactSHA256 &&
		bound.AgentProtocolVersion == target.AgentProtocolVersion &&
		bound.ExecutorProtocolVersion == target.ExecutorProtocolVersion &&
		bound.MutationProtocolVersion == target.MutationProtocolVersion &&
		bound.RecoveryProtocolVersion == target.RecoveryProtocolVersion &&
		bound.Release.ArchiveAssetName == target.Release.ArchiveAssetName &&
		bound.Release.ArchiveSize == target.Release.ArchiveSize &&
		bound.Release.ArchiveSHA256 == target.Release.ArchiveSHA256 &&
		bound.Release.Arch == target.Release.Arch &&
		bound.Release.MinimumPanelVersion == target.Release.MinimumPanelVersion
}
