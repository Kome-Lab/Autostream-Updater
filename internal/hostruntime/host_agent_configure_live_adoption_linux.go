//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strconv"
	"strings"
)

func verifyHostAgentLiveSystemdSidecar(
	ctx context.Context,
	currentPolicy LocalExecutorPolicy,
	stagedPolicy LocalExecutorPolicy,
	currentTarget LocalExecutorTarget,
	stagedTarget LocalExecutorTarget,
) (hostAgentLiveSystemdSidecarProof, error) {
	if currentPolicy.Validate() != nil || stagedPolicy.Validate() != nil ||
		currentTarget.validate() != nil || stagedTarget.validate() != nil ||
		!validSystemdPortServiceType(stagedTarget.ServiceType) ||
		currentTarget.Systemd == nil || stagedTarget.Systemd == nil {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar adoption authority is invalid")
	}
	adapter, err := systemdPortAdapterFor(
		stagedTarget.ServiceType,
		stagedTarget.Systemd.Unit,
	)
	if err != nil {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar adoption adapter is invalid")
	}
	stagedBody := systemdPortSidecarBytes(
		adapter.ServiceType,
		stagedTarget.LocalListen.Host,
		stagedTarget.LocalListen.Port,
		stagedTarget.ConfigRevision,
	)
	if stagedTarget.ConfigSHA256 != systemdPortSidecarSHA256(stagedBody) {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar adoption digest is invalid")
	}
	state, err := newFileSystemdPortStateStore(
		LocalExecutorMutationStateDir,
		true,
	)
	if err != nil {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar port state is unavailable")
	}
	active, err := state.LoadActive(stagedTarget.ServiceID)
	if err != nil || active != nil {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar target has port transaction state")
	}
	applied, err := state.LoadApplied(stagedTarget.ServiceID)
	if err != nil || applied != nil {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar target has applied port state")
	}
	runner := OSCommandRunner{NewProcessGroup: true}
	unitID, err := runner.Run(
		ctx,
		"",
		nil,
		stagedTarget.Systemd.SystemctlPath,
		"show",
		"--property=Id",
		"--value",
		stagedTarget.Systemd.Unit,
	)
	unitID = strings.TrimSpace(unitID)
	if err != nil || unitID != stagedTarget.Systemd.Unit {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar unit identity is unavailable")
	}
	loadCredential, err := runner.Run(
		ctx,
		"",
		nil,
		stagedTarget.Systemd.SystemctlPath,
		"show",
		"--property=LoadCredential",
		"--value",
		stagedTarget.Systemd.Unit,
	)
	if err != nil || !systemdLoadCredentialHasNodeListener(
		loadCredential,
		adapter.SidecarPath,
	) {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar credential binding is unavailable")
	}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		inUse, err := procNetTCPListeningPort(table, currentTarget.LocalListen.Port)
		if err != nil || inUse {
			return hostAgentLiveSystemdSidecarProof{}, errors.New("previous systemd sidecar port is not demonstrably unused")
		}
	}
	observation, err := verifyStableLocalTarget(
		ctx,
		stagedPolicy,
		stagedTarget,
		linuxLocalTargetVerifier{runner: runner},
		&http.Client{},
	)
	if err != nil || observation.MainPID != observation.ListenerPID {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar process proof failed")
	}
	mainStart, err := linuxProcessStartTime(observation.MainPID)
	if err != nil {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar process start time is unavailable")
	}
	listenerStart, err := linuxProcessStartTime(observation.ListenerPID)
	if err != nil || listenerStart != mainStart {
		return hostAgentLiveSystemdSidecarProof{}, errors.New("live systemd sidecar listener identity is unstable")
	}
	return hostAgentLiveSystemdSidecarProof{
		Observation:          observation,
		MainPIDStartTime:     mainStart,
		ListenerPIDStartTime: listenerStart,
		SystemdUnitID:        unitID,
		LoadCredential:       strings.TrimSpace(loadCredential),
	}, nil
}

func systemdLoadCredentialHasNodeListener(value, expected string) bool {
	expected = path.Clean(expected)
	if !path.IsAbs(expected) {
		return false
	}
	count := 0
	for _, field := range strings.Fields(value) {
		candidate := strings.Trim(field, "\"")
		candidate = strings.TrimPrefix(candidate, "LoadCredential=")
		name, source, ok := strings.Cut(candidate, ":")
		if !ok || name != "node-listener.json" {
			continue
		}
		count++
		if !path.IsAbs(source) || path.Clean(source) != source || source != expected {
			return false
		}
	}
	return count == 1
}

func linuxProcessStartTime(pid int) (uint64, error) {
	if pid < 1 {
		return 0, errors.New("process ID is invalid")
	}
	data, err := readBoundedProcFile(
		"/proc/"+strconv.Itoa(pid)+"/stat",
		64<<10,
	)
	if err != nil {
		return 0, err
	}
	line := string(data)
	endName := strings.LastIndex(line, ")")
	if endName < 0 || endName+1 >= len(line) {
		return 0, errors.New("process stat is invalid")
	}
	fields := strings.Fields(line[endName+1:])
	if len(fields) <= 19 {
		return 0, errors.New("process stat is incomplete")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTime == 0 {
		return 0, errors.New("process start time is invalid")
	}
	return startTime, nil
}
