//go:build linux

package hostruntime

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	localExecutorMaxProcNetBytes = 8 << 20
	localExecutorMaxCgroupPIDs   = 32 << 10
	localExecutorMaxProcessFDs   = 16 << 10
)

type linuxLocalTargetVerifier struct {
	runner CommandRunner
}

func (v linuxLocalTargetVerifier) Observe(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
) (LocalProcessObservation, error) {
	runtimeTarget := target.runtimeTarget(policy.HostID)
	secured, err := securePrivilegedTarget(runtimeTarget)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	if v.runner == nil {
		v.runner = OSCommandRunner{NewProcessGroup: true}
	}
	switch secured.DeploymentMode {
	case ModeSystemd:
		return v.observeSystemd(ctx, target, secured)
	case ModeDocker:
		return v.observeDocker(ctx, target, secured)
	default:
		return LocalProcessObservation{}, errors.New("unsupported local executor deployment mode")
	}
}

func (v linuxLocalTargetVerifier) ObserveDockerPort(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
	httpClient *http.Client,
) (LocalExecutorDockerPortProbe, error) {
	if target.DeploymentMode != ModeDocker ||
		target.Docker == nil ||
		target.Docker.PortEnvFile == "" {
		return LocalExecutorDockerPortProbe{}, errors.New("Docker port probe target is unavailable")
	}
	secured, err := securePrivilegedTarget(
		target.runtimeTarget(policy.HostID),
	)
	if err != nil || secured.Docker == nil {
		return LocalExecutorDockerPortProbe{}, errors.New("Docker port probe target is not root-controlled")
	}
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil {
		return LocalExecutorDockerPortProbe{}, err
	}
	runner := v.runner
	if runner == nil {
		runner = OSCommandRunner{NewProcessGroup: true}
	}
	portRuntime := &linuxDockerPortRuntime{
		adapter:          adapter,
		hostID:           policy.HostID,
		serviceID:        target.ServiceID,
		serviceType:      target.ServiceType,
		dockerPath:       secured.Docker.DockerPath,
		runner:           runner,
		httpClient:       httpClient,
		requireRootOwned: true,
		requireRootWork:  true,
	}
	observation, err := portRuntime.Observe(ctx, policy, target)
	if err != nil {
		return LocalExecutorDockerPortProbe{}, err
	}
	probe := LocalExecutorDockerPortProbe{
		CapabilityVersion:   dockerPortCapabilityVersion,
		PublishedPort:       observation.PublishedPort,
		ContainerPort:       observation.ContainerPort,
		HealthPort:          observation.HealthPort,
		ComposePolicySHA256: observation.ComposePolicySHA256,
		ComposeConfigSHA256: observation.ComposeConfigSHA256,
		ComposeRevision:     target.Docker.PortComposeRevision,
		VersionEnvSHA256:    observation.Runtime.VersionEnvSHA256,
		ContainerID:         observation.Runtime.ContainerID,
		ImageID:             observation.Runtime.ImageID,
		RepositoryDigest:    observation.Runtime.RepositoryDigest,
	}
	if err := probe.Validate(); err != nil {
		return LocalExecutorDockerPortProbe{}, err
	}
	return probe, nil
}

func (v linuxLocalTargetVerifier) observeSystemd(
	ctx context.Context,
	target LocalExecutorTarget,
	runtimeTarget Target,
) (LocalProcessObservation, error) {
	systemd := runtimeTarget.Systemd
	release, _, version, err := currentRelease(systemd.CurrentLink, systemd.ReleaseRoot)
	if err != nil || release == "" || !versionPattern.MatchString(version) {
		return LocalProcessObservation{}, errors.New("managed systemd release is unavailable")
	}
	if err := verifyManagedReleaseChecksums(release); err != nil {
		return LocalProcessObservation{}, err
	}
	if err := verifySystemdProcess(ctx, runtimeTarget, release, v.runner); err != nil {
		return LocalProcessObservation{}, err
	}
	pidOutput, err := v.runner.Run(ctx, "", nil, systemd.SystemctlPath,
		"show", "--property=MainPID", "--value", systemd.Unit)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	mainPID, err := parsePositivePID(pidOutput)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	cgroupOutput, err := v.runner.Run(ctx, "", nil, systemd.SystemctlPath,
		"show", "--property=ControlGroup", "--value", systemd.Unit)
	controlGroup := strings.TrimSpace(cgroupOutput)
	if err != nil || !validLocalExecutorCgroup(controlGroup) {
		return LocalProcessObservation{}, errors.New("systemd control group is unavailable")
	}
	if err := requireProcessCgroup(mainPID, controlGroup); err != nil {
		return LocalProcessObservation{}, err
	}
	listenerPID, listenerGroup, err := findLocalExecutorListenerPID(target.LocalListen, controlGroup)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	return LocalProcessObservation{
		ServiceID:            target.ServiceID,
		ServiceType:          target.ServiceType,
		DeploymentMode:       target.DeploymentMode,
		CurrentVersion:       version,
		MainPID:              mainPID,
		ListenerPID:          listenerPID,
		ControlGroup:         controlGroup,
		ListenerControlGroup: listenerGroup,
	}, nil
}

func (v linuxLocalTargetVerifier) observeDocker(
	ctx context.Context,
	target LocalExecutorTarget,
	runtimeTarget Target,
) (LocalProcessObservation, error) {
	containerID, err := managedContainerID(ctx, v.runner, runtimeTarget.Docker)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	pidOutput, err := v.runner.Run(ctx, runtimeTarget.Docker.ProjectDir, dockerCommandEnv(),
		runtimeTarget.Docker.DockerPath, "inspect", "--format={{.State.Pid}}", containerID)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	mainPID, err := parsePositivePID(pidOutput)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	controlGroup, err := processUnifiedControlGroup(mainPID)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	version := probeRemoteTargetVersion(runtimeTarget)
	if !versionPattern.MatchString(version) {
		return LocalProcessObservation{}, errors.New("managed Docker version is unavailable")
	}
	listenerPID, listenerGroup, err := findLocalExecutorListenerPID(target.LocalListen, controlGroup)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	return LocalProcessObservation{
		ServiceID:            target.ServiceID,
		ServiceType:          target.ServiceType,
		DeploymentMode:       target.DeploymentMode,
		CurrentVersion:       version,
		MainPID:              mainPID,
		ListenerPID:          listenerPID,
		ControlGroup:         controlGroup,
		ListenerControlGroup: listenerGroup,
	}, nil
}

func requireProcessCgroup(pid int, expected string) error {
	data, err := readBoundedProcFile(fmt.Sprintf("/proc/%d/cgroup", pid), 64<<10)
	if err != nil || !processCgroupTextMatches(string(data), expected) {
		return errors.New("process does not belong to the expected control group")
	}
	return nil
}

func processUnifiedControlGroup(pid int) (string, error) {
	data, err := readBoundedProcFile(fmt.Sprintf("/proc/%d/cgroup", pid), 64<<10)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" && validLocalExecutorCgroup(parts[2]) {
			return parts[2], nil
		}
	}
	return "", errors.New("unified process control group is unavailable")
}

func findLocalExecutorListenerPID(endpoint LocalExecutorEndpoint, controlGroup string) (int, string, error) {
	inodes, err := localExecutorListenerInodes(endpoint)
	if err != nil {
		return 0, "", err
	}
	owners, err := localExecutorSocketOwners(inodes)
	if err != nil {
		return 0, "", err
	}
	listenerPID, err := validateLocalExecutorSocketOwners(inodes, owners, controlGroup, requireProcessCgroup)
	if err != nil {
		return 0, "", err
	}
	return listenerPID, controlGroup, nil
}

func localExecutorListenerInodes(endpoint LocalExecutorEndpoint) (map[string]struct{}, error) {
	address, err := netip.ParseAddr(endpoint.Host)
	if err != nil || !address.IsLoopback() || endpoint.Port < 1024 || endpoint.Port > 65535 {
		return nil, errors.New("listener endpoint is invalid")
	}
	procPath := "/proc/net/tcp"
	if address.Is6() {
		procPath = "/proc/net/tcp6"
	}
	file, err := os.Open(procPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, localExecutorMaxProcNetBytes+1))
	expectedAddress := procNetAddress(address)
	expectedPort := fmt.Sprintf("%04X", endpoint.Port)
	inodes := make(map[string]struct{})
	total := 0
	for {
		line, readErr := reader.ReadString('\n')
		total += len(line)
		if total > localExecutorMaxProcNetBytes {
			return nil, errors.New("proc network table exceeds the size limit")
		}
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[3] == "0A" {
			host, port, ok := strings.Cut(fields[1], ":")
			if ok && strings.EqualFold(host, expectedAddress) && strings.EqualFold(port, expectedPort) {
				if _, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
					inodes[fields[9]] = struct{}{}
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	if len(inodes) == 0 {
		return nil, errors.New("expected local listener is unavailable")
	}
	return inodes, nil
}

func procNetAddress(address netip.Addr) string {
	if address.Is4() {
		bytes := address.As4()
		return strings.ToUpper(hex.EncodeToString([]byte{bytes[3], bytes[2], bytes[1], bytes[0]}))
	}
	bytes := address.As16()
	reordered := make([]byte, 0, len(bytes))
	for offset := 0; offset < len(bytes); offset += 4 {
		reordered = append(reordered, bytes[offset+3], bytes[offset+2], bytes[offset+1], bytes[offset])
	}
	return strings.ToUpper(hex.EncodeToString(reordered))
}

func localExecutorCgroupPIDs(controlGroup string) ([]int, error) {
	if !validLocalExecutorCgroup(controlGroup) {
		return nil, errors.New("control group is invalid")
	}
	clean := filepath.Clean(controlGroup)
	cgroupRoot := filepath.Clean("/sys/fs/cgroup")
	cgroupPath := filepath.Join(cgroupRoot, strings.TrimPrefix(clean, "/"))
	relative, err := filepath.Rel(cgroupRoot, cgroupPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("control group escaped the cgroup filesystem")
	}
	data, err := readBoundedProcFile(filepath.Join(cgroupPath, "cgroup.procs"), 1<<20)
	if err != nil {
		return scanProcForControlGroup(controlGroup)
	}
	pids, err := parseBoundedPIDList(string(data))
	if err != nil {
		return nil, err
	}
	return pids, nil
}

func parseBoundedPIDList(contents string) ([]int, error) {
	fields := strings.Fields(contents)
	if len(fields) == 0 || len(fields) > localExecutorMaxCgroupPIDs {
		return nil, errors.New("control group process list is empty or oversized")
	}
	pids := make([]int, 0, len(fields))
	for _, field := range fields {
		pid, err := parsePositivePID(field)
		if err != nil {
			return nil, errors.New("control group process list is invalid")
		}
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids, nil
}

func scanProcForControlGroup(controlGroup string) ([]int, error) {
	entries, err := readBoundedDirectory("/proc", localExecutorMaxCgroupPIDs*4)
	if err != nil {
		return nil, errors.New("process table is unavailable or oversized")
	}
	pids := make([]int, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 {
			continue
		}
		data, err := readBoundedProcFile(filepath.Join("/proc", entry.Name(), "cgroup"), 64<<10)
		if err == nil && processCgroupTextMatches(string(data), controlGroup) {
			pids = append(pids, pid)
			if len(pids) > localExecutorMaxCgroupPIDs {
				return nil, errors.New("control group process list exceeds the size limit")
			}
		}
	}
	if len(pids) == 0 {
		return nil, errors.New("control group has no observable processes")
	}
	sort.Ints(pids)
	return pids, nil
}

func localExecutorSocketOwners(inodes map[string]struct{}) (map[string][]int, error) {
	entries, err := readBoundedDirectory("/proc", localExecutorMaxCgroupPIDs*4)
	if err != nil {
		return nil, errors.New("process table is unavailable or oversized")
	}
	ownerSets := make(map[string]map[int]struct{}, len(inodes))
	for inode := range inodes {
		ownerSets[inode] = make(map[int]struct{})
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 {
			continue
		}
		owned, err := processOwnedSocketInodes(pid, inodes)
		if err != nil {
			continue
		}
		for inode := range owned {
			ownerSets[inode][pid] = struct{}{}
		}
	}
	owners := make(map[string][]int, len(ownerSets))
	for inode, pids := range ownerSets {
		for pid := range pids {
			owners[inode] = append(owners[inode], pid)
		}
		sort.Ints(owners[inode])
	}
	return owners, nil
}

func validateLocalExecutorSocketOwners(
	inodes map[string]struct{},
	owners map[string][]int,
	controlGroup string,
	matches func(int, string) error,
) (int, error) {
	if len(inodes) == 0 || !validLocalExecutorCgroup(controlGroup) || matches == nil {
		return 0, errors.New("listener ownership input is invalid")
	}
	listenerPID := 0
	for inode := range inodes {
		pids := owners[inode]
		if len(pids) == 0 {
			return 0, errors.New("listener socket owner is unavailable")
		}
		for _, pid := range pids {
			if pid < 1 || matches(pid, controlGroup) != nil {
				return 0, errors.New("listener socket is also owned outside the expected control group")
			}
			if listenerPID == 0 || pid < listenerPID {
				listenerPID = pid
			}
		}
	}
	if listenerPID == 0 {
		return 0, errors.New("listener socket is not owned by the expected control group")
	}
	return listenerPID, nil
}

func processOwnedSocketInodes(pid int, inodes map[string]struct{}) (map[string]struct{}, error) {
	entries, err := readBoundedDirectory(fmt.Sprintf("/proc/%d/fd", pid), localExecutorMaxProcessFDs)
	if err != nil {
		return nil, err
	}
	owned := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		if _, exists := inodes[inode]; exists {
			owned[inode] = struct{}{}
		}
	}
	return owned, nil
}

func readBoundedDirectory(directory string, maximum int) ([]os.DirEntry, error) {
	handle, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	entries, err := handle.ReadDir(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maximum {
		return nil, errors.New("directory exceeds the size limit")
	}
	return entries, nil
}
