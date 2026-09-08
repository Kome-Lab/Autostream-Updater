//go:build linux

package hostruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type localDockerListenerBinding struct {
	containerID string
	bind        netip.AddrPort
	mapping     dockerPortMapping
	checkpoint  dockerPortMappingCheckpoint
}

type localDockerProcIdentity struct {
	start     uint64
	netDevice uint64
	netInode  uint64
}

// Published sockets belong to the daemon's network namespace (or to NAT),
// while the application's socket belongs to the managed container. Bind the
// actual published mapping to the declared listener in that PID's namespace;
// neither enter a namespace nor accept a socket owned by another cgroup.
func (v linuxLocalTargetVerifier) observeDockerPortListener(
	ctx context.Context,
	target LocalExecutorTarget,
	runtimeTarget Target,
	containerID string,
	mainPID int,
	controlGroup, version string,
) (LocalProcessObservation, error) {
	before, err := v.localDockerListenerBinding(ctx, target, runtimeTarget, containerID)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	namespace, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", mainPID))
	if err != nil {
		return LocalProcessObservation{}, errors.New("managed Docker network namespace is unavailable")
	}
	defer namespace.Close()
	info, err := namespace.Stat()
	if err != nil {
		return LocalProcessObservation{}, errors.New("managed Docker network namespace is unavailable")
	}
	device, inode, err := localDockerNamespaceIdentity(info)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	process, err := readLocalDockerProcIdentity(mainPID, controlGroup)
	if err != nil || process.netDevice != device || process.netInode != inode {
		return LocalProcessObservation{}, errors.New("managed Docker process namespace changed")
	}
	inodes, err := localDockerListenerInodes(mainPID, before.bind)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	listenerPID, owners, err := localDockerListenerOwnerProof(inodes, controlGroup, process)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	afterInodes, err := localDockerListenerInodes(mainPID, before.bind)
	if err != nil {
		return LocalProcessObservation{}, err
	}
	afterPID, afterOwners, err := localDockerListenerOwnerProof(afterInodes, controlGroup, process)
	if err != nil || listenerPID != afterPID || owners != afterOwners {
		return LocalProcessObservation{}, errors.New("managed Docker listener ownership changed")
	}
	after, err := v.localDockerListenerBinding(ctx, target, runtimeTarget, containerID)
	if err != nil || before.containerID != after.containerID || before.bind != after.bind ||
		before.mapping != after.mapping || !sameDockerPortMappingCheckpoint(before.checkpoint, after.checkpoint) {
		return LocalProcessObservation{}, errors.New("managed Docker listener mapping changed")
	}
	pidOutput, err := v.runner.Run(ctx, runtimeTarget.Docker.ProjectDir, dockerCommandEnv(),
		runtimeTarget.Docker.DockerPath, "inspect", "--format={{.State.Pid}}", before.containerID)
	confirmedPID, pidErr := parsePositivePID(pidOutput)
	if err != nil || pidErr != nil || confirmedPID != mainPID {
		return LocalProcessObservation{}, errors.New("managed Docker process changed during listener verification")
	}
	confirmedProcess, err := readLocalDockerProcIdentity(mainPID, controlGroup)
	if err != nil || confirmedProcess != process {
		return LocalProcessObservation{}, errors.New("managed Docker process identity changed")
	}
	return LocalProcessObservation{
		ServiceID: target.ServiceID, ServiceType: target.ServiceType, DeploymentMode: target.DeploymentMode,
		CurrentVersion: version, MainPID: mainPID, ListenerPID: listenerPID,
		ControlGroup: controlGroup, ListenerControlGroup: controlGroup,
		dockerIdentity: localDockerProcessIdentity{
			containerID: before.containerID, mainStart: process.start, netDevice: device, netInode: inode,
			mapping: before.mapping, bindAddress: before.bind.String(), owners: owners,
		},
	}, nil
}

func (v linuxLocalTargetVerifier) localDockerListenerBinding(
	ctx context.Context,
	target LocalExecutorTarget,
	runtimeTarget Target,
	expectedContainerID string,
) (localDockerListenerBinding, error) {
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil {
		return localDockerListenerBinding{}, err
	}
	checkpoint, err := checkpointDockerPortMapping(adapter.PortEnvFile, true)
	if err != nil || !checkpoint.Existed {
		return localDockerListenerBinding{}, errors.New("Docker listener mapping checkpoint is unavailable")
	}
	published, container, revision, err := parseDockerPortEnv(adapter, checkpoint.Bytes)
	if err != nil || checkpoint.SHA256 != target.ConfigSHA256 || revision != target.ConfigRevision ||
		published != target.LocalListen.Port || target.LocalListen.Host != "127.0.0.1" {
		return localDockerListenerBinding{}, errors.New("Docker listener mapping differs from root policy")
	}
	runtime := &linuxDockerPortRuntime{adapter: adapter, runner: v.runner}
	resolved, err := runtime.resolveCompose(ctx, runtimeTarget.Docker)
	if err != nil || resolved.mapping.HostIP != target.LocalListen.Host ||
		resolved.mapping.PublishedPort != published || resolved.mapping.ContainerPort != container ||
		resolved.configRevision != revision || resolved.policySHA256 != target.Docker.PortComposePolicySHA256 ||
		resolved.composeSHA256 != target.Docker.ComposeConfigSHA256 {
		return localDockerListenerBinding{}, errors.New("Docker listener Compose model differs from root policy")
	}
	listener, _, err := dockerNodeListenerFromCompose(resolved.raw, target.Docker.Service)
	if err != nil {
		return localDockerListenerBinding{}, err
	}
	bind, err := netip.ParseAddrPort(listener.BindAddress)
	if err != nil || !bind.Addr().IsUnspecified() || int(bind.Port()) != container {
		return localDockerListenerBinding{}, errors.New("Docker declared listener differs from its container port")
	}
	managedID, err := managedContainerID(ctx, v.runner, runtimeTarget.Docker)
	if err != nil || !dockerContainerIDsMatch(managedID, expectedContainerID) {
		return localDockerListenerBinding{}, errors.New("managed Docker container changed")
	}
	fullID, err := runtime.fullContainerID(ctx, runtimeTarget.Docker, managedID)
	if err != nil {
		return localDockerListenerBinding{}, err
	}
	if err := preflightDockerPublishedPortOwnership(ctx, v.runner, runtimeTarget.Docker, []dockerPortMapping{resolved.mapping}, fullID); err != nil {
		return localDockerListenerBinding{}, errors.New("Docker listener published mapping is not exclusively owned")
	}
	return localDockerListenerBinding{containerID: fullID, bind: bind, mapping: resolved.mapping, checkpoint: checkpoint}, nil
}

func localDockerListenerInodes(pid int, bind netip.AddrPort) (map[string]struct{}, error) {
	if pid < 1 || !bind.IsValid() || !bind.Addr().IsUnspecified() || bind.Port() < 1024 {
		return nil, errors.New("Docker listener namespace input is invalid")
	}
	tcp, err := os.Open(fmt.Sprintf("/proc/%d/net/tcp", pid))
	if err != nil {
		return nil, errors.New("Docker listener namespace socket table is unavailable")
	}
	defer tcp.Close()
	tcp6, err := os.Open(fmt.Sprintf("/proc/%d/net/tcp6", pid))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("Docker listener namespace IPv6 socket table is unavailable")
	}
	var ipv6 io.Reader
	if err == nil {
		defer tcp6.Close()
		ipv6 = tcp6
	}
	return localDockerListenerInodesFromTables(tcp, ipv6, int(bind.Port()))
}

func localDockerListenerInodesFromTables(tcp, tcp6 io.Reader, port int) (map[string]struct{}, error) {
	if tcp == nil || port < 1024 || port > 65535 {
		return nil, errors.New("Docker listener socket table input is invalid")
	}
	// Go's wildcard TCP listener may use an IPv6 dual-stack socket even when
	// the declared bind is 0.0.0.0. Require a wildcard, and check every listener
	// on the internal port: a specific-address bind must not hide a foreign
	// owner behind a valid wildcard. The mapping and HTTP probe bind reachability.
	inodes, wildcard, err := localDockerListenerTable(tcp, netip.IPv4Unspecified(), port)
	if err != nil {
		return nil, err
	}
	if tcp6 != nil {
		ipv6, wildcard6, err := localDockerListenerTable(tcp6, netip.IPv6Unspecified(), port)
		if err != nil {
			return nil, err
		}
		wildcard = wildcard || wildcard6
		for inode := range ipv6 {
			inodes[inode] = struct{}{}
		}
	}
	if len(inodes) == 0 || !wildcard {
		return nil, errors.New("Docker declared listener is unavailable in its process namespace")
	}
	for inode := range inodes {
		value, err := strconv.ParseUint(inode, 10, 64)
		if err != nil || value == 0 {
			return nil, errors.New("Docker listener socket identity is unavailable")
		}
	}
	return inodes, nil
}

func localDockerListenerTable(input io.Reader, address netip.Addr, port int) (map[string]struct{}, bool, error) {
	wildcard := false
	expected := procNetAddress(address)
	inodes, err := localExecutorListenerInodesMatchingReader(input, address, port, true, func(host string) bool {
		wildcard = wildcard || strings.EqualFold(host, expected)
		return true
	})
	return inodes, wildcard, err
}

func localDockerNamespaceIdentity(info os.FileInfo) (uint64, uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return 0, 0, errors.New("Docker process namespace identity is unavailable")
	}
	return uint64(stat.Dev), stat.Ino, nil
}

func readLocalDockerProcIdentity(pid int, controlGroup string) (localDockerProcIdentity, error) {
	start, err := linuxProcessStartTime(pid)
	if err != nil || requireProcessCgroup(pid, controlGroup) != nil {
		return localDockerProcIdentity{}, errors.New("Docker listener process ownership is unavailable")
	}
	info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return localDockerProcIdentity{}, errors.New("Docker listener process namespace is unavailable")
	}
	device, inode, err := localDockerNamespaceIdentity(info)
	if err != nil {
		return localDockerProcIdentity{}, err
	}
	after, err := linuxProcessStartTime(pid)
	if err != nil || after != start || requireProcessCgroup(pid, controlGroup) != nil {
		return localDockerProcIdentity{}, errors.New("Docker listener process identity changed")
	}
	return localDockerProcIdentity{start: start, netDevice: device, netInode: inode}, nil
}

func localDockerListenerOwnerProof(inodes map[string]struct{}, controlGroup string, namespace localDockerProcIdentity) (int, [32]byte, error) {
	entries, err := readBoundedDirectory("/proc", localExecutorMaxCgroupPIDs*4)
	if err != nil {
		return 0, [32]byte{}, errors.New("Docker process table is unavailable or oversized")
	}
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	owners, err := localDockerSocketOwnersForPIDs(inodes, pids, localDockerProcessSocketInodes)
	if err != nil {
		return 0, [32]byte{}, err
	}
	return localDockerSocketOwnerProof(inodes, owners, controlGroup, namespace, readLocalDockerProcIdentity, localDockerProcessSocketInodes)
}

func localDockerSocketOwnersForPIDs(
	inodes map[string]struct{},
	pids []int,
	readOwned func(int, map[string]struct{}) (map[string]struct{}, error),
) (map[string][]int, error) {
	owners := make(map[string][]int, len(inodes))
	for _, pid := range pids {
		owned, err := readOwned(pid, inodes)
		if err != nil {
			// A known owner cannot make an unreadable possible co-owner safe.
			return nil, errors.New("Docker listener owner enumeration is incomplete")
		}
		for inode := range owned {
			owners[inode] = append(owners[inode], pid)
		}
	}
	return owners, nil
}

func localDockerProcessSocketInodes(pid int, inodes map[string]struct{}) (map[string]struct{}, error) {
	directory := fmt.Sprintf("/proc/%d/fd", pid)
	handle, err := os.Open(directory)
	if err != nil {
		return nil, errors.New("Docker process descriptors are unavailable")
	}
	// Keep the directory descriptor open while inspecting /proc/self/fd, too.
	defer handle.Close()
	entries, err := handle.ReadDir(localExecutorMaxProcessFDs + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > localExecutorMaxProcessFDs {
		return nil, errors.New("Docker process descriptors are unavailable or oversized")
	}
	owned := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(directory + "/" + entry.Name())
		if err != nil {
			return nil, errors.New("Docker process descriptor changed or is unreadable")
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, exists := inodes[inode]; exists {
				owned[inode] = struct{}{}
			}
		}
	}
	return owned, nil
}

func localDockerSocketOwnerProof(
	inodes map[string]struct{},
	owners map[string][]int,
	controlGroup string,
	namespace localDockerProcIdentity,
	readProcess func(int, string) (localDockerProcIdentity, error),
	readOwned func(int, map[string]struct{}) (map[string]struct{}, error),
) (int, [32]byte, error) {
	if readProcess == nil || readOwned == nil || namespace.netInode == 0 {
		return 0, [32]byte{}, errors.New("Docker listener ownership proof is unavailable")
	}
	processes := make(map[int]localDockerProcIdentity)
	listenerPID, err := validateLocalExecutorSocketOwners(inodes, owners, controlGroup, func(pid int, group string) error {
		if _, ok := processes[pid]; ok {
			return nil
		}
		before, err := readProcess(pid, group)
		if err != nil || before.start == 0 || before.netDevice != namespace.netDevice || before.netInode != namespace.netInode {
			return errors.New("Docker listener owner is outside the expected process namespace")
		}
		owned, err := readOwned(pid, inodes)
		if err != nil {
			return errors.New("Docker listener socket ownership is unavailable")
		}
		for inode := range inodes {
			expected := false
			for _, owner := range owners[inode] {
				expected = expected || owner == pid
			}
			_, actual := owned[inode]
			if actual != expected {
				return errors.New("Docker listener socket ownership changed")
			}
		}
		after, err := readProcess(pid, group)
		if err != nil || before != after {
			return errors.New("Docker listener owner identity changed")
		}
		processes[pid] = before
		return nil
	})
	if err != nil {
		return 0, [32]byte{}, err
	}
	keys := make([]string, 0, len(inodes))
	for inode := range inodes {
		keys = append(keys, inode)
	}
	sort.Strings(keys)
	digest := sha256.New()
	for _, inode := range keys {
		pids := append([]int(nil), owners[inode]...)
		sort.Ints(pids)
		for _, pid := range pids {
			identity := processes[pid]
			_, _ = fmt.Fprintf(digest, "%s:%d:%d:%d:%d\n", inode, pid, identity.start, identity.netDevice, identity.netInode)
		}
	}
	var proof [32]byte
	copy(proof[:], digest.Sum(nil))
	return listenerPID, proof, nil
}
