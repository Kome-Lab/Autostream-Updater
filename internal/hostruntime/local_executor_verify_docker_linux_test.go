//go:build linux

package hostruntime

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestLocalExecutorDockerListenerSelectsDeclaredNamespaceEndpoint(t *testing.T) {
	for _, test := range []struct {
		name, address, table string
	}{
		{
			name: "ipv4_container_port", address: "0.0.0.0",
			table: "0: 0100007F:46A1 00000000:0000 0A 0:0 00:0 0 0 0 2001\n" +
				"1: 00000000:1F90 00000000:0000 0A 0:0 00:0 0 0 0 1001\n" +
				"2: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 0 0 2002\n" +
				"3: 00000000:1F90 00000000:0000 01 0:0 00:0 0 0 0 2003\n",
		},
		{
			name: "ipv6_container_port", address: "::",
			table: "0: 00000000000000000000000000000000:46A1 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 2001\n" +
				"1: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 1001\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			inodes, err := localExecutorListenerInodesFromReader(strings.NewReader(test.table), netip.MustParseAddr(test.address), 8080, true)
			_, correct := inodes["1001"]
			if err != nil || len(inodes) != 1 || !correct {
				t.Fatal("namespace listener did not select the exact declared bind and container port")
			}
		})
	}
	for _, table := range []string{
		"0: 0100007F:46A1 00000000:0000 0A 0:0 00:0 0 0 0 2001\n",
		"0: 0100007F:1F90 00000000:0000 0A 0:0 00:0 0 0 0 2001\n",
		"0: 00000000:1F90 00000000:0000 0A 0:0 00:0 0 0 0 invalid\n",
		"0: 00000000:1F90 00000000:0000 0A 0:0 00:0 0 0 0 0\n",
		strings.Repeat(" ", localExecutorMaxProcNetBytes+1),
	} {
		if _, err := localDockerListenerInodesFromTables(strings.NewReader(table), nil, 8080); err == nil {
			t.Fatal("unavailable, malformed or oversized listener table was accepted")
		}
	}
	ipv4 := "0: 00000000:1F90 00000000:0000 0A 0:0 00:0 0 0 0 1001\n"
	ipv6 := "0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 1002\n"
	if inodes, err := localDockerListenerInodesFromTables(strings.NewReader(ipv4), nil, 8080); err != nil || len(inodes) != 1 {
		t.Fatal("an absent IPv6 table hid a valid IPv4 listener")
	}
	if _, err := localDockerListenerInodesFromTables(strings.NewReader(ipv4), localDockerListenerReadFailure{}, 8080); err == nil {
		t.Fatal("a valid family hid a read failure in the other table")
	}
	for _, test := range []struct {
		table string
		want  int
	}{{table: "", want: 1}, {table: ipv4, want: 2}} {
		inodes, err := localDockerListenerInodesFromTables(strings.NewReader(test.table), strings.NewReader(ipv6), 8080)
		_, dualStack := inodes["1002"]
		if err != nil || !dualStack || len(inodes) != test.want {
			t.Fatal("dual-stack or coexisting-family listener ownership was omitted")
		}
	}
	for _, invalid := range []string{
		"0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 invalid\n",
		"0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 0\n",
		"0: 00000000000000000000000000000000:1F90 0 0A\n",
		strings.Repeat(" ", localExecutorMaxProcNetBytes+1),
	} {
		if _, err := localDockerListenerInodesFromTables(strings.NewReader(ipv4), strings.NewReader(invalid), 8080); err == nil {
			t.Fatal("a valid family hid an invalid listener table in the other family")
		}
	}
	specific := "1: 020011AC:1F90 00000000:0000 0A 0:0 00:0 0 0 0 2002\n"
	inodes, err := localDockerListenerInodesFromTables(strings.NewReader(ipv4+specific), strings.NewReader(ipv6), 8080)
	_, included := inodes["2002"]
	if err != nil || len(inodes) != 3 || !included {
		t.Fatal("a specific-address listener escaped the namespace ownership proof")
	}
}

func TestLocalExecutorDockerListenerRequiresEveryStableOwner(t *testing.T) {
	const group = "/docker/test-container"
	namespace := localDockerProcIdentity{start: 10, netDevice: 4, netInode: 42}
	for _, readErr := range []error{nil, os.ErrNotExist, os.ErrPermission, errors.New("descriptor read failed")} {
		owners, err := localDockerSocketOwnersForPIDs(map[string]struct{}{"1001": {}}, []int{101, 202}, func(pid int, _ map[string]struct{}) (map[string]struct{}, error) {
			if pid == 202 && readErr != nil {
				return nil, readErr
			}
			return map[string]struct{}{"1001": {}}, nil
		})
		if readErr == nil {
			if err != nil || len(owners["1001"]) != 2 {
				t.Fatal("complete enumeration omitted a socket co-owner")
			}
		} else if err == nil || owners != nil {
			t.Fatal("known socket owner hid an unreadable possible co-owner")
		}
	}
	if _, err := localDockerProcessSocketInodes(os.Getpid(), map[string]struct{}{}); err != nil {
		t.Fatal("descriptor scan lost its own directory descriptor")
	}
	for _, test := range []struct {
		name string
		kind string
	}{
		{name: "managed_namespace", kind: "valid"},
		{name: "foreign_cgroup", kind: "cgroup"},
		{name: "coexisting_foreign_inode", kind: "coexisting"},
		{name: "foreign_namespace_same_cgroup", kind: "namespace"},
		{name: "foreign_namespace_device", kind: "device"},
		{name: "owner_start_time_changed", kind: "start"},
		{name: "owner_namespace_changed", kind: "changed_namespace"},
		{name: "owner_fd_changed", kind: "fd"},
		{name: "owner_missing", kind: "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inodes := map[string]struct{}{"1001": {}}
			owners := map[string][]int{"1001": {101, 202}}
			if test.kind == "coexisting" {
				inodes["2002"] = struct{}{}
				owners = map[string][]int{"1001": {101}, "2002": {202}}
			}
			if test.kind == "missing" {
				owners["1001"] = nil
			}
			calls := make(map[int]int)
			readProcess := func(pid int, expected string) (localDockerProcIdentity, error) {
				if expected != group {
					return localDockerProcIdentity{}, errors.New("unexpected group")
				}
				calls[pid]++
				value := namespace
				value.start += uint64(pid)
				if pid == 202 {
					switch test.kind {
					case "cgroup", "coexisting":
						return localDockerProcIdentity{}, errors.New("foreign group")
					case "namespace":
						value.netInode++
					case "device":
						value.netDevice++
					case "start":
						if calls[pid] > 1 {
							value.start++
						}
					case "changed_namespace":
						if calls[pid] > 1 {
							value.netInode++
						}
					}
				}
				return value, nil
			}
			readOwned := func(pid int, _ map[string]struct{}) (map[string]struct{}, error) {
				if test.kind == "fd" && pid == 202 {
					return map[string]struct{}{}, nil
				}
				return map[string]struct{}{"1001": {}}, nil
			}
			pid, proof, err := localDockerSocketOwnerProof(inodes, owners, group, namespace, readProcess, readOwned)
			if test.kind != "valid" {
				if err == nil {
					t.Fatal("unstable or foreign listener owner was accepted")
				}
				return
			}
			if err != nil || pid != 101 || proof == ([32]byte{}) || calls[101] != 2 || calls[202] != 2 {
				t.Fatal("stable owners in the exact target namespace were rejected")
			}
			owners["1001"] = []int{202, 101}
			_, reordered, err := localDockerSocketOwnerProof(inodes, owners, group, namespace, readProcess, readOwned)
			if err != nil || proof != reordered {
				t.Fatal("owner proof depends on process enumeration order")
			}
		})
	}
}

type localDockerListenerReadFailure struct{}

func (localDockerListenerReadFailure) Read([]byte) (int, error) {
	return 0, errors.New("read failure")
}

func TestLocalExecutorDockerIdentityBindsHTTPSandwich(t *testing.T) {
	base := LocalProcessObservation{
		ServiceID: "worker-smoke", ServiceType: "worker", DeploymentMode: ModeDocker,
		CurrentVersion: "v1.2.3", MainPID: 101, ListenerPID: 202,
		ControlGroup: "/docker/test-container", ListenerControlGroup: "/docker/test-container",
		dockerIdentity: localDockerProcessIdentity{
			containerID: strings.Repeat("a", 64), mainStart: 10, netDevice: 4, netInode: 42,
			mapping:     dockerPortMapping{HostIP: "127.0.0.1", PublishedPort: 18081, ContainerPort: 8080, Protocol: "tcp"},
			bindAddress: "0.0.0.0:8080", owners: [32]byte{1},
		},
	}
	if !sameLocalProcessObservation(base, base) {
		t.Fatal("stable Docker process observation changed")
	}
	for _, mutate := range []func(*localDockerProcessIdentity){
		func(value *localDockerProcessIdentity) { value.containerID = strings.Repeat("b", 64) },
		func(value *localDockerProcessIdentity) { value.mainStart++ },
		func(value *localDockerProcessIdentity) { value.netDevice++ },
		func(value *localDockerProcessIdentity) { value.netInode++ },
		func(value *localDockerProcessIdentity) { value.mapping.PublishedPort++ },
		func(value *localDockerProcessIdentity) { value.mapping.ContainerPort++ },
		func(value *localDockerProcessIdentity) { value.bindAddress = "[::]:8080" },
		func(value *localDockerProcessIdentity) { value.owners[0]++ },
	} {
		after := base
		mutate(&after.dockerIdentity)
		if sameLocalProcessObservation(base, after) {
			t.Fatal("Docker identity replacement was accepted across the HTTP probe")
		}
	}
	for _, mode := range []string{ModeSystemd, ModeDocker} {
		legacy := base
		legacy.DeploymentMode = mode
		legacy.dockerIdentity = localDockerProcessIdentity{}
		if !sameLocalProcessObservation(legacy, legacy) {
			t.Fatal("unchanged legacy process observation was rejected")
		}
	}
}
