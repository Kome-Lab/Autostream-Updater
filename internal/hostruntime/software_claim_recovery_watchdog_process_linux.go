//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var errSoftwareClaimWatchdogTransition = errors.New("trusted watchdog observation is transitioning")

type softwareClaimWatchdogProcessObservation struct {
	start       uint64
	exe         string
	exeInfo     os.FileInfo
	command     []byte
	credentials []byte
	cgroup      []byte
}

type softwareClaimWatchdogProcessRuntime struct {
	read               func(int) (softwareClaimWatchdogProcessObservation, error)
	sameLock           func(int) error
	binary             func(context.Context, int, string, os.FileInfo) error
	members            func(string) ([]int, error)
	units              func(context.Context) ([]softwareClaimRecoveryWatchdogUnit, error)
	diagnostic         *softwareClaimRecoveryRootRefusal
	observationAttempt int
}

func verifySoftwareClaimRecoveryWatchdogProcesses(ctx context.Context, rt manualHostUpgradeRuntime, units []softwareClaimRecoveryWatchdogUnit, held *heldHostLifecycleLock, absent []string, files []secureManualHostUpgradeFile) error {
	process := softwareClaimWatchdogProcessRuntime{
		read: readSoftwareClaimWatchdogProcess,
		sameLock: func(pid int) error {
			return held.MatchesPath(fmt.Sprintf("/proc/%d/root/run/autostream-updater/.autostream-host-lifecycle.lock", pid))
		},
		binary: func(ctx context.Context, pid int, path string, info os.FileInfo) error {
			for _, file := range files {
				if file.path == path {
					return verifySoftwareClaimWatchdogProcessBinary(ctx, pid, file, info, rt.allowTestPaths)
				}
			}
			return softwareClaimWatchdogRefusal("process_binary_namespace")
		},
		members: func(group string) ([]int, error) {
			d := softwareClaimRecoveryDiagnosticForRunner(rt.runner)
			var observed *softwareClaimRecoveryProcessDiagnostic
			if d != nil {
				observed = d.Process
			}
			return readSoftwareClaimWatchdogCgroupObserved(group, observed)
		},
		units: func(ctx context.Context) ([]softwareClaimRecoveryWatchdogUnit, error) {
			return readSoftwareClaimRecoveryWatchdogUnits(ctx, rt)
		},
		diagnostic: softwareClaimRecoveryDiagnosticForRunner(rt.runner),
	}
	return verifySoftwareClaimWatchdogProcessRuntime(ctx, rt.selfUpdate.slotsRoot, units, absent, process)
}

// Only a changing observation of an already authenticated fixed unit is joined.
// This never retries Recover, releases the lock, repairs a failed service, or
// uses elapsed time as proof. Every return still requires the full predicate.
func verifySoftwareClaimWatchdogProcessRuntime(ctx context.Context, slotsRoot string, units []softwareClaimRecoveryWatchdogUnit, absent []string, rt softwareClaimWatchdogProcessRuntime) error {
	for attempt := 0; attempt < 4; attempt++ {
		if ctx.Err() != nil {
			return softwareClaimWatchdogRefusal("process_deadline")
		}
		rt.observationAttempt = attempt + 1
		err := verifySoftwareClaimWatchdogProcessSet(ctx, slotsRoot, units, absent, rt)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errSoftwareClaimWatchdogTransition) {
			return err
		}
		if attempt == 3 {
			break
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return softwareClaimWatchdogRefusal("process_deadline")
		case <-timer.C:
		}
		next, err := rt.units(ctx)
		if err != nil || len(next) != len(units) {
			return softwareClaimWatchdogRefusal("process_unit")
		}
		for i := range next {
			if next[i].slot != units[i].slot || next[i].staticIdentity != units[i].staticIdentity {
				return softwareClaimWatchdogRefusal("process_unit")
			}
		}
		units = next
	}
	return softwareClaimWatchdogRefusal("process_transition")
}

func verifySoftwareClaimWatchdogProcessSet(ctx context.Context, slotsRoot string, units []softwareClaimRecoveryWatchdogUnit, absent []string, rt softwareClaimWatchdogProcessRuntime) error {
	if len(units) != 2 || rt.read == nil || rt.sameLock == nil || rt.binary == nil || rt.members == nil || rt.units == nil {
		return softwareClaimWatchdogRefusal("process_unit")
	}
	for index, unit := range units {
		if unit.slot != []string{"a", "b"}[index] {
			return softwareClaimWatchdogRefusal("process_unit")
		}
		missing := false
		for _, path := range absent {
			if path == filepath.Join(slotsRoot, unit.slot) {
				missing = true
			}
		}
		if missing && (unit.mainPID != 0 || unit.controlPID != 0) {
			return softwareClaimWatchdogRefusal("process_slot_missing")
		}
		if unit.controlGroup == "" {
			if unit.mainPID != 0 || unit.controlPID != 0 {
				return errSoftwareClaimWatchdogTransition
			}
			continue
		}
		rt.diagnostic.observeProcess(rt.observationAttempt, unit, "group_shape")
		if rt.diagnostic != nil {
			rt.diagnostic.Process.ReaderStage, rt.diagnostic.Process.Errno = "path_check", "NONE"
			rt.diagnostic.Process.GroupShape = validLocalExecutorCgroup(unit.controlGroup)
			rt.diagnostic.Process.GroupBasename = filepath.Base(unit.controlGroup) == "autostream-host-self-update-recovery@"+unit.slot+".service"
		}
		if !validLocalExecutorCgroup(unit.controlGroup) || filepath.Base(unit.controlGroup) != "autostream-host-self-update-recovery@"+unit.slot+".service" {
			rt.diagnostic.observeCgroupRefusal(ctx, unit)
			return softwareClaimWatchdogRefusal("process_cgroup")
		}
		if rt.diagnostic != nil {
			rt.diagnostic.Process.Site, rt.diagnostic.Process.ReaderStage, rt.diagnostic.Process.Errno = "initial_members", "not_captured", "NOT_CAPTURED"
		}
		members, err := rt.members(unit.controlGroup)
		rt.diagnostic.observeMemberResult(members, err)
		if errors.Is(err, os.ErrNotExist) && unit.mainPID == 0 && unit.controlPID == 0 {
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			return errSoftwareClaimWatchdogTransition
		}
		if err != nil {
			rt.diagnostic.observeCgroupRefusal(ctx, unit)
			return softwareClaimWatchdogRefusal("process_cgroup")
		}
		if len(members) > 2 {
			return softwareClaimWatchdogRefusal("process_members")
		}
		for _, pid := range members {
			if pid < 1 || (pid != unit.mainPID && pid != unit.controlPID) {
				return softwareClaimWatchdogRefusal("process_members")
			}
		}
		pids := []int{unit.mainPID}
		if unit.controlPID != unit.mainPID {
			pids = append(pids, unit.controlPID)
		}
		for _, pid := range pids {
			if pid == 0 {
				continue
			}
			found := false
			for _, member := range members {
				if member == pid {
					found = true
				}
			}
			if !found {
				return errSoftwareClaimWatchdogTransition
			}
			first, err := rt.read(pid)
			if errors.Is(err, os.ErrNotExist) {
				return errSoftwareClaimWatchdogTransition
			}
			if err != nil || first.start == 0 || !softwareClaimWatchdogRootCredentials(first.credentials) || !processCgroupTextMatches(string(first.cgroup), unit.controlGroup) {
				return softwareClaimWatchdogRefusal("process_identity")
			}
			expectedPath := filepath.Join(slotsRoot, unit.slot, "bin", "autostream-local-executor")
			if first.exe == "/usr/lib/systemd/systemd-executor" || first.exe == "/usr/lib/systemd/systemd" {
				return errSoftwareClaimWatchdogTransition
			}
			if first.exe != expectedPath || !bytes.Equal(first.command, []byte(expectedPath+"\x00recover-self-update\x00--recovery-slot\x00"+unit.slot+"\x00")) {
				return softwareClaimWatchdogRefusal("process_command")
			}
			if err := rt.binary(ctx, pid, expectedPath, first.exeInfo); errors.Is(err, os.ErrNotExist) {
				return errSoftwareClaimWatchdogTransition
			} else if err != nil {
				return softwareClaimWatchdogRefusal("process_binary_namespace")
			}
			if err := rt.sameLock(pid); errors.Is(err, os.ErrNotExist) {
				return errSoftwareClaimWatchdogTransition
			} else if err != nil {
				return softwareClaimWatchdogRefusal("process_lock_namespace")
			}
			second, err := rt.read(pid)
			if errors.Is(err, os.ErrNotExist) {
				return errSoftwareClaimWatchdogTransition
			}
			if err != nil || first.start != second.start || first.exe != second.exe || !sameSoftwareClaimWatchdogBinaryInfo(first.exeInfo, second.exeInfo) || !bytes.Equal(first.command, second.command) || !softwareClaimWatchdogRootCredentials(second.credentials) || !bytes.Equal(first.cgroup, second.cgroup) {
				return softwareClaimWatchdogRefusal("process_identity")
			}
		}
		if rt.diagnostic != nil {
			rt.diagnostic.Process.Site, rt.diagnostic.Process.ReaderStage, rt.diagnostic.Process.Errno = "final_members", "not_captured", "NOT_CAPTURED"
			rt.diagnostic.Process.BoundsExceeded, rt.diagnostic.Process.PartialRead, rt.diagnostic.Process.MemberCount = false, false, -1
		}
		again, err := rt.members(unit.controlGroup)
		rt.diagnostic.observeMemberResult(again, err)
		if errors.Is(err, os.ErrNotExist) {
			return errSoftwareClaimWatchdogTransition
		}
		if err != nil {
			rt.diagnostic.observeCgroupRefusal(ctx, unit)
			return softwareClaimWatchdogRefusal("process_cgroup")
		}
		if !reflect.DeepEqual(members, again) {
			return errSoftwareClaimWatchdogTransition
		}
	}
	return nil
}

func readSoftwareClaimWatchdogProcess(pid int) (softwareClaimWatchdogProcessObservation, error) {
	var result softwareClaimWatchdogProcessObservation
	var err error
	result.start, err = linuxProcessStartTime(pid)
	if err != nil {
		return result, err
	}
	result.exe, err = filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return result, err
	}
	result.exeInfo, err = os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return result, err
	}
	for _, file := range []struct {
		name    string
		into    *[]byte
		maximum int64
	}{{"cmdline", &result.command, 4096}, {"status", &result.credentials, 64 << 10}, {"cgroup", &result.cgroup, 64 << 10}} {
		*file.into, err = readBoundedProcFile(fmt.Sprintf("/proc/%d/%s", pid, file.name), file.maximum)
		if err != nil {
			// An exiting process can expose an empty proc field before its PID
			// disappears. Join only when the kernel now reports its exe gone;
			// the next fixed-unit observation still has to prove every guard.
			if _, gone := os.Stat(fmt.Sprintf("/proc/%d/exe", pid)); errors.Is(gone, os.ErrNotExist) {
				return result, os.ErrNotExist
			}
			return result, err
		}
	}
	return result, nil
}

func softwareClaimWatchdogRootCredentials(contents []byte) bool {
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(contents), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "Uid" && key != "Gid") {
			continue
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		values := strings.Fields(value)
		if len(values) != 4 {
			return false
		}
		for _, value := range values {
			if value != "0" {
				return false
			}
		}
	}
	return seen["Uid"] && seen["Gid"]
}

func readSoftwareClaimWatchdogCgroup(group string) ([]int, error) {
	return readSoftwareClaimWatchdogCgroupObserved(group, nil)
}

func readSoftwareClaimWatchdogCgroupObserved(group string, observed *softwareClaimRecoveryProcessDiagnostic) ([]int, error) {
	if observed != nil {
		observed.ReaderStage, observed.Errno = "path_check", "NONE"
	}
	if !validLocalExecutorCgroup(group) {
		return nil, softwareClaimWatchdogRefusal("process_cgroup")
	}
	path := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(group, "/"), "cgroup.procs")
	if !pathWithin("/sys/fs/cgroup", path) {
		return nil, softwareClaimWatchdogRefusal("process_cgroup")
	}
	file, err := os.Open(path)
	if observed != nil {
		observed.ReaderStage, observed.Errno = "open", softwareClaimRecoveryErrno(err)
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readSoftwareClaimWatchdogMembers(file, observed)
}

func readSoftwareClaimWatchdogMembers(reader io.Reader, observed *softwareClaimRecoveryProcessDiagnostic) ([]int, error) {
	// A genuine empty fixed-unit cgroup is meaningful with zero MainPID and
	// ControlPID plus the independently verified unit/slot/held-lock contract.
	data, err := io.ReadAll(io.LimitReader(reader, 4097))
	if observed != nil {
		observed.ReaderStage, observed.Errno = "read", softwareClaimRecoveryErrno(err)
		observed.BoundsExceeded, observed.PartialRead = len(data) > 4096, len(data) > 0 && err != nil
		if observed.BoundsExceeded {
			observed.ReaderStage = "bounds"
		}
	}
	if err != nil || len(data) > 4096 {
		return nil, softwareClaimWatchdogRefusal("process_cgroup")
	}
	fields := strings.Fields(string(data))
	if observed != nil {
		observed.ReaderStage, observed.MemberCount = "parse", len(fields)
		if len(fields) > 2 {
			observed.MemberCount = 3
			observed.BoundsExceeded = true
			observed.ReaderStage = "bounds"
		}
	}
	if len(fields) > 2 {
		return nil, softwareClaimWatchdogRefusal("process_members")
	}
	result := make([]int, 0, len(fields))
	for _, value := range fields {
		pid, err := strconv.Atoi(value)
		if observed != nil && err != nil {
			observed.Errno = softwareClaimRecoveryErrno(err)
		}
		if err != nil || pid < 1 {
			return nil, softwareClaimWatchdogRefusal("process_members")
		}
		for _, previous := range result {
			if pid == previous {
				return nil, softwareClaimWatchdogRefusal("process_members")
			}
		}
		result = append(result, pid)
	}
	return result, nil
}
