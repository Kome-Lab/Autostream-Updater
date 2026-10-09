//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Frozen R1 ProcessSet source, renamed only. The private source manifest
// compares its complete token body to e066c55 before any product edit.
// This test-only replay retains the positive case's expected old refusal;
// it never executes an old Updater or supplies a runtime fallback.
func softwareClaimRecoveryR2InitialENOENTChecks(t *testing.T) {
	cases := []softwareClaimRecoveryR2Expected{
		{"main_zero", "none", 1, 3, 0, 0, 0},
		{"control_zero", "none", 1, 3, 0, 0, 0},
		{"main_live", "none", 1, 3, 2, 1, 1},
		{"control_live", "none", 1, 3, 2, 1, 1},
		{"persistent_main", "process_transition", 3, 4, 0, 0, 0},
		{"persistent_control", "process_transition", 3, 4, 0, 0, 0},
		{"unit_changed", "process_unit", 1, 1, 0, 0, 0},
		{"slot_changed", "process_unit", 1, 1, 0, 0, 0},
		{"unit_count", "process_unit", 1, 1, 0, 0, 0},
		{"unit_shape", "process_unit", 1, 1, 0, 0, 0},
		{"query_error", "process_unit", 1, 1, 0, 0, 0},
		{"group_bad", "process_cgroup", 1, 1, 0, 0, 0},
		{"foreign_member", "process_members", 1, 2, 0, 0, 0},
		{"foreign_uid", "process_identity", 1, 2, 1, 0, 0},
		{"foreign_gid", "process_identity", 1, 2, 1, 0, 0},
		{"foreign_cgroup", "process_identity", 1, 2, 1, 0, 0},
		{"foreign_exe", "process_command", 1, 2, 1, 0, 0},
		{"foreign_command", "process_command", 1, 2, 1, 0, 0},
		{"foreign_inode", "process_binary_namespace", 1, 2, 1, 1, 0},
		{"binary_namespace", "process_binary_namespace", 1, 2, 1, 1, 0},
		{"different_lock", "process_lock_namespace", 1, 2, 1, 1, 1},
		{"recycled_inode", "process_identity", 1, 2, 2, 1, 1},
		{"recycled_pid", "process_identity", 1, 2, 2, 1, 1},
		{"member_absent", "process_transition", 3, 4, 0, 0, 0},
		{"ENODEV", "process_cgroup", 0, 1, 0, 0, 0},
		{"EACCES", "process_cgroup", 0, 1, 0, 0, 0},
		{"EPERM", "process_cgroup", 0, 1, 0, 0, 0},
		{"ENOTDIR", "process_cgroup", 0, 1, 0, 0, 0},
		{"EIO", "process_cgroup", 0, 1, 0, 0, 0},
		{"OTHER", "process_cgroup", 0, 1, 0, 0, 0},
		{"text_ENOENT", "process_cgroup", 0, 1, 0, 0, 0},
		{"read_ENOENT", "process_cgroup", 0, 1, 0, 0, 0},
		{"read_ENODEV", "process_cgroup", 0, 1, 0, 0, 0},
		{"malformed", "process_cgroup", 0, 1, 0, 0, 0},
		{"oversize", "process_cgroup", 0, 1, 0, 0, 0},
		{"duplicate", "process_cgroup", 0, 1, 0, 0, 0},
		{"excess", "process_cgroup", 0, 1, 0, 0, 0},
		{"canceled", "process_deadline", 0, 0, 0, 0, 0},
		{"deadline", "process_deadline", 0, 0, 0, 0, 0},
		{"cancel_after_missing", "process_deadline", 0, 1, 0, 0, 0},
		{"zero_missing", "none", 0, 1, 0, 0, 0},
		{"final_missing", "none", 1, 4, 2, 1, 1},
		{"steady_live", "none", 0, 2, 2, 1, 1},
	}
	for _, want := range cases {
		t.Run("r2_initial_enoent/"+want.name, func(t *testing.T) {
			infos := make([]os.FileInfo, 0, 2)
			for i := 0; i < 2; i++ {
				path := filepath.Join(t.TempDir(), "executor")
				if err := os.WriteFile(path, []byte("fixture executor\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				infos = append(infos, info)
			}
			var results []softwareClaimRecoveryR2Expected
			for _, enabled := range []bool{false, true} {
				// Same complete fixture input against frozen R1 source and the
				// real candidate loop. Before FAIL is retained, never erased.
				if strings.HasPrefix(want.name, "main_") || strings.HasPrefix(want.name, "control_") || strings.HasPrefix(want.name, "persistent_") {
					before := softwareClaimRecoveryR2Fixture(t, want.name, enabled, infos[0], infos[1])
					err := softwareClaimRecoveryR2BeforeProcessSet(before.ctx, before.root, before.units, nil, before.runtime)
					if softwareClaimRecoveryR2Reason(err) != "process_cgroup" || before.unitsRead != 0 || before.membersRead != 1 {
						t.Fatal("frozen R1 positive failure was not reproduced with the same inputs")
					}
					t.Logf("R2 before: case=%s diagnostic=%t positive=FAIL guard=process_cgroup unit_reads=0 members=1 source=e066c55", want.name, enabled)
				}
				f := softwareClaimRecoveryR2Fixture(t, want.name, enabled, infos[0], infos[1])
				err := verifySoftwareClaimWatchdogProcessRuntime(f.ctx, f.root, f.units, nil, f.runtime)
				got := softwareClaimRecoveryR2Expected{want.name, softwareClaimRecoveryR2Reason(err), f.unitsRead, f.membersRead, f.processRead, f.binaryChecks, f.lockChecks}
				if got != want {
					t.Fatalf("closed R2 result: got=%+v want=%+v", got, want)
				}
				results = append(results, got)
				t.Logf("R2 after: case=%s diagnostic=%t guard=%s unit_reads=%d members=%d process_reads=%d binary_checks=%d lock_checks=%d", want.name, enabled, got.reason, got.units, got.members, got.processes, got.binaries, got.locks)
			}
			if results[0] != results[1] {
				t.Fatal("diagnostic changed result or complete observation counts")
			}
		})
	}
}

type softwareClaimRecoveryR2Expected struct {
	name, reason                               string
	units, members, processes, binaries, locks int
}

type softwareClaimRecoveryR2FixtureState struct {
	ctx                                                           context.Context
	root                                                          string
	units                                                         []softwareClaimRecoveryWatchdogUnit
	runtime                                                       softwareClaimWatchdogProcessRuntime
	unitsRead, membersRead, processRead, binaryChecks, lockChecks int
}

func softwareClaimRecoveryR2Reason(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, errSoftwareClaimWatchdogTransition) {
		return "transition"
	}
	var authority softwareClaimWatchdogAuthorityError
	if errors.As(err, &authority) {
		return authority.reason
	}
	return "unexpected"
}

func softwareClaimRecoveryR2Fixture(t *testing.T, name string, enabled bool, trustedInfo, foreignInfo os.FileInfo) *softwareClaimRecoveryR2FixtureState {
	t.Helper()
	f := &softwareClaimRecoveryR2FixtureState{root: "/protected-fixture/slots"}
	group := "/system.slice/autostream-host-self-update-recovery@a.service"
	f.units = []softwareClaimRecoveryWatchdogUnit{{slot: "a", state: "activating", mainPID: 42, controlGroup: group, staticIdentity: "a"}, {slot: "b", state: "inactive", staticIdentity: "b"}}
	if strings.Contains(name, "control") {
		f.units[0].mainPID, f.units[0].controlPID = 0, 42
	}
	if name == "zero_missing" {
		f.units[0].mainPID = 0
	}
	path := f.root + "/a/bin/autostream-local-executor"
	observation := softwareClaimWatchdogProcessObservation{start: 1, exe: path, exeInfo: trustedInfo, command: []byte(path + "\x00recover-self-update\x00--recovery-slot\x00a\x00"), credentials: []byte("Uid: 0 0 0 0\nGid: 0 0 0 0\n"), cgroup: []byte("0::" + group + "\n")}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.ctx = ctx
	if name == "canceled" {
		cancel()
	}
	if name == "deadline" {
		var stop context.CancelFunc
		f.ctx, stop = context.WithDeadline(ctx, time.Unix(0, 0))
		t.Cleanup(stop)
	}
	d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
	if enabled {
		f.runtime.diagnostic = &d
	}
	f.runtime.observationAttempt = 1
	f.runtime.read = func(int) (softwareClaimWatchdogProcessObservation, error) {
		f.processRead++
		value := observation
		switch name {
		case "foreign_uid":
			value.credentials = []byte("Uid: 1 1 1 1\nGid: 0 0 0 0\n")
		case "foreign_gid":
			value.credentials = []byte("Uid: 0 0 0 0\nGid: 1 1 1 1\n")
		case "foreign_cgroup":
			value.cgroup = []byte("0::/foreign.service\n")
		case "foreign_exe":
			value.exe = "/foreign"
		case "foreign_command":
			value.command = []byte(path + "\x00run\x00")
		case "foreign_inode":
			value.exeInfo = foreignInfo
		case "recycled_inode":
			if f.processRead == 2 {
				value.exeInfo = foreignInfo
			}
		case "recycled_pid":
			if f.processRead == 2 {
				value.start = 2
			}
		}
		return value, nil
	}
	f.runtime.binary = func(_ context.Context, _ int, _ string, info os.FileInfo) error {
		f.binaryChecks++
		if name == "binary_namespace" || !sameSoftwareClaimWatchdogBinaryInfo(trustedInfo, info) {
			return errors.New("fixed fixture binary mismatch")
		}
		return nil
	}
	f.runtime.sameLock = func(int) error {
		f.lockChecks++
		if name == "different_lock" {
			return errors.New("fixed fixture lock mismatch")
		}
		return nil
	}
	missing := fmt.Errorf("wrapped: %w", &os.PathError{Op: "open", Path: "private-fixture-cgroup", Err: syscall.ENOENT})
	f.runtime.members = func(string) ([]int, error) {
		f.membersRead++
		codes := map[string]error{"ENODEV": syscall.ENODEV, "EACCES": syscall.EACCES, "EPERM": syscall.EPERM, "ENOTDIR": syscall.ENOTDIR, "EIO": syscall.EIO}
		if code, ok := codes[name]; ok {
			return nil, &os.PathError{Op: "open", Path: "private-fixture-cgroup", Err: code}
		}
		if name == "OTHER" || name == "text_ENOENT" {
			return nil, errors.New("ENOENT text only")
		}
		var observed *softwareClaimRecoveryProcessDiagnostic
		if enabled {
			observed = d.Process
		}
		if name == "read_ENOENT" || name == "read_ENODEV" {
			failure := error(syscall.ENODEV)
			if name == "read_ENOENT" {
				failure = missing
			}
			return readSoftwareClaimWatchdogMembers(&softwareClaimRecoveryR1ErrorReader{body: []byte("42\n"), err: failure}, observed)
		}
		if body, ok := map[string]string{"malformed": "bad\n", "oversize": strings.Repeat(" ", 4097), "duplicate": "42\n42\n", "excess": "42\n43\n44\n"}[name]; ok {
			return readSoftwareClaimWatchdogMembers(strings.NewReader(body), observed)
		}
		if strings.HasPrefix(name, "persistent_") || name == "zero_missing" {
			return nil, missing
		}
		if name == "final_missing" && f.membersRead == 2 {
			return nil, missing
		}
		if f.membersRead == 1 && name != "steady_live" && name != "final_missing" {
			if name == "cancel_after_missing" {
				cancel()
			}
			return nil, missing
		}
		if name == "foreign_member" {
			return []int{43}, nil
		}
		if name == "member_absent" || (f.units[0].mainPID == 0 && f.units[0].controlPID == 0) {
			return []int{}, nil
		}
		return []int{42}, nil
	}
	f.runtime.units = func(context.Context) ([]softwareClaimRecoveryWatchdogUnit, error) {
		f.unitsRead++
		next := append([]softwareClaimRecoveryWatchdogUnit(nil), f.units...)
		switch name {
		case "main_zero", "control_zero", "final_missing":
			next[0].mainPID, next[0].controlPID, next[0].state = 0, 0, "inactive"
		case "unit_changed":
			next[0].staticIdentity = "changed"
		case "slot_changed":
			next[0].slot = "foreign"
		case "group_bad":
			next[0].controlGroup = "/system.slice/foreign.service"
		case "unit_count":
			return next[:1], nil
		case "query_error":
			return nil, syscall.EIO
		case "unit_shape":
			body := strings.Replace(softwareClaimRecoveryWatchdogUnitTestOutput("a", softwareClaimRecoveryWatchdogUnitPath), "MainPID=0\n", "MainPID=bad\n", 1)
			_, err := parseSoftwareClaimRecoveryWatchdogUnit(body, "a", softwareClaimRecoveryWatchdogUnitPath)
			return nil, err
		}
		f.units = next
		return next, nil
	}
	return f
}

func softwareClaimRecoveryR2BeforeProcessSet(ctx context.Context, slotsRoot string, units []softwareClaimRecoveryWatchdogUnit, absent []string, rt softwareClaimWatchdogProcessRuntime) error {
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
