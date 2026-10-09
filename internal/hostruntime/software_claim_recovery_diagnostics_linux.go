//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
)

const softwareClaimRecoveryRefusalPrefix = "software_claim_recovery_refusal "

var softwareClaimRecoveryInspectionOrdinal atomic.Int64

type softwareClaimRecoveryServiceDiagnostic struct {
	Slot            string `json:"slot"`
	State           string `json:"state"`
	StateCommand    string `json:"state_command"`
	PIDCommand      string `json:"pid_command"`
	PIDValid        bool   `json:"pid_valid"`
	PIDZero         bool   `json:"pid_zero"`
	CombinedCommand string `json:"combined_command"`
	CombinedShape   string `json:"combined_shape"`
	MainPIDKind     string `json:"main_pid_kind"`
	ControlPIDKind  string `json:"control_pid_kind"`
}

// Observation only: no raw group, PID, namespace identifier or error text.
type softwareClaimRecoveryProcessDiagnostic struct {
	Slot           string                                      `json:"slot"`
	Attempt        int                                         `json:"attempt"`
	Site           string                                      `json:"site"`
	ReaderStage    string                                      `json:"reader_stage"`
	Errno          string                                      `json:"errno"`
	GroupShape     bool                                        `json:"group_shape"`
	GroupBasename  bool                                        `json:"group_basename"`
	BoundsExceeded bool                                        `json:"bounds_exceeded"`
	PartialRead    bool                                        `json:"partial_read"`
	MemberCount    int                                         `json:"member_count"`
	MainPIDKind    string                                      `json:"main_pid_kind"`
	ControlPIDKind string                                      `json:"control_pid_kind"`
	Refused        bool                                        `json:"refused"`
	Namespaces     [4]softwareClaimRecoveryNamespaceDiagnostic `json:"namespaces"`
}

type softwareClaimRecoveryNamespaceDiagnostic struct {
	Role       string `json:"role"`
	PIDKind    string `json:"pid_kind"`
	PID        string `json:"pid_vs_executor"`
	Cgroup     string `json:"cgroup_vs_executor"`
	Mount      string `json:"mount_vs_executor"`
	PID1PID    string `json:"pid_vs_pid1"`
	PID1Cgroup string `json:"cgroup_vs_pid1"`
	PID1Mount  string `json:"mount_vs_pid1"`
}

type softwareClaimRecoveryRootRefusal struct {
	SchemaVersion int                                       `json:"schema_version"`
	Ordinal       int64                                     `json:"ordinal"`
	RequestSHA256 string                                    `json:"request_sha256"`
	LifecycleHeld bool                                      `json:"lifecycle_held"`
	Phase         string                                    `json:"phase"`
	WatchdogGuard string                                    `json:"watchdog_guard,omitempty"`
	Slots         [2]softwareClaimRecoveryServiceDiagnostic `json:"slots"`
	Process       *softwareClaimRecoveryProcessDiagnostic   `json:"process,omitempty"`
}

func newSoftwareClaimRecoveryRootRefusal(request SoftwareClaimRecoveryRequest) softwareClaimRecoveryRootRefusal {
	d := softwareClaimRecoveryRootRefusal{SchemaVersion: 1, Ordinal: softwareClaimRecoveryInspectionOrdinal.Add(1), RequestSHA256: request.sha256()}
	for index := range d.Slots {
		d.Slots[index] = softwareClaimRecoveryServiceDiagnostic{Slot: [2]string{"a", "b"}[index], State: "not_read", StateCommand: "not_run", PIDCommand: "not_run", CombinedCommand: "not_run", CombinedShape: "not_read", MainPIDKind: "unknown", ControlPIDKind: "unknown"}
	}
	return d
}

// Observe only the guard's original fixed service reads. Return the exact
// output and error; diagnostics cannot authorize, retry or mutate anything.
type softwareClaimRecoveryDiagnosticRunner struct {
	CommandRunner
	diagnostic *softwareClaimRecoveryRootRefusal
}

func (r softwareClaimRecoveryDiagnosticRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	output, err := r.CommandRunner.Run(ctx, dir, env, name, args...)
	if dir != "/" || len(env) != 0 || name != "/usr/bin/systemctl" || r.diagnostic == nil {
		return output, err
	}
	for index, unit := range manualHostRecoveryUnitInstances {
		if index >= len(r.diagnostic.Slots) {
			break
		}
		d := &r.diagnostic.Slots[index]
		if softwareClaimRecoveryCombinedQuery(args, unit) {
			d.CombinedCommand = softwareClaimRecoveryCommandClass(ctx, err)
			d.CombinedShape = "not_read"
			if err == nil {
				d.CombinedShape = "not_checked"
			}
			d.State, d.StateCommand, d.PIDCommand = "unknown", d.CombinedCommand, d.CombinedCommand
			d.PIDValid, d.PIDZero = false, false
			d.MainPIDKind, d.ControlPIDKind = "unknown", "unknown"
		}
		if len(args) == 2 && args[0] == "is-active" && args[1] == unit {
			d.State, d.StateCommand = "unknown", softwareClaimRecoveryCommandClass(ctx, err)
			switch state := strings.TrimSpace(output); state {
			case "inactive", "failed", "active", "activating", "deactivating":
				d.State = state
			}
		}
		if len(args) == 4 && args[0] == "show" && args[1] == "--property=MainPID" && args[2] == "--value" && args[3] == unit {
			d.PIDCommand = softwareClaimRecoveryCommandClass(ctx, err)
			pid, parseErr := strconv.Atoi(strings.TrimSpace(output))
			d.PIDValid = err == nil && parseErr == nil && pid >= 0
			d.PIDZero = d.PIDValid && pid == 0
		}
	}
	return output, err
}

func softwareClaimRecoveryCombinedQuery(args []string, unit string) bool {
	if len(args) != len(softwareClaimRecoveryWatchdogUnitProperties)+3 || args[0] != "show" || args[1] != "--all" || args[len(args)-1] != unit {
		return false
	}
	for i, key := range softwareClaimRecoveryWatchdogUnitProperties {
		if args[i+2] != "--property="+key {
			return false
		}
	}
	return true
}

func softwareClaimRecoveryDiagnosticForRunner(r CommandRunner) *softwareClaimRecoveryRootRefusal {
	if observed, ok := r.(softwareClaimRecoveryDiagnosticRunner); ok {
		return observed.diagnostic
	}
	return nil
}

func softwareClaimRecoveryObserveUnit(r CommandRunner, slot string, unit softwareClaimRecoveryWatchdogUnit, err error) {
	d := softwareClaimRecoveryDiagnosticForRunner(r)
	if d == nil || (slot != "a" && slot != "b") {
		return
	}
	index := 0
	if slot == "b" {
		index = 1
	}
	s := &d.Slots[index]
	if s.CombinedCommand != "success" {
		return
	}
	s.CombinedShape = "invalid"
	if err == nil {
		s.CombinedShape, s.State = "valid", unit.state
		s.PIDValid, s.PIDZero = true, unit.mainPID == 0
		s.MainPIDKind, s.ControlPIDKind = softwareClaimRecoveryPIDKind(unit.mainPID), softwareClaimRecoveryPIDKind(unit.controlPID)
	}
}

func softwareClaimRecoveryPIDKind(pid int) string {
	if pid == 0 {
		return "zero"
	}
	if pid > 0 {
		return "positive"
	}
	return "unknown"
}

func softwareClaimRecoveryErrno(err error) string {
	if err == nil {
		return "NONE"
	}
	for _, item := range []struct {
		err  error
		name string
	}{{syscall.ENOENT, "ENOENT"}, {syscall.ENODEV, "ENODEV"}, {syscall.EACCES, "EACCES"}, {syscall.EPERM, "EPERM"}, {syscall.ENOTDIR, "ENOTDIR"}, {syscall.EIO, "EIO"}} {
		if errors.Is(err, item.err) {
			return item.name
		}
	}
	return "OTHER"
}

func (d *softwareClaimRecoveryRootRefusal) observeProcess(attempt int, unit softwareClaimRecoveryWatchdogUnit, site string) {
	if d == nil {
		return
	}
	d.Process = &softwareClaimRecoveryProcessDiagnostic{Slot: unit.slot, Attempt: attempt, Site: site, ReaderStage: "not_captured", Errno: "NOT_CAPTURED", MemberCount: -1,
		MainPIDKind: softwareClaimRecoveryPIDKind(unit.mainPID), ControlPIDKind: softwareClaimRecoveryPIDKind(unit.controlPID)}
	for i, role := range []string{"executor", "pid1", "watchdog_main", "watchdog_control"} {
		d.Process.Namespaces[i] = softwareClaimRecoveryNamespaceDiagnostic{Role: role, PIDKind: "unknown", PID: "unknown", Cgroup: "unknown", Mount: "unknown", PID1PID: "unknown", PID1Cgroup: "unknown", PID1Mount: "unknown"}
	}
}

func (d *softwareClaimRecoveryRootRefusal) observeMemberResult(members []int, err error) {
	if d == nil || d.Process == nil {
		return
	}
	if d.Process.ReaderStage == "not_captured" {
		d.Process.Errno = softwareClaimRecoveryErrno(err)
	}
	if err == nil {
		d.Process.MemberCount = len(members)
		if len(members) > 2 {
			d.Process.MemberCount = 3
		}
	}
}

// Called only after the guard has already selected a cgroup refusal. The
// original error is returned regardless of diagnostic availability/deadline.
func (d *softwareClaimRecoveryRootRefusal) observeCgroupRefusal(ctx context.Context, unit softwareClaimRecoveryWatchdogUnit) {
	if d == nil || d.Process == nil {
		return
	}
	d.Process.Refused = true
	pids := [4]int{os.Getpid(), 1, unit.mainPID, unit.controlPID}
	var infos [4][3]os.FileInfo
	for i, pid := range pids {
		d.Process.Namespaces[i].PIDKind = softwareClaimRecoveryPIDKind(pid)
		for j, kind := range []string{"pid", "cgroup", "mnt"} {
			if pid <= 0 || ctx.Err() != nil {
				continue
			}
			infos[i][j], _ = os.Stat("/proc/" + strconv.Itoa(pid) + "/ns/" + kind)
		}
	}
	for i := range infos {
		n := &d.Process.Namespaces[i]
		for j, pair := range [3][2]*string{{&n.PID, &n.PID1PID}, {&n.Cgroup, &n.PID1Cgroup}, {&n.Mount, &n.PID1Mount}} {
			for k, base := range []int{0, 1} {
				if infos[i][j] == nil || infos[base][j] == nil {
					continue
				}
				*pair[k] = "different"
				if os.SameFile(infos[i][j], infos[base][j]) {
					*pair[k] = "same"
				}
			}
		}
	}
}

func softwareClaimRecoveryCommandClass(ctx context.Context, err error) string {
	if err == nil {
		return "success"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "canceled"
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		if exited.ExitCode() == 3 {
			return "exit3"
		}
		return "exit_other"
	}
	return "launch_other"
}

func softwareClaimRecoveryRefusalPhase(err error) string {
	var authority softwareClaimWatchdogAuthorityError
	if errors.As(err, &authority) && softwareClaimWatchdogDiagnosticReasonAllowed(authority.reason) {
		return "watchdog_guard"
	}
	for _, unit := range manualHostRecoveryUnitInstances {
		if err.Error() == unit+" must be inactive and have no MainPID" || err.Error() == "read "+unit+" active state" ||
			err.Error() == "read "+unit+" MainPID" || err.Error() == unit+" MainPID is invalid" {
			return "recovery_service"
		}
	}
	return "other_guard"
}

func softwareClaimWatchdogDiagnosticReasonAllowed(reason string) bool {
	switch reason {
	case "lifecycle_capability", "slot_paths", "slot_state", "slot_directory", "slot_current", "slot_residue", "slot_missing", "slot_identity", "slot_binding", "slot_bootstrap", "slot_file", "slot_snapshot", "unit_file", "unit_read", "unit_output", "unit_exec_start", "unit_snapshot", "process_deadline", "process_unit", "process_transition", "process_slot_missing", "process_cgroup", "process_members", "process_identity", "process_command", "process_lock_namespace", "process_binary_namespace":
		return true
	}
	for _, key := range softwareClaimRecoveryWatchdogUnitProperties {
		if reason == "unit_property_"+key {
			return true
		}
	}
	return false
}

func (d softwareClaimRecoveryRootRefusal) valid() bool {
	if d.SchemaVersion != 1 || d.Ordinal < 1 || !digestPattern.MatchString(d.RequestSHA256) ||
		(d.Phase != "lifecycle_lock" && d.Phase != "recovery_service" && d.Phase != "other_guard" && d.Phase != "watchdog_guard") ||
		(d.Phase == "lifecycle_lock" && d.LifecycleHeld) || (d.Phase != "lifecycle_lock" && !d.LifecycleHeld) {
		return false
	}
	if (d.Phase == "watchdog_guard" && !softwareClaimWatchdogDiagnosticReasonAllowed(d.WatchdogGuard)) || (d.Phase != "watchdog_guard" && d.WatchdogGuard != "") {
		return false
	}
	for index, slot := range d.Slots {
		if slot.Slot != [2]string{"a", "b"}[index] {
			return false
		}
		switch slot.State {
		case "not_read", "inactive", "failed", "active", "activating", "deactivating", "reloading", "maintenance", "unknown":
		default:
			return false
		}
		for _, class := range []string{slot.StateCommand, slot.PIDCommand, slot.CombinedCommand} {
			switch class {
			case "not_run", "success", "exit3", "exit_other", "launch_other", "deadline", "canceled":
			default:
				return false
			}
		}
		if slot.PIDZero && !slot.PIDValid {
			return false
		}
		if (slot.State == "not_read" && (slot.StateCommand != "not_run" || slot.PIDCommand != "not_run")) ||
			(slot.State != "not_read" && slot.StateCommand == "not_run") ||
			(slot.PIDValid && slot.PIDCommand != "success") {
			return false
		}
		if !softwareClaimRecoveryEnum(slot.CombinedShape, "not_read", "not_checked", "valid", "invalid") ||
			!softwareClaimRecoveryEnum(slot.MainPIDKind, "unknown", "zero", "positive") || !softwareClaimRecoveryEnum(slot.ControlPIDKind, "unknown", "zero", "positive") ||
			(slot.CombinedCommand == "not_run" && slot.CombinedShape != "not_read") ||
			(slot.CombinedShape == "valid" && (slot.CombinedCommand != "success" || !slot.PIDValid || slot.MainPIDKind == "unknown" || slot.ControlPIDKind == "unknown")) {
			return false
		}
	}
	if d.Process != nil && !d.Process.valid() {
		return false
	}
	return true
}

func softwareClaimRecoveryEnum(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func (p softwareClaimRecoveryProcessDiagnostic) valid() bool {
	if !softwareClaimRecoveryEnum(p.Slot, "a", "b") || p.Attempt < 1 || p.Attempt > 4 ||
		!softwareClaimRecoveryEnum(p.Site, "group_shape", "initial_members", "final_members") ||
		!softwareClaimRecoveryEnum(p.ReaderStage, "not_captured", "path_check", "open", "read", "parse", "bounds") ||
		!softwareClaimRecoveryEnum(p.Errno, "NONE", "ENOENT", "ENODEV", "EACCES", "EPERM", "ENOTDIR", "EIO", "OTHER", "NOT_CAPTURED") ||
		p.MemberCount < -1 || p.MemberCount > 3 || !softwareClaimRecoveryEnum(p.MainPIDKind, "unknown", "zero", "positive") || !softwareClaimRecoveryEnum(p.ControlPIDKind, "unknown", "zero", "positive") {
		return false
	}
	for i, n := range p.Namespaces {
		if n.Role != [4]string{"executor", "pid1", "watchdog_main", "watchdog_control"}[i] || !softwareClaimRecoveryEnum(n.PIDKind, "unknown", "zero", "positive") {
			return false
		}
		for _, relation := range []string{n.PID, n.Cgroup, n.Mount, n.PID1PID, n.PID1Cgroup, n.PID1Mount} {
			if !softwareClaimRecoveryEnum(relation, "unknown", "same", "different") {
				return false
			}
		}
	}
	return true
}

func logSoftwareClaimRecoveryRootRefusal(d softwareClaimRecoveryRootRefusal) {
	if !d.valid() {
		return
	}
	body, err := json.Marshal(d)
	if err == nil {
		log.Printf("%s%s", softwareClaimRecoveryRefusalPrefix, body)
	}
}
