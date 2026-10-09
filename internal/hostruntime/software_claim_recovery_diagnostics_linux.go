//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
)

const softwareClaimRecoveryRefusalPrefix = "software_claim_recovery_refusal "

var softwareClaimRecoveryInspectionOrdinal atomic.Int64

type softwareClaimRecoveryServiceDiagnostic struct {
	Slot         string `json:"slot"`
	State        string `json:"state"`
	StateCommand string `json:"state_command"`
	PIDCommand   string `json:"pid_command"`
	PIDValid     bool   `json:"pid_valid"`
	PIDZero      bool   `json:"pid_zero"`
}

type softwareClaimRecoveryRootRefusal struct {
	SchemaVersion int                                       `json:"schema_version"`
	Ordinal       int64                                     `json:"ordinal"`
	RequestSHA256 string                                    `json:"request_sha256"`
	LifecycleHeld bool                                      `json:"lifecycle_held"`
	Phase         string                                    `json:"phase"`
	Slots         [2]softwareClaimRecoveryServiceDiagnostic `json:"slots"`
}

func newSoftwareClaimRecoveryRootRefusal(request SoftwareClaimRecoveryRequest) softwareClaimRecoveryRootRefusal {
	d := softwareClaimRecoveryRootRefusal{SchemaVersion: 1, Ordinal: softwareClaimRecoveryInspectionOrdinal.Add(1), RequestSHA256: request.sha256()}
	for index := range d.Slots {
		d.Slots[index] = softwareClaimRecoveryServiceDiagnostic{Slot: [2]string{"a", "b"}[index], State: "not_read", StateCommand: "not_run", PIDCommand: "not_run"}
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
	for _, unit := range manualHostRecoveryUnitInstances {
		if err.Error() == unit+" must be inactive and have no MainPID" || err.Error() == "read "+unit+" active state" ||
			err.Error() == "read "+unit+" MainPID" || err.Error() == unit+" MainPID is invalid" {
			return "recovery_service"
		}
	}
	return "other_guard"
}

func (d softwareClaimRecoveryRootRefusal) valid() bool {
	if d.SchemaVersion != 1 || d.Ordinal < 1 || !digestPattern.MatchString(d.RequestSHA256) ||
		(d.Phase != "lifecycle_lock" && d.Phase != "recovery_service" && d.Phase != "other_guard") ||
		(d.Phase == "lifecycle_lock" && d.LifecycleHeld) || (d.Phase != "lifecycle_lock" && !d.LifecycleHeld) {
		return false
	}
	for index, slot := range d.Slots {
		if slot.Slot != [2]string{"a", "b"}[index] {
			return false
		}
		switch slot.State {
		case "not_read", "inactive", "failed", "active", "activating", "deactivating", "unknown":
		default:
			return false
		}
		for _, class := range []string{slot.StateCommand, slot.PIDCommand} {
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
