//go:build linux

package hostruntime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func restartManualHostUpgradeLocalExecutor(
	ctx context.Context,
	slot string,
	expected manualHostBinaryIdentity,
	rt manualHostUpgradeRuntime,
) error {
	if err := rt.selfUpdate.restartLocalExecutor(ctx); err != nil {
		return errors.New("restart Local Executor after unit migration")
	}
	actual, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			slot,
			"bin",
			"autostream-local-executor",
		),
		"autostream-local-executor",
		rt,
	)
	if err != nil || actual != expected {
		return errors.New("Local Executor identity after unit migration is invalid")
	}
	return nil
}

func validateManualHostUpgradeCoreServicePreconditions(
	ctx context.Context,
	rt manualHostUpgradeRuntime,
	agentStoppedForRecovery bool,
) error {
	if agentStoppedForRecovery {
		state, pid, err := readManualHostUpgradeRecoveryServiceState(
			ctx,
			rt.runner,
			hostSelfUpdateServiceUnit,
		)
		if err != nil || state != "inactive" || pid != 0 {
			return errors.New(
				"Host Agent stopped-recovery handoff is not safely quiescent",
			)
		}
	} else if err := requireManualHostSystemdState(
		ctx,
		rt.runner,
		"is-active",
		hostSelfUpdateServiceUnit,
		"active",
	); err != nil {
		return err
	}
	for _, unit := range []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateExecutorSocketUnit,
		"autostream-host-self-update-recovery@a.timer",
		"autostream-host-self-update-recovery@b.timer",
	} {
		if err := requireManualHostSystemdState(
			ctx, rt.runner, "is-active", unit, "active",
		); err != nil {
			return err
		}
	}
	for _, unit := range []string{
		hostSelfUpdateServiceUnit,
		hostSelfUpdateExecutorSocketUnit,
		"autostream-host-self-update-recovery@a.timer",
		"autostream-host-self-update-recovery@b.timer",
	} {
		if err := requireManualHostSystemdState(
			ctx, rt.runner, "is-enabled", unit, "enabled",
		); err != nil {
			return err
		}
	}
	return nil
}

func validateManualHostUpgradeRecoveryServicePreconditions(
	ctx context.Context,
	rt manualHostUpgradeRuntime,
	allowFailedBootstrap bool,
) error {
	for _, unit := range manualHostRecoveryUnitInstances {
		observed, err := readManualHostUpgradeRecoveryServiceProperties(
			ctx, rt.runner, unit,
		)
		if err != nil {
			return err
		}
		if observed.controlPID != 0 {
			return fmt.Errorf("%s must have no ControlPID", unit)
		}
		if observed.mainPID == 0 && (observed.state == "inactive" ||
			allowFailedBootstrap && observed.state == "failed") {
			continue
		}
		if observed.mainPID != 0 {
			slot := strings.TrimSuffix(strings.TrimPrefix(unit,
				"autostream-host-self-update-recovery@"), ".service")
			expected := filepath.Join(rt.selfUpdate.slotsRoot, slot, "bin", "autostream-local-executor")
			actual, err := rt.resolveProcessExe(observed.mainPID)
			if err != nil || actual != expected {
				return &manualHostUpgradeRecoveryUnconfirmed{
					unit: unit, observed: observed, cause: err, pathMismatch: err == nil,
					startupExecutor: err == nil && actual == filepath.Clean(actual) &&
						isHostRuntimeSystemdExecutor(actual),
					comparison: captureManualHostUpgradeExecutableComparison(
						rt.selfUpdate.slotsRoot, slot, actual, expected, err, observed,
					),
				}
			}
		}
		if observed.state == "inactive" {
			return fmt.Errorf("%s inactive recovery service retains a MainPID", unit)
		}
		return &manualHostUpgradeRecoveryBusy{unit: unit, observed: observed}
	}
	return nil
}

func readManualHostUpgradeRecoveryServiceState(
	ctx context.Context,
	runner CommandRunner,
	unit string,
) (string, int, error) {
	for _, recoveryUnit := range manualHostRecoveryUnitInstances {
		if unit == recoveryUnit {
			observed, err := readManualHostUpgradeRecoveryServiceProperties(ctx, runner, unit)
			if err != nil {
				return "", 0, err
			}
			if observed.controlPID != 0 {
				return "", 0, fmt.Errorf("%s must have no ControlPID", unit)
			}
			return observed.state, observed.mainPID, nil
		}
	}
	output, _ := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "is-active", unit,
	)
	state := strings.TrimSpace(output)
	if state == "" {
		return "", 0, fmt.Errorf("read %s active state", unit)
	}
	pidOutput, err := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "show",
		"--property=MainPID", "--value", unit,
	)
	if err != nil {
		return "", 0, fmt.Errorf("read %s MainPID", unit)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidOutput))
	if err != nil || pid < 0 {
		return "", 0, fmt.Errorf("%s MainPID is invalid", unit)
	}
	return state, pid, nil
}

type manualHostRecoveryServiceProperties struct {
	state      string
	subState   string
	result     string
	mainPID    int
	controlPID int
}

type manualHostUpgradeRecoveryBusy struct {
	unit     string
	observed manualHostRecoveryServiceProperties
}

// Retain the resolver cause without exposing its path or arbitrary error text.
// This is a refusal, not a busy service or an under-lock handoff permission.
type manualHostUpgradeRecoveryUnconfirmed struct {
	unit            string
	observed        manualHostRecoveryServiceProperties
	cause           error
	pathMismatch    bool
	startupExecutor bool // Same resolver's exact canonical helper; never final permission.
	comparison      *manualHostUpgradeExecutableComparison
}

// Evidence only: operands come from the comparison that already chose refusal.
// No process read, normalization for permission, or retry uses these fields.
type manualHostUpgradeExecutableComparison struct {
	SchemaVersion         int                                `json:"schema_version"`
	RecordKind            string                             `json:"record_kind"`
	Slot                  string                             `json:"slot"`
	CallSite              string                             `json:"call_site"`
	PrecedingUnitState    string                             `json:"preceding_unit_state"`
	PrecedingUnitSubstate string                             `json:"preceding_unit_substate"`
	PrecedingUnitResult   string                             `json:"preceding_unit_result"`
	MainPIDKind           string                             `json:"main_pid_kind"`
	ControlPIDKind        string                             `json:"control_pid_kind"`
	ResolverErrorNil      bool                               `json:"resolver_error_nil"`
	ActualEqualsExpected  bool                               `json:"actual_equals_expected"`
	NonAtomic             bool                               `json:"non_atomic"`
	Actual                manualHostUpgradeExecutableOperand `json:"actual"`
	Expected              manualHostUpgradeExecutableOperand `json:"expected"`
}

type manualHostUpgradeExecutableOperand struct {
	Class     string  `json:"class"`
	Bytes     *int    `json:"bytes"`
	SHA256    *string `json:"sha256"`
	Canonical *bool   `json:"canonical"`
}

func captureManualHostUpgradeExecutableComparison(
	slotsRoot, slot, actual, expected string,
	resolverErr error,
	observed manualHostRecoveryServiceProperties,
) *manualHostUpgradeExecutableComparison {
	if slot != "a" && slot != "b" {
		slot = "unknown"
	}
	return &manualHostUpgradeExecutableComparison{
		SchemaVersion: 1, RecordKind: "recovery_executable_comparison", Slot: slot, CallSite: "unknown",
		PrecedingUnitState: closedManualHostUpgradeExecutableValue(observed.state,
			"inactive failed active activating deactivating"),
		PrecedingUnitSubstate: closedManualHostUpgradeExecutableValue(observed.subState,
			"dead failed start-pre start start-post running exited stop stop-sigterm stop-sigkill stop-post final-sigterm final-sigkill"),
		PrecedingUnitResult: closedManualHostUpgradeExecutableValue(observed.result,
			"success exit-code signal core-dump timeout watchdog resources start-limit-hit protocol canceled condition assert"),
		MainPIDKind:      manualHostUpgradeExecutablePIDKind(observed.mainPID),
		ControlPIDKind:   manualHostUpgradeExecutablePIDKind(observed.controlPID),
		ResolverErrorNil: resolverErr == nil, ActualEqualsExpected: actual == expected, NonAtomic: true,
		Actual:   captureManualHostUpgradeExecutableOperand(slotsRoot, slot, actual, expected),
		Expected: captureManualHostUpgradeExecutableOperand(slotsRoot, slot, expected, expected),
	}
}

func closedManualHostUpgradeExecutableValue(value, allowed string) string {
	for _, candidate := range strings.Fields(allowed) {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}

func manualHostUpgradeExecutablePIDKind(pid int) string {
	if pid > 0 {
		return "positive"
	}
	if pid == 0 {
		return "zero"
	}
	return "unknown"
}

func captureManualHostUpgradeExecutableOperand(slotsRoot, slot, value, expected string) manualHostUpgradeExecutableOperand {
	if len(value) > 4096 {
		return manualHostUpgradeExecutableOperand{Class: "not_captured"}
	}
	length, canonical := len(value), value == filepath.Clean(value)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(value))) // Hash original bytes, before any classification normalization.
	operand := manualHostUpgradeExecutableOperand{Class: "other", Bytes: &length, SHA256: &digest, Canonical: &canonical}
	otherSlot := "b"
	if slot == "b" {
		otherSlot = "a"
	}
	switch {
	case value == "":
		operand.Class = "empty"
	case (slot == "a" || slot == "b") && value == expected:
		operand.Class = "expected_slot_binary"
	case (slot == "a" || slot == "b") && filepath.Clean(value) == filepath.Join(slotsRoot, otherSlot, "bin", "autostream-local-executor"):
		operand.Class = "other_fixed_slot_binary"
	case isHostRuntimeSystemdExecutor(value):
		operand.Class = "systemd_executor"
	case filepath.Clean(value) == "/lib/systemd/systemd" || filepath.Clean(value) == "/usr/lib/systemd/systemd":
		operand.Class = "systemd_manager"
	}
	return operand
}

func (e *manualHostUpgradeRecoveryUnconfirmed) Error() string {
	return fmt.Sprintf("%s recovery process is unconfirmed", e.unit)
}

func (e *manualHostUpgradeRecoveryUnconfirmed) Unwrap() error { return e.cause }

func (e *manualHostUpgradeRecoveryUnconfirmed) classification() string {
	if e.pathMismatch {
		return "path_mismatch"
	}
	if e.cause == nil {
		return "UNKNOWN"
	}
	for _, code := range []struct {
		err  error
		name string
	}{{os.ErrNotExist, "ENOENT"}, {syscall.EACCES, "EACCES"}, {syscall.EPERM, "EPERM"},
		{syscall.ENODEV, "ENODEV"}, {syscall.EIO, "EIO"}} {
		if errors.Is(e.cause, code.err) {
			return "resolution_error/" + code.name
		}
	}
	return "resolution_error/OTHER"
}

func (e *manualHostUpgradeRecoveryBusy) Error() string {
	return fmt.Sprintf("%s must be inactive and have no MainPID (state=%s substate=%s MainPID=%d ControlPID=%d result=%s)",
		e.unit, e.observed.state, e.observed.subState, e.observed.mainPID,
		e.observed.controlPID, e.observed.result)
}

func manualHostUpgradeRecoveryCanSettle(err error) bool {
	var busy *manualHostUpgradeRecoveryBusy
	return errors.As(err, &busy)
}

func readManualHostUpgradeRecoveryServiceProperties(
	ctx context.Context,
	runner CommandRunner,
	unit string,
) (manualHostRecoveryServiceProperties, error) {
	var observed manualHostRecoveryServiceProperties
	if err := ctx.Err(); err != nil {
		return observed, err
	}
	// One bounded query removes the separate state/PID command gap. systemd
	// properties can still transition during observation; the preflight boundary
	// rechecks them, and never treats this query as a completely atomic snapshot.
	output, err := runner.Run(ctx, "/", nil, "/usr/bin/systemctl", "show",
		"--property=ActiveState", "--property=SubState", "--property=MainPID",
		"--property=ControlPID", "--property=Result", unit)
	if err != nil || len(output) == 0 || len(output) > 4096 {
		return observed, fmt.Errorf("read %s recovery properties", unit)
	}
	observed, err = parseManualHostUpgradeRecoveryServiceProperties(output, unit)
	if err != nil {
		return observed, err
	}
	return observed, ctx.Err()
}

func parseManualHostUpgradeRecoveryServiceProperties(output, unit string) (manualHostRecoveryServiceProperties, error) {
	var observed manualHostRecoveryServiceProperties
	if len(output) == 0 || len(output) > 4096 {
		return observed, fmt.Errorf("read %s recovery properties", unit)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return observed, fmt.Errorf("%s recovery properties are invalid", unit)
		}
		if _, duplicate := values[key]; duplicate {
			return observed, fmt.Errorf("%s recovery properties have duplicate fields", unit)
		}
		values[key] = value
	}
	observed.state, observed.subState, observed.result = values["ActiveState"], values["SubState"], values["Result"]
	var err error
	observed.mainPID, err = strconv.Atoi(values["MainPID"])
	controlPID, controlErr := strconv.Atoi(values["ControlPID"])
	observed.controlPID = controlPID
	if len(values) != 5 || err != nil || controlErr != nil || observed.mainPID < 0 || controlPID < 0 {
		return observed, fmt.Errorf("%s recovery properties are incomplete", unit)
	}
	switch observed.state {
	case "inactive", "failed", "active", "activating", "deactivating":
	default:
		return observed, fmt.Errorf("%s recovery state is unknown", unit)
	}
	switch observed.subState {
	case "dead", "failed", "start-pre", "start", "start-post", "running", "exited",
		"stop", "stop-sigterm", "stop-sigkill", "stop-post", "final-sigterm", "final-sigkill":
	default:
		return observed, fmt.Errorf("%s recovery substate is unknown", unit)
	}
	switch observed.result {
	case "success", "exit-code", "signal", "core-dump", "timeout", "watchdog", "resources",
		"start-limit-hit", "protocol", "canceled", "condition", "assert":
	default:
		return observed, fmt.Errorf("%s recovery result is unknown", unit)
	}
	return observed, nil
}

func normalizeManualHostUpgradeRecoveryServices(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	if snapshot.recoveryUnitConfig == nil || !snapshot.recoveryUnitFinal {
		return errors.New("corrected Host recovery unit is unavailable for bootstrap")
	}
	for _, unit := range manualHostRecoveryUnitInstances {
		state, pid, err := readManualHostUpgradeRecoveryServiceState(
			ctx, rt.runner, unit,
		)
		if err != nil || pid != 0 {
			return fmt.Errorf("%s is not safely quiescent", unit)
		}
		if state == "failed" {
			if _, err := rt.runner.Run(
				ctx, "/", nil, "/usr/bin/systemctl", "reset-failed", unit,
			); err != nil {
				return fmt.Errorf("reset failed bootstrap recovery unit %s", unit)
			}
		} else if state != "inactive" {
			return fmt.Errorf("%s is not inactive", unit)
		}
	}
	return validateManualHostUpgradeRecoveryServicePreconditions(ctx, rt, false)
}

func requireManualHostSystemdState(
	ctx context.Context,
	runner CommandRunner,
	operation, unit, expected string,
) error {
	output, err := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", operation, unit,
	)
	actual := strings.TrimSpace(output)
	if expected == "inactive" {
		if actual == expected {
			return nil
		}
	} else if err == nil && actual == expected {
		return nil
	}
	return fmt.Errorf("%s must be %s", unit, expected)
}
