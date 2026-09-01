//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	manualHostUpgradeTestOldVersion    = "v9.9.8"
	manualHostUpgradeTestTargetVersion = "v9.9.9"
)

var (
	manualHostUpgradeTestOldCommit     = strings.Repeat("a", 40)
	manualHostUpgradeTestTargetCommit  = strings.Repeat("b", 40)
	manualHostUpgradeTestOldBuildDate  = time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	manualHostUpgradeTestBuildDate     = time.Date(2026, 8, 1, 4, 5, 6, 0, time.UTC)
	manualHostUpgradeTestActivationNow = time.Date(2026, 8, 2, 7, 8, 9, 0, time.UTC)
)

type manualHostUpgradeLinuxFixture struct {
	root               string
	artifactRoot       string
	identityPath       string
	policyPath         string
	publicAgentPath    string
	publicExecutorPath string
	request            ManualHostUpgradeRequest
	targetRequest      HostSelfUpdateRequest
	runtime            manualHostUpgradeRuntime
	runner             *manualHostUpgradeLinuxRunner
	waitStableCalls    int
	watchdogCalls      int
	processExeResolves map[int]int
}

type manualHostUpgradeLinuxRunner struct {
	currentLink                 string
	slotsRoot                   string
	agentActive                 bool
	executorActive              bool
	failTargetAgent             bool
	targetAgentFailed           bool
	stopAfterSideEffectErr      bool
	stopCancel                  context.CancelFunc
	stopHook                    func() error
	stopCalls                   int
	blockPostStopRestart        bool
	postStopRestartBlocked      bool
	postStopRestartCanceled     bool
	restartOrder                []string
	restartContextCanceled      []bool
	mainPIDReads                map[string]int
	mainPIDSequence             map[string][]int
	identityReads               map[string]int
	binaryIdentityHook          func(string) error
	agentRestartCount           int
	agentIdentityAfterRestart   int
	inactiveUnits               map[string]bool
	disabledUnits               map[string]bool
	recoveryUnitPath            string
	executorUnitPath            string
	recoveryEffectiveExtra      string
	recoveryReloads             int
	recoveryFailedUnits         map[string]bool
	failRecoveryReset           bool
	recoveryResetFailedAttempts int
	recoveryResetFailedCalls    int
}

func (r *manualHostUpgradeLinuxRunner) Run(
	ctx context.Context,
	_ string,
	_ []string,
	name string,
	args ...string,
) (string, error) {
	if name != "/usr/bin/systemctl" {
		return r.binaryIdentity(name, args...)
	}
	if len(args) == 0 {
		return "", errors.New("missing systemctl operation")
	}
	switch args[0] {
	case "is-active":
		quiet := len(args) == 3 && args[1] == "--quiet"
		unitIndex := 1
		if quiet {
			unitIndex = 2
		}
		if len(args) != unitIndex+1 {
			return "", errors.New("invalid systemctl is-active arguments")
		}
		unit := args[unitIndex]
		if r.recoveryFailedUnits[unit] {
			return "failed\n", errors.New("unit is failed")
		}
		active := r.unitActive(unit)
		if active {
			if quiet {
				return "", nil
			}
			return "active\n", nil
		}
		if quiet {
			return "", errors.New("unit is inactive")
		}
		return "inactive\n", errors.New("unit is inactive")
	case "is-enabled":
		if len(args) != 2 {
			return "", errors.New("invalid systemctl is-enabled arguments")
		}
		if r.disabledUnits[args[1]] {
			return "disabled\n", errors.New("unit is disabled")
		}
		return "enabled\n", nil
	case "stop":
		if len(args) != 2 || args[1] != hostSelfUpdateServiceUnit {
			return "", errors.New("unexpected systemctl stop")
		}
		r.stopCalls++
		r.agentActive = false
		if r.stopCancel != nil {
			r.stopCancel()
		}
		if r.stopHook != nil {
			if err := r.stopHook(); err != nil {
				return "", err
			}
		}
		if r.stopAfterSideEffectErr {
			return "", errors.New("injected stop failure after Agent became inactive")
		}
		return "", nil
	case "restart":
		if len(args) != 2 {
			return "", errors.New("invalid systemctl restart arguments")
		}
		if r.blockPostStopRestart && r.stopCalls > 0 &&
			!r.postStopRestartBlocked {
			r.postStopRestartBlocked = true
			<-ctx.Done()
			r.postStopRestartCanceled = true
			return "", ctx.Err()
		}
		unit := args[1]
		r.restartOrder = append(r.restartOrder, unit)
		r.restartContextCanceled = append(
			r.restartContextCanceled,
			ctx.Err() != nil,
		)
		if err := ctx.Err(); err != nil {
			return "", errors.New("restart inherited a canceled context")
		}
		switch unit {
		case hostSelfUpdateExecutorServiceUnit:
			r.executorActive = true
			return "", nil
		case hostSelfUpdateServiceUnit:
			r.agentRestartCount++
			slot, err := r.currentSlot()
			if err != nil {
				return "", err
			}
			if r.failTargetAgent && slot == HostSelfUpdateSlotB &&
				!r.targetAgentFailed {
				r.targetAgentFailed = true
				r.agentActive = false
				return "", errors.New("injected target Host Agent restart failure")
			}
			r.agentActive = true
			return "", nil
		default:
			return "", errors.New("unexpected systemctl restart unit")
		}
	case "daemon-reload":
		if len(args) != 1 {
			return "", errors.New("invalid systemctl daemon-reload arguments")
		}
		r.recoveryReloads++
		return "", nil
	case "reset-failed":
		if len(args) != 2 ||
			(args[1] != manualHostRecoveryUnitInstances[0] &&
				args[1] != manualHostRecoveryUnitInstances[1]) {
			return "", errors.New("unexpected systemctl reset-failed arguments")
		}
		r.recoveryResetFailedAttempts++
		if r.failRecoveryReset {
			return "", errors.New("injected recovery reset-failed failure")
		}
		delete(r.recoveryFailedUnits, args[1])
		r.recoveryResetFailedCalls++
		return "", nil
	case "show":
		if len(args) == 5 && args[1] == "--property=FragmentPath" &&
			args[2] == "--property=DropInPaths" &&
			args[3] == "--property=NeedDaemonReload" &&
			args[4] == hostSelfUpdateExecutorServiceUnit {
			return "FragmentPath=" + r.executorUnitPath + "\n" +
				"DropInPaths=\nNeedDaemonReload=no\n", nil
		}
		if len(args) == 5 && args[1] == "--property=FragmentPath" &&
			args[2] == "--property=DropInPaths" &&
			args[3] == "--property=NeedDaemonReload" &&
			(args[4] == manualHostRecoveryUnitInstances[0] ||
				args[4] == manualHostRecoveryUnitInstances[1]) {
			dropIns := []string{}
			entries, err := os.ReadDir(r.recoveryUnitPath + ".d")
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
			for _, entry := range entries {
				dropIns = append(
					dropIns,
					filepath.Join(r.recoveryUnitPath+".d", entry.Name()),
				)
			}
			sort.Strings(dropIns)
			if r.recoveryEffectiveExtra != "" {
				dropIns = append(dropIns, r.recoveryEffectiveExtra)
				sort.Strings(dropIns)
			}
			return "FragmentPath=" + r.recoveryUnitPath + "\n" +
				"DropInPaths=" + strings.Join(dropIns, " ") + "\n" +
				"NeedDaemonReload=no\n", nil
		}
		if len(args) != 4 || args[1] != "--property=MainPID" ||
			args[2] != "--value" {
			return "", errors.New("invalid systemctl show arguments")
		}
		unit := args[3]
		r.mainPIDReads[unit]++
		if sequence := r.mainPIDSequence[unit]; len(sequence) > 0 {
			index := r.mainPIDReads[unit] - 1
			if index >= len(sequence) {
				index = len(sequence) - 1
			}
			return fmt.Sprintf("%d\n", sequence[index]), nil
		}
		switch unit {
		case hostSelfUpdateServiceUnit:
			if !r.agentActive {
				return "0\n", nil
			}
			return "3101\n", nil
		case hostSelfUpdateExecutorServiceUnit:
			if !r.executorActive {
				return "0\n", nil
			}
			return "3102\n", nil
		case manualHostRecoveryUnitInstances[0], manualHostRecoveryUnitInstances[1]:
			return "0\n", nil
		default:
			return "", errors.New("unexpected systemctl show unit")
		}
	default:
		return "", errors.New("unexpected systemctl operation")
	}
}

func (r *manualHostUpgradeLinuxRunner) unitActive(unit string) bool {
	if r.inactiveUnits[unit] {
		return false
	}
	switch unit {
	case hostSelfUpdateServiceUnit:
		return r.agentActive
	case hostSelfUpdateExecutorServiceUnit:
		return r.executorActive
	case hostSelfUpdateExecutorSocketUnit,
		"autostream-host-self-update-recovery@a.timer",
		"autostream-host-self-update-recovery@b.timer":
		return true
	case "autostream-host-self-update-recovery@a.service",
		"autostream-host-self-update-recovery@b.service":
		return false
	default:
		return false
	}
}

func (r *manualHostUpgradeLinuxRunner) currentSlot() (string, error) {
	target, err := os.Readlink(r.currentLink)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(r.currentLink), target)
	}
	target = filepath.Clean(target)
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if target == filepath.Join(r.slotsRoot, slot) {
			return slot, nil
		}
	}
	return "", errors.New("current symlink is outside the test slots")
}

func (r *manualHostUpgradeLinuxRunner) binaryIdentity(
	name string,
	args ...string,
) (string, error) {
	if len(args) != 1 || args[0] != "--version" {
		return "", errors.New("unexpected binary identity arguments")
	}
	if r.binaryIdentityHook != nil {
		if err := r.binaryIdentityHook(name); err != nil {
			return "", err
		}
	}
	payload, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	r.identityReads[filepath.Base(name)]++
	version := manualHostUpgradeTestOldVersion
	commit := manualHostUpgradeTestOldCommit
	buildDate := manualHostUpgradeTestOldBuildDate
	if bytes.HasPrefix(payload, []byte("target:")) {
		version = manualHostUpgradeTestTargetVersion
		commit = manualHostUpgradeTestTargetCommit
		buildDate = manualHostUpgradeTestBuildDate
	} else if !bytes.HasPrefix(payload, []byte("old:")) {
		return "", errors.New("unrecognized test binary payload")
	}
	binary := filepath.Base(name)
	if binary == "autostream-host-agent" && r.agentRestartCount > 0 {
		r.agentIdentityAfterRestart++
	}
	output := fmt.Sprintf(
		"%s %s\ncommit: %s\nbuild_date: %s\n",
		binary,
		version,
		commit,
		buildDate.Format("2006-01-02T15:04:05Z"),
	)
	if binary == "autostream-local-executor" {
		output += fmt.Sprintf(
			"mutation_protocol: %d\nrecovery_protocol: %d\n",
			LocalExecutorMutationProtocolVersion,
			HostSelfUpdateRecoveryProtocolVersion,
		)
	}
	return output, nil
}

func TestManualHostUpgradeJournalRecoveryInspection(t *testing.T) {
	t.Run("missing journal is inactive", func(t *testing.T) {
		fixture := newManualHostUpgradeLinuxFixture(t)
		manualHostUpgradeLinuxMkdir(
			t,
			fixture.runtime.paths.hostStateRoot,
			0o700,
		)
		if err := validateManualHostUpgradeStateRoots(fixture.runtime); err != nil {
			t.Fatalf("validate state roots: %v", err)
		}
		journal, err := readManualHostUpgradeJournal(fixture.runtime)
		if err != nil {
			t.Fatalf("read missing journal: %v", err)
		}
		active, err := manualHostUpgradeJournalRecoveryActive(journal)
		if err != nil || active {
			t.Fatalf("missing journal active=%v err=%v", active, err)
		}
	})

	t.Run("active job with exact plan is active", func(t *testing.T) {
		fixture := newManualHostUpgradeLinuxFixture(t)
		plan := validMutationPlan()
		plan.JobID = "job-active"
		var err error
		plan.PlanSHA256, err = plan.ComputePlanSHA256()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(
			fixture.runtime.paths.hostStateRoot,
			"journal.json",
		)
		payload, err := json.Marshal(journalData{
			ActiveJob: &UpdateJob{
				ID:        "job-active",
				Operation: updateJobOperationSoftwareUpdate,
			},
			ActivePlan: &plan,
			NextSeq:    1,
		})
		if err != nil {
			t.Fatal(err)
		}
		manualHostUpgradeLinuxWriteFile(
			t,
			path,
			append(payload, '\n'),
			0o600,
		)
		journal, err := readManualHostUpgradeJournal(fixture.runtime)
		if err != nil {
			t.Fatalf("read active journal: %v", err)
		}
		active, err := manualHostUpgradeJournalRecoveryActive(journal)
		if err != nil || !active {
			t.Fatalf("active journal active=%v err=%v", active, err)
		}
	})

	t.Run("active job without plan fails closed", func(t *testing.T) {
		journal := journalData{
			ActiveJob: &UpdateJob{
				ID:        "job-active",
				Operation: updateJobOperationSoftwareUpdate,
			},
			NextSeq: 1,
		}
		active, err := manualHostUpgradeJournalRecoveryActive(journal)
		if err == nil || active || !strings.Contains(
			err.Error(),
			"software recovery plan is invalid",
		) {
			t.Fatalf("planless journal active=%v err=%v", active, err)
		}
	})

	t.Run("mismatched plan fails closed", func(t *testing.T) {
		fixture := newManualHostUpgradeLinuxFixture(t)
		plan := validMutationPlan()
		plan.JobID = "job-other"
		var err error
		plan.PlanSHA256, err = plan.ComputePlanSHA256()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(
			fixture.runtime.paths.hostStateRoot,
			"journal.json",
		)
		payload, err := json.Marshal(journalData{
			ActiveJob: &UpdateJob{
				ID:        "job-active",
				Operation: updateJobOperationSoftwareUpdate,
			},
			ActivePlan: &plan,
			NextSeq:    1,
		})
		if err != nil {
			t.Fatal(err)
		}
		manualHostUpgradeLinuxWriteFile(
			t,
			path,
			append(payload, '\n'),
			0o600,
		)
		journal, err := readManualHostUpgradeJournal(fixture.runtime)
		if err != nil {
			t.Fatalf("read mismatched journal: %v", err)
		}
		active, err := manualHostUpgradeJournalRecoveryActive(journal)
		if err == nil || active || !strings.Contains(
			err.Error(),
			"software recovery plan is invalid",
		) {
			t.Fatalf("mismatched journal active=%v err=%v", active, err)
		}
	})

	t.Run("unsafe journal fails closed", func(t *testing.T) {
		fixture := newManualHostUpgradeLinuxFixture(t)
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(
				fixture.runtime.paths.hostStateRoot,
				"journal.json",
			),
			[]byte("{}\n"),
			0o644,
		)
		journal, err := readManualHostUpgradeJournal(fixture.runtime)
		if err == nil {
			active, inspectErr := manualHostUpgradeJournalRecoveryActive(journal)
			t.Fatalf(
				"unsafe journal active=%v inspect_err=%v read_err=%v",
				active,
				inspectErr,
				err,
			)
		}
		if !strings.Contains(err.Error(), "Host Agent journal is unsafe") {
			t.Fatalf("unsafe journal error=%v", err)
		}
	})
}

func TestManualHostUpgradeCoreServiceRecoveryHandoffPreconditions(
	t *testing.T,
) {
	for _, tc := range []struct {
		name                    string
		agentStoppedForRecovery bool
		mutate                  func(*manualHostUpgradeLinuxFixture)
		wantError               string
	}{
		{
			name: "normal upgrade requires active Agent",
		},
		{
			name: "normal upgrade rejects inactive Agent",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
			},
			wantError: hostSelfUpdateServiceUnit + " must be active",
		},
		{
			name:                    "recovery handoff accepts stopped Agent",
			agentStoppedForRecovery: true,
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
			},
		},
		{
			name:                    "recovery handoff rejects active Agent",
			agentStoppedForRecovery: true,
			wantError:               "stopped-recovery handoff is not safely quiescent",
		},
		{
			name:                    "recovery handoff rejects residual Agent PID",
			agentStoppedForRecovery: true,
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
				fixture.runner.mainPIDSequence = map[string][]int{
					hostSelfUpdateServiceUnit: {9191},
				}
			},
			wantError: "stopped-recovery handoff is not safely quiescent",
		},
		{
			name:                    "recovery handoff still requires executor service",
			agentStoppedForRecovery: true,
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
				fixture.runner.executorActive = false
			},
			wantError: hostSelfUpdateExecutorServiceUnit + " must be active",
		},
		{
			name:                    "recovery handoff still requires executor socket",
			agentStoppedForRecovery: true,
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
				fixture.runner.inactiveUnits[hostSelfUpdateExecutorSocketUnit] = true
			},
			wantError: hostSelfUpdateExecutorSocketUnit + " must be active",
		},
		{
			name:                    "recovery handoff still requires recovery timer",
			agentStoppedForRecovery: true,
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
				fixture.runner.inactiveUnits["autostream-host-self-update-recovery@b.timer"] = true
			},
			wantError: "autostream-host-self-update-recovery@b.timer must be active",
		},
		{
			name:                    "recovery handoff still requires enabled Agent",
			agentStoppedForRecovery: true,
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
				fixture.runner.disabledUnits[hostSelfUpdateServiceUnit] = true
			},
			wantError: hostSelfUpdateServiceUnit + " must be enabled",
		},
		{
			name:                    "recovery handoff still requires enabled socket",
			agentStoppedForRecovery: true,
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
				fixture.runner.disabledUnits[hostSelfUpdateExecutorSocketUnit] = true
			},
			wantError: hostSelfUpdateExecutorSocketUnit + " must be enabled",
		},
		{
			name:                    "recovery handoff still requires enabled timer",
			agentStoppedForRecovery: true,
			mutate: func(fixture *manualHostUpgradeLinuxFixture) {
				fixture.runner.agentActive = false
				fixture.runner.disabledUnits["autostream-host-self-update-recovery@a.timer"] = true
			},
			wantError: "autostream-host-self-update-recovery@a.timer must be enabled",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			if tc.mutate != nil {
				tc.mutate(fixture)
			}
			err := validateManualHostUpgradeCoreServicePreconditions(
				context.Background(),
				fixture.runtime,
				tc.agentStoppedForRecovery,
			)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("core service preconditions: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("core service precondition error=%v", err)
			}
		})
	}
}

func TestVerifyManualHostUnitProcessWaitsForTransientSystemdExecutor(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	var resolvedPIDs []int
	fixture.runtime.resolveProcessExe = func(pid int) (string, error) {
		resolvedPIDs = append(resolvedPIDs, pid)
		if len(resolvedPIDs) == 1 {
			return "/usr/lib/systemd/systemd-executor", nil
		}
		return expected, nil
	}

	identity, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err != nil {
		t.Fatalf("verifyManualHostUnitProcess: %v", err)
	}
	if identity.Version != manualHostUpgradeTestOldVersion {
		t.Fatalf("identity version=%q", identity.Version)
	}
	if len(resolvedPIDs) != 3 || fixture.waitStableCalls != 2 ||
		fixture.runner.mainPIDReads[hostSelfUpdateExecutorServiceUnit] != 3 ||
		fixture.runner.identityReads["autostream-local-executor"] != 1 {
		t.Fatalf("executable resolutions=%v, want transient plus stable pair", resolvedPIDs)
	}
	for _, pid := range resolvedPIDs {
		if pid != 3102 {
			t.Fatalf("resolved PIDs=%v, want one stable MainPID", resolvedPIDs)
		}
	}
}

func TestVerifyManualHostUnitProcessRejectsUntrustedSystemdExecutorPath(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	resolves := 0
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		resolves++
		return "/tmp/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		return nil
	}

	_, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"executing outside the selected slot",
	) {
		t.Fatalf("untrusted systemd-executor path err=%v", err)
	}
	if resolves != 1 || waits != 0 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"untrusted path resolves=%d waits=%d identity_reads=%d",
			resolves,
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessBoundsPersistentSystemdExecutor(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	resolves := 0
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		resolves++
		return "/usr/lib/systemd/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		return nil
	}

	_, err := verifyManualHostUnitProcess(
		context.Background(),
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "startup probe limit") {
		t.Fatalf("persistent systemd-executor err=%v", err)
	}
	if resolves != hostSelfUpdateSystemdExecutorProbes ||
		waits != hostSelfUpdateSystemdExecutorProbes-1 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"persistent helper resolves=%d waits=%d identity_reads=%d",
			resolves,
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessHonorsCanceledTransitionWait(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	expected := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	fixture.runtime.resolveProcessExe = func(int) (string, error) {
		return "/usr/lib/systemd/systemd-executor", nil
	}
	fixture.runtime.waitStable = func(context.Context) error {
		waits++
		cancel()
		return ctx.Err()
	}

	_, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		expected,
		"autostream-local-executor",
		fixture.runtime,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transition err=%v", err)
	}
	if waits != 1 ||
		fixture.runner.identityReads["autostream-local-executor"] != 0 {
		t.Fatalf(
			"canceled transition waits=%d identity_reads=%d",
			waits,
			fixture.runner.identityReads["autostream-local-executor"],
		)
	}
}

func TestVerifyManualHostUnitProcessRejectsPIDChurn(t *testing.T) {
	for _, test := range []struct {
		name             string
		transientFirst   bool
		wantError        string
		wantStableWaits  int
		wantResolveCalls int
	}{
		{
			name:             "during_systemd_executor_transition",
			transientFirst:   true,
			wantError:        "MainPID changed during systemd-executor transition",
			wantStableWaits:  1,
			wantResolveCalls: 2,
		},
		{
			name:             "after_expected_executable",
			wantError:        "MainPID changed during stability verification",
			wantStableWaits:  1,
			wantResolveCalls: 2,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			expected := filepath.Join(
				fixture.runtime.selfUpdate.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				"autostream-local-executor",
			)
			fixture.runner.mainPIDSequence = map[string][]int{
				hostSelfUpdateExecutorServiceUnit: {3102, 4102},
			}
			resolves := 0
			fixture.runtime.resolveProcessExe = func(int) (string, error) {
				resolves++
				if test.transientFirst && resolves == 1 {
					return "/usr/lib/systemd/systemd-executor", nil
				}
				return expected, nil
			}

			_, err := verifyManualHostUnitProcess(
				context.Background(),
				hostSelfUpdateExecutorServiceUnit,
				expected,
				"autostream-local-executor",
				fixture.runtime,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("PID churn err=%v", err)
			}
			if resolves != test.wantResolveCalls ||
				fixture.waitStableCalls != test.wantStableWaits ||
				fixture.runner.identityReads["autostream-local-executor"] != 0 {
				t.Fatalf(
					"PID churn resolves=%d waits=%d identity_reads=%d",
					resolves,
					fixture.waitStableCalls,
					fixture.runner.identityReads["autostream-local-executor"],
				)
			}
		})
	}
}

func TestManualHostUpgradeStoppedRecoveryObservesDiskAgentAndLiveExecutor(
	t *testing.T,
) {
	t.Run("exact pair", func(t *testing.T) {
		fixture := newManualHostUpgradeLinuxFixture(t)
		fixture.runner.agentActive = false
		observation, err := observeManualHostRuntimeForUpgrade(
			context.Background(),
			HostSelfUpdateSlotA,
			true,
			fixture.runtime,
		)
		if err != nil {
			t.Fatalf("observe stopped recovery runtime: %v", err)
		}
		if observation.Agent.Version != manualHostUpgradeTestOldVersion ||
			observation.Executor.Version != manualHostUpgradeTestOldVersion ||
			fixture.runner.identityReads["autostream-host-agent"] != 2 ||
			fixture.runner.identityReads["autostream-local-executor"] != 1 {
			t.Fatalf(
				"observation=%+v identity_reads=%v",
				observation,
				fixture.runner.identityReads,
			)
		}
	})

	t.Run("mixed disk agent", func(t *testing.T) {
		fixture := newManualHostUpgradeLinuxFixture(t)
		fixture.runner.agentActive = false
		agentPath := filepath.Join(
			fixture.runtime.selfUpdate.slotsRoot,
			HostSelfUpdateSlotA,
			"bin",
			"autostream-host-agent",
		)
		manualHostUpgradeLinuxWriteFile(
			t,
			agentPath,
			[]byte("target:agent\n"),
			0o755,
		)
		_, err := observeManualHostRuntimeForUpgrade(
			context.Background(),
			HostSelfUpdateSlotA,
			true,
			fixture.runtime,
		)
		if err == nil || !strings.Contains(
			err.Error(),
			"installed Host Agent and Local Executor are a mixed runtime",
		) {
			t.Fatalf("mixed stopped recovery pair err=%v", err)
		}
	})

	t.Run("agent changes between identity reads", func(t *testing.T) {
		fixture := newManualHostUpgradeLinuxFixture(t)
		fixture.runner.agentActive = false
		agentPath := filepath.Join(
			fixture.runtime.selfUpdate.slotsRoot,
			HostSelfUpdateSlotA,
			"bin",
			"autostream-host-agent",
		)
		reads := 0
		fixture.runner.binaryIdentityHook = func(path string) error {
			if filepath.Clean(path) != filepath.Clean(agentPath) {
				return nil
			}
			reads++
			if reads == 2 {
				return os.WriteFile(path, []byte("target:agent\n"), 0o755)
			}
			return nil
		}
		_, err := observeManualHostRuntimeForUpgrade(
			context.Background(),
			HostSelfUpdateSlotA,
			true,
			fixture.runtime,
		)
		if err == nil || !strings.Contains(
			err.Error(),
			"stopped Host Agent identity changed during verification",
		) {
			t.Fatalf("changing stopped Agent err=%v", err)
		}
	})
}

func TestManualHostUpgradeStoppedRecoveryHandoffCommitsRuntimePair(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	fixture.runner.agentActive = false
	fixture.request.AgentStoppedForRecovery = true

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(),
		fixture.request,
		fixture.runtime,
	)
	if err != nil {
		t.Fatalf("stopped-recovery manual upgrade: %v", err)
	}
	if result.PreviousSlot != HostSelfUpdateSlotA ||
		result.ActiveSlot != HostSelfUpdateSlotB ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("stopped-recovery result=%+v", result)
	}
	if !fixture.runner.agentActive || !fixture.runner.executorActive {
		t.Fatalf(
			"stopped-recovery services agent=%v executor=%v",
			fixture.runner.agentActive,
			fixture.runner.executorActive,
		)
	}
}

func TestManualHostUpgradeStoppedRecoveryHandoffAlreadyCurrentLeavesAgentStopped(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(),
		fixture.request,
		fixture.runtime,
	); err != nil {
		t.Fatalf("prepare current target runtime: %v", err)
	}
	fixture.runner.agentActive = false
	fixture.request.AgentStoppedForRecovery = true

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(),
		fixture.request,
		fixture.runtime,
	)
	if err != nil {
		t.Fatalf("same-version stopped-recovery manual upgrade: %v", err)
	}
	if !result.AlreadyCurrent || result.ActiveSlot != HostSelfUpdateSlotB ||
		result.Version != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version stopped-recovery result=%+v", result)
	}
	if fixture.runner.agentActive {
		t.Fatal("same-version root helper restarted the installer-owned stopped Agent")
	}
}

func TestManualHostUpgradeStoppedRecoveryPreFenceFailureLeavesAgentStopped(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	fixture.runner.agentActive = false
	fixture.request.AgentStoppedForRecovery = true
	fixture.runtime.selfUpdate.writeState = func(
		string,
		[]byte,
		os.FileMode,
	) error {
		return errors.New("injected stopped-recovery state persistence failure")
	}

	_, err := upgradeHostRuntimeWithRuntime(
		context.Background(),
		fixture.request,
		fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"persist bootstrap Host runtime stable state",
	) {
		t.Fatalf("stopped-recovery pre-fence failure err=%v", err)
	}
	if fixture.runner.agentActive {
		t.Fatal("pre-fence failure restarted the installer-owned stopped Agent")
	}
}

func TestManualHostUpgradeBootstrapsMissingSlotAndCommitsRuntimePair(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil {
		t.Fatalf("upgradeHostRuntimeWithRuntime: %v", err)
	}
	if result.PreviousSlot != HostSelfUpdateSlotA ||
		result.ActiveSlot != HostSelfUpdateSlotB ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("result=%+v", result)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)

	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("current slot=%q err=%v", current, err)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil {
		t.Fatalf("load persisted state: %v", err)
	}
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotB ||
		state.HealthySlot != HostSelfUpdateSlotB ||
		state.RollbackSlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion ||
		state.RollbackAgentVersion != manualHostUpgradeTestOldVersion ||
		state.RollbackExecutorVersion != manualHostUpgradeTestOldVersion ||
		state.FailedGeneration != "" || state.PendingGeneration != "" {
		t.Fatalf("persisted state=%+v", state)
	}
	stateRootInfo, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot)
	if err != nil || !stateRootInfo.IsDir() ||
		stateRootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("bootstrapped state root info=%v err=%v", stateRootInfo, err)
	}
	assertManualHostUpgradeLinuxSlotBinding(
		t, fixture, HostSelfUpdateSlotB,
	)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	wantRestartOrder := []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
	}
	if fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(wantRestartOrder) {
		t.Fatalf(
			"restart order=%v want=%v",
			fixture.runner.restartOrder,
			wantRestartOrder,
		)
	}
	if fixture.runner.stopCalls != 1 || fixture.watchdogCalls != 1 ||
		fixture.waitStableCalls < 4 ||
		fixture.runner.mainPIDReads[hostSelfUpdateServiceUnit] < 4 ||
		fixture.runner.mainPIDReads[hostSelfUpdateExecutorServiceUnit] < 4 ||
		fixture.processExeResolves[3101] < 4 ||
		fixture.processExeResolves[3102] < 4 ||
		fixture.runner.identityReads["autostream-host-agent"] < 4 ||
		fixture.runner.identityReads["autostream-local-executor"] < 4 {
		t.Fatalf(
			"strong verification was incomplete: stops=%d watchdog=%d waits=%d pid_reads=%v exe_resolves=%v identity_reads=%v",
			fixture.runner.stopCalls,
			fixture.watchdogCalls,
			fixture.waitStableCalls,
			fixture.runner.mainPIDReads,
			fixture.processExeResolves,
			fixture.runner.identityReads,
		)
	}
}

func TestManualHostUpgradeRollsBackWhenTargetAgentActivationFails(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	fixture.runner.failTargetAgent = true
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "restart Host Agent") {
		t.Fatalf("target Agent activation failure result=%+v err=%v", result, err)
	}
	if result != (ManualHostUpgradeResult{}) {
		t.Fatalf("failed upgrade returned a result: %+v", result)
	}
	if !fixture.runner.targetAgentFailed {
		t.Fatal("target Host Agent failure injection did not execute")
	}
	current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
	if currentErr != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("rollback current slot=%q err=%v", current, currentErr)
	}
	state, stateErr := fixture.runtime.selfUpdate.loadPersistedState()
	if stateErr != nil {
		t.Fatalf("load rollback state: %v", stateErr)
	}
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestOldVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestOldVersion ||
		!strings.HasPrefix(state.FailedGeneration, manualHostUpgradeBindingVersion+"-") ||
		state.PendingGeneration != "" || state.RollbackSlot != "" {
		t.Fatalf("rollback state=%+v", state)
	}
	if info, statErr := os.Lstat(fixture.runtime.selfUpdate.stateRoot); statErr != nil ||
		!info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("post-fence rollback removed bootstrap root: info=%v err=%v", info, statErr)
	}
	assertManualHostUpgradeLinuxSlotBinding(
		t, fixture, HostSelfUpdateSlotB,
	)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)
	wantRestartOrder := []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
	}
	if fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(wantRestartOrder) {
		t.Fatalf(
			"rollback restart order=%v want=%v",
			fixture.runner.restartOrder,
			wantRestartOrder,
		)
	}
	if fixture.watchdogCalls != 2 || fixture.waitStableCalls < 5 {
		t.Fatalf(
			"rollback proof was incomplete: watchdog=%d waits=%d",
			fixture.watchdogCalls,
			fixture.waitStableCalls,
		)
	}
}

func TestManualHostUpgradeRejectsTamperedArtifactBeforeMutation(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	tampered := filepath.Join(
		fixture.artifactRoot,
		"bin",
		"autostream-host-agent",
	)
	if err := os.WriteFile(
		tampered,
		[]byte("target:autostream-host-agent\ntampered\n"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "checksum verification failed") {
		t.Fatalf("tampered artifact err=%v", err)
	}
	if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
		t.Fatalf(
			"artifact rejection mutated services: stops=%d restarts=%v",
			fixture.runner.stopCalls,
			fixture.runner.restartOrder,
		)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotB,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection created slot b: %v", err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection persisted state: %v", err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact rejection created state root: %v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("artifact rejection current slot=%q err=%v", current, err)
	}
}

func TestManualHostUpgradeRejectsDurableBlockerBeforeCreatingStateRoot(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	writeManualHostUpgradeLinuxCheckpoint(t, fixture, "started")

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked upgrade result=%+v err=%v", result, err)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocker rejection created state root: %v", err)
	}
	assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
}

func TestManualHostUpgradeRejectsUnsafeBootstrapStateLayout(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*manualHostUpgradeLinuxFixture) error
	}{
		{
			name: "parent mode",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				removeManualHostUpgradeLinuxStateRoot(t, fixture)
				return os.Chmod(fixture.runtime.paths.localExecutorStateRoot, 0o755)
			},
		},
		{
			name: "root mode",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				return os.Chmod(fixture.runtime.selfUpdate.stateRoot, 0o755)
			},
		},
		{
			name: "root symlink",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				removeManualHostUpgradeLinuxStateRoot(t, fixture)
				target := filepath.Join(fixture.root, "unsafe-state-root-target")
				if err := os.Mkdir(target, 0o700); err != nil {
					return err
				}
				return os.Symlink(target, fixture.runtime.selfUpdate.stateRoot)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			if err := test.mutate(fixture); err != nil {
				t.Fatal(err)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil || result != (ManualHostUpgradeResult{}) {
				t.Fatalf("unsafe layout result=%+v err=%v", result, err)
			}
			if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
				t.Fatalf("unsafe layout mutated services: stops=%d restarts=%v", fixture.runner.stopCalls, fixture.runner.restartOrder)
			}
		})
	}
}

func TestManualHostUpgradeRejectsStateRootEEXISTRace(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	mkdirCalls := 0
	fixture.runtime.mkdirStateRoot = func(path string, mode os.FileMode) error {
		mkdirCalls++
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		return os.Mkdir(path, mode)
	}

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if !errors.Is(err, fs.ErrExist) || result != (ManualHostUpgradeResult{}) {
		t.Fatalf("EEXIST race result=%+v err=%v", result, err)
	}
	if mkdirCalls != 1 {
		t.Fatalf("state root mkdir calls=%d want=1", mkdirCalls)
	}
	if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); err != nil {
		t.Fatalf("racing state root was removed: %v", err)
	}
	assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
}

func TestManualHostUpgradeSameVersionPersistsMissingBootstrapState(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		payload, err := os.ReadFile(filepath.Join(fixture.artifactRoot, "bin", binary))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(
				fixture.runtime.selfUpdate.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				binary,
			),
			payload,
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	removeManualHostUpgradeLinuxStateRoot(t, fixture)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || !result.AlreadyCurrent ||
		result.ActiveSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version bootstrap result=%+v err=%v", result, err)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version bootstrap state=%+v err=%v", state, err)
	}
	if fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
		t.Fatalf("same-version bootstrap mutated services: stops=%d restarts=%v", fixture.runner.stopCalls, fixture.runner.restartOrder)
	}
}

func TestManualHostUpgradeCleansCreatedStateRootWhenBootstrapFsyncFails(
	t *testing.T,
) {
	for _, failAt := range []string{"child", "parent"} {
		t.Run(failAt, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			removeManualHostUpgradeLinuxStateRoot(t, fixture)
			injected := errors.New("injected bootstrap directory fsync failure")
			failed := false
			fixture.runtime.selfUpdate.syncDir = func(path string) error {
				want := fixture.runtime.selfUpdate.stateRoot
				if failAt == "parent" {
					want = fixture.runtime.paths.localExecutorStateRoot
				}
				if !failed && filepath.Clean(path) == filepath.Clean(want) {
					failed = true
					return injected
				}
				return syncDirectory(path)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if !errors.Is(err, injected) || result != (ManualHostUpgradeResult{}) {
				t.Fatalf("%s fsync result=%+v err=%v", failAt, result, err)
			}
			if !failed {
				t.Fatalf("%s fsync injection was not reached", failAt)
			}
			if _, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s fsync failure retained created root: %v", failAt, err)
			}
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
		})
	}
}

func TestManualHostUpgradeProductionArtifactRequiresInstallerStaging(
	t *testing.T,
) {
	unsafeStage := filepath.Join(
		t.TempDir(),
		"autostream-host-agent-install.A1b2C3d4",
	)
	unsafeRoot := filepath.Join(unsafeStage, "unpack", "artifact")
	manualHostUpgradeLinuxMkdir(t, unsafeRoot, 0o755)
	if err := os.Chmod(unsafeStage, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateManualHostUpgradeArtifactStagingPath(
		unsafeRoot,
		false,
	); err == nil || !strings.Contains(err.Error(), "outside the installer") {
		t.Fatalf("replaceable parent artifact err=%v", err)
	}

	if os.Geteuid() != 0 {
		t.Skip("root ownership contract is exercised by the root Docker fixture")
	}
	var stage string
	for attempt := 0; attempt < 100; attempt++ {
		name := fmt.Sprintf(
			"autostream-host-agent-install.%08x",
			uint32(time.Now().UnixNano()+int64(attempt)),
		)
		candidate := filepath.Join("/var/tmp", name)
		if err := os.Mkdir(candidate, 0o700); err == nil {
			stage = candidate
			break
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatalf("create production-shaped stage: %v", err)
		}
	}
	if stage == "" {
		t.Fatal("could not allocate a production-shaped stage")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stage); err != nil {
			t.Errorf("remove production-shaped stage: %v", err)
		}
	})
	unpack := filepath.Join(stage, "unpack")
	root := filepath.Join(unpack, "autostream-host-agent_v9.9.9_linux_amd64")
	manualHostUpgradeLinuxMkdir(t, unpack, 0o700)
	manualHostUpgradeLinuxMkdir(t, root, 0o755)
	if err := validateManualHostUpgradeArtifactStagingPath(root, false); err != nil {
		t.Fatalf("installer-created staging rejected: %v", err)
	}
	if err := os.Chmod(unpack, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateManualHostUpgradeArtifactStagingPath(
		root,
		false,
	); err == nil || !strings.Contains(err.Error(), "staging directory is unsafe") {
		t.Fatalf("replaceable unpack directory err=%v", err)
	}
}

func TestManualHostUpgradeAllowsTerminalLocalCheckpointWithoutMutation(
	t *testing.T,
) {
	for _, phase := range []string{"succeeded", "rolled_back"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			checkpoint := writeManualHostUpgradeLinuxCheckpoint(t, fixture, phase)
			before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err != nil {
				t.Fatalf("upgrade with terminal checkpoint: %v", err)
			}
			if result.ActiveSlot != HostSelfUpdateSlotB ||
				result.Version != manualHostUpgradeTestTargetVersion {
				t.Fatalf("result=%+v", result)
			}
			assertManualHostUpgradeLinuxProtectedFileUnchanged(
				t, checkpoint, before,
			)
		})
	}
}

func TestManualHostUpgradePreservesTerminalCheckpointAcrossRollback(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	checkpoint := writeManualHostUpgradeLinuxCheckpoint(t, fixture, "succeeded")
	before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)
	fixture.runner.failTargetAgent = true

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil {
		t.Fatal("injected activation failure unexpectedly succeeded")
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(t, checkpoint, before)
}

func TestManualHostUpgradeRejectsNonTerminalLocalCheckpointAndRestoresAgent(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	checkpoint := writeManualHostUpgradeLinuxCheckpoint(
		t, fixture, "started",
	)
	before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"non-terminal Local Executor update checkpoint",
	) {
		t.Fatalf("non-terminal checkpoint result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(t, checkpoint, before)
	assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
}

func TestManualHostUpgradeRejectsInvalidLocalCheckpointBeforeMutation(
	t *testing.T,
) {
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{name: "malformed JSON", payload: []byte("{not-json\n")},
		{
			name: "invalid fields",
			payload: []byte(
				`{"schema_version":1,"job_id":"fixture-job-1",` +
					`"target_id":"invalid target","deployment_mode":"systemd",` +
					`"phase":"succeeded","target_version":"v2.0.0"}` + "\n",
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			checkpoint := filepath.Join(
				fixture.runtime.paths.localExecutorStateRoot,
				".autostream-updater-invalid.checkpoint.json",
			)
			manualHostUpgradeLinuxWriteFile(t, checkpoint, test.payload, 0o600)
			checkpointBefore := snapshotManualHostUpgradeLinuxProtectedFile(
				t, checkpoint,
			)
			identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
				t, fixture.identityPath,
			)
			policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
				t, fixture.policyPath,
			)

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil || !strings.Contains(
				err.Error(), "Local Executor update checkpoint is invalid",
			) || result != (ManualHostUpgradeResult{}) {
				t.Fatalf("invalid checkpoint result=%+v err=%v", result, err)
			}
			assertManualHostUpgradeLinuxProtectedFileUnchanged(
				t, checkpoint, checkpointBefore,
			)
			assertManualHostUpgradeLinuxProtectedFileUnchanged(
				t, fixture.identityPath, identityBefore,
			)
			assertManualHostUpgradeLinuxProtectedFileUnchanged(
				t, fixture.policyPath, policyBefore,
			)
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
		})
	}
}

func TestManualHostUpgradeFixedSystemdCheckpointTargetsCoverEveryProfile(
	t *testing.T,
) {
	targets := manualHostUpgradeFixedSystemdCheckpointTargets()
	if len(targets) != len(manualHostUpgradeFixedSystemdServiceTypes) {
		t.Fatalf(
			"fixed checkpoint targets=%d want=%d",
			len(targets),
			len(manualHostUpgradeFixedSystemdServiceTypes),
		)
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		profile, ok := standardSystemdProfileFor(target.ServiceType)
		if !ok || target.DeploymentMode != ModeSystemd || target.Systemd == nil ||
			target.Systemd.Unit != profile.unit ||
			target.Systemd.ReleaseRoot != profile.releaseRoot {
			t.Fatalf("fixed checkpoint target=%+v profile=%+v", target, profile)
		}
		path := checkpointPath(target)
		if filepath.Dir(path) != profile.releaseRoot || seen[path] {
			t.Fatalf("fixed checkpoint path=%q duplicate=%v", path, seen[path])
		}
		seen[path] = true
	}
}

func TestManualHostUpgradeScansFixedCheckpointAbsentFromConfigurations(
	t *testing.T,
) {
	tests := []struct {
		name      string
		phase     string
		invalid   bool
		wantError string
	}{
		{name: "invalid", invalid: true, wantError: "checkpoint is invalid"},
		{name: "non-terminal", phase: "started", wantError: "non-terminal"},
		{name: "succeeded", phase: "succeeded"},
		{name: "rolled back", phase: "rolled_back"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			profile, ok := standardSystemdProfileFor("encoder_recorder")
			if !ok {
				t.Fatal("missing encoder_recorder systemd profile")
			}
			fixed := Target{
				TargetID:       "encoder-removed-from-policy",
				ServiceType:    "encoder_recorder",
				DeploymentMode: ModeSystemd,
				Systemd: &SystemdTarget{
					Unit: profile.unit,
					ReleaseRoot: filepath.Join(
						fixture.root,
						"opt",
						"autostream",
						"encoder-recorder",
						"releases",
					),
				},
			}
			fixture.runtime.fixedCheckpoints = []Target{fixed}
			path := checkpointPath(fixed)
			var payload []byte
			if test.invalid {
				payload = []byte("{}\n")
			} else {
				checkpoint := updateCheckpoint{
					SchemaVersion:  checkpointSchemaVersion,
					JobID:          "fixed-checkpoint-job",
					TargetID:       "historical-encoder-01",
					DeploymentMode: ModeSystemd,
					Phase:          test.phase,
					TargetVersion:  "v2.0.0",
				}
				var err error
				payload, err = json.Marshal(checkpoint)
				if err != nil {
					t.Fatal(err)
				}
				payload = append(payload, '\n')
			}
			manualHostUpgradeLinuxWriteFile(t, path, payload, 0o600)
			before := snapshotManualHostUpgradeLinuxProtectedFile(t, path)

			policy, err := LoadLocalExecutorPolicy(fixture.policyPath, false)
			if err != nil {
				t.Fatalf("load fixture policy: %v", err)
			}
			err = scanManualHostUpdateCheckpoints(policy, nil, fixture.runtime)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("terminal fixed checkpoint rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("fixed checkpoint err=%v want=%q", err, test.wantError)
			}
			assertManualHostUpgradeLinuxProtectedFileUnchanged(t, path, before)
		})
	}
}

func TestManualHostUpgradeStopFailureUsesDetachedAgentRecovery(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	fixture.runner.stopAfterSideEffectErr = true
	ctx, cancel := context.WithCancel(context.Background())
	fixture.runner.stopCancel = cancel
	defer cancel()

	result, err := upgradeHostRuntimeWithRuntime(
		ctx, fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"stop Host Agent for manual runtime upgrade",
	) {
		t.Fatalf("side-effecting stop failure result=%+v err=%v", result, err)
	}
	if !fixture.runner.agentActive || fixture.runner.stopCalls != 1 {
		t.Fatalf("old Agent was not restored: active=%v stops=%d", fixture.runner.agentActive, fixture.runner.stopCalls)
	}
	if len(fixture.runner.restartContextCanceled) != 2 ||
		fixture.runner.restartContextCanceled[0] ||
		fixture.runner.restartContextCanceled[1] {
		t.Fatalf(
			"Agent recovery inherited canceled context: %v",
			fixture.runner.restartContextCanceled,
		)
	}
}

func TestManualHostUpgradeSameArchiveRetryUsesFreshGeneration(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	identityBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.identityPath,
	)
	policyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.policyPath,
	)
	fixture.runner.failTargetAgent = true
	firstResult, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "restart Host Agent") ||
		firstResult != (ManualHostUpgradeResult{}) {
		t.Fatalf(
			"first activation failure result=%+v err=%v",
			firstResult,
			err,
		)
	}
	if !fixture.runner.targetAgentFailed || fixture.runner.stopCalls != 1 {
		t.Fatalf(
			"first request did not cross the activation fence: target_failed=%v stops=%d",
			fixture.runner.targetAgentFailed,
			fixture.runner.stopCalls,
		)
	}
	failed, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || failed.Phase != HostSelfUpdatePhaseStable ||
		failed.ActiveSlot != HostSelfUpdateSlotA ||
		failed.HealthySlot != HostSelfUpdateSlotA ||
		failed.ActiveAgentVersion != manualHostUpgradeTestOldVersion ||
		failed.ActiveExecutorVersion != manualHostUpgradeTestOldVersion ||
		failed.FailedGeneration == "" || failed.PendingGeneration != "" ||
		failed.PendingSlot != "" || failed.RollbackSlot != "" {
		t.Fatalf("failed state=%+v err=%v", failed, err)
	}
	firstBinding, _, err := readManualHostUpdateSlotBinding(
		HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
	)
	if err != nil || firstBinding.Generation != failed.FailedGeneration {
		t.Fatalf(
			"failed slot generation=%q failed_generation=%q err=%v",
			firstBinding.Generation,
			failed.FailedGeneration,
			err,
		)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("rollback current slot=%q err=%v", current, err)
	}
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil {
		t.Fatalf("same archive retry: %v", err)
	}
	if result.PreviousSlot != HostSelfUpdateSlotA ||
		result.ActiveSlot != HostSelfUpdateSlotB ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("retry result=%+v", result)
	}
	committed, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || committed.Phase != HostSelfUpdatePhaseStable ||
		committed.ActiveSlot != HostSelfUpdateSlotB ||
		committed.HealthySlot != HostSelfUpdateSlotB ||
		committed.RollbackSlot != HostSelfUpdateSlotA ||
		committed.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		committed.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion ||
		committed.RollbackAgentVersion != manualHostUpgradeTestOldVersion ||
		committed.RollbackExecutorVersion != manualHostUpgradeTestOldVersion ||
		committed.FailedGeneration != failed.FailedGeneration ||
		committed.PendingGeneration != "" || committed.PendingSlot != "" {
		t.Fatalf("retry state=%+v err=%v", committed, err)
	}
	retryBinding, _, err := readManualHostUpdateSlotBinding(
		HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
	)
	if err != nil || retryBinding.Generation == failed.FailedGeneration ||
		!sameManualHostUpgradeArchiveContent(firstBinding, retryBinding) {
		t.Fatalf(
			"retry binding generation=%q failed_generation=%q same_content=%v err=%v",
			retryBinding.Generation,
			failed.FailedGeneration,
			sameManualHostUpgradeArchiveContent(firstBinding, retryBinding),
			err,
		)
	}
	current, err = fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("committed current slot=%q err=%v", current, err)
	}
	if fixture.runner.stopCalls != 2 {
		t.Fatalf("retry stop calls=%d want=2", fixture.runner.stopCalls)
	}
	assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)

	stateBeforeNoOp := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.selfUpdate.statePath,
	)
	stopsBeforeNoOp := fixture.runner.stopCalls
	restartsBeforeNoOp := append([]string(nil), fixture.runner.restartOrder...)
	noOp, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || noOp.PreviousSlot != HostSelfUpdateSlotB ||
		noOp.ActiveSlot != HostSelfUpdateSlotB ||
		noOp.Version != manualHostUpgradeTestTargetVersion ||
		!noOp.AlreadyCurrent {
		t.Fatalf("already-current result=%+v err=%v", noOp, err)
	}
	if fixture.runner.stopCalls != stopsBeforeNoOp ||
		fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(restartsBeforeNoOp) {
		t.Fatalf(
			"already-current request mutated services: stops=%d want=%d restarts=%v want=%v",
			fixture.runner.stopCalls,
			stopsBeforeNoOp,
			fixture.runner.restartOrder,
			restartsBeforeNoOp,
		)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.selfUpdate.statePath, stateBeforeNoOp,
	)
	current, err = fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("already-current current slot=%q err=%v", current, err)
	}
	assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.identityPath, identityBefore,
	)
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.policyPath, policyBefore,
	)
}

func TestManualHostUpgradeSameVersionStillRejectsDurableBlocker(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err != nil {
		t.Fatalf("seed current target runtime: %v", err)
	}
	checkpoint := writeManualHostUpgradeLinuxCheckpoint(t, fixture, "started")
	before := snapshotManualHostUpgradeLinuxProtectedFile(t, checkpoint)
	stops := fixture.runner.stopCalls

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked same-version result=%+v err=%v", result, err)
	}
	if fixture.runner.stopCalls != stops {
		t.Fatalf("blocked same-version retry stopped Agent: %d -> %d", stops, fixture.runner.stopCalls)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(t, checkpoint, before)
}

func TestManualHostUpgradeBlocksOnTerminalGrantWithoutMutation(t *testing.T) {
	for _, phase := range []string{
		hostSelfUpdateGrantPhaseApplied,
		hostSelfUpdateGrantPhaseFailed,
	} {
		t.Run(phase, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			if _, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			); err != nil {
				t.Fatalf("seed current target runtime: %v", err)
			}
			request, _, err := readManualHostUpdateSlotBinding(
				HostSelfUpdateSlotB, fixture.runtime.selfUpdate,
			)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := LoadLocalExecutorPolicy(fixture.policyPath, false)
			if err != nil {
				t.Fatal(err)
			}
			policySHA256, err := policy.SHA256()
			if err != nil {
				t.Fatal(err)
			}
			authorization := validHostSelfUpdateGrantAuthorization(
				"stage",
				request,
				LocalExecutorMutationFence{
					SourcePolicyRevision:    policy.SourcePolicyRevision,
					OwnershipEpoch:          3,
					OwnershipPolicyRevision: policy.ProjectionRevision,
					ExecutorPolicyRevision:  policy.PolicyRevision,
				},
				policySHA256,
			)
			grant := newHostSelfUpdateGrantState(authorization)
			grant.Phase = phase
			if phase == hostSelfUpdateGrantPhaseApplied {
				receipt := consumedHostSelfUpdateGrant(authorization).Grant
				grant.Receipt = &receipt
			}
			if err := saveHostSelfUpdateGrantState(
				fixture.runtime.selfUpdate.grantStatePath, grant, false,
			); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(fixture.runtime.selfUpdate.grantStatePath)
			if err != nil {
				t.Fatal(err)
			}

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil ||
				!strings.Contains(err.Error(), "existing Host self-update grant blocks") ||
				result != (ManualHostUpgradeResult{}) {
				t.Fatalf("terminal grant result=%+v err=%v", result, err)
			}
			after, err := os.ReadFile(fixture.runtime.selfUpdate.grantStatePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("terminal Host self-update grant changed while blocking upgrade")
			}
		})
	}
}

func TestManualHostUpgradeLoadsLegacyHelperTargetsBeforeLocking(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	legacy := validHelperTestConfig(t)
	legacy.Targets[0].Systemd.Unit = "custom-legacy-worker.service"
	legacyPath := writeHelperTestConfig(t, legacy)
	fixture.runtime.paths.legacyHelperConfigPath = legacyPath
	var lockedLegacy []Target
	fixture.runtime.acquireTargetLocks = func(
		_ LocalExecutorPolicy,
		targets []Target,
	) (func(), error) {
		lockedLegacy = append([]Target(nil), targets...)
		return func() {}, nil
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err != nil {
		t.Fatalf("upgrade with legacy helper policy: %v", err)
	}
	if len(lockedLegacy) != 1 || lockedLegacy[0].Systemd == nil ||
		lockedLegacy[0].Systemd.Unit != "custom-legacy-worker.service" {
		t.Fatalf("legacy targets were not fenced: %+v", lockedLegacy)
	}
}

func TestManualHostUpgradeRecoversCandidateWhenBeginActivationFails(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		t.Run(fmt.Sprintf("preexisting=%v", preexisting), func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			rootBefore, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot)
			if err != nil {
				t.Fatal(err)
			}
			if !preexisting {
				removeManualHostUpgradeLinuxStateRoot(t, fixture)
			}
			fixture.runtime.now = func() time.Time { return time.Time{} }

			if _, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			); err == nil || !strings.Contains(err.Error(), "activation clock") {
				t.Fatalf("BeginActivation failure err=%v", err)
			}
			assertManualHostUpgradeLinuxRejectedBeforeMutation(t, fixture)
			after, err := os.Lstat(fixture.runtime.selfUpdate.stateRoot)
			if preexisting {
				if err != nil || !os.SameFile(rootBefore, after) {
					t.Fatalf("preexisting state root changed: info=%v err=%v", after, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("created state root survived pre-fence failure: %v", err)
			}
		})
	}
}

func TestManualHostUpgradeRollsBackAmbiguousActivationStateWrite(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	injected := false
	fixture.runtime.selfUpdate.writeState = func(
		path string,
		payload []byte,
		mode os.FileMode,
	) error {
		var state HostSelfUpdateState
		if err := json.Unmarshal(payload, &state); err != nil {
			return err
		}
		if state.Phase != HostSelfUpdatePhaseActivating || injected {
			return writeAtomicFile(path, payload, mode)
		}
		injected = true
		directory := filepath.Dir(path)
		file, err := os.CreateTemp(directory, ".manual-upgrade-state-*")
		if err != nil {
			return err
		}
		temporary := file.Name()
		defer os.Remove(temporary)
		if err := file.Chmod(mode); err != nil {
			_ = file.Close()
			return err
		}
		if _, err := file.Write(payload); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Rename(temporary, path); err != nil {
			return err
		}
		return errors.New("injected state directory sync ambiguity")
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "activation fence") {
		t.Fatalf("ambiguous state write err=%v", err)
	}
	if !injected || !fixture.runner.agentActive || fixture.runner.stopCalls != 0 {
		t.Fatalf("rollback injection=%v active=%v stops=%d", injected, fixture.runner.agentActive, fixture.runner.stopCalls)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA || state.FailedGeneration == "" {
		t.Fatalf("rollback state=%+v err=%v", state, err)
	}
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
}

func TestManualHostUpgradeRollsBackWhenActivationFenceDisappears(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	fixture.runner.stopHook = func() error {
		if err := os.Remove(fixture.runtime.selfUpdate.statePath); err != nil {
			return err
		}
		return syncDirectory(fixture.runtime.selfUpdate.stateRoot)
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "state changed") {
		t.Fatalf("missing activation fence err=%v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA || !fixture.runner.agentActive {
		t.Fatalf("rollback current=%q active=%v err=%v", current, fixture.runner.agentActive, err)
	}
}

func TestManualHostUpgradeRejectsProtectedInstallationDriftBeforeSwitch(
	t *testing.T,
) {
	tests := []struct {
		name      string
		wantError string
		mutate    func(*manualHostUpgradeLinuxFixture) error
	}{
		{
			name:      "installed unit",
			wantError: "installed Host runtime unit changed",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				return os.WriteFile(
					fixture.runtime.paths.installedAgentUnit,
					[]byte("old-installer unit drift\n"),
					0o644,
				)
			},
		},
		{
			name:      "public binary link",
			wantError: "public binary link changed",
			mutate: func(fixture *manualHostUpgradeLinuxFixture) error {
				if err := os.Remove(fixture.publicAgentPath); err != nil {
					return err
				}
				return os.Symlink(
					filepath.Join(fixture.root, "old-installer-current"),
					fixture.publicAgentPath,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newManualHostUpgradeLinuxFixture(t)
			fixture.runner.stopHook = func() error { return test.mutate(fixture) }

			result, err := upgradeHostRuntimeWithRuntime(
				context.Background(), fixture.request, fixture.runtime,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) ||
				result != (ManualHostUpgradeResult{}) {
				t.Fatalf("protected drift result=%+v err=%v", result, err)
			}
			current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
			if currentErr != nil || current != HostSelfUpdateSlotA ||
				!fixture.runner.agentActive || fixture.runner.stopCalls != 1 {
				t.Fatalf(
					"protected drift rollback current=%q active=%v stops=%d err=%v",
					current,
					fixture.runner.agentActive,
					fixture.runner.stopCalls,
					currentErr,
				)
			}
		})
	}
}

func TestManualHostUpgradeDeadlineExpiryRollsBackBeforeStop(t *testing.T) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	calls := 0
	fixture.runtime.now = func() time.Time {
		calls++
		if calls == 1 {
			return manualHostUpgradeTestActivationNow
		}
		return manualHostUpgradeTestActivationNow.Add(2 * time.Minute)
	}

	if _, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	); err == nil || !strings.Contains(err.Error(), "deadline expired") {
		t.Fatalf("deadline expiry err=%v", err)
	}
	if fixture.runner.stopCalls != 0 || !fixture.runner.agentActive {
		t.Fatalf("expired activation stopped Agent: stops=%d active=%v", fixture.runner.stopCalls, fixture.runner.agentActive)
	}
}

func TestManualHostUpgradeDeadlineCancelsBlockedPostStopRunnerAndRollsBack(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	fixture.runner.blockPostStopRestart = true
	logicalNow := manualHostUpgradeTestActivationNow
	nowCalls := 0
	fixture.runtime.now = func() time.Time {
		nowCalls++
		if nowCalls == 1 {
			return logicalNow
		}
		return logicalNow.Add(30*time.Second - 300*time.Millisecond)
	}
	fixture.runtime.selfUpdate.verificationTimeout = 30 * time.Second
	setupUnlocks := 0
	lifecycleUnlocks := 0
	targetUnlocks := 0
	fixture.runtime.acquireLocks = func() (func(), error) {
		return func() {
			lifecycleUnlocks++
			setupUnlocks++
		}, nil
	}
	fixture.runtime.acquireTargetLocks = func(
		LocalExecutorPolicy,
		[]Target,
	) (func(), error) {
		return func() { targetUnlocks++ }, nil
	}

	started := time.Now()
	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked post-stop runner result=%+v err=%v", result, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("deadline cancellation took %s", elapsed)
	}
	if !fixture.runner.postStopRestartBlocked ||
		!fixture.runner.postStopRestartCanceled {
		t.Fatalf(
			"post-stop runner was not canceled: blocked=%v canceled=%v err=%v",
			fixture.runner.postStopRestartBlocked,
			fixture.runner.postStopRestartCanceled,
			err,
		)
	}
	current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
	if currentErr != nil || current != HostSelfUpdateSlotA ||
		!fixture.runner.agentActive || !fixture.runner.executorActive {
		t.Fatalf(
			"detached rollback current=%q agent=%v executor=%v err=%v",
			current,
			fixture.runner.agentActive,
			fixture.runner.executorActive,
			currentErr,
		)
	}
	state, stateErr := fixture.runtime.selfUpdate.loadPersistedState()
	if stateErr != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA || state.FailedGeneration == "" {
		t.Fatalf("detached rollback state=%+v err=%v", state, stateErr)
	}
	for index, canceled := range fixture.runner.restartContextCanceled {
		if canceled {
			t.Fatalf("rollback restart %d inherited canceled context", index)
		}
	}
	if setupUnlocks != 1 || lifecycleUnlocks != 1 || targetUnlocks != 1 {
		t.Fatalf(
			"deadline rollback lock release setup=%d lifecycle=%d targets=%d",
			setupUnlocks,
			lifecycleUnlocks,
			targetUnlocks,
		)
	}
}

func TestEnsureManualHostUpgradeDeadlineBoundaries(t *testing.T) {
	deadline := time.Date(2026, 8, 2, 7, 9, 9, 0, time.UTC)
	tests := []struct {
		name    string
		state   HostSelfUpdateState
		now     time.Time
		wantErr bool
	}{
		{
			name:    "zero deadline",
			state:   HostSelfUpdateState{},
			now:     deadline.Add(-time.Nanosecond),
			wantErr: true,
		},
		{
			name: "one nanosecond before deadline",
			state: HostSelfUpdateState{
				ActivationDeadline: deadline,
			},
			now: deadline.Add(-time.Nanosecond),
		},
		{
			name: "exactly at deadline",
			state: HostSelfUpdateState{
				ActivationDeadline: deadline,
			},
			now:     deadline,
			wantErr: true,
		},
		{
			name: "after deadline",
			state: HostSelfUpdateState{
				ActivationDeadline: deadline,
			},
			now:     deadline.Add(time.Nanosecond),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ensureManualHostUpgradeDeadline(tt.state, tt.now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ensureManualHostUpgradeDeadline() err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestManualHostUpgradeCommitDeadlineExpiryRollsBackVerifiedRuntime(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	calls := 0
	fixture.runtime.now = func() time.Time {
		calls++
		if calls == 4 {
			return manualHostUpgradeTestActivationNow.Add(
				fixture.runtime.selfUpdate.verificationTimeout,
			)
		}
		return manualHostUpgradeTestActivationNow
	}

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "deadline expired") {
		t.Fatalf("commit deadline expiry result=%+v err=%v", result, err)
	}
	if result != (ManualHostUpgradeResult{}) {
		t.Fatalf("failed upgrade returned a result: %+v", result)
	}
	if calls != 4 {
		t.Fatalf("deadline checks=%d want=4", calls)
	}

	current, currentErr := fixture.runtime.selfUpdate.readCurrentSlot()
	if currentErr != nil || current != HostSelfUpdateSlotA ||
		!fixture.runner.agentActive || !fixture.runner.executorActive {
		t.Fatalf(
			"rollback current=%q agent_active=%v executor_active=%v err=%v",
			current,
			fixture.runner.agentActive,
			fixture.runner.executorActive,
			currentErr,
		)
	}
	state, stateErr := fixture.runtime.selfUpdate.loadPersistedState()
	if stateErr != nil {
		t.Fatalf("load rollback state: %v", stateErr)
	}
	if state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestOldVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestOldVersion ||
		!strings.HasPrefix(
			state.FailedGeneration,
			manualHostUpgradeBindingVersion+"-",
		) ||
		state.PendingGeneration != "" || state.RollbackSlot != "" ||
		!state.ActivationStartedAt.IsZero() ||
		!state.ActivationDeadline.IsZero() {
		t.Fatalf("rollback state=%+v", state)
	}

	wantRestartOrder := []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateServiceUnit,
	}
	if fmt.Sprint(fixture.runner.restartOrder) != fmt.Sprint(wantRestartOrder) {
		t.Fatalf(
			"rollback restart order=%v want=%v",
			fixture.runner.restartOrder,
			wantRestartOrder,
		)
	}
	if fixture.runner.stopCalls != 1 || fixture.watchdogCalls != 2 ||
		fixture.runner.agentIdentityAfterRestart < 2 {
		t.Fatalf(
			"verified activation did not complete before rollback: stops=%d watchdog=%d agent_identity_after_restart=%d",
			fixture.runner.stopCalls,
			fixture.watchdogCalls,
			fixture.runner.agentIdentityAfterRestart,
		)
	}
	assertManualHostUpgradeLinuxSlotBinding(t, fixture, HostSelfUpdateSlotB)
	assertManualHostUpgradeLinuxNoTransitionResidue(t, fixture)
	assertManualHostUpgradeLinuxPublicLinks(t, fixture)
}

func TestManualHostUpgradeMigratesLegacyRecoveryUnitDuringBootstrap(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryFailedUnits[manualHostRecoveryUnitInstances[0]] = true

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || result.ActiveSlot != HostSelfUpdateSlotB ||
		result.PreviousSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("legacy recovery migration result=%+v err=%v", result, err)
	}
	installed, err := os.ReadFile(fixture.runtime.paths.installedRecoveryService)
	if err != nil || manualHostRecoveryUnitDigest(installed) !=
		manualHostRecoveryUnitCorrectedDigest {
		t.Fatalf("migrated recovery unit digest=%s err=%v", manualHostRecoveryUnitDigest(installed), err)
	}
	if _, err := os.Lstat(
		fixture.runtime.paths.installedRecoveryService + ".d",
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("known recovery drop-ins remained after upgrade: %v", err)
	}
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"recovery reloads=%d reset-failed=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotB ||
		state.HealthySlot != HostSelfUpdateSlotB {
		t.Fatalf("migrated bootstrap state=%+v err=%v", state, err)
	}
}

func TestManualHostUpgradeMigratesLegacyExecutorUnitDuringBootstrap(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyExecutorUnit(t, fixture)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || result.ActiveSlot != HostSelfUpdateSlotB ||
		result.PreviousSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion ||
		result.AlreadyCurrent {
		t.Fatalf("legacy executor migration result=%+v err=%v", result, err)
	}
	installed, err := os.ReadFile(fixture.runtime.paths.installedExecutorUnit)
	if err != nil || manualHostExecutorUnitTestDigest(installed) !=
		manualHostExecutorUnitCorrectedDigest {
		t.Fatalf("migrated executor unit digest=%s err=%v", manualHostExecutorUnitTestDigest(installed), err)
	}
	if fixture.runner.recoveryReloads != 1 {
		t.Fatalf("executor unit daemon-reload calls=%d, want 1", fixture.runner.recoveryReloads)
	}
	if fmt.Sprint(fixture.runner.restartOrder) !=
		fmt.Sprint([]string{
			hostSelfUpdateExecutorServiceUnit,
			hostSelfUpdateServiceUnit,
		}) {
		t.Fatalf("executor migration restart order=%v", fixture.runner.restartOrder)
	}
}

func TestManualHostUpgradeSameVersionMigratesLegacyExecutorUnit(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	copyManualHostUpgradeArtifactBinariesToSlot(
		t, fixture, HostSelfUpdateSlotA,
	)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyExecutorUnit(t, fixture)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || !result.AlreadyCurrent ||
		result.ActiveSlot != HostSelfUpdateSlotA ||
		result.PreviousSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version executor migration result=%+v err=%v", result, err)
	}
	assertManualHostExecutorUnitCorrected(t, manualHostExecutorUnitFixture{
		installedPath: fixture.runtime.paths.installedExecutorUnit,
	})
	if fmt.Sprint(fixture.runner.restartOrder) !=
		fmt.Sprint([]string{hostSelfUpdateExecutorServiceUnit}) {
		t.Fatalf("same-version executor migration restart order=%v", fixture.runner.restartOrder)
	}
}

func TestManualHostUpgradeDoesNotMigrateRecoveryUnitBeforeBlockerChecks(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	writeManualHostUpgradeLinuxCheckpoint(t, fixture, "started")
	transitionArtifact := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		"."+HostSelfUpdateSlotB+"-111111111111.new",
	)
	manualHostUpgradeLinuxMkdir(t, transitionArtifact, 0o755)
	transitionBefore, err := os.Lstat(transitionArtifact)
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.paths.installedRecoveryService,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "non-terminal") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("blocked recovery migration result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.paths.installedRecoveryService, legacyBefore,
	)
	if _, err := os.Lstat(
		fixture.runtime.paths.installedRecoveryService + ".d",
	); err != nil {
		t.Fatalf("blocked recovery migration removed known drop-ins: %v", err)
	}
	if fixture.runner.recoveryReloads != 0 ||
		fixture.runner.recoveryResetFailedCalls != 0 {
		t.Fatalf(
			"blocked recovery migration reloaded=%d reset-failed=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.stateRoot,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocked recovery migration created state root: %v", err)
	}
	transitionAfter, err := os.Lstat(transitionArtifact)
	if err != nil || !os.SameFile(transitionBefore, transitionAfter) {
		t.Fatalf("blocked recovery migration changed slot residue: info=%v err=%v", transitionAfter, err)
	}
}

func TestManualHostUpgradeSameVersionMigratesLegacyRecoveryUnit(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	copyManualHostUpgradeArtifactBinariesToSlot(
		t, fixture, HostSelfUpdateSlotA,
	)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryFailedUnits[manualHostRecoveryUnitInstances[0]] = true

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || !result.AlreadyCurrent ||
		result.ActiveSlot != HostSelfUpdateSlotA ||
		result.PreviousSlot != HostSelfUpdateSlotA ||
		result.Version != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version recovery migration result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.stopCalls != 0 ||
		len(fixture.runner.restartOrder) != 0 ||
		fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"same-version migration stops=%d restarts=%v reloads=%d reset-failed=%d",
			fixture.runner.stopCalls,
			fixture.runner.restartOrder,
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
	state, err := fixture.runtime.selfUpdate.loadPersistedState()
	if err != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != HostSelfUpdateSlotA ||
		state.HealthySlot != HostSelfUpdateSlotA ||
		state.ActiveAgentVersion != manualHostUpgradeTestTargetVersion ||
		state.ActiveExecutorVersion != manualHostUpgradeTestTargetVersion {
		t.Fatalf("same-version migration state=%+v err=%v", state, err)
	}
}

func TestManualHostUpgradeKeepsCorrectedRecoveryUnitAcrossRollbackAndRetry(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryFailedUnits[manualHostRecoveryUnitInstances[0]] = true
	fixture.runner.failTargetAgent = true

	first, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "restart Host Agent") ||
		first != (ManualHostUpgradeResult{}) {
		t.Fatalf("migration rollback result=%+v err=%v", first, err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("migration rollback current=%q err=%v", current, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"migration rollback reloads=%d reset-failed=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}

	fixture.runner.failTargetAgent = false
	retry, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || retry.ActiveSlot != HostSelfUpdateSlotB ||
		retry.PreviousSlot != HostSelfUpdateSlotA || retry.AlreadyCurrent {
		t.Fatalf("migration retry result=%+v err=%v", retry, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"migration retry repeated unit mutation: reloads=%d reset-failed=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
}

func TestManualHostUpgradeRetriesAfterBootstrapResetFailedFailure(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryFailedUnits[manualHostRecoveryUnitInstances[0]] = true
	fixture.runner.failRecoveryReset = true

	first, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "reset failed") ||
		first != (ManualHostUpgradeResult{}) {
		t.Fatalf("reset-failed injection result=%+v err=%v", first, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedAttempts != 1 ||
		fixture.runner.recoveryResetFailedCalls != 0 {
		t.Fatalf(
			"reset-failed first attempt reloads=%d attempts=%d successes=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedAttempts,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.stateRoot,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reset-failed injection created state root: %v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("reset-failed injection current=%q err=%v", current, err)
	}

	fixture.runner.failRecoveryReset = false
	retry, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil || retry.ActiveSlot != HostSelfUpdateSlotB ||
		retry.PreviousSlot != HostSelfUpdateSlotA || retry.AlreadyCurrent {
		t.Fatalf("reset-failed retry result=%+v err=%v", retry, err)
	}
	assertManualHostUpgradeRecoveryUnitConverged(t, fixture)
	if fixture.runner.recoveryReloads != 2 ||
		fixture.runner.recoveryResetFailedAttempts != 2 ||
		fixture.runner.recoveryResetFailedCalls != 1 {
		t.Fatalf(
			"reset-failed retry reloads=%d attempts=%d successes=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedAttempts,
			fixture.runner.recoveryResetFailedCalls,
		)
	}
}

func TestManualHostUpgradeRejectsDowngradeBeforeRecoveryMutation(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	copyManualHostUpgradeArtifactBinariesToSlot(
		t, fixture, HostSelfUpdateSlotA,
	)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	configureManualHostUpgradeDowngradeArtifact(t, fixture)
	transitionArtifact := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		"."+HostSelfUpdateSlotB+"-111111111111.new",
	)
	manualHostUpgradeLinuxMkdir(t, transitionArtifact, 0o755)
	transitionBefore, err := os.Lstat(transitionArtifact)
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.paths.installedRecoveryService,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "downgrade") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("downgrade result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.paths.installedRecoveryService, legacyBefore,
	)
	transitionAfter, err := os.Lstat(transitionArtifact)
	if err != nil || !os.SameFile(transitionBefore, transitionAfter) {
		t.Fatalf("downgrade changed slot residue: info=%v err=%v", transitionAfter, err)
	}
	if fixture.runner.recoveryReloads != 0 ||
		fixture.runner.recoveryResetFailedCalls != 0 ||
		fixture.runner.stopCalls != 0 {
		t.Fatalf(
			"downgrade mutated runtime: reloads=%d reset-failed=%d stops=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
			fixture.runner.stopCalls,
		)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.stateRoot,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("downgrade created state root: %v", err)
	}
}

func TestManualHostUpgradeRejectsUnknownRecoveryOverrideBeforeMutation(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	removeManualHostUpgradeLinuxStateRoot(t, fixture)
	configureManualHostUpgradeLegacyRecoveryUnit(t, fixture)
	fixture.runner.recoveryEffectiveExtra = "/run/systemd/system/unknown.conf"
	legacyBefore := snapshotManualHostUpgradeLinuxProtectedFile(
		t, fixture.runtime.paths.installedRecoveryService,
	)

	result, err := upgradeHostRuntimeWithRuntime(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err == nil || !strings.Contains(err.Error(), "unknown effective") ||
		result != (ManualHostUpgradeResult{}) {
		t.Fatalf("unknown recovery override result=%+v err=%v", result, err)
	}
	assertManualHostUpgradeLinuxProtectedFileUnchanged(
		t, fixture.runtime.paths.installedRecoveryService, legacyBefore,
	)
	if fixture.runner.recoveryReloads != 0 ||
		fixture.runner.recoveryResetFailedCalls != 0 ||
		fixture.runner.stopCalls != 0 {
		t.Fatalf(
			"unknown override mutated runtime: reloads=%d reset-failed=%d stops=%d",
			fixture.runner.recoveryReloads,
			fixture.runner.recoveryResetFailedCalls,
			fixture.runner.stopCalls,
		)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.stateRoot,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown override created state root: %v", err)
	}
}

func TestSameManualHostUpgradeArchiveContentAcceptsOnlineBindingIdentity(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	bound := fixture.targetRequest
	bound.Generation = "online-release-generation-42"
	bound.Release.ManifestAssetID = 101
	bound.Release.ManifestChecksumAssetID = 102
	bound.Release.ArchiveAssetID = 103
	bound.Release.ArchiveChecksumAssetID = 104
	if err := bound.validate(); err != nil {
		t.Fatalf("online-derived binding is invalid: %v", err)
	}
	digests, err := hostSelfUpdateArtifactBinaryDigests(fixture.artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewHostSelfUpdateState(
		manualHostUpgradeTestOldVersion,
		manualHostUpgradeTestOldVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageHostSelfUpdate(
		state, bound, HostLifecycleBlockers{}, digests,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.selfUpdate.stageSlot(
		context.Background(),
		HostSelfUpdateSlotB,
		fixture.artifactRoot,
		bound,
		digests,
	); err != nil {
		t.Fatalf("stage online-derived slot binding: %v", err)
	}
	if err := fixture.runtime.selfUpdate.saveState(staged); err != nil {
		t.Fatalf("persist online-derived staged state: %v", err)
	}
	if err := fixture.runtime.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		t.Fatalf("promote online-derived slot binding: %v", err)
	}
	if err := fixture.runtime.selfUpdate.switchCurrent(
		HostSelfUpdateSlotB,
	); err != nil {
		t.Fatalf("select online-derived bound slot: %v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("bound current slot=%q err=%v", current, err)
	}
	boundCurrent, _, err := readManualHostUpdateSlotBinding(
		current, fixture.runtime.selfUpdate,
	)
	if err != nil {
		t.Fatalf("read online-derived current binding: %v", err)
	}
	if !sameManualHostUpgradeArchiveContent(
		boundCurrent, fixture.targetRequest,
	) {
		t.Fatal("identical archive content was coupled to generation or asset IDs")
	}

	differentArchive := boundCurrent
	differentArchive.ArtifactSHA256 = "sha256:" + strings.Repeat("d", 64)
	differentArchive.Release.ArchiveSHA256 = strings.Repeat("d", 64)
	differentArchive.Release.ArchiveChecksumSHA256 = strings.Repeat("e", 64)
	if err := differentArchive.validate(); err != nil {
		t.Fatalf("coherent different-archive binding is invalid: %v", err)
	}
	if sameManualHostUpgradeArchiveContent(
		differentArchive, fixture.targetRequest,
	) {
		t.Fatal("different archive digest was accepted as identical content")
	}
}

func assertManualHostUpgradeLinuxRejectedBeforeMutation(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	if !fixture.runner.agentActive || fixture.runner.stopCalls != 0 ||
		fixture.runner.agentIdentityAfterRestart != 0 {
		t.Fatalf(
			"old Agent was not restored and identity-verified: active=%v stops=%d post_restart_identity=%d",
			fixture.runner.agentActive,
			fixture.runner.stopCalls,
			fixture.runner.agentIdentityAfterRestart,
		)
	}
	if len(fixture.runner.restartOrder) != 0 {
		t.Fatalf(
			"rejected upgrade unexpectedly restarted services: %v",
			fixture.runner.restartOrder,
		)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotA {
		t.Fatalf("rejected upgrade current slot=%q err=%v", current, err)
	}
	if _, err := os.Lstat(
		fixture.runtime.selfUpdate.statePath,
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected upgrade changed durable state: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotB,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected upgrade staged slot b: %v", err)
	}
}

func writeManualHostUpgradeLinuxCheckpoint(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
	phase string,
) string {
	t.Helper()
	checkpoint := updateCheckpoint{
		SchemaVersion:  checkpointSchemaVersion,
		JobID:          "fixture-job-1",
		TargetID:       "orphan-worker-01",
		DeploymentMode: ModeSystemd,
		Phase:          phase,
		TargetVersion:  "v2.0.0",
	}
	payload, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(
		fixture.runtime.paths.localExecutorStateRoot,
		".autostream-updater-fixture.checkpoint.json",
	)
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func removeManualHostUpgradeLinuxStateRoot(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	if err := os.Remove(fixture.runtime.selfUpdate.stateRoot); err != nil {
		t.Fatalf("remove fixture Host self-update state root: %v", err)
	}
}

func newManualHostUpgradeLinuxFixture(
	t *testing.T,
) *manualHostUpgradeLinuxFixture {
	t.Helper()
	fixture := &manualHostUpgradeLinuxFixture{
		root:               t.TempDir(),
		processExeResolves: make(map[int]int),
	}
	installRoot := filepath.Join(fixture.root, "opt", "autostream", "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	stateRoot := filepath.Join(
		fixture.root,
		"var",
		"lib",
		"autostream-local-executor",
		"host-self-update",
	)
	manualHostUpgradeLinuxMkdir(t, filepath.Join(slotsRoot, HostSelfUpdateSlotA, "bin"), 0o755)
	manualHostUpgradeLinuxMkdir(t, stateRoot, 0o700)
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(slotsRoot, HostSelfUpdateSlotA, "bin", binary),
			[]byte("old:"+binary+"\n"),
			0o755,
		)
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(
		filepath.Join("slots", HostSelfUpdateSlotA),
		currentLink,
	); err != nil {
		t.Fatal(err)
	}

	fixture.artifactRoot = filepath.Join(fixture.root, "verified-artifact")
	manualHostUpgradeLinuxMkdir(t, filepath.Join(fixture.artifactRoot, "bin"), 0o755)
	manualHostUpgradeLinuxMkdir(t, filepath.Join(fixture.artifactRoot, "systemd"), 0o755)
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(fixture.artifactRoot, "bin", binary),
			[]byte("target:"+binary+"\n"),
			0o755,
		)
	}

	installedRoot := filepath.Join(fixture.root, "etc")
	unitPaths := manualHostUpgradeLinuxUnitPaths(installedRoot)
	for _, unit := range []struct {
		source    string
		installed string
	}{
		{"autostream-host-agent.service", unitPaths.installedAgentUnit},
		{"autostream-local-executor.service", unitPaths.installedExecutorUnit},
		{"autostream-local-executor.socket", unitPaths.installedExecutorSocket},
		{"autostream-local-executor.tmpfiles", unitPaths.installedExecutorTmpfiles},
		{"autostream-host-self-update-recovery@.service", unitPaths.installedRecoveryService},
		{"autostream-host-self-update-recovery@.timer", unitPaths.installedRecoveryTimer},
	} {
		payload := []byte("fixture:" + unit.source + "\n")
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(fixture.artifactRoot, "systemd", unit.source),
			payload,
			0o644,
		)
		manualHostUpgradeLinuxWriteFile(t, unit.installed, payload, 0o644)
	}

	manifest := manualHostArtifactManifest{
		SchemaVersion: 1,
		Component:     "host-agent",
		SourceVersion: manualHostUpgradeTestTargetVersion,
		Commit:        manualHostUpgradeTestTargetCommit,
		BuildDate:     manualHostUpgradeTestBuildDate.Format("2006-01-02T15:04:05Z"),
	}
	manifest.Platform.OS = "linux"
	manifest.Platform.Arch = "amd64"
	manifest.Archive.Root = "autostream-host-agent_" +
		manualHostUpgradeTestTargetVersion + "_linux_amd64"
	manifest.Archive.Name = manifest.Archive.Root + ".tar.gz"
	manifest.Compatibility.MinimumPanelVersion =
		manualHostUpgradeTestTargetVersion
	manifest.Compatibility.RollbackCompatible = true
	manifest.Compatibility.DatabaseSchema = "none"
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxWriteFile(
		t,
		filepath.Join(fixture.artifactRoot, "artifact-manifest.json"),
		append(manifestPayload, '\n'),
		0o644,
	)
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)

	identityRoot := filepath.Join(fixture.root, "etc", "autostream-host-agent")
	fixture.identityPath = filepath.Join(identityRoot, "identity.json")
	identityPayload := []byte(
		`{"panel_url":"https://panel.example.com","node_id":"host-a",` +
			`"runtime_token":"runtime-secret","service_name":"Host A"}` + "\n",
	)
	manualHostUpgradeLinuxWriteFile(t, fixture.identityPath, identityPayload, 0o600)
	fixture.policyPath = filepath.Join(
		fixture.root,
		"etc",
		"autostream-local-executor",
		"policy.json",
	)
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.SourcePolicyRevision = 3
	policy.ProjectionRevision = 5
	policy.Mutation = &LocalExecutorMutationPolicy{
		PanelURL: "https://panel.example.com",
	}
	policyPayload, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxWriteFile(
		t, fixture.policyPath, append(policyPayload, '\n'), 0o600,
	)

	fixture.publicAgentPath = filepath.Join(
		fixture.root, "usr", "local", "bin", "autostream-host-agent",
	)
	fixture.publicExecutorPath = filepath.Join(
		fixture.root,
		"usr",
		"local",
		"libexec",
		"autostream-local-executor",
	)
	for path, target := range map[string]string{
		fixture.publicAgentPath: filepath.Join(
			currentLink, "bin", "autostream-host-agent",
		),
		fixture.publicExecutorPath: filepath.Join(
			currentLink, "bin", "autostream-local-executor",
		),
	} {
		manualHostUpgradeLinuxMkdir(t, filepath.Dir(path), 0o755)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}

	fixture.runner = &manualHostUpgradeLinuxRunner{
		currentLink:         currentLink,
		slotsRoot:           slotsRoot,
		agentActive:         true,
		executorActive:      true,
		mainPIDReads:        make(map[string]int),
		identityReads:       make(map[string]int),
		inactiveUnits:       make(map[string]bool),
		disabledUnits:       make(map[string]bool),
		recoveryFailedUnits: make(map[string]bool),
		recoveryUnitPath:    unitPaths.installedRecoveryService,
		executorUnitPath:    unitPaths.installedExecutorUnit,
	}
	selfUpdate := hostSelfUpdateExecutorRuntime{
		installRoot:         installRoot,
		currentLink:         currentLink,
		slotsRoot:           slotsRoot,
		stateRoot:           stateRoot,
		statePath:           filepath.Join(stateRoot, "state.json"),
		grantStatePath:      filepath.Join(stateRoot, "grant-state.json"),
		downloadRoot:        filepath.Join(stateRoot, "downloads"),
		arch:                "amd64",
		executorVersion:     manualHostUpgradeTestTargetVersion,
		runner:              fixture.runner,
		identityRunner:      fixture.runner,
		now:                 func() time.Time { return manualHostUpgradeTestActivationNow },
		verificationTimeout: time.Minute,
		allowTestPaths:      true,
	}
	fixture.runtime = manualHostUpgradeRuntime{
		selfUpdate: selfUpdate,
		paths: manualHostUpgradePaths{
			identityPath:              fixture.identityPath,
			legacyIdentityPath:        filepath.Join(fixture.root, "legacy-identity.json"),
			stagedIdentityPath:        filepath.Join(identityRoot, "identity.json.staged"),
			wipingIdentityPath:        filepath.Join(identityRoot, "identity.json.wiping"),
			policyPath:                fixture.policyPath,
			hostStateRoot:             filepath.Join(fixture.root, "var", "lib", "autostream-host-agent"),
			localExecutorStateRoot:    filepath.Join(fixture.root, "var", "lib", "autostream-local-executor"),
			runtimeCredentialPath:     filepath.Join(fixture.root, "var", "lib", "runtime-credential.json"),
			publicAgentPath:           fixture.publicAgentPath,
			publicExecutorPath:        fixture.publicExecutorPath,
			installedAgentUnit:        unitPaths.installedAgentUnit,
			installedExecutorUnit:     unitPaths.installedExecutorUnit,
			installedExecutorSocket:   unitPaths.installedExecutorSocket,
			installedExecutorTmpfiles: unitPaths.installedExecutorTmpfiles,
			installedRecoveryService:  unitPaths.installedRecoveryService,
			installedRecoveryTimer:    unitPaths.installedRecoveryTimer,
		},
		runner:         fixture.runner,
		identityRunner: fixture.runner,
		now:            func() time.Time { return manualHostUpgradeTestActivationNow },
		waitStable: func(context.Context) error {
			fixture.waitStableCalls++
			return nil
		},
		resolveProcessExe: func(pid int) (string, error) {
			fixture.processExeResolves[pid]++
			slot, err := fixture.runner.currentSlot()
			if err != nil {
				return "", err
			}
			var binary string
			switch pid {
			case 3101:
				binary = "autostream-host-agent"
			case 3102:
				binary = "autostream-local-executor"
			default:
				return "", errors.New("unknown test MainPID")
			}
			return filepath.Join(slotsRoot, slot, "bin", binary), nil
		},
		acquireLocks:   func() (func(), error) { return func() {}, nil },
		allowTestPaths: true,
	}
	fixture.runtime.selfUpdate.watchdogStatus = func(
		context.Context,
	) (HostSelfUpdateRuntimeStatus, error) {
		fixture.watchdogCalls++
		state, err := fixture.runtime.selfUpdate.loadPersistedState()
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		current, err := fixture.runtime.selfUpdate.readCurrentSlot()
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		executorVersion := manualHostUpgradeTestOldVersion
		if current == HostSelfUpdateSlotB {
			executorVersion = manualHostUpgradeTestTargetVersion
		}
		return HostSelfUpdateRuntimeStatus{
			State:                   state,
			CurrentSlot:             current,
			ExecutorVersion:         executorVersion,
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
			LastAction:              HostSelfUpdateActionNone,
		}, nil
	}
	fixture.request = ManualHostUpgradeRequest{
		ArtifactRoot:  fixture.artifactRoot,
		ArchiveSHA256: strings.Repeat("c", 64),
		ArchiveSize:   4096,
	}
	artifact, err := inspectManualHostUpgradeArtifact(
		context.Background(), fixture.request, fixture.runtime,
	)
	if err != nil {
		t.Fatalf("inspect fixture artifact: %v", err)
	}
	fixture.targetRequest, err = newManualHostSelfUpdateRequest(
		artifact, fixture.request,
	)
	if err != nil {
		t.Fatalf("bind fixture artifact: %v", err)
	}
	fixture.runner.identityReads = make(map[string]int)
	return fixture
}

func configureManualHostUpgradeLegacyRecoveryUnit(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	artifactPath := filepath.Join(
		fixture.artifactRoot,
		"systemd",
		"autostream-host-self-update-recovery@.service",
	)
	manualHostUpgradeLinuxWriteFile(
		t, artifactPath, correctedManualHostRecoveryUnitBytes(t), 0o644,
	)
	manualHostUpgradeLinuxWriteFile(
		t,
		fixture.runtime.paths.installedRecoveryService,
		legacyManualHostRecoveryUnitBytes(t),
		0o644,
	)
	dropInDirectory := fixture.runtime.paths.installedRecoveryService + ".d"
	manualHostUpgradeLinuxMkdir(t, dropInDirectory, 0o755)
	for name, payload := range map[string]string{
		"10-executable-guard.conf":      "[Unit]\nConditionFileIsExecutable=/opt/autostream/host-agent/slots/%i/bin/autostream-local-executor\n",
		"20-bootstrap-state-guard.conf": "[Unit]\nConditionPathExists=/var/lib/autostream-local-executor/host-self-update/state.json\n",
	} {
		manualHostUpgradeLinuxWriteFile(
			t, filepath.Join(dropInDirectory, name), []byte(payload), 0o644,
		)
	}
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)
}

func configureManualHostUpgradeLegacyExecutorUnit(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	corrected, legacy := manualHostExecutorUnitTemplateBytes(t)
	artifactPath := filepath.Join(
		fixture.artifactRoot,
		"systemd",
		"autostream-local-executor.service",
	)
	manualHostUpgradeLinuxWriteFile(t, artifactPath, corrected, 0o644)
	manualHostUpgradeLinuxWriteFile(
		t, fixture.runtime.paths.installedExecutorUnit, legacy, 0o644,
	)
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)
}

func copyManualHostUpgradeArtifactBinariesToSlot(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
	slot string,
) {
	t.Helper()
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		payload, err := os.ReadFile(filepath.Join(
			fixture.artifactRoot, "bin", binary,
		))
		if err != nil {
			t.Fatal(err)
		}
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(fixture.runtime.selfUpdate.slotsRoot, slot, "bin", binary),
			payload,
			0o755,
		)
	}
}

func configureManualHostUpgradeDowngradeArtifact(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		manualHostUpgradeLinuxWriteFile(
			t,
			filepath.Join(fixture.artifactRoot, "bin", binary),
			[]byte("old:"+binary+"\n"),
			0o755,
		)
	}
	manifestPath := filepath.Join(fixture.artifactRoot, "artifact-manifest.json")
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest manualHostArtifactManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SourceVersion = manualHostUpgradeTestOldVersion
	manifest.Commit = manualHostUpgradeTestOldCommit
	manifest.BuildDate = manualHostUpgradeTestOldBuildDate.Format(
		"2006-01-02T15:04:05Z",
	)
	manifest.Archive.Root = "autostream-host-agent_" +
		manualHostUpgradeTestOldVersion + "_linux_amd64"
	manifest.Archive.Name = manifest.Archive.Root + ".tar.gz"
	manifest.Compatibility.MinimumPanelVersion = manualHostUpgradeTestOldVersion
	payload, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manualHostUpgradeLinuxWriteFile(
		t, manifestPath, append(payload, '\n'), 0o644,
	)
	manualHostUpgradeLinuxWriteChecksums(t, fixture.artifactRoot)
}

func assertManualHostUpgradeRecoveryUnitConverged(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	installed, err := os.ReadFile(fixture.runtime.paths.installedRecoveryService)
	if err != nil || manualHostRecoveryUnitDigest(installed) !=
		manualHostRecoveryUnitCorrectedDigest {
		t.Fatalf("recovery unit did not converge: err=%v", err)
	}
	if _, err := os.Lstat(
		fixture.runtime.paths.installedRecoveryService + ".d",
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery drop-in directory remained: %v", err)
	}
}

func manualHostUpgradeLinuxUnitPaths(root string) manualHostUpgradePaths {
	return manualHostUpgradePaths{
		installedAgentUnit: filepath.Join(
			root, "systemd", "autostream-host-agent.service",
		),
		installedExecutorUnit: filepath.Join(
			root, "systemd", "autostream-local-executor.service",
		),
		installedExecutorSocket: filepath.Join(
			root, "systemd", "autostream-local-executor.socket",
		),
		installedExecutorTmpfiles: filepath.Join(
			root, "tmpfiles.d", "autostream-local-executor.conf",
		),
		installedRecoveryService: filepath.Join(
			root,
			"systemd",
			"autostream-host-self-update-recovery@.service",
		),
		installedRecoveryTimer: filepath.Join(
			root,
			"systemd",
			"autostream-host-self-update-recovery@.timer",
		),
	}
}

func manualHostUpgradeLinuxMkdir(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func manualHostUpgradeLinuxWriteFile(
	t *testing.T,
	path string,
	payload []byte,
	mode fs.FileMode,
) {
	t.Helper()
	directory := filepath.Dir(path)
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		manualHostUpgradeLinuxMkdir(t, directory, 0o755)
	} else if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func manualHostUpgradeLinuxWriteChecksums(t *testing.T, root string) {
	t.Helper()
	entries := make([]string, 0, 16)
	err := filepath.WalkDir(root, func(
		path string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() == "checksums.txt" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		entries = append(
			entries,
			digest+"  ./"+filepath.ToSlash(relative),
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(entries)
	manualHostUpgradeLinuxWriteFile(
		t,
		filepath.Join(root, "checksums.txt"),
		[]byte(strings.Join(entries, "\n")+"\n"),
		0o644,
	)
}

type manualHostUpgradeLinuxProtectedSnapshot struct {
	info    os.FileInfo
	payload []byte
	mode    fs.FileMode
	uid     uint32
	gid     uint32
}

func snapshotManualHostUpgradeLinuxProtectedFile(
	t *testing.T,
	path string,
) manualHostUpgradeLinuxProtectedSnapshot {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("protected file has no Linux stat identity")
	}
	return manualHostUpgradeLinuxProtectedSnapshot{
		info: info, payload: payload, mode: info.Mode(), uid: stat.Uid, gid: stat.Gid,
	}
}

func assertManualHostUpgradeLinuxProtectedFileUnchanged(
	t *testing.T,
	path string,
	before manualHostUpgradeLinuxProtectedSnapshot,
) {
	t.Helper()
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || !os.SameFile(before.info, after) || before.mode != after.Mode() ||
		before.uid != stat.Uid || before.gid != stat.Gid ||
		!bytes.Equal(before.payload, payload) {
		t.Fatalf("protected file changed during upgrade: %s", path)
	}
}

func assertManualHostUpgradeLinuxPublicLinks(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	for path, want := range map[string]string{
		fixture.publicAgentPath: filepath.Join(
			fixture.runtime.selfUpdate.currentLink,
			"bin",
			"autostream-host-agent",
		),
		fixture.publicExecutorPath: filepath.Join(
			fixture.runtime.selfUpdate.currentLink,
			"bin",
			"autostream-local-executor",
		),
	} {
		got, err := os.Readlink(path)
		if err != nil || got != want {
			t.Fatalf("public link %s=%q want=%q err=%v", path, got, want, err)
		}
	}
}

func assertManualHostUpgradeLinuxSlotBinding(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
	slot string,
) {
	t.Helper()
	request, digests, err := readManualHostUpdateSlotBinding(
		slot, fixture.runtime.selfUpdate,
	)
	if err != nil {
		t.Fatalf("read slot %s binding: %v", slot, err)
	}
	if !sameManualHostUpgradeArchiveContent(request, fixture.targetRequest) {
		t.Fatalf("slot %s request=%+v want=%+v", slot, request, fixture.targetRequest)
	}
	wantDigests, err := hostSelfUpdateArtifactBinaryDigests(fixture.artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	if digests != wantDigests {
		t.Fatalf("slot %s digests=%+v want=%+v", slot, digests, wantDigests)
	}
	for name, wantMode := range map[string]fs.FileMode{
		".generation":                   0o444,
		".release-binding.json":         0o444,
		"bin/autostream-host-agent":     0o755,
		"bin/autostream-local-executor": 0o755,
	} {
		info, err := os.Lstat(filepath.Join(
			fixture.runtime.selfUpdate.slotsRoot,
			slot,
			filepath.FromSlash(name),
		))
		if err != nil || info.Mode().Perm() != wantMode {
			t.Fatalf("slot %s path %s mode=%v err=%v", slot, name, infoMode(info), err)
		}
	}
}

func assertManualHostUpgradeLinuxNoTransitionResidue(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	entries, err := os.ReadDir(fixture.runtime.selfUpdate.slotsRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Fatalf("slot transition residue remains: %s", entry.Name())
		}
	}
	entries, err = os.ReadDir(fixture.runtime.selfUpdate.installRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".current-") {
			t.Fatalf("current-link transition residue remains: %s", entry.Name())
		}
	}
}

func infoMode(info os.FileInfo) fs.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}
