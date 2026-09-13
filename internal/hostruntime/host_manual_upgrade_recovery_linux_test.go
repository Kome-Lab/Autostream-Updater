//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
