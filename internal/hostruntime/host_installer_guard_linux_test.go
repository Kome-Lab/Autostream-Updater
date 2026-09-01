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

type hostInstallerGuardTestRunner struct {
	base       *manualHostUpgradeLinuxRunner
	startCalls int
}

func (r *hostInstallerGuardTestRunner) Run(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (string, error) {
	if name == "/usr/bin/systemctl" && len(args) == 2 &&
		args[0] == "start" && args[1] == hostSelfUpdateServiceUnit {
		r.startCalls++
		if err := ctx.Err(); err != nil {
			return "", err
		}
		r.base.agentActive = true
		return "", nil
	}
	return r.base.Run(ctx, dir, env, name, args...)
}

func TestHostInstallerGuardRestartsOnlyExactStablePair(t *testing.T) {
	t.Run("exact pair with clean journal restarts", func(t *testing.T) {
		fixture, request, runtime, runner := newHostInstallerGuardFixture(t)

		if err := restartHostAgentFromUpgradeGuardWithRuntime(
			context.Background(), request, runtime,
		); err != nil {
			t.Fatalf("restart exact pre-upgrade pair: %v", err)
		}
		if runner.startCalls != 1 || !fixture.runner.agentActive {
			t.Fatalf(
				"guard start calls=%d agent_active=%v",
				runner.startCalls,
				fixture.runner.agentActive,
			)
		}
		if _, err := os.Lstat(runtime.dropInPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("guard drop-in still present: %v", err)
		}
		if fixture.runner.recoveryReloads != 1 {
			t.Fatalf("daemon reload calls=%d", fixture.runner.recoveryReloads)
		}
	})

	t.Run("exact pair with valid active journal restarts", func(t *testing.T) {
		fixture, request, runtime, runner := newHostInstallerGuardFixture(t)
		writeHostInstallerGuardActiveJournal(t, fixture)

		if err := restartHostAgentFromUpgradeGuardWithRuntime(
			context.Background(), request, runtime,
		); err != nil {
			t.Fatalf("restart pair with active recovery: %v", err)
		}
		if runner.startCalls != 1 {
			t.Fatalf("guard start calls=%d", runner.startCalls)
		}
	})
}

func TestHostInstallerGuardRejectsUnsafeStateWithoutStarting(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(
			*testing.T,
			*manualHostUpgradeLinuxFixture,
			*HostAgentUpgradeGuardRequest,
			*hostInstallerGuardRuntime,
		)
	}{
		{
			name: "journal clear marker",
			mutate: func(
				t *testing.T,
				_ *manualHostUpgradeLinuxFixture,
				_ *HostAgentUpgradeGuardRequest,
				runtime *hostInstallerGuardRuntime,
			) {
				manualHostUpgradeLinuxWriteFile(
					t, runtime.markerPath, []byte("uncertain\n"), 0o600,
				)
			},
		},
		{
			name: "current slot flip",
			mutate: func(
				t *testing.T,
				fixture *manualHostUpgradeLinuxFixture,
				_ *HostAgentUpgradeGuardRequest,
				_ *hostInstallerGuardRuntime,
			) {
				if err := os.Remove(fixture.runtime.selfUpdate.currentLink); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(
					filepath.Join("slots", HostSelfUpdateSlotB),
					fixture.runtime.selfUpdate.currentLink,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "agent digest drift",
			mutate: func(
				t *testing.T,
				fixture *manualHostUpgradeLinuxFixture,
				_ *HostAgentUpgradeGuardRequest,
				_ *hostInstallerGuardRuntime,
			) {
				manualHostUpgradeLinuxWriteFile(
					t,
					filepath.Join(
						fixture.runtime.selfUpdate.slotsRoot,
						HostSelfUpdateSlotA,
						"bin",
						"autostream-host-agent",
					),
					[]byte("old:autostream-host-agent\ndrift\n"),
					0o755,
				)
			},
		},
		{
			name: "mixed runtime identity",
			mutate: func(
				t *testing.T,
				fixture *manualHostUpgradeLinuxFixture,
				request *HostAgentUpgradeGuardRequest,
				_ *hostInstallerGuardRuntime,
			) {
				path := filepath.Join(
					fixture.runtime.selfUpdate.slotsRoot,
					HostSelfUpdateSlotA,
					"bin",
					"autostream-local-executor",
				)
				manualHostUpgradeLinuxWriteFile(
					t, path, []byte("target:autostream-local-executor\n"), 0o755,
				)
				digest, err := hashFile(path)
				if err != nil {
					t.Fatal(err)
				}
				request.ExecutorSHA256 = digest
			},
		},
		{
			name: "planless active journal",
			mutate: func(
				t *testing.T,
				fixture *manualHostUpgradeLinuxFixture,
				_ *HostAgentUpgradeGuardRequest,
				_ *hostInstallerGuardRuntime,
			) {
				payload, err := json.Marshal(journalData{
					ActiveJob: &UpdateJob{
						ID:        "job-unsafe",
						Operation: updateJobOperationSoftwareUpdate,
					},
					NextSeq: 1,
				})
				if err != nil {
					t.Fatal(err)
				}
				manualHostUpgradeLinuxWriteFile(
					t,
					filepath.Join(fixture.runtime.paths.hostStateRoot, "journal.json"),
					append(payload, '\n'),
					0o600,
				)
			},
		},
		{
			name: "nonstable self update state",
			mutate: func(
				t *testing.T,
				fixture *manualHostUpgradeLinuxFixture,
				_ *HostAgentUpgradeGuardRequest,
				_ *hostInstallerGuardRuntime,
			) {
				state, err := NewHostSelfUpdateState(
					manualHostUpgradeTestOldVersion,
					manualHostUpgradeTestOldVersion,
				)
				if err != nil {
					t.Fatal(err)
				}
				state, err = StageHostSelfUpdate(
					state,
					validHostSelfUpdateRequest(),
					HostLifecycleBlockers{},
					validHostSelfUpdateSlotDigests(),
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := fixture.runtime.selfUpdate.saveState(state); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, request, runtime, runner := newHostInstallerGuardFixture(t)
			test.mutate(t, fixture, &request, &runtime)

			err := restartHostAgentFromUpgradeGuardWithRuntime(
				context.Background(), request, runtime,
			)
			if err == nil {
				t.Fatal("unsafe guard state unexpectedly restarted the Agent")
			}
			if runner.startCalls != 0 || fixture.runner.agentActive {
				t.Fatalf(
					"unsafe state started Agent: calls=%d active=%v err=%v",
					runner.startCalls,
					fixture.runner.agentActive,
					err,
				)
			}
			if _, statErr := os.Lstat(runtime.dropInPath); statErr != nil {
				t.Fatalf("unsafe state removed guard drop-in: %v", statErr)
			}
		})
	}
}

func newHostInstallerGuardFixture(
	t *testing.T,
) (
	*manualHostUpgradeLinuxFixture,
	HostAgentUpgradeGuardRequest,
	hostInstallerGuardRuntime,
	*hostInstallerGuardTestRunner,
) {
	t.Helper()
	fixture := newManualHostUpgradeLinuxFixture(t)
	fixture.runner.agentActive = false
	manualHostUpgradeLinuxMkdir(t, fixture.runtime.paths.hostStateRoot, 0o700)

	guardDirectory := filepath.Join(fixture.root, "run", "autostream-host-agent-upgrade-guard.test")
	guardPath := filepath.Join(guardDirectory, "autostream-local-executor")
	manualHostUpgradeLinuxWriteFile(t, guardPath, []byte("guard\n"), 0o700)
	dropInPath := filepath.Join(
		fixture.root,
		"etc",
		"systemd",
		"system",
		"autostream-host-agent.service.d",
		"90-autostream-upgrade-recovery-guard.conf",
	)
	markerPath := filepath.Join(
		fixture.runtime.paths.hostStateRoot,
		journalActiveClearMarkerName,
	)
	manualHostUpgradeLinuxWriteFile(
		t,
		dropInPath,
		[]byte(hostInstallerGuardDropInContent(guardPath, markerPath)),
		0o644,
	)

	runner := &hostInstallerGuardTestRunner{base: fixture.runner}
	fixture.runtime.runner = runner
	fixture.runtime.selfUpdate.runner = runner
	runtime := hostInstallerGuardRuntime{
		manual:         fixture.runtime,
		markerPath:     markerPath,
		dropInPath:     dropInPath,
		executablePath: func() (string, error) { return guardPath, nil },
	}
	agentPath := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-host-agent",
	)
	executorPath := filepath.Join(
		fixture.runtime.selfUpdate.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	agentDigest, err := hashFile(agentPath)
	if err != nil {
		t.Fatal(err)
	}
	executorDigest, err := hashFile(executorPath)
	if err != nil {
		t.Fatal(err)
	}
	request := HostAgentUpgradeGuardRequest{
		ExpectedSlot:   HostSelfUpdateSlotA,
		AgentSHA256:    agentDigest,
		ExecutorSHA256: executorDigest,
	}
	return fixture, request, runtime, runner
}

func writeHostInstallerGuardActiveJournal(
	t *testing.T,
	fixture *manualHostUpgradeLinuxFixture,
) {
	t.Helper()
	plan := validMutationPlan()
	plan.JobID = "job-active"
	var err error
	plan.PlanSHA256, err = plan.ComputePlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
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
		filepath.Join(fixture.runtime.paths.hostStateRoot, "journal.json"),
		append(payload, '\n'),
		0o600,
	)
}

func TestHostInstallerGuardRequestRejectsNonCanonicalDigests(t *testing.T) {
	fixture, request, runtime, runner := newHostInstallerGuardFixture(t)
	request.AgentSHA256 = strings.ToUpper(request.AgentSHA256)

	err := restartHostAgentFromUpgradeGuardWithRuntime(
		context.Background(), request, runtime,
	)
	if err == nil || runner.startCalls != 0 || fixture.runner.agentActive {
		t.Fatalf("noncanonical request err=%v starts=%d", err, runner.startCalls)
	}
}
