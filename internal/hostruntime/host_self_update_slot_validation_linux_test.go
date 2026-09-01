//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type hostSelfUpdateValidationRunner struct {
	request       HostSelfUpdateRequest
	agentRestarts int
}

func (r *hostSelfUpdateValidationRunner) Run(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (string, error) {
	if name == "/usr/bin/systemctl" {
		if len(args) == 2 &&
			args[0] == "restart" &&
			args[1] == hostSelfUpdateServiceUnit {
			r.agentRestarts++
			return "", nil
		}
		return "", errors.New("unexpected systemctl operation")
	}
	return (hostSelfUpdateSlotIdentityRunner{request: r.request}).Run(
		ctx,
		dir,
		env,
		name,
		args...,
	)
}

type hostSelfUpdateCountingDownloader struct {
	release HostAgentRelease
	calls   int
}

func (d *hostSelfUpdateCountingDownloader) DownloadHostAgentRelease(
	context.Context,
	string,
	string,
	string,
) (HostAgentRelease, error) {
	d.calls++
	return d.release, nil
}

type hostSelfUpdateSlotValidationFixture struct {
	rt           hostSelfUpdateExecutorRuntime
	request      HostSelfUpdateRequest
	artifactRoot string
	runner       *hostSelfUpdateValidationRunner
	downloader   *hostSelfUpdateCountingDownloader
}

func TestHostSelfUpdatePrepareRequiresDurableNewStateRoot(t *testing.T) {
	root := t.TempDir()
	installRoot := filepath.Join(root, "install", "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	stateParent := filepath.Join(root, "state")
	stateRoot := filepath.Join(stateParent, "host-self-update")
	if err := os.MkdirAll(slotsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	rt := hostSelfUpdateExecutorRuntime{
		installRoot:     installRoot,
		currentLink:     filepath.Join(installRoot, "current"),
		slotsRoot:       slotsRoot,
		stateRoot:       stateRoot,
		statePath:       filepath.Join(stateRoot, "state.json"),
		grantStatePath:  filepath.Join(stateRoot, "grant.json"),
		downloadRoot:    filepath.Join(stateRoot, "downloads"),
		arch:            "amd64",
		executorVersion: "v1.7.8",
		allowTestPaths:  true,
	}
	parentSyncAttempts := 0
	failParentSync := true
	rt.syncDir = func(path string) error {
		if filepath.Clean(path) == filepath.Clean(stateParent) &&
			hostSelfUpdatePathExists(stateRoot) {
			parentSyncAttempts++
			if failParentSync {
				return errors.New("injected state-root parent sync failure")
			}
		}
		return nil
	}

	prepareErr := rt.prepare()
	if prepareErr == nil {
		t.Fatal("prepare succeeded without durably publishing stateRoot")
	}
	if parentSyncAttempts != 1 {
		t.Fatalf(
			"stateRoot parent directory sync boundary was not reached: %v",
			prepareErr,
		)
	}
	if _, err := os.Lstat(rt.statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state was persisted after root durability failure: %v", err)
	}
	if retryErr := rt.prepare(); retryErr == nil {
		t.Fatal("prepare retry skipped the failed stateRoot parent sync")
	}
	if parentSyncAttempts != 2 {
		t.Fatalf(
			"stateRoot parent sync attempts = %d, want 2",
			parentSyncAttempts,
		)
	}
	failParentSync = false
	if err := rt.prepare(); err != nil {
		t.Fatalf("prepare did not converge after parent sync recovered: %v", err)
	}
	if parentSyncAttempts < 3 {
		t.Fatalf(
			"successful prepare parent sync attempts = %d, want at least 3",
			parentSyncAttempts,
		)
	}
}

func TestHostSelfUpdateFreshProcessRejectsCoherentBinaryDigestTamper(
	t *testing.T,
) {
	fixture := newHostSelfUpdateSlotValidationFixture(t)
	state := fixture.stagePending(t)
	slotRoot := filepath.Join(fixture.rt.slotsRoot, state.PendingSlot)
	binaryPath := filepath.Join(slotRoot, "bin", "autostream-host-agent")
	if err := os.WriteFile(binaryPath, []byte("coherently tampered\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := hashFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(slotRoot, ".agent-sha256")
	if err := os.Chmod(markerPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, []byte(digest+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(markerPath, 0o444); err != nil {
		t.Fatal(err)
	}
	switchCalls := 0
	fixture.rt.switchCurrentHook = func(string) error {
		switchCalls++
		return nil
	}

	if _, err := fixture.rt.activate(
		context.Background(),
		fixture.request.Generation,
	); err == nil {
		t.Fatal("coherent binary and digest-marker tamper was accepted")
	}
	if switchCalls != 0 || fixture.runner.agentRestarts != 0 {
		t.Fatalf(
			"tampered slot crossed activation boundary: switches=%d restarts=%d",
			switchCalls,
			fixture.runner.agentRestarts,
		)
	}
}

func TestHostSelfUpdateRecoveryPreservesBackupOnPendingCandidateTamper(
	t *testing.T,
) {
	fixture := newHostSelfUpdateSlotValidationFixture(t)
	previousSlot := filepath.Join(
		fixture.rt.slotsRoot,
		HostSelfUpdateSlotB,
	)
	if err := os.MkdirAll(previousSlot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(previousSlot, "previous-slot"),
		[]byte("previous inactive slot\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	state := fixture.stagePendingBeforeRecovery(t)
	slotRoot := filepath.Join(fixture.rt.slotsRoot, state.PendingSlot)
	backup := filepath.Join(
		fixture.rt.slotsRoot,
		"."+state.PendingSlot+"-"+shortID(state.PendingGeneration)+".old",
	)
	if _, err := os.Lstat(backup); err != nil {
		t.Fatalf("staged backup is unavailable before recovery: %v", err)
	}
	binaryPath := filepath.Join(slotRoot, "bin", "autostream-host-agent")
	if err := os.WriteFile(
		binaryPath,
		[]byte("tampered after durable staged state\n"),
		0o755,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := fixture.rt.recoverHostSelfUpdateSlotArtifacts(); err == nil {
		t.Fatal("tampered pending candidate released its rollback backup")
	}
	for _, path := range []string{slotRoot, backup} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("failed recovery removed %q: %v", path, err)
		}
	}
}

func TestHostSelfUpdateFreshProcessRevalidatesPendingSlotBeforeMutation(
	t *testing.T,
) {
	for _, transition := range []string{
		"activate",
		"resumed_switch",
		"resumed_restart",
	} {
		transition := transition
		t.Run(transition, func(t *testing.T) {
			fixture := newHostSelfUpdateSlotValidationFixture(t)
			state := fixture.stagePending(t)
			if transition != "activate" {
				var err error
				state, err = BeginHostSelfUpdateActivation(
					state,
					fixture.rt.now().UTC(),
					fixture.rt.verificationTimeout,
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := fixture.rt.saveState(state); err != nil {
					t.Fatal(err)
				}
			}
			if transition == "resumed_restart" {
				if err := fixture.rt.switchCurrent(state.PendingSlot); err != nil {
					t.Fatal(err)
				}
				fixture.rt.executorVersion = state.PendingExecutorVersion
			}
			commitPath := filepath.Join(
				fixture.rt.slotsRoot,
				state.PendingSlot,
				".commit",
			)
			if err := os.Chmod(commitPath, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				commitPath,
				[]byte(strings.Repeat("f", 40)+"\n"),
				0o644,
			); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(commitPath, 0o444); err != nil {
				t.Fatal(err)
			}
			switchCalls := 0
			fixture.rt.switchCurrentHook = func(string) error {
				switchCalls++
				return nil
			}

			var err error
			switch transition {
			case "activate":
				_, err = fixture.rt.activate(
					context.Background(),
					fixture.request.Generation,
				)
			case "resumed_switch", "resumed_restart":
				_, err = fixture.rt.reconcile(
					context.Background(),
					HostSelfUpdateAgentProof{},
				)
			default:
				t.Fatalf("unknown transition %q", transition)
			}
			if err == nil {
				t.Fatal("tampered pending slot crossed a fresh-process boundary")
			}
			if switchCalls != 0 || fixture.runner.agentRestarts != 0 {
				t.Fatalf(
					"tampered pending slot mutated runtime: switches=%d restarts=%d",
					switchCalls,
					fixture.runner.agentRestarts,
				)
			}
			persisted, loadErr := fixture.rt.loadPersistedState()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			wantPhase := HostSelfUpdatePhaseRollingBack
			if transition == "activate" {
				wantPhase = HostSelfUpdatePhaseStable
			}
			if persisted.Phase != wantPhase ||
				persisted.FailedGeneration != fixture.request.Generation {
				t.Fatalf("tamper fence was not persisted: %#v", persisted)
			}
		})
	}
}

func TestHostSelfUpdateStageRejectsStableCurrentSlotDriftBeforeDownload(
	t *testing.T,
) {
	fixture := newHostSelfUpdateSlotValidationFixture(t)
	slotB := filepath.Join(fixture.rt.slotsRoot, HostSelfUpdateSlotB)
	if err := os.MkdirAll(filepath.Join(slotB, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		if err := os.WriteFile(
			filepath.Join(slotB, "bin", binary),
			[]byte(binary+"\n"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(slotB, "current-slot-sentinel"),
		[]byte("do not replace\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.rt.stage(
		context.Background(),
		fixture.request,
	); err == nil {
		t.Fatal("stable current-slot drift was allowed to stage")
	}
	if fixture.downloader.calls != 0 {
		t.Fatalf(
			"stable drift reached release download %d times",
			fixture.downloader.calls,
		)
	}
	body, err := os.ReadFile(filepath.Join(slotB, "current-slot-sentinel"))
	if err != nil || string(body) != "do not replace\n" {
		t.Fatalf("current drift slot was replaced: body=%q err=%v", body, err)
	}
}

func TestHostSelfUpdateActivationRequiresAvailableHealthySlot(t *testing.T) {
	fixture := newHostSelfUpdateSlotValidationFixture(t)
	state := fixture.stagePending(t)
	healthyRoot := filepath.Join(fixture.rt.slotsRoot, state.HealthySlot)
	if err := os.RemoveAll(healthyRoot); err != nil {
		t.Fatal(err)
	}
	switchCalls := 0
	fixture.rt.switchCurrentHook = func(string) error {
		switchCalls++
		return nil
	}

	if _, err := fixture.rt.activate(
		context.Background(),
		fixture.request.Generation,
	); err == nil {
		t.Fatal("activation proceeded without the healthy rollback slot")
	}
	if switchCalls != 0 || fixture.runner.agentRestarts != 0 {
		t.Fatalf(
			"missing healthy slot crossed activation: switches=%d restarts=%d",
			switchCalls,
			fixture.runner.agentRestarts,
		)
	}
}

func TestHostSelfUpdateActivationRejectsUnsafeSlotDescendants(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*testing.T, hostSelfUpdateSlotValidationFixture, HostSelfUpdateState)
	}{
		{
			name: "missing_healthy_agent",
			mutate: func(
				t *testing.T,
				fixture hostSelfUpdateSlotValidationFixture,
				state HostSelfUpdateState,
			) {
				t.Helper()
				if err := os.Remove(filepath.Join(
					fixture.rt.slotsRoot,
					state.HealthySlot,
					"bin",
					"autostream-host-agent",
				)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "world_writable_healthy_bin",
			mutate: func(
				t *testing.T,
				fixture hostSelfUpdateSlotValidationFixture,
				state HostSelfUpdateState,
			) {
				t.Helper()
				if err := os.Chmod(filepath.Join(
					fixture.rt.slotsRoot,
					state.HealthySlot,
					"bin",
				), 0o777); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "world_writable_pending_executor",
			mutate: func(
				t *testing.T,
				fixture hostSelfUpdateSlotValidationFixture,
				state HostSelfUpdateState,
			) {
				t.Helper()
				if err := os.Chmod(filepath.Join(
					fixture.rt.slotsRoot,
					state.PendingSlot,
					"bin",
					"autostream-local-executor",
				), 0o777); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newHostSelfUpdateSlotValidationFixture(t)
			state := fixture.stagePending(t)
			testCase.mutate(t, fixture, state)
			switchCalls := 0
			fixture.rt.switchCurrentHook = func(string) error {
				switchCalls++
				return nil
			}

			if _, err := fixture.rt.activate(
				context.Background(),
				fixture.request.Generation,
			); err == nil {
				t.Fatal("unsafe slot descendant crossed activation")
			}
			if switchCalls != 0 || fixture.runner.agentRestarts != 0 {
				t.Fatalf(
					"unsafe slot crossed activation: switches=%d restarts=%d",
					switchCalls,
					fixture.runner.agentRestarts,
				)
			}
		})
	}
}

func TestHostSelfUpdateMissingStateRejectsNonBootstrapCurrentSlot(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(*testing.T, hostSelfUpdateSlotValidationFixture)
	}{
		{
			name: "slot_b",
			setup: func(
				t *testing.T,
				fixture hostSelfUpdateSlotValidationFixture,
			) {
				t.Helper()
				slotB := filepath.Join(
					fixture.rt.slotsRoot,
					HostSelfUpdateSlotB,
				)
				if err := os.MkdirAll(
					filepath.Join(slotB, "bin"),
					0o755,
				); err != nil {
					t.Fatal(err)
				}
				for _, binary := range []string{
					"autostream-host-agent",
					"autostream-local-executor",
				} {
					if err := os.WriteFile(
						filepath.Join(slotB, "bin", binary),
						[]byte(binary+"\n"),
						0o755,
					); err != nil {
						t.Fatal(err)
					}
				}
				if err := fixture.rt.switchCurrent(
					HostSelfUpdateSlotB,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "bound_slot_a",
			setup: func(
				t *testing.T,
				fixture hostSelfUpdateSlotValidationFixture,
			) {
				t.Helper()
				if err := os.WriteFile(
					filepath.Join(
						fixture.rt.slotsRoot,
						HostSelfUpdateSlotA,
						".generation",
					),
					[]byte("crash-durable-candidate\n"),
					0o444,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newHostSelfUpdateSlotValidationFixture(t)
			if err := os.Remove(fixture.rt.statePath); err != nil {
				t.Fatal(err)
			}
			testCase.setup(t, fixture)

			if _, err := fixture.rt.status(); err == nil {
				t.Fatal("missing state self-certified a candidate current slot")
			}
			if _, err := os.Lstat(
				fixture.rt.statePath,
			); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf(
					"missing state was recreated from candidate current: %v",
					err,
				)
			}
		})
	}
}

func TestHostSelfUpdateRecoveryRejectsWorldWritableReservedArtifact(
	t *testing.T,
) {
	slotsRoot := t.TempDir()
	artifact := filepath.Join(
		slotsRoot,
		"."+HostSelfUpdateSlotB+"-111111111111.old",
	)
	if err := os.MkdirAll(artifact, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(artifact, 0o777); err != nil {
		t.Fatal(err)
	}
	rt := hostSelfUpdateExecutorRuntime{
		slotsRoot:      slotsRoot,
		allowTestPaths: true,
	}
	if err := rt.recoverHostSelfUpdateSlotArtifacts(); err == nil {
		t.Fatal("world-writable reserved artifact was accepted")
	}
}

func newHostSelfUpdateSlotValidationFixture(
	t *testing.T,
) hostSelfUpdateSlotValidationFixture {
	t.Helper()
	root := t.TempDir()
	installRoot := filepath.Join(root, "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	healthyRoot := filepath.Join(slotsRoot, HostSelfUpdateSlotA)
	if err := os.MkdirAll(filepath.Join(healthyRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(healthyRoot, "healthy-slot-sentinel"),
		[]byte("healthy\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		if err := os.WriteFile(
			filepath.Join(healthyRoot, "bin", name),
			[]byte(name+" v1.7.8\n"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(
		filepath.Join("slots", HostSelfUpdateSlotA),
		currentLink,
	); err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(root, "artifact")
	if err := os.MkdirAll(filepath.Join(artifactRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		if err := os.WriteFile(
			filepath.Join(artifactRoot, "bin", name),
			[]byte(name+"\n"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	request := validHostSelfUpdateRequest()
	runner := &hostSelfUpdateValidationRunner{request: request}
	downloader := &hostSelfUpdateCountingDownloader{
		release: HostAgentRelease{
			Artifact: DownloadedArtifact{
				RootDir: artifactRoot,
				SHA256:  strings.TrimPrefix(request.ArtifactSHA256, "sha256:"),
			},
			Request:             request,
			PublishedAt:         request.Release.PublishedAt,
			MinimumPanelVersion: request.Release.MinimumPanelVersion,
		},
	}
	stateRoot := filepath.Join(root, "state")
	rt := hostSelfUpdateExecutorRuntime{
		installRoot:         installRoot,
		currentLink:         currentLink,
		slotsRoot:           slotsRoot,
		stateRoot:           stateRoot,
		statePath:           filepath.Join(stateRoot, "state.json"),
		grantStatePath:      filepath.Join(stateRoot, "grant.json"),
		downloadRoot:        filepath.Join(stateRoot, "downloads"),
		arch:                "amd64",
		executorVersion:     "v1.7.8",
		downloader:          downloader,
		runner:              runner,
		now:                 testHostSelfUpdateNow,
		verificationTimeout: defaultHostSelfUpdateVerificationTimeout,
		allowTestPaths:      true,
	}
	if err := rt.prepare(); err != nil {
		t.Fatal(err)
	}
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	return hostSelfUpdateSlotValidationFixture{
		rt:           rt,
		request:      request,
		artifactRoot: artifactRoot,
		runner:       runner,
		downloader:   downloader,
	}
}

func (f hostSelfUpdateSlotValidationFixture) stagePending(
	t *testing.T,
) HostSelfUpdateState {
	t.Helper()
	state := f.stagePendingBeforeRecovery(t)
	if err := f.rt.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		t.Fatalf("promote durable pending slot: %v", err)
	}
	return state
}

func (f hostSelfUpdateSlotValidationFixture) stagePendingBeforeRecovery(
	t *testing.T,
) HostSelfUpdateState {
	t.Helper()
	slotDigests, err := hostSelfUpdateArtifactBinaryDigests(f.artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.rt.stageSlot(
		context.Background(),
		HostSelfUpdateSlotB,
		f.artifactRoot,
		f.request,
		slotDigests,
	); err != nil {
		t.Fatal(err)
	}
	state, err := f.rt.loadPersistedState()
	if err != nil {
		t.Fatal(err)
	}
	state, err = StageHostSelfUpdate(
		state,
		f.request,
		HostLifecycleBlockers{},
		slotDigests,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	return state
}

func testHostSelfUpdateNow() time.Time {
	return time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
}
