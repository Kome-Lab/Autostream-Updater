package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type hostSelfUpdateSlotIdentityRunner struct {
	request HostSelfUpdateRequest
}

func (r hostSelfUpdateSlotIdentityRunner) Run(
	_ context.Context,
	_ string,
	_ []string,
	name string,
	_ ...string,
) (string, error) {
	binary := filepath.Base(name)
	version := r.request.AgentVersion
	if binary == "autostream-local-executor" {
		version = r.request.ExecutorVersion
	}
	lines := []string{
		binary + " " + version,
		"commit: " + r.request.Commit,
	}
	if binary == "autostream-local-executor" {
		lines = append(
			lines,
			"mutation_protocol: "+
				strconv.Itoa(r.request.MutationProtocolVersion),
			"recovery_protocol: "+
				strconv.Itoa(r.request.RecoveryProtocolVersion),
		)
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func TestHostSelfUpdateStageSlotSyncFaultsRestorePreviousSlot(
	t *testing.T,
) {
	for _, testCase := range []struct {
		name       string
		shouldFail func(
			path, slotsRoot, slotRoot, temporary, backup string,
		) bool
	}{
		{
			name: "bin",
			shouldFail: func(path, _, _, temporary, _ string) bool {
				return filepath.Clean(path) ==
					filepath.Join(temporary, "bin")
			},
		},
		{
			name: "temporary_slot",
			shouldFail: func(path, _, _, temporary, _ string) bool {
				return filepath.Clean(path) == filepath.Clean(temporary)
			},
		},
		{
			name: "backup_rename",
			shouldFail: func(
				path, slotsRoot, slotRoot, temporary, backup string,
			) bool {
				return filepath.Clean(path) == filepath.Clean(slotsRoot) &&
					!hostSelfUpdatePathExists(slotRoot) &&
					hostSelfUpdatePathExists(temporary) &&
					hostSelfUpdatePathExists(backup)
			},
		},
		{
			name: "candidate_rename",
			shouldFail: func(
				path, slotsRoot, slotRoot, temporary, backup string,
			) bool {
				return filepath.Clean(path) == filepath.Clean(slotsRoot) &&
					hostSelfUpdatePathExists(slotRoot) &&
					!hostSelfUpdatePathExists(temporary) &&
					hostSelfUpdatePathExists(backup)
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			rt, request, artifactRoot, slotRoot, slotDigests :=
				newHostSelfUpdateSlotFixture(t)
			temporary := filepath.Join(
				rt.slotsRoot,
				"."+HostSelfUpdateSlotB+"-"+
					shortID(request.Generation)+".new",
			)
			backup := filepath.Join(
				rt.slotsRoot,
				"."+HostSelfUpdateSlotB+"-"+
					shortID(request.Generation)+".old",
			)
			injected := false
			rt.syncDir = func(path string) error {
				if !injected && testCase.shouldFail(
					path,
					rt.slotsRoot,
					slotRoot,
					temporary,
					backup,
				) {
					injected = true
					return errors.New("injected directory sync failure")
				}
				return nil
			}

			if err := rt.stageSlot(
				context.Background(),
				HostSelfUpdateSlotB,
				artifactRoot,
				request,
				slotDigests,
			); err == nil {
				t.Fatal("directory sync fault did not fail staging")
			}
			if !injected {
				t.Fatal("expected directory sync boundary was not reached")
			}
			assertPreviousHostSelfUpdateSlot(t, rt.slotsRoot, slotRoot)
		})
	}
}

func TestHostSelfUpdateStageSlotDurablyQuarantinesCandidateBeforeRestore(
	t *testing.T,
) {
	rt, request, artifactRoot, slotRoot, slotDigests :=
		newHostSelfUpdateSlotFixture(t)
	backup := filepath.Join(
		rt.slotsRoot,
		"."+HostSelfUpdateSlotB+"-"+shortID(request.Generation)+".old",
	)
	temporary := filepath.Join(
		rt.slotsRoot,
		"."+HostSelfUpdateSlotB+"-"+shortID(request.Generation)+".new",
	)
	candidateSyncFailed := false
	sawDurableQuarantine := false
	rt.syncDir = func(path string) error {
		if filepath.Clean(path) != filepath.Clean(rt.slotsRoot) {
			return nil
		}
		slotExists := hostSelfUpdatePathExists(slotRoot)
		temporaryExists := hostSelfUpdatePathExists(temporary)
		backupExists := hostSelfUpdatePathExists(backup)
		if !candidateSyncFailed &&
			slotExists &&
			!temporaryExists &&
			backupExists {
			candidateSyncFailed = true
			return errors.New("injected candidate directory sync failure")
		}
		if candidateSyncFailed &&
			!slotExists &&
			temporaryExists &&
			backupExists {
			sawDurableQuarantine = true
		}
		return nil
	}

	if err := rt.stageSlot(
		context.Background(),
		HostSelfUpdateSlotB,
		artifactRoot,
		request,
		slotDigests,
	); err == nil {
		t.Fatal("candidate directory sync fault did not fail staging")
	}
	if !sawDurableQuarantine {
		t.Fatal(
			"candidate was not directory-synced out of the final slot " +
				"before the backup was restored",
		)
	}
	assertPreviousHostSelfUpdateSlot(t, rt.slotsRoot, slotRoot)
}

func TestHostSelfUpdateSlotArtifactRecovery(t *testing.T) {
	const (
		firstID  = "111111111111"
		secondID = "222222222222"
	)
	t.Run("sole_backup_is_restored_and_new_is_reaped", func(t *testing.T) {
		slotsRoot := t.TempDir()
		rt := hostSelfUpdateExecutorRuntime{
			slotsRoot:      slotsRoot,
			allowTestPaths: true,
		}
		backup := filepath.Join(
			slotsRoot,
			"."+HostSelfUpdateSlotB+"-"+firstID+".old",
		)
		temporary := filepath.Join(
			slotsRoot,
			"."+HostSelfUpdateSlotB+"-"+firstID+".new",
		)
		if err := os.MkdirAll(backup, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(backup, "previous-slot"),
			[]byte("previous\n"),
			0o644,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(temporary, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := rt.recoverHostSelfUpdateSlotArtifacts(); err != nil {
			t.Fatalf("recover sole backup: %v", err)
		}
		slotRoot := filepath.Join(slotsRoot, HostSelfUpdateSlotB)
		if body, err := os.ReadFile(
			filepath.Join(slotRoot, "previous-slot"),
		); err != nil || string(body) != "previous\n" {
			t.Fatalf("sole backup was not restored: body=%q err=%v", body, err)
		}
		if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restored backup artifact survived: %v", err)
		}
		if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary artifact survived recovery: %v", err)
		}
	})

	t.Run("multiple_backups_fail_closed", func(t *testing.T) {
		slotsRoot := t.TempDir()
		rt := hostSelfUpdateExecutorRuntime{
			slotsRoot:      slotsRoot,
			allowTestPaths: true,
		}
		for _, id := range []string{firstID, secondID} {
			if err := os.MkdirAll(
				filepath.Join(
					slotsRoot,
					"."+HostSelfUpdateSlotB+"-"+id+".old",
				),
				0o755,
			); err != nil {
				t.Fatal(err)
			}
		}
		if err := rt.recoverHostSelfUpdateSlotArtifacts(); err == nil ||
			!strings.Contains(err.Error(), "multiple") {
			t.Fatalf("multiple backups were not rejected: %v", err)
		}
	})

	t.Run("live_slot_with_multiple_backups_fails_without_mutation", func(t *testing.T) {
		slotsRoot := t.TempDir()
		rt := hostSelfUpdateExecutorRuntime{
			slotsRoot:      slotsRoot,
			allowTestPaths: true,
		}
		slotRoot := filepath.Join(slotsRoot, HostSelfUpdateSlotB)
		if err := os.MkdirAll(slotRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(slotRoot, "live-slot"),
			[]byte("live\n"),
			0o644,
		); err != nil {
			t.Fatal(err)
		}
		paths := []string{slotRoot}
		for _, id := range []string{firstID, secondID} {
			backup := filepath.Join(
				slotsRoot,
				"."+HostSelfUpdateSlotB+"-"+id+".old",
			)
			if err := os.MkdirAll(backup, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(backup, "backup-slot"),
				[]byte(id+"\n"),
				0o644,
			); err != nil {
				t.Fatal(err)
			}
			paths = append(paths, backup)
		}

		if err := rt.recoverHostSelfUpdateSlotArtifacts(); err == nil ||
			!strings.Contains(err.Error(), "multiple") {
			t.Fatalf("live slot with multiple backups was not rejected: %v", err)
		}
		for _, path := range paths {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("recovery mutated %q after ambiguity: %v", path, err)
			}
		}
	})

	t.Run("backup_ambiguity_in_later_slot_fails_before_any_slot_mutation", func(t *testing.T) {
		slotsRoot := t.TempDir()
		rt := hostSelfUpdateExecutorRuntime{
			slotsRoot:      slotsRoot,
			allowTestPaths: true,
		}
		firstBackup := filepath.Join(
			slotsRoot,
			"."+HostSelfUpdateSlotA+"-"+firstID+".old",
		)
		if err := os.MkdirAll(firstBackup, 0o755); err != nil {
			t.Fatal(err)
		}
		paths := []string{firstBackup}
		for _, id := range []string{firstID, secondID} {
			backup := filepath.Join(
				slotsRoot,
				"."+HostSelfUpdateSlotB+"-"+id+".old",
			)
			if err := os.MkdirAll(backup, 0o755); err != nil {
				t.Fatal(err)
			}
			paths = append(paths, backup)
		}

		if err := rt.recoverHostSelfUpdateSlotArtifacts(); err == nil ||
			!strings.Contains(err.Error(), "multiple") {
			t.Fatalf("later-slot backup ambiguity was not rejected: %v", err)
		}
		if _, err := os.Lstat(
			filepath.Join(slotsRoot, HostSelfUpdateSlotA),
		); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("slot A was mutated before global ambiguity rejection: %v", err)
		}
		for _, path := range paths {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("backup %q was mutated before ambiguity rejection: %v", path, err)
			}
		}
	})

	t.Run("stable_state_reaps_first_inactive_candidate_without_backup", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory durability recovery is Linux-only")
		}
		fixture := newFirstHostSelfUpdateStageFixture(t)
		if err := fixture.rt.stageSlot(
			context.Background(),
			HostSelfUpdateSlotB,
			fixture.artifactRoot,
			fixture.request,
			fixture.slotDigests,
		); err != nil {
			t.Fatalf("reserve first inactive candidate: %v", err)
		}
		if _, err := os.Lstat(fixture.slotRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("candidate became canonical before state save: %v", err)
		}
		if _, err := os.Lstat(fixture.temporary); err != nil {
			t.Fatalf("reserved candidate was not durable: %v", err)
		}

		fresh := fixture.rt
		if err := fresh.prepare(); err != nil {
			t.Fatalf("fresh prepare did not reap first inactive candidate: %v", err)
		}
		if _, err := os.Lstat(fixture.slotRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("uncommitted canonical candidate survived recovery: %v", err)
		}
		if _, err := os.Lstat(fixture.temporary); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("uncommitted reserved candidate survived recovery: %v", err)
		}
	})

	t.Run("pending_state_promotes_first_reserved_candidate", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory durability recovery is Linux-only")
		}
		fixture := newFirstHostSelfUpdateStageFixture(t)
		if err := fixture.rt.stageSlot(
			context.Background(),
			HostSelfUpdateSlotB,
			fixture.artifactRoot,
			fixture.request,
			fixture.slotDigests,
		); err != nil {
			t.Fatalf("reserve first inactive candidate: %v", err)
		}
		next, err := StageHostSelfUpdate(
			fixture.state,
			fixture.request,
			HostLifecycleBlockers{},
			fixture.slotDigests,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.rt.saveState(next); err != nil {
			t.Fatal(err)
		}

		fresh := fixture.rt
		if err := fresh.prepare(); err != nil {
			t.Fatalf("fresh prepare did not promote pending candidate: %v", err)
		}
		if _, err := os.Lstat(fixture.slotRoot); err != nil {
			t.Fatalf("pending candidate was not promoted: %v", err)
		}
		if _, err := os.Lstat(fixture.temporary); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("promoted reserved candidate survived: %v", err)
		}
	})

	t.Run("pending_candidate_promotion_sync_failure_is_retryable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory durability recovery is Linux-only")
		}
		fixture := newFirstHostSelfUpdateStageFixture(t)
		if err := fixture.rt.stageSlot(
			context.Background(),
			HostSelfUpdateSlotB,
			fixture.artifactRoot,
			fixture.request,
			fixture.slotDigests,
		); err != nil {
			t.Fatalf("reserve first inactive candidate: %v", err)
		}
		next, err := StageHostSelfUpdate(
			fixture.state,
			fixture.request,
			HostLifecycleBlockers{},
			fixture.slotDigests,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.rt.saveState(next); err != nil {
			t.Fatal(err)
		}
		first := fixture.rt
		first.syncDir = func(path string) error {
			if filepath.Clean(path) == filepath.Clean(first.slotsRoot) {
				return errors.New("injected promoted slot sync failure")
			}
			return nil
		}
		if err := first.recoverHostSelfUpdateSlotArtifacts(); err == nil ||
			!strings.Contains(err.Error(), "injected promoted slot sync failure") {
			t.Fatalf("promoted slot sync fault was not surfaced: %v", err)
		}
		if _, err := os.Lstat(fixture.slotRoot); err != nil {
			t.Fatalf("candidate was not atomically promoted before sync fault: %v", err)
		}
		if _, err := os.Lstat(fixture.temporary); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("reserved candidate survived atomic promotion: %v", err)
		}

		successfulRootSyncs := 0
		retry := fixture.rt
		retry.syncDir = func(path string) error {
			if filepath.Clean(path) == filepath.Clean(retry.slotsRoot) {
				successfulRootSyncs++
			}
			return nil
		}
		if err := retry.recoverHostSelfUpdateSlotArtifacts(); err != nil {
			t.Fatalf("retry promoted candidate recovery: %v", err)
		}
		if successfulRootSyncs == 0 {
			t.Fatal("promotion retry succeeded without a slots root directory sync")
		}
		if _, err := os.Lstat(fixture.slotRoot); err != nil {
			t.Fatalf("promoted candidate unavailable after retry: %v", err)
		}
	})

	t.Run("stable_state_preserves_recorded_rollback_slot", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory durability recovery is Linux-only")
		}
		fixture := newFirstHostSelfUpdateStageFixture(t)
		fixture.state.RollbackSlot = HostSelfUpdateSlotB
		fixture.state.RollbackAgentVersion = "v1.7.7"
		fixture.state.RollbackExecutorVersion = "v1.7.7"
		if err := fixture.rt.saveState(fixture.state); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(
			filepath.Join(fixture.slotRoot, "bin"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(fixture.slotRoot, "rollback-slot")
		if err := os.WriteFile(
			sentinel,
			[]byte("must remain\n"),
			0o444,
		); err != nil {
			t.Fatal(err)
		}

		fresh := fixture.rt
		if err := fresh.prepare(); err != nil {
			t.Fatalf("fresh prepare rejected recorded rollback slot: %v", err)
		}
		if body, err := os.ReadFile(sentinel); err != nil ||
			string(body) != "must remain\n" {
			t.Fatalf(
				"recorded rollback slot was not preserved: body=%q err=%v",
				body,
				err,
			)
		}
	})

	t.Run("stable_state_restores_inactive_backup_over_uncommitted_candidate", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("directory durability recovery is Linux-only")
		}
		root := t.TempDir()
		slotsRoot := filepath.Join(root, "slots")
		stateRoot := filepath.Join(root, "state")
		if err := os.MkdirAll(slotsRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(stateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		rt := hostSelfUpdateExecutorRuntime{
			slotsRoot:      slotsRoot,
			stateRoot:      stateRoot,
			statePath:      filepath.Join(stateRoot, "state.json"),
			allowTestPaths: true,
		}
		state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
		if err != nil {
			t.Fatal(err)
		}
		if err := rt.saveState(state); err != nil {
			t.Fatal(err)
		}
		slotRoot := filepath.Join(slotsRoot, HostSelfUpdateSlotB)
		backup := filepath.Join(
			slotsRoot,
			"."+HostSelfUpdateSlotB+"-"+firstID+".old",
		)
		if err := os.MkdirAll(slotRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(slotRoot, "candidate"),
			[]byte("uncommitted\n"),
			0o644,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(backup, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(backup, "previous-slot"),
			[]byte("previous\n"),
			0o644,
		); err != nil {
			t.Fatal(err)
		}

		if err := rt.recoverHostSelfUpdateSlotArtifacts(); err != nil {
			t.Fatalf("recover uncommitted candidate: %v", err)
		}
		if body, err := os.ReadFile(
			filepath.Join(slotRoot, "previous-slot"),
		); err != nil || string(body) != "previous\n" {
			t.Fatalf("previous inactive slot was not restored: body=%q err=%v", body, err)
		}
		if _, err := os.Lstat(
			filepath.Join(slotRoot, "candidate"),
		); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("uncommitted candidate survived recovery: %v", err)
		}
		if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restored backup artifact survived: %v", err)
		}
	})

	t.Run("malformed_reserved_backup_fails_closed", func(t *testing.T) {
		slotsRoot := t.TempDir()
		rt := hostSelfUpdateExecutorRuntime{
			slotsRoot:      slotsRoot,
			allowTestPaths: true,
		}
		if err := os.MkdirAll(
			filepath.Join(
				slotsRoot,
				"."+HostSelfUpdateSlotB+"-not-a-digest.old",
			),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
		if err := rt.recoverHostSelfUpdateSlotArtifacts(); err == nil {
			t.Fatal("malformed reserved backup was silently ignored")
		}
	})

	t.Run("non_directory_reserved_backup_fails_closed", func(t *testing.T) {
		slotsRoot := t.TempDir()
		rt := hostSelfUpdateExecutorRuntime{
			slotsRoot:      slotsRoot,
			allowTestPaths: true,
		}
		if err := os.WriteFile(
			filepath.Join(
				slotsRoot,
				"."+HostSelfUpdateSlotB+"-"+firstID+".old",
			),
			[]byte("unsafe\n"),
			0o644,
		); err != nil {
			t.Fatal(err)
		}
		if err := rt.recoverHostSelfUpdateSlotArtifacts(); err == nil {
			t.Fatal("non-directory reserved backup was accepted")
		}
	})
}

func TestHostSelfUpdateSlotBackupRecoveryRetryRequiresDirectorySync(
	t *testing.T,
) {
	slotsRoot := t.TempDir()
	backup := filepath.Join(
		slotsRoot,
		"."+HostSelfUpdateSlotB+"-111111111111.old",
	)
	if err := os.MkdirAll(backup, 0o755); err != nil {
		t.Fatal(err)
	}
	rt := hostSelfUpdateExecutorRuntime{
		slotsRoot:      slotsRoot,
		allowTestPaths: true,
	}
	syncCalls := 0
	successfulSyncs := 0
	rt.syncDir = func(path string) error {
		if filepath.Clean(path) != filepath.Clean(slotsRoot) {
			return nil
		}
		syncCalls++
		if syncCalls == 1 {
			return errors.New("injected recovered slot sync failure")
		}
		successfulSyncs++
		return nil
	}

	if err := rt.recoverHostSelfUpdateSlotArtifacts(); err == nil {
		t.Fatal("first recovered slot sync failure was ignored")
	}
	if err := rt.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		t.Fatalf("retry recovered slot durability: %v", err)
	}
	if successfulSyncs == 0 {
		t.Fatal("recovery retry succeeded without a directory sync")
	}
	if !hostSelfUpdatePathExists(
		filepath.Join(slotsRoot, HostSelfUpdateSlotB),
	) {
		t.Fatal("recovered slot is unavailable after retry")
	}
}

type firstHostSelfUpdateStageFixture struct {
	rt           hostSelfUpdateExecutorRuntime
	state        HostSelfUpdateState
	request      HostSelfUpdateRequest
	artifactRoot string
	slotDigests  hostSelfUpdateSlotDigests
	slotRoot     string
	temporary    string
}

func newFirstHostSelfUpdateStageFixture(
	t *testing.T,
) firstHostSelfUpdateStageFixture {
	t.Helper()
	root := t.TempDir()
	installRoot := filepath.Join(root, "install")
	slotsRoot := filepath.Join(installRoot, "slots")
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(slotsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
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
		runner:          hostSelfUpdateSlotIdentityRunner{request: request},
		allowTestPaths:  true,
	}
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
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
	slotDigests, err := hostSelfUpdateArtifactBinaryDigests(artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	return firstHostSelfUpdateStageFixture{
		rt:           rt,
		state:        state,
		request:      request,
		artifactRoot: artifactRoot,
		slotDigests:  slotDigests,
		slotRoot:     filepath.Join(slotsRoot, HostSelfUpdateSlotB),
		temporary: filepath.Join(
			slotsRoot,
			"."+HostSelfUpdateSlotB+"-"+shortID(request.Generation)+".new",
		),
	}
}

func newHostSelfUpdateSlotFixture(
	t *testing.T,
) (
	hostSelfUpdateExecutorRuntime,
	HostSelfUpdateRequest,
	string,
	string,
	hostSelfUpdateSlotDigests,
) {
	t.Helper()
	root := t.TempDir()
	slotsRoot := filepath.Join(root, "slots")
	slotRoot := filepath.Join(slotsRoot, HostSelfUpdateSlotB)
	if err := os.MkdirAll(filepath.Join(slotRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(slotRoot, "previous-slot"),
		[]byte("previous\n"),
		0o644,
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
	slotDigests, err := hostSelfUpdateArtifactBinaryDigests(artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	rt := hostSelfUpdateExecutorRuntime{
		slotsRoot:      slotsRoot,
		runner:         hostSelfUpdateSlotIdentityRunner{request: request},
		allowTestPaths: true,
	}
	return rt, request, artifactRoot, slotRoot, slotDigests
}

func assertPreviousHostSelfUpdateSlot(
	t *testing.T,
	slotsRoot string,
	slotRoot string,
) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(slotRoot, "previous-slot"))
	if err != nil || string(body) != "previous\n" {
		t.Fatalf("previous slot was not restored: body=%q err=%v", body, err)
	}
	entries, err := os.ReadDir(slotsRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if looksLikeReservedHostSelfUpdateSlotArtifact(entry.Name()) {
			t.Fatalf("reserved slot artifact survived failure: %q", entry.Name())
		}
	}
}

func looksLikeReservedHostSelfUpdateSlotArtifact(name string) bool {
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if !strings.HasPrefix(name, "."+slot+"-") {
			continue
		}
		return strings.HasSuffix(name, ".new") ||
			strings.HasSuffix(name, ".old")
	}
	return false
}

func hostSelfUpdatePathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
