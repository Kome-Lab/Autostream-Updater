//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type hostSelfUpdateExecutorTestDownloader struct {
	release HostAgentRelease
}

func (d hostSelfUpdateExecutorTestDownloader) DownloadHostAgentRelease(
	context.Context,
	string,
	string,
	string,
) (HostAgentRelease, error) {
	return d.release, nil
}

type hostSelfUpdateExecutorTestRunner struct {
	version          string
	commit           string
	binaryIdentities map[string]hostSelfUpdateExecutorTestBinaryIdentity
	restarts         int
	executorRestarts int
	restartOrder     []string
	failExecutor     bool
	serviceActive    bool
	socketActive     bool
	serviceChecks    int
	failServiceAfter int
	mainPID          string
	secondMainPID    string
	mainPIDChecks    int
	runningExe       string
	mutationProtocol int
	recoveryProtocol int
}

type hostSelfUpdateExecutorTestBinaryIdentity struct {
	version          string
	commit           string
	mutationProtocol int
	recoveryProtocol int
}

func (r *hostSelfUpdateExecutorTestRunner) Run(
	_ context.Context,
	_ string,
	_ []string,
	name string,
	args ...string,
) (string, error) {
	if name == "/usr/bin/systemctl" {
		switch {
		case len(args) == 2 &&
			args[0] == "restart" &&
			args[1] == hostSelfUpdateServiceUnit:
			r.restarts++
			r.restartOrder = append(r.restartOrder, args[1])
			return "", nil
		case len(args) == 2 &&
			args[0] == "restart" &&
			args[1] == hostSelfUpdateExecutorServiceUnit:
			r.executorRestarts++
			r.restartOrder = append(r.restartOrder, args[1])
			if r.failExecutor {
				return "", errors.New("injected Local Executor restart failure")
			}
			return "", nil
		case len(args) == 3 &&
			args[0] == "is-active" &&
			args[1] == "--quiet" &&
			(args[2] == hostSelfUpdateExecutorServiceUnit ||
				args[2] == hostSelfUpdateExecutorSocketUnit):
			if args[2] == hostSelfUpdateExecutorSocketUnit {
				if !r.socketActive {
					return "", errors.New(
						"injected inactive Local Executor socket",
					)
				}
				return "", nil
			}
			r.serviceChecks++
			if !r.serviceActive ||
				(r.failServiceAfter > 0 &&
					r.serviceChecks > r.failServiceAfter) {
				return "", errors.New("injected inactive Local Executor")
			}
			return "", nil
		case len(args) == 4 &&
			args[0] == "show" &&
			args[1] == "--property=MainPID" &&
			args[2] == "--value" &&
			args[3] == hostSelfUpdateExecutorServiceUnit:
			r.mainPIDChecks++
			if r.mainPIDChecks > 1 && r.secondMainPID != "" {
				return r.secondMainPID + "\n", nil
			}
			return r.mainPID + "\n", nil
		}
		return "", errHostSelfUpdatePrecondition
	}
	version := r.version
	commit := r.commit
	mutationProtocol := r.mutationProtocol
	recoveryProtocol := r.recoveryProtocol
	if identity, ok := r.binaryIdentities[filepath.Clean(name)]; ok {
		version = identity.version
		commit = identity.commit
		mutationProtocol = identity.mutationProtocol
		recoveryProtocol = identity.recoveryProtocol
	}
	if mutationProtocol == 0 {
		mutationProtocol = LocalExecutorMutationProtocolVersion
	}
	if recoveryProtocol == 0 {
		recoveryProtocol = HostSelfUpdateRecoveryProtocolVersion
	}
	return filepath.Base(name) + " " + version +
		"\ncommit: " + commit + "\nbuild_date: test\n" +
		"mutation_protocol: " +
		strconv.Itoa(mutationProtocol) + "\n" +
		"recovery_protocol: " +
		strconv.Itoa(recoveryProtocol) + "\n", nil
}

func (r *hostSelfUpdateExecutorTestRunner) registerBinaryIdentity(
	path string,
	identity hostSelfUpdateExecutorTestBinaryIdentity,
) {
	if r.binaryIdentities == nil {
		r.binaryIdentities =
			make(map[string]hostSelfUpdateExecutorTestBinaryIdentity)
	}
	r.binaryIdentities[filepath.Clean(path)] = identity
}

func TestLocalExecutorHostSelfUpdateStagesSwitchesAndCommitsABSlot(t *testing.T) {
	root := t.TempDir()
	installRoot := filepath.Join(root, "opt", "autostream", "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	stateRoot := filepath.Join(root, "var", "lib", "autostream-local-executor", "host-self-update")
	if err := os.MkdirAll(filepath.Join(slotsRoot, HostSelfUpdateSlotA, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		if err := os.WriteFile(
			filepath.Join(slotsRoot, HostSelfUpdateSlotA, "bin", name),
			[]byte("healthy "+name+"\n"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(filepath.Join("slots", HostSelfUpdateSlotA), currentLink); err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(root, "artifact")
	if err := os.MkdirAll(filepath.Join(artifactRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"autostream-host-agent", "autostream-local-executor"} {
		if err := os.WriteFile(filepath.Join(artifactRoot, "bin", name), []byte(name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	request := validHostSelfUpdateRequest()
	runner := &hostSelfUpdateExecutorTestRunner{
		version: request.AgentVersion, commit: request.Commit,
	}
	rt := hostSelfUpdateExecutorRuntime{
		installRoot:     installRoot,
		currentLink:     currentLink,
		slotsRoot:       slotsRoot,
		stateRoot:       stateRoot,
		statePath:       filepath.Join(stateRoot, "state.json"),
		downloadRoot:    filepath.Join(stateRoot, "downloads"),
		arch:            "amd64",
		executorVersion: "v1.7.8",
		downloader: hostSelfUpdateExecutorTestDownloader{release: HostAgentRelease{
			Artifact: DownloadedArtifact{
				RootDir: artifactRoot,
				SHA256:  strings.TrimPrefix(request.ArtifactSHA256, "sha256:"),
			},
			Request:             request,
			PublishedAt:         request.Release.PublishedAt,
			MinimumPanelVersion: request.Release.MinimumPanelVersion,
		}},
		runner:         runner,
		allowTestPaths: true,
	}
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 7
	policy.ProjectionRevision = 11
	policy.PolicyRevision = 9
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: policy.ProjectionRevision,
		ExecutorPolicyRevision:  policy.PolicyRevision,
	}
	policySHA256, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	consumedGrants := 0
	rt.consumeGrant = func(
		_ context.Context,
		panelURL string,
		authorization HostSelfUpdateGrantAuthorization,
	) (HostSelfUpdateGrantConsumeResult, error) {
		if panelURL != policy.Mutation.PanelURL {
			t.Fatalf("grant consumed against %q", panelURL)
		}
		consumedGrants++
		return consumedHostSelfUpdateGrant(authorization), nil
	}
	baseRequest := LocalExecutorRequest{
		Version:                 LocalExecutorMutationProtocolVersion,
		ServiceID:               policy.HostID,
		SourcePolicyRevision:    fence.SourcePolicyRevision,
		OwnershipEpoch:          fence.OwnershipEpoch,
		OwnershipPolicyRevision: fence.OwnershipPolicyRevision,
		ExecutorPolicyRevision:  fence.ExecutorPolicyRevision,
	}

	stageRequest := baseRequest
	stageRequest.Operation = "host_self_update_stage"
	stageRequest.HostSelfUpdate = &request
	stageAuthorization := validHostSelfUpdateGrantAuthorization(
		"stage", request, fence, policySHA256,
	)
	stageRequest.HostSelfUpdateGrant = &stageAuthorization
	response := handleLocalExecutorHostSelfUpdate(
		context.Background(), policy, stageRequest, rt,
	)
	if response.Error != nil || response.HostSelfUpdate == nil ||
		response.HostSelfUpdate.State.Phase != HostSelfUpdatePhaseStaged {
		t.Fatalf("stage response=%#v", response)
	}
	response = handleLocalExecutorHostSelfUpdate(
		context.Background(), policy, stageRequest, rt,
	)
	if response.Error != nil || response.HostSelfUpdate == nil ||
		response.HostSelfUpdate.State.Phase != HostSelfUpdatePhaseStaged ||
		consumedGrants != 1 {
		t.Fatalf(
			"exact stage replay was not recovered: response=%#v grants=%d",
			response,
			consumedGrants,
		)
	}
	contradictoryStageRequest := stageRequest
	contradictoryStage := request
	contradictoryStage.Generation = "22222222-2222-4222-8222-222222222222"
	contradictoryStageRequest.HostSelfUpdate = &contradictoryStage
	response = handleLocalExecutorHostSelfUpdate(
		context.Background(), policy, contradictoryStageRequest, rt,
	)
	if response.Error == nil ||
		response.Error.Code != "authorization_failed" ||
		response.HostSelfUpdate != nil ||
		consumedGrants != 1 {
		t.Fatalf(
			"contradictory applied stage replay was accepted: response=%#v grants=%d",
			response,
			consumedGrants,
		)
	}
	for _, name := range []string{"autostream-host-agent", "autostream-local-executor"} {
		info, err := os.Lstat(filepath.Join(slotsRoot, HostSelfUpdateSlotB, "bin", name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
			t.Fatalf("staged binary %s is unsafe: info=%v err=%v", name, info, err)
		}
	}

	activateRequest := baseRequest
	activateRequest.Operation = "host_self_update_activate"
	activateRequest.HostSelfUpdateGeneration = request.Generation
	response = handleLocalExecutorHostSelfUpdate(
		context.Background(), policy, activateRequest, rt,
	)
	if response.Error != nil || response.HostSelfUpdate == nil ||
		!response.HostSelfUpdate.RestartRequested ||
		response.HostSelfUpdate.State.Phase != HostSelfUpdatePhaseActivating ||
		runner.restarts != 1 {
		t.Fatalf("activate response=%#v restarts=%d", response, runner.restarts)
	}
	if slot, err := rt.readCurrentSlot(); err != nil || slot != HostSelfUpdateSlotB {
		t.Fatalf("current slot=%q err=%v", slot, err)
	}

	rt.executorVersion = request.ExecutorVersion
	reconcileRequest := baseRequest
	reconcileRequest.Operation = "host_self_update_reconcile"
	reconcileRequest.HostSelfUpdateProof = &HostSelfUpdateAgentProof{
		RunningAgentVersion:   request.AgentVersion,
		PanelHeartbeatVersion: request.AgentVersion,
		HeartbeatGeneration:   request.Generation,
	}
	reconcileAuthorization := validHostSelfUpdateGrantAuthorization(
		"reconcile", request, fence, policySHA256,
	)
	reconcileRequest.HostSelfUpdateGrant = &reconcileAuthorization
	response = handleLocalExecutorHostSelfUpdate(
		context.Background(), policy, reconcileRequest, rt,
	)
	if response.Error != nil || response.HostSelfUpdate == nil ||
		response.HostSelfUpdate.State.Phase != HostSelfUpdatePhaseStable ||
		response.HostSelfUpdate.State.ActiveSlot != HostSelfUpdateSlotB ||
		response.HostSelfUpdate.LastAction != HostSelfUpdateActionCommit {
		t.Fatalf("commit response=%#v", response)
	}
	if consumedGrants != 2 {
		t.Fatalf("consumed grants=%d, want stage and reconcile", consumedGrants)
	}
	response = handleLocalExecutorHostSelfUpdate(
		context.Background(), policy, reconcileRequest, rt,
	)
	if response.Error != nil || response.HostSelfUpdate == nil ||
		response.HostSelfUpdate.State.Phase != HostSelfUpdatePhaseStable ||
		consumedGrants != 2 {
		t.Fatalf(
			"exact reconcile replay was not recovered: response=%#v grants=%d",
			response,
			consumedGrants,
		)
	}
	contradictoryReconcileRequest := reconcileRequest
	contradictoryProof := *reconcileRequest.HostSelfUpdateProof
	contradictoryProof.HeartbeatGeneration =
		"33333333-3333-4333-8333-333333333333"
	contradictoryReconcileRequest.HostSelfUpdateProof = &contradictoryProof
	response = handleLocalExecutorHostSelfUpdate(
		context.Background(), policy, contradictoryReconcileRequest, rt,
	)
	if response.Error == nil ||
		response.Error.Code != "authorization_failed" ||
		response.HostSelfUpdate != nil ||
		consumedGrants != 2 {
		t.Fatalf(
			"contradictory applied reconcile replay was accepted: response=%#v grants=%d",
			response,
			consumedGrants,
		)
	}
	info, err := os.Lstat(rt.statePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("durable state mode=%v err=%v", info, err)
	}
}

func TestLocalExecutorHostSelfUpdateFailureRestoresHealthySlot(t *testing.T) {
	root := t.TempDir()
	installRoot := filepath.Join(root, "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if err := os.MkdirAll(filepath.Join(slotsRoot, slot, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"autostream-host-agent",
			"autostream-local-executor",
		} {
			if err := os.WriteFile(
				filepath.Join(slotsRoot, slot, "bin", name),
				[]byte("test "+name+"\n"),
				0o755,
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(filepath.Join("slots", HostSelfUpdateSlotB), currentLink); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	rt := hostSelfUpdateExecutorRuntime{
		installRoot: installRoot, currentLink: currentLink,
		slotsRoot: slotsRoot, stateRoot: stateRoot,
		statePath:    filepath.Join(stateRoot, "state.json"),
		downloadRoot: filepath.Join(stateRoot, "downloads"),
		arch:         "amd64", executorVersion: "v1.7.8",
		runner: &hostSelfUpdateExecutorTestRunner{
			version: "v1.7.8", commit: strings.Repeat("a", 40),
		},
		downloader:     hostSelfUpdateExecutorTestDownloader{},
		allowTestPaths: true,
	}
	if err := rt.prepare(); err != nil {
		t.Fatal(err)
	}
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	state.ActiveSlot = HostSelfUpdateSlotB
	state.HealthySlot = HostSelfUpdateSlotB
	request := validHostSelfUpdateRequest()
	runner := rt.runner.(*hostSelfUpdateExecutorTestRunner)
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = beginHostSelfUpdateActivationForTest(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := rt.switchCurrent(HostSelfUpdateSlotA); err != nil {
		t.Fatal(err)
	}
	status, err := rt.reconcile(context.Background(), HostSelfUpdateAgentProof{
		RunningAgentVersion: request.AgentVersion,
		FailureCode:         "executor_probe_failed",
	})
	if err != nil {
		t.Fatalf("rollback reconcile: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseRollingBack ||
		status.CurrentSlot != HostSelfUpdateSlotB ||
		!status.RollbackRequested ||
		!status.RestartRequested {
		t.Fatalf("failed update did not restore healthy slot: %#v", status)
	}
	rt.now = func() time.Time {
		return state.ActivationDeadline.Add(time.Minute)
	}
	status, err = rt.reconcile(context.Background(), HostSelfUpdateAgentProof{
		RunningAgentVersion: "v1.7.8",
	})
	if err != nil {
		t.Fatalf("rollback completion after restart: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		status.State.ActiveSlot != HostSelfUpdateSlotB ||
		status.State.FailedGeneration != request.Generation ||
		status.LastAction != HostSelfUpdateActionRollbackComplete {
		t.Fatalf("healthy slot did not become stable after restart: %#v", status)
	}
}

func TestLocalExecutorHostSelfUpdateRebootRecoversActivatingStateWithoutRestage(t *testing.T) {
	root := t.TempDir()
	installRoot := filepath.Join(root, "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if err := os.MkdirAll(filepath.Join(slotsRoot, slot, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"autostream-host-agent",
			"autostream-local-executor",
		} {
			if err := os.WriteFile(
				filepath.Join(slotsRoot, slot, "bin", name),
				[]byte("test "+name+"\n"),
				0o755,
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(filepath.Join("slots", HostSelfUpdateSlotA), currentLink); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	runner := &hostSelfUpdateExecutorTestRunner{}
	reconcileNow := time.Date(2026, 7, 28, 1, 3, 0, 0, time.UTC)
	runtimeBeforeRestart := hostSelfUpdateExecutorRuntime{
		installRoot: installRoot, currentLink: currentLink,
		slotsRoot: slotsRoot, stateRoot: stateRoot,
		statePath:    filepath.Join(stateRoot, "state.json"),
		downloadRoot: filepath.Join(stateRoot, "downloads"),
		arch:         "amd64", executorVersion: "v1.7.8",
		runner: runner, downloader: hostSelfUpdateExecutorTestDownloader{},
		now:            func() time.Time { return reconcileNow },
		allowTestPaths: true,
	}
	if err := runtimeBeforeRestart.prepare(); err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	state = stageHostSelfUpdateStateForLinuxTest(
		t, runtimeBeforeRestart, runner, state, request,
	)
	state, err = beginHostSelfUpdateActivationForTest(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtimeBeforeRestart.saveState(state); err != nil {
		t.Fatal(err)
	}

	status, err := runtimeBeforeRestart.reconcile(
		context.Background(), HostSelfUpdateAgentProof{},
	)
	if err != nil {
		t.Fatalf("reconcile crash before current switch: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseActivating ||
		status.CurrentSlot != HostSelfUpdateSlotB ||
		status.LastAction != HostSelfUpdateActionSwitchCurrent ||
		runner.restarts != 1 {
		t.Fatalf("activating state did not resume once: %#v restarts=%d", status, runner.restarts)
	}

	runtimeAfterRestart := runtimeBeforeRestart
	runtimeAfterRestart.executorVersion = request.ExecutorVersion
	status, err = runtimeAfterRestart.reconcile(
		context.Background(),
		HostSelfUpdateAgentProof{
			RunningAgentVersion:   request.AgentVersion,
			PanelHeartbeatVersion: request.AgentVersion,
			HeartbeatGeneration:   request.Generation,
		},
	)
	if err != nil {
		t.Fatalf("reconcile new runtime after reboot: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		status.State.ActiveSlot != HostSelfUpdateSlotB ||
		status.LastAction != HostSelfUpdateActionCommit ||
		runner.restarts != 1 {
		t.Fatalf("reboot recovery restaged or failed to commit: %#v restarts=%d", status, runner.restarts)
	}
}

func TestLocalExecutorStopsOldRuntimeWheneverRestartWasRequested(t *testing.T) {
	if localExecutorResponseRequiresRuntimeRestart(LocalExecutorResponse{}) {
		t.Fatal("empty response requested a runtime restart")
	}
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	if !localExecutorResponseRequiresRuntimeRestart(LocalExecutorResponse{
		Version: LocalExecutorMutationProtocolVersion,
		HostSelfUpdate: &HostSelfUpdateRuntimeStatus{
			State:                   state,
			CurrentSlot:             HostSelfUpdateSlotA,
			ExecutorVersion:         "v1.7.8",
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
			RestartRequested:        true,
		},
	}) {
		t.Fatal("old executor would survive a lost activation response")
	}
}

func TestLocalExecutorHostSelfUpdateActivationUsesOnlyRootClock(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	rt.verificationTimeout = 2 * time.Minute
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	status, err := rt.activate(context.Background(), request.Generation)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if !status.State.ActivationStartedAt.Equal(rootNow) ||
		!status.State.ActivationDeadline.Equal(rootNow.Add(2*time.Minute)) ||
		runner.restarts != 1 {
		t.Fatalf("activation did not persist the root clock: status=%#v restarts=%d", status, runner.restarts)
	}
}

func TestLocalExecutorHostSelfUpdateSwitchFailurePersistsRollbackFence(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	rt.switchCurrentHook = func(string) error {
		return errors.New("injected atomic switch failure")
	}
	if _, err := rt.activate(
		context.Background(),
		request.Generation,
	); !errors.Is(err, errHostSelfUpdateRollback) {
		t.Fatalf("switch failure err=%v", err)
	}
	rt.switchCurrentHook = nil
	status, err := rt.status()
	if err != nil {
		t.Fatal(err)
	}
	if status.State.Phase != HostSelfUpdatePhaseRollingBack ||
		status.State.FailedGeneration != request.Generation ||
		status.CurrentSlot != HostSelfUpdateSlotA ||
		runner.restarts != 0 {
		t.Fatalf("switch failure was not durably fenced: %#v restarts=%d", status, runner.restarts)
	}
	status, err = rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	)
	if err != nil {
		t.Fatalf("watchdog finish rollback: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		status.State.FailedGeneration != request.Generation ||
		status.CurrentSlot != HostSelfUpdateSlotA ||
		runner.restarts != 1 {
		t.Fatalf("healthy slot did not converge: %#v restarts=%d", status, runner.restarts)
	}
}

func TestHealthySlotWatchdogRollsBackWhenCandidateNeverContactsPanel(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }

	wrongSlot, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotB,
	)
	if err != nil {
		t.Fatalf("candidate watchdog no-op: %v", err)
	}
	if wrongSlot.State.Phase != HostSelfUpdatePhaseActivating ||
		wrongSlot.CurrentSlot != HostSelfUpdateSlotA ||
		runner.restarts != 0 {
		t.Fatalf("candidate slot was allowed to own recovery: %#v restarts=%d", wrongSlot, runner.restarts)
	}
	if current, err := rt.readCurrentSlot(); err != nil ||
		current != HostSelfUpdateSlotB {
		t.Fatalf(
			"candidate watchdog mutated current: slot=%q err=%v",
			current,
			err,
		)
	}

	status, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	)
	if err != nil {
		t.Fatalf("healthy watchdog rollback: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		status.State.FailedGeneration != request.Generation ||
		status.CurrentSlot != HostSelfUpdateSlotA ||
		status.State.ActiveAgentVersion != "v1.7.8" ||
		runner.restarts != 1 ||
		runner.executorRestarts != 1 ||
		len(runner.restartOrder) != 2 ||
		runner.restartOrder[0] != hostSelfUpdateExecutorServiceUnit ||
		runner.restartOrder[1] != hostSelfUpdateServiceUnit {
		t.Fatalf(
			"panel-less candidate crash was not rolled back: status=%#v agent_restarts=%d executor_restarts=%d order=%v",
			status,
			runner.restarts,
			runner.executorRestarts,
			runner.restartOrder,
		)
	}
}

func TestNonHealthySlotWatchdogDoesNotRecoverSharedSlotArtifacts(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(
		rt.slotsRoot,
		"."+HostSelfUpdateSlotB+"-111111111111.new",
	)
	if err := os.MkdirAll(artifact, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(artifact, "must-remain")
	if err := os.WriteFile(sentinel, []byte("pending timer no-op\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(rt.statePath)
	if err != nil {
		t.Fatal(err)
	}
	currentBefore, err := os.Readlink(rt.currentLink)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotB,
	); err != nil {
		t.Fatalf("non-healthy watchdog no-op: %v", err)
	}
	if body, err := os.ReadFile(sentinel); err != nil ||
		string(body) != "pending timer no-op\n" {
		t.Fatalf(
			"non-healthy watchdog recovered shared artifact: body=%q err=%v",
			body,
			err,
		)
	}
	stateAfter, err := os.ReadFile(rt.statePath)
	if err != nil || string(stateAfter) != string(stateBefore) {
		t.Fatalf("non-healthy watchdog mutated state: err=%v", err)
	}
	currentAfter, err := os.Readlink(rt.currentLink)
	if err != nil || currentAfter != currentBefore {
		t.Fatalf(
			"non-healthy watchdog mutated current: before=%q after=%q err=%v",
			currentBefore,
			currentAfter,
			err,
		)
	}
}

func TestHealthySlotWatchdogLeavesRollbackFenceWhenExecutorRestartFails(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }
	runner.failExecutor = true

	if _, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	); !errors.Is(err, errHostSelfUpdateRollback) {
		t.Fatalf("executor restart failure err=%v", err)
	}
	persisted, err := rt.loadPersistedState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Phase != HostSelfUpdatePhaseRollingBack ||
		persisted.FailedGeneration != request.Generation ||
		runner.executorRestarts != 1 ||
		runner.restarts != 0 {
		t.Fatalf(
			"rollback fence was cleared after executor restart failure: state=%#v agent_restarts=%d executor_restarts=%d",
			persisted,
			runner.restarts,
			runner.executorRestarts,
		)
	}
	if current, err := rt.readCurrentSlot(); err != nil ||
		current != HostSelfUpdateSlotA {
		t.Fatalf("healthy current was not restored: slot=%q err=%v", current, err)
	}

	runner.failExecutor = false
	status, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	)
	if err != nil {
		t.Fatalf("resume rollback: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseStable ||
		runner.executorRestarts != 2 ||
		runner.restarts != 1 {
		t.Fatalf(
			"resumed rollback did not converge: status=%#v agent_restarts=%d executor_restarts=%d",
			status,
			runner.restarts,
			runner.executorRestarts,
		)
	}
}

func TestHealthySlotWatchdogLeavesRollbackFenceWhenSocketHandshakeFails(
	t *testing.T,
) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }
	rt.watchdogStatus = func(
		context.Context,
	) (HostSelfUpdateRuntimeStatus, error) {
		return HostSelfUpdateRuntimeStatus{}, context.DeadlineExceeded
	}

	if _, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		HostSelfUpdateSlotA,
	); !errors.Is(err, errHostSelfUpdateRollback) {
		t.Fatalf("socket handshake failure err=%v", err)
	}
	persisted, err := rt.loadPersistedState()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Phase != HostSelfUpdatePhaseRollingBack ||
		persisted.FailedGeneration != request.Generation ||
		runner.executorRestarts != 1 ||
		runner.restarts != 0 {
		t.Fatalf(
			"socket handshake failure cleared rollback fence: state=%#v agent_restarts=%d executor_restarts=%d",
			persisted,
			runner.restarts,
			runner.executorRestarts,
		)
	}
	if current, err := rt.readCurrentSlot(); err != nil ||
		current != HostSelfUpdateSlotA {
		t.Fatalf(
			"healthy current was not retained after handshake failure: slot=%q err=%v",
			current,
			err,
		)
	}
}

func TestVerifyHealthyLocalExecutorWaitsForTransientSystemdExecutor(
	t *testing.T,
) {
	now := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		now,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(
		rt.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	var resolvedPIDs []int
	rt.resolveProcessExe = func(pid int) (string, error) {
		resolvedPIDs = append(resolvedPIDs, pid)
		if len(resolvedPIDs) == 1 {
			return "/usr/lib/systemd/systemd-executor", nil
		}
		return expected, nil
	}
	waits := 0
	rt.waitExecutorStable = func(context.Context) error {
		waits++
		return nil
	}

	if err := rt.verifyHealthyLocalExecutor(
		context.Background(),
		HostSelfUpdateSlotA,
		state,
	); err != nil {
		t.Fatalf("verifyHealthyLocalExecutor: %v", err)
	}
	if len(resolvedPIDs) != 3 || waits != 2 || runner.mainPIDChecks != 3 {
		t.Fatalf(
			"transient verification probes=%v waits=%d MainPID_reads=%d",
			resolvedPIDs,
			waits,
			runner.mainPIDChecks,
		)
	}
	for _, pid := range resolvedPIDs {
		if pid != 4242 {
			t.Fatalf("resolved PIDs=%v, want one stable MainPID", resolvedPIDs)
		}
	}
}

func TestAcquireHealthyLocalExecutorRejectsUnsafeOrPersistentHelper(
	t *testing.T,
) {
	for _, test := range []struct {
		name         string
		running      string
		wantError    string
		wantResolves int
		wantWaits    int
	}{
		{
			name:         "untrusted_same_basename",
			running:      "/tmp/systemd-executor",
			wantError:    "not running the healthy slot binary",
			wantResolves: 1,
			wantWaits:    0,
		},
		{
			name:         "persistent_allowlisted_helper",
			running:      "/usr/lib/systemd/systemd-executor",
			wantError:    "startup probe limit",
			wantResolves: hostSelfUpdateSystemdExecutorProbes,
			wantWaits:    hostSelfUpdateSystemdExecutorProbes - 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt, runner := newHostSelfUpdateRecoveryFixture(
				t,
				HostSelfUpdateSlotA,
				"v1.7.8",
				time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC),
			)
			expected := filepath.Join(
				rt.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				"autostream-local-executor",
			)
			resolves := 0
			waits := 0
			rt.resolveProcessExe = func(int) (string, error) {
				resolves++
				return test.running, nil
			}
			rt.waitExecutorStable = func(context.Context) error {
				waits++
				return nil
			}

			_, err := rt.acquireHealthyLocalExecutorPID(
				context.Background(),
				expected,
			)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("helper verification err=%v", err)
			}
			if resolves != test.wantResolves || waits != test.wantWaits ||
				runner.mainPIDChecks != test.wantResolves {
				t.Fatalf(
					"helper verification resolves=%d waits=%d MainPID_reads=%d",
					resolves,
					waits,
					runner.mainPIDChecks,
				)
			}
		})
	}
}

func TestAcquireHealthyLocalExecutorHonorsCanceledTransitionWait(
	t *testing.T,
) {
	rt, _ := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC),
	)
	expected := filepath.Join(
		rt.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	rt.resolveProcessExe = func(int) (string, error) {
		return "/usr/lib/systemd/systemd-executor", nil
	}
	rt.waitExecutorStable = func(context.Context) error {
		waits++
		cancel()
		return ctx.Err()
	}

	_, err := rt.acquireHealthyLocalExecutorPID(ctx, expected)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled transition err=%v", err)
	}
	if waits != 1 {
		t.Fatalf("canceled transition waits=%d", waits)
	}
}

func TestAcquireHealthyLocalExecutorRejectsPIDChurnDuringTransition(
	t *testing.T,
) {
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC),
	)
	expected := filepath.Join(
		rt.slotsRoot,
		HostSelfUpdateSlotA,
		"bin",
		"autostream-local-executor",
	)
	runner.secondMainPID = "4343"
	resolves := 0
	rt.resolveProcessExe = func(int) (string, error) {
		resolves++
		if resolves == 1 {
			return "/usr/lib/systemd/systemd-executor", nil
		}
		return expected, nil
	}

	_, err := rt.acquireHealthyLocalExecutorPID(
		context.Background(),
		expected,
	)
	if err == nil || !strings.Contains(
		err.Error(),
		"MainPID changed during systemd-executor transition",
	) {
		t.Fatalf("PID churn err=%v", err)
	}
	if resolves != 2 || runner.mainPIDChecks != 2 {
		t.Fatalf(
			"PID churn resolves=%d MainPID_reads=%d",
			resolves,
			runner.mainPIDChecks,
		)
	}
}

func TestHealthySlotWatchdogRequiresRunningHealthyExecutorIdentity(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	for name, mutate := range map[string]func(
		hostSelfUpdateExecutorRuntime,
		*hostSelfUpdateExecutorTestRunner,
	){
		"start_then_crash": func(
			_ hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.failServiceAfter = 1
		},
		"main_pid_changes_during_probe": func(
			_ hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.secondMainPID = "4343"
		},
		"wrong_main_executable": func(
			rt hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.runningExe = filepath.Join(
				rt.slotsRoot,
				HostSelfUpdateSlotB,
				"bin",
				"autostream-local-executor",
			)
		},
		"wrong_mutation_protocol": func(
			rt hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			path := filepath.Clean(filepath.Join(
				rt.slotsRoot,
				HostSelfUpdateSlotA,
				"bin",
				"autostream-local-executor",
			))
			identity := runner.binaryIdentities[path]
			identity.mutationProtocol =
				LocalExecutorMutationProtocolVersion - 1
			runner.binaryIdentities[path] = identity
		},
		"socket_service_has_no_main_pid": func(
			_ hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.mainPID = "0"
		},
		"socket_activation_is_inactive": func(
			_ hostSelfUpdateExecutorRuntime,
			runner *hostSelfUpdateExecutorTestRunner,
		) {
			runner.socketActive = false
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			rt, runner := newHostSelfUpdateRecoveryFixture(
				t,
				HostSelfUpdateSlotA,
				"v1.7.8",
				rootNow,
			)
			state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
			if err != nil {
				t.Fatal(err)
			}
			request := validHostSelfUpdateRequest()
			state = stageHostSelfUpdateStateForLinuxTest(
				t, rt, runner, state, request,
			)
			state, err = BeginHostSelfUpdateActivation(
				state,
				rootNow,
				time.Minute,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := rt.saveState(state); err != nil {
				t.Fatal(err)
			}
			if err := rt.switchCurrent(HostSelfUpdateSlotB); err != nil {
				t.Fatal(err)
			}
			rt.now = func() time.Time {
				return rootNow.Add(2 * time.Minute)
			}
			mutate(rt, runner)

			if _, err := rt.recoverExpiredHostSelfUpdate(
				context.Background(),
				HostSelfUpdateSlotA,
			); !errors.Is(err, errHostSelfUpdateRollback) {
				t.Fatalf("unhealthy executor proof err=%v", err)
			}
			persisted, err := rt.loadPersistedState()
			if err != nil {
				t.Fatal(err)
			}
			if persisted.Phase != HostSelfUpdatePhaseRollingBack ||
				persisted.FailedGeneration != request.Generation ||
				runner.executorRestarts != 1 ||
				runner.restarts != 0 {
				t.Fatalf(
					"unhealthy executor cleared rollback fence: state=%#v agent_restarts=%d executor_restarts=%d",
					persisted,
					runner.restarts,
					runner.executorRestarts,
				)
			}
		})
	}
}

func TestHealthySlotWatchdogReconstructsCurrentFromDurableState(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	for _, healthySlot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		healthySlot := healthySlot
		t.Run("healthy_"+healthySlot, func(t *testing.T) {
			for _, currentState := range []struct {
				name  string
				setup func(*testing.T, hostSelfUpdateExecutorRuntime, string)
			}{
				{
					name: "missing",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, _ string) {
						t.Helper()
						if err := os.Remove(rt.currentLink); err != nil {
							t.Fatal(err)
						}
					},
				},
				{
					name: "regular_file",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, _ string) {
						t.Helper()
						if err := os.Remove(rt.currentLink); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(rt.currentLink, []byte("not a slot\n"), 0o644); err != nil {
							t.Fatal(err)
						}
					},
				},
				{
					name: "malformed_symlink",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, _ string) {
						t.Helper()
						if err := os.Remove(rt.currentLink); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink("../../outside", rt.currentLink); err != nil {
							t.Fatal(err)
						}
					},
				},
				{
					name: "dangling_symlink",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, _ string) {
						t.Helper()
						if err := os.Remove(rt.currentLink); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(filepath.Join("slots", "missing"), rt.currentLink); err != nil {
							t.Fatal(err)
						}
					},
				},
				{
					name: "power_loss_immediately_after_switch",
					setup: func(t *testing.T, rt hostSelfUpdateExecutorRuntime, pendingSlot string) {
						t.Helper()
						if err := rt.switchCurrent(pendingSlot); err != nil {
							t.Fatal(err)
						}
					},
				},
			} {
				currentState := currentState
				t.Run(currentState.name, func(t *testing.T) {
					rt, runner := newHostSelfUpdateRecoveryFixture(
						t,
						healthySlot,
						"v1.7.8",
						rootNow,
					)
					state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
					if err != nil {
						t.Fatal(err)
					}
					state.ActiveSlot = healthySlot
					state.HealthySlot = healthySlot
					request := validHostSelfUpdateRequest()
					state = stageHostSelfUpdateStateForLinuxTest(
						t, rt, runner, state, request,
					)
					state, err = BeginHostSelfUpdateActivation(
						state,
						rootNow,
						time.Minute,
					)
					if err != nil {
						t.Fatal(err)
					}
					if err := rt.saveState(state); err != nil {
						t.Fatal(err)
					}
					currentState.setup(t, rt, state.PendingSlot)
					rt.now = func() time.Time {
						return rootNow.Add(2 * time.Minute)
					}

					status, err := rt.recoverExpiredHostSelfUpdate(
						context.Background(),
						healthySlot,
					)
					if err != nil {
						t.Fatalf("recover fixed healthy slot: %v", err)
					}
					if status.State.Phase != HostSelfUpdatePhaseStable ||
						status.State.ActiveSlot != healthySlot ||
						status.State.HealthySlot != healthySlot ||
						status.State.FailedGeneration != request.Generation ||
						status.CurrentSlot != healthySlot ||
						runner.restarts != 1 {
						t.Fatalf(
							"fixed recovery did not converge: status=%#v restarts=%d",
							status,
							runner.restarts,
						)
					}
					currentSlot, err := rt.readCurrentSlot()
					if err != nil || currentSlot != healthySlot {
						t.Fatalf(
							"current was not reconstructed: slot=%q err=%v",
							currentSlot,
							err,
						)
					}
				})
			}
		})
	}
}

func TestHealthySlotWatchdogRejectsArbitraryRecoveryPaths(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(rt.currentLink); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }
	if _, err := rt.recoverExpiredHostSelfUpdate(
		context.Background(),
		filepath.Join("..", HostSelfUpdateSlotA),
	); err == nil || !strings.Contains(err.Error(), "slot is invalid") {
		t.Fatalf("arbitrary recovery path err=%v", err)
	}
	if _, err := os.Lstat(rt.currentLink); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected recovery path mutated current: %v", err)
	}
	if runner.restarts != 0 {
		t.Fatalf("rejected recovery path restarted agent %d times", runner.restarts)
	}
}

func TestExpiredActivationAtHealthySlotCannotLoopSwitchCurrent(t *testing.T) {
	rootNow := time.Date(2026, 7, 28, 8, 9, 10, 0, time.UTC)
	rt, runner := newHostSelfUpdateRecoveryFixture(
		t,
		HostSelfUpdateSlotA,
		"v1.7.8",
		rootNow,
	)
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	request := validHostSelfUpdateRequest()
	state = stageHostSelfUpdateStateForLinuxTest(
		t, rt, runner, state, request,
	)
	state, err = BeginHostSelfUpdateActivation(state, rootNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	rt.now = func() time.Time { return rootNow.Add(2 * time.Minute) }
	status, err := rt.reconcile(
		context.Background(),
		HostSelfUpdateAgentProof{RunningAgentVersion: "v1.7.8"},
	)
	if err != nil {
		t.Fatalf("expired healthy activation: %v", err)
	}
	if status.State.Phase != HostSelfUpdatePhaseRollingBack ||
		status.State.FailedGeneration != request.Generation ||
		status.LastAction != HostSelfUpdateActionRestartHealthy ||
		status.CurrentSlot != HostSelfUpdateSlotA ||
		runner.restarts != 1 {
		t.Fatalf("expired activation retried candidate switch: %#v restarts=%d", status, runner.restarts)
	}
}

func stageHostSelfUpdateStateForLinuxTest(
	t *testing.T,
	rt hostSelfUpdateExecutorRuntime,
	runner *hostSelfUpdateExecutorTestRunner,
	state HostSelfUpdateState,
	request HostSelfUpdateRequest,
) HostSelfUpdateState {
	t.Helper()
	artifactRoot := t.TempDir()
	binRoot := filepath.Join(artifactRoot, "bin")
	if err := os.MkdirAll(binRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		if err := os.WriteFile(
			filepath.Join(binRoot, binary),
			[]byte(binary+" "+request.Generation+"\n"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}
	digests, err := hostSelfUpdateArtifactBinaryDigests(artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	pendingSlot := otherHostSelfUpdateSlot(state.ActiveSlot)
	temporaryRoot := filepath.Join(
		rt.slotsRoot,
		"."+pendingSlot+"-"+shortID(request.Generation)+".new",
	)
	finalRoot := filepath.Join(rt.slotsRoot, pendingSlot)
	for _, root := range []string{temporaryRoot, finalRoot} {
		runner.registerBinaryIdentity(
			filepath.Join(root, "bin", "autostream-host-agent"),
			hostSelfUpdateExecutorTestBinaryIdentity{
				version:          request.AgentVersion,
				commit:           request.Commit,
				mutationProtocol: request.MutationProtocolVersion,
				recoveryProtocol: request.RecoveryProtocolVersion,
			},
		)
		runner.registerBinaryIdentity(
			filepath.Join(root, "bin", "autostream-local-executor"),
			hostSelfUpdateExecutorTestBinaryIdentity{
				version:          request.ExecutorVersion,
				commit:           request.Commit,
				mutationProtocol: request.MutationProtocolVersion,
				recoveryProtocol: request.RecoveryProtocolVersion,
			},
		)
	}
	if err := rt.stageSlot(
		context.Background(),
		pendingSlot,
		artifactRoot,
		request,
		digests,
	); err != nil {
		t.Fatalf("stage production-shaped host self-update slot: %v", err)
	}
	next, err := StageHostSelfUpdate(
		state,
		request,
		HostLifecycleBlockers{},
		digests,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.saveState(next); err != nil {
		t.Fatalf("persist staged production-shaped host self-update state: %v", err)
	}
	if err := rt.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		t.Fatalf("finalize staged production-shaped host self-update slot: %v", err)
	}
	return next
}

func newHostSelfUpdateRecoveryFixture(
	t *testing.T,
	currentSlot string,
	executorVersion string,
	now time.Time,
) (hostSelfUpdateExecutorRuntime, *hostSelfUpdateExecutorTestRunner) {
	t.Helper()
	root := t.TempDir()
	installRoot := filepath.Join(root, "host-agent")
	slotsRoot := filepath.Join(installRoot, "slots")
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if err := os.MkdirAll(filepath.Join(slotsRoot, slot, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"autostream-host-agent",
			"autostream-local-executor",
		} {
			if err := os.WriteFile(
				filepath.Join(slotsRoot, slot, "bin", name),
				[]byte("test "+name+"\n"),
				0o755,
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	currentLink := filepath.Join(installRoot, "current")
	if err := os.Symlink(
		filepath.Join("slots", currentSlot),
		currentLink,
	); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "state")
	runner := &hostSelfUpdateExecutorTestRunner{
		version:          executorVersion,
		commit:           strings.Repeat("a", 40),
		serviceActive:    true,
		socketActive:     true,
		mainPID:          "4242",
		mutationProtocol: LocalExecutorMutationProtocolVersion,
		recoveryProtocol: HostSelfUpdateRecoveryProtocolVersion,
	}
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		runner.registerBinaryIdentity(
			filepath.Join(
				slotsRoot,
				slot,
				"bin",
				"autostream-local-executor",
			),
			hostSelfUpdateExecutorTestBinaryIdentity{
				version:          executorVersion,
				commit:           strings.Repeat("a", 40),
				mutationProtocol: LocalExecutorMutationProtocolVersion,
				recoveryProtocol: HostSelfUpdateRecoveryProtocolVersion,
			},
		)
	}
	rt := hostSelfUpdateExecutorRuntime{
		installRoot:         installRoot,
		currentLink:         currentLink,
		slotsRoot:           slotsRoot,
		stateRoot:           stateRoot,
		statePath:           filepath.Join(stateRoot, "state.json"),
		downloadRoot:        filepath.Join(stateRoot, "downloads"),
		arch:                "amd64",
		executorVersion:     executorVersion,
		runner:              runner,
		downloader:          hostSelfUpdateExecutorTestDownloader{},
		now:                 func() time.Time { return now },
		verificationTimeout: defaultHostSelfUpdateVerificationTimeout,
		allowTestPaths:      true,
		waitExecutorStable:  func(context.Context) error { return nil },
	}
	runner.runningExe = filepath.Join(
		slotsRoot,
		currentSlot,
		"bin",
		"autostream-local-executor",
	)
	rt.resolveProcessExe = func(int) (string, error) {
		if runner.runningExe == "" {
			return "", errors.New("injected missing process executable")
		}
		return runner.runningExe, nil
	}
	rt.watchdogStatus = func(
		context.Context,
	) (HostSelfUpdateRuntimeStatus, error) {
		state, err := rt.loadPersistedState()
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		current, err := rt.readCurrentSlot()
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		return HostSelfUpdateRuntimeStatus{
			State:                   state,
			CurrentSlot:             current,
			ExecutorVersion:         rt.executorVersion,
			ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
			LastAction:              HostSelfUpdateActionNone,
		}, nil
	}
	if err := rt.prepare(); err != nil {
		t.Fatal(err)
	}
	return rt, runner
}
