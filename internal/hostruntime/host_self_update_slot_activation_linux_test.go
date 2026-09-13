//go:build linux

package hostruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
