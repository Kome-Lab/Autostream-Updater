package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDockerPortTransactionAppliesAndReplaysTerminalResult(t *testing.T) {
	harness := newDockerPortHarness(t)
	response := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if response.PortResult == nil ||
		response.PortResult.Result != systemdPortResultApplied ||
		response.PortResult.Docker == nil ||
		response.PortResult.Docker.AppliedPublishedPort !=
			harness.plan.Docker.NewPublishedPort ||
		response.PortResult.Docker.AppliedContainerPort !=
			harness.plan.Docker.NewContainerPort {
		t.Fatalf("response=%+v", response)
	}
	if harness.runtime.consumeCalls != 1 ||
		harness.runtime.writeCalls != 1 ||
		harness.runtime.recreateCalls != 1 {
		t.Fatalf(
			"calls consume=%d write=%d recreate=%d",
			harness.runtime.consumeCalls,
			harness.runtime.writeCalls,
			harness.runtime.recreateCalls,
		)
	}
	applied, err := harness.state.LoadDockerApplied(harness.plan.TargetID)
	if err != nil || applied == nil ||
		applied.PublishedPort != harness.plan.Docker.NewPublishedPort ||
		applied.ContainerPort != harness.plan.Docker.NewContainerPort ||
		applied.ConfigRevision != harness.plan.TargetConfigRevision {
		t.Fatalf("applied=%+v err=%v", applied, err)
	}

	replayed := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if replayed.PortResult == nil ||
		replayed.PortResult.Result != systemdPortResultApplied ||
		harness.runtime.consumeCalls != 1 ||
		harness.runtime.writeCalls != 1 ||
		harness.runtime.recreateCalls != 1 {
		t.Fatalf("replayed=%+v runtime=%+v", replayed, harness.runtime)
	}
}

func TestDockerPortTransactionRollsBackFailedRecreate(t *testing.T) {
	harness := newDockerPortHarness(t)
	harness.runtime.failTargetRecreate = true
	response := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if response.PortResult == nil ||
		response.PortResult.Result != systemdPortResultRolledBack ||
		response.PortResult.Docker == nil ||
		response.PortResult.Docker.AppliedPublishedPort !=
			harness.plan.Docker.OldPublishedPort ||
		!bytes.Equal(harness.runtime.current, harness.runtime.oldBytes) ||
		harness.runtime.onTarget {
		t.Fatalf("response=%+v runtime=%+v", response, harness.runtime)
	}
}

func TestDockerPortPostGrantStagedDriftCommitsVerifiedUnchangedState(t *testing.T) {
	harness := newDockerPortHarness(t)
	harness.runtime.driftPreparedAfterGrant = true
	response := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if response.PortResult == nil ||
		response.PortResult.Result != systemdPortResultUnchanged ||
		response.PortResult.EndpointRevision !=
			harness.plan.TargetEndpointRevision+1 ||
		harness.runtime.writeCalls != 0 ||
		harness.runtime.recreateCalls != 0 ||
		!bytes.Equal(harness.runtime.current, harness.runtime.oldBytes) {
		t.Fatalf("response=%+v runtime=%+v", response, harness.runtime)
	}
}

func TestDockerPortAmbiguousRecreateReconcilesWithoutSecondGrant(t *testing.T) {
	harness := newDockerPortHarness(t)
	harness.runtime.crashAt = "after_docker_recreate"
	first := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if first.Error == nil || first.Error.Code != "reconcile_required" {
		t.Fatalf("first=%+v", first)
	}
	harness.runtime.crashAt = ""
	reconciled := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure_reconcile"),
		harness.runtime,
		harness.state,
	)
	if reconciled.PortResult == nil ||
		reconciled.PortResult.Result != systemdPortResultApplied ||
		harness.runtime.consumeCalls != 1 ||
		harness.runtime.writeCalls != 1 ||
		harness.runtime.recreateCalls != 1 {
		t.Fatalf("reconciled=%+v runtime=%+v", reconciled, harness.runtime)
	}
}

func TestDockerPortReconcileAcceptsTargetSidecarAfterProcessRestart(t *testing.T) {
	harness := newDockerPortHarness(t)
	policySHA256, err := harness.policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.state.SaveApplied(dockerPortAppliedState{
		SchemaVersion:          1,
		TargetID:               harness.plan.TargetID,
		ServiceType:            harness.plan.ServiceType,
		PublishedPort:          harness.plan.Docker.OldPublishedPort,
		ContainerPort:          harness.plan.Docker.OldContainerPort,
		HealthPort:             harness.plan.Docker.OldHealthPort,
		EndpointRevision:       harness.plan.ExpectedEndpointRevision,
		ConfigRevision:         harness.plan.ExpectedConfigRevision,
		ConfigSHA256:           harness.plan.ExpectedConfigSHA256,
		ComposeConfigSHA256:    harness.runtime.oldComposeSHA256,
		SourcePolicyRevision:   harness.plan.ExpectedSourcePolicyRevision,
		UpdaterPolicyRevision:  harness.plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision: harness.plan.ExpectedExecutorPolicyRevision,
		ExecutorPolicySHA256:   policySHA256,
		OwnershipEpoch:         harness.plan.OwnershipEpoch,
	}); err != nil {
		t.Fatal(err)
	}
	state := &dockerPortSidecarCheckingState{
		dockerPortStateStore: harness.state,
		runtime:              harness.runtime,
	}
	harness.state = state
	harness.runtime.crashAt = "after_docker_recreate"
	first := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if first.Error == nil || first.Error.Code != "reconcile_required" {
		t.Fatalf("first=%+v", first)
	}
	if !harness.runtime.onTarget {
		t.Fatal("simulated process interruption did not leave the target sidecar active")
	}

	harness.runtime.crashAt = ""
	reconciled := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure_reconcile"),
		harness.runtime,
		harness.state,
	)
	if reconciled.PortResult == nil ||
		reconciled.PortResult.Result != systemdPortResultApplied ||
		harness.runtime.consumeCalls != 1 ||
		state.verifyCalls != 1 {
		t.Fatalf(
			"reconciled=%+v runtime=%+v sidecar_verifications=%d",
			reconciled, harness.runtime, state.verifyCalls,
		)
	}
}

func TestDockerPortCommitRepairsCrashAfterAppliedStateSave(t *testing.T) {
	harness := newDockerPortCommittingHarness(t)
	applied, err := harness.state.LoadDockerApplied(harness.plan.TargetID)
	if err != nil || applied == nil ||
		applied.PublishedPort != harness.plan.Docker.NewPublishedPort ||
		applied.ContainerPort != harness.plan.Docker.NewContainerPort ||
		applied.EndpointRevision != harness.plan.TargetEndpointRevision {
		t.Fatalf("applied=%+v err=%v", applied, err)
	}

	restarted := restartedFakeDockerPortRuntime(harness.runtime)
	reconciled := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure_reconcile"),
		restarted,
		harness.state,
	)
	if reconciled.PortResult == nil ||
		reconciled.PortResult.Result != systemdPortResultApplied ||
		restarted.consumeCalls != 1 ||
		len(restarted.consumeOperations) != 1 ||
		restarted.consumeOperations[0] != "port_reconfigure_reconcile" ||
		restarted.writeCalls != 0 ||
		restarted.restoreCalls != 0 ||
		restarted.recreateCalls != 0 {
		t.Fatalf("reconciled=%+v restarted=%+v", reconciled, restarted)
	}
	ledger, err := harness.state.LoadJob(
		harness.plan.TargetID, harness.plan.JobID,
	)
	if err != nil || ledger == nil ||
		ledger.State != dockerPortLedgerTerminal {
		t.Fatalf("repaired ledger=%+v err=%v", ledger, err)
	}

	replayed := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure_reconcile"),
		restarted,
		harness.state,
	)
	if replayed.PortResult == nil ||
		replayed.PortResult.Result != systemdPortResultApplied ||
		restarted.consumeCalls != 1 {
		t.Fatalf("replayed=%+v restarted=%+v", replayed, restarted)
	}
}

func TestDockerPortCommitRepairFailsClosedBeforeGrantWithoutExactObservation(
	t *testing.T,
) {
	cases := map[string]func(*fakeDockerPortRuntime){
		"missing": func(runtime *fakeDockerPortRuntime) {
			runtime.observeErr = errors.New("Docker runtime unavailable")
		},
		"wrong": func(runtime *fakeDockerPortRuntime) {
			runtime.repositoryDigest = "sha256:" + strings.Repeat("9", 64)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			harness := newDockerPortCommittingHarness(t)
			restarted := restartedFakeDockerPortRuntime(harness.runtime)
			mutate(restarted)
			response := executeDockerPortRequest(
				context.Background(),
				harness.policy,
				harness.request("port_reconfigure_reconcile"),
				restarted,
				harness.state,
			)
			if response.Error == nil ||
				response.Error.Code != "reconcile_required" ||
				restarted.consumeCalls != 0 ||
				restarted.writeCalls != 0 ||
				restarted.restoreCalls != 0 ||
				restarted.recreateCalls != 0 {
				t.Fatalf("response=%+v restarted=%+v", response, restarted)
			}
			ledger, err := harness.state.LoadJob(
				harness.plan.TargetID, harness.plan.JobID,
			)
			if err != nil || ledger == nil ||
				ledger.State != dockerPortLedgerCommitting {
				t.Fatalf("commit ledger=%+v err=%v", ledger, err)
			}
		})
	}
}

func TestDockerPortTransactionSupportsSecondSequentialChangeFromAppliedOverlay(t *testing.T) {
	harness := newDockerPortHarness(t)
	first := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if first.PortResult == nil ||
		first.PortResult.Result != systemdPortResultApplied {
		t.Fatalf("first=%+v", first)
	}

	secondBytes, err := dockerPortEnvBytes(
		harness.runtime.adapter, 19084, 19080, 13,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondPlan := harness.plan
	secondPlan.JobID = "job-docker-port-two"
	secondPlan.OldPort = harness.plan.NewPort
	secondPlan.NewPort = 19084
	secondPlan.ExpectedEndpointRevision = harness.plan.TargetEndpointRevision
	secondPlan.TargetEndpointRevision++
	secondPlan.ExpectedConfigRevision = harness.plan.TargetConfigRevision
	secondPlan.TargetConfigRevision++
	secondPlan.ExpectedConfigSHA256 = harness.plan.TargetConfigSHA256
	secondPlan.TargetConfigSHA256 = dockerPortEnvSHA256(secondBytes)
	secondPlan.SessionID = "docker-port-session-9876543210"
	secondDocker := *harness.plan.Docker
	secondDocker.OldPublishedPort = harness.plan.Docker.NewPublishedPort
	secondDocker.NewPublishedPort = 19084
	secondDocker.OldContainerPort = harness.plan.Docker.NewContainerPort
	secondDocker.NewContainerPort = 19080
	secondDocker.OldHealthPort = harness.plan.Docker.NewHealthPort
	secondDocker.NewHealthPort = 19084
	secondDocker.ExpectedContainerID = harness.runtime.targetContainerID
	secondPlan.Docker = &secondDocker
	secondPlan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, secondPlan)

	harness.runtime.oldBytes = append(
		[]byte(nil), harness.runtime.targetBytes...,
	)
	harness.runtime.targetBytes = secondBytes
	harness.runtime.oldComposeSHA256 = harness.runtime.targetComposeSHA256
	harness.runtime.targetComposeSHA256 = strings.Repeat("4", 64)
	harness.runtime.oldContainerID = harness.runtime.targetContainerID
	harness.runtime.targetContainerID = strings.Repeat("3", 64)
	harness.runtime.onTarget = false
	secondRequest := LocalExecutorRequest{
		Version:                 LocalExecutorMutationProtocolVersion,
		Operation:               "port_reconfigure",
		ServiceID:               secondPlan.TargetID,
		PortPlan:                &secondPlan,
		SourcePolicyRevision:    secondPlan.ExpectedSourcePolicyRevision,
		OwnershipEpoch:          secondPlan.OwnershipEpoch,
		OwnershipPolicyRevision: secondPlan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision:  secondPlan.ExpectedExecutorPolicyRevision,
		MutationGrant:           NewBoundedSecret("second-one-time-grant"),
	}
	second := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		secondRequest,
		harness.runtime,
		harness.state,
	)
	if second.PortResult == nil ||
		second.PortResult.Result != systemdPortResultApplied ||
		second.PortResult.AppliedPort != secondPlan.NewPort ||
		second.PortResult.Docker == nil ||
		second.PortResult.Docker.AppliedPublishedPort !=
			secondPlan.Docker.NewPublishedPort ||
		second.PortResult.Docker.AppliedContainerPort !=
			secondPlan.Docker.NewContainerPort {
		t.Fatalf("second=%+v", second)
	}
	applied, err := harness.state.LoadDockerApplied(secondPlan.TargetID)
	if err != nil ||
		applied == nil ||
		applied.EndpointRevision != secondPlan.TargetEndpointRevision ||
		applied.ConfigRevision != secondPlan.TargetConfigRevision ||
		applied.PublishedPort != secondPlan.Docker.NewPublishedPort ||
		applied.ContainerPort != secondPlan.Docker.NewContainerPort {
		t.Fatalf("applied=%+v err=%v", applied, err)
	}
	if harness.policy.Targets[0].EndpointRevision !=
		harness.plan.ExpectedEndpointRevision ||
		harness.policy.Targets[0].ConfigRevision !=
			harness.plan.ExpectedConfigRevision {
		t.Fatal("test did not preserve the stale root policy across both changes")
	}
}

func TestDockerPortAppliedStateRejectsUnboundLineageAndRevisionReuse(t *testing.T) {
	harness := newDockerPortHarness(t)
	policySHA256, err := harness.policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	applied := func() dockerPortAppliedState {
		return dockerPortAppliedState{
			SchemaVersion:          1,
			TargetID:               harness.plan.TargetID,
			ServiceType:            harness.plan.ServiceType,
			PublishedPort:          harness.plan.Docker.NewPublishedPort,
			ContainerPort:          harness.plan.Docker.NewContainerPort,
			HealthPort:             harness.plan.Docker.NewHealthPort,
			EndpointRevision:       harness.plan.TargetEndpointRevision,
			ConfigRevision:         harness.plan.TargetConfigRevision,
			ConfigSHA256:           harness.plan.TargetConfigSHA256,
			ComposeConfigSHA256:    harness.runtime.targetComposeSHA256,
			SourcePolicyRevision:   harness.plan.ExpectedSourcePolicyRevision,
			UpdaterPolicyRevision:  harness.plan.ExpectedUpdaterPolicyRevision,
			ExecutorPolicyRevision: harness.plan.ExpectedExecutorPolicyRevision,
			ExecutorPolicySHA256:   policySHA256,
			OwnershipEpoch:         harness.plan.OwnershipEpoch,
		}
	}
	cases := map[string]dockerPortAppliedState{
		"source policy lineage is stale": func() dockerPortAppliedState {
			state := applied()
			state.SourcePolicyRevision--
			return state
		}(),
		"projection policy lineage is stale": func() dockerPortAppliedState {
			state := applied()
			state.UpdaterPolicyRevision--
			return state
		}(),
		"executor policy digest is stale": func() dockerPortAppliedState {
			state := applied()
			state.ExecutorPolicySHA256 =
				"sha256:" + strings.Repeat("9", 64)
			return state
		}(),
		"endpoint revision is reused": func() dockerPortAppliedState {
			state := applied()
			state.EndpointRevision =
				harness.policy.Targets[0].EndpointRevision
			return state
		}(),
		"config revision is reused": func() dockerPortAppliedState {
			state := applied()
			state.ConfigRevision =
				harness.policy.Targets[0].ConfigRevision
			body, err := dockerPortEnvBytes(
				harness.runtime.adapter,
				state.PublishedPort,
				state.ContainerPort,
				state.ConfigRevision,
			)
			if err != nil {
				t.Fatal(err)
			}
			state.ConfigSHA256 = dockerPortEnvSHA256(body)
			return state
		}(),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			state := newMemoryDockerPortStateStore()
			if err := state.SaveApplied(candidate); err != nil {
				t.Fatal(err)
			}
			if _, err := resolveDockerPortAppliedTarget(
				harness.policy, harness.policy.Targets[0], state,
			); err == nil {
				t.Fatalf("unbound applied state was accepted: %+v", candidate)
			}
		})
	}
}

type dockerPortHarness struct {
	policy  LocalExecutorPolicy
	plan    SystemdPortReconfigurePlan
	runtime *fakeDockerPortRuntime
	state   dockerPortStateStore
}

type dockerPortSidecarCheckingState struct {
	dockerPortStateStore
	runtime     *fakeDockerPortRuntime
	verifyCalls int
}

func (s *dockerPortSidecarCheckingState) VerifyAppliedDockerSidecar(
	LocalExecutorTarget,
	dockerPortAppliedState,
) error {
	s.verifyCalls++
	if s.runtime.onTarget {
		return errors.New("applied overlay sidecar has advanced to target bytes")
	}
	return nil
}

func newDockerPortCommittingHarness(t *testing.T) dockerPortHarness {
	t.Helper()
	harness := newDockerPortHarness(t)
	harness.runtime.crashAt = "after_applied_state_save"
	response := executeDockerPortRequest(
		context.Background(),
		harness.policy,
		harness.request("port_reconfigure"),
		harness.runtime,
		harness.state,
	)
	if response.Error == nil ||
		response.Error.Code != "reconcile_required" ||
		harness.runtime.consumeCalls != 1 ||
		len(harness.runtime.consumeOperations) != 1 ||
		harness.runtime.consumeOperations[0] != "port_reconfigure" {
		t.Fatalf("interrupted commit response=%+v runtime=%+v", response, harness.runtime)
	}
	ledger, err := harness.state.LoadJob(
		harness.plan.TargetID, harness.plan.JobID,
	)
	if err != nil || ledger == nil ||
		ledger.State != dockerPortLedgerCommitting ||
		ledger.Result == nil ||
		ledger.Result.Result != systemdPortResultApplied {
		t.Fatalf("commit ledger=%+v err=%v", ledger, err)
	}
	return harness
}

func restartedFakeDockerPortRuntime(
	source *fakeDockerPortRuntime,
) *fakeDockerPortRuntime {
	restarted := *source
	restarted.current = append([]byte(nil), source.current...)
	restarted.crashAt = ""
	restarted.observeErr = nil
	restarted.consumeCalls = 0
	restarted.consumeOperations = nil
	restarted.writeCalls = 0
	restarted.restoreCalls = 0
	restarted.recreateCalls = 0
	return &restarted
}

func newDockerPortHarness(t *testing.T) dockerPortHarness {
	t.Helper()
	adapterTarget := validLocalDockerTarget(t)
	adapterTarget.PortEnvFile =
		"/opt/autostream/local-executor/docker/ports/worker.env"
	adapterTarget.PortComposePolicySHA256 = strings.Repeat("b", 64)
	adapterTarget.PortComposeRevision = 8
	adapterTarget.ComposeConfigSHA256 = strings.Repeat("a", 64)
	adapter, err := dockerPortAdapterFor("worker", &adapterTarget)
	if err != nil {
		t.Fatal(err)
	}
	oldBytes, err := dockerPortEnvBytes(adapter, 8084, 8080, 11)
	if err != nil {
		t.Fatal(err)
	}
	targetBytes, err := dockerPortEnvBytes(adapter, 18084, 18080, 12)
	if err != nil {
		t.Fatal(err)
	}
	policy := LocalExecutorPolicy{
		SchemaVersion:   LocalExecutorMutationPolicySchemaVersion,
		ProtocolVersion: LocalExecutorMutationProtocolVersion,
		HostID:          "host-a", AgentUID: 1001, AgentGID: 1001,
		SocketPath:           LocalExecutorSocketPath,
		SourcePolicyRevision: 6, ProjectionRevision: 7, PolicyRevision: 8,
		Mutation: &LocalExecutorMutationPolicy{
			PanelURL: "https://panel.example.com",
		},
		Targets: []LocalExecutorTarget{{
			ServiceID: "worker-01", ServiceType: "worker",
			DeploymentMode:   ModeDocker,
			EndpointRevision: 4, ConfigRevision: 11,
			ConfigSHA256: dockerPortEnvSHA256(oldBytes),
			LocalListen: LocalExecutorEndpoint{
				Host: "127.0.0.1", Port: 8084,
			},
			Docker: &adapterTarget,
		}},
	}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	policySHA256, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	plan := SystemdPortReconfigurePlan{
		DeploymentMode: ModeDocker,
		JobID:          "job-docker-port-one", HostID: policy.HostID,
		TargetID: "worker-01", ServiceType: "worker",
		NetworkNamespace: systemdPortNetworkNamespaceHost,
		Protocol:         systemdPortProtocolTCP,
		OldPort:          8084, NewPort: 18084,
		ExpectedEndpointRevision: 4, TargetEndpointRevision: 5,
		ExpectedConfigRevision: 11, TargetConfigRevision: 12,
		ExpectedConfigSHA256:           dockerPortEnvSHA256(oldBytes),
		TargetConfigSHA256:             dockerPortEnvSHA256(targetBytes),
		ExpectedSourcePolicyRevision:   6,
		ExpectedUpdaterPolicyRevision:  7,
		ExpectedExecutorPolicyRevision: 8,
		ExpectedExecutorPolicySHA256:   policySHA256,
		OwnershipEpoch:                 3, LeaseGeneration: 2,
		SessionID: "docker-port-session-0123456789",
		Docker: &DockerPortMutationGrantBinding{
			PublishedHostIP:  "127.0.0.1",
			OldPublishedPort: 8084, NewPublishedPort: 18084,
			OldContainerPort: 8080, NewContainerPort: 18080,
			OldHealthPort: 8084, NewHealthPort: 18084,
			ApprovedComposeConfigSHA256: strings.Repeat("b", 64),
			ApprovedComposeRevision:     8,
			ExpectedVersionEnvSHA256:    "sha256:" + strings.Repeat("f", 64),
			ExpectedContainerID:         strings.Repeat("1", 64),
			ExpectedImageID:             "sha256:" + strings.Repeat("d", 64),
			ExpectedRepositoryDigest:    "sha256:" + strings.Repeat("e", 64),
		},
	}
	plan.PortPlanSHA256 = mustSystemdPortPlanSHA256(t, plan)
	runtime := &fakeDockerPortRuntime{
		adapter: adapter, oldBytes: oldBytes, targetBytes: targetBytes,
		current:             append([]byte(nil), oldBytes...),
		oldComposeSHA256:    strings.Repeat("a", 64),
		targetComposeSHA256: strings.Repeat("c", 64),
		policySHA256:        strings.Repeat("b", 64),
		versionEnvSHA256:    "sha256:" + strings.Repeat("f", 64),
		oldContainerID:      strings.Repeat("1", 64),
		targetContainerID:   strings.Repeat("2", 64),
		imageID:             "sha256:" + strings.Repeat("d", 64),
		repositoryDigest:    "sha256:" + strings.Repeat("e", 64),
		currentVersion:      "v1.2.3",
	}
	return dockerPortHarness{
		policy:  policy,
		plan:    plan,
		runtime: runtime,
		state:   newMemoryDockerPortStateStore(),
	}
}

func (h dockerPortHarness) request(operation string) LocalExecutorRequest {
	return LocalExecutorRequest{
		Version:                 LocalExecutorMutationProtocolVersion,
		Operation:               operation,
		ServiceID:               h.plan.TargetID,
		PortPlan:                &h.plan,
		SourcePolicyRevision:    h.plan.ExpectedSourcePolicyRevision,
		OwnershipEpoch:          h.plan.OwnershipEpoch,
		OwnershipPolicyRevision: h.plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision:  h.plan.ExpectedExecutorPolicyRevision,
		MutationGrant:           NewBoundedSecret("one-time-mutation-grant"),
	}
}

type fakeDockerPortRuntime struct {
	adapter                 dockerPortAdapter
	oldBytes                []byte
	targetBytes             []byte
	current                 []byte
	oldComposeSHA256        string
	targetComposeSHA256     string
	policySHA256            string
	versionEnvSHA256        string
	oldContainerID          string
	targetContainerID       string
	imageID                 string
	repositoryDigest        string
	currentVersion          string
	onTarget                bool
	failTargetRecreate      bool
	driftPreparedAfterGrant bool
	crashAt                 string
	observeErr              error
	consumeCalls            int
	consumeOperations       []string
	writeCalls              int
	restoreCalls            int
	recreateCalls           int
}

func (f *fakeDockerPortRuntime) Observe(
	_ context.Context,
	_ LocalExecutorPolicy,
	target LocalExecutorTarget,
) (dockerPortObservation, error) {
	if f.observeErr != nil {
		return dockerPortObservation{}, f.observeErr
	}
	expectedBytes := f.oldBytes
	composeSHA256 := f.oldComposeSHA256
	containerID := f.oldContainerID
	if f.onTarget {
		expectedBytes = f.targetBytes
		composeSHA256 = f.targetComposeSHA256
		containerID = f.targetContainerID
	}
	if !bytes.Equal(f.current, expectedBytes) ||
		target.ConfigSHA256 != dockerPortEnvSHA256(expectedBytes) ||
		target.Docker == nil ||
		target.Docker.ComposeConfigSHA256 != composeSHA256 {
		return dockerPortObservation{}, errors.New("target does not match fake runtime")
	}
	publishedPort, containerPort, configRevision, err := parseDockerPortEnv(
		f.adapter, expectedBytes,
	)
	if err != nil {
		return dockerPortObservation{}, err
	}
	return dockerPortObservation{
		MappingEnv: newDockerPortMappingCheckpoint(
			true, 0o600, expectedBytes,
		),
		PublishedHostIP:     "127.0.0.1",
		PublishedPort:       publishedPort,
		ContainerPort:       containerPort,
		HealthPort:          publishedPort,
		ConfigRevision:      configRevision,
		ConfigSHA256:        dockerPortEnvSHA256(expectedBytes),
		ComposePolicySHA256: f.policySHA256,
		ComposeConfigSHA256: composeSHA256,
		Runtime: dockerPortRuntimeBaseline{
			VersionEnvSHA256: f.versionEnvSHA256,
			ContainerID:      containerID,
			ImageID:          f.imageID,
			RepositoryDigest: f.repositoryDigest,
			CurrentVersion:   f.currentVersion,
		},
	}, nil
}

func (f *fakeDockerPortRuntime) Prepare(
	_ context.Context,
	_ LocalExecutorTarget,
	targetBytes []byte,
) (dockerPortPreparedModel, error) {
	publishedPort, containerPort, _, err := parseDockerPortEnv(
		f.adapter, targetBytes,
	)
	if err != nil {
		return dockerPortPreparedModel{}, err
	}
	composeSHA256 := f.targetComposeSHA256
	if f.driftPreparedAfterGrant && f.consumeCalls > 0 {
		composeSHA256 = strings.Repeat("9", 64)
	}
	return dockerPortPreparedModel{
		ComposePolicySHA256: f.policySHA256,
		ComposeConfigSHA256: composeSHA256,
		PublishedHostIP:     "127.0.0.1",
		PublishedPort:       publishedPort,
		ContainerPort:       containerPort,
		HealthPort:          publishedPort,
	}, nil
}

func (*fakeDockerPortRuntime) EnsureAvailable(
	context.Context,
	LocalExecutorTarget,
	dockerPortPreparedModel,
	string,
) error {
	return nil
}

func (f *fakeDockerPortRuntime) ConsumeGrant(
	_ context.Context,
	_ SystemdPortReconfigurePlan,
	operation string,
	_ string,
	_ BoundedSecret,
) error {
	f.consumeCalls++
	f.consumeOperations = append(f.consumeOperations, operation)
	return nil
}

func (f *fakeDockerPortRuntime) Write(
	checkpoint dockerPortMappingCheckpoint,
	body []byte,
) error {
	f.writeCalls++
	if !bytes.Equal(f.current, checkpoint.Bytes) ||
		!bytes.Equal(body, f.targetBytes) {
		return errors.New("fake write mismatch")
	}
	f.current = append([]byte(nil), body...)
	return nil
}

func (f *fakeDockerPortRuntime) Restore(
	checkpoint dockerPortMappingCheckpoint,
	targetBytes []byte,
) error {
	f.restoreCalls++
	if !bytes.Equal(f.current, targetBytes) {
		return errors.New("fake restore mismatch")
	}
	f.current = append([]byte(nil), checkpoint.Bytes...)
	return nil
}

func (f *fakeDockerPortRuntime) Recreate(
	_ context.Context,
	_ LocalExecutorTarget,
	prepared dockerPortPreparedModel,
) error {
	f.recreateCalls++
	targetSide := prepared.ComposeConfigSHA256 == f.targetComposeSHA256
	if targetSide && f.failTargetRecreate {
		f.failTargetRecreate = false
		return errors.New("fake target recreate failed")
	}
	f.onTarget = targetSide
	return nil
}

func (f *fakeDockerPortRuntime) CrashPoint(point string) error {
	if point == f.crashAt {
		return errSystemdPortSimulatedCrash
	}
	return nil
}
