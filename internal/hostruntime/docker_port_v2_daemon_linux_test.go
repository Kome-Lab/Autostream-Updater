//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

// This extends the existing disposable real-daemon fixture. Its root grant
// endpoint is a binding-checking stub; CP and Agent process integration remain
// distinct from the actual root policy/Compose/listener boundaries below.
func runSTPortDockerDaemonSequence(t *testing.T, runner *dockerPortSmokeRunner, base OSCommandRunner, stateDir, captureDir string,
	policy LocalExecutorPolicy, current dockerPortSmokeState, imageID, repositoryDigest, versionEnvSHA256 string) dockerPortSmokeState {
	t.Helper()
	state, err := newFileDockerPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := state.LoadDockerApplied(policy.Targets[0].ServiceID)
	if err != nil || applied == nil {
		t.Fatal("legacy fixture did not leave a verified baseline", err)
	}
	// Model the existing configure/install adoption of the already verified
	// legacy baseline. Subsequent changes use only the production v2 delta.
	target := &policy.Targets[0]
	target.EndpointRevision, target.ConfigRevision, target.ConfigSHA256 = current.endpointRevision, current.configRevision, current.configSHA256
	target.LocalListen.Port = current.publishedPort
	docker := *target.Docker
	docker.ComposeConfigSHA256 = applied.ComposeConfigSHA256
	target.Docker = &docker
	root, err := json.Marshal(policy)
	if err != nil || writeAtomicFile(dockerPortSmokePolicyPath, root, 0o600) != nil {
		t.Fatal("write exact installed fixture baseline", err)
	}
	adapter, err := dockerPortAdapterFor("worker", target.Docker)
	if err != nil {
		t.Fatal(err)
	}
	planFor := func(mode contracts.SystemUpdatePortMode, advertised, published, container int, jobID string) SystemdPortReconfigurePlan {
		loaded, err := LoadLocalExecutorPolicy(dockerPortSmokePolicyPath, true)
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := resolveDockerPortAppliedTarget(loaded, loaded.Targets[0], state)
		if err != nil {
			t.Fatal("resolve actual Docker baseline", err)
		}
		return stPortDockerDaemonPlan(t, loaded, current, mode, advertised, published, container, jobID,
			dockerPortSmokeContainerID(t, base), imageID, repositoryDigest, versionEnvSHA256, resolved.Docker.ComposeConfigSHA256)
	}
	assertResult := func(step string, response LocalExecutorResponse, plan SystemdPortReconfigurePlan, kind string, consumed int) dockerPortSmokeState {
		t.Helper()
		if response.Validate() != nil || response.PortResult == nil || response.PortResult.PortResult == nil || response.PortResult.Result != kind ||
			!portV2AcceptedResultMatchesPlan(plan, *response.PortResult) {
			runner.logSTPortResultFailure(t, step, response, plan, kind, consumed)
			t.Fatal("versioned real Docker result is unverified; see bounded result evidence")
		}
		ref := portV2ResultSnapshot(plan, kind)
		manager, err := newFilePortPolicyStore(dockerPortSmokePolicyPath, true)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := manager.Snapshot()
		if err != nil || !portPolicySnapshotMatches(loaded, loaded.Targets[0], *ref) {
			t.Fatal("real root policy does not match accepted snapshot", err)
		}
		payload, _ := json.Marshal(loaded)
		if manager.Verify(payload) != nil {
			t.Fatal("real root disk and loaded memory are not verified")
		}
		next := newDockerPortSmokeState(t, adapter, ref.AdvertisedPort, ref.Docker.PublishedPort, ref.Docker.ContainerPort, ref.AppliedEndpointRevision, ref.ConfigRevision)
		if next.configSHA256 != ref.ConfigSHA256 {
			t.Fatal("real Docker rollback/config digest does not match canonical bytes")
		}
		assertDockerPortSmokeDurableState(t, stateDir, adapter, next, plan)
		// Public endpoint changes belong to CP; this Node fixture's environment
		// deliberately keeps its unrelated public-port value at 443.
		waitForDockerPortFixture(t, next.publishedPort, 443, next.containerPort, next.configRevision, false)
		assertDockerPortFixtureBoundary(t, base, dockerPortSmokeContainerID(t, base), next.publishedPort, next.containerPort, filepath.Join(stateDir, "docker-listener-configs"))
		return next
	}
	noop := planFor(contracts.SystemUpdatePortModeLocalOnly, current.advertisedPort, current.publishedPort, current.containerPort, "job-st-port-noop")
	beforeID := dockerPortSmokeContainerID(t, base)
	runner.beginSTPortDiagnostic("noop", true)
	response, consumed := runSTPortDockerDaemonMutation(t, runner, stateDir, noop, "port_reconfigure")
	current = assertResult("noop", response, noop, systemdPortResultUnchanged, consumed)
	if consumed != 0 || dockerPortSmokeContainerID(t, base) != beforeID {
		t.Fatal("real Docker no-op consumed or recreated")
	}

	local := planFor(contracts.SystemUpdatePortModeLocalOnly, current.advertisedPort, 18083, current.containerPort, "job-st-port-local")
	runner.beginSTPortDiagnostic("local_only", true)
	response, consumed = runSTPortDockerDaemonMutation(t, runner, stateDir, local, "port_reconfigure")
	current = assertResult("local_only", response, local, systemdPortResultApplied, consumed)
	if consumed != 1 || current.advertisedPort != 443 || current.containerPort != local.Before.Docker.ContainerPort {
		t.Fatal("local-only real Docker changed unrelated endpoint or container port")
	}
	containerOnly := planFor(contracts.SystemUpdatePortModeLocalOnly, current.advertisedPort, current.publishedPort, 18080, "job-st-port-container-only")
	runner.beginSTPortDiagnostic("container_only", true)
	response, consumed = runSTPortDockerDaemonMutation(t, runner, stateDir, containerOnly, "port_reconfigure")
	current = assertResult("container_only", response, containerOnly, systemdPortResultApplied, consumed)
	if consumed != 1 || current.publishedPort != containerOnly.Before.Docker.PublishedPort || current.containerPort == containerOnly.Before.Docker.ContainerPort {
		t.Fatal("container-only change did not retain its existing published port")
	}

	// Independent jobs and alternating mappings exercise fresh child recovery
	// repeatedly without replacing a failed attempt with a replay of its result.
	for attempt := 0; attempt < 3; attempt++ {
		suffix := strconv.Itoa(attempt)
		combined := planFor(contracts.SystemUpdatePortModeLocalAndAdvertised, 8443, 18084+attempt%2, 19080+attempt%2, "job-st-port-combined-"+suffix)
		// The child owns its execution counters. Do not reuse the preceding
		// same-process trace or claim an unobserved consume count for recovery.
		runner.beginSTPortDiagnostic("combined_recovery", false)
		grantRecord := filepath.Join(stateDir, "st-port-crash-grant-"+suffix+".json")
		runDockerPortSmokeChild(t, dockerPortSmokeChildPayload{Plan: combined, Operation: "port_reconfigure", StateDir: stateDir,
			CaptureDir: captureDir, ImageID: imageID, RepositoryDigest: repositoryDigest, GrantRecordPath: grantRecord, ExpectGrant: true, CrashPhase: "after_target_verify"}, true)
		var consumedBinding contracts.UpdaterMutationGrantBinding
		readDockerPortSmokeJSON(t, grantRecord, &consumedBinding)
		if consumedBinding.Operation != contracts.UpdaterMutationPortReconfigure || consumedBinding.Lease.Command.MutationAuthorization.JobID != combined.JobID {
			t.Fatal("real versioned crash grant is not bound to the original job")
		}
		combined.LeaseGeneration++
		combined.SessionID = "st-port-daemon-restarted-session-0123456789"
		combined.PortPlanSHA256, _ = combined.ComputePortPlanSHA256()
		responsePath := filepath.Join(stateDir, "st-port-reconcile-response-"+suffix+".json")
		unconsumedPath := filepath.Join(stateDir, "st-port-reconcile-grant-"+suffix+".json")
		runDockerPortSmokeChild(t, dockerPortSmokeChildPayload{Plan: combined, Operation: "port_reconfigure_reconcile", StateDir: stateDir,
			CaptureDir: captureDir, ImageID: imageID, RepositoryDigest: repositoryDigest, ResponsePath: responsePath, GrantRecordPath: unconsumedPath}, false)
		readDockerPortSmokeJSON(t, responsePath, &response)
		current = assertResult("combined_recovery", response, combined, systemdPortResultApplied, -1)
		if pathExists(unconsumedPath) || current.advertisedPort != 8443 {
			t.Fatal("root restart repeated forward consume or lost combined snapshot")
		}
	}

	// after_restart alone does not prove T is observable. Preserve this earlier
	// crash boundary with an actually unhealthy T and require a fresh reconcile
	// grant plus exact R, rather than asserting a completed target unconditionally.
	interrupted := planFor(contracts.SystemUpdatePortModeLocalAndAdvertised, 9443, 18086, 21080, "job-st-port-unverified-recovery")
	forwardGrantPath := filepath.Join(stateDir, "st-port-unverified-forward-grant.json")
	runDockerPortSmokeChild(t, dockerPortSmokeChildPayload{Plan: interrupted, Operation: "port_reconfigure", StateDir: stateDir,
		CaptureDir: captureDir, ImageID: imageID, RepositoryDigest: repositoryDigest, GrantRecordPath: forwardGrantPath, ExpectGrant: true, CrashPhase: "after_restart"}, true)
	waitForDockerPortFixture(t, interrupted.Target.Docker.PublishedPort, 443, interrupted.Target.Docker.ContainerPort, interrupted.Target.ConfigRevision, true)
	interruptedLedger, err := state.LoadJob(interrupted.TargetID, interrupted.JobID)
	if err != nil || interruptedLedger == nil || interruptedLedger.PolicyTransition == nil || interruptedLedger.Result != nil || interruptedLedger.State != systemdPortLedgerRestarted ||
		!interruptedLedger.PolicyTransition.Consumed || interruptedLedger.PolicyTransition.RollbackLatched {
		t.Fatal("unverified target did not retain its interrupted forward state")
	}
	interrupted.LeaseGeneration++
	interrupted.SessionID = "st-port-daemon-rollback-session-0123456789"
	interrupted.PortPlanSHA256, _ = interrupted.ComputePortPlanSHA256()
	recoveryGrantPath := filepath.Join(stateDir, "st-port-unverified-reconcile-grant.json")
	recoveryResponsePath := filepath.Join(stateDir, "st-port-unverified-reconcile-response.json")
	runDockerPortSmokeChild(t, dockerPortSmokeChildPayload{Plan: interrupted, Operation: "port_reconfigure_reconcile", StateDir: stateDir,
		CaptureDir: captureDir, ImageID: imageID, RepositoryDigest: repositoryDigest, ResponsePath: recoveryResponsePath,
		GrantRecordPath: recoveryGrantPath, ExpectGrant: true}, false)
	var recoveryBinding contracts.UpdaterMutationGrantBinding
	readDockerPortSmokeJSON(t, recoveryGrantPath, &recoveryBinding)
	if recoveryBinding.Operation != contracts.UpdaterMutationOperation("port_reconfigure_reconcile") ||
		recoveryBinding.Lease.Command.MutationAuthorization.JobID != interrupted.JobID || recoveryBinding.Lease.LeaseGeneration != int64(interrupted.LeaseGeneration) {
		t.Fatal("unverified target recovery did not consume the exact new reconcile authority")
	}
	readDockerPortSmokeJSON(t, recoveryResponsePath, &response)
	current = assertResult("rollback", response, interrupted, systemdPortResultRolledBack, -1)
	if current.advertisedPort != interrupted.Before.AdvertisedPort || current.publishedPort != interrupted.Before.Docker.PublishedPort ||
		current.containerPort != interrupted.Before.Docker.ContainerPort || current.configRevision != interrupted.Before.ConfigRevision+2 {
		t.Fatal("unverified target recovery did not preserve B functional values with fresh R revisions")
	}

	unhealthy := planFor(contracts.SystemUpdatePortModeLocalAndAdvertised, 9443, 18086, 21080, "job-st-port-rollback")
	runner.beginSTPortDiagnostic("rollback", true)
	response, consumed = runSTPortDockerDaemonMutation(t, runner, stateDir, unhealthy, "port_reconfigure")
	current = assertResult("rollback", response, unhealthy, systemdPortResultRolledBack, consumed)
	if consumed != 1 || current.configRevision != unhealthy.Before.ConfigRevision+2 || current.advertisedPort != 8443 ||
		current.publishedPort != unhealthy.Before.Docker.PublishedPort || current.containerPort != unhealthy.Before.Docker.ContainerPort {
		t.Fatal("real rollback did not restore B functional values using C+2")
	}
	ledger, err := state.LoadJob(unhealthy.TargetID, unhealthy.JobID)
	if err != nil || bytes.Equal(ledger.Checkpoint.Bytes, ledger.PolicyTransition.RollbackRuntimeBytes) || ledger.Result == nil || ledger.PolicyTransition.RecoveryRequired {
		t.Fatal("real rollback reused B bytes or retained an incomplete hold", err)
	}
	return current
}

func runSTPortDockerDaemonMutation(t *testing.T, runner CommandRunner, stateDir string, plan SystemdPortReconfigurePlan, operation string) (LocalExecutorResponse, int) {
	t.Helper()
	manager, err := newFilePortPolicyStore(dockerPortSmokePolicyPath, true)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	request := newSTPortV2Request(t, plan, time.Now(), operation)
	request.MutationGrant = NewBoundedSecret(dockerPortDaemonSmokeGrant)
	consumed := 0
	rt := executorMutationRuntime{platformOS: "linux", localStateDir: stateDir, runner: runner,
		consumeV2Grant: func(_ context.Context, panelURL, jobID, grant string, input contracts.UpdaterMutationGrantConsumeRequest, _ *http.Client, now time.Time) error {
			consumed++
			if panelURL != "https://panel.example.com" || jobID != plan.JobID || grant != dockerPortDaemonSmokeGrant ||
				!reflect.DeepEqual(input.Binding, *request.MutationGrantV2Binding) || contracts.ValidateUpdaterMutationGrantBinding(now, input.Binding) != nil {
				return errors.New("real Docker v2 grant binding changed")
			}
			return nil
		}}
	if observed, ok := runner.(*dockerPortSmokeRunner); ok {
		rt.dockerPortCrashPointForTest = observed.observeSTPortPhase
	}
	ctx := context.WithValue(context.Background(), portPolicyContextKey{}, portPolicyStore(manager))
	failureSeen := false
	var failurePhase localExecutionFailurePhase
	var failureClass localExecutionFailureClass
	ctx = context.WithValue(ctx, localExecutionFailureContextKey{}, func(phase localExecutionFailurePhase, class localExecutionFailureClass) {
		if !failureSeen {
			failureSeen, failurePhase, failureClass = true, phase, class
		}
	})
	response := handleLocalExecutorMutation(ctx, policy, request, rt)
	if response.Error != nil {
		t.Logf("ST-PORT mutation first failure: observed=%t phase=%d class=%d", failureSeen, failurePhase, failureClass)
	}
	return response, consumed
}

func stPortDockerDaemonPlan(t *testing.T, policy LocalExecutorPolicy, current dockerPortSmokeState, mode contracts.SystemUpdatePortMode,
	advertised, published, container int, jobID, containerID, imageID, repositoryDigest, versionEnvSHA256, composeSHA256 string) SystemdPortReconfigurePlan {
	t.Helper()
	root, _ := json.Marshal(policy)
	rootSHA, _ := policy.SHA256()
	identifier := func(state string) string {
		return strings.TrimPrefix(systemdPortSidecarSHA256([]byte(jobID+":"+state)), "sha256:")
	}
	before := contracts.SystemUpdatePortSnapshotRef{SnapshotID: "ps1:" + identifier("before"), SnapshotSHA256: "sha256:" + identifier("before"),
		SourcePolicyRevision: policy.SourcePolicyRevision, ProjectionRevision: policy.ProjectionRevision, ExecutorPolicyRevision: policy.PolicyRevision,
		ExecutorPolicySHA256: rootSHA, EndpointRevision: current.endpointRevision, AppliedEndpointRevision: current.endpointRevision,
		ConfigRevision: current.configRevision, ConfigSHA256: current.configSHA256, AdvertisedPort: current.advertisedPort,
		AdvertisedEndpointSHA256: systemdPortSidecarSHA256([]byte("advertised:" + strconv.Itoa(current.advertisedPort))), LocalListenPort: current.publishedPort,
		Docker: &contracts.SystemUpdatePortDockerSnapshot{PublishedHostIP: "127.0.0.1", PublishedPort: current.publishedPort, ContainerPort: current.containerPort,
			HealthPort: current.publishedPort, ComposePolicySHA256: "sha256:" + policy.Targets[0].Docker.PortComposePolicySHA256,
			ComposeRevision: policy.Targets[0].Docker.PortComposeRevision, VersionEnvSHA256: versionEnvSHA256, ImageID: imageID, RepositoryDigest: repositoryDigest}}
	target, rollback := *clonePortSnapshotRef(&before), *clonePortSnapshotRef(&before)
	if published != current.publishedPort || container != current.containerPort {
		target.SnapshotID, target.SnapshotSHA256 = "ps1:"+identifier("target"), "sha256:"+identifier("target")
		rollback.SnapshotID, rollback.SnapshotSHA256 = "ps1:"+identifier("rollback"), "sha256:"+identifier("rollback")
		target.SourcePolicyRevision++
		target.ProjectionRevision++
		target.ExecutorPolicyRevision++
		target.ConfigRevision++
		target.Docker.ComposeRevision++
		target.LocalListenPort, target.Docker.PublishedPort, target.Docker.HealthPort, target.Docker.ContainerPort = published, published, published, container
		rollback.SourcePolicyRevision += 2
		rollback.ProjectionRevision += 2
		rollback.ExecutorPolicyRevision += 2
		rollback.ConfigRevision += 2
		rollback.Docker.ComposeRevision += 2
		if advertised != current.advertisedPort {
			target.AdvertisedPort = advertised
			target.AdvertisedEndpointSHA256 = systemdPortSidecarSHA256([]byte("advertised:" + strconv.Itoa(advertised)))
			target.EndpointRevision++
			target.AppliedEndpointRevision++
			rollback.EndpointRevision += 2
			rollback.AppliedEndpointRevision += 2
		}
		for _, ref := range []*contracts.SystemUpdatePortSnapshotRef{&target, &rollback} {
			ref.ConfigSHA256, _ = contracts.SystemUpdateDockerPortConfigSHA256(contracts.SystemUpdateTargetWorker, ref.Docker.PublishedPort, ref.Docker.ContainerPort, ref.ConfigRevision)
			ref.ExecutorPolicySHA256 = ""
			payload, err := contracts.ApplySystemUpdatePortPolicyDelta(root, "worker-smoke", before, *ref)
			if err != nil {
				t.Fatal("derive bounded real Docker policy", err)
			}
			ref.ExecutorPolicySHA256 = systemdPortSidecarSHA256(payload)
		}
	}
	baseline := &contracts.SystemUpdatePortDockerBaseline{ExpectedContainerID: containerID, ExpectedImageID: imageID,
		ExpectedRepositoryDigest: repositoryDigest, ExpectedVersionEnvSHA256: versionEnvSHA256,
		ApprovedComposeConfigSHA256: composeSHA256, ApprovedComposeRevision: before.Docker.ComposeRevision}
	shared := contracts.SystemUpdatePortReconfiguration{PortContractVersion: 2, Mode: mode, NetworkNamespace: "host", Protocol: contracts.SystemUpdatePortProtocolTCP,
		Before: &before, Target: &target, Rollback: &rollback, DockerBaseline: baseline}
	intent, err := contracts.ComputeSystemUpdatePortPlanSHA256(shared)
	if err != nil {
		t.Fatal(err)
	}
	plan := SystemdPortReconfigurePlan{PortContractVersion: 2, Mode: mode, DeploymentMode: ModeDocker, Before: &before, Target: &target, Rollback: &rollback, DockerBaseline: baseline,
		PortIntentSHA256: intent, JobID: jobID, HostID: policy.HostID, TargetID: "worker-smoke", ServiceType: "worker", NetworkNamespace: "host", Protocol: "tcp",
		OwnershipEpoch: 41, LeaseGeneration: 2, SessionID: "st-port-daemon-session-" + jobID}
	plan.PortPlanSHA256, err = plan.ComputePortPlanSHA256()
	if err != nil || plan.Validate() != nil {
		t.Fatal("invalid real Docker v2 plan", err)
	}
	return plan
}
