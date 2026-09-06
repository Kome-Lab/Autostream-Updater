package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

type stDockerPortRuntime struct {
	*fakeDockerPortRuntime
	store                             *stPortTestPolicyStore
	clock                             time.Time
	live                              []byte
	events                            []string
	forwardRevision, rollbackRevision int64
	failForward, failRollback         bool
}

func (r *stDockerPortRuntime) PortPolicyStore() portPolicyStore { return r.store }
func (r *stDockerPortRuntime) PortNow() time.Time               { return r.clock }
func (r *stDockerPortRuntime) PortCheckpoint() (dockerPortMappingCheckpoint, error) {
	return newDockerPortMappingCheckpoint(true, 0o600, r.current), nil
}
func (r *stDockerPortRuntime) modelHash(payload []byte) string {
	if bytes.Equal(payload, r.oldBytes) {
		return r.oldComposeSHA256
	}
	return strings.TrimPrefix(dockerPortEnvSHA256(append([]byte("resolved-compose:"), payload...)), "sha256:")
}
func (r *stDockerPortRuntime) Prepare(ctx context.Context, _ LocalExecutorTarget, payload []byte) (dockerPortPreparedModel, error) {
	published, container, _, err := parseDockerPortEnv(r.adapter, payload)
	if err != nil || ctx.Err() != nil {
		return dockerPortPreparedModel{}, errors.New("invalid prepared model")
	}
	return dockerPortPreparedModel{PublishedHostIP: "127.0.0.1", PublishedPort: published, ContainerPort: container, HealthPort: published,
		ComposePolicySHA256: r.policySHA256, ComposeConfigSHA256: r.modelHash(payload)}, nil
}
func (r *stDockerPortRuntime) Observe(ctx context.Context, _ LocalExecutorPolicy, target LocalExecutorTarget) (dockerPortObservation, error) {
	if ctx.Err() != nil || r.observeErr != nil || !bytes.Equal(r.current, r.live) || target.Docker == nil ||
		target.ConfigSHA256 != dockerPortEnvSHA256(r.live) || target.Docker.ComposeConfigSHA256 != r.modelHash(r.live) {
		return dockerPortObservation{}, errors.New("Docker listener or canonical mapping is unverified")
	}
	published, container, revision, err := parseDockerPortEnv(r.adapter, r.live)
	if err != nil {
		return dockerPortObservation{}, err
	}
	containerID := r.oldContainerID
	if !bytes.Equal(r.live, r.oldBytes) {
		containerID = r.targetContainerID
	}
	return dockerPortObservation{MappingEnv: newDockerPortMappingCheckpoint(true, 0o600, r.current), PublishedHostIP: "127.0.0.1",
		PublishedPort: published, ContainerPort: container, HealthPort: published, ConfigRevision: revision, ConfigSHA256: dockerPortEnvSHA256(r.live),
		ComposePolicySHA256: r.policySHA256, ComposeConfigSHA256: r.modelHash(r.live),
		Runtime: dockerPortRuntimeBaseline{ContainerID: containerID, ImageID: r.imageID, RepositoryDigest: r.repositoryDigest,
			VersionEnvSHA256: r.versionEnvSHA256, CurrentVersion: r.currentVersion}}, nil
}
func (r *stDockerPortRuntime) ConsumeGrant(ctx context.Context, plan SystemdPortReconfigurePlan, operation, version string, grant BoundedSecret) error {
	r.events = append(r.events, "consume")
	return r.fakeDockerPortRuntime.ConsumeGrant(ctx, plan, operation, version, grant)
}
func (r *stDockerPortRuntime) Write(checkpoint dockerPortMappingCheckpoint, payload []byte) error {
	policy, err := r.store.Snapshot()
	if err != nil || r.store.Verify(r.store.memory) != nil || !bytes.Equal(checkpoint.Bytes, r.current) ||
		policy.Targets[0].ConfigSHA256 != dockerPortEnvSHA256(payload) {
		return errors.New("Docker mapping write before verified policy")
	}
	r.writeCalls++
	r.events = append(r.events, "runtime_write")
	r.current = append([]byte(nil), payload...)
	return nil
}
func (r *stDockerPortRuntime) Recreate(ctx context.Context, target LocalExecutorTarget, prepared dockerPortPreparedModel) error {
	r.recreateCalls++
	r.events = append(r.events, "recreate")
	if ctx.Err() != nil || target.Docker.ComposeConfigSHA256 != prepared.ComposeConfigSHA256 || prepared.ComposeConfigSHA256 != r.modelHash(r.current) ||
		target.ConfigRevision == r.forwardRevision && r.failForward || target.ConfigRevision == r.rollbackRevision && r.failRollback {
		return errors.New("injected Docker recreate failure")
	}
	r.live = append([]byte(nil), r.current...)
	return nil
}

type stDockerPortHarness struct {
	plan    SystemdPortReconfigurePlan
	runtime *stDockerPortRuntime
	state   dockerPortStateStore
}

func newSTDockerPortHarness(t *testing.T, mode contracts.SystemUpdatePortMode, noop bool) *stDockerPortHarness {
	t.Helper()
	legacy := newDockerPortHarness(t)
	policy := legacy.policy
	rootBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	rootSHA, _ := policy.SHA256()
	docker := contracts.SystemUpdatePortDockerSnapshot{PublishedHostIP: "127.0.0.1", PublishedPort: 8084, ContainerPort: 8080, HealthPort: 8084,
		ComposePolicySHA256: "sha256:" + legacy.runtime.policySHA256, ComposeRevision: 8, VersionEnvSHA256: legacy.runtime.versionEnvSHA256,
		ImageID: legacy.runtime.imageID, RepositoryDigest: legacy.runtime.repositoryDigest}
	before := contracts.SystemUpdatePortSnapshotRef{SnapshotID: "ps1:" + strings.Repeat("a", 64), SnapshotSHA256: "sha256:" + strings.Repeat("a", 64),
		SourcePolicyRevision: 6, ProjectionRevision: 7, ExecutorPolicyRevision: 8, ExecutorPolicySHA256: rootSHA,
		EndpointRevision: 4, AppliedEndpointRevision: 4, ConfigRevision: 11, ConfigSHA256: dockerPortEnvSHA256(legacy.runtime.oldBytes),
		AdvertisedPort: 443, AdvertisedEndpointSHA256: "sha256:" + strings.Repeat("d", 64), LocalListenPort: 8084, Docker: &docker}
	target, rollback := *clonePortSnapshotRef(&before), *clonePortSnapshotRef(&before)
	if !noop {
		target.SnapshotID, target.SnapshotSHA256 = "ps1:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("b", 64)
		rollback.SnapshotID, rollback.SnapshotSHA256 = "ps1:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("c", 64)
		target.SourcePolicyRevision++
		target.ProjectionRevision++
		target.ExecutorPolicyRevision++
		target.ConfigRevision++
		target.Docker.ComposeRevision++
		target.LocalListenPort, target.Docker.PublishedPort, target.Docker.HealthPort = 18084, 18084, 18084
		// The container port is deliberately independent of the host port.
		rollback.SourcePolicyRevision += 2
		rollback.ProjectionRevision += 2
		rollback.ExecutorPolicyRevision += 2
		rollback.ConfigRevision += 2
		rollback.Docker.ComposeRevision += 2
		if mode == contracts.SystemUpdatePortModeLocalAndAdvertised {
			target.EndpointRevision++
			target.AppliedEndpointRevision++
			target.AdvertisedPort = 8443
			target.AdvertisedEndpointSHA256 = "sha256:" + strings.Repeat("e", 64)
			rollback.EndpointRevision += 2
			rollback.AppliedEndpointRevision += 2
		}
		for _, ref := range []*contracts.SystemUpdatePortSnapshotRef{&target, &rollback} {
			payload, err := dockerPortEnvBytes(legacy.runtime.adapter, ref.Docker.PublishedPort, ref.Docker.ContainerPort, ref.ConfigRevision)
			if err != nil {
				t.Fatal(err)
			}
			ref.ConfigSHA256, ref.ExecutorPolicySHA256 = dockerPortEnvSHA256(payload), ""
			candidate, err := contracts.ApplySystemUpdatePortPolicyDelta(rootBytes, "worker-01", before, *ref)
			if err != nil {
				t.Fatal("derive Docker root candidate", err)
			}
			ref.ExecutorPolicySHA256 = systemdPortSidecarSHA256(candidate)
		}
	}
	baseline := &contracts.SystemUpdatePortDockerBaseline{ExpectedContainerID: legacy.runtime.oldContainerID, ExpectedImageID: docker.ImageID,
		ExpectedRepositoryDigest: docker.RepositoryDigest, ExpectedVersionEnvSHA256: docker.VersionEnvSHA256,
		ApprovedComposeConfigSHA256: legacy.runtime.oldComposeSHA256, ApprovedComposeRevision: docker.ComposeRevision}
	shared := contracts.SystemUpdatePortReconfiguration{PortContractVersion: 2, Mode: mode, NetworkNamespace: "host", Protocol: contracts.SystemUpdatePortProtocolTCP,
		Before: &before, Target: &target, Rollback: &rollback, DockerBaseline: baseline}
	shared.PortPlanSHA256, err = contracts.ComputeSystemUpdatePortPlanSHA256(shared)
	if err != nil {
		t.Fatal(err)
	}
	plan := SystemdPortReconfigurePlan{PortContractVersion: 2, Mode: mode, Before: &before, Target: &target, Rollback: &rollback, DockerBaseline: baseline,
		PortIntentSHA256: shared.PortPlanSHA256, DeploymentMode: ModeDocker, JobID: "job-docker-port-v2", HostID: policy.HostID,
		TargetID: "worker-01", ServiceType: "worker", NetworkNamespace: "host", Protocol: "tcp", OwnershipEpoch: 3, LeaseGeneration: 2,
		SessionID: "docker-v2-session-0123456789abcdef"}
	plan.PortPlanSHA256, err = plan.ComputePortPlanSHA256()
	if err != nil || plan.Validate() != nil {
		t.Fatal("invalid Docker v2 fixture", err)
	}
	runtime := &stDockerPortRuntime{fakeDockerPortRuntime: legacy.runtime, clock: time.Now(), live: append([]byte(nil), legacy.runtime.oldBytes...),
		forwardRevision: target.ConfigRevision, rollbackRevision: rollback.ConfigRevision}
	runtime.store = &stPortTestPolicyStore{disk: append([]byte(nil), rootBytes...), memory: append([]byte(nil), rootBytes...), events: &runtime.events}
	return &stDockerPortHarness{plan: plan, runtime: runtime, state: legacy.state}
}

func (h *stDockerPortHarness) run(t *testing.T, operation string) LocalExecutorResponse {
	t.Helper()
	policy, err := h.runtime.store.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return executeDockerPortRequest(context.Background(), policy, newSTPortV2Request(t, h.plan, h.runtime.clock, operation), h.runtime, h.state)
}

func TestSTPortDockerModesPreserveImageAndCanonicalProfile(t *testing.T) {
	for _, mode := range []contracts.SystemUpdatePortMode{contracts.SystemUpdatePortModeLocalOnly, contracts.SystemUpdatePortModeLocalAndAdvertised} {
		t.Run(string(mode), func(t *testing.T) {
			h := newSTDockerPortHarness(t, mode, false)
			response := h.run(t, "port_reconfigure")
			if response.PortResult == nil || response.PortResult.PortResult == nil || response.PortResult.Result != systemdPortResultApplied {
				t.Fatalf("Docker apply was not verified; safe error=%v", response.Error)
			}
			observed := response.PortResult.PortResult
			if observed.RuntimeInstance == nil || observed.RuntimeInstance.ContainerID == h.plan.DockerBaseline.ExpectedContainerID ||
				observed.RuntimeInstance.ImageID != h.plan.Before.Docker.ImageID || observed.RuntimeInstance.RepositoryDigest != h.plan.Before.Docker.RepositoryDigest {
				t.Fatal("Docker runtime instance or image invariant mismatch")
			}
			if !reflect.DeepEqual(h.runtime.events, []string{"consume", "policy_write", "policy_reload", "runtime_write", "recreate"}) {
				t.Fatalf("Docker policy/runtime order: %v", h.runtime.events)
			}
			policy, _ := h.runtime.store.Snapshot()
			if policy.Targets[0].Docker.ComposeConfigSHA256 != h.plan.DockerBaseline.ApprovedComposeConfigSHA256 ||
				policy.Targets[0].Docker.PortComposePolicySHA256 != strings.TrimPrefix(h.plan.Before.Docker.ComposePolicySHA256, "sha256:") {
				t.Fatal("fixed root profile was replaced")
			}
			resolved, err := resolveDockerPortAppliedTarget(policy, policy.Targets[0], h.state)
			if err != nil || resolved.Docker.ComposeConfigSHA256 != h.runtime.modelHash(h.runtime.live) {
				t.Fatal("verified applied overlay missing", err)
			}
			firstTime := observed.Observation.ObservedAt
			h.plan.LeaseGeneration++
			h.plan.SessionID = "docker-v2-fresh-session-0123456789"
			h.plan.PortPlanSHA256, _ = h.plan.ComputePortPlanSHA256()
			replay := h.run(t, "port_reconfigure_reconcile")
			if replay.PortResult == nil || !replay.PortResult.PortResult.Observation.ObservedAt.Equal(firstTime) || h.runtime.recreateCalls != 1 || h.runtime.consumeCalls != 1 {
				t.Fatal("accepted Docker result replay changed content or repeated mutation")
			}
		})
	}
}

func TestSTPortDockerNoopRequiresActualUnchangedContainer(t *testing.T) {
	h := newSTDockerPortHarness(t, contracts.SystemUpdatePortModeLocalOnly, true)
	response := h.run(t, "port_reconfigure")
	if response.PortResult == nil || response.PortResult.Result != systemdPortResultUnchanged || response.PortResult.PortResult.RuntimeInstance.ContainerID != h.plan.DockerBaseline.ExpectedContainerID ||
		h.runtime.consumeCalls != 0 || h.runtime.writeCalls != 0 || h.runtime.recreateCalls != 0 || h.runtime.store.writes != 0 {
		t.Fatal("Docker no-op mutated or lacked proof")
	}
	unobserved := newSTDockerPortHarness(t, contracts.SystemUpdatePortModeLocalOnly, true)
	unobserved.runtime.observeErr = errors.New("daemon unavailable")
	if failed := unobserved.run(t, "port_reconfigure"); failed.PortResult != nil {
		t.Fatal("unobserved Docker no-op fabricated success")
	}
}

func TestSTPortDockerRollbackWritesRevisionPlusTwoAndRecovers(t *testing.T) {
	h := newSTDockerPortHarness(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	h.runtime.failForward, h.runtime.failRollback = true, true
	failed := h.run(t, "port_reconfigure")
	if failed.PortResult == nil || failed.PortResult.Result != systemdPortResultRollbackFailed || !failed.PortResult.RecoveryRequired {
		t.Fatal("confirmed Docker recovery failure not retained")
	}
	ledger, err := h.state.LoadJob(h.plan.TargetID, h.plan.JobID)
	if err != nil || ledger.Result != nil || !ledger.PolicyTransition.RollbackLatched || ledger.PolicyTransition.LastRecoveryObservation == nil {
		t.Fatal("failure occupied accepted slot or cleared hold")
	}
	_, _, revision, err := parseDockerPortEnv(h.runtime.adapter, h.runtime.current)
	if err != nil || revision != h.plan.Before.ConfigRevision+2 || bytes.Equal(h.runtime.current, h.runtime.oldBytes) {
		t.Fatal("rollback restored obsolete B payload")
	}
	h.runtime.failForward, h.runtime.failRollback = false, false
	h.plan.LeaseGeneration++
	h.plan.SessionID = "docker-v2-recovery-session-0123456789"
	h.plan.PortPlanSHA256, _ = h.plan.ComputePortPlanSHA256()
	recovered := h.run(t, "port_reconfigure_reconcile")
	if recovered.PortResult == nil || recovered.PortResult.Result != systemdPortResultRolledBack || recovered.PortResult.PortResult.ObservedConfigRevision != h.plan.Rollback.ConfigRevision || h.runtime.consumeCalls != 2 || h.runtime.restoreCalls != 0 {
		t.Fatal("same-job Docker recovery did not converge to exact R")
	}
	policy, _ := h.runtime.store.Snapshot()
	if !portPolicySnapshotMatches(policy, policy.Targets[0], *h.plan.Rollback) {
		t.Fatal("Docker root policy did not retain R")
	}
	resolved, err := resolveDockerPortAppliedTarget(policy, policy.Targets[0], h.state)
	if err != nil || resolved.Docker.ComposeConfigSHA256 != h.runtime.modelHash(h.runtime.live) {
		t.Fatal("Docker R overlay is not backed by immutable accepted ledger", err)
	}
}

func TestSTPortDockerRecoveryRejectsImageAndComposeDrift(t *testing.T) {
	for _, field := range []string{"image", "profile", "container"} {
		t.Run(field, func(t *testing.T) {
			h := newSTDockerPortHarness(t, contracts.SystemUpdatePortModeLocalOnly, false)
			switch field {
			case "image":
				h.runtime.imageID = "sha256:" + strings.Repeat("9", 64)
			case "profile":
				h.runtime.policySHA256 = strings.Repeat("9", 64)
			case "container":
				h.runtime.oldContainerID = strings.Repeat("9", 64)
			}
			response := h.run(t, "port_reconfigure")
			if response.PortResult != nil || h.runtime.consumeCalls != 0 || h.runtime.writeCalls != 0 || h.runtime.recreateCalls != 0 {
				t.Fatal("unapproved Docker baseline reached mutation")
			}
		})
	}
}

func TestSTPortDockerSoftwareTargetsUseAcceptedAppliedAndRollbackModels(t *testing.T) {
	for _, kind := range []string{systemdPortResultApplied, systemdPortResultRolledBack} {
		t.Run(kind, func(t *testing.T) {
			h := newSTDockerPortHarness(t, contracts.SystemUpdatePortModeLocalOnly, false)
			h.runtime.failForward = kind == systemdPortResultRolledBack
			response := h.run(t, "port_reconfigure")
			if response.PortResult == nil || response.PortResult.Result != kind {
				t.Fatal("versioned port fixture did not converge")
			}
			policy, _ := h.runtime.store.Snapshot()
			before, _ := json.Marshal(policy)
			beforeSHA, _ := policy.SHA256()
			target, err := localExecutorSoftwareRuntimeTarget(policy, policy.Targets[0], h.state)
			if err != nil || target.Docker == nil || target.Docker.ComposeConfigSHA256 != h.runtime.modelHash(h.runtime.live) ||
				target.Docker.ComposeConfigSHA256 == policy.Targets[0].Docker.ComposeConfigSHA256 ||
				target.Docker.PortEnvFile != policy.Targets[0].Docker.PortEnvFile || target.Docker.ImageRepo != policy.Targets[0].Docker.ImageRepo {
				t.Fatal("software did not use the accepted same-target model while retaining its fixed profile", err)
			}
			after, _ := json.Marshal(policy)
			afterSHA, _ := policy.SHA256()
			if !bytes.Equal(before, after) || beforeSHA != afterSHA {
				t.Fatal("software projection rewrote the root policy authority")
			}
			accepted, _ := h.state.LoadDockerApplied(h.plan.TargetID)
			for _, field := range []string{"ownership", "source", "projection", "executor", "model"} {
				t.Run(field, func(t *testing.T) {
					mutant := *accepted
					switch field {
					case "ownership":
						mutant.OwnershipEpoch++
					case "source":
						mutant.SourcePolicyRevision++
					case "projection":
						mutant.UpdaterPolicyRevision++
					case "executor":
						mutant.ExecutorPolicyRevision++
					case "model":
						mutant.ComposeConfigSHA256 = strings.Repeat("9", 64)
					}
					if h.state.SaveApplied(mutant) != nil {
						t.Fatal("invalid fixture mutation")
					}
					if _, err := localExecutorSoftwareRuntimeTarget(policy, policy.Targets[0], h.state); err == nil {
						t.Fatal("software accepted a rebound port overlay")
					}
					if h.state.SaveApplied(*accepted) != nil {
						t.Fatal("restore fixture overlay")
					}
				})
			}
			unknown := policy.Targets[0]
			copied := *unknown.Docker
			unknown.Docker = &copied
			copied.PortComposeRevision++
			if _, err := localExecutorSoftwareRuntimeTarget(policy, unknown, h.state); err == nil {
				t.Fatal("software accepted a non-installed Docker target")
			}
		})
	}
}
