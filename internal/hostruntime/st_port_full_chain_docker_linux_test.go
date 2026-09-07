//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

// These are real CP/MariaDB, non-root Agent, root UDS and Docker-daemon cases.
// The existing Docker Node-listener fixture is the target process; this does
// not replace the separate canonical Worker/systemd witness. Every image and
// repository digest comes from the isolated daemon, without a runner override.
func TestSTPortFullChainDocker(t *testing.T) {
	fixture := &stPortChainDockerFixture{}
	h := newSTPortChainHarnessWithRuntime(t, stPortChainRuntimeAdapter{
		Mode: ModeDocker, InitialLocalPort: 18081,
		Prepare: fixture.prepare, Install: fixture.install, Cleanup: fixture.cleanup,
	})
	t.Run("D1_local_only", func(t *testing.T) {
		before := h.current(t)
		runtimeBefore := fixture.observe(t, h, before.Snapshot)
		job := fixture.create(t, h, "D1-local", "local_only", 18083, 18080, 0)
		fixture.complete(t, h, job, contracts.SystemUpdatePortReconfigurationApplied)
		after := h.current(t)
		runtimeAfter := fixture.observe(t, h, after.Snapshot)
		if after.Snapshot.AdvertisedPort != before.Snapshot.AdvertisedPort || after.Snapshot.EndpointRevision != before.Snapshot.EndpointRevision ||
			after.Snapshot.LocalListenPort != 18083 || after.Snapshot.Docker.ContainerPort != 18080 || runtimeBefore.Runtime.ContainerID == runtimeAfter.Runtime.ContainerID ||
			after.Snapshot.SourcePolicyRevision != before.Snapshot.SourcePolicyRevision+1 || after.Snapshot.ConfigRevision != before.Snapshot.ConfigRevision+1 {
			t.Fatal("Docker local-only did not change the real mapping while retaining its advertised endpoint")
		}
	})
	t.Run("D2_local_and_advertised", func(t *testing.T) {
		before := h.current(t)
		job := fixture.create(t, h, "D2-combined", "local_and_advertised", 18084, 19080, 8443)
		fixture.complete(t, h, job, contracts.SystemUpdatePortReconfigurationApplied)
		after := h.current(t)
		fixture.observe(t, h, after.Snapshot)
		if after.Snapshot.AdvertisedPort != 8443 || after.Snapshot.LocalListenPort != 18084 || after.Snapshot.Docker.ContainerPort != 19080 ||
			after.Snapshot.EndpointRevision != before.Snapshot.EndpointRevision+1 || after.Snapshot.AppliedEndpointRevision != before.Snapshot.AppliedEndpointRevision+1 {
			t.Fatal("Docker combined mode lost independent advertised, published or container values")
		}
	})
	t.Run("D3_unchanged", func(t *testing.T) {
		before := h.current(t)
		runtimeBefore := fixture.observe(t, h, before.Snapshot)
		policy := stPortChainDockerRead(t, localExecutorPortPolicyPath)
		mapping := stPortChainDockerRead(t, fixture.target.PortEnvFile)
		policyInfo := stPortChainFileInfo(t, localExecutorPortPolicyPath)
		mappingInfo := stPortChainFileInfo(t, fixture.target.PortEnvFile)
		job := fixture.create(t, h, "D3-unchanged", "local_and_advertised", before.Snapshot.Docker.PublishedPort, before.Snapshot.Docker.ContainerPort, before.Snapshot.AdvertisedPort)
		fixture.complete(t, h, job, contracts.SystemUpdatePortReconfigurationUnchanged)
		after := h.current(t)
		runtimeAfter := fixture.observe(t, h, after.Snapshot)
		stPortChainSameBytes(t, localExecutorPortPolicyPath, policy)
		stPortChainSameBytes(t, fixture.target.PortEnvFile, mapping)
		if !reflect.DeepEqual(before.Snapshot, after.Snapshot) || runtimeBefore.Runtime.ContainerID != runtimeAfter.Runtime.ContainerID ||
			!os.SameFile(policyInfo, stPortChainFileInfo(t, localExecutorPortPolicyPath)) || !os.SameFile(mappingInfo, stPortChainFileInfo(t, fixture.target.PortEnvFile)) ||
			before.ConsumeCount != after.ConsumeCount || before.Reservations != after.Reservations {
			t.Fatal("Docker fresh-B no-op changed policy, mapping, container, grant consume or reservations")
		}
	})
	t.Run("D4_rolled_back", func(t *testing.T) {
		before := h.current(t)
		runtimeBefore := fixture.observe(t, h, before.Snapshot)
		mapping := stPortChainDockerRead(t, fixture.target.PortEnvFile)
		// The existing fixture really listens on 21080 and returns HTTP 503.
		// This exercises production health failure and recreation back to R.
		job := fixture.create(t, h, "D4-rollback", "local_and_advertised", 18086, 21080, 9443)
		finishObservation := stPortChainDockerWatchUnhealthy(h.ctx, job.PortReconfigure.Target)
		defer finishObservation()
		fixture.complete(t, h, job, contracts.SystemUpdatePortReconfigurationRolledBack)
		if !finishObservation() {
			t.Fatal("Docker rollback did not witness the actual target listener reporting unhealthy")
		}
		after := h.current(t)
		runtimeAfter := fixture.observe(t, h, after.Snapshot)
		if after.Snapshot.AdvertisedPort != before.Snapshot.AdvertisedPort || after.Snapshot.LocalListenPort != before.Snapshot.LocalListenPort ||
			after.Snapshot.Docker.ContainerPort != before.Snapshot.Docker.ContainerPort || after.Snapshot.ConfigRevision != before.Snapshot.ConfigRevision+2 ||
			after.Snapshot.SourcePolicyRevision != before.Snapshot.SourcePolicyRevision+2 || after.Snapshot.EndpointRevision != before.Snapshot.EndpointRevision+2 ||
			runtimeBefore.Runtime.ContainerID == runtimeAfter.Runtime.ContainerID || bytes.Equal(mapping, runtimeAfter.MappingEnv.Bytes) {
			t.Fatal("Docker rollback did not recreate B functional values with fresh R revisions and bytes")
		}
		ledger := fixture.ledger(t, job.ID)
		if ledger.PolicyTransition == nil || ledger.PolicyTransition.RecoveryRequired || bytes.Equal(ledger.Checkpoint.Bytes, ledger.PolicyTransition.RollbackRuntimeBytes) {
			t.Fatal("Docker rollback reused B bytes or left a recovery hold")
		}
	})
}

type stPortChainDockerFixture struct {
	target           DockerTarget
	adapter          dockerPortAdapter
	image            string
	imageID          string
	containerID      string
	repositoryDigest string
	versionEnvSHA256 string
	canonical        []byte
	immutableFiles   map[string][]byte
	nonPort          *stPortChainDockerNonPort
}

func (f *stPortChainDockerFixture) prepare(t *testing.T, h *stPortChainHarness) map[string]any {
	t.Helper()
	if os.Getenv("AUTOSTREAM_ST_PORT_DOCKER_FULL_CHAIN") != "1" || os.Getenv(dockerPortDaemonSmokeFixtureEnv) == "" {
		t.Fatal("isolated Docker full-chain selection and immutable fixture binary are required")
	}
	stPortChainFileInfo(t, os.Getenv(dockerPortDaemonSmokeFixtureEnv))
	stPortChainDockerRegistry(t)
	stPortChainDockerRun(t, h.ctx, "daemon_version", "", "version", "--format", "{{.Server.Version}}")
	stPortChainDockerRun(t, h.ctx, "compose_version", "", "compose", "version")
	if strings.TrimSpace(stPortChainDockerRun(t, h.ctx, "empty_project", "", "ps", "-aq", "--filter", "label=com.docker.compose.project=autostream")) != "" {
		t.Fatal("Docker integration refuses a pre-existing managed container")
	}
	for _, port := range []int{18081, 18083, 18084, 18086} {
		requireDockerPortSmokePortAvailable(t, port)
	}
	f.image = dockerPortSmokeImageRepo + ":" + h.workerVersion
	buildDockerPortFixtureImage(t, f.image)
	// ghcr.io resolves only to this network-none container's TLS registry.
	// No external registry is contacted and this is not a release publication.
	stPortChainDockerRun(t, h.ctx, "fixture_push", "", "push", f.image)
	stPortChainDockerRun(t, h.ctx, "fixture_pull", "", "pull", f.image)
	f.imageID = strings.TrimSpace(stPortChainDockerRun(t, h.ctx, "image_identity", "", "image", "inspect", "--format={{.Id}}", f.image))
	if !digestPattern.MatchString(f.imageID) {
		t.Fatal("real Docker fixture image identity is unavailable")
	}
	rawDigests := stPortChainDockerRun(t, h.ctx, "repository_identity", "", "image", "inspect", "--format={{json .RepoDigests}}", f.imageID)
	var err error
	f.repositoryDigest, err = repositoryDigest(rawDigests, dockerPortSmokeImageRepo)
	if err != nil {
		t.Fatal("real canonical-repository manifest digest is unavailable")
	}
	f.target = dockerPortSmokeTarget()
	f.target.CurrentVersion = h.workerVersion
	f.target.PortComposeRevision = 23
	f.adapter, err = dockerPortAdapterFor("worker", &f.target)
	if err != nil {
		t.Fatal("fixed canonical Docker profile is unavailable")
	}
	for _, directory := range []string{"/opt/autostream", "/opt/autostream/local-executor/docker", "/opt/autostream/local-executor/docker/ports", "/etc/autostream-local-executor/docker"} {
		if os.MkdirAll(directory, 0o700) != nil {
			t.Fatal("prepare isolated canonical Docker directories")
		}
	}
	compose := fmt.Sprintf(`services:
  worker:
    image: %s@%s
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    pids_limit: 64
    stop_grace_period: 1s
    environment:
      CREDENTIALS_DIRECTORY: "/run/autostream-credentials"
      AUTOSTREAM_FIXTURE_ADVERTISED_PORT: "${AUTOSTREAM_FIXTURE_ADVERTISED_PORT}"
      AUTOSTREAM_FIXTURE_BUNDLE_PIN: "${AUTOSTREAM_DOCKER_VERSION}"
      AUTOSTREAM_FIXTURE_VERSION: "%s"
      AUTOSTREAM_FIXTURE_UNHEALTHY_PORT: "21080"
    configs:
      - source: worker_node_listener
        target: /run/autostream-credentials/node-listener.json
    ports:
      - "127.0.0.1:${AUTOSTREAM_WORKER_PORT}:${AUTOSTREAM_WORKER_CONTAINER_PORT}/tcp"
configs:
  worker_node_listener:
    content: |
      {"schema_version":2,"service_type":"worker","bind_address":"0.0.0.0:${AUTOSTREAM_WORKER_CONTAINER_PORT}","config_revision":${AUTOSTREAM_CONFIG_REVISION}}
`, dockerPortSmokeImageRepo, f.repositoryDigest, h.workerVersion)
	versionEnv := []byte("AUTOSTREAM_DOCKER_VERSION=" + h.workerVersion + "@" + f.repositoryDigest + "\n")
	f.versionEnvSHA256 = dockerPortEnvSHA256(versionEnv)
	mapping, err := dockerPortEnvBytes(f.adapter, 18081, 8080, 31)
	if err != nil {
		t.Fatal("derive initial canonical Docker mapping")
	}
	f.immutableFiles = map[string][]byte{
		"/opt/autostream/compose.yml":                       []byte(compose),
		f.target.BaseEnvFile:                                []byte("AUTOSTREAM_FIXTURE_ADVERTISED_PORT=443\n"),
		f.target.VersionEnvFile:                             versionEnv,
		"/etc/autostream-local-executor/docker/config.json": []byte("{}\n"),
	}
	for path, body := range f.immutableFiles {
		writeDockerPortSmokeFile(t, path, body)
	}
	writeDockerPortSmokeFile(t, f.target.PortEnvFile, mapping)
	f.canonical = []byte(stPortChainDockerRun(t, h.ctx, "compose_config", f.target.ProjectDir, append(composeArgs(&f.target, ""), "config", "--format", "json", "--no-env-resolution")...))
	f.target.PortComposePolicySHA256, err = dockerPortComposePolicyHash(f.canonical, &f.target)
	if err != nil {
		t.Fatal("observe initial full non-port Compose projection")
	}
	f.target.ComposeConfigSHA256, err = composeModelHash(f.canonical, f.target.Service)
	if err != nil {
		t.Fatal("observe initial resolved Compose projection")
	}
	f.startInitialNode(t, h)
	f.containerID = dockerPortSmokeContainerID(t, OSCommandRunner{NewProcessGroup: true})
	return map[string]any{"docker": map[string]any{
		"compose_config_sha256": f.target.ComposeConfigSHA256, "compose_policy_sha256": f.target.PortComposePolicySHA256,
		"compose_revision": f.target.PortComposeRevision, "published_port": 18081, "container_port": 8080,
		"current_version": h.workerVersion, "container_id": f.containerID, "image_id": f.imageID, "repository_digest": f.repositoryDigest, "version_env_sha256": f.versionEnvSHA256,
	}}
}

func (f *stPortChainDockerFixture) install(t *testing.T, h *stPortChainHarness) {
	t.Helper()
	target, ok := h.rootPolicy.Target("worker-smoke")
	if !ok || target.DeploymentMode != ModeDocker || target.Docker == nil || !reflect.DeepEqual(*target.Docker, f.target) ||
		target.ConfigRevision != 31 || target.LocalListen.Port != 18081 || target.ConfigSHA256 != dockerPortEnvSHA256(stPortChainDockerRead(t, f.target.PortEnvFile)) {
		t.Fatal("CP-owned Docker policy does not match the actual fixed fixture baseline")
	}
	if dockerPortSmokeContainerID(t, OSCommandRunner{NewProcessGroup: true}) != f.containerID || !stPortChainDockerNodeHealthy(h.workerVersion, 18081, 8080, 31) {
		t.Fatal("initial Docker runtime changed before CP policy installation")
	}
}

func (f *stPortChainDockerFixture) startInitialNode(t *testing.T, h *stPortChainHarness) {
	t.Helper()
	if ensureDockerPortWorkDirectory(localExecutorDockerWorkDir, true) != nil {
		t.Fatal("prepare root-owned Docker transient work directory")
	}
	work, err := os.MkdirTemp(localExecutorDockerWorkDir, dockerPortRecreatePrefix)
	if err != nil {
		t.Fatal("prepare initial canonical Docker execution")
	}
	canonicalPath := filepath.Join(work, "compose-frozen.json")
	writeDockerPortSmokeFile(t, canonicalPath, f.canonical)
	listener := defaultDockerNodeListenerStore()
	execution, err := listener.freeze(canonicalPath, &f.target)
	if err != nil || listener.validateFrozen(execution, &f.target) != nil {
		t.Fatal("freeze verified initial Node listener projection")
	}
	stPortChainDockerRun(t, h.ctx, "initial_up", f.target.ProjectDir, append(composeFrozenArgs(&f.target, execution.path), "up", "-d", "--no-deps", "--no-build", "--pull", "never", f.target.Service)...)
	if secureRemoveDockerPortTransient(localExecutorDockerWorkDir, work, true) != nil {
		t.Fatal("remove initial transient Compose input")
	}
	stPortChainWait(t, 20*time.Second, func() bool { return stPortChainDockerNodeHealthy(h.workerVersion, 18081, 8080, 31) })
}

func (f *stPortChainDockerFixture) cleanup(t *testing.T, h *stPortChainHarness) {
	if f.image == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	runner := OSCommandRunner{NewProcessGroup: true}
	ids, err := runner.Run(ctx, "", dockerCommandEnv(), "/usr/bin/docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=autostream", "--filter", "label=com.docker.compose.service=worker")
	if err != nil {
		t.Error("read owned Docker fixture during cleanup")
		return
	}
	for _, id := range strings.Fields(ids) {
		if len(id) < 12 || len(id) > 64 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Error("refuse ambiguous Docker fixture cleanup identity")
			continue
		}
		if _, err := runner.Run(ctx, "", dockerCommandEnv(), "/usr/bin/docker", "rm", "--force", id); err != nil {
			t.Error("remove owned Docker fixture container")
		}
	}
	// All storage, registry data and images remain inside the disposable CI
	// container; the parent script removes that exact container after the run.
}

func (f *stPortChainDockerFixture) create(t *testing.T, h *stPortChainHarness, key, mode string, published, container, advertised int) stPortChainJob {
	t.Helper()
	_ = h.current(t)
	return stPortChainDecodeJob(t, h.cp.call(t, stPortChainCommand{Command: "create", Mode: mode, PublishedPort: published, ContainerPort: container, AdvertisedPort: advertised, IdempotencyKey: key}))
}

func (f *stPortChainDockerFixture) ledger(t *testing.T, jobID string) *dockerPortLedger {
	t.Helper()
	state, err := newFileDockerPortStateStore(LocalExecutorMutationStateDir, true)
	if err != nil {
		t.Fatal("open actual root Docker ledger")
	}
	ledger, err := state.LoadJob("worker-smoke", jobID)
	if err != nil || ledger == nil || ledger.Plan.JobID != jobID || ledger.validate("worker-smoke") != nil {
		t.Fatal("read exact durable root Docker job")
	}
	return ledger
}

func (f *stPortChainDockerFixture) complete(t *testing.T, h *stPortChainHarness, job stPortChainJob, kind contracts.SystemUpdatePortReconfigurationResult) {
	t.Helper()
	if response := h.agent.call(t, stPortChainCommand{Command: "poll"}); !response.OK {
		t.Fatal("real Agent Docker execution did not complete")
	}
	accepted := h.job(t, job.ID)
	if accepted.PortResult == nil || accepted.PortResult.Result != kind || accepted.RecoveryRequired || contracts.ValidateSystemUpdatePortResult(*job.PortReconfigure, *accepted.PortResult) != nil {
		t.Fatal("typed Docker root result did not survive CP database acceptance")
	}
	ledger := f.ledger(t, job.ID)
	if ledger.Result == nil || ledger.Result.PortResult == nil {
		t.Fatal("actual Docker ledger has no accepted observation")
	}
	first := clonePortResult(ledger.Result.PortResult)
	first.Observation.AgentProjectionVerified = true
	if !stPortChainSameResult(first, accepted.PortResult) {
		t.Fatal("CP changed the first Docker root observation")
	}
	expected := job.PortReconfigure.Target
	if kind == contracts.SystemUpdatePortReconfigurationUnchanged {
		expected = job.PortReconfigure.Before
	} else if kind == contracts.SystemUpdatePortReconfigurationRolledBack {
		expected = job.PortReconfigure.Rollback
	}
	current := h.current(t)
	if !reflect.DeepEqual(current.Snapshot, expected) {
		t.Fatal("accepted Docker database and real Agent projection do not equal the immutable result snapshot")
	}
	f.observe(t, h, expected)
}

func (f *stPortChainDockerFixture) observe(t *testing.T, h *stPortChainHarness, expected *contracts.SystemUpdatePortSnapshotRef) dockerPortObservation {
	t.Helper()
	if expected == nil || expected.Docker == nil {
		t.Fatal("complete Docker snapshot is required")
	}
	policy, err := LoadLocalExecutorPolicy(localExecutorPortPolicyPath, true)
	if err != nil {
		t.Fatal("read installed root Docker policy")
	}
	target, ok := policy.Target("worker-smoke")
	if !ok || !portPolicySnapshotMatches(policy, target, *expected) {
		t.Fatal("actual root Docker policy differs from the accepted CP snapshot")
	}
	state, err := newFileDockerPortStateStore(LocalExecutorMutationStateDir, true)
	if err != nil {
		t.Fatal("read actual Docker applied overlay")
	}
	target, err = resolveDockerPortAppliedTarget(policy, target, state)
	if err != nil {
		t.Fatal("actual Docker applied overlay differs from root policy")
	}
	runtime := &linuxDockerPortRuntime{adapter: f.adapter, hostID: policy.HostID, serviceID: target.ServiceID, serviceType: target.ServiceType,
		dockerPath: target.Docker.DockerPath, runner: OSCommandRunner{NewProcessGroup: true}, requireRootOwned: true, httpClient: &http.Client{Timeout: 2 * time.Second}}
	observation, err := runtime.Observe(h.ctx, policy, target)
	if err != nil || observation.validate() != nil || observation.PublishedPort != expected.Docker.PublishedPort || observation.ContainerPort != expected.Docker.ContainerPort ||
		observation.ConfigRevision != expected.ConfigRevision || observation.ConfigSHA256 != expected.ConfigSHA256 ||
		"sha256:"+observation.ComposePolicySHA256 != expected.Docker.ComposePolicySHA256 || observation.ComposePolicySHA256 != f.target.PortComposePolicySHA256 ||
		observation.Runtime.ImageID != f.imageID || observation.Runtime.RepositoryDigest != f.repositoryDigest || observation.Runtime.VersionEnvSHA256 != f.versionEnvSHA256 {
		t.Fatal("actual Docker image, Compose, mapping or runtime observation differs from the accepted snapshot")
	}
	for path, body := range f.immutableFiles {
		stPortChainSameBytes(t, path, body)
	}
	base := OSCommandRunner{NewProcessGroup: true}
	assertDockerPortFixtureBoundary(t, base, observation.Runtime.ContainerID, observation.PublishedPort, observation.ContainerPort, dockerNodeListenerConfigRoot)
	if !stPortChainDockerNodeHealthy(h.workerVersion, observation.PublishedPort, observation.ContainerPort, observation.ConfigRevision) {
		t.Fatal("actual Docker Node listener identity/configuration did not match")
	}
	inspect := stPortChainDockerRun(t, h.ctx, "runtime_inspect", "", "inspect", "--format={{json .}}", observation.Runtime.ContainerID)
	var running stPortChainDockerInspect
	if json.Unmarshal([]byte(inspect), &running) != nil || len(running.Mounts) != 1 {
		t.Fatal("actual Docker inspection is incomplete")
	}
	nonPort := running.nonPort()
	if f.nonPort == nil {
		if nonPort.User != "65532:65532" || !nonPort.ReadonlyRootfs || nonPort.Privileged || nonPort.PidsLimit != 64 {
			t.Fatal("initial Docker process confinement differs from the fixed fixture")
		}
		f.nonPort = &nonPort
	} else if !reflect.DeepEqual(*f.nonPort, nonPort) {
		t.Fatal("actual non-port Docker projection changed")
	}
	var node struct {
		ListenerSHA256 string `json:"listener_sha256"`
		ListenerDevice uint64 `json:"listener_device"`
		ListenerInode  uint64 `json:"listener_inode"`
	}
	client := &http.Client{Timeout: 2 * time.Second}
	if getDockerPortFixtureJSON(client, fmt.Sprintf("http://127.0.0.1:%d/config", observation.PublishedPort), &node) != nil {
		t.Fatal("actual Node listener identity observation is unavailable")
	}
	listenerPath := running.Mounts[0].Source
	listenerBytes := stPortChainDockerRead(t, listenerPath)
	info := stPortChainFileInfo(t, listenerPath)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || node.ListenerSHA256 != stPortChainDigest(listenerBytes) || node.ListenerDevice != uint64(stat.Dev) || node.ListenerInode != stat.Ino {
		t.Fatal("Docker process is not reading the verified listener inode and bytes")
	}
	return observation
}

type stPortChainDockerNonPort struct {
	Image, User, NetworkMode                           string
	Env, Entrypoint, Cmd, CapDrop, CapAdd, SecurityOpt []string
	ReadonlyRootfs, Privileged                         bool
	PidsLimit                                          int64
}

type stPortChainDockerInspect struct {
	Config struct {
		Image, User          string
		Env, Entrypoint, Cmd []string
	}
	HostConfig struct {
		NetworkMode                  string
		ReadonlyRootfs, Privileged   bool
		CapDrop, CapAdd, SecurityOpt []string
		PidsLimit                    int64
	}
	Mounts []struct{ Source string }
}

func (value stPortChainDockerInspect) nonPort() stPortChainDockerNonPort {
	return stPortChainDockerNonPort{Image: value.Config.Image, User: value.Config.User, Env: value.Config.Env,
		Entrypoint: value.Config.Entrypoint, Cmd: value.Config.Cmd, NetworkMode: value.HostConfig.NetworkMode,
		ReadonlyRootfs: value.HostConfig.ReadonlyRootfs, Privileged: value.HostConfig.Privileged, CapDrop: value.HostConfig.CapDrop,
		CapAdd: value.HostConfig.CapAdd, SecurityOpt: value.HostConfig.SecurityOpt, PidsLimit: value.HostConfig.PidsLimit}
}

func stPortChainDockerNodeHealthy(version string, published, container int, revision int64) bool {
	client := &http.Client{Timeout: time.Second}
	base := fmt.Sprintf("http://127.0.0.1:%d", published)
	var health struct {
		Status string `json:"status"`
	}
	var reported struct {
		Version        string `json:"version"`
		ServiceID      string `json:"service_id"`
		ServiceType    string `json:"service_type"`
		ConfigRevision int64  `json:"config_revision"`
	}
	var config struct {
		AdvertisedPort int   `json:"advertised_port"`
		ContainerPort  int   `json:"container_port"`
		ConfigRevision int64 `json:"config_revision"`
	}
	return getDockerPortFixtureJSON(client, base+"/health", &health) == nil && health.Status == "ok" &&
		getDockerPortFixtureJSON(client, base+"/updater/version", &reported) == nil && reported.Version == version && reported.ServiceID == "worker-smoke" && reported.ServiceType == "worker" && reported.ConfigRevision == revision &&
		getDockerPortFixtureJSON(client, base+"/config", &config) == nil && config.AdvertisedPort == 443 && config.ContainerPort == container && config.ConfigRevision == revision
}

func stPortChainDockerWatchUnhealthy(parent context.Context, target *contracts.SystemUpdatePortSnapshotRef) func() bool {
	ctx, cancel := context.WithCancel(parent)
	ready, finished := make(chan struct{}), make(chan bool, 1)
	go func() {
		client := &http.Client{Timeout: 250 * time.Millisecond}
		base := fmt.Sprintf("http://127.0.0.1:%d", target.Docker.PublishedPort)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		close(ready)
		for {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
			if err == nil {
				response, requestErr := client.Do(request)
				if requestErr == nil {
					status := response.StatusCode
					_ = response.Body.Close()
					var config struct {
						ContainerPort  int   `json:"container_port"`
						ConfigRevision int64 `json:"config_revision"`
					}
					if status == http.StatusServiceUnavailable && getDockerPortFixtureJSON(client, base+"/config", &config) == nil &&
						config.ContainerPort == target.Docker.ContainerPort && config.ConfigRevision == target.ConfigRevision {
						finished <- true
						return
					}
				}
			}
			select {
			case <-ctx.Done():
				finished <- false
				return
			case <-ticker.C:
			}
		}
	}()
	<-ready
	var result *bool
	return func() bool {
		if result == nil {
			cancel()
			observed := <-finished
			result = &observed
		}
		return *result
	}
}

func stPortChainDockerRegistry(t *testing.T) {
	t.Helper()
	addresses, err := net.LookupIP("ghcr.io")
	if err != nil || len(addresses) == 0 {
		t.Fatal("isolated registry identity is unavailable")
	}
	for _, address := range addresses {
		if !address.IsLoopback() {
			t.Fatal("Docker fixture refuses external registry resolution")
		}
	}
	ca := stPortChainDockerRead(t, "/etc/docker/certs.d/ghcr.io/ca.crt")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("isolated registry trust is unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("https://ghcr.io/v2/")
	if err != nil {
		t.Fatal("isolated registry did not pass normal TLS identity verification")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("isolated registry TLS/HTTP observation is invalid")
	}
}

func stPortChainDockerRun(t *testing.T, parent context.Context, stage, directory string, args ...string) string {
	t.Helper()
	switch stage {
	case "daemon_version", "compose_version", "empty_project", "fixture_push", "fixture_pull", "image_identity", "repository_identity", "compose_config", "initial_up", "runtime_inspect":
	default:
		t.Fatal("unlisted isolated Docker observation stage")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	started := time.Now()
	output, err := (OSCommandRunner{NewProcessGroup: true}).Run(ctx, directory, dockerCommandEnv(), "/usr/bin/docker", args...)
	exitStatus := 0
	if err != nil {
		exitStatus = -1
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitStatus = exitError.ExitCode()
		}
	}
	// One bounded, allowlisted record per command. Raw command output may
	// contain credentials and is never copied into public test diagnostics.
	t.Logf("ST-PORT Docker command: stage=%s exit=%d elapsed_ms=%d deadline_exceeded=%t", stage, exitStatus, time.Since(started).Milliseconds(), errors.Is(ctx.Err(), context.DeadlineExceeded))
	if err != nil {
		if stage == "fixture_push" {
			stPortChainDockerRegistryFailure(t, ctx, output)
		}
		for _, class := range []struct{ text, name string }{
			{"connection refused", "connection_refused"},
			{"x509:", "tls_validation_failed"},
			{"unauthorized", "authorization_failed"},
			{"unknown flag:", "unsupported_flag"},
			{"client version", "api_version_mismatch"},
			{"no such host", "dns_failed"},
			{"network is unreachable", "network_unreachable"},
			{"permission denied", "permission_denied"},
			{"no such file or directory", "file_missing"},
			{"read-only file system", "read_only_filesystem"},
		} {
			if strings.Contains(strings.ToLower(output), class.text) {
				t.Logf("ST-PORT Docker failure: class=%s", class.name)
			}
		}
		t.Fatal("isolated real Docker command failed at the recorded stage")
	}
	return output
}

func stPortChainDockerRegistryFailure(t *testing.T, ctx context.Context, output string) {
	t.Helper()
	// Classify only bounded network observations. Never emit URLs, addresses,
	// registry responses, authentication data or the original command output.
	for _, raw := range regexp.MustCompile(`https?://[^\s"<>]+`).FindAllString(output, 4) {
		endpoint, err := url.Parse(raw)
		if err == nil {
			t.Logf("ST-PORT Docker registry: expected_authority=%t tls=%t", endpoint.Hostname() == "ghcr.io", endpoint.Scheme == "https")
		}
	}
	for _, match := range regexp.MustCompile(`dial tcp (\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]+)`).FindAllStringSubmatch(output, 4) {
		address := net.ParseIP(strings.Trim(match[1], "[]"))
		if address != nil {
			t.Logf("ST-PORT Docker registry dial: ipv4=%t loopback=%t private=%t expected_port=%t", address.To4() != nil, address.IsLoopback(), address.IsPrivate(), match[2] == "443")
		}
	}
	pidText, err := (OSCommandRunner{NewProcessGroup: true}).Run(ctx, "", nil, "/usr/bin/systemctl", "show", "docker.service", "--property=MainPID", "--value")
	pid, parseErr := strconv.ParseUint(strings.TrimSpace(pidText), 10, 32)
	if err != nil || parseErr != nil || pid == 0 {
		t.Log("ST-PORT Docker registry: daemon_hosts_observed=false")
		return
	}
	file, err := os.Open(fmt.Sprintf("/proc/%d/root/etc/hosts", pid))
	if err != nil {
		t.Log("ST-PORT Docker registry: daemon_hosts_observed=false")
		return
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(body) > 8192 {
		t.Log("ST-PORT Docker registry: daemon_hosts_observed=false")
		return
	}
	found, loopbackOnly := false, true
	for _, line := range strings.Split(string(body), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, alias := range fields[1:] {
			if alias == "ghcr.io" {
				address := net.ParseIP(fields[0])
				found = true
				loopbackOnly = loopbackOnly && address != nil && address.IsLoopback()
			}
		}
	}
	t.Logf("ST-PORT Docker registry: daemon_hosts_observed=true alias_present=%t loopback_only=%t", found, found && loopbackOnly)
}

func stPortChainDockerRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 {
		t.Fatal("required Docker fixture observation file is unavailable")
	}
	return body
}
