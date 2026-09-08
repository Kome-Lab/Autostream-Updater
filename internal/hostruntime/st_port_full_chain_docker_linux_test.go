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
	// Initial Compose preparation needs the canonical state root before the root runtime starts.
	for _, directory := range []string{LocalExecutorMutationStateDir, "/opt/autostream", "/opt/autostream/local-executor/docker", "/opt/autostream/local-executor/docker/ports", "/etc/autostream-local-executor/docker"} {
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
	stPortChainDockerRunObserved(t, h.ctx, "initial_up", f.target.ProjectDir, func(ctx context.Context, output string, truncated bool) {
		f.observeInitialFailure(t, ctx, output, truncated)
	}, append(composeFrozenArgs(&f.target, execution.path), "up", "-d", "--no-deps", "--no-build", "--pull", "never", f.target.Service)...)
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
		t.Logf("ST-PORT Docker non-port equality: %v", stPortChainDockerNonPortEquality(*f.nonPort, nonPort))
		if !reflect.DeepEqual(f.nonPort.Env, nonPort.Env) {
			t.Logf("ST-PORT Docker Env comparison: %v", stPortChainDockerEnvComparison(f.nonPort.Env, nonPort.Env))
		}
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

// Only fixed field names and equality booleans may enter the public test log.
// DeepEqual deliberately retains sequence ordering and nil/empty distinctions.
func stPortChainDockerNonPortEquality(before, after stPortChainDockerNonPort) map[string]bool {
	return map[string]bool{
		"Image": before.Image == after.Image, "User": before.User == after.User,
		"NetworkMode": before.NetworkMode == after.NetworkMode,
		"Env":         reflect.DeepEqual(before.Env, after.Env), "Entrypoint": reflect.DeepEqual(before.Entrypoint, after.Entrypoint),
		"Cmd": reflect.DeepEqual(before.Cmd, after.Cmd), "CapDrop": reflect.DeepEqual(before.CapDrop, after.CapDrop),
		"CapAdd": reflect.DeepEqual(before.CapAdd, after.CapAdd), "SecurityOpt": reflect.DeepEqual(before.SecurityOpt, after.SecurityOpt),
		"ReadonlyRootfs": before.ReadonlyRootfs == after.ReadonlyRootfs, "Privileged": before.Privileged == after.Privileged,
		"PidsLimit": before.PidsLimit == after.PidsLimit,
	}
}

// Raw environment entries remain in this private in-memory comparison. Neither
// names nor values are returned, and these diagnostics never decide acceptance.
func stPortChainDockerEnvComparison(before, after []string) map[string]bool {
	parse := func(entries []string) (map[string]string, bool, bool) {
		values := make(map[string]string, len(entries))
		wellFormed, unique := true, true
		for _, entry := range entries {
			key, value, found := strings.Cut(entry, "=")
			if !found || key == "" || strings.ContainsRune(entry, '\x00') {
				wellFormed = false
				continue
			}
			if _, exists := values[key]; exists {
				unique = false
			}
			values[key] = value
		}
		return values, wellFormed, unique
	}
	left, leftValid, leftUnique := parse(before)
	right, rightValid, rightUnique := parse(after)
	keysEqual := leftValid && rightValid && len(left) == len(right)
	for key := range left {
		if _, exists := right[key]; !exists {
			keysEqual = false
		}
	}
	valuesEqual := keysEqual && leftUnique && rightUnique
	for key, value := range left {
		if value != right[key] {
			valuesEqual = false
		}
	}
	orderEqual := len(before) == len(after)
	if orderEqual {
		for i := range before {
			if before[i] != after[i] {
				orderEqual = false
			}
		}
	}
	return map[string]bool{
		"before_well_formed": leftValid, "after_well_formed": rightValid,
		"before_unique_keys": leftUnique, "after_unique_keys": rightUnique,
		"key_set_equal": keysEqual, "values_equal": valuesEqual, "order_equal": orderEqual,
		"nilness_equal": (before == nil) == (after == nil), "emptiness_equal": (len(before) == 0) == (len(after) == 0),
	}
}

func TestSTPortDockerEnvDiagnosticSeparatesContentOrderAndRepresentation(t *testing.T) {
	base := []string{"A=1", "B=two=3"}
	for _, test := range []struct {
		name          string
		before, after []string
		falseFields   []string
	}{
		{"same", base, base, nil},
		{"order_only", base, []string{"B=two=3", "A=1"}, []string{"order_equal"}},
		{"value", base, []string{"A=changed", "B=two=3"}, []string{"values_equal", "order_equal"}},
		{"key", base, []string{"C=1", "B=two=3"}, []string{"key_set_equal", "values_equal", "order_equal"}},
		{"duplicate_before", []string{"A=1", "A=1", "B=two=3"}, base, []string{"before_unique_keys", "values_equal", "order_equal"}},
		{"duplicate_after", base, []string{"A=1", "B=two=3", "A=1"}, []string{"after_unique_keys", "values_equal", "order_equal"}},
		{"malformed_before", []string{"A", "B=two=3"}, base, []string{"before_well_formed", "key_set_equal", "values_equal", "order_equal"}},
		{"malformed_after", base, []string{"A=1", "=two=3"}, []string{"after_well_formed", "key_set_equal", "values_equal", "order_equal"}},
		{"nil_empty", nil, []string{}, []string{"nilness_equal"}},
		{"both_nil", nil, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := stPortChainDockerEnvComparison(test.before, test.after)
			if len(facts) != 9 {
				t.Fatal("environment diagnostic inventory changed")
			}
			for field, actual := range facts {
				want := true
				for _, unequal := range test.falseFields {
					if field == unequal {
						want = false
					}
				}
				if actual != want {
					t.Fatal("environment diagnostic did not separate the injected difference")
				}
			}
			if test.name != "same" && test.name != "both_nil" && reflect.DeepEqual(test.before, test.after) {
				t.Fatal("diagnostic normalized an unequal environment")
			}
		})
	}
}

func TestSTPortDockerNonPortDiagnosticRetainsExactComparison(t *testing.T) {
	before := stPortChainDockerNonPort{Image: "fixture-image", User: "65532:65532", NetworkMode: "fixture-network",
		Env: []string{"FIRST=1", "SECOND=2"}, Entrypoint: []string{"fixture-entry"}, Cmd: []string{"fixture-command"},
		CapDrop: []string{"ALL"}, CapAdd: []string{}, SecurityOpt: []string{"no-new-privileges:true"}, ReadonlyRootfs: true, PidsLimit: 64}
	for _, test := range []struct {
		name, field string
		mutate      func(*stPortChainDockerNonPort)
	}{
		{"image", "Image", func(v *stPortChainDockerNonPort) { v.Image = "changed" }},
		{"user", "User", func(v *stPortChainDockerNonPort) { v.User = "changed" }},
		{"network", "NetworkMode", func(v *stPortChainDockerNonPort) { v.NetworkMode = "changed" }},
		{"env", "Env", func(v *stPortChainDockerNonPort) { v.Env = []string{"CHANGED=1"} }},
		{"env_order", "Env", func(v *stPortChainDockerNonPort) { v.Env = []string{"SECOND=2", "FIRST=1"} }},
		{"entrypoint", "Entrypoint", func(v *stPortChainDockerNonPort) { v.Entrypoint = nil }},
		{"command", "Cmd", func(v *stPortChainDockerNonPort) { v.Cmd = nil }},
		{"cap_drop", "CapDrop", func(v *stPortChainDockerNonPort) { v.CapDrop = nil }},
		{"cap_add", "CapAdd", func(v *stPortChainDockerNonPort) { v.CapAdd = []string{"CHOWN"} }},
		{"nil_empty", "CapAdd", func(v *stPortChainDockerNonPort) { v.CapAdd = nil }},
		{"security", "SecurityOpt", func(v *stPortChainDockerNonPort) { v.SecurityOpt = nil }},
		{"readonly", "ReadonlyRootfs", func(v *stPortChainDockerNonPort) { v.ReadonlyRootfs = false }},
		{"privileged", "Privileged", func(v *stPortChainDockerNonPort) { v.Privileged = true }},
		{"pids", "PidsLimit", func(v *stPortChainDockerNonPort) { v.PidsLimit++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			after := before
			test.mutate(&after)
			if reflect.DeepEqual(before, after) {
				t.Fatal("changed non-port projection was accepted")
			}
			equality := stPortChainDockerNonPortEquality(before, after)
			if len(equality) != 12 {
				t.Fatal("diagnostic field inventory changed")
			}
			for field, equal := range equality {
				if equal != (field != test.field) {
					t.Fatal("diagnostic did not identify the exact changed field")
				}
			}
		})
	}
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
	return stPortChainDockerRunObserved(t, parent, stage, directory, nil, args...)
}

func stPortChainDockerRunObserved(t *testing.T, parent context.Context, stage, directory string, onFailure func(context.Context, string, bool), args ...string) string {
	t.Helper()
	switch stage {
	case "daemon_version", "compose_version", "empty_project", "fixture_push", "fixture_pull", "image_identity", "repository_identity", "compose_config", "initial_up", "runtime_inspect":
	default:
		t.Fatal("unlisted isolated Docker observation stage")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	started := time.Now()
	output, truncated, err := (OSCommandRunner{NewProcessGroup: true}).runWithOutputMetadata(ctx, directory, dockerCommandEnv(), "/usr/bin/docker", args...)
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
		t.Log("ST-PORT Docker failure evidence: " + stPortChainDockerOutputEvidence(output, truncated, false).summary())
		if stage == "fixture_push" {
			stPortChainDockerRegistryFailure(t, ctx, output)
		}
		if onFailure != nil {
			// Observations get one separate ten-second read-only budget. They do
			// not retry the failed command or extend its execution deadline.
			observationCtx, observationCancel := context.WithTimeout(parent, 10*time.Second)
			onFailure(observationCtx, output, truncated)
			observationCancel()
		}
		t.Fatal("isolated real Docker command failed at the recorded stage")
	}
	return output
}

func stPortChainDockerRegistryFailure(t *testing.T, ctx context.Context, output string) {
	t.Helper()
	// Classify only bounded network observations. Never emit URLs, addresses,
	// registry responses, authentication data or the original command output.
	lowerOutput := strings.ToLower(output)
	t.Logf("ST-PORT Docker registry error shape: lookup=%t proxyconnect=%t dial_tcp=%t dial_udp=%t", strings.Contains(lowerOutput, "lookup "), strings.Contains(lowerOutput, "proxyconnect"), strings.Contains(lowerOutput, "dial tcp"), strings.Contains(lowerOutput, "dial udp"))
	lookupNamePattern := regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	for _, match := range regexp.MustCompile(`\blookup(?:[ \t]+([^ \t\r\n]+))?`).FindAllStringSubmatch(lowerOutput, 4) {
		name := strings.TrimSuffix(strings.TrimSuffix(match[1], ":"), ".")
		lookupClass := "unparsed"
		if name == "ghcr.io" {
			lookupClass = "expected_authority"
		} else if len(name) <= 253 && lookupNamePattern.MatchString(name) {
			lookupClass = "other_authority"
		}
		t.Logf("ST-PORT Docker registry lookup: class=%s", lookupClass)
	}
	for _, raw := range regexp.MustCompile(`https?://[^\s"<>]+`).FindAllString(output, 4) {
		endpoint, err := url.Parse(raw)
		if err == nil {
			t.Logf("ST-PORT Docker registry: expected_authority=%t tls=%t", endpoint.Hostname() == "ghcr.io", endpoint.Scheme == "https")
		}
	}
	// A resolver failure can say "dial tcp: lookup ... dial udp ...".
	// Classify at most four operation endpoints, including UDP destinations;
	// a missing or non-IP endpoint contributes only to the bounded count.
	matches := regexp.MustCompile(`\b(?:dial|read|write) (tcp[46]?|udp[46]?)(?::)?(?:[ \t]+([^ \t\r\n]+))?`).FindAllStringSubmatch(output, 5)
	limitReached := len(matches) > 4
	if limitReached {
		matches = matches[:4]
	}
	endpointCount, unparsedCount := 0, 0
	for _, match := range matches {
		rawEndpoint := match[2]
		if _, destination, found := strings.Cut(rawEndpoint, "->"); found {
			rawEndpoint = destination
		}
		host, port, splitErr := net.SplitHostPort(strings.TrimSuffix(rawEndpoint, ":"))
		host, _, _ = strings.Cut(host, "%")
		address := net.ParseIP(host)
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if splitErr != nil || address == nil || portErr != nil {
			unparsedCount++
			continue
		}
		protocol := "tcp"
		if strings.HasPrefix(match[1], "udp") {
			protocol = "udp"
		}
		portClass := "other"
		switch portNumber {
		case 443:
			portClass = "443"
		case 53:
			portClass = "53"
		}
		endpointCount++
		t.Logf("ST-PORT Docker registry dial: protocol=%s ipv4=%t loopback=%t private=%t unspecified=%t expected_port=%t port_class=%s", protocol, address.To4() != nil, address.IsLoopback(), address.IsPrivate(), address.IsUnspecified(), portNumber == 443, portClass)
	}
	t.Logf("ST-PORT Docker registry endpoints: observed=%d unparsed=%d limit_reached=%t", endpointCount, unparsedCount, limitReached)
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
