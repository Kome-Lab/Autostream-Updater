//go:build linux

package hostruntime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	dockerPortDaemonSmokeEnv        = "AUTOSTREAM_DOCKER_PORT_DAEMON_SMOKE"
	dockerPortDaemonSmokeMountNSEnv = "AUTOSTREAM_DOCKER_PORT_DAEMON_SMOKE_MOUNT_NS"
	dockerPortDaemonSmokeChildEnv   = "AUTOSTREAM_DOCKER_PORT_DAEMON_SMOKE_CHILD"
	dockerPortDaemonSmokePayloadEnv = "AUTOSTREAM_DOCKER_PORT_DAEMON_SMOKE_PAYLOAD"
	dockerPortDaemonSmokeGrantEnv   = "AUTOSTREAM_DOCKER_PORT_DAEMON_SMOKE_GRANT"
	dockerPortDaemonSmokeFixtureEnv = "AUTOSTREAM_DOCKER_PORT_FIXTURE_BINARY"
	dockerPortDaemonSmokeGrant      = "docker-port-smoke-one-time-grant"
	dockerPortDaemonSmokeCrashExit  = 86
	dockerPortDaemonSmokeOwnerFile  = ".docker-port-smoke-owner"

	dockerPortSmokeProjectDir = "/opt/autostream"
	dockerPortSmokePolicyPath = "/etc/autostream/updater/executor-policy.json"
	dockerPortSmokeImageRepo  = "ghcr.io/kome-lab/autostream-docker/worker"
)

type dockerPortSmokeState struct {
	advertisedPort   int
	publishedPort    int
	containerPort    int
	endpointRevision int64
	configRevision   int64
	configSHA256     string
}

type dockerPortSmokeChildPayload struct {
	Plan               SystemdPortReconfigurePlan `json:"plan"`
	Operation          string                     `json:"operation"`
	StateDir           string                     `json:"state_dir"`
	CaptureDir         string                     `json:"capture_dir"`
	ImageID            string                     `json:"image_id"`
	RepositoryDigest   string                     `json:"repository_digest"`
	ResponsePath       string                     `json:"response_path"`
	GrantRecordPath    string                     `json:"grant_record_path"`
	ExpectGrant        bool                       `json:"expect_grant"`
	CrashAfterRecreate bool                       `json:"crash_after_recreate"`
	CrashPhase         string                     `json:"crash_phase,omitempty"`
}

// TestDockerPortDaemonSmoke is intentionally a Linux/root integration test.
// It runs the same root-side handler, fixed policy, file ledger and Compose
// transaction used by the Local Executor. The only simulated daemon fact is a
// canonical RepoDigest for the locally built, network-free scratch image.
func TestDockerPortDaemonSmoke(t *testing.T) {
	if os.Getenv(dockerPortDaemonSmokeEnv) != "1" {
		t.Skip(dockerPortDaemonSmokeEnv + "=1 is required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("Docker port daemon smoke requires root")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("Docker port daemon smoke requires Linux")
	}
	prepareDockerPortSmokeMountNamespace(t)
	if _, err := os.Stat("/usr/bin/docker"); err != nil {
		t.Fatalf("/usr/bin/docker is unavailable: %v", err)
	}
	baseRunner := OSCommandRunner{NewProcessGroup: true}
	mustDockerPortSmokeRun(
		t, baseRunner, "", "/usr/bin/docker",
		"version", "--format", "{{.Server.Version}}",
	)
	mustDockerPortSmokeRun(
		t, baseRunner, "", "/usr/bin/docker",
		"compose", "version",
	)
	proveDockerAutoConfigureFailsClosed(t)
	proveDockerTransientCleanup(t)

	for _, port := range []int{18081, 18083, 18084, 18085, 18086, 18087} {
		requireDockerPortSmokePortAvailable(t, port)
	}
	requireDockerPortSmokeHostClean(t, baseRunner)
	writeDockerPortSmokeFile(
		t,
		filepath.Join(os.TempDir(), dockerPortDaemonSmokeOwnerFile),
		[]byte("github-actions-docker-port-smoke\n"),
	)
	hardenDockerPortSmokeProjectParent(t)

	// /opt is a private tmpfs in this namespace. /var/lib is shared with
	// the actual Docker daemon, so its bind source sees the same inode.
	stateDir, err := os.MkdirTemp("/var/lib", "autostream-docker-port-smoke-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	captureDir := filepath.Join(stateDir, "frozen-captures")
	if err := os.Mkdir(captureDir, 0o700); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	image := dockerPortSmokeImageRepo + ":port-smoke-" + suffix
	foreignContainer := "autostream-port-foreign-" + suffix
	runDirExisted := pathExists(privilegedLockDir())
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			cleanupDockerPortSmokeEnvironment(
				t, baseRunner, image, foreignContainer, runDirExisted,
			)
			cleanupDockerPortSmokeListeners(t, baseRunner, stateDir, foreignContainer)
		}
	})

	buildDockerPortFixtureImage(t, image)
	imageID := strings.ToLower(strings.TrimSpace(mustDockerPortSmokeRun(
		t, baseRunner, "", "/usr/bin/docker",
		"image", "inspect", "--format={{.Id}}", image,
	)))
	if !digestPattern.MatchString(imageID) {
		t.Fatalf("fixture image ID is not canonical: %q", imageID)
	}
	repositoryDigest := imageID
	setupDockerPortSmokeRoot(t, image, imageID)

	initialPortEnv, err := os.ReadFile(
		"/opt/autostream/local-executor/docker/ports/worker.env",
	)
	if err != nil {
		t.Fatal(err)
	}
	versionEnv, err := os.ReadFile(
		"/opt/autostream/local-executor/docker/worker.env",
	)
	if err != nil {
		t.Fatal(err)
	}
	versionEnvSHA256 := dockerPortSmokeSHA256(versionEnv)

	dockerTarget := dockerPortSmokeTarget()
	rawCompose := mustDockerPortSmokeRun(
		t, baseRunner, dockerPortSmokeProjectDir, "/usr/bin/docker",
		append(
			composeArgs(&dockerTarget, ""),
			"config", "--format", "json", "--no-env-resolution",
		)...,
	)
	composePolicySHA256, err := dockerPortComposePolicyHash(
		[]byte(rawCompose), &dockerTarget,
	)
	if err != nil {
		t.Fatal(err)
	}
	composeConfigSHA256, err := composeModelHash(
		[]byte(rawCompose), dockerTarget.Service,
	)
	if err != nil {
		t.Fatal(err)
	}
	dockerTarget.PortComposePolicySHA256 = composePolicySHA256
	dockerTarget.ComposeConfigSHA256 = composeConfigSHA256
	adapter, err := dockerPortAdapterFor("worker", &dockerTarget)
	if err != nil {
		t.Fatal(err)
	}
	runner := newDockerPortSmokeRunner(t, imageID, repositoryDigest, captureDir, adapter)
	workRoot := filepath.Join(stateDir, "docker-work")
	if err := ensureDockerPortWorkDirectory(workRoot, true); err != nil {
		t.Fatal(err)
	}
	initialWork, err := os.MkdirTemp(workRoot, dockerPortRecreatePrefix)
	if err != nil {
		t.Fatal(err)
	}
	initialCanonical := filepath.Join(initialWork, "compose-frozen.json")
	writeDockerPortSmokeFile(t, initialCanonical, []byte(rawCompose))
	listenerStore := defaultDockerNodeListenerStore()
	listenerStore.root = filepath.Join(stateDir, "docker-listener-configs")
	initialExecution, err := listenerStore.freeze(initialCanonical, &dockerTarget)
	if err != nil {
		t.Fatal(err)
	}
	if err := listenerStore.validateFrozen(initialExecution, &dockerTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), dockerPortSmokeProjectDir, dockerCommandEnv(), "/usr/bin/docker",
		append(composeFrozenArgs(&dockerTarget, initialExecution.path), "up", "-d", "--no-deps", "--no-build", "--pull", "never", dockerTarget.Service)...); err != nil {
		t.Fatal(err)
	}
	if err := secureRemoveDockerPortTransient(workRoot, initialWork, true); err != nil {
		t.Fatal(err)
	}
	waitForDockerPortFixture(t, 18081, 443, 8080, 1, false)
	initialContainerID := dockerPortSmokeContainerID(t, baseRunner)
	assertDockerPortFixtureBoundary(t, baseRunner, initialContainerID, 18081, 8080, listenerStore.root)

	policy := LocalExecutorPolicy{
		SchemaVersion:        LocalExecutorMutationPolicySchemaVersion,
		ProtocolVersion:      LocalExecutorMutationProtocolVersion,
		HostID:               "host-docker-smoke",
		AgentUID:             1001,
		AgentGID:             1001,
		SocketPath:           LocalExecutorSocketPath,
		SourcePolicyRevision: 11,
		ProjectionRevision:   12,
		PolicyRevision:       13,
		Mutation: &LocalExecutorMutationPolicy{
			PanelURL: "https://panel.example.com",
		},
		Targets: []LocalExecutorTarget{{
			ServiceID:        "worker-smoke",
			ServiceType:      "worker",
			DeploymentMode:   ModeDocker,
			EndpointRevision: 1,
			ConfigRevision:   1,
			ConfigSHA256:     dockerPortEnvSHA256(initialPortEnv),
			LocalListen: LocalExecutorEndpoint{
				Host: "127.0.0.1",
				Port: 18081,
			},
			Docker: &dockerTarget,
		}},
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("fixture policy: %v", err)
	}
	writeDockerPortSmokeJSON(t, dockerPortSmokePolicyPath, policy)
	loadedPolicy, err := LoadLocalExecutorPolicy(dockerPortSmokePolicyPath, true)
	if err != nil {
		t.Fatalf("reload root policy: %v", err)
	}
	if _, err := securePrivilegedTarget(
		loadedPolicy.Targets[0].runtimeTarget(loadedPolicy.HostID),
	); err != nil {
		t.Fatalf("secure Docker target preflight: %v", err)
	}

	current := newDockerPortSmokeState(t, adapter, 443, 18081, 8080, 1, 1)
	if current.configSHA256 != dockerPortEnvSHA256(initialPortEnv) {
		t.Fatal("initial root policy and port sidecar differ")
	}
	// First real transaction: advertised, published and container ports remain
	// independent. The public endpoint stays 443 while both local Docker ports
	// move.
	first := newDockerPortSmokeState(t, adapter, 443, 18083, 18080, 2, 2)
	firstPlan := dockerPortSmokePlan(
		t, policy, current, first, "job-docker-smoke-first",
		dockerPortSmokeContainerID(t, baseRunner),
		imageID, repositoryDigest, versionEnvSHA256,
	)
	firstResponse, firstGrants := runDockerPortSmokeMutation(
		t, runner, stateDir, firstPlan, "port_reconfigure", nil,
	)
	assertDockerPortSmokeApplied(t, firstResponse, firstPlan)
	if firstGrants != 1 {
		t.Fatalf("first mutation grant calls=%d", firstGrants)
	}
	waitForDockerPortFixture(t, first.publishedPort, 443, first.containerPort, first.configRevision, false)
	assertDockerPortSmokeDurableState(t, stateDir, adapter, first, firstPlan)
	current = first

	// A second sequential mutation proves that the durable applied overlay, not
	// the unchanged root projection, becomes the next baseline.
	second := newDockerPortSmokeState(t, adapter, 443, 18084, 19080, 3, 3)
	secondPlan := dockerPortSmokePlan(
		t, policy, current, second, "job-docker-smoke-second",
		dockerPortSmokeContainerID(t, baseRunner),
		imageID, repositoryDigest, versionEnvSHA256,
	)
	secondResponse, secondGrants := runDockerPortSmokeMutation(
		t, runner, stateDir, secondPlan, "port_reconfigure", nil,
	)
	assertDockerPortSmokeApplied(t, secondResponse, secondPlan)
	if secondGrants != 1 {
		t.Fatalf("second mutation grant calls=%d", secondGrants)
	}
	waitForDockerPortFixture(t, second.publishedPort, 443, second.containerPort, second.configRevision, false)
	assertDockerPortSmokeDurableState(t, stateDir, adapter, second, secondPlan)
	current = second

	// The third mutation exits the executor process after the real Compose
	// recreate and durable ledger write. A fresh process must reconcile from
	// disk without consuming the one-time grant again.
	recreated := newDockerPortSmokeState(t, adapter, 443, 18085, 20080, 4, 4)
	recreatedPlan := dockerPortSmokePlan(
		t, policy, current, recreated, "job-docker-smoke-recreated",
		dockerPortSmokeContainerID(t, baseRunner),
		imageID, repositoryDigest, versionEnvSHA256,
	)
	crashGrantRecord := filepath.Join(stateDir, "crash-grant.json")
	runDockerPortSmokeChild(t, dockerPortSmokeChildPayload{
		Plan: recreatedPlan, Operation: "port_reconfigure",
		StateDir: stateDir, CaptureDir: captureDir,
		ImageID: imageID, RepositoryDigest: repositoryDigest,
		GrantRecordPath: crashGrantRecord,
		ExpectGrant:     true, CrashAfterRecreate: true,
	}, true)
	var crashBinding MutationGrantBinding
	readDockerPortSmokeJSON(t, crashGrantRecord, &crashBinding)
	if err := validateDockerPortSmokeGrantBinding(
		recreatedPlan, "port_reconfigure",
		"https://panel.example.com", recreatedPlan.JobID,
		dockerPortDaemonSmokeGrant, crashBinding,
	); err != nil {
		t.Fatal(err)
	}
	waitForDockerPortFixture(
		t, recreated.publishedPort, 443, recreated.containerPort,
		recreated.configRevision, false,
	)
	assertDockerPortSmokeWorkDirEmpty(t, stateDir)

	reconcileResponsePath := filepath.Join(stateDir, "reconcile-response.json")
	reconcileGrantRecord := filepath.Join(stateDir, "reconcile-grant.json")
	runDockerPortSmokeChild(t, dockerPortSmokeChildPayload{
		Plan: recreatedPlan, Operation: "port_reconfigure_reconcile",
		StateDir: stateDir, CaptureDir: captureDir,
		ImageID: imageID, RepositoryDigest: repositoryDigest,
		ResponsePath:    reconcileResponsePath,
		GrantRecordPath: reconcileGrantRecord,
		ExpectGrant:     false,
	}, false)
	var reconciled LocalExecutorResponse
	readDockerPortSmokeJSON(t, reconcileResponsePath, &reconciled)
	assertDockerPortSmokeApplied(t, reconciled, recreatedPlan)
	if pathExists(reconcileGrantRecord) {
		t.Fatal("fresh reconcile process consumed the mutation grant twice")
	}
	assertDockerPortSmokeDurableState(t, stateDir, adapter, recreated, recreatedPlan)
	current = recreated

	// Container port 21080 is a fixed unhealthy fixture condition. The real
	// post-recreate HTTP verification must reject it and restore the exact
	// prior mapping.
	unhealthy := newDockerPortSmokeState(t, adapter, 443, 18086, 21080, 5, 5)
	unhealthyPlan := dockerPortSmokePlan(
		t, policy, current, unhealthy, "job-docker-smoke-unhealthy",
		dockerPortSmokeContainerID(t, baseRunner),
		imageID, repositoryDigest, versionEnvSHA256,
	)
	rollbackResponse, rollbackGrants := observeDockerPortSmokeUnhealthyMutation(
		t, runner, unhealthyPlan, func(scope *dockerPortSmokeLegacyDiagnostic) (LocalExecutorResponse, int) {
			return runDockerPortSmokeMutation(t, runner, stateDir, unhealthyPlan, "port_reconfigure", nil, scope)
		},
	)
	assertDockerPortSmokeRolledBack(t, rollbackResponse, unhealthyPlan)
	if rollbackGrants != 1 {
		t.Fatalf("rollback mutation grant calls=%d", rollbackGrants)
	}
	waitForDockerPortFixture(
		t, current.publishedPort, 443, current.containerPort,
		current.configRevision, false,
	)
	current.endpointRevision = rollbackResponse.PortResult.EndpointRevision
	assertDockerPortSmokeDurableState(t, stateDir, adapter, current, unhealthyPlan)

	// A foreign container owns the proposed loopback port. The production
	// availability check must reject it before grant consumption or any write.
	startDockerPortSmokeForeignContainer(
		t, baseRunner, image, foreignContainer, stateDir, 18087, 22080,
	)
	foreign := newDockerPortSmokeState(
		t, adapter, 443, 18087, 22080,
		current.endpointRevision+1, current.configRevision+1,
	)
	foreignPlan := dockerPortSmokePlan(
		t, policy, current, foreign, "job-docker-smoke-foreign",
		dockerPortSmokeContainerID(t, baseRunner),
		imageID, repositoryDigest, versionEnvSHA256,
	)
	beforeForeignContainer := dockerPortSmokeContainerID(t, baseRunner)
	foreignResponse, foreignGrants := runDockerPortSmokeMutation(
		t, runner, stateDir, foreignPlan, "port_reconfigure", nil,
	)
	if foreignResponse.Error == nil ||
		foreignResponse.Error.Code != "mutation_precondition_failed" {
		t.Fatalf("foreign-owner response=%+v", foreignResponse)
	}
	if foreignGrants != 0 {
		t.Fatalf("foreign-owner rejection consumed %d grants", foreignGrants)
	}
	if got := dockerPortSmokeContainerID(t, baseRunner); got != beforeForeignContainer {
		t.Fatal("foreign-owner rejection recreated the managed container")
	}
	assertDockerPortSmokeSidecar(t, adapter, current)
	waitForDockerPortFixture(
		t, current.publishedPort, 443, current.containerPort,
		current.configRevision, false,
	)
	mustDockerPortSmokeRun(
		t, baseRunner, "", "/usr/bin/docker",
		"rm", "-f", foreignContainer,
	)

	if runner.repoDigestCalls() == 0 {
		t.Fatal("production baseline did not inspect immutable image identity")
	}
	if !t.Run("st_port_v2", func(t *testing.T) {
		current = runSTPortDockerDaemonSequence(t, runner, baseRunner, stateDir, captureDir, policy, current, imageID, repositoryDigest, versionEnvSHA256)
	}) {
		t.FailNow()
	}
	// Reopen the same retained generation through a fresh container process,
	// then a restarted daemon. The shared absolute source must remain usable.
	restartContainer := dockerPortSmokeContainerID(t, baseRunner)
	mustDockerPortSmokeRun(t, baseRunner, "", "/usr/bin/docker", "restart", restartContainer)
	waitForDockerPortFixture(t, current.publishedPort, 443, current.containerPort, current.configRevision, false)
	assertDockerPortFixtureBoundary(t, baseRunner, restartContainer, current.publishedPort, current.containerPort, listenerStore.root)
	mustDockerPortSmokeRun(t, baseRunner, "", "/usr/bin/systemctl", "restart", "docker")
	mustDockerPortSmokeRun(t, baseRunner, "", "/usr/bin/docker", "start", restartContainer)
	waitForDockerPortFixture(t, current.publishedPort, 443, current.containerPort, current.configRevision, false)
	assertDockerPortFixtureBoundary(t, baseRunner, restartContainer, current.publishedPort, current.containerPort, listenerStore.root)
	assertDockerPortSmokeFrozenCaptures(t, captureDir)
	assertDockerPortSmokeWorkDirEmpty(t, stateDir)

	cleanupDockerPortSmokeEnvironment(
		t, baseRunner, image, foreignContainer, runDirExisted,
	)
	cleanupDockerPortSmokeListeners(t, baseRunner, stateDir, foreignContainer)
	cleaned = true
	requireDockerPortSmokeHostClean(t, baseRunner)
}
