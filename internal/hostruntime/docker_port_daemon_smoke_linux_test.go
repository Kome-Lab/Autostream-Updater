//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
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
	dockerPortSmokePolicyPath = "/etc/autostream-local-executor/policy.json"
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

	stateDir := t.TempDir()
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
	mustDockerPortSmokeRun(
		t, baseRunner, dockerPortSmokeProjectDir, "/usr/bin/docker",
		append(
			composeArgs(&dockerTarget, ""),
			"up", "-d", "--no-deps", "--no-build", "--pull", "never",
			dockerTarget.Service,
		)...,
	)
	waitForDockerPortFixture(t, 18081, 443, 8080, 1, false)
	initialContainerID := dockerPortSmokeContainerID(t, baseRunner)
	assertDockerPortFixtureBoundary(t, baseRunner, initialContainerID, 18081, 8080)

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

	adapter, err := dockerPortAdapterFor("worker", &dockerTarget)
	if err != nil {
		t.Fatal(err)
	}
	current := newDockerPortSmokeState(t, adapter, 443, 18081, 8080, 1, 1)
	if current.configSHA256 != dockerPortEnvSHA256(initialPortEnv) {
		t.Fatal("initial root policy and port sidecar differ")
	}
	runner := newDockerPortSmokeRunner(
		t, imageID, repositoryDigest, captureDir, adapter,
	)

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
	rollbackResponse, rollbackGrants := runDockerPortSmokeMutation(
		t, runner, stateDir, unhealthyPlan, "port_reconfigure", nil,
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
		t, baseRunner, image, foreignContainer, 18087, 22080,
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
	assertDockerPortSmokeFrozenCaptures(t, captureDir)
	assertDockerPortSmokeWorkDirEmpty(t, stateDir)

	cleanupDockerPortSmokeEnvironment(
		t, baseRunner, image, foreignContainer, runDirExisted,
	)
	cleaned = true
	requireDockerPortSmokeHostClean(t, baseRunner)
}

func TestDockerPortDaemonSmokeChild(t *testing.T) {
	if os.Getenv(dockerPortDaemonSmokeChildEnv) != "1" {
		t.Skip("Docker port daemon smoke child only")
	}
	var payload dockerPortSmokeChildPayload
	readDockerPortSmokeJSON(
		t, os.Getenv(dockerPortDaemonSmokePayloadEnv), &payload,
	)
	policy, err := LoadLocalExecutorPolicy(dockerPortSmokePolicyPath, true)
	if err != nil {
		t.Fatalf("load child root policy: %v", err)
	}
	adapter, err := dockerPortAdapterFor(
		"worker", policy.Targets[0].Docker,
	)
	if err != nil {
		t.Fatal(err)
	}
	runner := newDockerPortSmokeRunner(
		t, payload.ImageID, payload.RepositoryDigest,
		payload.CaptureDir, adapter,
	)
	grantCalls := 0
	remoteRuntime := executorMutationRuntime{
		platformOS:    "linux",
		localStateDir: payload.StateDir,
		runner:        runner,
		consumeGrant: func(
			_ context.Context,
			panelURL, jobID, grant string,
			binding MutationGrantBinding,
			_ *http.Client,
		) error {
			grantCalls++
			if err := validateDockerPortSmokeGrantBinding(
				payload.Plan, payload.Operation,
				panelURL, jobID, grant, binding,
			); err != nil {
				return err
			}
			writeDockerPortSmokeJSON(
				t, payload.GrantRecordPath, binding,
			)
			return nil
		},
	}
	if payload.CrashAfterRecreate {
		remoteRuntime.dockerPortCrashPointForTest = func(point string) error {
			if point == "after_docker_recreate" {
				os.Exit(dockerPortDaemonSmokeCrashExit)
			}
			return nil
		}
	}
	request := dockerPortSmokeRequest(payload.Plan, payload.Operation)
	request.MutationGrant = NewBoundedSecret(
		os.Getenv(dockerPortDaemonSmokeGrantEnv),
	)
	response := handleLocalExecutorMutation(
		context.Background(),
		policy,
		request,
		remoteRuntime,
	)
	if payload.ExpectGrant != (grantCalls == 1) {
		t.Fatalf(
			"child grant calls=%d expect_grant=%t",
			grantCalls, payload.ExpectGrant,
		)
	}
	if payload.ResponsePath == "" {
		t.Fatal("child returned without a response path")
	}
	writeDockerPortSmokeJSON(t, payload.ResponsePath, response)
}

type dockerPortSmokeRunner struct {
	base             OSCommandRunner
	imageID          string
	repositoryDigest string
	captureDir       string
	adapter          dockerPortAdapter

	mu              sync.Mutex
	repositoryCalls int
}

func newDockerPortSmokeRunner(
	t *testing.T,
	imageID, repositoryDigest, captureDir string,
	adapter dockerPortAdapter,
) *dockerPortSmokeRunner {
	t.Helper()
	if !digestPattern.MatchString(imageID) ||
		!digestPattern.MatchString(repositoryDigest) ||
		!filepath.IsAbs(captureDir) {
		t.Fatal("Docker port smoke runner identity is invalid")
	}
	return &dockerPortSmokeRunner{
		base:    OSCommandRunner{NewProcessGroup: true},
		imageID: imageID, repositoryDigest: repositoryDigest,
		captureDir: captureDir, adapter: adapter,
	}
}

func (r *dockerPortSmokeRunner) Run(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (string, error) {
	if len(args) == 4 &&
		args[0] == "image" &&
		args[1] == "inspect" &&
		args[2] == "--format={{json .RepoDigests}}" &&
		strings.EqualFold(args[3], r.imageID) {
		r.mu.Lock()
		r.repositoryCalls++
		r.mu.Unlock()
		raw, _ := json.Marshal([]string{
			dockerPortSmokeImageRepo + "@" + r.repositoryDigest,
		})
		return string(raw), nil
	}
	frozenPath := dockerPortSmokeFrozenComposePath(args)
	if frozenPath != "" {
		capturePath := filepath.Join(
			r.captureDir,
			fmt.Sprintf(
				"compose-frozen-%d-%d.json",
				os.Getpid(), time.Now().UnixNano(),
			),
		)
		if err := os.Link(frozenPath, capturePath); err != nil {
			return "", fmt.Errorf("capture frozen Compose inode: %w", err)
		}
	}
	output, err := r.base.Run(ctx, dir, env, name, args...)
	if err == nil && frozenPath != "" {
		body, readErr := os.ReadFile(r.adapter.PortEnvFile)
		if readErr != nil {
			return output, readErr
		}
		publishedPort, _, _, parseErr := parseDockerPortEnv(
			r.adapter, body,
		)
		if parseErr != nil {
			return output, parseErr
		}
		if waitErr := waitForDockerPortTCP(ctx, publishedPort); waitErr != nil {
			return output, waitErr
		}
	}
	return output, err
}

func (r *dockerPortSmokeRunner) repoDigestCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.repositoryCalls
}

func dockerPortSmokeFrozenComposePath(args []string) string {
	hasUp := false
	frozenPath := ""
	for index := range args {
		if args[index] == "up" {
			hasUp = true
		}
		if args[index] == "-f" && index+1 < len(args) {
			candidate := args[index+1]
			if filepath.Base(candidate) == "compose-frozen.json" {
				frozenPath = candidate
			}
		}
	}
	if !hasUp {
		return ""
	}
	return frozenPath
}

func waitForDockerPortTCP(ctx context.Context, port int) error {
	deadline := time.Now().Add(10 * time.Second)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		connection, err := (&net.Dialer{
			Timeout: 200 * time.Millisecond,
		}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("Docker fixture did not listen on %s", address)
}

func dockerPortSmokeTarget() DockerTarget {
	return DockerTarget{
		DockerPath:              "/usr/bin/docker",
		ComposeProject:          "autostream",
		ProjectDir:              dockerPortSmokeProjectDir,
		ComposeFiles:            []string{"/opt/autostream/compose.yml"},
		Service:                 "worker",
		ImageRepo:               dockerPortSmokeImageRepo,
		ImageVariable:           "AUTOSTREAM_DOCKER_VERSION",
		BaseEnvFile:             "/opt/autostream/.env",
		VersionEnvFile:          "/opt/autostream/local-executor/docker/worker.env",
		PortEnvFile:             "/opt/autostream/local-executor/docker/ports/worker.env",
		ComposeConfigSHA256:     strings.Repeat("0", 64),
		PortComposePolicySHA256: strings.Repeat("0", 64),
		PortComposeRevision:     13,
		CurrentVersion:          "v1.0.0",
		Channel:                 "docker",
	}
}

func prepareDockerPortSmokeMountNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv(dockerPortDaemonSmokeMountNSEnv) != "1" {
		t.Fatal(dockerPortDaemonSmokeMountNSEnv + "=1 is required")
	}
	selfNamespace, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("read Docker smoke mount namespace: %v", err)
	}
	initNamespace, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		t.Fatalf("read init mount namespace: %v", err)
	}
	if selfNamespace == initNamespace {
		t.Fatal("Docker port smoke requires a dedicated mount namespace")
	}
	requireDockerPortSmokePrivateRootPropagation(t)
	requireDockerPortSmokeRootAnchor(t, "/", 0o755)

	scratch := t.TempDir()
	mounted := make([]string, 0, 5)
	t.Cleanup(func() {
		for index := len(mounted) - 1; index >= 0; index-- {
			if err := syscall.Unmount(mounted[index], syscall.MNT_DETACH); err != nil {
				t.Errorf(
					"unmount Docker smoke fixture %s: %v",
					mounted[index], err,
				)
			}
		}
	})

	dockerPortSmokeOverlayRoot(t, scratch, "etc", "/etc", nil, &mounted)
	dockerPortSmokeOverlayRoot(
		t,
		scratch,
		"usr",
		"/usr",
		[]string{
			"bin",
			"sbin",
			"local",
			"local/bin",
			"local/sbin",
			"local/libexec",
		},
		&mounted,
	)
	if err := syscall.Mount(
		"autostream-docker-port-smoke-opt",
		"/opt",
		"tmpfs",
		uintptr(syscall.MS_NODEV|syscall.MS_NOSUID|syscall.MS_NOEXEC),
		"mode=0755,uid=0,gid=0",
	); err != nil {
		t.Fatalf("mount isolated Docker smoke /opt: %v", err)
	}
	mounted = append(mounted, "/opt")

	requireDockerPortSmokeFilesystem(t, "/etc", 0x794c7630)
	requireDockerPortSmokeFilesystem(t, "/usr", 0x794c7630)
	requireDockerPortSmokeFilesystem(t, "/opt", 0x01021994)
	for _, path := range []string{
		"/etc",
		"/usr",
		"/usr/bin",
		"/usr/local",
		"/usr/local/bin",
		"/usr/local/sbin",
		"/usr/local/libexec",
		"/opt",
	} {
		requireDockerPortSmokeRootAnchor(t, path, 0o755)
	}
}

func dockerPortSmokeOverlayRoot(
	t *testing.T,
	scratch, name, target string,
	upperDirectories []string,
	mounted *[]string,
) {
	t.Helper()
	root := filepath.Join(scratch, name)
	lower := filepath.Join(root, "lower")
	upper := filepath.Join(root, "upper")
	work := filepath.Join(root, "work")
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{path: root, mode: 0o700},
		{path: lower, mode: 0o700},
		{path: upper, mode: 0o755},
		{path: work, mode: 0o700},
	} {
		if err := os.Mkdir(directory.path, directory.mode); err != nil {
			t.Fatalf("create Docker smoke overlay directory %s: %v", directory.path, err)
		}
		if err := os.Chown(directory.path, 0, 0); err != nil {
			t.Fatalf("own Docker smoke overlay directory %s: %v", directory.path, err)
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			t.Fatalf("mode Docker smoke overlay directory %s: %v", directory.path, err)
		}
	}
	for _, relative := range upperDirectories {
		path := filepath.Join(upper, relative)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create Docker smoke overlay upper %s: %v", path, err)
		}
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatalf("own Docker smoke overlay upper %s: %v", path, err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatalf("mode Docker smoke overlay upper %s: %v", path, err)
		}
	}
	if err := syscall.Mount(
		target,
		lower,
		"",
		uintptr(syscall.MS_BIND|syscall.MS_REC),
		"",
	); err != nil {
		t.Fatalf("bind Docker smoke lower %s: %v", target, err)
	}
	*mounted = append(*mounted, lower)
	if err := syscall.Mount(
		"",
		lower,
		"",
		uintptr(syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY),
		"",
	); err != nil {
		t.Fatalf("make Docker smoke lower read-only %s: %v", target, err)
	}
	options := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := syscall.Mount(
		"overlay",
		target,
		"overlay",
		uintptr(syscall.MS_NODEV|syscall.MS_NOSUID),
		options,
	); err != nil {
		t.Fatalf("mount isolated Docker smoke %s: %v", target, err)
	}
	*mounted = append(*mounted, target)
}

func requireDockerPortSmokePrivateRootPropagation(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("read Docker smoke mount propagation: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[4] != "/" {
			continue
		}
		separator := -1
		for index := 6; index < len(fields); index++ {
			if fields[index] == "-" {
				separator = index
				break
			}
			if strings.HasPrefix(fields[index], "shared:") ||
				strings.HasPrefix(fields[index], "master:") {
				t.Fatal("Docker port smoke root mount propagation is not private")
			}
		}
		if separator < 0 {
			t.Fatal("Docker port smoke root mountinfo is malformed")
		}
		return
	}
	t.Fatal("Docker port smoke root mount was not found")
}

func requireDockerPortSmokeRootAnchor(
	t *testing.T,
	path string,
	mode os.FileMode,
) {
	t.Helper()
	info, err := os.Lstat(path)
	stat, ok := infoSyscallStat(info)
	if err != nil ||
		!ok ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		stat.Uid != 0 ||
		stat.Gid != 0 ||
		info.Mode().Perm() != mode {
		uid, gid := uint32(^uint32(0)), uint32(^uint32(0))
		actualMode := os.FileMode(0)
		if ok {
			uid, gid = stat.Uid, stat.Gid
		}
		if info != nil {
			actualMode = info.Mode()
		}
		t.Fatalf(
			"Docker port smoke root anchor %s must be a root:root non-symlink directory with mode %04o; uid=%d gid=%d mode=%v err=%v",
			path, mode, uid, gid, actualMode, err,
		)
	}
}

func infoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func requireDockerPortSmokeFilesystem(
	t *testing.T,
	path string,
	wantType int64,
) {
	t.Helper()
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		t.Fatalf("stat Docker smoke filesystem %s: %v", path, err)
	}
	if int64(stat.Type) != wantType {
		t.Fatalf(
			"Docker port smoke filesystem %s type=%#x want=%#x",
			path, stat.Type, wantType,
		)
	}
}

func hardenDockerPortSmokeProjectParent(t *testing.T) {
	t.Helper()
	parent := filepath.Dir(filepath.Clean(dockerPortSmokeProjectDir))
	info, err := os.Lstat(parent)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		!isRootOwner(info) {
		t.Fatalf(
			"Docker port smoke project parent %s must be a root-owned non-symlink directory",
			parent,
		)
	}
	originalMode := info.Mode()
	hardenedMode := originalMode &^ 0o022
	if hardenedMode != originalMode {
		if err := os.Chmod(parent, hardenedMode); err != nil {
			t.Fatalf("harden Docker port smoke project parent %s: %v", parent, err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(parent, originalMode); err != nil {
				t.Errorf(
					"restore Docker port smoke project parent %s mode: %v",
					parent, err,
				)
			}
		})
	}
	if err := validateSecureRootPath(parent, true); err != nil {
		t.Fatalf("secure Docker port smoke project parent %s: %v", parent, err)
	}
}

func setupDockerPortSmokeRoot(t *testing.T, image, imageID string) {
	t.Helper()
	for _, directory := range []string{
		"/opt/autostream",
		"/opt/autostream/local-executor",
		"/opt/autostream/local-executor/docker",
		"/opt/autostream/local-executor/docker/ports",
		"/etc/autostream-local-executor",
		"/etc/autostream-local-executor/docker",
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("create %s: %v", directory, err)
		}
	}
	compose := fmt.Sprintf(`services:
  worker:
    image: %s
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    pids_limit: 64
    stop_grace_period: 1s
    environment:
      AUTOSTREAM_BIND_ADDR: "0.0.0.0:${AUTOSTREAM_WORKER_CONTAINER_PORT}"
      AUTOSTREAM_CONFIG_REVISION: "${AUTOSTREAM_CONFIG_REVISION}"
      AUTOSTREAM_FIXTURE_ADVERTISED_PORT: "${AUTOSTREAM_FIXTURE_ADVERTISED_PORT}"
      AUTOSTREAM_FIXTURE_BUNDLE_PIN: "${AUTOSTREAM_DOCKER_VERSION}"
      AUTOSTREAM_FIXTURE_VERSION: "v1.0.0"
      AUTOSTREAM_FIXTURE_UNHEALTHY_PORT: "21080"
    ports:
      - "127.0.0.1:${AUTOSTREAM_WORKER_PORT}:${AUTOSTREAM_WORKER_CONTAINER_PORT}/tcp"
`, image)
	writeDockerPortSmokeFile(
		t, "/opt/autostream/compose.yml", []byte(compose),
	)
	writeDockerPortSmokeFile(
		t, "/opt/autostream/.env",
		[]byte("AUTOSTREAM_FIXTURE_ADVERTISED_PORT=443\n"),
	)
	writeDockerPortSmokeFile(
		t, "/opt/autostream/local-executor/docker/worker.env",
		[]byte("AUTOSTREAM_DOCKER_VERSION=v1.0.0@"+imageID+"\n"),
	)
	adapterTarget := dockerPortSmokeTarget()
	adapter, err := dockerPortAdapterFor("worker", &adapterTarget)
	if err != nil {
		t.Fatal(err)
	}
	portEnv, err := dockerPortEnvBytes(adapter, 18081, 8080, 1)
	if err != nil {
		t.Fatal(err)
	}
	writeDockerPortSmokeFile(t, adapter.PortEnvFile, portEnv)
	writeDockerPortSmokeFile(
		t, "/etc/autostream-local-executor/docker/config.json",
		[]byte("{}\n"),
	)
	writeDockerPortSmokeFile(
		t, "/opt/autostream/.docker-port-smoke-owner",
		[]byte("github-actions-docker-port-smoke\n"),
	)
	writeDockerPortSmokeFile(
		t, "/etc/autostream-local-executor/.docker-port-smoke-owner",
		[]byte("github-actions-docker-port-smoke\n"),
	)
}

func writeDockerPortSmokeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := writeAtomicFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func newDockerPortSmokeState(
	t *testing.T,
	adapter dockerPortAdapter,
	advertisedPort, publishedPort, containerPort int,
	endpointRevision, configRevision int64,
) dockerPortSmokeState {
	t.Helper()
	body, err := dockerPortEnvBytes(
		adapter, publishedPort, containerPort, configRevision,
	)
	if err != nil {
		t.Fatal(err)
	}
	return dockerPortSmokeState{
		advertisedPort:   advertisedPort,
		publishedPort:    publishedPort,
		containerPort:    containerPort,
		endpointRevision: endpointRevision,
		configRevision:   configRevision,
		configSHA256:     dockerPortEnvSHA256(body),
	}
}

func dockerPortSmokePlan(
	t *testing.T,
	policy LocalExecutorPolicy,
	current, target dockerPortSmokeState,
	jobID, containerID, imageID, repositoryDigest,
	versionEnvSHA256 string,
) SystemdPortReconfigurePlan {
	t.Helper()
	policySHA256, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	plan := SystemdPortReconfigurePlan{
		DeploymentMode: ModeDocker,
		JobID:          jobID, HostID: policy.HostID,
		TargetID: "worker-smoke", ServiceType: "worker",
		NetworkNamespace:               systemdPortNetworkNamespaceHost,
		Protocol:                       systemdPortProtocolTCP,
		OldPort:                        current.advertisedPort,
		NewPort:                        target.advertisedPort,
		ExpectedEndpointRevision:       current.endpointRevision,
		TargetEndpointRevision:         target.endpointRevision,
		ExpectedConfigRevision:         current.configRevision,
		TargetConfigRevision:           target.configRevision,
		ExpectedConfigSHA256:           current.configSHA256,
		TargetConfigSHA256:             target.configSHA256,
		ExpectedSourcePolicyRevision:   policy.SourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  policy.ProjectionRevision,
		ExpectedExecutorPolicyRevision: policy.PolicyRevision,
		ExpectedExecutorPolicySHA256:   policySHA256,
		OwnershipEpoch:                 41,
		LeaseGeneration:                uint64(target.endpointRevision),
		SessionID:                      "docker-port-session-" + jobID,
		Docker: &DockerPortMutationGrantBinding{
			PublishedHostIP:             "127.0.0.1",
			OldPublishedPort:            current.publishedPort,
			NewPublishedPort:            target.publishedPort,
			OldContainerPort:            current.containerPort,
			NewContainerPort:            target.containerPort,
			OldHealthPort:               current.publishedPort,
			NewHealthPort:               target.publishedPort,
			ApprovedComposeConfigSHA256: policy.Targets[0].Docker.PortComposePolicySHA256,
			ApprovedComposeRevision:     policy.PolicyRevision,
			ExpectedVersionEnvSHA256:    versionEnvSHA256,
			ExpectedContainerID:         containerID,
			ExpectedImageID:             imageID,
			ExpectedRepositoryDigest:    repositoryDigest,
		},
	}
	plan.PortPlanSHA256, err = plan.ComputePortPlanSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	return plan
}

func dockerPortSmokeRequest(
	plan SystemdPortReconfigurePlan,
	operation string,
) LocalExecutorRequest {
	return LocalExecutorRequest{
		Version:                 LocalExecutorMutationProtocolVersion,
		Operation:               operation,
		ServiceID:               plan.TargetID,
		PortPlan:                &plan,
		SourcePolicyRevision:    plan.ExpectedSourcePolicyRevision,
		OwnershipEpoch:          plan.OwnershipEpoch,
		OwnershipPolicyRevision: plan.ExpectedUpdaterPolicyRevision,
		ExecutorPolicyRevision:  plan.ExpectedExecutorPolicyRevision,
		MutationGrant:           NewBoundedSecret(dockerPortDaemonSmokeGrant),
	}
}

func runDockerPortSmokeMutation(
	t *testing.T,
	runner CommandRunner,
	stateDir string,
	plan SystemdPortReconfigurePlan,
	operation string,
	crashPoint func(string) error,
) (LocalExecutorResponse, int) {
	t.Helper()
	policy, err := LoadLocalExecutorPolicy(
		dockerPortSmokePolicyPath, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	grantCalls := 0
	response := handleLocalExecutorMutation(
		context.Background(),
		policy,
		dockerPortSmokeRequest(plan, operation),
		executorMutationRuntime{
			platformOS: "linux", localStateDir: stateDir,
			runner:                      runner,
			dockerPortCrashPointForTest: crashPoint,
			consumeGrant: func(
				_ context.Context,
				panelURL, jobID, grant string,
				binding MutationGrantBinding,
				_ *http.Client,
			) error {
				grantCalls++
				return validateDockerPortSmokeGrantBinding(
					plan, operation, panelURL, jobID, grant, binding,
				)
			},
		},
	)
	return response, grantCalls
}

func validateDockerPortSmokeGrantBinding(
	plan SystemdPortReconfigurePlan,
	operation, panelURL, jobID, grant string,
	binding MutationGrantBinding,
) error {
	want := MutationGrantBinding{
		LeaseGeneration: plan.LeaseGeneration,
		HostID:          plan.HostID,
		TransportMode:   HostTransportPullV2,
		TargetID:        plan.TargetID,
		ServiceType:     plan.ServiceType,
		TargetVersion:   "v1.0.0",
		DeploymentMode:  ModeDocker,
		JobOperation:    "port_reconfigure",
		Operation:       operation,
		PlanSHA256:      plan.PortPlanSHA256,
		SessionID:       plan.SessionID,
		OwnershipEpoch:  plan.OwnershipEpoch,
		PolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		PortReconfigure: plan.mutationGrantBinding(),
	}
	if panelURL != "https://panel.example.com" ||
		jobID != plan.JobID ||
		grant != dockerPortDaemonSmokeGrant ||
		!reflect.DeepEqual(binding, want) {
		return errors.New("Docker port smoke mutation grant binding changed")
	}
	return nil
}

func runDockerPortSmokeChild(
	t *testing.T,
	payload dockerPortSmokeChildPayload,
	expectCrash bool,
) {
	t.Helper()
	payloadPath := filepath.Join(
		payload.StateDir,
		fmt.Sprintf("child-payload-%d.json", time.Now().UnixNano()),
	)
	writeDockerPortSmokeJSON(t, payloadPath, payload)
	command := exec.Command(
		os.Args[0],
		"-test.run", "^TestDockerPortDaemonSmokeChild$",
		"-test.count=1",
		"-test.timeout=2m",
		"-test.v",
	)
	command.Env = append(
		os.Environ(),
		dockerPortDaemonSmokeChildEnv+"=1",
		dockerPortDaemonSmokePayloadEnv+"="+payloadPath,
		dockerPortDaemonSmokeGrantEnv+"="+dockerPortDaemonSmokeGrant,
	)
	output, err := command.CombinedOutput()
	if expectCrash {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) ||
			exitError.ExitCode() != dockerPortDaemonSmokeCrashExit {
			t.Fatalf(
				"crash child exit=%v\n%s",
				err, output,
			)
		}
		return
	}
	if err != nil {
		t.Fatalf("child mutation: %v\n%s", err, output)
	}
}

func writeDockerPortSmokeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func readDockerPortSmokeJSON(t *testing.T, path string, value any) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatal("Docker port smoke JSON contains trailing data")
	}
}

func assertDockerPortSmokeApplied(
	t *testing.T,
	response LocalExecutorResponse,
	plan SystemdPortReconfigurePlan,
) {
	t.Helper()
	if err := response.Validate(); err != nil ||
		response.PortResult == nil ||
		response.PortResult.Result != systemdPortResultApplied ||
		response.PortResult.Docker == nil ||
		response.PortResult.AppliedPort != plan.NewPort ||
		response.PortResult.Docker.AppliedPublishedPort !=
			plan.Docker.NewPublishedPort ||
		response.PortResult.Docker.AppliedContainerPort !=
			plan.Docker.NewContainerPort ||
		response.PortResult.Docker.AppliedHealthPort !=
			plan.Docker.NewHealthPort {
		t.Fatalf(
			"applied response=%+v error=%+v validate=%v",
			response, response.Error, response.Validate(),
		)
	}
}

func assertDockerPortSmokeRolledBack(
	t *testing.T,
	response LocalExecutorResponse,
	plan SystemdPortReconfigurePlan,
) {
	t.Helper()
	if err := response.Validate(); err != nil ||
		response.PortResult == nil ||
		response.PortResult.Result != systemdPortResultRolledBack ||
		response.PortResult.Docker == nil ||
		response.PortResult.AppliedPort != plan.OldPort ||
		response.PortResult.Docker.AppliedPublishedPort !=
			plan.Docker.OldPublishedPort ||
		response.PortResult.Docker.AppliedContainerPort !=
			plan.Docker.OldContainerPort ||
		response.PortResult.Docker.AppliedHealthPort !=
			plan.Docker.OldHealthPort {
		t.Fatalf("rollback response=%+v validate=%v", response, response.Validate())
	}
}

func assertDockerPortSmokeDurableState(
	t *testing.T,
	stateDir string,
	adapter dockerPortAdapter,
	state dockerPortSmokeState,
	plan SystemdPortReconfigurePlan,
) {
	t.Helper()
	assertDockerPortSmokeSidecar(t, adapter, state)
	store, err := newFileDockerPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := store.LoadDockerApplied(plan.TargetID)
	if err != nil || applied == nil ||
		applied.PublishedPort != state.publishedPort ||
		applied.ContainerPort != state.containerPort ||
		applied.HealthPort != state.publishedPort ||
		applied.EndpointRevision != state.endpointRevision ||
		applied.ConfigRevision != state.configRevision ||
		applied.ConfigSHA256 != state.configSHA256 {
		t.Fatalf("durable applied=%+v err=%v", applied, err)
	}
	assertDockerPortSmokeWorkDirEmpty(t, stateDir)
}

func assertDockerPortSmokeSidecar(
	t *testing.T,
	adapter dockerPortAdapter,
	state dockerPortSmokeState,
) {
	t.Helper()
	want, err := dockerPortEnvBytes(
		adapter, state.publishedPort, state.containerPort,
		state.configRevision,
	)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(adapter.PortEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(adapter.PortEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 ||
		!bytes.Equal(got, want) ||
		dockerPortEnvSHA256(got) != state.configSHA256 {
		t.Fatalf("Docker port sidecar mode=%o body=%q", info.Mode().Perm(), got)
	}
}

func assertDockerPortSmokeWorkDirEmpty(t *testing.T, stateDir string) {
	t.Helper()
	workDir := filepath.Join(stateDir, "docker-work")
	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Docker transient work survived: %+v", entries)
	}
}

func assertDockerPortSmokeFrozenCaptures(
	t *testing.T,
	captureDir string,
) {
	t.Helper()
	entries, err := os.ReadDir(captureDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 5 {
		t.Fatalf("captured frozen Compose count=%d", len(entries))
	}
	for _, entry := range entries {
		path := filepath.Join(captureDir, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 ||
			!bytes.Equal(body, make([]byte, len(body))) {
			t.Fatalf("frozen Compose inode was not zeroed: %s", path)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
}

func startDockerPortSmokeForeignContainer(
	t *testing.T,
	runner OSCommandRunner,
	image, name string,
	publishedPort, containerPort int,
) {
	t.Helper()
	mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"run", "-d",
		"--name", name,
		"--label", "com.kome-lab.autostream.test=docker-port-smoke",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "64",
		"-p", fmt.Sprintf(
			"127.0.0.1:%d:%d/tcp", publishedPort, containerPort,
		),
		"-e", fmt.Sprintf(
			"AUTOSTREAM_BIND_ADDR=0.0.0.0:%d", containerPort,
		),
		"-e", "AUTOSTREAM_FIXTURE_ADVERTISED_PORT=443",
		"-e", "AUTOSTREAM_CONFIG_REVISION=5",
		"-e", "AUTOSTREAM_FIXTURE_VERSION=v1.0.0",
		image,
	)
	if err := waitForDockerPortTCP(
		context.Background(), publishedPort,
	); err != nil {
		t.Fatal(err)
	}
}

func dockerPortSmokeContainerID(
	t *testing.T,
	runner OSCommandRunner,
) string {
	t.Helper()
	shortID := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, dockerPortSmokeProjectDir, "/usr/bin/docker",
		"ps", "-q",
		"--filter", "label=com.docker.compose.project=autostream",
		"--filter", "label=com.docker.compose.service=worker",
	))
	fullID := strings.ToLower(strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, dockerPortSmokeProjectDir, "/usr/bin/docker",
		"inspect", "--format={{.Id}}", shortID,
	)))
	if len(fullID) != 64 || !dockerContainerIDPattern.MatchString(fullID) {
		t.Fatalf("managed container ID=%q", fullID)
	}
	return fullID
}

func assertDockerPortFixtureBoundary(
	t *testing.T,
	runner OSCommandRunner,
	containerID string,
	publishedPort, containerPort int,
) {
	t.Helper()
	mounts := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"inspect", "--format={{json .Mounts}}", containerID,
	))
	privileged := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"inspect", "--format={{.HostConfig.Privileged}}", containerID,
	))
	mapping := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"port", containerID, fmt.Sprintf("%d/tcp", containerPort),
	))
	if mounts != "[]" || privileged != "false" ||
		mapping != fmt.Sprintf("127.0.0.1:%d", publishedPort) {
		t.Fatalf(
			"Docker fixture boundary mounts=%s privileged=%s mapping=%s",
			mounts, privileged, mapping,
		)
	}
}

func waitForDockerPortFixture(
	t *testing.T,
	publishedPort, advertisedPort, containerPort int,
	configRevision int64,
	unhealthy bool,
) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastError error
	for time.Now().Before(deadline) {
		lastError = verifyDockerPortFixture(
			publishedPort, advertisedPort, containerPort,
			configRevision, unhealthy,
		)
		if lastError == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("fixture verification failed: %v", lastError)
}

func verifyDockerPortFixture(
	publishedPort, advertisedPort, containerPort int,
	configRevision int64,
	unhealthy bool,
) error {
	client := &http.Client{Timeout: time.Second}
	base := fmt.Sprintf("http://127.0.0.1:%d", publishedPort)
	healthResponse, err := client.Get(base + "/health")
	if err != nil {
		return err
	}
	defer healthResponse.Body.Close()
	expectedStatus := http.StatusOK
	if unhealthy {
		expectedStatus = http.StatusServiceUnavailable
	}
	if healthResponse.StatusCode != expectedStatus {
		return fmt.Errorf(
			"health status=%d want=%d",
			healthResponse.StatusCode, expectedStatus,
		)
	}
	var version struct {
		Version        string `json:"version"`
		ServiceID      string `json:"service_id"`
		ServiceType    string `json:"service_type"`
		ConfigRevision int64  `json:"config_revision"`
	}
	if err := getDockerPortFixtureJSON(
		client, base+"/updater/version", &version,
	); err != nil {
		return err
	}
	if version.Version != "v1.0.0" ||
		version.ServiceID != "worker-smoke" ||
		version.ServiceType != "worker" ||
		version.ConfigRevision != configRevision {
		return fmt.Errorf("version identity=%+v", version)
	}
	var config struct {
		AdvertisedPort int   `json:"advertised_port"`
		ContainerPort  int   `json:"container_port"`
		ConfigRevision int64 `json:"config_revision"`
	}
	if err := getDockerPortFixtureJSON(
		client, base+"/config", &config,
	); err != nil {
		return err
	}
	if config.AdvertisedPort != advertisedPort ||
		config.ContainerPort != containerPort ||
		config.ConfigRevision != configRevision {
		return fmt.Errorf("config identity=%+v", config)
	}
	return nil
}

func getDockerPortFixtureJSON(
	client *http.Client,
	endpoint string,
	out any,
) error {
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d", endpoint, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func buildDockerPortFixtureImage(t *testing.T, image string) {
	t.Helper()
	contextDir := t.TempDir()
	fixtureBinary := filepath.Join(contextDir, "docker-port-fixture")
	if prebuilt := os.Getenv(dockerPortDaemonSmokeFixtureEnv); prebuilt != "" {
		body, err := os.ReadFile(prebuilt)
		if err != nil || len(body) == 0 {
			t.Fatalf("read prebuilt Docker port fixture: %v", err)
		}
		if err := os.WriteFile(fixtureBinary, body, 0o555); err != nil {
			t.Fatal(err)
		}
	} else {
		command := exec.Command(
			"go", "build", "-trimpath", "-ldflags=-s -w",
			"-o", fixtureBinary,
			"./testdata/docker-port-fixture",
		)
		command.Env = append(
			os.Environ(),
			"CGO_ENABLED=0",
			"GOOS=linux",
			"GOARCH="+dockerPortSmokeServerGoArch(t),
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build Docker port fixture: %v\n%s", err, output)
		}
	}
	dockerfile := []byte(
		"FROM scratch\n" +
			"COPY --chmod=0555 docker-port-fixture /docker-port-fixture\n" +
			"USER 65532:65532\n" +
			"ENTRYPOINT [\"/docker-port-fixture\"]\n",
	)
	if err := os.WriteFile(
		filepath.Join(contextDir, "Dockerfile"), dockerfile, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	baseRunner := OSCommandRunner{NewProcessGroup: true}
	fixtureDockerConfig := t.TempDir()
	if err := os.Chmod(fixtureDockerConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := baseRunner.Run(
		context.Background(),
		"",
		[]string{"HOME=/", "DOCKER_CONFIG=" + fixtureDockerConfig},
		"/usr/bin/docker",
		"build", "--pull=false", "--network=none",
		"--label", "com.kome-lab.autostream.test=docker-port-smoke",
		"--tag", image, contextDir,
	)
	if err != nil {
		t.Fatalf("build isolated Docker port fixture: %v\n%s", err, output)
	}
}

func dockerPortSmokeServerGoArch(t *testing.T) string {
	t.Helper()
	baseRunner := OSCommandRunner{NewProcessGroup: true}
	architecture := strings.TrimSpace(mustDockerPortSmokeRun(
		t, baseRunner, "", "/usr/bin/docker",
		"version", "--format", "{{.Server.Arch}}",
	))
	switch architecture {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		t.Fatalf("unsupported Docker server architecture %q", architecture)
		return ""
	}
}

func proveDockerAutoConfigureFailsClosed(t *testing.T) {
	t.Helper()
	_, err := BuildHostAgentConfigurePolicy(HostAgentConfigurePolicySource{
		PanelURL:                    "https://panel.example.com",
		ExecutionHostID:             "host-smoke",
		AgentUID:                    1001,
		AgentGID:                    1001,
		SourcePolicyRevision:        1,
		ProjectionRevision:          1,
		LocalExecutorPolicyRevision: 1,
		Targets: []HostAgentConfigurePolicyTarget{{
			ServiceID:             "worker-smoke",
			ServiceType:           "worker",
			DeploymentMode:        ModeDocker,
			EndpointRevision:      1,
			AppliedConfigRevision: 1,
			AppliedEndpointPort:   443,
		}},
	})
	if err == nil {
		t.Fatal("Auto Configure synthesized privileged Docker authority")
	}
}

func proveDockerTransientCleanup(t *testing.T) {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(base, dockerPortRecreatePrefix+"daemon-smoke")
	if err := os.Mkdir(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := []byte(`{"services":{"worker":{"environment":{"TOKEN":"wipe-me"}}}}`)
	frozen := filepath.Join(orphan, "compose-frozen.json")
	if err := os.WriteFile(frozen, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	captured := filepath.Join(base, "captured")
	if err := os.Link(frozen, captured); err != nil {
		t.Fatal(err)
	}
	if err := cleanupDockerPortTransientOrphans(base, false); err != nil {
		t.Fatal(err)
	}
	wiped, err := os.ReadFile(captured)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wiped, make([]byte, len(secret))) {
		t.Fatal("frozen Compose model was not zeroed before unlink")
	}
}

func requireDockerPortSmokePortAvailable(t *testing.T, port int) {
	t.Helper()
	listener, err := net.Listen(
		"tcp", fmt.Sprintf("127.0.0.1:%d", port),
	)
	if err != nil {
		t.Fatalf("required smoke port %d is in use: %v", port, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func requireDockerPortSmokeHostClean(
	t *testing.T,
	runner OSCommandRunner,
) {
	t.Helper()
	for _, path := range []string{
		dockerPortSmokeProjectDir,
		"/etc/autostream-local-executor",
		filepath.Join(
			privilegedLockDir(), ".autostream-host-lifecycle.lock",
		),
		filepath.Join(
			privilegedLockDir(),
			".autostream-updater-"+
				shortID(filepath.Clean(dockerPortSmokeProjectDir)+"\x00autostream")+
				".lock",
		),
	} {
		if pathExists(path) {
			t.Fatalf("Docker port smoke refuses existing host path %s", path)
		}
	}
	projectContainers := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"ps", "-aq",
		"--filter", "label=com.docker.compose.project=autostream",
	))
	if projectContainers != "" {
		t.Fatalf(
			"Docker port smoke refuses existing project containers %s",
			projectContainers,
		)
	}
	labelledContainers := strings.TrimSpace(mustDockerPortSmokeRun(
		t, runner, "", "/usr/bin/docker",
		"ps", "-aq",
		"--filter", "label=com.kome-lab.autostream.test=docker-port-smoke",
	))
	if labelledContainers != "" {
		t.Fatalf(
			"Docker port smoke refuses existing labelled containers %s",
			labelledContainers,
		)
	}
	if dockerPortSmokeCommand(
		runner, "", "/usr/bin/docker",
		"network", "inspect", "autostream_default",
	) == nil {
		t.Fatal("Docker port smoke refuses existing autostream_default network")
	}
}

func cleanupDockerPortSmokeEnvironment(
	t *testing.T,
	runner OSCommandRunner,
	image, foreignContainer string,
	runDirExisted bool,
) {
	t.Helper()
	_ = dockerPortSmokeCommand(
		runner, "", "/usr/bin/docker", "rm", "-f", foreignContainer,
	)
	if output, err := runner.Run(
		context.Background(), "", dockerCommandEnv(), "/usr/bin/docker",
		"ps", "-aq",
		"--filter", "label=com.docker.compose.project=autostream",
	); err == nil {
		for _, containerID := range strings.Fields(output) {
			_ = dockerPortSmokeCommand(
				runner, "", "/usr/bin/docker", "rm", "-f", containerID,
			)
		}
	}
	_ = dockerPortSmokeCommand(
		runner, "", "/usr/bin/docker",
		"network", "rm", "autostream_default",
	)
	_ = dockerPortSmokeCommand(
		runner, "", "/usr/bin/docker", "image", "rm", "-f", image,
	)

	for _, path := range []string{
		"/opt/autostream/local-executor/docker/ports/worker.env",
		"/opt/autostream/local-executor/docker/worker.env",
		"/opt/autostream/compose.yml",
		"/opt/autostream/.env",
		"/opt/autostream/.docker-port-smoke-owner",
		"/etc/autostream-local-executor/docker/config.json",
		"/etc/autostream-local-executor/policy.json",
		"/etc/autostream-local-executor/.docker-port-smoke-owner",
		filepath.Join(
			privilegedLockDir(), ".autostream-host-lifecycle.lock",
		),
		filepath.Join(
			privilegedLockDir(),
			".autostream-updater-"+
				shortID(filepath.Clean(dockerPortSmokeProjectDir)+"\x00autostream")+
				".lock",
		),
	} {
		if err := os.Remove(path); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove %s: %v", path, err)
		}
	}
	for _, path := range []string{
		"/opt/autostream/local-executor/docker/ports",
		"/opt/autostream/local-executor/docker",
		"/opt/autostream/local-executor",
		"/opt/autostream",
		"/etc/autostream-local-executor/docker",
		"/etc/autostream-local-executor",
	} {
		if err := os.Remove(path); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove empty %s: %v", path, err)
		}
	}
	if !runDirExisted {
		if err := os.Remove(privilegedLockDir()); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove empty %s: %v", privilegedLockDir(), err)
		}
	}
}

func mustDockerPortSmokeRun(
	t *testing.T,
	runner OSCommandRunner,
	dir, name string,
	args ...string,
) string {
	t.Helper()
	output, err := runner.Run(
		context.Background(), dir, dockerCommandEnv(), name, args...,
	)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return output
}

func dockerPortSmokeCommand(
	runner OSCommandRunner,
	dir, name string,
	args ...string,
) error {
	_, err := runner.Run(
		context.Background(), dir, dockerCommandEnv(), name, args...,
	)
	return err
}

func dockerPortSmokeSHA256(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
