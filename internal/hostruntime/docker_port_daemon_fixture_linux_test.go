//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func setupDockerPortSmokeRoot(t *testing.T, image, imageID string) {
	t.Helper()
	for _, directory := range []string{
		"/opt/autostream",
		"/opt/autostream/local-executor",
		"/opt/autostream/local-executor/docker",
		"/opt/autostream/local-executor/docker/ports",
		"/etc/autostream-local-executor",
		"/etc/autostream-local-executor/docker",
		"/etc/autostream",
		"/etc/autostream/updater",
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
      CREDENTIALS_DIRECTORY: "/run/autostream-credentials"
      AUTOSTREAM_FIXTURE_ADVERTISED_PORT: "${AUTOSTREAM_FIXTURE_ADVERTISED_PORT}"
      AUTOSTREAM_FIXTURE_BUNDLE_PIN: "${AUTOSTREAM_DOCKER_VERSION}"
      AUTOSTREAM_FIXTURE_VERSION: "v1.0.0"
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
	diagnostics ...*dockerPortSmokeLegacyDiagnostic,
) (LocalExecutorResponse, int) {
	t.Helper()
	policy, err := LoadLocalExecutorPolicy(
		dockerPortSmokePolicyPath, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	grantCalls := 0
	ctx := context.Background()
	if len(diagnostics) != 0 && diagnostics[0] != nil {
		ctx = diagnostics[0].withFailureObserver(ctx)
		crashPoint = diagnostics[0].wrapCrashPoint(crashPoint)
	}
	response := handleLocalExecutorMutation(
		ctx,
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
