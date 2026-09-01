//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const dockerPortGrantTimeout = 30 * time.Second

type linuxDockerPortRuntime struct {
	adapter          dockerPortAdapter
	hostID           string
	serviceID        string
	serviceType      string
	panelURL         string
	dockerPath       string
	workDir          string
	runner           CommandRunner
	httpClient       *http.Client
	consumeGrant     func(context.Context, string, string, string, MutationGrantBinding, *http.Client) error
	crashPoint       func(string) error
	requireRootOwned bool
	requireRootWork  bool
}

type dockerPortResolvedModel struct {
	raw            []byte
	mapping        dockerPortMapping
	configRevision int64
	policySHA256   string
	composeSHA256  string
}

func newPlatformDockerPortExecution(
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
	secured Target,
	remoteRuntime executorMutationRuntime,
) (dockerPortRuntime, dockerPortStateStore, error) {
	if runtime.GOOS != "linux" ||
		(remoteRuntime.platformOS != "" && remoteRuntime.platformOS != "linux") ||
		os.Geteuid() != 0 {
		return nil, nil, errors.New("Docker port reconfiguration requires a root Linux executor")
	}
	if err := policy.Validate(); err != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil ||
		target.validate() != nil ||
		target.DeploymentMode != ModeDocker ||
		target.Docker == nil ||
		secured.DeploymentMode != ModeDocker ||
		secured.Docker == nil {
		return nil, nil, errors.New("Docker port policy is invalid")
	}
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil {
		return nil, nil, err
	}
	expected := target.runtimeTarget(policy.HostID)
	if secured.TargetID != expected.TargetID ||
		secured.HostID != expected.HostID ||
		secured.ServiceType != expected.ServiceType ||
		secured.HealthURL != expected.HealthURL ||
		secured.VersionURL != expected.VersionURL ||
		secured.Docker.Service != expected.Docker.Service ||
		secured.Docker.PortEnvFile != adapter.PortEnvFile {
		return nil, nil, errors.New("secured Docker target does not match root policy")
	}
	if err := validateRuntimeSystemdPortSidecarDirectory(
		filepath.Dir(adapter.PortEnvFile), true,
	); err != nil {
		return nil, nil, errors.New("Docker port mapping directory is not root-controlled")
	}

	stateDir := LocalExecutorMutationStateDir
	requireRootState := true
	workDir := localExecutorDockerWorkDir
	if remoteRuntime.localStateDir != "" {
		// localStateDir is an internal test hook. Production construction never
		// supplies it and always enforces root ownership.
		stateDir = remoteRuntime.localStateDir
		requireRootState = false
		workDir = filepath.Join(stateDir, "docker-work")
	}
	state, err := newFileDockerPortStateStore(stateDir, requireRootState)
	if err != nil {
		return nil, nil, err
	}
	if err := ensureDockerPortWorkDirectory(workDir, requireRootState); err != nil {
		return nil, nil, err
	}
	if err := cleanupDockerPortTransientOrphans(
		workDir, requireRootState,
	); err != nil {
		return nil, nil, err
	}
	runner := remoteRuntime.runner
	if runner == nil {
		runner = OSCommandRunner{NewProcessGroup: true}
	}
	consumeGrant := remoteRuntime.consumeGrant
	if consumeGrant == nil {
		consumeGrant = ConsumeMutationGrant
	}
	portRuntime := &linuxDockerPortRuntime{
		adapter: adapter, hostID: policy.HostID,
		serviceID: target.ServiceID, serviceType: target.ServiceType,
		panelURL: policy.Mutation.PanelURL, dockerPath: secured.Docker.DockerPath,
		workDir: workDir, runner: runner, httpClient: remoteRuntime.httpClient,
		consumeGrant: consumeGrant, requireRootOwned: true,
		requireRootWork: requireRootState,
	}
	if remoteRuntime.localStateDir != "" {
		// The crash hook is intentionally reachable only through the existing
		// private state-directory test seam. Production construction never
		// supplies either value.
		portRuntime.crashPoint = remoteRuntime.dockerPortCrashPointForTest
	}
	return portRuntime, state, nil
}

func (r *linuxDockerPortRuntime) Observe(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
) (dockerPortObservation, error) {
	if err := r.validateTarget(policy, target); err != nil {
		return dockerPortObservation{}, err
	}
	checkpoint, err := checkpointDockerPortMapping(
		r.adapter.PortEnvFile, r.requireRootOwned,
	)
	if err != nil || !checkpoint.Existed {
		return dockerPortObservation{}, errors.New("Docker port mapping checkpoint is unavailable")
	}
	publishedPort, containerPort, configRevision, err := parseDockerPortEnv(
		r.adapter, checkpoint.Bytes,
	)
	if err != nil ||
		checkpoint.SHA256 != target.ConfigSHA256 ||
		configRevision != target.ConfigRevision ||
		publishedPort != target.LocalListen.Port {
		return dockerPortObservation{}, errors.New("Docker port mapping sidecar differs from root policy")
	}

	runtimeTarget := r.runtimeTarget(target)
	resolved, err := r.resolveCompose(ctx, runtimeTarget.Docker)
	if err != nil ||
		resolved.mapping.HostIP != target.LocalListen.Host ||
		resolved.mapping.PublishedPort != publishedPort ||
		resolved.mapping.ContainerPort != containerPort ||
		resolved.configRevision != configRevision ||
		resolved.policySHA256 != target.Docker.PortComposePolicySHA256 ||
		resolved.composeSHA256 != target.Docker.ComposeConfigSHA256 {
		return dockerPortObservation{}, errors.New("resolved Docker port model differs from root policy")
	}
	baseline, err := observeDockerMutationBaseline(ctx, runtimeTarget, r.runner)
	if err != nil {
		return dockerPortObservation{}, err
	}
	fullContainerID, err := r.fullContainerID(
		ctx, runtimeTarget.Docker, baseline.Baseline.ContainerID,
	)
	if err != nil {
		return dockerPortObservation{}, err
	}
	if err := preflightDockerPublishedPortOwnership(
		ctx,
		r.runner,
		runtimeTarget.Docker,
		[]dockerPortMapping{resolved.mapping},
		fullContainerID,
	); err != nil {
		return dockerPortObservation{}, err
	}
	if err := verifyLocalExecutorHTTP(
		ctx, target, baseline.Baseline.SourceVersion, r.httpClient,
	); err != nil {
		return dockerPortObservation{}, errors.New("Docker port endpoint verification failed")
	}
	observation := dockerPortObservation{
		MappingEnv:          checkpoint,
		PublishedHostIP:     resolved.mapping.HostIP,
		PublishedPort:       resolved.mapping.PublishedPort,
		ContainerPort:       resolved.mapping.ContainerPort,
		HealthPort:          resolved.mapping.PublishedPort,
		ConfigRevision:      configRevision,
		ConfigSHA256:        checkpoint.SHA256,
		ComposePolicySHA256: resolved.policySHA256,
		ComposeConfigSHA256: resolved.composeSHA256,
		Runtime: dockerPortRuntimeBaseline{
			VersionEnvSHA256: baseline.Baseline.VersionEnvSHA256,
			ContainerID:      fullContainerID,
			ImageID:          baseline.Baseline.ImageID,
			RepositoryDigest: baseline.Baseline.RepositoryDigest,
			CurrentVersion:   baseline.Baseline.SourceVersion,
		},
	}
	if err := observation.validate(); err != nil {
		return dockerPortObservation{}, err
	}
	return observation, nil
}

func (r *linuxDockerPortRuntime) Prepare(
	ctx context.Context,
	target LocalExecutorTarget,
	targetBytes []byte,
) (dockerPortPreparedModel, error) {
	if err := r.validateTargetIdentity(target); err != nil {
		return dockerPortPreparedModel{}, err
	}
	publishedPort, containerPort, configRevision, err := parseDockerPortEnv(
		r.adapter, targetBytes,
	)
	if err != nil {
		return dockerPortPreparedModel{}, err
	}
	workDir, err := os.MkdirTemp(r.workDir, dockerPortPreparePrefix)
	if err != nil {
		return dockerPortPreparedModel{}, errors.New("create Docker port preparation directory")
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_ = secureRemoveDockerPortTransient(
				r.workDir, workDir, r.requireRootWork,
			)
		}
	}()
	if err := os.Chmod(workDir, 0o700); err != nil {
		return dockerPortPreparedModel{}, errors.New("secure Docker port preparation directory")
	}
	portEnvPath := filepath.Join(workDir, "ports.env")
	if err := writeAtomicFile(portEnvPath, targetBytes, 0o600); err != nil {
		return dockerPortPreparedModel{}, errors.New("write staged Docker port mapping")
	}
	runtimeTarget := r.runtimeTarget(target)
	docker := *runtimeTarget.Docker
	docker.PortEnvFile = portEnvPath
	resolved, err := r.resolveCompose(ctx, &docker)
	if err != nil ||
		resolved.mapping.HostIP != target.LocalListen.Host ||
		resolved.mapping.PublishedPort != publishedPort ||
		resolved.mapping.ContainerPort != containerPort ||
		resolved.configRevision != configRevision ||
		resolved.policySHA256 != target.Docker.PortComposePolicySHA256 {
		return dockerPortPreparedModel{}, errors.New("staged Docker port model differs from approved policy")
	}
	prepared := dockerPortPreparedModel{
		ComposePolicySHA256: resolved.policySHA256,
		ComposeConfigSHA256: resolved.composeSHA256,
		PublishedHostIP:     resolved.mapping.HostIP,
		PublishedPort:       resolved.mapping.PublishedPort,
		ContainerPort:       resolved.mapping.ContainerPort,
		HealthPort:          resolved.mapping.PublishedPort,
	}
	if err := prepared.validate(); err != nil {
		return dockerPortPreparedModel{}, err
	}
	if err := secureRemoveDockerPortTransient(
		r.workDir, workDir, r.requireRootWork,
	); err != nil {
		return dockerPortPreparedModel{}, errors.New("remove staged Docker port mapping")
	}
	cleaned = true
	return prepared, nil
}

func (r *linuxDockerPortRuntime) EnsureAvailable(
	ctx context.Context,
	target LocalExecutorTarget,
	prepared dockerPortPreparedModel,
	currentContainerID string,
) error {
	if err := r.validateTargetIdentity(target); err != nil ||
		prepared.validate() != nil ||
		prepared.ComposePolicySHA256 != target.Docker.PortComposePolicySHA256 {
		return errors.New("Docker proposed port mapping is invalid")
	}
	return preflightDockerProposedPortAvailability(
		ctx,
		r.runner,
		r.runtimeTarget(target).Docker,
		dockerPortMapping{
			HostIP:        prepared.PublishedHostIP,
			PublishedPort: prepared.PublishedPort,
			ContainerPort: prepared.ContainerPort,
			Protocol:      "tcp",
		},
		currentContainerID,
	)
}

func (r *linuxDockerPortRuntime) ConsumeGrant(
	ctx context.Context,
	plan SystemdPortReconfigurePlan,
	operation string,
	currentVersion string,
	grant BoundedSecret,
) error {
	if err := plan.Validate(); err != nil ||
		plan.effectiveDeploymentMode() != ModeDocker ||
		plan.HostID != r.hostID ||
		plan.TargetID != r.serviceID ||
		plan.ServiceType != r.serviceType ||
		(operation != "port_reconfigure" &&
			operation != "port_reconfigure_reconcile") ||
		!versionPattern.MatchString(currentVersion) ||
		!validBoundedSecret(grant.Reveal()) ||
		r.consumeGrant == nil {
		return errors.New("Docker port grant binding is invalid")
	}
	binding := MutationGrantBinding{
		LeaseGeneration: plan.LeaseGeneration,
		HostID:          plan.HostID, TransportMode: HostTransportPullV2,
		TargetID: plan.TargetID, ServiceType: plan.ServiceType,
		TargetVersion: currentVersion, DeploymentMode: ModeDocker,
		JobOperation: "port_reconfigure", Operation: operation,
		PlanSHA256: plan.PortPlanSHA256, SessionID: plan.SessionID,
		OwnershipEpoch:  plan.OwnershipEpoch,
		PolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		PortReconfigure: plan.mutationGrantBinding(),
	}
	consumeCtx, cancel := context.WithTimeout(ctx, dockerPortGrantTimeout)
	defer cancel()
	if err := r.consumeGrant(
		consumeCtx,
		r.panelURL,
		plan.JobID,
		grant.Reveal(),
		binding,
		r.httpClient,
	); err != nil {
		return errors.New("Docker port mutation grant rejected")
	}
	return nil
}

func (r *linuxDockerPortRuntime) Write(
	checkpoint dockerPortMappingCheckpoint,
	body []byte,
) error {
	if checkpoint.validate() != nil {
		return errors.New("Docker port mapping checkpoint is invalid")
	}
	if _, _, _, err := parseDockerPortEnv(r.adapter, body); err != nil {
		return err
	}
	current, err := checkpointDockerPortMapping(
		r.adapter.PortEnvFile, r.requireRootOwned,
	)
	if err != nil || !sameDockerPortMappingCheckpoint(current, checkpoint) {
		return errors.New("Docker port mapping changed before write")
	}
	if err := writeAtomicFile(r.adapter.PortEnvFile, body, 0o600); err != nil {
		return errors.New("write Docker port mapping")
	}
	written, err := checkpointDockerPortMapping(
		r.adapter.PortEnvFile, r.requireRootOwned,
	)
	if err != nil ||
		!written.Existed ||
		written.Mode != 0o600 ||
		!bytes.Equal(written.Bytes, body) ||
		written.SHA256 != dockerPortEnvSHA256(body) {
		return errors.New("verify Docker port mapping write")
	}
	return nil
}

func (r *linuxDockerPortRuntime) Restore(
	checkpoint dockerPortMappingCheckpoint,
	targetBytes []byte,
) error {
	if checkpoint.validate() != nil {
		return errors.New("Docker port mapping checkpoint is invalid")
	}
	if _, _, _, err := parseDockerPortEnv(r.adapter, targetBytes); err != nil {
		return err
	}
	current, err := checkpointDockerPortMapping(
		r.adapter.PortEnvFile, r.requireRootOwned,
	)
	if err != nil ||
		!current.Existed ||
		current.Mode != 0o600 ||
		!bytes.Equal(current.Bytes, targetBytes) {
		return errors.New("Docker port mapping changed before restore")
	}
	if checkpoint.Existed {
		if err := writeAtomicFile(
			r.adapter.PortEnvFile, checkpoint.Bytes, 0o600,
		); err != nil {
			return errors.New("restore Docker port mapping")
		}
	} else {
		if err := os.Remove(r.adapter.PortEnvFile); err != nil {
			return errors.New("remove Docker port mapping")
		}
		if err := syncDirectory(filepath.Dir(r.adapter.PortEnvFile)); err != nil {
			return errors.New("sync Docker port mapping directory")
		}
	}
	restored, err := checkpointDockerPortMapping(
		r.adapter.PortEnvFile, r.requireRootOwned,
	)
	if err != nil || !sameDockerPortMappingCheckpoint(restored, checkpoint) {
		return errors.New("verify Docker port mapping restore")
	}
	return nil
}

func (r *linuxDockerPortRuntime) Recreate(
	ctx context.Context,
	target LocalExecutorTarget,
	prepared dockerPortPreparedModel,
) error {
	if err := r.validateTargetIdentity(target); err != nil ||
		prepared.validate() != nil ||
		target.Docker.ComposeConfigSHA256 != prepared.ComposeConfigSHA256 ||
		target.Docker.PortComposePolicySHA256 != prepared.ComposePolicySHA256 {
		return errors.New("Docker recreate target is invalid")
	}
	runtimeTarget := r.runtimeTarget(target)
	resolved, err := r.resolveCompose(ctx, runtimeTarget.Docker)
	if err != nil ||
		resolved.composeSHA256 != prepared.ComposeConfigSHA256 ||
		resolved.policySHA256 != prepared.ComposePolicySHA256 ||
		resolved.mapping.HostIP != prepared.PublishedHostIP ||
		resolved.mapping.PublishedPort != prepared.PublishedPort ||
		resolved.mapping.ContainerPort != prepared.ContainerPort ||
		resolved.configRevision != target.ConfigRevision {
		return errors.New("Docker recreate model changed after authorization")
	}
	workDir, err := os.MkdirTemp(r.workDir, dockerPortRecreatePrefix)
	if err != nil {
		return errors.New("create Docker port recreate directory")
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_ = secureRemoveDockerPortTransient(
				r.workDir, workDir, r.requireRootWork,
			)
		}
	}()
	if err := os.Chmod(workDir, 0o700); err != nil {
		return errors.New("secure Docker port recreate directory")
	}
	frozenPath := filepath.Join(workDir, "compose-frozen.json")
	if err := writeAtomicFile(frozenPath, resolved.raw, 0o600); err != nil {
		return errors.New("freeze Docker port Compose model")
	}
	args := append(
		composeFrozenArgs(runtimeTarget.Docker, frozenPath),
		"up", "-d", "--no-deps", "--no-build", "--pull", "never",
		"--force-recreate", runtimeTarget.Docker.Service,
	)
	_, runErr := r.runner.Run(
		ctx,
		runtimeTarget.Docker.ProjectDir,
		dockerCommandEnv(),
		runtimeTarget.Docker.DockerPath,
		args...,
	)
	cleanupErr := secureRemoveDockerPortTransient(
		r.workDir, workDir, r.requireRootWork,
	)
	cleaned = cleanupErr == nil
	if runErr != nil {
		return errors.New("recreate Docker service with approved port mapping")
	}
	if cleanupErr != nil {
		return errors.New("wipe Docker port frozen Compose model")
	}
	return nil
}

func (r *linuxDockerPortRuntime) CrashPoint(point string) error {
	if r.crashPoint != nil {
		return r.crashPoint(point)
	}
	return nil
}

func (r *linuxDockerPortRuntime) validateTarget(
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
) error {
	if policy.Validate() != nil || policy.HostID != r.hostID {
		return errors.New("Docker port runtime policy is invalid")
	}
	return r.validateTargetIdentity(target)
}

func (r *linuxDockerPortRuntime) validateTargetIdentity(
	target LocalExecutorTarget,
) error {
	if target.validate() != nil ||
		target.ServiceID != r.serviceID ||
		target.ServiceType != r.serviceType ||
		target.DeploymentMode != ModeDocker ||
		target.Docker == nil ||
		target.LocalListen.Host != "127.0.0.1" {
		return errors.New("Docker port runtime target does not match root authority")
	}
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil || adapter != r.adapter {
		return errors.New("Docker port runtime adapter does not match root authority")
	}
	return nil
}

func (r *linuxDockerPortRuntime) runtimeTarget(
	target LocalExecutorTarget,
) Target {
	runtimeTarget := target.runtimeTarget(r.hostID)
	runtimeTarget.Docker.DockerPath = r.dockerPath
	return runtimeTarget
}

func (r *linuxDockerPortRuntime) resolveCompose(
	ctx context.Context,
	target *DockerTarget,
) (dockerPortResolvedModel, error) {
	if target == nil {
		return dockerPortResolvedModel{}, errors.New("Docker port Compose target is unavailable")
	}
	output, err := r.runner.Run(
		ctx,
		target.ProjectDir,
		dockerCommandEnv(),
		target.DockerPath,
		append(
			composeArgs(target, ""),
			"config", "--format", "json", "--no-env-resolution",
		)...,
	)
	if err != nil {
		return dockerPortResolvedModel{}, errors.New("resolve Docker port Compose model")
	}
	raw := []byte(output)
	if err := validateComposeModelSecurity(raw, target); err != nil {
		return dockerPortResolvedModel{}, err
	}
	mappings, err := validateDockerComposePortMappings(raw, target)
	if err != nil || len(mappings) != 1 {
		return dockerPortResolvedModel{}, errors.New("resolved Docker service must expose exactly one managed API port")
	}
	policySHA256, err := dockerPortComposePolicyHash(raw, target)
	if err != nil {
		return dockerPortResolvedModel{}, err
	}
	composeSHA256, err := composeModelHash(raw, target.Service)
	if err != nil {
		return dockerPortResolvedModel{}, err
	}
	configRevision, err := dockerPortComposeConfigRevision(raw, target.Service)
	if err != nil {
		return dockerPortResolvedModel{}, err
	}
	return dockerPortResolvedModel{
		raw: raw, mapping: mappings[0], configRevision: configRevision,
		policySHA256: policySHA256, composeSHA256: composeSHA256,
	}, nil
}

func (r *linuxDockerPortRuntime) fullContainerID(
	ctx context.Context,
	target *DockerTarget,
	currentID string,
) (string, error) {
	output, err := r.runner.Run(
		ctx,
		target.ProjectDir,
		dockerCommandEnv(),
		target.DockerPath,
		"inspect", "--format={{.Id}}", currentID,
	)
	fullID := strings.ToLower(strings.TrimSpace(output))
	if err != nil ||
		len(fullID) != 64 ||
		!dockerContainerIDPattern.MatchString(fullID) ||
		!dockerContainerIDsMatch(fullID, strings.ToLower(currentID)) {
		return "", errors.New("managed Docker container has no full immutable identity")
	}
	return fullID, nil
}

func checkpointDockerPortMapping(
	path string,
	requireRootOwned bool,
) (dockerPortMappingCheckpoint, error) {
	checkpoint, err := checkpointSystemdPortSidecar(path, requireRootOwned)
	if err != nil {
		return dockerPortMappingCheckpoint{}, err
	}
	return newDockerPortMappingCheckpoint(
		checkpoint.Existed, checkpoint.Mode, checkpoint.Bytes,
	), nil
}

func sameDockerPortMappingCheckpoint(
	left dockerPortMappingCheckpoint,
	right dockerPortMappingCheckpoint,
) bool {
	return left.Existed == right.Existed &&
		left.Mode == right.Mode &&
		left.SHA256 == right.SHA256 &&
		bytes.Equal(left.Bytes, right.Bytes)
}

func dockerPortComposeConfigRevision(raw []byte, service string) (int64, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var model struct {
		Services map[string]struct {
			Environment map[string]any `json:"environment"`
		} `json:"services"`
	}
	if err := decoder.Decode(&model); err != nil {
		return 0, errors.New("Docker port Compose config revision is unavailable")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return 0, errors.New("Docker port Compose model contains trailing data")
	}
	managed, ok := model.Services[service]
	if !ok {
		return 0, errors.New("Docker port Compose service is unavailable")
	}
	text := fmt.Sprint(managed.Environment["AUTOSTREAM_CONFIG_REVISION"])
	revision, err := strconv.ParseInt(text, 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != text {
		return 0, errors.New("Docker port Compose config revision is invalid")
	}
	return revision, nil
}

func ensureDockerPortWorkDirectory(path string, requireRootOwned bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("Docker port work directory is invalid")
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("create Docker port work directory")
	}
	info, err := os.Lstat(path)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm() != 0o700 {
		return errors.New("Docker port work directory is not private")
	}
	if requireRootOwned && validateSecureRootPath(path, true) != nil {
		return errors.New("Docker port work directory is not root-controlled")
	}
	return nil
}
