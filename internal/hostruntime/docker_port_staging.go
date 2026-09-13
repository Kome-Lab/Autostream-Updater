package hostruntime

import (
	"context"
	"errors"
	"reflect"
)

func stageDockerPortLedger(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
	adapter dockerPortAdapter,
	plan SystemdPortReconfigurePlan,
	runtime dockerPortRuntime,
) (dockerPortLedger, error) {
	observation, err := runtime.Observe(ctx, policy, target)
	if err != nil || !dockerPortObservationMatchesPlanBaseline(observation, plan) {
		return dockerPortLedger{}, errors.New("Docker port baseline changed")
	}
	oldBytes, err := dockerPortEnvBytes(
		adapter, plan.Docker.OldPublishedPort,
		plan.Docker.OldContainerPort, plan.ExpectedConfigRevision,
	)
	if err != nil ||
		!observation.MappingEnv.Existed ||
		!reflect.DeepEqual(observation.MappingEnv.Bytes, oldBytes) {
		return dockerPortLedger{}, errors.New("Docker port mapping env differs from the plan")
	}
	targetBytes, err := dockerPortEnvBytes(
		adapter, plan.Docker.NewPublishedPort,
		plan.Docker.NewContainerPort, plan.TargetConfigRevision,
	)
	if err != nil || dockerPortEnvSHA256(targetBytes) != plan.TargetConfigSHA256 {
		return dockerPortLedger{}, errors.New("Docker port target env differs from the plan")
	}
	prepared, err := runtime.Prepare(ctx, target, targetBytes)
	if err != nil || !dockerPortPreparedMatchesPlan(prepared, plan) {
		return dockerPortLedger{}, errors.New("Docker port target Compose model is not approved")
	}
	if err := runtime.EnsureAvailable(
		ctx, target, prepared, observation.Runtime.ContainerID,
	); err != nil {
		return dockerPortLedger{}, err
	}
	return dockerPortLedger{
		SchemaVersion: 1, Plan: plan, State: dockerPortLedgerStaged,
		Checkpoint: observation.MappingEnv, TargetBytes: targetBytes,
		Baseline:            observation.Runtime,
		OldComposeSHA256:    observation.ComposeConfigSHA256,
		TargetComposeSHA256: prepared.ComposeConfigSHA256,
	}, nil
}

func recheckDockerPortStagedInputs(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
	ledger dockerPortLedger,
	runtime dockerPortRuntime,
) error {
	observation, err := runtime.Observe(ctx, policy, target)
	if err != nil ||
		!dockerPortObservationMatchesPlanBaseline(observation, ledger.Plan) ||
		!reflect.DeepEqual(observation.MappingEnv, ledger.Checkpoint) ||
		observation.ComposeConfigSHA256 != ledger.OldComposeSHA256 ||
		observation.Runtime != ledger.Baseline {
		return errors.New("Docker port baseline changed while authorizing the mutation")
	}
	prepared, err := runtime.Prepare(ctx, target, ledger.TargetBytes)
	if err != nil ||
		!dockerPortPreparedMatchesPlan(prepared, ledger.Plan) ||
		prepared.ComposeConfigSHA256 != ledger.TargetComposeSHA256 {
		return errors.New("Docker port staged inputs changed while authorizing the mutation")
	}
	return runtime.EnsureAvailable(
		ctx, target, prepared, observation.Runtime.ContainerID,
	)
}

func dockerPortObservationMatchesPlanBaseline(
	observation dockerPortObservation,
	plan SystemdPortReconfigurePlan,
) bool {
	return observation.validate() == nil &&
		observation.PublishedHostIP == plan.Docker.PublishedHostIP &&
		observation.PublishedPort == plan.Docker.OldPublishedPort &&
		observation.ContainerPort == plan.Docker.OldContainerPort &&
		observation.HealthPort == plan.Docker.OldHealthPort &&
		observation.ConfigRevision == plan.ExpectedConfigRevision &&
		observation.ConfigSHA256 == plan.ExpectedConfigSHA256 &&
		observation.ComposePolicySHA256 == plan.Docker.ApprovedComposeConfigSHA256 &&
		observation.Runtime.VersionEnvSHA256 == plan.Docker.ExpectedVersionEnvSHA256 &&
		dockerContainerIDsMatch(observation.Runtime.ContainerID, plan.Docker.ExpectedContainerID) &&
		observation.Runtime.ImageID == plan.Docker.ExpectedImageID &&
		observation.Runtime.RepositoryDigest == plan.Docker.ExpectedRepositoryDigest
}

func dockerPortPreparedMatchesPlan(
	prepared dockerPortPreparedModel,
	plan SystemdPortReconfigurePlan,
) bool {
	return prepared.validate() == nil &&
		prepared.ComposePolicySHA256 == plan.Docker.ApprovedComposeConfigSHA256 &&
		prepared.PublishedHostIP == plan.Docker.PublishedHostIP &&
		prepared.PublishedPort == plan.Docker.NewPublishedPort &&
		prepared.ContainerPort == plan.Docker.NewContainerPort &&
		prepared.HealthPort == plan.Docker.NewHealthPort
}

func dockerPortObservationMatchesTarget(
	observation dockerPortObservation,
	plan SystemdPortReconfigurePlan,
	ledger dockerPortLedger,
	targetSide bool,
) bool {
	if observation.validate() != nil ||
		observation.ComposePolicySHA256 != plan.Docker.ApprovedComposeConfigSHA256 ||
		observation.Runtime.VersionEnvSHA256 != ledger.Baseline.VersionEnvSHA256 ||
		observation.Runtime.ImageID != ledger.Baseline.ImageID ||
		observation.Runtime.RepositoryDigest != ledger.Baseline.RepositoryDigest ||
		observation.Runtime.CurrentVersion != ledger.Baseline.CurrentVersion {
		return false
	}
	if targetSide {
		return observation.PublishedHostIP == plan.Docker.PublishedHostIP &&
			observation.PublishedPort == plan.Docker.NewPublishedPort &&
			observation.ContainerPort == plan.Docker.NewContainerPort &&
			observation.HealthPort == plan.Docker.NewHealthPort &&
			observation.ConfigRevision == plan.TargetConfigRevision &&
			observation.ConfigSHA256 == plan.TargetConfigSHA256 &&
			observation.ComposeConfigSHA256 == ledger.TargetComposeSHA256 &&
			!dockerContainerIDsMatch(observation.Runtime.ContainerID, ledger.Baseline.ContainerID)
	}
	return observation.PublishedHostIP == plan.Docker.PublishedHostIP &&
		observation.PublishedPort == plan.Docker.OldPublishedPort &&
		observation.ContainerPort == plan.Docker.OldContainerPort &&
		observation.HealthPort == plan.Docker.OldHealthPort &&
		observation.ConfigRevision == plan.ExpectedConfigRevision &&
		observation.ConfigSHA256 == plan.ExpectedConfigSHA256 &&
		observation.ComposeConfigSHA256 == ledger.OldComposeSHA256
}

func dockerPortTargetAfter(
	target LocalExecutorTarget,
	plan SystemdPortReconfigurePlan,
	composeSHA256 string,
) LocalExecutorTarget {
	updated := target
	updated.LocalListen.Port = plan.Docker.NewHealthPort
	updated.EndpointRevision = plan.TargetEndpointRevision
	updated.ConfigRevision = plan.TargetConfigRevision
	updated.ConfigSHA256 = plan.TargetConfigSHA256
	docker := *target.Docker
	docker.ComposeConfigSHA256 = composeSHA256
	updated.Docker = &docker
	return updated
}
