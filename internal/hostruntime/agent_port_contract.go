package hostruntime

import (
	"encoding/json"
	"reflect"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

// sharedPortPlan preserves the stable intent union. The execution request's
// separate plan hash binds its runtime session; no desired field is inferred.
func (p SystemdPortMutationGrantBinding) sharedPortPlan() contracts.SystemUpdatePortReconfiguration {
	return contracts.SystemUpdatePortReconfiguration{
		PortContractVersion: p.PortContractVersion, Mode: p.Mode,
		Before: clonePortSnapshotRef(p.Before), Target: clonePortSnapshotRef(p.Target),
		Rollback: clonePortSnapshotRef(p.Rollback), DockerBaseline: clonePortDockerBaseline(p.DockerBaseline),
		NetworkNamespace: p.NetworkNamespace, Protocol: contracts.SystemUpdatePortProtocol(p.Protocol),
		PortPlanSHA256: p.PortPlanSHA256,
		OldPort:        p.OldPort, NewPort: p.NewPort,
		ExpectedEndpointRevision: p.ExpectedEndpointRevision, TargetEndpointRevision: p.TargetEndpointRevision,
		ExpectedConfigRevision: p.ExpectedConfigRevision, TargetConfigRevision: p.TargetConfigRevision,
		ExpectedConfigSHA256: p.ExpectedConfigSHA256, TargetConfigSHA256: p.TargetConfigSHA256,
		ExpectedSourcePolicyRevision:   p.ExpectedSourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  p.ExpectedUpdaterPolicyRevision,
		ExpectedExecutorPolicyRevision: p.ExpectedExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   p.ExpectedExecutorPolicySHA256,
	}
}

func clonePortSnapshotRef(value *contracts.SystemUpdatePortSnapshotRef) *contracts.SystemUpdatePortSnapshotRef {
	if value == nil {
		return nil
	}
	copy := *value
	if value.Docker != nil {
		docker := *value.Docker
		copy.Docker = &docker
	}
	return &copy
}

func clonePortDockerBaseline(value *contracts.SystemUpdatePortDockerBaseline) *contracts.SystemUpdatePortDockerBaseline {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func clonePortResult(value *contracts.SystemUpdatePortResultV2) *contracts.SystemUpdatePortResultV2 {
	if value == nil {
		return nil
	}
	copy := *value
	if value.RuntimeInstance != nil {
		runtime := *value.RuntimeInstance
		copy.RuntimeInstance = &runtime
	}
	return &copy
}

func clonePortMutationBinding(value *SystemdPortMutationGrantBinding) *SystemdPortMutationGrantBinding {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Before = clonePortSnapshotRef(value.Before)
	copy.Target = clonePortSnapshotRef(value.Target)
	copy.Rollback = clonePortSnapshotRef(value.Rollback)
	copy.DockerBaseline = clonePortDockerBaseline(value.DockerBaseline)
	copy.Docker = cloneDockerPortMutationGrantBinding(value.Docker)
	return &copy
}

func clonePortExecutionPlan(value SystemdPortReconfigurePlan) SystemdPortReconfigurePlan {
	copy := value
	copy.Before = clonePortSnapshotRef(value.Before)
	copy.Target = clonePortSnapshotRef(value.Target)
	copy.Rollback = clonePortSnapshotRef(value.Rollback)
	copy.DockerBaseline = clonePortDockerBaseline(value.DockerBaseline)
	copy.Docker = cloneDockerPortMutationGrantBinding(value.Docker)
	return copy
}

func clonePortAgentPolicy(value HostAgentPolicy) HostAgentPolicy {
	// The policy projection is credential-free and all its members are JSON
	// values. A deep copy keeps nested endpoints out of the caller's ownership.
	data, _ := json.Marshal(value)
	var copy HostAgentPolicy
	_ = json.Unmarshal(data, &copy)
	return copy
}

func isPortContractV2(job UpdateJob) bool {
	return job.ProtocolVersion == 2 && job.EffectiveOperation() == updateJobOperationPortReconfigure &&
		job.PortReconfigure != nil && job.PortReconfigure.PortContractVersion == 2
}

func samePortSnapshot(left, right *contracts.SystemUpdatePortSnapshotRef) bool {
	return reflect.DeepEqual(left, right)
}
