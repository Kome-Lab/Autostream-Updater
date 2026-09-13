package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
)

func authorizeHostAgentSystemdSidecarAdoption(
	stagedPolicy LocalExecutorPolicy,
	stagedIdentity UpdaterConfigureIdentity,
	currentIdentityBytes []byte,
	currentPolicyBytes []byte,
	plans []initialSystemdPortSidecarPlan,
	snapshots map[string]initialSystemdPortSidecarSnapshot,
	parent string,
) (*hostAgentSystemdSidecarAdoption, error) {
	if validateUpdaterConfigureIdentity(
		stagedIdentity,
		stagedIdentity.NodeID,
		"",
	) != nil ||
		stagedIdentity.ServiceType != ServiceTypeUpdateAgent ||
		stagedIdentity.TransportMode != HostTransportPullV2 ||
		stagedIdentity.API != (UpdaterConfigureAPIAssertion{}) {
		return nil, errors.New("live systemd sidecar staged identity is invalid")
	}
	currentIdentity, err := decodeManagedHostAgentIdentity(currentIdentityBytes)
	if err != nil ||
		!sameConfiguredPanelURL(currentIdentity.PanelURL, stagedIdentity.PanelURL) ||
		currentIdentity.NodeID != stagedIdentity.NodeID {
		return nil, errors.New("live systemd sidecar identity binding changed")
	}
	currentPolicy, err := decodeCanonicalLocalExecutorPolicy(currentPolicyBytes)
	if err != nil {
		return nil, errors.New("live systemd sidecar current policy is unavailable")
	}
	if currentPolicy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		currentPolicy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		currentPolicy.Mutation == nil || stagedPolicy.Mutation == nil ||
		currentPolicy.HostID != stagedPolicy.HostID ||
		currentPolicy.AgentUID != stagedPolicy.AgentUID ||
		currentPolicy.AgentGID != stagedPolicy.AgentGID ||
		currentPolicy.SocketPath != stagedPolicy.SocketPath ||
		!sameConfiguredPanelURL(
			currentPolicy.Mutation.PanelURL,
			stagedPolicy.Mutation.PanelURL,
		) ||
		!sameConfiguredPanelURL(
			stagedPolicy.Mutation.PanelURL,
			stagedIdentity.PanelURL,
		) ||
		stagedPolicy.SourcePolicyRevision <= currentPolicy.SourcePolicyRevision ||
		stagedPolicy.ProjectionRevision <= currentPolicy.ProjectionRevision ||
		stagedPolicy.PolicyRevision <= currentPolicy.PolicyRevision {
		return nil, errors.New("live systemd sidecar policy authority did not strictly advance")
	}
	mismatches := make([]initialSystemdPortSidecarPlan, 0, 1)
	for _, plan := range plans {
		snapshot, ok := snapshots[plan.Path]
		if !ok {
			return nil, errors.New("canonical systemd port sidecar was not preflighted")
		}
		if snapshot.Existed && !bytes.Equal(snapshot.Body, plan.Body) {
			mismatches = append(mismatches, plan)
		}
	}
	if len(mismatches) != 1 {
		return nil, errors.New("live systemd sidecar adoption requires exactly one existing mismatch")
	}
	plan := mismatches[0]
	stagedTarget, ok := stagedPolicy.Target(plan.ServiceID)
	if !ok || stagedTarget.DeploymentMode != ModeSystemd ||
		stagedTarget.Systemd == nil ||
		!validSystemdPortServiceType(stagedTarget.ServiceType) {
		return nil, errors.New("live systemd sidecar target is not eligible")
	}
	currentTarget, ok := currentPolicy.Target(plan.ServiceID)
	if !ok || currentTarget.DeploymentMode != ModeSystemd ||
		currentTarget.Systemd == nil ||
		currentTarget.ServiceID != stagedTarget.ServiceID ||
		currentTarget.ServiceType != stagedTarget.ServiceType ||
		currentTarget.DatabaseName != stagedTarget.DatabaseName ||
		currentTarget.EndpointRevision != stagedTarget.EndpointRevision ||
		currentTarget.ConfigRevision != stagedTarget.ConfigRevision ||
		currentTarget.LocalListen.Host != stagedTarget.LocalListen.Host ||
		currentTarget.LocalListen.Port == stagedTarget.LocalListen.Port ||
		!reflect.DeepEqual(currentTarget.Systemd, stagedTarget.Systemd) {
		return nil, errors.New("live systemd sidecar target changed beyond its loopback port")
	}
	adapter, err := systemdPortAdapterFor(
		stagedTarget.ServiceType,
		stagedTarget.Systemd.Unit,
	)
	if err != nil || filepath.Base(adapter.SidecarPath) != filepath.Base(plan.Path) {
		return nil, errors.New("live systemd sidecar target adapter is invalid")
	}
	currentPlans, err := initialSystemdPortSidecarPlans(currentPolicy, parent)
	if err != nil {
		return nil, errors.New("derive live systemd sidecar current policy")
	}
	var currentPlan *initialSystemdPortSidecarPlan
	for index := range currentPlans {
		if currentPlans[index].Path == plan.Path &&
			currentPlans[index].ServiceID == plan.ServiceID {
			currentPlan = &currentPlans[index]
			break
		}
	}
	snapshot := snapshots[plan.Path]
	if currentPlan == nil || !snapshot.Existed ||
		!bytes.Equal(snapshot.Body, currentPlan.Body) ||
		currentTarget.ConfigSHA256 != currentPlan.SHA256 ||
		stagedTarget.ConfigSHA256 != plan.SHA256 {
		return nil, errors.New("existing systemd sidecar is not canonical for the current root policy")
	}
	return &hostAgentSystemdSidecarAdoption{
		plan:          plan,
		currentPolicy: currentPolicy,
		currentTarget: currentTarget,
		stagedTarget:  stagedTarget,
	}, nil
}

func decodeManagedHostAgentIdentity(data []byte) (Config, error) {
	return decodeManagedBootstrapConfig(data)
}

func decodeCanonicalLocalExecutorPolicy(data []byte) (LocalExecutorPolicy, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return LocalExecutorPolicy{}, errors.New("Local Executor policy is missing")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy LocalExecutorPolicy
	if err := decoder.Decode(&policy); err != nil {
		return LocalExecutorPolicy{}, errors.New("decode Local Executor policy")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return LocalExecutorPolicy{}, errors.New("Local Executor policy contains trailing data")
	}
	projection, err := BuildConfigurePolicyProjection(policy)
	if err != nil || !bytes.Equal(data, projection.Policy) {
		return LocalExecutorPolicy{}, errors.New("Local Executor policy is not canonical")
	}
	return policy, nil
}

func sameConfiguredPanelURL(left, right string) bool {
	return strings.TrimRight(strings.TrimSpace(left), "/") ==
		strings.TrimRight(strings.TrimSpace(right), "/")
}

func validateInitialSystemdPortSidecarSnapshots(
	plans []initialSystemdPortSidecarPlan,
	snapshots map[string]initialSystemdPortSidecarSnapshot,
) error {
	for _, plan := range plans {
		snapshot, ok := snapshots[plan.Path]
		if !ok {
			return errors.New("canonical systemd port sidecar was not preflighted")
		}
		if snapshot.Existed && !bytes.Equal(snapshot.Body, plan.Body) {
			return fmt.Errorf(
				"existing systemd port sidecar for %s differs from the active policy target",
				plan.ServiceID,
			)
		}
	}
	return nil
}
