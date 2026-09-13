package hostruntime

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalExecutorProbeBindsProcessEndpointIdentityAndRevision(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	target := policy.Targets[0]
	server := newLocalExecutorProbeServer(t, target, "v1.2.3", target.ConfigRevision)
	defer server.Close()
	target.LocalListen = endpointFromServer(t, server)
	policy.Targets[0] = target

	verifier := &fakeLocalTargetVerifier{observations: []LocalProcessObservation{
		validLocalProcessObservation(target, "v1.2.3"),
		validLocalProcessObservation(target, "v1.2.3"),
	}}
	response := handleLocalExecutorRequest(
		context.Background(),
		policy,
		LocalExecutorRequest{Version: LocalExecutorProtocolVersion, Operation: "probe", ServiceID: target.ServiceID},
		verifier,
		server.Client(),
	)
	if response.Error != nil || response.Probe == nil {
		t.Fatalf("response=%+v", response)
	}
	if response.Probe.ConfigRevision != target.ConfigRevision ||
		response.Probe.MainPID != 101 ||
		response.Probe.ListenerPID != 102 ||
		response.Probe.ListenerAddress == "" {
		t.Fatalf("probe=%+v", response.Probe)
	}
	if verifier.calls != 2 {
		t.Fatalf("process/listener identity must be checked before and after HTTP probe; calls=%d", verifier.calls)
	}
}

func TestLocalExecutorProbeUsesDurableAppliedSystemdPortState(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 6
	policy.ProjectionRevision = 7
	policy.PolicyRevision = 8
	policy.Targets[0].EndpointRevision = 4
	adapter, err := systemdPortAdapterFor(
		policy.Targets[0].ServiceType,
		policy.Targets[0].Systemd.Unit,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy.Targets[0].ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.ServiceType,
		policy.Targets[0].LocalListen.Host,
		policy.Targets[0].LocalListen.Port,
		policy.Targets[0].ConfigRevision,
	))
	rootPolicyDigest, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}

	effectiveTarget := policy.Targets[0]
	effectiveTarget.EndpointRevision++
	effectiveTarget.ConfigRevision++
	server := newLocalExecutorProbeServer(
		t,
		effectiveTarget,
		"v1.2.3",
		effectiveTarget.ConfigRevision,
	)
	defer server.Close()
	effectiveTarget.LocalListen = endpointFromServer(t, server)
	effectiveTarget.ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.ServiceType,
		effectiveTarget.LocalListen.Host,
		effectiveTarget.LocalListen.Port,
		effectiveTarget.ConfigRevision,
	))

	stateDir := t.TempDir()
	state, err := newFileSystemdPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SaveApplied(systemdPortAppliedState{
		SchemaVersion:          systemdPortPlanSchemaVersion,
		TargetID:               effectiveTarget.ServiceID,
		ServiceType:            effectiveTarget.ServiceType,
		Port:                   effectiveTarget.LocalListen.Port,
		EndpointRevision:       effectiveTarget.EndpointRevision,
		ConfigRevision:         effectiveTarget.ConfigRevision,
		ConfigSHA256:           effectiveTarget.ConfigSHA256,
		SourcePolicyRevision:   policy.SourcePolicyRevision,
		UpdaterPolicyRevision:  policy.ProjectionRevision,
		ExecutorPolicyRevision: policy.PolicyRevision,
		ExecutorPolicySHA256:   rootPolicyDigest,
		OwnershipEpoch:         3,
	}); err != nil {
		t.Fatal(err)
	}
	sidecarDir := filepath.Join(t.TempDir(), "ports")
	if err := os.Mkdir(sidecarDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sidecarPath := filepath.Join(sidecarDir, "worker.json")
	writeTestFile(t, sidecarPath, string(systemdPortSidecarBytes(
		adapter.ServiceType,
		effectiveTarget.LocalListen.Host,
		effectiveTarget.LocalListen.Port,
		effectiveTarget.ConfigRevision,
	)), 0o600)
	state.sidecarPathForTestOnly = sidecarPath
	reopened, err := newFileSystemdPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	reopened.sidecarPathForTestOnly = sidecarPath
	resolved, err := resolveSystemdPortAppliedTarget(
		policy, policy.Targets[0], reopened,
	)
	if err != nil {
		t.Fatalf("resolve durable applied target: %v", err)
	}
	if resolved.LocalListen != effectiveTarget.LocalListen ||
		resolved.EndpointRevision != effectiveTarget.EndpointRevision ||
		resolved.ConfigRevision != effectiveTarget.ConfigRevision ||
		resolved.ConfigSHA256 != effectiveTarget.ConfigSHA256 {
		t.Fatalf("resolved=%+v effective=%+v", resolved, effectiveTarget)
	}
	verifier := &fakeLocalTargetVerifier{observations: []LocalProcessObservation{
		validLocalProcessObservation(effectiveTarget, "v1.2.3"),
		validLocalProcessObservation(effectiveTarget, "v1.2.3"),
	}}
	response := handleLocalExecutorRequestWithSystemdState(
		context.Background(),
		policy,
		LocalExecutorRequest{
			Version:   LocalExecutorProtocolVersion,
			Operation: "probe",
			ServiceID: effectiveTarget.ServiceID,
		},
		verifier,
		server.Client(),
		reopened,
	)
	if response.Error != nil || response.Probe == nil {
		t.Fatalf("response=%+v error=%+v", response, response.Error)
	}
	if response.Probe.ListenerAddress != effectiveTarget.LocalListen.address() ||
		response.Probe.ConfigRevision != effectiveTarget.ConfigRevision ||
		response.Probe.ConfigSHA256 != effectiveTarget.ConfigSHA256 ||
		response.Probe.PolicySHA256 != rootPolicyDigest {
		t.Fatalf("probe=%+v", response.Probe)
	}
	if policy.Targets[0].LocalListen.Port == effectiveTarget.LocalListen.Port ||
		policy.Targets[0].ConfigRevision == effectiveTarget.ConfigRevision {
		t.Fatal("test did not preserve a stale root policy target")
	}

	writeTestFile(t, sidecarPath, strings.Repeat("x", len(systemdPortSidecarBytes(
		adapter.ServiceType,
		effectiveTarget.LocalListen.Host,
		effectiveTarget.LocalListen.Port,
		effectiveTarget.ConfigRevision,
	))), 0o600)
	untrustedVerifier := &fakeLocalTargetVerifier{}
	untrusted := handleLocalExecutorRequestWithSystemdState(
		context.Background(),
		policy,
		LocalExecutorRequest{
			Version:   LocalExecutorProtocolVersion,
			Operation: "probe",
			ServiceID: effectiveTarget.ServiceID,
		},
		untrustedVerifier,
		server.Client(),
		reopened,
	)
	if untrusted.Error == nil ||
		untrusted.Error.Code != "target_unavailable" ||
		untrusted.Probe != nil ||
		untrustedVerifier.calls != 0 {
		t.Fatalf(
			"tampered sidecar response=%+v verifier_calls=%d",
			untrusted, untrustedVerifier.calls,
		)
	}
}

func TestLocalExecutorProbeUsesDurableAppliedDockerPortStateAfterReopen(t *testing.T) {
	harness := newDockerPortHarness(t)
	policy := harness.policy
	policySHA256, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	effectiveTarget := policy.Targets[0]
	effectiveTarget.EndpointRevision++
	effectiveTarget.ConfigRevision++
	server := newLocalExecutorProbeServer(
		t,
		effectiveTarget,
		"v1.2.3",
		effectiveTarget.ConfigRevision,
	)
	defer server.Close()
	effectiveTarget.LocalListen = endpointFromServer(t, server)
	adapter, err := dockerPortAdapterFor(
		effectiveTarget.ServiceType, effectiveTarget.Docker,
	)
	if err != nil {
		t.Fatal(err)
	}
	sidecarBody, err := dockerPortEnvBytes(
		adapter,
		effectiveTarget.LocalListen.Port,
		18080,
		effectiveTarget.ConfigRevision,
	)
	if err != nil {
		t.Fatal(err)
	}
	effectiveTarget.ConfigSHA256 = dockerPortEnvSHA256(sidecarBody)
	dockerTarget := *effectiveTarget.Docker
	effectiveTarget.Docker = &dockerTarget
	effectiveTarget.Docker.ComposeConfigSHA256 = strings.Repeat("c", 64)

	stateDir := t.TempDir()
	state, err := newFileDockerPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SaveApplied(dockerPortAppliedState{
		SchemaVersion:          1,
		TargetID:               effectiveTarget.ServiceID,
		ServiceType:            effectiveTarget.ServiceType,
		PublishedPort:          effectiveTarget.LocalListen.Port,
		ContainerPort:          18080,
		HealthPort:             effectiveTarget.LocalListen.Port,
		EndpointRevision:       effectiveTarget.EndpointRevision,
		ConfigRevision:         effectiveTarget.ConfigRevision,
		ConfigSHA256:           effectiveTarget.ConfigSHA256,
		ComposeConfigSHA256:    effectiveTarget.Docker.ComposeConfigSHA256,
		SourcePolicyRevision:   policy.SourcePolicyRevision,
		UpdaterPolicyRevision:  policy.ProjectionRevision,
		ExecutorPolicyRevision: policy.PolicyRevision,
		ExecutorPolicySHA256:   policySHA256,
		OwnershipEpoch:         3,
	}); err != nil {
		t.Fatal(err)
	}
	sidecarDir := filepath.Join(t.TempDir(), "docker-ports")
	if err := os.Mkdir(sidecarDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sidecarPath := filepath.Join(sidecarDir, "worker.env")
	writeTestFile(t, sidecarPath, string(sidecarBody), 0o600)
	state.sidecarPathForTestOnly = sidecarPath

	reopened, err := newFileDockerPortStateStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	reopened.sidecarPathForTestOnly = sidecarPath
	verifier := &fakeLocalTargetVerifier{
		observations: []LocalProcessObservation{
			validLocalProcessObservation(effectiveTarget, "v1.2.3"),
			validLocalProcessObservation(effectiveTarget, "v1.2.3"),
		},
		dockerProbe: &LocalExecutorDockerPortProbe{
			CapabilityVersion:   dockerPortCapabilityVersion,
			PublishedPort:       effectiveTarget.LocalListen.Port,
			ContainerPort:       18080,
			HealthPort:          effectiveTarget.LocalListen.Port,
			ComposePolicySHA256: effectiveTarget.Docker.PortComposePolicySHA256,
			ComposeConfigSHA256: effectiveTarget.Docker.ComposeConfigSHA256,
			ComposeRevision:     effectiveTarget.Docker.PortComposeRevision,
			VersionEnvSHA256:    harness.plan.Docker.ExpectedVersionEnvSHA256,
			ContainerID:         harness.plan.Docker.ExpectedContainerID,
			ImageID:             harness.plan.Docker.ExpectedImageID,
			RepositoryDigest:    harness.plan.Docker.ExpectedRepositoryDigest,
		},
	}
	response := handleLocalExecutorRequestWithSystemdState(
		context.Background(),
		policy,
		LocalExecutorRequest{
			Version:   LocalExecutorProtocolVersion,
			Operation: "probe",
			ServiceID: effectiveTarget.ServiceID,
		},
		verifier,
		server.Client(),
		localExecutorAppliedPortState{docker: reopened},
	)
	if response.Error != nil ||
		response.Probe == nil ||
		response.Probe.Docker == nil ||
		response.Probe.ListenerAddress != effectiveTarget.LocalListen.address() ||
		response.Probe.ConfigRevision != effectiveTarget.ConfigRevision ||
		response.Probe.ConfigSHA256 != effectiveTarget.ConfigSHA256 ||
		response.Probe.Docker.PublishedPort != effectiveTarget.LocalListen.Port {
		t.Fatalf("response=%+v", response)
	}
	if len(verifier.observedTargets) != 2 ||
		verifier.observedTargets[0].LocalListen != effectiveTarget.LocalListen ||
		verifier.observedTargets[1].ConfigRevision != effectiveTarget.ConfigRevision {
		t.Fatalf("observed targets=%+v", verifier.observedTargets)
	}
	if policy.Targets[0].LocalListen.Port == effectiveTarget.LocalListen.Port ||
		policy.Targets[0].ConfigRevision == effectiveTarget.ConfigRevision {
		t.Fatal("test did not preserve a stale root policy target")
	}

	writeTestFile(t, sidecarPath, strings.Repeat("x", len(sidecarBody)), 0o600)
	untrustedVerifier := &fakeLocalTargetVerifier{}
	untrusted := handleLocalExecutorRequestWithSystemdState(
		context.Background(),
		policy,
		LocalExecutorRequest{
			Version:   LocalExecutorProtocolVersion,
			Operation: "probe",
			ServiceID: effectiveTarget.ServiceID,
		},
		untrustedVerifier,
		server.Client(),
		localExecutorAppliedPortState{docker: reopened},
	)
	if untrusted.Error == nil ||
		untrusted.Error.Code != "target_unavailable" ||
		untrusted.Probe != nil ||
		untrustedVerifier.calls != 0 {
		t.Fatalf(
			"tampered Docker sidecar response=%+v verifier_calls=%d",
			untrusted, untrustedVerifier.calls,
		)
	}
}

func TestLocalExecutorProbeRejectsUnboundAppliedSystemdPortState(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 6
	policy.ProjectionRevision = 7
	policy.PolicyRevision = 8
	policy.Targets[0].EndpointRevision = 4
	adapter, err := systemdPortAdapterFor(
		policy.Targets[0].ServiceType,
		policy.Targets[0].Systemd.Unit,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy.Targets[0].ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.ServiceType,
		policy.Targets[0].LocalListen.Host,
		policy.Targets[0].LocalListen.Port,
		policy.Targets[0].ConfigRevision,
	))
	policySHA, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	applied := func(port int, endpointRevision, configRevision int64) systemdPortAppliedState {
		return systemdPortAppliedState{
			SchemaVersion:    systemdPortPlanSchemaVersion,
			TargetID:         policy.Targets[0].ServiceID,
			ServiceType:      policy.Targets[0].ServiceType,
			Port:             port,
			EndpointRevision: endpointRevision,
			ConfigRevision:   configRevision,
			ConfigSHA256: systemdPortSidecarSHA256(systemdPortSidecarBytes(
				adapter.ServiceType,
				policy.Targets[0].LocalListen.Host,
				port,
				configRevision,
			)),
			SourcePolicyRevision:   policy.SourcePolicyRevision,
			UpdaterPolicyRevision:  policy.ProjectionRevision,
			ExecutorPolicyRevision: policy.PolicyRevision,
			ExecutorPolicySHA256:   policySHA,
			OwnershipEpoch:         3,
		}
	}
	cases := map[string]systemdPortAppliedState{
		"digest does not bind canonical sidecar": func() systemdPortAppliedState {
			state := applied(18085, 5, 12)
			state.ConfigSHA256 = "sha256:" + strings.Repeat("f", 64)
			return state
		}(),
		"endpoint revision regresses": applied(18085, 3, 12),
		"config revision regresses":   applied(18085, 5, 10),
		"endpoint revision is reused": applied(18085, 4, 12),
		"config revision is reused":   applied(18085, 5, 11),
		"service identity does not match": func() systemdPortAppliedState {
			state := applied(18085, 5, 12)
			state.ServiceType = "discord_bot"
			return state
		}(),
		"source policy lineage is stale": func() systemdPortAppliedState {
			state := applied(18085, 5, 12)
			state.SourcePolicyRevision--
			return state
		}(),
		"projection policy lineage is stale": func() systemdPortAppliedState {
			state := applied(18085, 5, 12)
			state.UpdaterPolicyRevision--
			return state
		}(),
		"executor policy digest is stale": func() systemdPortAppliedState {
			state := applied(18085, 5, 12)
			state.ExecutorPolicySHA256 = "sha256:" + strings.Repeat("d", 64)
			return state
		}(),
		"ownership epoch is absent": func() systemdPortAppliedState {
			state := applied(18085, 5, 12)
			state.OwnershipEpoch = 0
			return state
		}(),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			state := newMemorySystemdPortStateStore()
			if err := state.SaveApplied(candidate); err != nil {
				t.Fatal(err)
			}
			verifier := &fakeLocalTargetVerifier{}
			response := handleLocalExecutorRequestWithSystemdState(
				context.Background(),
				policy,
				LocalExecutorRequest{
					Version:   LocalExecutorProtocolVersion,
					Operation: "probe",
					ServiceID: policy.Targets[0].ServiceID,
				},
				verifier,
				http.DefaultClient,
				state,
			)
			if response.Error == nil || response.Error.Code != "target_unavailable" ||
				response.Probe != nil || verifier.calls != 0 {
				t.Fatalf("response=%+v verifier_calls=%d", response, verifier.calls)
			}
		})
	}
}
