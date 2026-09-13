package hostruntime

import (
	"context"
	"strings"
	"testing"
)

func TestLocalExecutorHostObserverRequiresPinnedMatchingPolicy(t *testing.T) {
	rootPolicy := validLocalExecutorPolicy(t)
	rootPolicy.Targets[0].LocalListen = LocalExecutorEndpoint{Host: "127.0.0.1", Port: 18084}
	configDigest := "sha256:" + strings.Repeat("c", 64)
	rootPolicy.Targets[0].ConfigSHA256 = configDigest
	digest, err := rootPolicy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	probe := LocalExecutorProbe{
		ServiceID:       "worker-01",
		ServiceType:     "worker",
		DeploymentMode:  ModeSystemd,
		PolicyRevision:  rootPolicy.PolicyRevision,
		PolicySHA256:    digest,
		ConfigRevision:  rootPolicy.Targets[0].ConfigRevision,
		ConfigSHA256:    configDigest,
		CurrentVersion:  "v1.2.3",
		MainPID:         101,
		ListenerPID:     102,
		ControlGroup:    "/system.slice/autostream-worker.service",
		ListenerAddress: "127.0.0.1:18084",
	}
	policy := HostAgentPolicy{
		ServiceID:                   "host-agent-a",
		TransportMode:               HostTransportPullV2,
		ExecutionHostID:             "host-a",
		OwnershipEpoch:              1,
		Revision:                    13,
		SourcePolicyRevision:        5,
		LocalExecutorPolicyRevision: rootPolicy.PolicyRevision,
		ObserveOnly:                 false,
		LocalExecutorPolicySHA256:   digest,
		Targets: []HostAgentPolicyTarget{{
			ServiceID:             "worker-01",
			ServiceType:           "worker",
			DeploymentMode:        ModeSystemd,
			AppliedConfigRevision: rootPolicy.Targets[0].ConfigRevision,
			AppliedConfigSHA256:   configDigest,
			LocalListenEndpoint: &HostAgentEndpoint{
				Host: "127.0.0.1", Port: 18084, PublicURL: "http://127.0.0.1:18084",
			},
		}},
	}
	client := &fakeLocalExecutorProbeClient{probes: map[string]LocalExecutorProbe{"worker-01": probe}}
	observer := NewLocalExecutorTargetObserver(client)
	observations, err := observer(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 ||
		observations[0].Availability != TargetAvailabilityAvailable ||
		observations[0].AvailabilityCode != "executor_verified" ||
		observations[0].ReportedPort != 18084 ||
		observations[0].PolicySHA256 != digest ||
		observations[0].ConfigRevision != 11 ||
		observations[0].ConfigSHA256 != configDigest {
		t.Fatalf("observations=%+v", observations)
	}
	capabilities := (&HostPullAgent{}).capabilities(HostAgentBinding{}, &policy, observations, false)
	if capabilities["reported_service_types"].(map[string]string)["worker-01"] != "worker" ||
		capabilities["reported_deployment_modes"].(map[string]string)["worker-01"] != ModeSystemd ||
		capabilities["reported_executor_policy_revisions"].(map[string]int64)["worker-01"] != rootPolicy.PolicyRevision ||
		capabilities["reported_executor_policy_sha256"].(map[string]string)["worker-01"] != digest ||
		capabilities["reported_config_revisions"].(map[string]int64)["worker-01"] != 11 ||
		capabilities["reported_config_sha256"].(map[string]string)["worker-01"] != configDigest {
		t.Fatalf("executor capabilities=%+v", capabilities)
	}

	t.Run("unpinned policy is unknown without socket call", func(t *testing.T) {
		unpinned := policy
		unpinned.LocalExecutorPolicySHA256 = ""
		client.calls = 0
		observations, err := observer(context.Background(), unpinned)
		if err != nil {
			t.Fatal(err)
		}
		if client.calls != 0 || observations[0].Availability != TargetAvailabilityUnknown ||
			observations[0].AvailabilityCode != "executor_policy_unpinned" {
			t.Fatalf("calls=%d observations=%+v", client.calls, observations)
		}
	})

	t.Run("legacy systemd target requires a valid reported config digest", func(t *testing.T) {
		legacy := policy
		legacy.OwnershipEpoch = 0
		legacy.ObserveOnly = true
		legacy.Targets = append([]HostAgentPolicyTarget(nil), policy.Targets...)
		legacy.Targets[0].AppliedConfigSHA256 = ""

		for _, testCase := range []struct {
			name             string
			reportedDigest   string
			wantAvailability string
			wantCode         string
		}{
			{
				name:             "valid digest is accepted for backfill",
				reportedDigest:   configDigest,
				wantAvailability: TargetAvailabilityAvailable,
				wantCode:         "executor_verified",
			},
			{
				name:             "empty digest is rejected",
				reportedDigest:   "",
				wantAvailability: TargetAvailabilityUnavailable,
				wantCode:         "executor_probe_mismatch",
			},
			{
				name:             "invalid digest is rejected",
				reportedDigest:   "sha256:not-a-digest",
				wantAvailability: TargetAvailabilityUnavailable,
				wantCode:         "executor_probe_mismatch",
			},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				candidate := probe
				candidate.ConfigSHA256 = testCase.reportedDigest
				legacyClient := &fakeLocalExecutorProbeClient{
					probes: map[string]LocalExecutorProbe{"worker-01": candidate},
				}
				legacyObserver := NewLocalExecutorTargetObserver(legacyClient)
				observations, err := legacyObserver(context.Background(), legacy)
				if err != nil {
					t.Fatal(err)
				}
				if len(observations) != 1 ||
					observations[0].Availability != testCase.wantAvailability ||
					observations[0].AvailabilityCode != testCase.wantCode {
					t.Fatalf("observations=%+v", observations)
				}
				if testCase.wantAvailability == TargetAvailabilityAvailable &&
					observations[0].ConfigSHA256 != testCase.reportedDigest {
					t.Fatalf("reported config digest was not preserved: %+v", observations)
				}
			})
		}
	})

	t.Run("active systemd target without applied config digest fails closed", func(t *testing.T) {
		active := policy
		active.Targets = append([]HostAgentPolicyTarget(nil), policy.Targets...)
		active.Targets[0].AppliedConfigSHA256 = ""
		activeClient := &fakeLocalExecutorProbeClient{
			probes: map[string]LocalExecutorProbe{"worker-01": probe},
		}
		observations, err := NewLocalExecutorTargetObserver(activeClient)(
			context.Background(), active,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(observations) != 1 ||
			observations[0].Availability != TargetAvailabilityUnavailable ||
			observations[0].AvailabilityCode != "executor_probe_mismatch" {
			t.Fatalf("observations=%+v", observations)
		}
	})

	t.Run("digest mismatch fails closed", func(t *testing.T) {
		mismatch := probe
		mismatch.PolicySHA256 = "sha256:" + strings.Repeat("b", 64)
		client.probes["worker-01"] = mismatch
		observations, err := observer(context.Background(), policy)
		if err != nil {
			t.Fatal(err)
		}
		if observations[0].Availability != TargetAvailabilityUnavailable ||
			observations[0].AvailabilityCode != "executor_policy_mismatch" {
			t.Fatalf("observations=%+v", observations)
		}
	})

	t.Run("applied config digest mismatch fails closed", func(t *testing.T) {
		mismatch := probe
		mismatch.ConfigSHA256 = "sha256:" + strings.Repeat("d", 64)
		client.probes["worker-01"] = mismatch
		observations, err := observer(context.Background(), policy)
		if err != nil {
			t.Fatal(err)
		}
		if observations[0].Availability != TargetAvailabilityUnavailable ||
			observations[0].AvailabilityCode != "executor_probe_mismatch" {
			t.Fatalf("observations=%+v", observations)
		}
	})
}

func TestLocalExecutorHostObserverReportsVerifiedDockerPortMapping(t *testing.T) {
	policyDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	composePolicyDigest := strings.Repeat("c", 64)
	probe := LocalExecutorProbe{
		ServiceID:       "worker-01",
		ServiceType:     "worker",
		DeploymentMode:  ModeDocker,
		PolicyRevision:  9,
		PolicySHA256:    policyDigest,
		ConfigRevision:  12,
		ConfigSHA256:    configDigest,
		CurrentVersion:  "v1.2.3",
		MainPID:         101,
		ListenerPID:     102,
		ControlGroup:    "/docker/worker-01",
		ListenerAddress: "127.0.0.1:18081",
		Docker: &LocalExecutorDockerPortProbe{
			CapabilityVersion:   dockerPortCapabilityVersion,
			PublishedPort:       18081,
			ContainerPort:       8084,
			HealthPort:          18081,
			ComposePolicySHA256: composePolicyDigest,
			ComposeConfigSHA256: strings.Repeat("d", 64),
			ComposeRevision:     9,
			VersionEnvSHA256:    "sha256:" + strings.Repeat("e", 64),
			ContainerID:         strings.Repeat("f", 64),
			ImageID:             "sha256:" + strings.Repeat("1", 64),
			RepositoryDigest:    "sha256:" + strings.Repeat("2", 64),
		},
	}
	policy := HostAgentPolicy{
		ServiceID:                   "host-agent-a",
		TransportMode:               HostTransportPullV2,
		ExecutionHostID:             "host-a",
		OwnershipEpoch:              1,
		Revision:                    13,
		SourcePolicyRevision:        5,
		LocalExecutorPolicyRevision: 9,
		LocalExecutorPolicySHA256:   policyDigest,
		Targets: []HostAgentPolicyTarget{{
			ServiceID:             "worker-01",
			ServiceType:           "worker",
			DeploymentMode:        ModeDocker,
			AppliedConfigRevision: 12,
			AppliedConfigSHA256:   configDigest,
			AppliedEndpoint: &HostAgentEndpoint{
				Host: "worker.example.com", Port: 443,
				SSLEnabled: true, PublicURL: "https://worker.example.com",
			},
		}},
	}
	client := &fakeLocalExecutorProbeClient{
		probes: map[string]LocalExecutorProbe{"worker-01": probe},
	}
	observer := NewLocalExecutorTargetObserver(client)
	observations, err := observer(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 ||
		observations[0].Availability != TargetAvailabilityAvailable ||
		observations[0].ReportedPort != 18081 ||
		observations[0].Docker == nil ||
		observations[0].Docker.AdvertisedPort != 443 ||
		observations[0].Docker.ComposeConfigSHA256 != probe.Docker.ComposeConfigSHA256 {
		t.Fatalf("observations=%+v", observations)
	}
	capabilities := (&HostPullAgent{}).capabilities(
		HostAgentBinding{}, &policy, observations, false,
	)
	if capabilities["reported_ports"].(map[string]int)["worker-01"] != 443 ||
		capabilities["reported_docker_port_capabilities"].(map[string]string)["worker-01"] != dockerPortCapabilityVersion ||
		capabilities["reported_docker_published_ports"].(map[string]int)["worker-01"] != 18081 ||
		capabilities["reported_docker_container_ports"].(map[string]int)["worker-01"] != 8084 ||
		capabilities["reported_docker_health_ports"].(map[string]int)["worker-01"] != 18081 ||
		capabilities["reported_docker_compose_sha256"].(map[string]string)["worker-01"] != composePolicyDigest ||
		capabilities["reported_docker_compose_config_sha256"].(map[string]string)["worker-01"] != probe.Docker.ComposeConfigSHA256 ||
		capabilities["reported_docker_compose_revisions"].(map[string]int64)["worker-01"] != 9 ||
		capabilities["reported_docker_version_env_sha256"].(map[string]string)["worker-01"] != probe.Docker.VersionEnvSHA256 ||
		capabilities["reported_docker_container_ids"].(map[string]string)["worker-01"] != probe.Docker.ContainerID ||
		capabilities["reported_docker_image_ids"].(map[string]string)["worker-01"] != probe.Docker.ImageID ||
		capabilities["reported_docker_repository_digests"].(map[string]string)["worker-01"] != probe.Docker.RepositoryDigest {
		t.Fatalf("Docker capabilities=%+v", capabilities)
	}
	if drift := capabilities["port_drift"].(map[string]bool)["worker-01"]; drift {
		t.Fatalf("local Docker listener was reported as drifted: %+v", capabilities)
	}

	t.Run("unverified full Compose digest is not advertised", func(t *testing.T) {
		for _, test := range []struct {
			name         string
			availability string
			digest       string
			failed       bool
		}{
			{"missing", TargetAvailabilityAvailable, "", false},
			{"malformed", TargetAvailabilityAvailable, "not-a-digest", false},
			{"unavailable", TargetAvailabilityUnavailable, probe.Docker.ComposeConfigSHA256, false},
			{"unknown", TargetAvailabilityUnknown, probe.Docker.ComposeConfigSHA256, false},
			{"failed", TargetAvailabilityAvailable, probe.Docker.ComposeConfigSHA256, true},
		} {
			t.Run(test.name, func(t *testing.T) {
				changed := observations[0]
				docker := *changed.Docker
				docker.ComposeConfigSHA256 = test.digest
				changed.Docker, changed.Availability = &docker, test.availability
				caps := (&HostPullAgent{}).capabilities(HostAgentBinding{}, &policy, []HostTargetObservation{changed}, test.failed)
				if len(caps["reported_docker_compose_config_sha256"].(map[string]string)) != 0 {
					t.Fatal("unverified runtime Compose digest was advertised")
				}
			})
		}
		caps := (&HostPullAgent{}).capabilities(HostAgentBinding{}, nil, nil, false)
		if len(caps["reported_docker_compose_config_sha256"].(map[string]string)) != 0 {
			t.Fatal("missing policy retained a runtime Compose observation")
		}
	})

	t.Run("missing advertised endpoint fails closed", func(t *testing.T) {
		incomplete := policy
		incomplete.Targets = append(
			[]HostAgentPolicyTarget(nil), policy.Targets...,
		)
		incomplete.Targets[0].AppliedEndpoint = nil
		observations, err := observer(context.Background(), incomplete)
		if err != nil {
			t.Fatal(err)
		}
		if observations[0].Availability != TargetAvailabilityUnknown ||
			observations[0].AvailabilityCode != "executor_policy_incomplete" ||
			observations[0].Docker != nil {
			t.Fatalf("observations=%+v", observations)
		}
	})
}
