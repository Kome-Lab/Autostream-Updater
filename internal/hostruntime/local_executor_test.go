package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLocalExecutorRequestIsProbeOnlyAndStrict(t *testing.T) {
	valid := `{"version":1,"operation":"probe","service_id":"worker-01"}`
	request, err := DecodeLocalExecutorRequest(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("DecodeLocalExecutorRequest: %v", err)
	}
	if request != (LocalExecutorRequest{Version: 1, Operation: "probe", ServiceID: "worker-01"}) {
		t.Fatalf("request=%+v", request)
	}

	for name, payload := range map[string]string{
		"mutation":       `{"version":1,"operation":"apply","service_id":"worker-01"}`,
		"unknown":        `{"version":1,"operation":"probe","service_id":"worker-01","command":"/bin/sh"}`,
		"path":           `{"version":1,"operation":"probe","service_id":"worker-01","path":"/tmp/payload"}`,
		"unit":           `{"version":1,"operation":"probe","service_id":"worker-01","unit":"attacker.service"}`,
		"url":            `{"version":1,"operation":"probe","service_id":"worker-01","url":"http://127.0.0.1:1"}`,
		"image":          `{"version":1,"operation":"probe","service_id":"worker-01","image":"attacker/image"}`,
		"credential":     `{"version":1,"operation":"probe","service_id":"worker-01","mutation_grant":"secret"}`,
		"second request": valid + "\n" + valid,
		"trailing":       valid + "x",
		"bad identity":   `{"version":1,"operation":"probe","service_id":"../worker"}`,
		"wrong version":  `{"version":2,"operation":"probe","service_id":"worker-01"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLocalExecutorRequest(strings.NewReader(payload)); err == nil {
				t.Fatal("malformed or privileged request was accepted")
			}
		})
	}

	oversize := `{"version":1,"operation":"probe","service_id":"` +
		strings.Repeat("a", LocalExecutorProtocolMaxFrameBytes) + `"}`
	if _, err := DecodeLocalExecutorRequest(strings.NewReader(oversize)); err == nil {
		t.Fatal("oversized request was accepted")
	}
}

func TestLocalExecutorResponseFromOutcomePreservesSafeFailureMessage(t *testing.T) {
	response := localExecutorResponseFromOutcome(executorMutationOutcome{
		Error: &executorMutationFailure{
			Code:    "stage_failed",
			Message: "candidate binary smoke execution failed",
		},
	})
	if err := response.Validate(); err != nil {
		t.Fatalf("response.Validate: %v", err)
	}
	if response.Error == nil || response.Error.Code != "stage_failed" || response.Error.Message != "candidate binary smoke execution failed" {
		t.Fatalf("response=%+v", response)
	}
	versionMismatch := localExecutorResponseFromOutcome(executorMutationOutcome{
		Error: &executorMutationFailure{
			Code:    "stage_failed",
			Message: "candidate binary version output mismatch",
		},
	})
	if err := versionMismatch.Validate(); err != nil {
		t.Fatalf("versionMismatch.Validate: %v", err)
	}
	if versionMismatch.Error == nil || versionMismatch.Error.Code != "stage_failed" || versionMismatch.Error.Message != "candidate binary version output mismatch" {
		t.Fatalf("versionMismatch=%+v", versionMismatch)
	}
}

func TestLocalExecutorMutationProtocolCarriesOnlyBoundedPlanAndEphemeralGrant(t *testing.T) {
	plan := validMutationPlan()
	request := LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: "stage", ServiceID: plan.TargetID,
		Plan: &plan, SourcePolicyRevision: 5, OwnershipEpoch: 7,
		OwnershipPolicyRevision: 11, ExecutorPolicyRevision: 13,
	}
	var encoded bytes.Buffer
	if err := EncodeLocalExecutorRequest(&encoded, request); err != nil {
		t.Fatalf("EncodeLocalExecutorRequest: %v", err)
	}
	payload := encoded.String()
	if strings.Contains(payload, "credential") || strings.Contains(payload, "[REDACTED]") {
		t.Fatalf("stage transferred a credential: %q", payload)
	}
	decoded, err := DecodeLocalExecutorRequest(&encoded)
	if err != nil {
		t.Fatalf("DecodeLocalExecutorRequest: %v", err)
	}
	if decoded.Plan == nil || decoded.Plan.PlanSHA256 != plan.PlanSHA256 ||
		decoded.SourcePolicyRevision != 5 ||
		decoded.OwnershipEpoch != 7 ||
		decoded.OwnershipPolicyRevision != 11 ||
		decoded.ExecutorPolicyRevision != 13 {
		t.Fatalf("decoded=%+v", decoded)
	}

	for name, payload := range map[string]string{
		"version one mutation": `{"version":1,"operation":"apply","service_id":"worker-01"}`,
		"arbitrary command":    `{"version":2,"operation":"apply","service_id":"worker-01","command":"/bin/sh"}`,
		"arbitrary path":       `{"version":2,"operation":"apply","service_id":"worker-01","path":"/tmp/payload"}`,
		"arbitrary unit":       `{"version":2,"operation":"apply","service_id":"worker-01","unit":"attacker.service"}`,
		"arbitrary url":        `{"version":2,"operation":"apply","service_id":"worker-01","url":"https://attacker.example"}`,
		"arbitrary image":      `{"version":2,"operation":"apply","service_id":"worker-01","image":"attacker/image"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLocalExecutorRequest(strings.NewReader(payload)); err == nil {
				t.Fatal("unbounded privileged input was accepted")
			}
		})
	}

	apply := request
	apply.Operation = "apply"
	apply.MutationGrant = NewBoundedSecret("one-time-mutation-grant")
	encoded.Reset()
	if err := EncodeLocalExecutorRequest(&encoded, apply); err != nil {
		t.Fatalf("encode apply: %v", err)
	}
	if _, err := DecodeLocalExecutorRequest(&encoded); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
}

func TestLocalExecutorResponseIsBoundedAndStrict(t *testing.T) {
	response := LocalExecutorResponse{
		Version: LocalExecutorProtocolVersion,
		Probe: &LocalExecutorProbe{
			ServiceID:       "worker-01",
			ServiceType:     "worker",
			DeploymentMode:  ModeSystemd,
			PolicyRevision:  7,
			PolicySHA256:    "sha256:" + strings.Repeat("a", 64),
			ConfigRevision:  11,
			CurrentVersion:  "v1.2.3",
			MainPID:         101,
			ListenerPID:     102,
			ControlGroup:    "/system.slice/autostream-worker.service",
			ListenerAddress: "127.0.0.1:18084",
		},
	}
	var encoded bytes.Buffer
	if err := EncodeLocalExecutorResponse(&encoded, response); err != nil {
		t.Fatalf("EncodeLocalExecutorResponse: %v", err)
	}
	decoded, err := DecodeLocalExecutorResponse(&encoded)
	if err != nil {
		t.Fatalf("DecodeLocalExecutorResponse: %v", err)
	}
	if decoded.Probe == nil || decoded.Probe.ServiceID != "worker-01" {
		t.Fatalf("decoded=%+v", decoded)
	}

	for name, payload := range map[string]string{
		"unknown": `{"version":1,"error":{"code":"invalid_request","message":"request rejected","secret":"no"}}`,
		"both":    `{"version":1,"probe":` + mustJSON(t, response.Probe) + `,"error":{"code":"invalid_request","message":"request rejected"}}`,
		"bad code": `{"version":1,"error":{"code":"arbitrary",
			"message":"request rejected"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLocalExecutorResponse(strings.NewReader(payload)); err == nil {
				t.Fatal("invalid response was accepted")
			}
		})
	}
}

func TestLocalExecutorPolicyValidationAndStrictLoad(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	digest, err := policy.SHA256()
	if err != nil || !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		t.Fatalf("digest=%q err=%v", digest, err)
	}

	for name, mutate := range map[string]func(*LocalExecutorPolicy){
		"root agent": func(policy *LocalExecutorPolicy) {
			policy.AgentUID = 0
		},
		"relative socket": func(policy *LocalExecutorPolicy) {
			policy.SocketPath = "executor.sock"
		},
		"non-fixed socket": func(policy *LocalExecutorPolicy) {
			policy.SocketPath = filepath.Join(filepath.Dir(LocalExecutorSocketPath), "other.sock")
		},
		"non-loopback": func(policy *LocalExecutorPolicy) {
			policy.Targets[0].LocalListen.Host = "192.0.2.1"
		},
		"localhost dns": func(policy *LocalExecutorPolicy) {
			policy.Targets[0].LocalListen.Host = "localhost"
		},
		"bad port": func(policy *LocalExecutorPolicy) {
			policy.Targets[0].LocalListen.Port = 0
		},
		"missing config revision": func(policy *LocalExecutorPolicy) {
			policy.Targets[0].ConfigRevision = 0
		},
		"duplicate service": func(policy *LocalExecutorPolicy) {
			policy.Targets = append(policy.Targets, policy.Targets[0])
		},
		"duplicate privileged target": func(policy *LocalExecutorPolicy) {
			duplicate := policy.Targets[0]
			duplicate.ServiceID = "worker-02"
			policy.Targets = append(policy.Targets, duplicate)
		},
		"mixed deployment": func(policy *LocalExecutorPolicy) {
			docker := validLocalDockerTarget(t)
			policy.Targets[0].Docker = &docker
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneLocalExecutorPolicy(t, policy)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}

	for _, testCase := range []struct {
		port  int
		valid bool
	}{
		{port: 1023, valid: false},
		{port: 1024, valid: true},
		{port: 65535, valid: true},
		{port: 65536, valid: false},
	} {
		t.Run(fmt.Sprintf("port_%d", testCase.port), func(t *testing.T) {
			candidate := cloneLocalExecutorPolicy(t, policy)
			candidate.Targets[0].LocalListen.Port = testCase.port
			err := candidate.Validate()
			if testCase.valid && err != nil {
				t.Fatalf("valid boundary rejected: %v", err)
			}
			if !testCase.valid && err == nil {
				t.Fatal("invalid boundary accepted")
			}
		})
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "executor-policy.json")
	writeTestFile(t, path, mustJSON(t, policy), 0o600)
	loaded, err := LoadLocalExecutorPolicy(path, false)
	if err != nil {
		t.Fatalf("LoadLocalExecutorPolicy: %v", err)
	}
	if loaded.HostID != policy.HostID {
		t.Fatalf("loaded=%+v", loaded)
	}

	writeTestFile(t, path, strings.TrimSuffix(mustJSON(t, policy), "}")+`,"unknown":true}`, 0o600)
	if _, err := LoadLocalExecutorPolicy(path, false); err == nil {
		t.Fatal("unknown policy field was accepted")
	}

	writeTestFile(t, path, mustJSON(t, policy), 0o600)
	symlink := filepath.Join(dir, "executor-policy-link.json")
	if err := os.Symlink(path, symlink); err == nil {
		if _, err := LoadLocalExecutorPolicy(symlink, false); err == nil {
			t.Fatal("symlink policy was accepted")
		}
	}
}

func TestLocalExecutorMutationRequiresExplicitRootOwnedPolicyV2(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	if _, err := policy.mutationHelperConfig(runtime.GOARCH); err == nil {
		t.Fatal("probe-only policy enabled mutation")
	}
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 3
	policy.ProjectionRevision = 5
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate mutation policy: %v", err)
	}
	cfg, err := policy.mutationHelperConfig(runtime.GOARCH)
	if err != nil {
		t.Fatalf("mutationHelperConfig: %v", err)
	}
	if cfg.PanelURL != "https://panel.example.com" ||
		cfg.StateDir != LocalExecutorMutationStateDir ||
		cfg.HostID != policy.HostID ||
		len(cfg.Targets) != len(policy.Targets) {
		t.Fatalf("cfg=%+v", cfg)
	}

	for name, mutate := range map[string]func(*LocalExecutorPolicy){
		"missing mutation": func(candidate *LocalExecutorPolicy) { candidate.Mutation = nil },
		"request protocol": func(candidate *LocalExecutorPolicy) { candidate.ProtocolVersion = LocalExecutorProtocolVersion },
		"untrusted panel": func(candidate *LocalExecutorPolicy) {
			candidate.Mutation.PanelURL = "http://attacker.example"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneLocalExecutorPolicy(t, policy)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid mutation policy was accepted")
			}
		})
	}
}

func TestLocalExecutorPolicyFixesPrivilegedSystemdProfiles(t *testing.T) {
	base := validLocalExecutorPolicy(t)
	for name, mutate := range map[string]func(*LocalExecutorTarget){
		"systemctl": func(target *LocalExecutorTarget) {
			target.Systemd.SystemctlPath = "/tmp/systemctl"
		},
		"unit": func(target *LocalExecutorTarget) {
			target.Systemd.Unit = "attacker.service"
		},
		"release root": func(target *LocalExecutorTarget) {
			target.Systemd.ReleaseRoot = "/tmp/releases"
		},
		"current link": func(target *LocalExecutorTarget) {
			target.Systemd.CurrentLink = "/tmp/current"
		},
		"binary": func(target *LocalExecutorTarget) {
			target.Systemd.BinaryPath = "bin/attacker"
		},
		"smoke user": func(target *LocalExecutorTarget) {
			target.Systemd.SmokeUser = "root"
		},
		"unexpected database": func(target *LocalExecutorTarget) {
			target.DatabaseName = "attacker"
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := base
			policy.Targets = append([]LocalExecutorTarget(nil), base.Targets...)
			systemd := *base.Targets[0].Systemd
			policy.Targets[0].Systemd = &systemd
			mutate(&policy.Targets[0])
			if err := policy.Validate(); err == nil {
				t.Fatal("privileged systemd profile drift was accepted")
			}
		})
	}

	profile, ok := standardSystemdProfileFor("control_panel")
	if !ok {
		t.Fatal("control panel fixed profile is unavailable")
	}
	control := base.Targets[0]
	control.ServiceID = "control-panel"
	control.ServiceType = "control_panel"
	control.DatabaseName = "autostream_control_panel"
	control.LocalListen.Port = profile.port
	control.Systemd = &SystemdTarget{
		SystemctlPath: "/usr/bin/systemctl",
		RunuserPath:   "/usr/sbin/runuser",
		SmokeUser:     "autostream",
		Unit:          profile.unit,
		ReleaseRoot:   profile.releaseRoot,
		CurrentLink:   profile.currentLink,
		BinaryPath:    profile.binaryPath,
		RequiredPaths: append([]string(nil), profile.requiredPaths...),
	}
	base.Targets = []LocalExecutorTarget{control}
	if err := base.Validate(); err != nil {
		t.Fatalf("fixed control panel policy rejected: %v", err)
	}
	runtimeTarget := control.runtimeTarget(base.HostID)
	if len(runtimeTarget.BackupArgv) != 2 ||
		runtimeTarget.BackupArgv[0] != profile.backupExecutable ||
		runtimeTarget.BackupArgv[1] != control.DatabaseName {
		t.Fatalf("fixed backup policy was not derived: %#v", runtimeTarget.BackupArgv)
	}
}

func TestLocalExecutorPolicyFixesPrivilegedDockerProfiles(t *testing.T) {
	base := validLocalExecutorPolicy(t)
	target := base.Targets[0]
	target.DeploymentMode = ModeDocker
	target.Systemd = nil
	docker := validLocalDockerTarget(t)
	target.Docker = &docker
	base.Targets = []LocalExecutorTarget{target}
	if err := base.Validate(); err != nil {
		t.Fatalf("fixed Docker policy rejected: %v", err)
	}

	for name, mutate := range map[string]func(*DockerTarget){
		"docker executable": func(target *DockerTarget) {
			target.DockerPath = "/tmp/docker"
		},
		"compose project": func(target *DockerTarget) {
			target.ComposeProject = "attacker"
		},
		"project directory": func(target *DockerTarget) {
			target.ProjectDir = "/tmp/project"
		},
		"compose file": func(target *DockerTarget) {
			target.ComposeFiles[0] = "/tmp/compose.yml"
		},
		"service": func(target *DockerTarget) {
			target.Service = "control-panel"
		},
		"image repository": func(target *DockerTarget) {
			target.ImageRepo = "ghcr.io/kome-lab/autostream-docker/control-panel"
		},
		"image variable": func(target *DockerTarget) {
			target.ImageVariable = "ATTACKER_VERSION"
		},
		"base environment": func(target *DockerTarget) {
			target.BaseEnvFile = "/tmp/base.env"
		},
		"version environment": func(target *DockerTarget) {
			target.VersionEnvFile = "/tmp/version.env"
		},
		"channel": func(target *DockerTarget) {
			target.Channel = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := cloneLocalExecutorPolicy(t, base)
			policy.Targets[0].Docker.ComposeFiles = append([]string(nil), policy.Targets[0].Docker.ComposeFiles...)
			mutate(policy.Targets[0].Docker)
			if err := policy.Validate(); err == nil {
				t.Fatal("privileged Docker profile drift was accepted")
			}
		})
	}

	runtimeTarget := target.runtimeTarget(base.HostID)
	if runtimeTarget.Docker == target.Docker {
		t.Fatal("runtime Docker authority aliases the policy object")
	}
	if runtimeTarget.Docker.DockerPath != "/usr/bin/docker" ||
		runtimeTarget.Docker.ProjectDir != "/opt/autostream" ||
		runtimeTarget.Docker.BaseEnvFile != "/opt/autostream/.env" ||
		runtimeTarget.Docker.VersionEnvFile != "/opt/autostream/local-executor/docker/worker.env" ||
		runtimeTarget.Docker.ImageRepo != "ghcr.io/kome-lab/autostream-docker/worker" ||
		runtimeTarget.Docker.CurrentVersion != docker.CurrentVersion ||
		runtimeTarget.Docker.ComposeConfigSHA256 != docker.ComposeConfigSHA256 {
		t.Fatalf("runtime Docker profile was not safely derived: %+v", runtimeTarget.Docker)
	}
	if got := checkpointPath(runtimeTarget); filepath.Dir(got) != filepath.Clean(LocalExecutorMutationStateDir) {
		t.Fatalf("Local Executor Docker checkpoint escaped durable executor state: %q", got)
	}

	for serviceType, expected := range map[string]struct {
		service string
		port    int
	}{
		"control_panel":    {service: "control-panel", port: 18080},
		"encoder_recorder": {service: "encoder-recorder", port: 18081},
		"observability":    {service: "observability", port: 18082},
		"discord_bot":      {service: "discord-bot", port: 18083},
		"worker":           {service: "worker", port: 18084},
	} {
		t.Run("mapping_"+serviceType, func(t *testing.T) {
			policy := validLocalExecutorPolicy(t)
			candidate := policy.Targets[0]
			candidate.ServiceID = expected.service + "-01"
			candidate.ServiceType = serviceType
			candidate.DeploymentMode = ModeDocker
			candidate.LocalListen.Port = expected.port
			candidate.Systemd = nil
			dockerProfile, ok := localExecutorDockerProfileFor(serviceType)
			if !ok {
				t.Fatalf("missing fixed Docker profile for %s", serviceType)
			}
			candidate.Docker = &DockerTarget{
				DockerPath:          "/usr/bin/docker",
				ComposeProject:      "autostream",
				ProjectDir:          "/opt/autostream",
				ComposeFiles:        []string{"/opt/autostream/compose.yml"},
				Service:             dockerProfile.service,
				ImageRepo:           dockerProfile.imageRepo,
				ImageVariable:       "AUTOSTREAM_DOCKER_VERSION",
				BaseEnvFile:         "/opt/autostream/.env",
				VersionEnvFile:      dockerProfile.versionEnvFile,
				ComposeConfigSHA256: strings.Repeat("b", 64),
				CurrentVersion:      "v2.0.0",
				Channel:             "docker",
			}
			policy.Targets = []LocalExecutorTarget{candidate}
			if err := policy.Validate(); err != nil {
				t.Fatalf("fixed %s Docker mapping rejected: %v", serviceType, err)
			}
		})
	}
}

func TestNewDockerVersionPinDefaultsToPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.env")
	payload, mode, existed, err := readVersionEnv(path)
	if err != nil || existed || payload != nil || mode != 0o600 {
		t.Fatalf("payload=%q mode=%#o existed=%v err=%v", payload, mode, existed, err)
	}
	if mode := checkpointMode(nil); mode != 0o600 {
		t.Fatalf("checkpoint fallback mode=%#o", mode)
	}
}

func TestLocalExecutorMutationValidPolicyBindingReachesDurableCore(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 3
	policy.ProjectionRevision = 5
	digest, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	base := ApplyPlan{
		JobID: "job-one", HostID: policy.HostID, TargetID: policy.Targets[0].ServiceID,
		ServiceType: policy.Targets[0].ServiceType, DeploymentMode: policy.Targets[0].DeploymentMode,
		CurrentVersion: "v1.0.0", TargetVersion: "v1.1.0", ConfigSHA256: digest,
		LeaseGeneration: 1, ArtifactDigest: strings.Repeat("a", 64), ExpectedVersion: "v1.1.0",
	}
	planSHA256, err := MutationPlanSHA256(base)
	if err != nil {
		t.Fatal(err)
	}
	plan := MutationPlan{
		JobID: base.JobID, HostID: base.HostID, TargetID: base.TargetID,
		ServiceType: base.ServiceType, DeploymentMode: base.DeploymentMode,
		CurrentVersion: base.CurrentVersion, TargetVersion: base.TargetVersion,
		ConfigSHA256: base.ConfigSHA256, LeaseGeneration: base.LeaseGeneration,
		ArtifactDigest: base.ArtifactDigest, ExpectedVersion: base.ExpectedVersion,
		SessionID: "session-0123456789abcdef", PlanSHA256: planSHA256,
	}
	response := handleLocalExecutorMutation(context.Background(), policy, LocalExecutorRequest{
		Version: LocalExecutorMutationProtocolVersion, Operation: "stage",
		ServiceID: plan.TargetID, Plan: &plan, SourcePolicyRevision: policy.SourcePolicyRevision, OwnershipEpoch: 2,
		OwnershipPolicyRevision: 5, ExecutorPolicyRevision: policy.PolicyRevision,
	}, executorMutationRuntime{platformOS: runtime.GOOS, platformArch: runtime.GOARCH, localStateDir: t.TempDir()})
	if response.Error == nil {
		t.Fatal("unprovisioned test target unexpectedly completed staging")
	}
	switch response.Error.Code {
	case "config_mismatch", "policy_invalid", "invalid_request":
		t.Fatalf("valid root policy binding did not reach the durable mutation core: %+v", response)
	}
}

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
		adapter.BindVariable,
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
		adapter.BindVariable,
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
	sidecarPath := filepath.Join(sidecarDir, "worker.env")
	writeTestFile(t, sidecarPath, string(systemdPortSidecarBytes(
		adapter.BindVariable,
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
		adapter.BindVariable,
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
		adapter.BindVariable,
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
				adapter.BindVariable,
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

func TestSystemdAppliedStateAllowsOnlyExactRootPolicyLineageMigration(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 10
	policy.ProjectionRevision = 11
	policy.PolicyRevision = 12
	policy.Targets[0].EndpointRevision = 5
	adapter, err := systemdPortAdapterFor(
		policy.Targets[0].ServiceType,
		policy.Targets[0].Systemd.Unit,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy.Targets[0].ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.BindVariable,
		policy.Targets[0].LocalListen.Host,
		policy.Targets[0].LocalListen.Port,
		policy.Targets[0].ConfigRevision,
	))
	applied := systemdPortAppliedState{
		SchemaVersion:    systemdPortPlanSchemaVersion,
		TargetID:         policy.Targets[0].ServiceID,
		ServiceType:      policy.Targets[0].ServiceType,
		Port:             policy.Targets[0].LocalListen.Port,
		EndpointRevision: policy.Targets[0].EndpointRevision,
		ConfigRevision:   policy.Targets[0].ConfigRevision,
		ConfigSHA256:     policy.Targets[0].ConfigSHA256,
		// Deliberately stale lineage from the policy that performed the port
		// transaction. The newly installed policy already contains the exact
		// endpoint, so the overlay is redundant rather than authoritative.
		SourcePolicyRevision:   6,
		UpdaterPolicyRevision:  7,
		ExecutorPolicyRevision: 8,
		ExecutorPolicySHA256:   "sha256:" + strings.Repeat("e", 64),
		OwnershipEpoch:         3,
	}
	state := newMemorySystemdPortStateStore()
	if err := state.SaveApplied(applied); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveSystemdPortAppliedTarget(
		policy, policy.Targets[0], state,
	)
	if err != nil || resolved != policy.Targets[0] {
		t.Fatalf("exact lineage migration resolved=%+v err=%v", resolved, err)
	}

	applied.Port++
	applied.ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.BindVariable,
		policy.Targets[0].LocalListen.Host,
		applied.Port,
		applied.ConfigRevision,
	))
	if err := state.SaveApplied(applied); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSystemdPortAppliedTarget(
		policy, policy.Targets[0], state,
	); err == nil {
		t.Fatal("stale lineage with a different endpoint was accepted")
	}
}

func TestFileSystemdAppliedStateVerifierRejectsModeAndSymlinkDrift(t *testing.T) {
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
	body := systemdPortSidecarBytes(
		adapter.BindVariable,
		policy.Targets[0].LocalListen.Host,
		policy.Targets[0].LocalListen.Port,
		policy.Targets[0].ConfigRevision,
	)
	policy.Targets[0].ConfigSHA256 = systemdPortSidecarSHA256(body)
	policySHA, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	applied := systemdPortAppliedState{
		SchemaVersion:          systemdPortPlanSchemaVersion,
		TargetID:               policy.Targets[0].ServiceID,
		ServiceType:            policy.Targets[0].ServiceType,
		Port:                   policy.Targets[0].LocalListen.Port,
		EndpointRevision:       policy.Targets[0].EndpointRevision,
		ConfigRevision:         policy.Targets[0].ConfigRevision,
		ConfigSHA256:           policy.Targets[0].ConfigSHA256,
		SourcePolicyRevision:   policy.SourcePolicyRevision,
		UpdaterPolicyRevision:  policy.ProjectionRevision,
		ExecutorPolicyRevision: policy.PolicyRevision,
		ExecutorPolicySHA256:   policySHA,
		OwnershipEpoch:         3,
	}
	state, err := newFileSystemdPortStateStore(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	sidecarDir := filepath.Join(t.TempDir(), "ports")
	if err := os.Mkdir(sidecarDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sidecarPath := filepath.Join(sidecarDir, "worker.env")
	writeTestFile(t, sidecarPath, string(body), 0o600)
	state.sidecarPathForTestOnly = sidecarPath
	if err := state.VerifyAppliedSidecar(policy.Targets[0], applied); err != nil {
		t.Fatalf("canonical sidecar: %v", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(sidecarPath, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := state.VerifyAppliedSidecar(policy.Targets[0], applied); err == nil {
			t.Fatal("group-readable sidecar was accepted")
		}
		if err := os.Chmod(sidecarPath, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linkTarget := filepath.Join(sidecarDir, "target.env")
	writeTestFile(t, linkTarget, string(body), 0o600)
	if err := os.Remove(sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, sidecarPath); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := state.VerifyAppliedSidecar(policy.Targets[0], applied); err == nil {
		t.Fatal("sidecar symlink was accepted")
	}
}

func TestFileSystemdStateStoreRejectsDirectoryLinkWithoutChangingTarget(t *testing.T) {
	parent := t.TempDir()
	victim := filepath.Join(parent, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(parent, "state")
	if err := os.Symlink(victim, stateDir); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	before, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newFileSystemdPortStateStore(stateDir, false); err == nil {
		t.Fatal("linked state directory was accepted")
	}
	after, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf(
			"linked target mode changed from %o to %o",
			before.Mode().Perm(), after.Mode().Perm(),
		)
	}
}

func TestFileSystemdStateStoreRejectsNestedDirectoryLinkWithoutChangingTarget(t *testing.T) {
	parent := t.TempDir()
	victim := filepath.Join(parent, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(parent, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(stateDir, "port-ledger")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	before, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newFileSystemdPortStateStore(stateDir, false); err == nil {
		t.Fatal("linked nested state directory was accepted")
	}
	after, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf(
			"nested linked target mode changed from %o to %o",
			before.Mode().Perm(), after.Mode().Perm(),
		)
	}
}

func TestLocalExecutorProbeRejectsFakeHealthAndWrongCgroup(t *testing.T) {
	basePolicy := validLocalExecutorPolicy(t)
	baseTarget := basePolicy.Targets[0]

	t.Run("fake health identity", func(t *testing.T) {
		server := newLocalExecutorProbeServer(t, baseTarget, "v1.2.3", baseTarget.ConfigRevision)
		defer server.Close()
		policy := cloneLocalExecutorPolicy(t, basePolicy)
		policy.Targets[0].LocalListen = endpointFromServer(t, server)
		observation := validLocalProcessObservation(policy.Targets[0], "v1.2.3")
		observation.ServiceID = "attacker"
		response := handleLocalExecutorRequest(context.Background(), policy,
			LocalExecutorRequest{Version: 1, Operation: "probe", ServiceID: baseTarget.ServiceID},
			&fakeLocalTargetVerifier{observations: []LocalProcessObservation{observation}},
			server.Client(),
		)
		if response.Error == nil || response.Error.Code != "target_unavailable" {
			t.Fatalf("response=%+v", response)
		}
	})

	t.Run("wrong listener cgroup", func(t *testing.T) {
		server := newLocalExecutorProbeServer(t, baseTarget, "v1.2.3", baseTarget.ConfigRevision)
		defer server.Close()
		policy := cloneLocalExecutorPolicy(t, basePolicy)
		policy.Targets[0].LocalListen = endpointFromServer(t, server)
		observation := validLocalProcessObservation(policy.Targets[0], "v1.2.3")
		observation.ListenerControlGroup = "/system.slice/attacker.service"
		response := handleLocalExecutorRequest(context.Background(), policy,
			LocalExecutorRequest{Version: 1, Operation: "probe", ServiceID: baseTarget.ServiceID},
			&fakeLocalTargetVerifier{observations: []LocalProcessObservation{observation}},
			server.Client(),
		)
		if response.Error == nil || response.Error.Code != "target_unavailable" {
			t.Fatalf("response=%+v", response)
		}
	})

	t.Run("revision mismatch", func(t *testing.T) {
		server := newLocalExecutorProbeServer(t, baseTarget, "v1.2.3", baseTarget.ConfigRevision+1)
		defer server.Close()
		policy := cloneLocalExecutorPolicy(t, basePolicy)
		policy.Targets[0].LocalListen = endpointFromServer(t, server)
		response := handleLocalExecutorRequest(context.Background(), policy,
			LocalExecutorRequest{Version: 1, Operation: "probe", ServiceID: baseTarget.ServiceID},
			&fakeLocalTargetVerifier{observations: []LocalProcessObservation{
				validLocalProcessObservation(policy.Targets[0], "v1.2.3"),
			}},
			server.Client(),
		)
		if response.Error == nil || response.Error.Code != "target_unavailable" {
			t.Fatalf("response=%+v", response)
		}
	})
}

func TestLocalExecutorHTTPProbeBypassesConfiguredProxy(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	target := policy.Targets[0]
	targetServer := newLocalExecutorProbeServer(t, target, "v1.2.3", target.ConfigRevision)
	defer targetServer.Close()
	target.LocalListen = endpointFromServer(t, targetServer)

	var proxyCalls int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","version":"v1.2.3","service_id":"worker-01","service_type":"worker","config_revision":11}`)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	poisoned := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	if err := verifyLocalExecutorHTTP(context.Background(), target, "v1.2.3", poisoned); err != nil {
		t.Fatalf("direct local probe failed: %v", err)
	}
	if proxyCalls != 0 {
		t.Fatalf("local probe used configured proxy %d times", proxyCalls)
	}
}

func TestLocalExecutorProbeRejectsMutationWithoutTouchingRuntime(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	verifier := &fakeLocalTargetVerifier{}
	response := handleLocalExecutorRequest(context.Background(), policy,
		LocalExecutorRequest{Version: 1, Operation: "apply", ServiceID: policy.Targets[0].ServiceID},
		verifier,
		http.DefaultClient,
	)
	if response.Error == nil || response.Error.Code != "invalid_request" || verifier.calls != 0 {
		t.Fatalf("response=%+v calls=%d", response, verifier.calls)
	}
}

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
		observations[0].Docker.AdvertisedPort != 443 {
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

type fakeLocalTargetVerifier struct {
	observations    []LocalProcessObservation
	calls           int
	err             error
	observedTargets []LocalExecutorTarget
	dockerProbe     *LocalExecutorDockerPortProbe
	dockerErr       error
}

type fakeLocalExecutorProbeClient struct {
	probes map[string]LocalExecutorProbe
	err    error
	calls  int
}

func (f *fakeLocalExecutorProbeClient) Probe(_ context.Context, serviceID string) (LocalExecutorProbe, error) {
	f.calls++
	if f.err != nil {
		return LocalExecutorProbe{}, f.err
	}
	probe, ok := f.probes[serviceID]
	if !ok {
		return LocalExecutorProbe{}, errors.New("not found")
	}
	return probe, nil
}

func (f *fakeLocalTargetVerifier) Observe(
	_ context.Context,
	_ LocalExecutorPolicy,
	target LocalExecutorTarget,
) (LocalProcessObservation, error) {
	f.calls++
	f.observedTargets = append(f.observedTargets, target)
	if f.err != nil {
		return LocalProcessObservation{}, f.err
	}
	if len(f.observations) == 0 {
		return LocalProcessObservation{}, errors.New("no observation")
	}
	index := f.calls - 1
	if index >= len(f.observations) {
		index = len(f.observations) - 1
	}
	return f.observations[index], nil
}

func (f *fakeLocalTargetVerifier) ObserveDockerPort(
	context.Context,
	LocalExecutorPolicy,
	LocalExecutorTarget,
	*http.Client,
) (LocalExecutorDockerPortProbe, error) {
	if f.dockerErr != nil {
		return LocalExecutorDockerPortProbe{}, f.dockerErr
	}
	if f.dockerProbe == nil {
		return LocalExecutorDockerPortProbe{}, errors.New("no Docker port observation")
	}
	return *f.dockerProbe, nil
}

func validLocalProcessObservation(target LocalExecutorTarget, version string) LocalProcessObservation {
	return LocalProcessObservation{
		ServiceID:            target.ServiceID,
		ServiceType:          target.ServiceType,
		DeploymentMode:       target.DeploymentMode,
		CurrentVersion:       version,
		MainPID:              101,
		ListenerPID:          102,
		ControlGroup:         "/system.slice/autostream-worker.service",
		ListenerControlGroup: "/system.slice/autostream-worker.service",
	}
}

func validLocalExecutorPolicy(t *testing.T) LocalExecutorPolicy {
	t.Helper()
	systemd := validLocalSystemdTarget(t)
	return LocalExecutorPolicy{
		SchemaVersion:   LocalExecutorPolicySchemaVersion,
		ProtocolVersion: LocalExecutorProtocolVersion,
		HostID:          "host-a",
		AgentUID:        1001,
		AgentGID:        1001,
		SocketPath:      LocalExecutorSocketPath,
		PolicyRevision:  7,
		Targets: []LocalExecutorTarget{{
			ServiceID:      "worker-01",
			ServiceType:    "worker",
			DeploymentMode: ModeSystemd,
			ConfigRevision: 11,
			LocalListen:    LocalExecutorEndpoint{Host: "127.0.0.1", Port: 18084},
			Systemd:        &systemd,
		}},
	}
}

func validLocalSystemdTarget(t *testing.T) SystemdTarget {
	t.Helper()
	return SystemdTarget{
		SystemctlPath: "/usr/bin/systemctl",
		RunuserPath:   "/usr/sbin/runuser",
		SmokeUser:     "autostream",
		Unit:          "autostream-worker.service",
		ReleaseRoot:   "/opt/autostream/worker/releases",
		CurrentLink:   "/opt/autostream/worker/current",
		BinaryPath:    "bin/autostream-worker",
	}
}

func validLocalDockerTarget(t *testing.T) DockerTarget {
	t.Helper()
	return DockerTarget{
		DockerPath:          "/usr/bin/docker",
		ComposeProject:      "autostream",
		ProjectDir:          "/opt/autostream",
		ComposeFiles:        []string{"/opt/autostream/compose.yml"},
		Service:             "worker",
		ImageRepo:           "ghcr.io/kome-lab/autostream-docker/worker",
		ImageVariable:       "AUTOSTREAM_DOCKER_VERSION",
		BaseEnvFile:         "/opt/autostream/.env",
		VersionEnvFile:      "/opt/autostream/local-executor/docker/worker.env",
		ComposeConfigSHA256: strings.Repeat("a", 64),
		CurrentVersion:      "v1.2.3",
		Channel:             "docker",
	}
}

func newLocalExecutorProbeServer(t *testing.T, target LocalExecutorTarget, version string, revision int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /updater/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":         version,
			"service_id":      target.ServiceID,
			"service_type":    target.ServiceType,
			"config_revision": revision,
		})
	})
	return httptest.NewServer(mux)
}

func endpointFromServer(t *testing.T, server *httptest.Server) LocalExecutorEndpoint {
	t.Helper()
	hostPort := strings.TrimPrefix(server.URL, "http://")
	host, portText, ok := strings.Cut(hostPort, ":")
	if !ok {
		t.Fatalf("server URL=%q", server.URL)
	}
	var port int
	if _, err := fmt.Sscan(portText, &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return LocalExecutorEndpoint{Host: host, Port: port}
}

func cloneLocalExecutorPolicy(t *testing.T, policy LocalExecutorPolicy) LocalExecutorPolicy {
	t.Helper()
	var clone LocalExecutorPolicy
	if err := json.Unmarshal([]byte(mustJSON(t, policy)), &clone); err != nil {
		t.Fatalf("clone policy: %v", err)
	}
	return clone
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func writeTestFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
