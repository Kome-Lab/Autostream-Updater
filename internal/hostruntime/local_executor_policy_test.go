package hostruntime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
