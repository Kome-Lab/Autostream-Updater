package hostruntime

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildConfigurePolicyProjectionUsesCanonicalPayloadDigest(t *testing.T) {
	policy := configurePolicyProjectionFixture()
	projection, err := BuildConfigurePolicyProjection(policy)
	if err != nil {
		t.Fatalf("build projection: %v", err)
	}
	if !json.Valid(projection.Policy) ||
		projection.SHA256 != "sha256:"+sha256Hex(projection.Policy) ||
		projection.SourcePolicyRevision != policy.SourcePolicyRevision ||
		projection.ProjectionRevision != policy.ProjectionRevision ||
		projection.PolicyRevision != policy.PolicyRevision {
		t.Fatalf("projection is not canonical and revision-bound: %#v", projection)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, projection.Policy, "", "  "); err != nil {
		t.Fatalf("indent projection: %v", err)
	}
	if bytes.Equal(indented.Bytes(), projection.Policy) {
		t.Fatal("fixture unexpectedly failed to distinguish canonical compact payload")
	}
	if err := ValidateConfigurePolicyActivation(
		projection.Policy,
		projection.SHA256,
		projection.SourcePolicyRevision,
		projection.ProjectionRevision,
		projection.PolicyRevision,
	); err != nil {
		t.Fatalf("activate canonical projection: %v", err)
	}
}

func TestConfigurePolicyActivationRejectsManualOrTamperedDigest(t *testing.T) {
	projection, err := BuildConfigurePolicyProjection(configurePolicyProjectionFixture())
	if err != nil {
		t.Fatalf("build projection: %v", err)
	}
	tampered := append([]byte(nil), projection.Policy...)
	tampered[len(tampered)-1] = ' '
	tests := []struct {
		name       string
		payload    []byte
		digest     string
		source     int64
		projection int64
		policy     int64
	}{
		{"tampered payload", tampered, projection.SHA256, projection.SourcePolicyRevision, projection.ProjectionRevision, projection.PolicyRevision},
		{"manual digest", projection.Policy, "sha256:" + strings.Repeat("f", 64), projection.SourcePolicyRevision, projection.ProjectionRevision, projection.PolicyRevision},
		{"source revision", projection.Policy, projection.SHA256, projection.SourcePolicyRevision + 1, projection.ProjectionRevision, projection.PolicyRevision},
		{"projection revision", projection.Policy, projection.SHA256, projection.SourcePolicyRevision, projection.ProjectionRevision + 1, projection.PolicyRevision},
		{"policy revision", projection.Policy, projection.SHA256, projection.SourcePolicyRevision, projection.ProjectionRevision, projection.PolicyRevision + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateConfigurePolicyActivation(
				test.payload,
				test.digest,
				test.source,
				test.projection,
				test.policy,
			); err == nil {
				t.Fatal("untrusted configure policy activation was accepted")
			}
		})
	}
}

func TestBuildHostAgentConfigurePolicyDerivesFixedSystemdAuthority(t *testing.T) {
	input := HostAgentConfigurePolicySource{
		PanelURL:                    "https://panel.example.com",
		ExecutionHostID:             "host-a",
		AgentUID:                    1001,
		AgentGID:                    1002,
		SourcePolicyRevision:        3,
		ProjectionRevision:          4,
		LocalExecutorPolicyRevision: 5,
		Targets: []HostAgentConfigurePolicyTarget{{
			ServiceID:             "worker-a",
			ServiceType:           "worker",
			DeploymentMode:        ModeSystemd,
			EndpointRevision:      2,
			AppliedConfigRevision: 7,
			AppliedEndpointPort:   18084,
		}},
	}
	projection, err := BuildHostAgentConfigurePolicy(input)
	if err != nil {
		t.Fatalf("build Host Agent configure policy: %v", err)
	}
	var policy LocalExecutorPolicy
	if err := json.Unmarshal(projection.Policy, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.HostID != input.ExecutionHostID ||
		policy.AgentUID != input.AgentUID ||
		policy.AgentGID != input.AgentGID ||
		policy.Mutation == nil ||
		policy.Mutation.PanelURL != input.PanelURL ||
		len(policy.Targets) != 1 {
		t.Fatalf("derived policy = %#v", policy)
	}
	target := policy.Targets[0]
	profile, ok := standardSystemdProfileFor("worker")
	if !ok {
		t.Fatal("worker systemd profile is unavailable")
	}
	adapter, err := systemdPortAdapterFor("worker", profile.unit)
	if err != nil {
		t.Fatal(err)
	}
	wantConfigSHA := systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.BindVariable,
		"127.0.0.1",
		input.Targets[0].AppliedEndpointPort,
		input.Targets[0].AppliedConfigRevision,
	))
	if target.Systemd == nil ||
		target.Systemd.Unit != profile.unit ||
		target.Systemd.ReleaseRoot != profile.releaseRoot ||
		target.LocalListen != (LocalExecutorEndpoint{Host: "127.0.0.1", Port: 18084}) ||
		target.ConfigSHA256 != wantConfigSHA ||
		projection.SHA256 != "sha256:"+sha256Hex(projection.Policy) {
		t.Fatalf("derived target/projection = %#v / %#v", target, projection)
	}
}

func TestBuildHostAgentConfigurePolicySeparatesPublicAndLocalPorts(t *testing.T) {
	input := HostAgentConfigurePolicySource{
		PanelURL:                    "https://panel.example.com",
		ExecutionHostID:             "host-a",
		AgentUID:                    1001,
		AgentGID:                    1002,
		SourcePolicyRevision:        3,
		ProjectionRevision:          4,
		LocalExecutorPolicyRevision: 5,
		Targets: []HostAgentConfigurePolicyTarget{{
			ServiceID:             "observability-a",
			ServiceType:           "observability",
			DeploymentMode:        ModeSystemd,
			DatabaseName:          "autostream_observability",
			EndpointRevision:      2,
			AppliedConfigRevision: 7,
			AppliedEndpointPort:   443,
			LocalListenPort:       8082,
		}},
	}
	projection, err := BuildHostAgentConfigurePolicy(input)
	if err != nil {
		t.Fatalf("build Host Agent configure policy: %v", err)
	}
	var policy LocalExecutorPolicy
	if err := json.Unmarshal(projection.Policy, &policy); err != nil {
		t.Fatal(err)
	}
	wantConfigSHA256, err := SystemdConfigurePortSidecarSHA256("observability", 8082, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Targets) != 1 ||
		policy.Targets[0].LocalListen != (LocalExecutorEndpoint{
			Host: "127.0.0.1",
			Port: 8082,
		}) ||
		policy.Targets[0].ConfigSHA256 != wantConfigSHA256 {
		t.Fatalf("local target = %#v", policy.Targets)
	}
}

func TestSystemdConfigurePortSidecarSHA256UsesOnlyFixedConfigureAuthority(t *testing.T) {
	tests := []struct {
		name         string
		serviceType  string
		bindVariable string
		port         int
		revision     int64
	}{
		{
			name:         "control panel",
			serviceType:  "control_panel",
			bindVariable: "AUTOSTREAM_BIND_ADDR",
			port:         18080,
			revision:     7,
		},
		{
			name:         "encoder recorder",
			serviceType:  "encoder_recorder",
			bindVariable: "AUTOSTREAM_BIND_ADDR",
			port:         18081,
			revision:     8,
		},
		{
			name:         "observability",
			serviceType:  "observability",
			bindVariable: "OBSERVABILITY_BIND_ADDR",
			port:         18082,
			revision:     9,
		},
		{
			name:         "discord bot",
			serviceType:  "discord_bot",
			bindVariable: "AUTOSTREAM_BIND_ADDR",
			port:         18083,
			revision:     10,
		},
		{
			name:         "worker",
			serviceType:  "worker",
			bindVariable: "AUTOSTREAM_BIND_ADDR",
			port:         18084,
			revision:     11,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := SystemdConfigurePortSidecarSHA256(
				test.serviceType,
				test.port,
				test.revision,
			)
			if err != nil {
				t.Fatalf("compute configure sidecar digest: %v", err)
			}
			want := systemdPortSidecarSHA256(systemdPortSidecarBytes(
				test.bindVariable,
				"127.0.0.1",
				test.port,
				test.revision,
			))
			if got != want {
				t.Fatalf("digest = %q, want %q", got, want)
			}
		})
	}

	invalid := []struct {
		name        string
		serviceType string
		port        int
		revision    int64
	}{
		{name: "unsupported service", serviceType: "other", port: 18080, revision: 1},
		{name: "missing port", serviceType: "control_panel", port: 0, revision: 1},
		{name: "privileged port", serviceType: "control_panel", port: 443, revision: 1},
		{name: "port overflow", serviceType: "control_panel", port: 65536, revision: 1},
		{name: "missing revision", serviceType: "control_panel", port: 18080, revision: 0},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := SystemdConfigurePortSidecarSHA256(
				test.serviceType,
				test.port,
				test.revision,
			); err == nil {
				t.Fatal("invalid configure sidecar authority was accepted")
			}
		})
	}

	if _, err := systemdPortAdapterFor(
		"control_panel",
		"autostream-control-panel.service",
	); err == nil {
		t.Fatal("control panel escaped the configure-only adapter boundary")
	}
	if validSystemdPortServiceType("control_panel") {
		t.Fatal("control panel escaped the configure-only runtime mutation boundary")
	}
}

func TestBuildHostAgentConfigurePolicyDerivesFixedDatabaseBackupAuthority(t *testing.T) {
	tests := []struct {
		name         string
		serviceID    string
		serviceType  string
		databaseName string
		port         int
	}{
		{
			name:         "control panel",
			serviceID:    "control-panel",
			serviceType:  "control_panel",
			databaseName: "autostream-kometubu_panel",
			port:         18080,
		},
		{
			name:         "observability",
			serviceID:    "observability-a",
			serviceType:  "observability",
			databaseName: "autostream-kometubu_o11y",
			port:         18082,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := databaseConfigurePolicySource(
				test.serviceID,
				test.serviceType,
				test.databaseName,
				test.port,
			)
			projection, err := BuildHostAgentConfigurePolicy(input)
			if err != nil {
				t.Fatalf("build Host Agent configure policy: %v", err)
			}
			var policy LocalExecutorPolicy
			if err := json.Unmarshal(projection.Policy, &policy); err != nil {
				t.Fatal(err)
			}
			if len(policy.Targets) != 1 {
				t.Fatalf("targets = %#v", policy.Targets)
			}
			target := policy.Targets[0]
			profile, ok := standardSystemdProfileFor(test.serviceType)
			if !ok {
				t.Fatalf("missing fixed profile for %s", test.serviceType)
			}
			runtimeTarget := target.runtimeTarget(policy.HostID)
			if target.DatabaseName != test.databaseName ||
				len(runtimeTarget.BackupArgv) != 2 ||
				runtimeTarget.BackupArgv[0] != profile.backupExecutable ||
				runtimeTarget.BackupArgv[1] != test.databaseName {
				t.Fatalf(
					"database backup authority was not fixed: target=%#v backup=%#v",
					target,
					runtimeTarget.BackupArgv,
				)
			}
		})
	}
}

func TestBuildHostAgentConfigurePolicyRejectsUntrustedDatabaseAuthority(t *testing.T) {
	tests := []struct {
		name         string
		serviceID    string
		serviceType  string
		databaseName string
	}{
		{
			name:        "control panel database missing",
			serviceID:   "control-panel",
			serviceType: "control_panel",
		},
		{
			name:        "observability database missing",
			serviceID:   "observability-a",
			serviceType: "observability",
		},
		{
			name:         "shell metacharacter",
			serviceID:    "control-panel",
			serviceType:  "control_panel",
			databaseName: "database;touch-pwned",
		},
		{
			name:         "path traversal",
			serviceID:    "observability-a",
			serviceType:  "observability",
			databaseName: "../database",
		},
		{
			name:         "leading option",
			serviceID:    "observability-a",
			serviceType:  "observability",
			databaseName: "--all-databases",
		},
		{
			name:         "unsupported punctuation",
			serviceID:    "control-panel",
			serviceType:  "control_panel",
			databaseName: "bad.name",
		},
		{
			name:         "too long",
			serviceID:    "control-panel",
			serviceType:  "control_panel",
			databaseName: strings.Repeat("a", 65),
		},
		{
			name:         "database for non owner",
			serviceID:    "worker-a",
			serviceType:  "worker",
			databaseName: "worker_db",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := databaseConfigurePolicySource(
				test.serviceID,
				test.serviceType,
				test.databaseName,
				18084,
			)
			if _, err := BuildHostAgentConfigurePolicy(input); err == nil {
				t.Fatal("untrusted database authority generated a privileged policy")
			}
		})
	}
}

func TestBuildHostAgentConfigurePolicyDigestBindsDatabaseName(t *testing.T) {
	input := databaseConfigurePolicySource(
		"observability-a",
		"observability",
		"autostream_observability_a",
		18082,
	)
	first, err := BuildHostAgentConfigurePolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Targets[0].DatabaseName = "autostream_observability_b"
	second, err := BuildHostAgentConfigurePolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Policy, second.Policy) || first.SHA256 == second.SHA256 {
		t.Fatal("database authority was not bound into the canonical policy digest")
	}
}

func TestBuildHostAgentConfigurePolicyFailsClosedWhenServerStateCannotDefineAuthority(t *testing.T) {
	base := HostAgentConfigurePolicySource{
		PanelURL:                    "https://panel.example.com",
		ExecutionHostID:             "host-a",
		AgentUID:                    1001,
		AgentGID:                    1002,
		SourcePolicyRevision:        3,
		ProjectionRevision:          4,
		LocalExecutorPolicyRevision: 5,
		Targets: []HostAgentConfigurePolicyTarget{{
			ServiceID:             "worker-a",
			ServiceType:           "worker",
			DeploymentMode:        ModeSystemd,
			EndpointRevision:      2,
			AppliedConfigRevision: 7,
			AppliedEndpointPort:   18084,
		}},
	}
	tests := map[string]func(*HostAgentConfigurePolicySource){
		"root peer": func(input *HostAgentConfigurePolicySource) {
			input.AgentUID = 0
		},
		"missing applied port": func(input *HostAgentConfigurePolicySource) {
			input.Targets[0].AppliedEndpointPort = 0
		},
		"stored digest drift": func(input *HostAgentConfigurePolicySource) {
			input.Targets[0].AppliedConfigSHA256 = "sha256:" + strings.Repeat("f", 64)
		},
		"docker runtime state unavailable": func(input *HostAgentConfigurePolicySource) {
			input.Targets[0].DeploymentMode = ModeDocker
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.Targets = append([]HostAgentConfigurePolicyTarget(nil), base.Targets...)
			mutate(&candidate)
			if _, err := BuildHostAgentConfigurePolicy(candidate); err == nil {
				t.Fatal("incomplete server state generated privileged policy")
			}
		})
	}
}

func databaseConfigurePolicySource(
	serviceID string,
	serviceType string,
	databaseName string,
	port int,
) HostAgentConfigurePolicySource {
	return HostAgentConfigurePolicySource{
		PanelURL:                    "https://panel.example.com",
		ExecutionHostID:             "host-a",
		AgentUID:                    1001,
		AgentGID:                    1002,
		SourcePolicyRevision:        3,
		ProjectionRevision:          4,
		LocalExecutorPolicyRevision: 5,
		Targets: []HostAgentConfigurePolicyTarget{{
			ServiceID:             serviceID,
			ServiceType:           serviceType,
			DeploymentMode:        ModeSystemd,
			DatabaseName:          databaseName,
			EndpointRevision:      2,
			AppliedConfigRevision: 7,
			AppliedEndpointPort:   port,
		}},
	}
}

func configurePolicyProjectionFixture() LocalExecutorPolicy {
	return LocalExecutorPolicy{
		SchemaVersion:        LocalExecutorMutationPolicySchemaVersion,
		ProtocolVersion:      LocalExecutorMutationProtocolVersion,
		HostID:               "host-a",
		AgentUID:             1001,
		AgentGID:             1001,
		SocketPath:           LocalExecutorSocketPath,
		SourcePolicyRevision: 3,
		ProjectionRevision:   4,
		PolicyRevision:       5,
		Mutation:             &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"},
		Targets: []LocalExecutorTarget{{
			ServiceID:        "worker-a",
			ServiceType:      "worker",
			DeploymentMode:   ModeSystemd,
			EndpointRevision: 2,
			ConfigRevision:   7,
			ConfigSHA256:     "sha256:" + strings.Repeat("a", 64),
			LocalListen:      LocalExecutorEndpoint{Host: "127.0.0.1", Port: 18081},
			Systemd: &SystemdTarget{
				SystemctlPath: "/usr/bin/systemctl",
				RunuserPath:   "/usr/sbin/runuser",
				SmokeUser:     "autostream",
				Unit:          "autostream-worker.service",
				ReleaseRoot:   "/opt/autostream/worker/releases",
				CurrentLink:   "/opt/autostream/worker/current",
				BinaryPath:    "bin/autostream-worker",
			},
		}},
	}
}
