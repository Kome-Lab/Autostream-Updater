package hostruntime

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthorizeHostAgentSystemdSidecarAdoptionRequiresOneCanonicalCurrentMismatch(
	t *testing.T,
) {
	current, staged, identity, identityBytes, plans, snapshots :=
		configureAdoptionAuthorityFixture(t)

	adoption, err := authorizeHostAgentSystemdSidecarAdoption(
		staged,
		identity,
		identityBytes,
		mustConfigureProjection(t, current).Policy,
		plans,
		snapshots,
		defaultSystemdPortSidecarDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	if adoption.plan.ServiceID != "observability-a" ||
		adoption.currentTarget.LocalListen.Port != 18080 ||
		adoption.stagedTarget.LocalListen.Port != 18084 ||
		adoption.stagedTarget.ConfigRevision != 14 {
		t.Fatalf("adoption = %#v", adoption)
	}

	for _, plan := range plans {
		snapshots[plan.Path] = initialSystemdPortSidecarSnapshot{
			Existed: true,
			Body:    append([]byte(nil), plan.Body...),
		}
	}
	if _, err := authorizeHostAgentSystemdSidecarAdoption(
		staged,
		identity,
		identityBytes,
		mustConfigureProjection(t, current).Policy,
		plans,
		snapshots,
		defaultSystemdPortSidecarDirectory,
	); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("zero mismatch error = %v", err)
	}
}

func TestAuthorizeHostAgentSystemdSidecarAdoptionRejectsArbitraryDriftAndBroadChanges(
	t *testing.T,
) {
	current, staged, identity, identityBytes, plans, snapshots :=
		configureAdoptionAuthorityFixture(t)
	currentProjection := mustConfigureProjection(t, current)

	t.Run("arbitrary current sidecar drift", func(t *testing.T) {
		changed := cloneInitialSidecarSnapshots(snapshots)
		changed[plans[0].Path] = initialSystemdPortSidecarSnapshot{
			Existed: true,
			Body:    []byte("OBSERVABILITY_BIND_ADDR=127.0.0.1:19999\nAUTOSTREAM_CONFIG_REVISION=14\n"),
		}
		if _, err := authorizeHostAgentSystemdSidecarAdoption(
			staged, identity, identityBytes, currentProjection.Policy,
			plans, changed, defaultSystemdPortSidecarDirectory,
		); err == nil || !strings.Contains(err.Error(), "not canonical") {
			t.Fatalf("arbitrary drift error = %v", err)
		}
	})

	t.Run("policy lineage reuse", func(t *testing.T) {
		reused := staged
		reused.SourcePolicyRevision = current.SourcePolicyRevision
		if _, err := authorizeHostAgentSystemdSidecarAdoption(
			reused, identity, identityBytes, currentProjection.Policy,
			plans, snapshots, defaultSystemdPortSidecarDirectory,
		); err == nil || !strings.Contains(err.Error(), "strictly advance") {
			t.Fatalf("lineage error = %v", err)
		}
	})

	t.Run("config revision change", func(t *testing.T) {
		changed := staged
		changed.Targets = append([]LocalExecutorTarget(nil), staged.Targets...)
		changed.Targets[0].ConfigRevision++
		setConfigureTargetPort(t, &changed.Targets[0], changed.Targets[0].LocalListen.Port)
		changedPlans, err := initialSystemdPortSidecarPlans(
			changed,
			defaultSystemdPortSidecarDirectory,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authorizeHostAgentSystemdSidecarAdoption(
			changed, identity, identityBytes, currentProjection.Policy,
			changedPlans, snapshots, defaultSystemdPortSidecarDirectory,
		); err == nil || !strings.Contains(err.Error(), "beyond its loopback port") {
			t.Fatalf("config revision error = %v", err)
		}
	})

	t.Run("control panel", func(t *testing.T) {
		controlCurrent, controlStaged := configureAdoptionControlPanelPolicies(t)
		controlPlans, err := initialSystemdPortSidecarPlans(
			controlStaged,
			defaultSystemdPortSidecarDirectory,
		)
		if err != nil {
			t.Fatal(err)
		}
		currentPlans, err := initialSystemdPortSidecarPlans(
			controlCurrent,
			defaultSystemdPortSidecarDirectory,
		)
		if err != nil {
			t.Fatal(err)
		}
		controlSnapshots := map[string]initialSystemdPortSidecarSnapshot{
			controlPlans[0].Path: {Existed: true, Body: currentPlans[0].Body},
		}
		if _, err := authorizeHostAgentSystemdSidecarAdoption(
			controlStaged,
			identity,
			identityBytes,
			mustConfigureProjection(t, controlCurrent).Policy,
			controlPlans,
			controlSnapshots,
			defaultSystemdPortSidecarDirectory,
		); err == nil || !strings.Contains(err.Error(), "not eligible") {
			t.Fatalf("control Panel error = %v", err)
		}
	})
}

func configureAdoptionAuthorityFixture(
	t *testing.T,
) (
	LocalExecutorPolicy,
	LocalExecutorPolicy,
	UpdaterConfigureIdentity,
	[]byte,
	[]initialSystemdPortSidecarPlan,
	map[string]initialSystemdPortSidecarSnapshot,
) {
	t.Helper()
	fixture := configureTransactionPolicyFixture(t)
	staged := fixture
	staged.SourcePolicyRevision = 6
	staged.ProjectionRevision = 6
	staged.PolicyRevision = 6
	staged.Targets = []LocalExecutorTarget{fixture.Targets[4]}
	current := staged
	current.SourcePolicyRevision = 4
	current.ProjectionRevision = 4
	current.PolicyRevision = 4
	current.Targets = append([]LocalExecutorTarget(nil), staged.Targets...)
	setConfigureTargetPort(t, &current.Targets[0], 18080)
	identity := UpdaterConfigureIdentity{
		PanelURL:      "https://panel.example.com",
		NodeID:        "host-agent-a",
		RuntimeToken:  "new-runtime-token",
		ServiceName:   "Host Agent A",
		ServiceType:   ServiceTypeUpdateAgent,
		TransportMode: HostTransportPullV2,
	}
	identityBytes, err := mergeUpdaterConfiguredIdentity(
		nil,
		UpdaterConfigureIdentity{
			PanelURL:     identity.PanelURL,
			NodeID:       identity.NodeID,
			RuntimeToken: "old-runtime-token",
			ServiceName:  identity.ServiceName,
			ServiceType:  ServiceTypeUpdateAgent,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := initialSystemdPortSidecarPlans(
		staged,
		defaultSystemdPortSidecarDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	currentPlans, err := initialSystemdPortSidecarPlans(
		current,
		defaultSystemdPortSidecarDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := map[string]initialSystemdPortSidecarSnapshot{
		plans[0].Path: {Existed: true, Body: currentPlans[0].Body},
	}
	return current, staged, identity, identityBytes, plans, snapshots
}

func configureAdoptionControlPanelPolicies(
	t *testing.T,
) (LocalExecutorPolicy, LocalExecutorPolicy) {
	t.Helper()
	fixture := configureTransactionPolicyFixture(t)
	staged := fixture
	staged.SourcePolicyRevision = 6
	staged.ProjectionRevision = 6
	staged.PolicyRevision = 6
	staged.Targets = []LocalExecutorTarget{fixture.Targets[0]}
	current := staged
	current.SourcePolicyRevision = 4
	current.ProjectionRevision = 4
	current.PolicyRevision = 4
	current.Targets = append([]LocalExecutorTarget(nil), staged.Targets...)
	setConfigureTargetPort(t, &current.Targets[0], 17080)
	return current, staged
}

func setConfigureTargetPort(
	t *testing.T,
	target *LocalExecutorTarget,
	port int,
) {
	t.Helper()
	adapter, err := hostAgentConfigureSystemdPortAdapterFor(
		target.ServiceType,
		target.Systemd.Unit,
	)
	if err != nil {
		t.Fatal(err)
	}
	target.LocalListen.Port = port
	target.ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.BindVariable,
		target.LocalListen.Host,
		port,
		target.ConfigRevision,
	))
}

func mustConfigureProjection(
	t *testing.T,
	policy LocalExecutorPolicy,
) ConfigurePolicyProjection {
	t.Helper()
	projection, err := BuildConfigurePolicyProjection(policy)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func cloneInitialSidecarSnapshots(
	source map[string]initialSystemdPortSidecarSnapshot,
) map[string]initialSystemdPortSidecarSnapshot {
	clone := make(map[string]initialSystemdPortSidecarSnapshot, len(source))
	for path, snapshot := range source {
		clone[path] = initialSystemdPortSidecarSnapshot{
			Existed: snapshot.Existed,
			Body:    append([]byte(nil), snapshot.Body...),
		}
	}
	return clone
}

func TestInitialSystemdPortSidecarPlansUseFiveFixedRootPathsAndExactTwoLines(
	t *testing.T,
) {
	policy := configureTransactionPolicyFixture(t)
	plans, err := initialSystemdPortSidecarPlans(
		policy,
		defaultSystemdPortSidecarDirectory,
	)
	if err != nil {
		t.Fatalf("plan initial sidecars: %v", err)
	}
	if len(plans) != 5 {
		t.Fatalf("plans = %#v", plans)
	}
	want := map[string]string{
		"/opt/autostream/local-executor/ports/control-panel.env":    "AUTOSTREAM_BIND_ADDR=127.0.0.1:18080\nAUTOSTREAM_CONFIG_REVISION=10\n",
		"/opt/autostream/local-executor/ports/worker.env":           "AUTOSTREAM_BIND_ADDR=127.0.0.1:18081\nAUTOSTREAM_CONFIG_REVISION=11\n",
		"/opt/autostream/local-executor/ports/encoder-recorder.env": "AUTOSTREAM_BIND_ADDR=127.0.0.1:18082\nAUTOSTREAM_CONFIG_REVISION=12\n",
		"/opt/autostream/local-executor/ports/discord-bot.env":      "AUTOSTREAM_BIND_ADDR=127.0.0.1:18083\nAUTOSTREAM_CONFIG_REVISION=13\n",
		"/opt/autostream/local-executor/ports/observability.env":    "OBSERVABILITY_BIND_ADDR=127.0.0.1:18084\nAUTOSTREAM_CONFIG_REVISION=14\n",
	}
	for _, plan := range plans {
		wantBody, ok := want[filepath.ToSlash(plan.Path)]
		if !ok {
			t.Fatalf("unexpected sidecar path %q", plan.Path)
		}
		if string(plan.Body) != wantBody ||
			bytes.Count(plan.Body, []byte{'\n'}) != 2 ||
			plan.SHA256 != systemdPortSidecarSHA256(plan.Body) {
			t.Fatalf("non-canonical sidecar plan = %#v", plan)
		}
	}
}

func TestCanonicalSystemdPortSidecarPathsCoverFiveConfigureServices(t *testing.T) {
	paths, err := canonicalSystemdPortSidecarPaths(
		defaultSystemdPortSidecarDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/opt/autostream/local-executor/ports/control-panel.env":    true,
		"/opt/autostream/local-executor/ports/worker.env":           true,
		"/opt/autostream/local-executor/ports/encoder-recorder.env": true,
		"/opt/autostream/local-executor/ports/discord-bot.env":      true,
		"/opt/autostream/local-executor/ports/observability.env":    true,
	}
	if len(paths) != len(want) {
		t.Fatalf("canonical paths = %#v", paths)
	}
	for _, candidate := range paths {
		if !want[filepath.ToSlash(candidate)] {
			t.Fatalf("unexpected canonical sidecar path %q", candidate)
		}
	}
}

func TestInitialSystemdPortSidecarPlansRejectTargetDigestDrift(t *testing.T) {
	policy := configureTransactionPolicyFixture(t)
	policy.Targets[0].ConfigSHA256 = "sha256:" + strings.Repeat("f", 64)
	if _, err := initialSystemdPortSidecarPlans(
		policy,
		defaultSystemdPortSidecarDirectory,
	); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("digest drift error = %v", err)
	}
}

func TestInitialSystemdPortSidecarsNeverOverwriteDifferingExistingFile(
	t *testing.T,
) {
	policy := configureTransactionPolicyFixture(t)
	plans, err := initialSystemdPortSidecarPlans(
		policy,
		defaultSystemdPortSidecarDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := make(map[string]initialSystemdPortSidecarSnapshot, len(plans))
	for _, plan := range plans {
		snapshots[plan.Path] = initialSystemdPortSidecarSnapshot{
			Existed: true,
			Body:    append([]byte(nil), plan.Body...),
		}
	}
	snapshots[plans[0].Path] = initialSystemdPortSidecarSnapshot{
		Existed: true,
		Body:    []byte("AUTOSTREAM_BIND_ADDR=127.0.0.1:19999\nAUTOSTREAM_CONFIG_REVISION=1\n"),
	}
	if err := validateInitialSystemdPortSidecarSnapshots(
		plans,
		snapshots,
	); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("different existing sidecar error = %v", err)
	}
}

func TestInitialSystemdPortSidecarsPermitExactExistingAndMissingFiles(
	t *testing.T,
) {
	policy := configureTransactionPolicyFixture(t)
	plans, err := initialSystemdPortSidecarPlans(
		policy,
		defaultSystemdPortSidecarDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshots := make(map[string]initialSystemdPortSidecarSnapshot, len(plans))
	for index, plan := range plans {
		snapshots[plan.Path] = initialSystemdPortSidecarSnapshot{
			Existed: index%2 == 0,
			Body:    append([]byte(nil), plan.Body...),
		}
	}
	if err := validateInitialSystemdPortSidecarSnapshots(
		plans,
		snapshots,
	); err != nil {
		t.Fatalf("exact/missing snapshots: %v", err)
	}
}

func configureTransactionPolicyFixture(t *testing.T) LocalExecutorPolicy {
	t.Helper()
	definitions := []struct {
		id          string
		serviceType string
		port        int
		revision    int64
		database    string
	}{
		{id: "control-panel", serviceType: "control_panel", port: 18080, revision: 10, database: "autostream_control_panel"},
		{id: "worker-a", serviceType: "worker", port: 18081, revision: 11},
		{id: "encoder-a", serviceType: "encoder_recorder", port: 18082, revision: 12},
		{id: "discord-a", serviceType: "discord_bot", port: 18083, revision: 13},
		{id: "observability-a", serviceType: "observability", port: 18084, revision: 14, database: "autostream_observability"},
	}
	targets := make([]LocalExecutorTarget, 0, len(definitions))
	for index, definition := range definitions {
		profile, ok := standardSystemdProfileFor(definition.serviceType)
		if !ok {
			t.Fatalf("missing profile for %s", definition.serviceType)
		}
		adapter, err := hostAgentConfigureSystemdPortAdapterFor(
			definition.serviceType,
			profile.unit,
		)
		if err != nil {
			t.Fatal(err)
		}
		body := systemdPortSidecarBytes(
			adapter.BindVariable,
			"127.0.0.1",
			definition.port,
			definition.revision,
		)
		targets = append(targets, LocalExecutorTarget{
			ServiceID:        definition.id,
			ServiceType:      definition.serviceType,
			DeploymentMode:   ModeSystemd,
			DatabaseName:     definition.database,
			EndpointRevision: int64(index + 1),
			ConfigRevision:   definition.revision,
			ConfigSHA256:     systemdPortSidecarSHA256(body),
			LocalListen: LocalExecutorEndpoint{
				Host: "127.0.0.1",
				Port: definition.port,
			},
			Systemd: &SystemdTarget{
				SystemctlPath: "/usr/bin/systemctl",
				RunuserPath:   "/usr/sbin/runuser",
				SmokeUser:     "autostream",
				Unit:          profile.unit,
				ReleaseRoot:   profile.releaseRoot,
				CurrentLink:   profile.currentLink,
				BinaryPath:    profile.binaryPath,
				RequiredPaths: append([]string(nil), profile.requiredPaths...),
			},
		})
	}
	return LocalExecutorPolicy{
		SchemaVersion:        LocalExecutorMutationPolicySchemaVersion,
		ProtocolVersion:      LocalExecutorMutationProtocolVersion,
		HostID:               "host-a",
		AgentUID:             1001,
		AgentGID:             1002,
		SocketPath:           LocalExecutorSocketPath,
		SourcePolicyRevision: 3,
		ProjectionRevision:   4,
		PolicyRevision:       5,
		Mutation: &LocalExecutorMutationPolicy{
			PanelURL: "https://panel.example.com",
		},
		Targets: targets,
	}
}
