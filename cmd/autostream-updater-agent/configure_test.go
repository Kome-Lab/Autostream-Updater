package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/hostruntime"
)

type fakePreparedHostAgentConfig struct {
	committedIdentity   *hostruntime.UpdaterConfigureIdentity
	committedProjection *hostruntime.ConfigurePolicyProjection
	commitContext       context.Context
	aborted             bool
}

func (f *fakePreparedHostAgentConfig) CommitContext(
	ctx context.Context,
	identity hostruntime.UpdaterConfigureIdentity,
	projection hostruntime.ConfigurePolicyProjection,
) error {
	f.commitContext = ctx
	copy := identity
	projectionCopy := projection
	f.committedIdentity = &copy
	f.committedProjection = &projectionCopy
	return nil
}

func (f *fakePreparedHostAgentConfig) Abort() {
	f.aborted = true
}

func TestRunHostAgentConfigureStagesWritesValidatesAndActivates(t *testing.T) {
	prepared := &fakePreparedHostAgentConfig{}
	var stageToken string
	var validatedPath string
	var activated bool
	dependencies := validHostAgentConfigureDependencies(prepared)
	dependencies.AcquireTargetLocks = func() (func(), error) {
		t.Fatal("normal configure acquired recovery-only target locks")
		return func() {}, nil
	}
	dependencies.Stage = func(_ context.Context, panelURL, nodeID, token string, peer hostruntime.HostAgentConfigurePeerIdentity, timeout time.Duration) (hostruntime.UpdaterStagedConfiguration, error) {
		if panelURL != "https://panel.example.com" || nodeID != "host-agent-a" || timeout != 45*time.Second {
			t.Fatalf("stage request = %q %q %s", panelURL, nodeID, timeout)
		}
		if peer != (hostruntime.HostAgentConfigurePeerIdentity{UID: 1001, GID: 1002}) {
			t.Fatalf("stage peer = %#v", peer)
		}
		stageToken = token
		return validHostAgentStagedConfiguration(), nil
	}
	dependencies.ValidateInstalled = func(path, policyPath string, staged hostruntime.UpdaterStagedConfiguration) error {
		validatedPath = path
		if policyPath != hostruntime.DefaultLocalExecutorPolicyPath ||
			staged.Config.TransportMode != "pull_v2" ||
			staged.Config.API != (hostruntime.UpdaterConfigureAPIAssertion{}) {
			t.Fatalf("validated configuration = %#v policy=%q", staged, policyPath)
		}
		return nil
	}
	dependencies.Activate = func(_ context.Context, panelURL string, staged hostruntime.UpdaterStagedConfiguration, report hostruntime.UpdaterRuntimeReport, timeout time.Duration) (hostruntime.UpdaterActivationResult, error) {
		activated = true
		if panelURL != "https://panel.example.com" || staged.ConfigurationID != "configuration-a" ||
			report.Hostname != "host-a" || timeout != 45*time.Second {
			t.Fatalf("activation = panel %q staged %#v report %#v timeout %s", panelURL, staged, report, timeout)
		}
		return hostruntime.UpdaterActivationResult{State: "activated", ConfigurationID: staged.ConfigurationID}, nil
	}

	err := runHostAgentConfigure(context.Background(), []string{
		"--panel-url", "https://panel.example.com",
		"--node", "host-agent-a",
		"--timeout", "45s",
	}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if stageToken != "configure-token" {
		t.Fatalf("stage token = %q", stageToken)
	}
	if prepared.committedIdentity == nil ||
		prepared.committedIdentity.RuntimeToken != "runtime-token" ||
		prepared.committedProjection == nil {
		t.Fatalf(
			"committed configuration = %#v / %#v",
			prepared.committedIdentity,
			prepared.committedProjection,
		)
	}
	if validatedPath != defaultHostAgentConfigPath || !activated || !prepared.aborted {
		t.Fatalf("validated=%q activated=%v aborted=%v", validatedPath, activated, prepared.aborted)
	}
	if output := dependencies.Output.(*bytes.Buffer).String(); !strings.Contains(output, defaultHostAgentConfigPath) {
		t.Fatalf("output = %q", output)
	}
}

func TestRunHostAgentConfigureAcceptsExplicitLiveSystemdSidecarAdoption(t *testing.T) {
	prepared := &fakePreparedHostAgentConfig{}
	dependencies := validHostAgentConfigureDependencies(prepared)
	var options hostruntime.HostAgentConfigurationOptions
	var targetLocked, targetUnlocked bool
	dependencies.AcquireTargetLocks = func() (func(), error) {
		targetLocked = true
		return func() { targetUnlocked = true }, nil
	}
	dependencies.ReadToken = func(context.Context) (string, error) {
		if !targetLocked || targetUnlocked {
			t.Fatal("Configure Token was read outside the recovery target lock")
		}
		return "configure-token", nil
	}
	dependencies.Prepare = func(path, policyPath string, got hostruntime.HostAgentConfigurationOptions) (preparedHostAgentConfig, error) {
		if path != defaultHostAgentConfigPath || policyPath != hostruntime.DefaultLocalExecutorPolicyPath {
			return nil, errors.New("unexpected configuration path")
		}
		options = got
		return prepared, nil
	}

	err := runHostAgentConfigure(context.Background(), []string{
		"--panel-url", "https://panel.example.com",
		"--node", "host-agent-a",
		"--adopt-live-systemd-sidecar",
	}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.committedIdentity == nil || prepared.committedProjection == nil {
		t.Fatalf(
			"configuration was not committed: %#v / %#v",
			prepared.committedIdentity,
			prepared.committedProjection,
		)
	}
	if !options.AdoptLiveSystemdSidecar {
		t.Fatal("live systemd sidecar adoption was not explicitly authorized")
	}
	if !targetLocked || !targetUnlocked {
		t.Fatalf("target lock lifecycle locked=%v unlocked=%v", targetLocked, targetUnlocked)
	}
}

func TestRunHostAgentConfigureRejectsNonPullOrEndpointIdentityBeforeCommit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*hostruntime.UpdaterStagedConfiguration)
		want   string
	}{
		{
			name: "missing transport",
			mutate: func(staged *hostruntime.UpdaterStagedConfiguration) {
				staged.Config.TransportMode = ""
			},
			want: "pull_v2",
		},
		{
			name: "unsupported transport",
			mutate: func(staged *hostruntime.UpdaterStagedConfiguration) {
				staged.Config.TransportMode = "unsupported"
			},
			want: "pull_v2",
		},
		{
			name: "api endpoint",
			mutate: func(staged *hostruntime.UpdaterStagedConfiguration) {
				staged.Config.API = hostruntime.UpdaterConfigureAPIAssertion{Host: "127.0.0.1", Port: 19090}
			},
			want: "must not contain an API endpoint",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared := &fakePreparedHostAgentConfig{}
			dependencies := validHostAgentConfigureDependencies(prepared)
			dependencies.Stage = func(context.Context, string, string, string, hostruntime.HostAgentConfigurePeerIdentity, time.Duration) (hostruntime.UpdaterStagedConfiguration, error) {
				staged := validHostAgentStagedConfiguration()
				test.mutate(&staged)
				return staged, nil
			}
			err := runHostAgentConfigure(context.Background(), []string{
				"--panel-url", "https://panel.example.com",
				"--node", "host-agent-a",
			}, dependencies)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v", err)
			}
			if prepared.committedIdentity != nil || prepared.committedProjection != nil {
				t.Fatalf(
					"unsafe configuration was committed: %#v / %#v",
					prepared.committedIdentity,
					prepared.committedProjection,
				)
			}
		})
	}
}

func TestRunHostAgentConfigureNeverAcceptsTokenInArgv(t *testing.T) {
	dependencies := validHostAgentConfigureDependencies(&fakePreparedHostAgentConfig{})
	readToken := false
	secret := "forbidden-configure-secret"
	dependencies.ReadToken = func(context.Context) (string, error) {
		readToken = true
		return "", errors.New("must not read")
	}
	err := runHostAgentConfigure(context.Background(), []string{
		"--panel-url", "https://panel.example.com",
		"--node", "host-agent-a",
		"--runtime-token", secret,
	}, dependencies)
	if err == nil || readToken || strings.Contains(err.Error(), secret) {
		t.Fatalf("error=%v readToken=%v", err, readToken)
	}
}

func TestRunHostAgentConfigureRejectsBusySetupBeforePrepareOrToken(t *testing.T) {
	prepared := &fakePreparedHostAgentConfig{}
	dependencies := validHostAgentConfigureDependencies(prepared)
	dependencies.AcquireRuntimeLocks = func() (func(), error) {
		return func() {}, errors.New("busy")
	}
	serviceIdentityCalled := false
	dependencies.ServiceIdentity = func() (hostruntime.HostAgentConfigurePeerIdentity, error) {
		serviceIdentityCalled = true
		return hostruntime.HostAgentConfigurePeerIdentity{UID: 1001, GID: 1002}, nil
	}
	prepareCalled := false
	dependencies.Prepare = func(string, string, hostruntime.HostAgentConfigurationOptions) (preparedHostAgentConfig, error) {
		prepareCalled = true
		return prepared, nil
	}
	readToken := false
	dependencies.ReadToken = func(context.Context) (string, error) {
		readToken = true
		return "configure-token", nil
	}

	err := runHostAgentConfigure(context.Background(), []string{
		"--panel-url", "https://panel.example.com",
		"--node", "host-agent-a",
	}, dependencies)
	if err == nil || !strings.Contains(err.Error(), "another Host runtime setup") ||
		serviceIdentityCalled || prepareCalled || readToken {
		t.Fatalf(
			"error=%v serviceIdentity=%v prepare=%v readToken=%v",
			err,
			serviceIdentityCalled,
			prepareCalled,
			readToken,
		)
	}
}

func TestRunHostAgentConfigureRejectsBusyAdoptionTargetBeforePrepareOrToken(
	t *testing.T,
) {
	prepared := &fakePreparedHostAgentConfig{}
	dependencies := validHostAgentConfigureDependencies(prepared)
	dependencies.AcquireTargetLocks = func() (func(), error) {
		return func() {}, errors.New("busy")
	}
	prepareCalled := false
	dependencies.Prepare = func(
		string,
		string,
		hostruntime.HostAgentConfigurationOptions,
	) (preparedHostAgentConfig, error) {
		prepareCalled = true
		return prepared, nil
	}
	readToken := false
	dependencies.ReadToken = func(context.Context) (string, error) {
		readToken = true
		return "configure-token", nil
	}

	err := runHostAgentConfigure(context.Background(), []string{
		"--panel-url", "https://panel.example.com",
		"--node", "host-agent-a",
		"--adopt-live-systemd-sidecar",
	}, dependencies)
	if err == nil || !strings.Contains(err.Error(), "managed service target") ||
		prepareCalled || readToken {
		t.Fatalf(
			"error=%v prepare=%v readToken=%v",
			err,
			prepareCalled,
			readToken,
		)
	}
}

func TestNormalizeHostAgentConfigureToken(t *testing.T) {
	if token, err := normalizeHostAgentConfigureToken([]byte(" configure-token\r\n")); err != nil || token != "configure-token" {
		t.Fatalf("token=%q error=%v", token, err)
	}
	if _, err := normalizeHostAgentConfigureToken([]byte(" \n")); err == nil {
		t.Fatal("empty Configure Token was accepted")
	}
	if _, err := normalizeHostAgentConfigureToken(bytes.Repeat([]byte("x"), hostAgentConfigureTokenMaxBytes+1)); err == nil {
		t.Fatal("oversized Configure Token was accepted")
	}
}

func validHostAgentConfigureDependencies(prepared preparedHostAgentConfig) hostAgentConfigureDependencies {
	return hostAgentConfigureDependencies{
		AcquireRuntimeLocks: func() (func(), error) { return func() {}, nil },
		AcquireTargetLocks:  func() (func(), error) { return func() {}, nil },
		Prepare: func(path, policyPath string, options hostruntime.HostAgentConfigurationOptions) (preparedHostAgentConfig, error) {
			if path != defaultHostAgentConfigPath ||
				policyPath != hostruntime.DefaultLocalExecutorPolicyPath {
				return nil, errors.New("unexpected configuration path")
			}
			if options.AdoptLiveSystemdSidecar {
				return nil, errors.New("unexpected live sidecar adoption")
			}
			return prepared, nil
		},
		ServiceIdentity: func() (hostruntime.HostAgentConfigurePeerIdentity, error) {
			return hostruntime.HostAgentConfigurePeerIdentity{UID: 1001, GID: 1002}, nil
		},
		ReadToken: func(context.Context) (string, error) {
			return "configure-token", nil
		},
		Stage: func(context.Context, string, string, string, hostruntime.HostAgentConfigurePeerIdentity, time.Duration) (hostruntime.UpdaterStagedConfiguration, error) {
			return validHostAgentStagedConfiguration(), nil
		},
		ValidateInstalled: func(string, string, hostruntime.UpdaterStagedConfiguration) error { return nil },
		Activate: func(_ context.Context, _ string, staged hostruntime.UpdaterStagedConfiguration, _ hostruntime.UpdaterRuntimeReport, _ time.Duration) (hostruntime.UpdaterActivationResult, error) {
			return hostruntime.UpdaterActivationResult{State: "activated", ConfigurationID: staged.ConfigurationID}, nil
		},
		Hostname: func() (string, error) { return "host-a", nil },
		Output:   &bytes.Buffer{},
	}
}

func validHostAgentStagedConfiguration() hostruntime.UpdaterStagedConfiguration {
	projection, err := hostruntime.BuildHostAgentConfigurePolicy(
		hostruntime.HostAgentConfigurePolicySource{
			PanelURL:                    "https://panel.example.com",
			ExecutionHostID:             "host-a",
			AgentUID:                    1001,
			AgentGID:                    1002,
			SourcePolicyRevision:        3,
			ProjectionRevision:          4,
			LocalExecutorPolicyRevision: 5,
			Targets: []hostruntime.HostAgentConfigurePolicyTarget{{
				ServiceID:             "worker-a",
				ServiceType:           "worker",
				DeploymentMode:        hostruntime.ModeSystemd,
				EndpointRevision:      2,
				AppliedConfigRevision: 7,
				AppliedEndpointPort:   18084,
			}},
		},
	)
	if err != nil {
		panic(err)
	}
	return hostruntime.UpdaterStagedConfiguration{
		Config: hostruntime.UpdaterConfigureIdentity{
			PanelURL:      "https://panel.example.com",
			NodeID:        "host-agent-a",
			RuntimeToken:  "runtime-token",
			ServiceName:   "Host Agent A",
			ServiceType:   "update_agent",
			TransportMode: "pull_v2",
		},
		ConfigurationID:     "configuration-a",
		ActivationToken:     "activation-token",
		ActivationExpiresAt: time.Now().Add(time.Minute),
		ConfigureProtocol:   hostruntime.HostAgentConfigureProtocolVersion,
		LocalExecutorPolicy: &projection,
	}
}
