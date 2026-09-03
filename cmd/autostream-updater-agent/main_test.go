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

func TestRunHostAgentRequiresExplicitCommand(t *testing.T) {
	err := run(nil, hostAgentTestDependencies(t))
	if err == nil || !strings.Contains(err.Error(), "usage: autostream-host-agent run") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunHostAgentUsesOnlyRootOwnedFourFieldIdentity(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	var loadedPath string
	var requireRootOwned bool
	var started hostruntime.Config
	dependencies.LoadIdentity = func(path string, requireRoot bool) (hostruntime.Config, error) {
		loadedPath = path
		requireRootOwned = requireRoot
		return hostruntime.Config{
			PanelURL:     "https://panel.example.com",
			NodeID:       "host-agent-a",
			RuntimeToken: "runtime-token",
			ServiceName:  "Host Agent A",
		}, nil
	}
	dependencies.Start = func(_ context.Context, identity hostruntime.Config) error {
		started = identity
		return nil
	}

	if err := run([]string{"run", "--config", "/root/agent.yaml"}, dependencies); err != nil {
		t.Fatal(err)
	}
	if loadedPath != "/root/agent.yaml" || !requireRootOwned {
		t.Fatalf("load = path %q root-owned %v", loadedPath, requireRootOwned)
	}
	if started.NodeID != "host-agent-a" || started.RuntimeToken != "runtime-token" {
		t.Fatalf("started identity = %#v", started)
	}
}

func TestValidateHostAgentConfigDoesNotStartAgent(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	started := false
	dependencies.Start = func(context.Context, hostruntime.Config) error {
		started = true
		return errors.New("must not start")
	}
	if err := run([]string{"validate-config"}, dependencies); err != nil {
		t.Fatal(err)
	}
	if started {
		t.Fatal("validate-config started the host agent")
	}
	if got := dependencies.Output.(*bytes.Buffer).String(); got != "host agent identity configuration valid\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestHostAgentCLIRejectsRuntimeTokenArgument(t *testing.T) {
	err := run([]string{"run", "--runtime-token", "must-not-enter-argv"}, hostAgentTestDependencies(t))
	if err == nil {
		t.Fatal("runtime token argument was accepted")
	}
}

func TestHostAgentConfigureCommandDelegatesWithoutTokenArgument(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	var got []string
	dependencies.Configure = func(_ context.Context, args []string) error {
		got = append([]string(nil), args...)
		return nil
	}
	args := []string{"--panel-url", "https://panel.example.com", "--node", "host-agent-a"}
	if err := run(append([]string{"configure"}, args...), dependencies); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "\x00") != strings.Join(args, "\x00") {
		t.Fatalf("configure args = %#v", got)
	}
}

func TestRecoverUpdateRejectsRootBeforeLoadingIdentity(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.EffectiveUID = func() int { return 0 }
	dependencies.LoadCanonicalIdentity = func(string, bool) (hostruntime.Config, error) {
		t.Fatal("root recovery loaded the Host Agent identity")
		return hostruntime.Config{}, nil
	}
	dependencies.Recover = func(context.Context, hostruntime.Config) error {
		t.Fatal("root recovery started the Host Pull Agent")
		return nil
	}

	err := run([]string{"recover-update", "--config", defaultHostAgentConfigPath}, dependencies)
	if err == nil || !strings.Contains(err.Error(), "non-root Host Agent service account") {
		t.Fatalf("root recovery error = %v", err)
	}
}

func TestRecoverUpdateRejectsDifferentNonRootAccount(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.EffectiveUID = func() int { return 1000 }
	dependencies.LoadCanonicalIdentity = func(string, bool) (hostruntime.Config, error) {
		t.Fatal("foreign non-root account loaded the Host Agent identity")
		return hostruntime.Config{}, nil
	}
	err := run([]string{"recover-update", "--config", defaultHostAgentConfigPath}, dependencies)
	if err == nil || !strings.Contains(err.Error(), "Host Agent service account") {
		t.Fatalf("foreign account recovery error = %v", err)
	}
}

func TestRecoverUpdateLoadsCanonicalIdentityWithBoundedContext(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.EffectiveUID = func() int { return 993 }
	var loadedPath string
	var requireRootOwned bool
	var recovered hostruntime.Config
	dependencies.LoadCanonicalIdentity = func(path string, requireRoot bool) (hostruntime.Config, error) {
		loadedPath = path
		requireRootOwned = requireRoot
		return hostruntime.Config{
			PanelURL:     "https://panel.example.com",
			NodeID:       "host-agent-a",
			RuntimeToken: "runtime-token",
			ServiceName:  "Host Agent A",
		}, nil
	}
	dependencies.Recover = func(ctx context.Context, identity hostruntime.Config) error {
		recovered = identity
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("recovery context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > hostAgentRecoverUpdateTimeout {
			t.Fatalf("recovery deadline remaining = %s", remaining)
		}
		return nil
	}

	if err := run([]string{"recover-update", "--config", defaultHostAgentConfigPath}, dependencies); err != nil {
		t.Fatal(err)
	}
	if loadedPath != defaultHostAgentConfigPath || !requireRootOwned {
		t.Fatalf("load = path %q root-owned %v", loadedPath, requireRootOwned)
	}
	if recovered.NodeID != "host-agent-a" || recovered.RuntimeToken != "runtime-token" {
		t.Fatalf("recovered identity = %#v", recovered)
	}
}

func TestRecoverUpdateRejectsNonCanonicalIdentityPath(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.LoadCanonicalIdentity = func(string, bool) (hostruntime.Config, error) {
		t.Fatal("non-canonical recovery identity was loaded")
		return hostruntime.Config{}, nil
	}
	err := run([]string{"recover-update", "--config", "/root/other-agent.yaml"}, dependencies)
	if err == nil || !strings.Contains(err.Error(), "canonical Host Agent identity path") {
		t.Fatalf("non-canonical recovery error = %v", err)
	}
}

func TestHostAgentVersionDoesNotLoadIdentity(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.LoadIdentity = func(string, bool) (hostruntime.Config, error) {
		t.Fatal("version loaded identity")
		return hostruntime.Config{}, nil
	}
	if err := run([]string{"--version"}, dependencies); err != nil {
		t.Fatal(err)
	}
	if got := dependencies.Output.(*bytes.Buffer).String(); !strings.HasPrefix(got, "autostream-host-agent ") {
		t.Fatalf("version output = %q", got)
	}
}

func hostAgentTestDependencies(t *testing.T) hostAgentCLIDependencies {
	t.Helper()
	return hostAgentCLIDependencies{
		LoadIdentity: func(path string, requireRoot bool) (hostruntime.Config, error) {
			if path != defaultHostAgentConfigPath || !requireRoot {
				t.Fatalf("load = path %q root-owned %v", path, requireRoot)
			}
			return hostruntime.Config{
				PanelURL:     "https://panel.example.com",
				NodeID:       "host-agent-a",
				RuntimeToken: "runtime-token",
				ServiceName:  "Host Agent A",
			}, nil
		},
		LoadCanonicalIdentity: func(path string, requireRoot bool) (hostruntime.Config, error) {
			if path != defaultHostAgentConfigPath || !requireRoot {
				t.Fatalf("canonical load = path %q root-owned %v", path, requireRoot)
			}
			return hostruntime.Config{
				PanelURL:     "https://panel.example.com",
				NodeID:       "host-agent-a",
				RuntimeToken: "runtime-token",
				ServiceName:  "Host Agent A",
			}, nil
		},
		Start:        func(context.Context, hostruntime.Config) error { return nil },
		Recover:      func(context.Context, hostruntime.Config) error { return nil },
		Configure:    func(context.Context, []string) error { return nil },
		EffectiveUID: func() int { return 993 },
		ServiceAccountUID: func() (int, error) {
			return 993, nil
		},
		Output: &bytes.Buffer{},
	}
}
