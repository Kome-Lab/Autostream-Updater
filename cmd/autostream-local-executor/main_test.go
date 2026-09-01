package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Kome-Lab/Autostream-Updater/internal/hostruntime"
)

func TestRunRequiresExplicitCommand(t *testing.T) {
	err := run(nil, localExecutorCLIDependencies{
		Output: &bytes.Buffer{},
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "usage: autostream-local-executor") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunStartsExecutorWithDefaultRootOwnedPolicy(t *testing.T) {
	var servedPath string
	err := run([]string{"run"}, localExecutorCLIDependencies{
		Output: &bytes.Buffer{},
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			t.Fatal("run must let ServeLocalExecutor own secure policy loading")
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(_ context.Context, policyPath string) error {
			servedPath = policyPath
			return context.Canceled
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	if servedPath != defaultLocalExecutorPolicyPath {
		t.Fatalf("served policy path=%q", servedPath)
	}
}

func TestRunValidatesRootOwnedPolicyAndPrintsDigest(t *testing.T) {
	output := &bytes.Buffer{}
	policy := hostruntime.LocalExecutorPolicy{
		SchemaVersion:   hostruntime.LocalExecutorPolicySchemaVersion,
		ProtocolVersion: hostruntime.LocalExecutorProtocolVersion,
		HostID:          "host-a",
		AgentUID:        1234,
		AgentGID:        1234,
		SocketPath:      hostruntime.LocalExecutorSocketPath,
		PolicyRevision:  1,
		Targets: []hostruntime.LocalExecutorTarget{{
			ServiceID:      "worker-a",
			ServiceType:    "worker",
			DeploymentMode: hostruntime.ModeSystemd,
			ConfigRevision: 1,
			LocalListen:    hostruntime.LocalExecutorEndpoint{Host: "127.0.0.1", Port: 8084},
			Systemd:        &hostruntime.SystemdTarget{Unit: "autostream-worker.service"},
		}},
	}
	var loadedPath string
	var requireRootOwned bool
	err := run([]string{"validate-policy"}, localExecutorCLIDependencies{
		Output: output,
		LoadPolicy: func(path string, requireRoot bool) (hostruntime.LocalExecutorPolicy, error) {
			loadedPath = path
			requireRootOwned = requireRoot
			return policy, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if loadedPath != defaultLocalExecutorPolicyPath || !requireRootOwned {
		t.Fatalf("path=%q require_root=%v", loadedPath, requireRootOwned)
	}
	digest, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, digest) || !strings.Contains(got, "policy valid") {
		t.Fatalf("output=%q", got)
	}
}

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	dependencies := localExecutorCLIDependencies{
		Output: &bytes.Buffer{},
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
	}
	for _, args := range [][]string{
		{"run", "--listen", "127.0.0.1:8090"},
		{"run", "--policy", "relative.json"},
		{"validate-policy", "extra"},
		{"apply"},
		{"recover-self-update"},
		{"recover-self-update", "--recovery-slot", "c"},
		{"recover-self-update", "--recovery-slot", "a", "--policy", "/tmp/policy.json"},
	} {
		if err := run(args, dependencies); err == nil {
			t.Fatalf("args %q unexpectedly accepted", args)
		}
	}
}

func TestRunDelegatesFixedSlotSelfUpdateRecovery(t *testing.T) {
	var recoveredSlot string
	dependencies := localExecutorCLIDependencies{
		Output: &bytes.Buffer{},
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
		RecoverSelfUpdate: func(_ context.Context, slot string) error {
			recoveredSlot = slot
			return nil
		},
	}
	if err := run(
		[]string{"recover-self-update", "--recovery-slot", "a"},
		dependencies,
	); err != nil {
		t.Fatalf("recover-self-update: %v", err)
	}
	if recoveredSlot != hostruntime.HostSelfUpdateSlotA {
		t.Fatalf("recovered slot=%q", recoveredSlot)
	}
}

func TestRunDelegatesVerifiedBundleManualUpgrade(t *testing.T) {
	output := &bytes.Buffer{}
	var received hostruntime.ManualHostUpgradeRequest
	rootChecked := false
	dependencies := localExecutorCLIDependencies{
		Output: output,
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
		RequireRoot: func() error {
			rootChecked = true
			return nil
		},
		UpgradeHostRuntime: func(
			_ context.Context,
			request hostruntime.ManualHostUpgradeRequest,
		) (hostruntime.ManualHostUpgradeResult, error) {
			received = request
			return hostruntime.ManualHostUpgradeResult{
				PreviousSlot: hostruntime.HostSelfUpdateSlotA,
				ActiveSlot:   hostruntime.HostSelfUpdateSlotB,
				Version:      "v9.9.9",
			}, nil
		},
	}
	err := run([]string{
		"manual-upgrade-host-runtime",
		"--artifact-root", "/var/tmp/verified-host-agent",
		"--archive-sha256", strings.Repeat("a", 64),
		"--archive-size", "12345",
	}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if !rootChecked {
		t.Fatal("manual upgrade did not require root")
	}
	if received.ArtifactRoot != "/var/tmp/verified-host-agent" ||
		received.ArchiveSHA256 != strings.Repeat("a", 64) ||
		received.ArchiveSize != 12345 ||
		received.AgentStoppedForRecovery {
		t.Fatalf("manual upgrade request=%#v", received)
	}
	if got := output.String(); !strings.Contains(got, "v9.9.9") ||
		!strings.Contains(got, "slots/a -> slots/b") {
		t.Fatalf("manual upgrade output=%q", got)
	}
}

func TestRunPassesStoppedAgentRecoveryHandoffToManualUpgrade(t *testing.T) {
	var received hostruntime.ManualHostUpgradeRequest
	dependencies := localExecutorCLIDependencies{
		Output: &bytes.Buffer{},
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
		RequireRoot:   func() error { return nil },
		UpgradeHostRuntime: func(
			_ context.Context,
			request hostruntime.ManualHostUpgradeRequest,
		) (hostruntime.ManualHostUpgradeResult, error) {
			received = request
			return hostruntime.ManualHostUpgradeResult{
				ActiveSlot: hostruntime.HostSelfUpdateSlotA,
				Version:    "v9.9.9",
			}, nil
		},
	}
	err := run([]string{
		"manual-upgrade-host-runtime",
		"--artifact-root", "/var/tmp/verified-host-agent",
		"--archive-sha256", strings.Repeat("b", 64),
		"--archive-size", "54321",
		"--agent-stopped-for-recovery",
	}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if !received.AgentStoppedForRecovery {
		t.Fatalf("manual upgrade request=%#v", received)
	}
}

func TestRunDelegatesExactHostAgentUpgradeGuard(t *testing.T) {
	output := &bytes.Buffer{}
	rootChecked := false
	var received hostruntime.HostAgentUpgradeGuardRequest
	dependencies := localExecutorCLIDependencies{
		Output: output,
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
		RequireRoot: func() error {
			rootChecked = true
			return nil
		},
		GuardRestartHostAgent: func(
			_ context.Context,
			request hostruntime.HostAgentUpgradeGuardRequest,
		) error {
			received = request
			return nil
		},
	}
	err := run([]string{
		"guard-restart-host-agent",
		"--expected-slot", "a",
		"--agent-sha256", strings.Repeat("a", 64),
		"--executor-sha256", strings.Repeat("b", 64),
	}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if !rootChecked {
		t.Fatal("Host Agent upgrade guard did not require root")
	}
	if received != (hostruntime.HostAgentUpgradeGuardRequest{
		ExpectedSlot:   hostruntime.HostSelfUpdateSlotA,
		AgentSHA256:    strings.Repeat("a", 64),
		ExecutorSHA256: strings.Repeat("b", 64),
	}) {
		t.Fatalf("guard request=%+v", received)
	}
	if !strings.Contains(output.String(), "exact pre-upgrade Host Agent restarted") {
		t.Fatalf("guard output=%q", output.String())
	}
}

func TestRunRejectsUnsafeHostAgentUpgradeGuardArgumentsBeforeRoot(t *testing.T) {
	rootChecks := 0
	guardCalls := 0
	dependencies := localExecutorCLIDependencies{
		Output: &bytes.Buffer{},
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
		RequireRoot: func() error {
			rootChecks++
			return nil
		},
		GuardRestartHostAgent: func(
			context.Context,
			hostruntime.HostAgentUpgradeGuardRequest,
		) error {
			guardCalls++
			return nil
		},
	}
	for _, args := range [][]string{
		{"guard-restart-host-agent"},
		{
			"guard-restart-host-agent",
			"--expected-slot", "c",
			"--agent-sha256", strings.Repeat("a", 64),
			"--executor-sha256", strings.Repeat("b", 64),
		},
		{
			"guard-restart-host-agent",
			"--expected-slot", "a",
			"--agent-sha256", strings.Repeat("A", 64),
			"--executor-sha256", strings.Repeat("b", 64),
		},
		{
			"guard-restart-host-agent",
			"--expected-slot", "a",
			"--agent-sha256", strings.Repeat("a", 64),
			"--executor-sha256", strings.Repeat("b", 64),
			"unexpected",
		},
	} {
		if err := run(args, dependencies); err == nil {
			t.Fatalf("guard args %q unexpectedly accepted", args)
		}
	}
	if rootChecks != 0 || guardCalls != 0 {
		t.Fatalf("unsafe guard args root_checks=%d guard_calls=%d", rootChecks, guardCalls)
	}
}

func TestRunInspectsHostUpdateRecoveryAsRoot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active bool
		want   string
	}{
		{name: "active", active: true, want: "active\n"},
		{name: "inactive", active: false, want: "inactive\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := &bytes.Buffer{}
			rootChecked := false
			inspected := false
			err := run(
				[]string{"inspect-host-update-recovery"},
				localExecutorCLIDependencies{
					Output: output,
					LoadPolicy: func(
						string,
						bool,
					) (hostruntime.LocalExecutorPolicy, error) {
						return hostruntime.LocalExecutorPolicy{}, nil
					},
					ServeExecutor: func(context.Context, string) error {
						return nil
					},
					RequireRoot: func() error {
						rootChecked = true
						return nil
					},
					InspectHostUpdateRecovery: func() (bool, error) {
						inspected = true
						return tc.active, nil
					},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if !rootChecked || !inspected {
				t.Fatalf(
					"root_checked=%v inspected=%v",
					rootChecked,
					inspected,
				)
			}
			if got := output.String(); got != tc.want {
				t.Fatalf("output=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestRunHostUpdateRecoveryInspectionFailsClosed(t *testing.T) {
	base := func() localExecutorCLIDependencies {
		return localExecutorCLIDependencies{
			Output: &bytes.Buffer{},
			LoadPolicy: func(
				string,
				bool,
			) (hostruntime.LocalExecutorPolicy, error) {
				return hostruntime.LocalExecutorPolicy{}, nil
			},
			ServeExecutor: func(context.Context, string) error { return nil },
		}
	}

	dependencies := base()
	inspected := false
	dependencies.RequireRoot = func() error { return errors.New("not root") }
	dependencies.InspectHostUpdateRecovery = func() (bool, error) {
		inspected = true
		return false, nil
	}
	err := run([]string{"inspect-host-update-recovery"}, dependencies)
	if err == nil || err.Error() != "Host update recovery inspection requires root" {
		t.Fatalf("non-root error=%v", err)
	}
	if inspected {
		t.Fatal("non-root inspection reached the Host journal")
	}

	dependencies = base()
	dependencies.RequireRoot = func() error { return nil }
	dependencies.InspectHostUpdateRecovery = func() (bool, error) {
		return false, errors.New("unsafe journal")
	}
	err = run([]string{"inspect-host-update-recovery"}, dependencies)
	if err == nil || !strings.Contains(
		err.Error(),
		"inspect Host update recovery: unsafe journal",
	) {
		t.Fatalf("unsafe inspection error=%v", err)
	}
	if got := dependencies.Output.(*bytes.Buffer).String(); got != "" {
		t.Fatalf("unsafe inspection output=%q", got)
	}
}

func TestHostRuntimeMutationCancellationIsNotSuppressed(t *testing.T) {
	if suppressLocalExecutorCancellation(
		[]string{"manual-upgrade-host-runtime"}, context.Canceled,
	) {
		t.Fatal("manual upgrade cancellation would be reported as success")
	}
	if suppressLocalExecutorCancellation(
		[]string{"guard-restart-host-agent"}, context.Canceled,
	) {
		t.Fatal("Host Agent recovery guard cancellation would be reported as success")
	}
	if !suppressLocalExecutorCancellation([]string{"run"}, context.Canceled) {
		t.Fatal("normal server shutdown cancellation should remain quiet")
	}
	if !suppressLocalExecutorCancellation(
		[]string{"recover-self-update"}, context.Canceled,
	) {
		t.Fatal("existing recovery cancellation behavior should remain quiet")
	}
}

func TestRunEmergencyRuntimeCredentialRecoveryRequiresRootAndConfirmation(
	t *testing.T,
) {
	base := func() localExecutorCLIDependencies {
		return localExecutorCLIDependencies{
			Output: &bytes.Buffer{},
			LoadPolicy: func(
				string,
				bool,
			) (hostruntime.LocalExecutorPolicy, error) {
				return hostruntime.LocalExecutorPolicy{}, nil
			},
			ServeExecutor: func(context.Context, string) error {
				return nil
			},
		}
	}
	for _, args := range [][]string{
		{"recover-runtime-credential", "--rotation-id", "rotation-a"},
		{"recover-runtime-credential", "--confirm-emergency-revoked"},
		{"recover-runtime-credential", "--rotation-id", " rotation-a", "--confirm-emergency-revoked"},
		{"recover-runtime-credential", "--rotation-id", "rotation-a", "--confirm-emergency-revoked", "extra"},
		{"recover-runtime-credential", "--rotation-id", "rotation-a", "--confirm-emergency-revoked=sentinel-runtime-token-secret"},
	} {
		dependencies := base()
		called := false
		dependencies.RequireRoot = func() error {
			called = true
			return nil
		}
		dependencies.RecoverRuntimeCredential = func(string) error {
			t.Fatal("invalid request reached recovery")
			return nil
		}
		err := run(args, dependencies)
		if err == nil || called {
			t.Fatalf("args=%q err=%v root_called=%v", args, err, called)
		}
		if strings.Contains(
			err.Error(),
			"sentinel-runtime-token-secret",
		) {
			t.Fatalf("argument parse error leaked input: %v", err)
		}
	}

	dependencies := base()
	recovered := ""
	dependencies.RequireRoot = func() error {
		return errors.New("not root")
	}
	dependencies.RecoverRuntimeCredential = func(string) error {
		t.Fatal("non-root request reached recovery")
		return nil
	}
	args := []string{
		"recover-runtime-credential",
		"--rotation-id",
		"rotation-a",
		"--confirm-emergency-revoked",
	}
	if err := run(args, dependencies); err == nil ||
		err.Error() != "recover-runtime-credential requires root" {
		t.Fatalf("non-root error=%v", err)
	}

	dependencies.RequireRoot = func() error { return nil }
	dependencies.RecoverRuntimeCredential = func(rotationID string) error {
		recovered = rotationID
		return nil
	}
	if err := run(args, dependencies); err != nil {
		t.Fatal(err)
	}
	if recovered != "rotation-a" {
		t.Fatalf("recovered rotation=%q", recovered)
	}
}

func TestRunPrintsVersion(t *testing.T) {
	output := &bytes.Buffer{}
	err := run([]string{"version"}, localExecutorCLIDependencies{
		Output: output,
		LoadPolicy: func(string, bool) (hostruntime.LocalExecutorPolicy, error) {
			return hostruntime.LocalExecutorPolicy{}, nil
		},
		ServeExecutor: func(context.Context, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.HasPrefix(got, "autostream-local-executor ") {
		t.Fatalf("output=%q", got)
	}
}
