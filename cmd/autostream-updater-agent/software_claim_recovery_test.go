package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/hostruntime"
)

func softwareClaimRecoveryCLIArgs(command string) []string {
	return []string{command, "--job-id", "orphan-job-one", "--lease-generation", "1", "--target-id", "control-panel",
		"--current-version", "v2.0.0", "--target-version", "v2.0.1", "--config-revision", "1", "--ownership-epoch", "3"}
}

func TestSoftwareClaimRecoveryCLIRequiresExactMetadataAndServiceAccount(t *testing.T) {
	for _, name := range []string{"root", "foreign_account", "missing_metadata", "wrong_config", "extra_token", "duplicate_generation", "mixed_hyphen_duplicate", "generation_overflow", "positional"} {
		t.Run(name, func(t *testing.T) {
			dependencies := hostAgentTestDependencies(t)
			dependencies.LoadCanonicalIdentity = func(string, bool) (hostruntime.Config, error) {
				t.Fatal("rejected recovery read an identity")
				return hostruntime.Config{}, nil
			}
			dependencies.RecoverSoftwareClaim = func(context.Context, hostruntime.Config, hostruntime.SoftwareClaimRecoveryRequest) error {
				t.Fatal("rejected recovery claimed a job")
				return nil
			}
			args := softwareClaimRecoveryCLIArgs("recover-software-claim")
			switch name {
			case "root":
				dependencies.EffectiveUID = func() int { return 0 }
			case "foreign_account":
				dependencies.EffectiveUID = func() int { return 1000 }
			case "missing_metadata":
				args = []string{"recover-software-claim", "--job-id", "orphan-job-one"}
			case "wrong_config":
				args = append(args, "--config", "/tmp/other-identity")
			case "extra_token":
				args = append(args, "--runtime-token", "secret-must-not-be-returned")
			case "duplicate_generation":
				args = append(args, "--lease-generation", "2")
			case "mixed_hyphen_duplicate":
				args = append(args, "-job-id", "foreign-job")
			case "generation_overflow":
				args[4] = "18446744073709551616-secret-must-not-be-returned"
			case "positional":
				args = append(args, "secret-must-not-be-returned")
			}
			err := run(args, dependencies)
			if err == nil || strings.Contains(err.Error(), "secret-must-not-be-returned") {
				t.Fatal("unsafe CLI metadata accepted or echoed")
			}
		})
	}
}

func TestSoftwareClaimRecoveryCLIUsesCanonicalIdentityAndBoundedTerminalOnlyEntry(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.Start = func(context.Context, hostruntime.Config) error {
		t.Fatal("recovery started the ordinary daemon")
		return nil
	}
	dependencies.Recover = func(context.Context, hostruntime.Config) error {
		t.Fatal("orphan recovery used cursor-only recovery")
		return nil
	}
	var actual hostruntime.SoftwareClaimRecoveryRequest
	dependencies.RecoverSoftwareClaim = func(ctx context.Context, identity hostruntime.Config, request hostruntime.SoftwareClaimRecoveryRequest) error {
		actual = request
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > hostAgentRecoverUpdateTimeout || identity.NodeID != "host-agent-a" {
			t.Fatal("canonical bounded recovery context was not used")
		}
		return nil
	}
	if err := run(softwareClaimRecoveryCLIArgs("recover-software-claim"), dependencies); err != nil {
		t.Fatal(err)
	}
	if actual.JobID != "orphan-job-one" || actual.LeaseGeneration != 1 || actual.TargetID != "control-panel" || actual.ConfigRevision != 1 || actual.OwnershipEpoch != 3 {
		t.Fatal("exact operator metadata was changed")
	}
	if got := dependencies.Output.(*bytes.Buffer).String(); got != "software claim recovery settled without applying software\n" {
		t.Fatalf("output=%q", got)
	}
}

func TestSoftwareClaimRecoveryInspectionCLIPrintsMetadataWithoutRecovering(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.RecoverSoftwareClaim = func(context.Context, hostruntime.Config, hostruntime.SoftwareClaimRecoveryRequest) error {
		t.Fatal("inspection claimed a job")
		return nil
	}
	dependencies.InspectSoftwareClaim = func(_ context.Context, _ hostruntime.Config, _ hostruntime.SoftwareClaimRecoveryRequest) (hostruntime.SoftwareClaimRecoveryProof, error) {
		return hostruntime.SoftwareClaimRecoveryProof{RequestSHA256: "sha256:" + strings.Repeat("a", 64), UpdaterID: "host-agent-a", HostID: "host-a", SourcePolicyRevision: 8,
			ProjectionRevision: 8, ExecutorPolicyRevision: 8, ExecutorPolicySHA256: "sha256:" + strings.Repeat("b", 64), OwnershipEpoch: 3, RuntimeVersion: "v2.0.0", NoMutation: true, ObservedAt: time.Now().UTC()}, nil
	}
	if err := run(softwareClaimRecoveryCLIArgs("inspect-software-claim"), dependencies); err != nil {
		t.Fatal(err)
	}
	output := dependencies.Output.(*bytes.Buffer).String()
	if !strings.Contains(output, `"no_mutation":true`) || strings.Contains(output, "runtime-token") || strings.Contains(output, "panel.example") || strings.Contains(output, "command") {
		t.Fatal("inspection did not return bounded secret-free metadata")
	}
}

func TestSoftwareClaimRecoveryCLIExplicitGenerationRereadUsesSeparateEntry(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.RecoverSoftwareClaim = func(context.Context, hostruntime.Config, hostruntime.SoftwareClaimRecoveryRequest) error {
		t.Fatal("confirmed generation reread used the default strict retry entry")
		return nil
	}
	called := false
	dependencies.RecoverSoftwareClaimAfterGenerationRead = func(_ context.Context, _ hostruntime.Config, request hostruntime.SoftwareClaimRecoveryRequest) error {
		called = true
		if request.JobID != "orphan-job-one" || request.LeaseGeneration != 1 {
			t.Fatal("confirmed reread changed immutable metadata")
		}
		return nil
	}
	if err := run(append(softwareClaimRecoveryCLIArgs("recover-software-claim"), "--confirm-current-generation"), dependencies); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("confirmed generation reread entry was not invoked")
	}
	dependencies.LoadCanonicalIdentity = func(string, bool) (hostruntime.Config, error) {
		t.Fatal("inspection accepted a recovery confirmation flag")
		return hostruntime.Config{}, nil
	}
	if err := run(append(softwareClaimRecoveryCLIArgs("inspect-software-claim"), "--confirm-current-generation"), dependencies); err == nil {
		t.Fatal("inspection accepted mutation intent confirmation")
	}
}
