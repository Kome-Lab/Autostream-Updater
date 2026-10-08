package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/hostruntime"
)

func TestSoftwarePlanRecoveryCLIUsesExactRereadAndSeparateReconcileEntry(t *testing.T) {
	dependencies := hostAgentTestDependencies(t)
	dependencies.Start = func(context.Context, hostruntime.Config) error {
		t.Fatal("saved-plan recovery started the daemon")
		return nil
	}
	dependencies.RecoverSoftwareClaim = func(context.Context, hostruntime.Config, hostruntime.SoftwareClaimRecoveryRequest) error {
		t.Fatal("saved-plan recovery used root-absence terminal recovery")
		return nil
	}
	called := false
	dependencies.RecoverSoftwarePlanAfterGenerationRead = func(ctx context.Context, identity hostruntime.Config, request hostruntime.SoftwareClaimRecoveryRequest) error {
		called = true
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > hostAgentRecoverUpdateTimeout || identity.NodeID != "host-agent-a" ||
			request.JobID != "orphan-job-one" || request.LeaseGeneration != 1 || request.ConfigRevision != 1 || request.OwnershipEpoch != 3 {
			t.Fatal("saved-plan recovery changed the exact request or canonical bounded context")
		}
		return nil
	}
	if err := run(softwareClaimRecoveryCLIArgs("recover-software-plan"), dependencies); err != nil {
		t.Fatal(err)
	}
	if !called || dependencies.Output.(*bytes.Buffer).String() != "saved software plan reconciled without restaging or reapplying\n" {
		t.Fatal("separate saved-plan entry was not invoked")
	}
}

func TestSoftwarePlanRecoveryCLIRejectsNonexactRequestsBeforeIdentity(t *testing.T) {
	for _, failure := range []string{"root", "missing", "unknown", "duplicate", "orphan_confirmation", "foreign_path"} {
		t.Run(failure, func(t *testing.T) {
			dependencies := hostAgentTestDependencies(t)
			dependencies.LoadCanonicalIdentity = func(string, bool) (hostruntime.Config, error) {
				t.Fatal("invalid saved-plan request reached identity loading")
				return hostruntime.Config{}, nil
			}
			args := softwareClaimRecoveryCLIArgs("recover-software-plan")
			switch failure {
			case "root":
				dependencies.EffectiveUID = func() int { return 0 }
			case "missing":
				args = []string{"recover-software-plan", "--job-id", "orphan-job-one"}
			case "unknown":
				args = append(args, "--runtime-token", "secret-must-not-be-echoed")
			case "duplicate":
				args = append(args, "-lease-generation", "2")
			case "orphan_confirmation":
				args = append(args, "--confirm-current-generation")
			case "foreign_path":
				args = append(args, "--config", "/tmp/other-identity")
			}
			if err := run(args, dependencies); err == nil || strings.Contains(err.Error(), "secret-must-not-be-echoed") {
				t.Fatal("invalid saved-plan request was accepted or echoed a secret")
			}
		})
	}
}
