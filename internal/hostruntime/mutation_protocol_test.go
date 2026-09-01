package hostruntime

import (
	"fmt"
	"strings"
	"testing"
)

func validMutationPlan() MutationPlan {
	plan := MutationPlan{
		JobID: "job-01", HostID: "edge-01", TargetID: "worker-01",
		ServiceType: "worker", DeploymentMode: ModeSystemd,
		CurrentVersion: "v1.0.0", ConfigSHA256: "sha256:" + strings.Repeat("f", 64),
		TargetVersion: "v1.1.0", LeaseGeneration: 2,
		ArtifactDigest: strings.Repeat("a", 64), ExpectedVersion: "v1.1.0",
		SessionID: "session-00000001",
	}
	plan.PlanSHA256, _ = plan.ComputePlanSHA256()
	return plan
}

func TestMutationPlanRejectsPrivilegedWireFields(t *testing.T) {
	plan := validMutationPlan()
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded := fmt.Sprintf("%#v", plan)
	for _, forbidden := range []string{"argv", "environment", "unit", "path", "command"} {
		if strings.Contains(strings.ToLower(encoded), forbidden) {
			t.Fatalf("mutation plan exposed privileged %s field: %s", forbidden, encoded)
		}
	}
}

func TestBoundedSecretFormattingIsAlwaysRedacted(t *testing.T) {
	const marker = "super-sensitive-value"
	secret := NewBoundedSecret(marker)
	for _, rendered := range []string{
		fmt.Sprint(secret), fmt.Sprintf("%v", secret), fmt.Sprintf("%#v", secret),
	} {
		if strings.Contains(rendered, marker) || rendered != "[REDACTED]" {
			t.Fatalf("secret formatting = %q", rendered)
		}
	}
}
