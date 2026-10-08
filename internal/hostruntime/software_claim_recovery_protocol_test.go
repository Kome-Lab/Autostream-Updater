package hostruntime

import (
	"strings"
	"testing"
)

// This uses the existing strict decoder so the before result is an observable
// unsupported-operation failure, rather than a missing-symbol compiler error.
func TestSoftwareClaimRecoveryReadOnlyRequestUsesTypedBoundedProtocol(t *testing.T) {
	payload := `{"version":2,"operation":"software_claim_recovery_inspect","service_id":"control-panel","source_policy_revision":8,"ownership_epoch":3,"ownership_policy_revision":8,"executor_policy_revision":8,"software_claim_recovery":{"request":{"job_id":"orphan-job-one","lease_generation":1,"target_id":"control-panel","current_version":"v2.0.0","target_version":"v2.0.1","config_revision":1,"ownership_epoch":3},"executor_policy_sha256":"sha256:` + strings.Repeat("a", 64) + `"}}`
	request, err := DecodeLocalExecutorRequest(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("bounded read-only recovery inspection was rejected: %v", err)
	}
	if request.Operation != "software_claim_recovery_inspect" || request.ServiceID != "control-panel" {
		t.Fatal("read-only recovery request lost its fixed operation or target")
	}
	for _, extra := range []string{
		`,"mutation_grant":"must-not-be-a-recovery-credential"`,
		`,"command":"must-not-run"`,
		`,"path":"/arbitrary/path"`,
	} {
		mutant := strings.TrimSuffix(payload, "}") + extra + "}"
		if _, err := DecodeLocalExecutorRequest(strings.NewReader(mutant)); err == nil {
			t.Fatal("read-only recovery inspection accepted an execution credential or arbitrary input")
		}
	}
}
