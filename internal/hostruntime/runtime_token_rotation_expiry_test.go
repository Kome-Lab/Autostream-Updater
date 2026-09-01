package hostruntime

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

func TestRuntimeCredentialExpiryRejectsLegacyIdentityBeforeOrphanCleanup(
	t *testing.T,
) {
	now := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
	policy, rt, _, activeBefore := newRuntimeCredentialExecutorFixture(t, now)
	active, _, _, err := rt.loadIdentity(rt.activeIdentity, policy.AgentGID)
	if err != nil {
		t.Fatal(err)
	}
	active.RuntimeToken = testNewRuntimeToken
	stagedBefore, err := marshalRuntimeCredentialIdentity(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.writeIdentityAtomic(
		rt.stagedIdentity,
		stagedBefore,
		policy.AgentGID,
		false,
	); err != nil {
		t.Fatal(err)
	}
	expiredAt := now.Add(-runtimeCredentialStagedMaxAge - time.Minute)
	if err := os.Chtimes(rt.stagedIdentity, expiredAt, expiredAt); err != nil {
		t.Fatal(err)
	}

	checks := 0
	rt.verifyIdentityLayout = func() error {
		checks++
		return errors.New("legacy Host Agent identity already exists")
	}
	if err := reconcileRuntimeCredentialExpiry(rt, policy.AgentGID); err == nil {
		t.Fatal("expiry reconciliation accepted a legacy Host Agent identity")
	}
	if checks != 1 {
		t.Fatalf("identity layout checks = %d", checks)
	}
	activeAfter, err := os.ReadFile(rt.activeIdentity)
	if err != nil || !bytes.Equal(activeAfter, activeBefore) {
		t.Fatalf("active identity changed: %q, %v", activeAfter, err)
	}
	stagedAfter, err := os.ReadFile(rt.stagedIdentity)
	if err != nil || !bytes.Equal(stagedAfter, stagedBefore) {
		t.Fatalf("staged identity changed: %q, %v", stagedAfter, err)
	}
	if _, exists, err := rt.loadStatus(); err != nil || exists {
		t.Fatalf("runtime credential state changed: exists=%v err=%v", exists, err)
	}
}

func TestRuntimeCredentialExpiryRechecksLegacyIdentityBeforeCompletion(
	t *testing.T,
) {
	now := time.Date(2026, 8, 4, 9, 15, 0, 0, time.UTC)
	policy, rt, _, _ := newRuntimeCredentialExecutorFixture(t, now)
	checks := 0
	rt.verifyIdentityLayout = func() error {
		checks++
		if checks == 2 {
			return errors.New("legacy Host Agent identity appeared during expiry reconciliation")
		}
		return nil
	}

	if err := reconcileRuntimeCredentialExpiry(rt, policy.AgentGID); err == nil {
		t.Fatal("expiry reconciliation completed after a legacy identity appeared")
	}
	if checks != 2 {
		t.Fatalf("identity layout checks = %d", checks)
	}
}
