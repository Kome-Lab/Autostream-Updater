//go:build linux

package hostruntime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/autostream-contracts/pkg/contracts"
)

func TestSTPortLinuxRootPolicyUsesPrivateAtomicReload(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned policy transition fixture requires Linux root")
	}
	dir, err := os.MkdirTemp("/var/lib", "autostream-st-port-policy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h := newSTPortV2Harness(t, contracts.SystemUpdatePortModeLocalAndAdvertised, false)
	candidates, err := buildSystemUpdatePortPolicyCandidates(h.policy, h.plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "executor-policy.json")
	if err := os.WriteFile(path, candidates.Before, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newFilePortPolicyStore(path, true); err == nil {
		t.Fatal("production constructor accepted an arbitrary root policy path")
	}
	// The test supplies only its isolated root-controlled fixture path.
	store := &filePortPolicyStore{path: path, requireRootOwned: true, policy: h.policy}
	before, err := os.Stat(path)
	if err != nil || store.Verify(candidates.Before) != nil {
		t.Fatal("secure baseline unavailable", err)
	}
	if err := store.Write(candidates, candidates.Target); err != nil {
		t.Fatal(err)
	}
	target, err := os.Stat(path)
	if err != nil || os.SameFile(before, target) || target.Mode().Perm() != 0o600 || !isRootOwner(target) || store.Verify(candidates.Target) == nil {
		t.Fatal("atomic root write did not preserve disk/memory separation", err)
	}
	if err := store.Reload(candidates.Target); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(candidates.Target); err != nil {
		t.Fatal(err)
	}
	if err := store.Replace(candidates, candidates.Rollback); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(candidates.Rollback); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if store.Verify(candidates.Rollback) == nil {
		t.Fatal("unsafe root policy mode accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked-policy.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	store.path = link
	if store.Verify(candidates.Rollback) == nil {
		t.Fatal("root policy symlink accepted")
	}
}
