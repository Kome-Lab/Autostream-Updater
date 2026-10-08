package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func prepareSoftwareClaimRecoveryHistoryTransition(t *testing.T) (*HostPullAgent, *softwareClaimRecoveryTestPanel,
	*softwareClaimRecoveryHistoryTestInspector, softwareClaimRecoverySnapshot, softwareClaimRecoveryIntent, SoftwareClaimRecoveryProof) {
	t.Helper()
	agent, panel, inspector, _, first := newSoftwareClaimRecoveryHarness(t)
	historyInspector := &softwareClaimRecoveryHistoryTestInspector{base: inspector, stateDir: agent.StateDir}
	agent.ClaimRecoveryInspector = historyInspector
	if err := agent.RecoverSoftwareClaim(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	old, exists, err := loadSoftwareClaimRecoverySnapshot(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists {
		t.Fatal("load settled transition fixture")
	}
	second := prepareSoftwareClaimRecoveryHistorySuccessor(t, agent, panel, first)
	binding := HostAgentBinding{ServiceID: agent.Bootstrap.NodeID, ServiceType: ServiceTypeUpdateAgent,
		TransportMode: HostTransportPullV2, ExecutionHostID: panel.policy.ExecutionHostID, OwnershipEpoch: second.OwnershipEpoch}
	proof, err := agent.inspectSoftwareClaimRecovery(context.Background(), second, binding, panel.policy)
	if err != nil {
		t.Fatal(err)
	}
	next := newSoftwareClaimRecoveryIntent(second, agent.Bootstrap.NodeID, binding.ExecutionHostID, panel.policy)
	next.PreviousSettledRawSHA256 = softwareClaimRecoveryRawSHA256(old.Raw)
	next.Attempts = []softwareClaimRecoveryAttempt{{LeaseGeneration: second.LeaseGeneration, StartedAt: time.Now().UTC()}}
	return agent, panel, historyInspector, old, next, proof
}

func TestSoftwareClaimRecoveryHistorySyncOrderAndExactCrashArchiveReuse(t *testing.T) {
	agent, _, _, old, next, proof := prepareSoftwareClaimRecoveryHistoryTransition(t)
	runtime := defaultSoftwareClaimRecoveryHistoryStoreRuntime()
	var order []string
	runtime.syncFile = func(file *os.File) error { order = append(order, "file"); return file.Sync() }
	runtime.syncDir = func(path string) error {
		if path == agent.StateDir {
			order = append(order, "parent")
		} else {
			order = append(order, "history")
		}
		return syncDirectory(path)
	}
	runtime.writeCurrent = func(string, []byte, os.FileMode) error {
		order = append(order, "current")
		return errors.New("before current rename")
	}
	if err := transitionSoftwareClaimRecoveryIntent(agent.StateDir, next.PreviousSettledRawSHA256, next, proof, runtime); err == nil {
		t.Fatal("failed current commit was accepted")
	}
	if strings.Join(order, ",") != "file,history,parent,current" {
		t.Fatalf("current was replaced before archive file/directory/parent durability: %v", order)
	}
	current, exists, err := loadSoftwareClaimRecoverySnapshot(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || string(current.Raw) != string(old.Raw) || len(current.Archives) != 1 {
		t.Fatal("crash-before-CAS did not retain complete current and exclusive raw archive")
	}
	archive := filepath.Join(agent.StateDir, softwareClaimRecoveryHistoryName, next.PreviousSettledRawSHA256+".json")
	info, err := os.Lstat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := transitionSoftwareClaimRecoveryIntent(agent.StateDir, next.PreviousSettledRawSHA256, next, proof, defaultSoftwareClaimRecoveryHistoryStoreRuntime()); err != nil {
		t.Fatal("exact safe archive from a prior crash could not be reused:", err)
	}
	after, err := os.Lstat(archive)
	if err != nil || !os.SameFile(info, after) || !info.ModTime().Equal(after.ModTime()) {
		t.Fatal("retry overwrote the immutable archive instead of verifying and syncing it")
	}
}

func TestSoftwareClaimRecoveryHistoryDurabilityFailuresKeepOldOrNewCompleteState(t *testing.T) {
	for _, kind := range []string{"file_sync", "history_sync", "parent_sync", "before_rename", "after_rename"} {
		t.Run(kind, func(t *testing.T) {
			agent, panel, _, old, next, proof := prepareSoftwareClaimRecoveryHistoryTransition(t)
			pending, err := os.ReadFile(agent.Journal.path)
			if err != nil {
				t.Fatal(err)
			}
			claims := len(panel.claims)
			runtime := defaultSoftwareClaimRecoveryHistoryStoreRuntime()
			switch kind {
			case "file_sync":
				runtime.syncFile = func(*os.File) error { return errors.New("file durability unavailable") }
			case "history_sync", "parent_sync":
				runtime.syncDir = func(path string) error {
					if (kind == "parent_sync") == (path == agent.StateDir) {
						return errors.New("directory durability unavailable")
					}
					return syncDirectory(path)
				}
			case "before_rename":
				runtime.writeCurrent = func(string, []byte, os.FileMode) error { return errors.New("before rename") }
			case "after_rename":
				runtime.writeCurrent = func(path string, payload []byte, mode os.FileMode) error {
					if err := writeAtomicFile(path, payload, mode); err != nil {
						return err
					}
					return errors.New("reported uncertainty after visible atomic rename")
				}
			}
			if err := transitionSoftwareClaimRecoveryIntent(agent.StateDir, next.PreviousSettledRawSHA256, next, proof, runtime); err == nil {
				t.Fatal("uncertain history durability was accepted")
			}
			current, exists, err := loadSoftwareClaimRecoverySnapshot(agent.StateDir, managedSnapshotOwnedByCurrentUser)
			if err != nil || !exists {
				t.Fatal("durability failure exposed an absent or partial current head")
			}
			if kind == "after_rename" {
				if current.Intent.Original != next.Original || current.Intent.Settled || len(current.Archives) != 1 {
					t.Fatal("postrename uncertainty lost the complete unsettled head and immutable history")
				}
				if err := agent.RecoverSoftwareClaim(context.Background(), next.Request); err == nil || len(panel.claims) != claims {
					t.Fatal("postrename uncertainty blindly issued a central claim")
				}
			} else if string(current.Raw) != string(old.Raw) {
				t.Fatal("failed archive durability replaced the original current head")
			}
			afterPending, err := os.ReadFile(agent.Journal.path)
			if err != nil || string(pending) != string(afterPending) || len(panel.claims) != claims {
				t.Fatal("history durability failure changed pending bytes or issued a new claim")
			}
		})
	}
}

func TestSoftwareClaimRecoveryHistoryCASUsesRawBytesInsteadOfCanonicalJSON(t *testing.T) {
	agent, _, _, old, next, proof := prepareSoftwareClaimRecoveryHistoryTransition(t)
	runtime := defaultSoftwareClaimRecoveryHistoryStoreRuntime()
	changed := append([]byte(" \n"), old.Raw...)
	runtime.syncDir = func(path string) error {
		if path == agent.StateDir {
			if err := os.WriteFile(filepath.Join(path, softwareClaimRecoveryIntentName), changed, 0o600); err != nil {
				return err
			}
		}
		return syncDirectory(path)
	}
	if err := transitionSoftwareClaimRecoveryIntent(agent.StateDir, next.PreviousSettledRawSHA256, next, proof, runtime); err == nil {
		t.Fatal("canonical reserialization hid a change to the archived raw head")
	}
	current, _, err := loadSoftwareClaimRecoverySnapshot(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || string(current.Raw) != string(changed) || softwareClaimRecoveryIntentSHA256(current.Intent) != softwareClaimRecoveryIntentSHA256(old.Intent) {
		t.Fatal("raw CAS fixture did not retain distinct bytes with equal decoded metadata")
	}
}
