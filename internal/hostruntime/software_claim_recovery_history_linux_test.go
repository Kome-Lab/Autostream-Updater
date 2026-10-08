//go:build linux

package hostruntime

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type softwareClaimRecoveryHistoryRootInspector struct {
	policy  LocalExecutorPolicy
	request LocalExecutorRequest
	runtime softwareClaimRecoveryRootRuntime
}

func prepareSoftwareClaimRecoveryHistoryRootCompleted(t *testing.T) (*manualHostUpgradeLinuxFixture, LocalExecutorPolicy,
	LocalExecutorRequest, softwareClaimRecoveryRootRuntime, *HostPullAgent, *softwareClaimRecoveryTestPanel, SoftwareClaimRecoveryRequest) {
	t.Helper()
	fixture, policy, local, runtime := newSoftwareClaimRecoveryRootHarness(t)
	agent, panel, _, _, _ := newSoftwareClaimRecoveryHarness(t)
	authenticated, err := runtime.readPolicy(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	first := local.SoftwareClaimRecovery.Request
	agent.StateDir, panel.policy = fixture.runtime.paths.hostStateRoot, authenticated
	panel.job.ID, panel.job.HostID = first.JobID, policy.HostID
	panel.job.TargetID, panel.job.TargetType, panel.job.ServiceType = first.TargetID, policy.Targets[0].ServiceType, policy.Targets[0].ServiceType
	agent.ClaimRecoveryInspector = softwareClaimRecoveryHistoryRootInspector{policy: policy, request: local, runtime: runtime}
	if err := agent.RecoverSoftwareClaim(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := prepareSoftwareClaimRecoveryHistorySuccessor(t, agent, panel, first)
	if err := agent.RecoverSoftwareClaim(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	return fixture, policy, local, runtime, agent, panel, first
}

func TestSoftwareClaimRecoveryHistoryRootRejectsCurrentPriorAndLinkedTerminalRecords(t *testing.T) {
	for _, kind := range []string{"successor", "previous", "linked", "unrelated"} {
		t.Run(kind, func(t *testing.T) {
			fixture, policy, local, runtime, agent, panel, first := prepareSoftwareClaimRecoveryHistoryRootCompleted(t)
			request := prepareSoftwareClaimRecoveryHistorySuccessor(t, agent, panel, first, "orphan-job-three")
			local.SoftwareClaimRecovery = &SoftwareClaimRecoveryInspection{Request: request, ExecutorPolicySHA256: panel.policy.LocalExecutorPolicySHA256}
			jobID := request.JobID
			switch kind {
			case "previous":
				jobID = "orphan-job-two"
			case "linked":
				jobID = first.JobID
			case "unrelated":
				jobID = "unrelated-terminal-job"
			}
			path := filepath.Join(fixture.runtime.paths.localExecutorStateRoot, ".autostream-updater-history.checkpoint.json")
			writeSoftwareClaimRecoveryRootJSON(t, path, updateCheckpoint{SchemaVersion: 1, JobID: jobID, TargetID: request.TargetID,
				DeploymentMode: ModeSystemd, Phase: "succeeded", TargetVersion: request.TargetVersion})
			beforeMarker, err := os.ReadFile(filepath.Join(agent.StateDir, softwareClaimRecoveryIntentName))
			if err != nil {
				t.Fatal(err)
			}
			beforeJournal, err := os.ReadFile(agent.Journal.path)
			if err != nil {
				t.Fatal(err)
			}
			proof, inspectErr := inspectSoftwareClaimRecoveryRoot(context.Background(), policy, local, runtime)
			if kind == "unrelated" {
				if inspectErr != nil || proof.Validate() != nil || !proof.NoMutation || proof.PriorSettledRawSHA256 != softwareClaimRecoveryRawSHA256(beforeMarker) {
					t.Fatal("unrelated terminal history prevented the exact read-only successor proof")
				}
			} else if inspectErr == nil {
				t.Fatal("root accepted a terminal mutation record for a current, previous or linked recovery job")
			}
			afterMarker, markerErr := os.ReadFile(filepath.Join(agent.StateDir, softwareClaimRecoveryIntentName))
			afterJournal, journalErr := os.ReadFile(agent.Journal.path)
			if markerErr != nil || journalErr != nil || string(beforeMarker) != string(afterMarker) || string(beforeJournal) != string(afterJournal) ||
				fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 {
				t.Fatal("root history inspection rewrote state or changed services")
			}
		})
	}
}

func TestSoftwareClaimRecoveryHistoryBrokenChainBlocksStageAndManualUpgrade(t *testing.T) {
	for _, kind := range []string{"head_absent", "missing_link", "changed_raw", "head_hardlink"} {
		t.Run(kind, func(t *testing.T) {
			fixture, policy, _, _, agent, _, _ := prepareSoftwareClaimRecoveryHistoryRootCompleted(t)
			if softwareClaimRecoveryIntentBlocksHostRuntime(policy, fixture.runtime) != nil ||
				rejectManualHostUpgradeSoftwareClaimRecovery(fixture.runtime, policy) != nil {
				t.Fatal("valid settled history incorrectly blocks host lifecycle")
			}
			intent, _, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
			if err != nil {
				t.Fatal(err)
			}
			head := filepath.Join(agent.StateDir, softwareClaimRecoveryIntentName)
			archive := filepath.Join(agent.StateDir, softwareClaimRecoveryHistoryName, intent.PreviousSettledRawSHA256+".json")
			switch kind {
			case "head_absent":
				if err := os.Remove(head); err != nil {
					t.Fatal(err)
				}
			case "missing_link":
				if err := os.Remove(archive); err != nil {
					t.Fatal(err)
				}
			case "changed_raw":
				payload, err := os.ReadFile(archive)
				if err != nil || os.WriteFile(archive, append([]byte(" \n"), payload...), 0o600) != nil {
					t.Fatal("persist changed raw history fixture")
				}
			case "head_hardlink":
				if err := os.Link(head, filepath.Join(agent.StateDir, "head-hardlink")); err != nil {
					t.Fatal(err)
				}
			}
			if softwareClaimRecoveryIntentBlocksHostRuntime(policy, fixture.runtime) == nil ||
				rejectManualHostUpgradeSoftwareClaimRecovery(fixture.runtime, policy) == nil {
				t.Fatal("broken raw history bypassed the shared Stage/mutation or manual-upgrade gate")
			}
		})
	}
}

type softwareClaimRecoveryHistoryOwnerInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i softwareClaimRecoveryHistoryOwnerInfo) Sys() any { return &i.stat }

func TestSoftwareClaimRecoveryHistoryOwnerChecksServiceUIDGIDAndFileLinkCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-record")
	if err := os.WriteFile(path, []byte("record\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := *info.Sys().(*syscall.Stat_t)
	owner := func(candidate os.FileInfo) bool {
		value, ok := candidate.Sys().(*syscall.Stat_t)
		return ok && value.Uid == stat.Uid && value.Gid == stat.Gid
	}
	if !softwareClaimRecoveryRecordOwnerSafe(info, owner) {
		t.Fatal("exact service UID/GID single-link file was rejected")
	}
	wrongGroup := stat
	wrongGroup.Gid++
	linked := stat
	linked.Nlink = 2
	if softwareClaimRecoveryRecordOwnerSafe(softwareClaimRecoveryHistoryOwnerInfo{info, wrongGroup}, owner) ||
		softwareClaimRecoveryRecordOwnerSafe(softwareClaimRecoveryHistoryOwnerInfo{info, linked}, owner) ||
		!softwareClaimRecoveryDirectoryOwnerSafe(softwareClaimRecoveryHistoryOwnerInfo{info, linked}, owner) {
		t.Fatal("ownership boundary ignored service GID or confused directory/file link rules")
	}
}

func (i softwareClaimRecoveryHistoryRootInspector) InspectSoftwareClaimRecovery(ctx context.Context, inspection SoftwareClaimRecoveryInspection, fence LocalExecutorMutationFence) (SoftwareClaimRecoveryProof, error) {
	request := i.request
	request.SoftwareClaimRecovery = &inspection
	request.SourcePolicyRevision, request.OwnershipPolicyRevision = fence.SourcePolicyRevision, fence.OwnershipPolicyRevision
	request.ExecutorPolicyRevision, request.OwnershipEpoch = fence.ExecutorPolicyRevision, fence.OwnershipEpoch
	return inspectSoftwareClaimRecoveryRoot(ctx, i.policy, request, i.runtime)
}

func TestSoftwareClaimRecoveryHistoryRootPreflightKeepsPriorSettledAndNewPending(t *testing.T) {
	fixture, policy, local, runtime := newSoftwareClaimRecoveryRootHarness(t)
	agent, panel, _, executor, _ := newSoftwareClaimRecoveryHarness(t)
	authenticated, err := runtime.readPolicy(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	first := local.SoftwareClaimRecovery.Request
	agent.StateDir, panel.policy = fixture.runtime.paths.hostStateRoot, authenticated
	panel.job.ID, panel.job.HostID = first.JobID, policy.HostID
	panel.job.TargetID, panel.job.TargetType, panel.job.ServiceType = first.TargetID, policy.Targets[0].ServiceType, policy.Targets[0].ServiceType
	inspector := softwareClaimRecoveryHistoryRootInspector{policy: policy, request: local, runtime: runtime}
	agent.ClaimRecoveryInspector = inspector
	if err := agent.RecoverSoftwareClaim(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(agent.StateDir, softwareClaimRecoveryIntentName)
	oldBytes, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	second := prepareSoftwareClaimRecoveryHistorySuccessor(t, agent, panel, first)
	pendingBytes, err := os.ReadFile(agent.Journal.path)
	if err != nil {
		t.Fatal(err)
	}
	local.SoftwareClaimRecovery = &SoftwareClaimRecoveryInspection{Request: second, ExecutorPolicySHA256: authenticated.LocalExecutorPolicySHA256}
	proof, inspectErr := inspectSoftwareClaimRecoveryRoot(context.Background(), policy, local, runtime)
	afterMarker, markerErr := os.ReadFile(marker)
	afterJournal, journalErr := os.ReadFile(agent.Journal.path)
	if markerErr != nil || journalErr != nil || string(oldBytes) != string(afterMarker) || string(pendingBytes) != string(afterJournal) ||
		fixture.runner.stopCalls != 0 || len(fixture.runner.restartOrder) != 0 ||
		executor.stageCalls+executor.applyCalls+executor.reconcileCalls+executor.v2ApplyCalls+executor.v2ReconCalls != 0 {
		t.Fatal("read-only successor preflight changed settled history, pending bytes, services or software")
	}
	if inspectErr != nil {
		t.Fatalf("the fixed-path root proof rejects a different nonexecuting successor after settlement: %v", inspectErr)
	}
	if proof.Validate() != nil || !proof.NoMutation || proof.RequestSHA256 != second.sha256() {
		t.Fatal("root preflight lost the exact successor absence proof")
	}
}
