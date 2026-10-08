package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type softwareClaimRecoveryHistoryTestPanel struct {
	*softwareClaimRecoveryTestPanel
	grantCalls int
}

func (p *softwareClaimRecoveryHistoryTestPanel) IssueMutationGrant(context.Context, string, MutationGrantRequest) (MutationGrant, error) {
	p.grantCalls++
	return MutationGrant{}, errors.New("history recovery must not issue a grant")
}

type softwareClaimRecoveryHistoryTestDownloader struct{ calls int }

func (d *softwareClaimRecoveryHistoryTestDownloader) Download(context.Context, string, string, string, string) (DownloadedArtifact, error) {
	d.calls++
	return DownloadedArtifact{}, errors.New("history recovery must not download")
}

func (d *softwareClaimRecoveryHistoryTestDownloader) ResolveDockerReleaseForArch(context.Context, string, string, string, string, string, string) (ResolvedDockerRelease, error) {
	d.calls++
	return ResolvedDockerRelease{}, errors.New("history recovery must not resolve an artifact")
}

type softwareClaimRecoveryHistoryTestInspector struct {
	base     *softwareClaimRecoveryTestInspector
	stateDir string
	alter    func(*SoftwareClaimRecoveryProof, int)
}

func (i *softwareClaimRecoveryHistoryTestInspector) InspectSoftwareClaimRecovery(ctx context.Context, inspection SoftwareClaimRecoveryInspection, fence LocalExecutorMutationFence) (SoftwareClaimRecoveryProof, error) {
	proof, err := i.base.InspectSoftwareClaimRecovery(ctx, inspection, fence)
	if err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	snapshot, exists, err := loadSoftwareClaimRecoverySnapshot(i.stateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	if exists {
		proof.PriorSettledRawSHA256 = snapshot.Intent.PreviousSettledRawSHA256
		if !snapshot.Intent.Original.sameIntent(inspection.Request) {
			proof.PriorSettledRawSHA256 = softwareClaimRecoveryRawSHA256(snapshot.Raw)
		}
	}
	if i.alter != nil {
		i.alter(&proof, i.base.calls)
	}
	return proof, nil
}

// The successor is produced through the existing journal and binding APIs on
// the original host state directory. It is the exact first progress ACK-loss
// cursor, not a fixture that deletes the previous recovery intent.
func prepareSoftwareClaimRecoveryHistorySuccessor(t *testing.T, agent *HostPullAgent, panel *softwareClaimRecoveryTestPanel, original SoftwareClaimRecoveryRequest, jobIDs ...string) SoftwareClaimRecoveryRequest {
	t.Helper()
	request := original
	request.JobID = "orphan-job-two"
	if len(jobIDs) != 0 {
		request.JobID = jobIDs[0]
	}
	panel.job.ID, panel.generation, panel.terminal = request.JobID, 1, false
	journal, err := OpenJournal(agent.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	job := cloneV2PanelJob(panel.job)
	job.LeaseGeneration, job.ReportSequence, job.CommandID, job.Status = 1, 1, "successor-claimed-command", "claimed"
	job.LeaseExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	binding := HostAgentBinding{ServiceID: agent.Bootstrap.NodeID, ServiceType: ServiceTypeUpdateAgent,
		TransportMode: HostTransportPullV2, ExecutionHostID: panel.policy.ExecutionHostID, OwnershipEpoch: request.OwnershipEpoch}
	if err := agent.bindSoftwareClaim(panel, binding, panel.policy, nil, &job); err != nil {
		t.Fatal(err)
	}
	if err := journal.SetActive(&job); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Queue(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "claimed", "",
		"update job claimed and fixed target validated", 5, "", ""); err != nil {
		t.Fatal(err)
	}
	agent.Journal = journal
	return request
}

func TestSoftwareClaimRecoveryHistoryAllowsDistinctSuccessorWithFirstProgressPending(t *testing.T) {
	agent, panel, inspector, executor, first := newSoftwareClaimRecoveryHarness(t)
	countedPanel := &softwareClaimRecoveryHistoryTestPanel{softwareClaimRecoveryTestPanel: panel}
	downloader := &softwareClaimRecoveryHistoryTestDownloader{}
	agent.ControlPlane, agent.Downloader = countedPanel, downloader
	agent.ClaimRecoveryInspector = &softwareClaimRecoveryHistoryTestInspector{base: inspector, stateDir: agent.StateDir}
	if err := agent.RecoverSoftwareClaim(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	old, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || !old.Settled || old.Original != first || len(old.Attempts) != 1 ||
		agent.Journal.Active() != nil || len(agent.Journal.Pending()) != 0 {
		t.Fatal("first recovery did not settle on its original host state directory")
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
	data, err := readSoftwareClaimRecoveryJournal(agent.StateDir)
	if err != nil || data.ActiveJob == nil || data.ActiveJob.ID != second.JobID || len(data.Pending) != 1 ||
		!softwareClaimRecoveryPendingAllowed(data) {
		t.Fatal("successor fixture is not the exact nonexecuting first-progress cursor")
	}
	claimsBefore, reportsBefore := len(panel.claims), len(panel.reports)
	err = agent.RecoverSoftwareClaim(context.Background(), second)
	if executor.stageCalls+executor.applyCalls+executor.reconcileCalls+executor.v2ApplyCalls+executor.v2ReconCalls+
		countedPanel.grantCalls+downloader.calls != 0 {
		t.Fatal("consecutive terminal-only recovery mutated or downloaded software")
	}
	if err != nil {
		afterMarker, markerErr := os.ReadFile(marker)
		afterJournal, journalErr := os.ReadFile(agent.Journal.path)
		if markerErr != nil || journalErr != nil || string(afterMarker) != string(oldBytes) ||
			string(afterJournal) != string(pendingBytes) || len(agent.Journal.Pending()) != 1 ||
			len(panel.claims) != claimsBefore || len(panel.reports) != reportsBefore {
			t.Fatal("refused successor changed the previous settled bytes or new pending cursor")
		}
		t.Fatalf("a settled prior recovery blocks the next exact orphan on the same host: %v", err)
	}
	digest := sha256.Sum256(oldBytes)
	archive := filepath.Join(agent.StateDir, "software-claim-recovery-history", hex.EncodeToString(digest[:])+".json")
	archivedBytes, err := os.ReadFile(archive)
	if err != nil || string(archivedBytes) != string(oldBytes) {
		t.Fatal("the previous settled original bytes were not preserved in immutable history")
	}
	settled, exists, err := loadSoftwareClaimRecoveryIntent(agent.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || !settled.Settled || settled.Original != second || len(settled.Attempts) != 1 ||
		agent.Journal.Active() != nil || len(agent.Journal.Pending()) != 0 ||
		len(panel.claims) != claimsBefore+2 || len(panel.reports) != reportsBefore+1 {
		t.Fatal("successor recovery did not settle independently while retaining prior history")
	}
}
