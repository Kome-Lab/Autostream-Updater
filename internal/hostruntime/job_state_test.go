package hostruntime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJobDirectorySurvivesPendingTerminalUntilCleanupAndActiveClear(t *testing.T) {
	stateDir := t.TempDir()
	journal, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	job := &UpdateJob{ID: "job-cleanup", ReportSequence: 1}
	if err := journal.SetActive(job); err != nil {
		t.Fatal(err)
	}
	dir, err := ensurePrivateJobDirectory(stateDir, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(dir, "plan.json")
	if err := writePrivateJSON(planPath, ApplyPlan{JobID: job.ID, LeaseToken: "lease-secret"}); err != nil {
		t.Fatal(err)
	}
	report, err := journal.Queue(job.ID, "updater", "lease-secret", 1, "succeeded", "", "", 100, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := garbageCollectJobDirectories(stateDir, journal); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(planPath); err != nil {
		t.Fatalf("pending terminal response lost its recovery plan: %v", err)
	}
	if err := journal.Ack(job.ID, report.Sequence); err != nil {
		t.Fatal(err)
	}
	if journal.Active() == nil {
		t.Fatal("terminal report cursor ACK cleared active state before job cleanup")
	}
	if err := cleanupJobDirectory(stateDir, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := journal.ClearActive(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash after cleanup and the durable active-cursor clear.
	reopened, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Active() != nil || len(reopened.Pending()) != 0 {
		t.Fatal("terminal cleanup and active-cursor clear were not durable")
	}
	if err := garbageCollectJobDirectories(stateDir, reopened); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("orphaned lease-bearing job directory remained: %v", err)
	}
}

func TestGarbageCollectorDoesNotFollowJobSymlink(t *testing.T) {
	stateDir := t.TempDir()
	journal, err := OpenJournal(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	root := jobsRoot(stateDir)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "keep")
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(external, "marker")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, shortID("orphan-job"))
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := garbageCollectJobDirectories(stateDir, journal); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("garbage collection followed the symlink: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("orphan symlink remained: %v", err)
	}
}
