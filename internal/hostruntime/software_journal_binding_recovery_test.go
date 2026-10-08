package hostruntime

import (
	"reflect"
	"testing"
	"time"
)

func TestSoftwareJournalPreservesPendingReportsOnSameCursor(t *testing.T) {
	journal, _, job, plan := newSoftwareJournalBindingFixture(t)
	first, err := journal.Queue(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "claimed", "", "claim validated", 5, "", "")
	if err != nil {
		t.Fatal(err)
	}
	before := journal.Pending()
	if err := journal.SetActive(&job); err != nil {
		t.Fatalf("same cursor cannot continue: %v", err)
	}
	if !reflect.DeepEqual(before, journal.Pending()) {
		t.Fatal("same cursor silently changed its pending report")
	}
	second, err := journal.Queue(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "downloading", "", "release verification started", 20, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || second.Sequence != first.Sequence+1 {
		t.Fatalf("same cursor report sequence regressed: first=%d second=%d", first.Sequence, second.Sequence)
	}
	if actual := journal.ActivePlan(); !reflect.DeepEqual(actual, &plan) {
		t.Fatal("same cursor changed its immutable plan")
	}
}

func TestSoftwareJournalRejectsRecoveryRebindWithPendingReports(t *testing.T) {
	journal, _, job, _ := newSoftwareJournalBindingFixture(t)
	if _, err := journal.Queue(job.ID, job.AgentServiceID, "", job.LeaseGeneration, "claimed", "", "claim validated", 5, "", ""); err != nil {
		t.Fatal(err)
	}
	before := journal.Pending()
	recovery := job
	recovery.RecoveryRequired = true
	recovery.LeaseGeneration++
	recovery.CommandID = "command-software-recovery"
	recovery.LeaseExpiresAt = time.Date(2026, time.October, 8, 14, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if err := journal.SetActive(&recovery); err == nil {
		t.Fatal("fresh lease replaced a cursor before its pending report was acknowledged")
	}
	if !reflect.DeepEqual(before, journal.Pending()) || !reflect.DeepEqual(journal.Active(), &job) {
		t.Fatal("rejected recovery changed the pending report or its lease cursor")
	}
}
