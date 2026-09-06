package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

func largePortAgentJournal(t *testing.T) (string, *Journal) {
	t.Helper()
	_, job, policy, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalOnly, false)
	other := policy.Targets[0]
	other.ServiceID = "worker-side"
	other.AppliedEndpoint = &HostAgentEndpoint{Host: "worker-side.example.test", Port: 443, SSLEnabled: true, PublicURL: "https://worker-side.example.test/" + strings.Repeat("x", 180<<10)}
	desired := *other.AppliedEndpoint
	other.DesiredEndpoint = &desired
	policy.Targets = append(policy.Targets, other)
	dir := t.TempDir()
	journal, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{journal.SetActive(&job), journal.SetActivePortPlan(plan), journal.StagePortPolicy(policy, job, plan)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "journal.json"))
	if err != nil || len(data) <= journalActiveClearMarkerMaxSize || len(data) >= journalPortActiveClearMarkerMaxSize {
		t.Fatal("fixture does not cross the original marker limit")
	}
	return dir, journal
}

func TestSTPortAgentLargeJournalClearFenceSurvivesRestart(t *testing.T) {
	dir, journal := largePortAgentJournal(t)
	original := journal.Active()
	fault := errors.New("injected marker sync interruption")
	journal.syncDir = func(string) error { return fault }
	if err := journal.ClearActive(); !errors.Is(err, fault) {
		t.Fatalf("clear fault: %v", err)
	}
	markerPath := filepath.Join(dir, journalActiveClearMarkerName)
	marker, err := os.ReadFile(markerPath)
	if err != nil || len(marker) <= journalActiveClearMarkerMaxSize {
		t.Fatal("large clear marker was not written")
	}
	reopened, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Active() == nil || reopened.Active().ID != original.ID {
		t.Fatal("restart lost the active cursor")
	}
	if _, err := reopened.portPolicyCandidate(""); err != nil {
		t.Fatal("restart lost bounded candidates")
	}
	if err := reopened.ClearActive(); err != nil {
		t.Fatal(err)
	}
	final, err := OpenJournal(dir)
	if err != nil || final.Active() != nil {
		t.Fatal("clear did not persist")
	}
}

func TestSTPortAgentLargeJournalCorruptionFailsClosed(t *testing.T) {
	dir, journal := largePortAgentJournal(t)
	journal.syncDir = func(string) error { return errors.New("interrupted") }
	if journal.ClearActive() == nil {
		t.Fatal("fault was not injected")
	}
	mainPath := filepath.Join(dir, "journal.json")
	before, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(dir, journalActiveClearMarkerName)
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var marker journalActiveClearMarker
	if json.Unmarshal(data, &marker) != nil {
		t.Fatal("invalid fixture")
	}
	marker.PreviousSHA256 = "sha256:" + strings.Repeat("9", 64)
	corrupt, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil {
		t.Fatal("corrupted large marker was accepted")
	}
	after, err := os.ReadFile(mainPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("corruption changed the durable cursor")
	}
}

func TestSTPortAgentJournalBoundsDoNotRelaxOtherPayloads(t *testing.T) {
	t.Run("candidate", func(t *testing.T) {
		_, job, policy, plan := agentPortV2Fixture(t, contracts.SystemUpdatePortModeLocalOnly, false)
		other := policy.Targets[0]
		other.ServiceID = "worker-side"
		other.AppliedEndpoint = &HostAgentEndpoint{Host: "worker-side.example.test", Port: 443, SSLEnabled: true, PublicURL: "https://worker-side.example.test/" + strings.Repeat("x", hostAgentPolicyResponseMaxBytes)}
		policy.Targets = append(policy.Targets, other)
		journal, err := OpenJournal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := journal.SetActive(&job); err != nil {
			t.Fatal(err)
		}
		if err := journal.SetActivePortPlan(plan); err != nil {
			t.Fatal(err)
		}
		if err := journal.StagePortPolicy(policy, job, plan); err == nil {
			t.Fatal("oversized candidate accepted")
		}
	})
	t.Run("legacy marker", func(t *testing.T) {
		dir, journal, _ := newJournalWithActivePlan(t)
		journal.syncDir = func(string) error { return errors.New("interrupted") }
		if journal.ClearActive() == nil {
			t.Fatal("fault was not injected")
		}
		path := filepath.Join(dir, journalActiveClearMarkerName)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, bytes.Repeat([]byte(" "), journalActiveClearMarkerMaxSize-len(data)+1)...)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenJournal(dir); err == nil {
			t.Fatal("legacy marker limit was enlarged")
		}
	})
	t.Run("existing metadata", func(t *testing.T) {
		_, journal := largePortAgentJournal(t)
		if err := journal.MarkDeployed("worker-side", strings.Repeat("x", journalActiveClearMarkerMaxSize)); err != nil {
			t.Fatal(err)
		}
		if err := journal.ClearActive(); err == nil {
			t.Fatal("existing metadata used candidate-only capacity")
		}
	})
}
