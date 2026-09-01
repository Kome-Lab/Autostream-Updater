package hostruntime

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestManualHostUpgradeContentBindingIsDeterministicAndSchemaV2Compatible(
	t *testing.T,
) {
	t.Parallel()
	artifact := manualHostUpgradeArtifact{
		Version:         "v9.9.9",
		Commit:          strings.Repeat("a", 40),
		BuildDate:       time.Date(2026, 8, 2, 1, 2, 3, 0, time.UTC),
		Arch:            "amd64",
		MinimumPanel:    "v9.9.9",
		ManifestSHA256:  strings.Repeat("b", 64),
		ChecksumsSHA256: strings.Repeat("c", 64),
	}
	request := ManualHostUpgradeRequest{
		ArchiveSHA256: strings.Repeat("d", 64),
		ArchiveSize:   12345,
	}

	first, err := newManualHostSelfUpdateRequest(artifact, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newManualHostSelfUpdateRequest(artifact, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Generation == second.Generation {
		t.Fatal("separate manual upgrade attempts reused one generation")
	}
	second.Generation = first.Generation
	if first != second {
		t.Fatalf("manual content binding is not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if err := first.validate(); err != nil {
		t.Fatalf("manual binding does not satisfy schema v2 request validation: %v", err)
	}
	ids := []int64{
		first.Release.ManifestAssetID,
		first.Release.ManifestChecksumAssetID,
		first.Release.ArchiveAssetID,
		first.Release.ArchiveChecksumAssetID,
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if id < 1<<62 || id < 1 || seen[id] {
			t.Fatalf("manual compatibility ID is not positive, reserved, and unique: %v", ids)
		}
		seen[id] = true
	}
	state, err := NewHostSelfUpdateState("v9.9.8", "v9.9.8")
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageHostSelfUpdate(
		state,
		first,
		HostLifecycleBlockers{},
		hostSelfUpdateSlotDigests{
			AgentSHA256:    strings.Repeat("e", 64),
			ExecutorSHA256: strings.Repeat("f", 64),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(staged)
	if err != nil {
		t.Fatal(err)
	}
	var recovered HostSelfUpdateState
	if err := json.Unmarshal(payload, &recovered); err != nil {
		t.Fatal(err)
	}
	if err := recovered.validate(); err != nil {
		t.Fatalf("schema v2 recovery rejected the manual pending state: %v", err)
	}

	changed := request
	changed.ArchiveSHA256 = strings.Repeat("1", 64)
	different, err := newManualHostSelfUpdateRequest(artifact, changed)
	if err != nil {
		t.Fatal(err)
	}
	if different.Generation == first.Generation ||
		different.Release.ManifestAssetID == first.Release.ManifestAssetID {
		t.Fatal("manual compatibility binding did not change with the archive digest")
	}
}
