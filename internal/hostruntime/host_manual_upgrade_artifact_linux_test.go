//go:build linux

package hostruntime

import (
	"context"
	"strings"
	"testing"
)

func TestSameManualHostUpgradeArchiveContentAcceptsOnlineBindingIdentity(
	t *testing.T,
) {
	fixture := newManualHostUpgradeLinuxFixture(t)
	bound := fixture.targetRequest
	bound.Generation = "online-release-generation-42"
	bound.Release.ManifestAssetID = 101
	bound.Release.ManifestChecksumAssetID = 102
	bound.Release.ArchiveAssetID = 103
	bound.Release.ArchiveChecksumAssetID = 104
	if err := bound.validate(); err != nil {
		t.Fatalf("online-derived binding is invalid: %v", err)
	}
	digests, err := hostSelfUpdateArtifactBinaryDigests(fixture.artifactRoot)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewHostSelfUpdateState(
		manualHostUpgradeTestOldVersion,
		manualHostUpgradeTestOldVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := StageHostSelfUpdate(
		state, bound, HostLifecycleBlockers{}, digests,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.selfUpdate.stageSlot(
		context.Background(),
		HostSelfUpdateSlotB,
		fixture.artifactRoot,
		bound,
		digests,
	); err != nil {
		t.Fatalf("stage online-derived slot binding: %v", err)
	}
	if err := fixture.runtime.selfUpdate.saveState(staged); err != nil {
		t.Fatalf("persist online-derived staged state: %v", err)
	}
	if err := fixture.runtime.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		t.Fatalf("promote online-derived slot binding: %v", err)
	}
	if err := fixture.runtime.selfUpdate.switchCurrent(
		HostSelfUpdateSlotB,
	); err != nil {
		t.Fatalf("select online-derived bound slot: %v", err)
	}
	current, err := fixture.runtime.selfUpdate.readCurrentSlot()
	if err != nil || current != HostSelfUpdateSlotB {
		t.Fatalf("bound current slot=%q err=%v", current, err)
	}
	boundCurrent, _, err := readManualHostUpdateSlotBinding(
		current, fixture.runtime.selfUpdate,
	)
	if err != nil {
		t.Fatalf("read online-derived current binding: %v", err)
	}
	if !sameManualHostUpgradeArchiveContent(
		boundCurrent, fixture.targetRequest,
	) {
		t.Fatal("identical archive content was coupled to generation or asset IDs")
	}

	differentArchive := boundCurrent
	differentArchive.ArtifactSHA256 = "sha256:" + strings.Repeat("d", 64)
	differentArchive.Release.ArchiveSHA256 = strings.Repeat("d", 64)
	differentArchive.Release.ArchiveChecksumSHA256 = strings.Repeat("e", 64)
	if err := differentArchive.validate(); err != nil {
		t.Fatalf("coherent different-archive binding is invalid: %v", err)
	}
	if sameManualHostUpgradeArchiveContent(
		differentArchive, fixture.targetRequest,
	) {
		t.Fatal("different archive digest was accepted as identical content")
	}
}
