package hostruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	manualHostUpgradeBindingVersion       = "manual-v1"
	manualHostUpgradeAgentProtocolVersion = 2
)

// ManualHostUpgradeRequest carries only the provenance already verified by the
// archive installer. Identity, policy, and credentials never cross argv.
type ManualHostUpgradeRequest struct {
	ArtifactRoot            string
	ArchiveSHA256           string
	ArchiveSize             int64
	AgentStoppedForRecovery bool
}

type ManualHostUpgradeResult struct {
	PreviousSlot   string
	ActiveSlot     string
	Version        string
	AlreadyCurrent bool
}

// manualHostUpgradeArtifact is the credential-free identity extracted from
// the archive's checksummed artifact-manifest.json. The installer has already
// verified the archive; the root helper reads and verifies these values again
// while it holds the lifecycle locks.
type manualHostUpgradeArtifact struct {
	Version         string
	Commit          string
	BuildDate       time.Time
	Arch            string
	MinimumPanel    string
	ManifestSHA256  string
	ChecksumsSHA256 string
}

func (a manualHostUpgradeArtifact) validate() error {
	if !versionPattern.MatchString(a.Version) ||
		!updaterReleaseCommitPattern.MatchString(a.Commit) ||
		a.BuildDate.IsZero() || a.BuildDate.Location() != time.UTC ||
		(a.Arch != "amd64" && a.Arch != "arm64") ||
		!versionPattern.MatchString(a.MinimumPanel) ||
		!isCanonicalBareSHA256(a.ManifestSHA256) ||
		!isCanonicalBareSHA256(a.ChecksumsSHA256) {
		return errors.New("manual Host runtime artifact identity is invalid")
	}
	return nil
}

// newManualHostSelfUpdateRequest encodes an offline archive binding into the
// existing schema-v2 release envelope. The four high-range IDs are an opaque,
// deterministic manual namespace, not GitHub asset IDs. Keeping every field
// in the old envelope lets the healthy slot's older recovery binary validate
// and roll back an interrupted manual activation without a schema migration.
func newManualHostSelfUpdateRequest(
	artifact manualHostUpgradeArtifact,
	input ManualHostUpgradeRequest,
) (HostSelfUpdateRequest, error) {
	if err := artifact.validate(); err != nil {
		return HostSelfUpdateRequest{}, err
	}
	archiveSHA256 := strings.TrimSpace(input.ArchiveSHA256)
	if !isCanonicalBareSHA256(archiveSHA256) || input.ArchiveSize < 1 ||
		input.ArchiveSize > defaultMaxArtifactBytes {
		return HostSelfUpdateRequest{}, errors.New(
			"manual Host runtime archive identity is invalid",
		)
	}
	archiveName := hostAgentReleaseAssetName(artifact.Version, artifact.Arch)
	archiveChecksum := sha256.Sum256([]byte(
		archiveSHA256 + "  " + archiveName + "\n",
	))
	release := HostSelfUpdateReleaseIdentity{
		Tag:                     artifact.Version,
		Commit:                  artifact.Commit,
		PublishedAt:             artifact.BuildDate,
		ManifestAssetName:       hostAgentManifestName,
		ManifestSHA256:          artifact.ManifestSHA256,
		ManifestChecksumSHA256:  artifact.ChecksumsSHA256,
		ArchiveAssetName:        archiveName,
		ArchiveSize:             input.ArchiveSize,
		ArchiveSHA256:           archiveSHA256,
		ArchiveChecksumSHA256:   hex.EncodeToString(archiveChecksum[:]),
		Arch:                    artifact.Arch,
		AgentProtocolVersion:    manualHostUpgradeAgentProtocolVersion,
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		MutationProtocolVersion: LocalExecutorMutationProtocolVersion,
		RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
		MinimumPanelVersion:     artifact.MinimumPanel,
	}
	identitySeed, err := json.Marshal(struct {
		Namespace string                        `json:"namespace"`
		Release   HostSelfUpdateReleaseIdentity `json:"release"`
	}{
		Namespace: manualHostUpgradeBindingVersion,
		Release:   release,
	})
	if err != nil {
		return HostSelfUpdateRequest{}, errors.New(
			"encode manual Host runtime release binding",
		)
	}
	seed := sha256.Sum256(identitySeed)
	base := binary.BigEndian.Uint64(seed[:8]) & ((uint64(1) << 60) - 1)
	manualID := func(index uint64) int64 {
		return int64((uint64(1) << 62) | (base << 2) | index)
	}
	release.ManifestAssetID = manualID(0)
	release.ManifestChecksumAssetID = manualID(1)
	release.ArchiveAssetID = manualID(2)
	release.ArchiveChecksumAssetID = manualID(3)
	var attemptNonce [16]byte
	if _, err := rand.Read(attemptNonce[:]); err != nil {
		return HostSelfUpdateRequest{}, errors.New(
			"generate manual Host runtime attempt identity",
		)
	}
	request := HostSelfUpdateRequest{
		Generation: manualHostUpgradeBindingVersion + "-" +
			hex.EncodeToString(seed[:6]) + "-" +
			hex.EncodeToString(attemptNonce[:]),
		AgentVersion:            artifact.Version,
		ExecutorVersion:         artifact.Version,
		Commit:                  artifact.Commit,
		ArtifactSHA256:          "sha256:" + archiveSHA256,
		AgentProtocolVersion:    manualHostUpgradeAgentProtocolVersion,
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		MutationProtocolVersion: LocalExecutorMutationProtocolVersion,
		RecoveryProtocolVersion: HostSelfUpdateRecoveryProtocolVersion,
		Release:                 release,
	}
	if err := request.validate(); err != nil {
		return HostSelfUpdateRequest{}, err
	}
	return request, nil
}

func UpgradeHostRuntimeFromVerifiedBundle(
	ctx context.Context,
	request ManualHostUpgradeRequest,
) (ManualHostUpgradeResult, error) {
	return upgradeHostRuntimeFromVerifiedBundle(ctx, request)
}

// InspectHostUpdateRecovery reports whether the protected Host Agent journal
// contains an interrupted job that must be reconciled before a manual runtime
// upgrade. The platform implementation performs a read-only, root-owned
// inspection; it never clears the journal or any Local Executor ledger.
func InspectHostUpdateRecovery() (bool, error) {
	return inspectHostUpdateRecovery()
}
