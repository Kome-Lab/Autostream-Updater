package hostruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	softwareClaimRecoveryHistoryName     = "software-claim-recovery-history"
	softwareClaimRecoveryHistoryMaxFiles = 32
	softwareClaimRecoveryHistoryMaxBytes = 1 << 20
)

type softwareClaimRecoverySnapshot struct {
	Intent   softwareClaimRecoveryIntent
	Raw      []byte
	Archives map[string]softwareClaimRecoverySnapshot
}

func softwareClaimRecoveryRawSHA256(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func softwareClaimRecoveryRawDigestValid(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func readSoftwareClaimRecoveryRaw(path string, owner func(os.FileInfo) bool) (softwareClaimRecoverySnapshot, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return softwareClaimRecoverySnapshot{}, false, nil
	}
	if err != nil || owner == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		(snapshotModeEnforced() && info.Mode().Perm() != 0o600) || !softwareClaimRecoveryRecordOwnerSafe(info, owner) ||
		info.Size() <= 0 || info.Size() > softwareClaimRecoveryIntentMaxBytes {
		return softwareClaimRecoverySnapshot{}, false, errors.New("software claim recovery raw record is unsafe")
	}
	file, opened, err := openVerifiedConfig(path, info)
	if err != nil || !softwareClaimRecoveryRecordOwnerSafe(opened, owner) {
		if file != nil {
			_ = file.Close()
		}
		return softwareClaimRecoverySnapshot{}, false, errors.New("software claim recovery raw record changed during secure open")
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, softwareClaimRecoveryIntentMaxBytes+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || len(payload) == 0 || int64(len(payload)) != opened.Size() ||
		len(payload) > softwareClaimRecoveryIntentMaxBytes || !os.SameFile(opened, after) ||
		opened.Mode() != after.Mode() || !opened.ModTime().Equal(after.ModTime()) || !softwareClaimRecoveryRecordOwnerSafe(after, owner) {
		return softwareClaimRecoverySnapshot{}, false, errors.New("software claim recovery raw record changed during bounded read")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var intent softwareClaimRecoveryIntent
	if decoder.Decode(&intent) != nil || intent.validate() != nil {
		return softwareClaimRecoverySnapshot{}, false, errors.New("decode software claim recovery raw record")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return softwareClaimRecoverySnapshot{}, false, errors.New("software claim recovery raw record contains trailing data")
	}
	return softwareClaimRecoverySnapshot{Intent: intent, Raw: payload}, true, nil
}

func loadSoftwareClaimRecoverySnapshot(stateDir string, owner func(os.FileInfo) bool) (softwareClaimRecoverySnapshot, bool, error) {
	head, exists, err := readSoftwareClaimRecoveryRaw(filepath.Join(stateDir, softwareClaimRecoveryIntentName), owner)
	if err != nil {
		return softwareClaimRecoverySnapshot{}, false, err
	}
	archives, err := readSoftwareClaimRecoveryArchives(stateDir, owner)
	if err != nil || !exists && archives != nil {
		return softwareClaimRecoverySnapshot{}, false, errors.New("software claim recovery history has no safe current record")
	}
	if !exists {
		return head, false, nil
	}
	head.Archives = archives
	if err := validateSoftwareClaimRecoveryHistory(head.Intent, archives); err != nil {
		return softwareClaimRecoverySnapshot{}, false, err
	}
	return head, true, nil
}

func readSoftwareClaimRecoveryArchives(stateDir string, owner func(os.FileInfo) bool) (map[string]softwareClaimRecoverySnapshot, error) {
	path := filepath.Join(stateDir, softwareClaimRecoveryHistoryName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || owner == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !softwareClaimRecoveryDirectoryOwnerSafe(info, owner) ||
		(snapshotModeEnforced() && info.Mode().Perm() != 0o700) {
		return nil, errors.New("software claim recovery history directory is unsafe")
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open software claim recovery history directory")
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Mode() != info.Mode() || !softwareClaimRecoveryDirectoryOwnerSafe(opened, owner) {
		return nil, errors.New("software claim recovery history directory changed during secure open")
	}
	entries, err := directory.ReadDir(softwareClaimRecoveryHistoryMaxFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > softwareClaimRecoveryHistoryMaxFiles {
		return nil, errors.New("software claim recovery history exceeds the fixed entry bound")
	}
	archives := make(map[string]softwareClaimRecoverySnapshot, len(entries))
	total := 0
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".json")
		if entry.Name() != name+".json" || !softwareClaimRecoveryRawDigestValid(name) || entry.IsDir() {
			return nil, errors.New("software claim recovery history contains an unknown entry")
		}
		archive, exists, err := readSoftwareClaimRecoveryRaw(filepath.Join(path, entry.Name()), owner)
		if err != nil || !exists || softwareClaimRecoveryRawSHA256(archive.Raw) != name ||
			archive.Intent.SchemaVersion != 2 || !archive.Intent.Settled || archive.Intent.TerminalClear == nil {
			return nil, errors.New("software claim recovery raw archive is invalid")
		}
		total += len(archive.Raw)
		if total > softwareClaimRecoveryHistoryMaxBytes {
			return nil, errors.New("software claim recovery history exceeds the fixed byte bound")
		}
		archives[name] = archive
	}
	return archives, nil
}

func sameSoftwareClaimRecoveryAuthority(a, b softwareClaimRecoveryIntent) bool {
	return a.UpdaterID == b.UpdaterID && a.HostID == b.HostID && a.Original.OwnershipEpoch == b.Original.OwnershipEpoch &&
		a.SourcePolicyRevision == b.SourcePolicyRevision && a.ProjectionRevision == b.ProjectionRevision &&
		a.ExecutorPolicyRevision == b.ExecutorPolicyRevision && a.ExecutorPolicySHA256 == b.ExecutorPolicySHA256
}

func validateSoftwareClaimRecoveryHistory(head softwareClaimRecoveryIntent, archives map[string]softwareClaimRecoverySnapshot) error {
	for _, start := range append([]softwareClaimRecoveryIntent{head}, softwareClaimRecoveryArchiveIntents(archives)...) {
		if !sameSoftwareClaimRecoveryAuthority(head, start) {
			return errors.New("software claim recovery immutable archive authority differs from current history")
		}
		seen := map[string]bool{start.Original.JobID: true}
		cursor := start
		for count := 0; cursor.PreviousSettledRawSHA256 != ""; count++ {
			archive, exists := archives[cursor.PreviousSettledRawSHA256]
			if !exists || count >= softwareClaimRecoveryHistoryMaxFiles || !sameSoftwareClaimRecoveryAuthority(start, archive.Intent) ||
				seen[archive.Intent.Original.JobID] || !archive.Intent.Settled || archive.Intent.SchemaVersion != 2 || archive.Intent.TerminalClear == nil {
				return errors.New("software claim recovery immutable history link is invalid")
			}
			seen[archive.Intent.Original.JobID] = true
			cursor = archive.Intent
		}
	}
	return nil
}

func softwareClaimRecoveryArchiveIntents(archives map[string]softwareClaimRecoverySnapshot) []softwareClaimRecoveryIntent {
	intents := make([]softwareClaimRecoveryIntent, 0, len(archives))
	for _, archive := range archives {
		intents = append(intents, archive.Intent)
	}
	return intents
}
