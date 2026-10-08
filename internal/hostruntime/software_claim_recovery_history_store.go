package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type softwareClaimRecoveryHistoryStoreRuntime struct {
	syncFile     func(*os.File) error
	syncDir      func(string) error
	writeCurrent func(string, []byte, os.FileMode) error
}

func defaultSoftwareClaimRecoveryHistoryStoreRuntime() softwareClaimRecoveryHistoryStoreRuntime {
	return softwareClaimRecoveryHistoryStoreRuntime{
		syncFile: func(file *os.File) error { return file.Sync() }, syncDir: syncDirectory, writeCurrent: writeAtomicFile,
	}
}

// This is the only cross-job transition. The old bytes remain the current head
// until their exclusive immutable archive and both containing directories are
// durable. Same-job saves cannot replace a settled record.
func transitionSoftwareClaimRecoveryIntent(stateDir, previousRawSHA256 string, next softwareClaimRecoveryIntent,
	proof SoftwareClaimRecoveryProof, runtime softwareClaimRecoveryHistoryStoreRuntime) error {
	if validateManagedDirectoryChain(stateDir) != nil || !softwareClaimRecoveryRawDigestValid(previousRawSHA256) ||
		runtime.syncFile == nil || runtime.syncDir == nil || runtime.writeCurrent == nil ||
		next.SchemaVersion != 2 || next.validate() != nil || next.Settled || next.TerminalClear != nil || len(next.Attempts) != 1 ||
		next.PreviousSettledRawSHA256 != previousRawSHA256 || !softwareClaimRecoveryProofMatchesIntent(proof, next) {
		return errors.New("software claim recovery history transition lacks an exact root proof")
	}
	old, exists, err := loadSoftwareClaimRecoverySnapshot(stateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || softwareClaimRecoveryRawSHA256(old.Raw) != previousRawSHA256 ||
		old.Intent.SchemaVersion != 2 || !old.Intent.Settled || old.Intent.TerminalClear == nil ||
		old.Intent.Original.JobID == next.Original.JobID || !sameSoftwareClaimRecoveryAuthority(old.Intent, next) {
		return errors.New("software claim recovery raw head compare-and-swap failed")
	}
	for _, archive := range old.Archives {
		if archive.Intent.Original.JobID == next.Original.JobID {
			return errors.New("software claim recovery cannot reuse a historical job identity")
		}
	}
	if err := preserveSoftwareClaimRecoveryRawArchive(stateDir, old, runtime); err != nil {
		return err
	}
	current, exists, err := loadSoftwareClaimRecoverySnapshot(stateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || softwareClaimRecoveryRawSHA256(current.Raw) != previousRawSHA256 || !bytes.Equal(current.Raw, old.Raw) {
		return errors.New("software claim recovery raw head changed after durable archive; no claim was sent")
	}
	if validateSoftwareClaimRecoveryHistory(next, current.Archives) != nil {
		return errors.New("software claim recovery new head has incomplete immutable history")
	}
	payload, err := json.Marshal(next)
	if err != nil || len(payload)+1 > softwareClaimRecoveryIntentMaxBytes {
		return errors.New("encode software claim recovery history head")
	}
	if runtime.writeCurrent(filepath.Join(stateDir, softwareClaimRecoveryIntentName), append(payload, '\n'), 0o600) != nil {
		return errors.New("persist software claim recovery history head; outcome remains uncertain and no claim was sent")
	}
	return nil
}

func preserveSoftwareClaimRecoveryRawArchive(stateDir string, old softwareClaimRecoverySnapshot, runtime softwareClaimRecoveryHistoryStoreRuntime) error {
	digest := softwareClaimRecoveryRawSHA256(old.Raw)
	if existing, exists := old.Archives[digest]; exists && !bytes.Equal(existing.Raw, old.Raw) {
		return errors.New("software claim recovery immutable archive differs from the current original")
	}
	if _, exists := old.Archives[digest]; !exists {
		total := len(old.Raw)
		for _, archive := range old.Archives {
			total += len(archive.Raw)
		}
		if len(old.Archives) >= softwareClaimRecoveryHistoryMaxFiles || total > softwareClaimRecoveryHistoryMaxBytes {
			return errors.New("software claim recovery immutable archive capacity is exhausted")
		}
	}
	directory := filepath.Join(stateDir, softwareClaimRecoveryHistoryName)
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("create software claim recovery history directory")
	}
	if validateManagedDirectoryChain(directory) != nil {
		return errors.New("software claim recovery history parent is unsafe")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || !softwareClaimRecoveryDirectoryOwnerSafe(info, managedSnapshotOwnedByCurrentUser) ||
		(snapshotModeEnforced() && info.Mode().Perm() != 0o700) {
		return errors.New("software claim recovery history directory is unsafe")
	}
	path := filepath.Join(directory, digest+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		// A crash after archive sync but before current-head CAS is retryable
		// only when the already existing raw file is exactly the same record.
		archive, exists, readErr := readSoftwareClaimRecoveryRaw(path, managedSnapshotOwnedByCurrentUser)
		if readErr != nil || !exists || softwareClaimRecoveryRawSHA256(archive.Raw) != digest || !bytes.Equal(archive.Raw, old.Raw) {
			return errors.New("software claim recovery existing raw archive is unsafe or different")
		}
		file, err = openSoftwareClaimRecoveryArchiveForSync(path)
	} else if err == nil {
		if _, err = file.Write(old.Raw); err != nil {
			_ = file.Close()
			return errors.New("write software claim recovery immutable archive")
		}
	}
	if err != nil || file == nil {
		return errors.New("open software claim recovery immutable archive")
	}
	syncErr, closeErr := runtime.syncFile(file), file.Close()
	if syncErr != nil || closeErr != nil || runtime.syncDir(directory) != nil || runtime.syncDir(stateDir) != nil {
		return errors.New("persist software claim recovery immutable archive; current original remains")
	}
	return nil
}

func openSoftwareClaimRecoveryArchiveForSync(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !softwareClaimRecoveryRecordOwnerSafe(info, managedSnapshotOwnedByCurrentUser) ||
		(snapshotModeEnforced() && info.Mode().Perm() != 0o600) {
		return nil, errors.New("software claim recovery reused archive is unsafe")
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || info.Mode() != opened.Mode() ||
		info.Size() != opened.Size() || !info.ModTime().Equal(opened.ModTime()) || !softwareClaimRecoveryRecordOwnerSafe(opened, managedSnapshotOwnedByCurrentUser) {
		_ = file.Close()
		return nil, errors.New("software claim recovery reused archive changed during secure sync open")
	}
	return file, nil
}
