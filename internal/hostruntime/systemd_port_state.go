package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const (
	systemdPortLedgerMaxBytes         = 128 << 10
	systemdPortAppliedSidecarMaxBytes = 64 << 10
)

type systemdPortAppliedStateReader interface {
	LoadApplied(string) (*systemdPortAppliedState, error)
}

type systemdPortAppliedSidecarVerifier interface {
	VerifyAppliedSidecar(LocalExecutorTarget, systemdPortAppliedState) error
}

type fileSystemdPortStateStore struct {
	stateDir               string
	requireRootOwned       bool
	sidecarPathForTestOnly string
}

func newFileSystemdPortStateStore(stateDir string, requireRootOwned bool) (*fileSystemdPortStateStore, error) {
	store := &fileSystemdPortStateStore{
		stateDir: filepath.Clean(stateDir), requireRootOwned: requireRootOwned,
	}
	if !filepath.IsAbs(store.stateDir) ||
		store.stateDir == string(filepath.Separator) {
		return nil, errors.New("systemd port state directory is invalid")
	}
	if err := store.ensureDirectory(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *fileSystemdPortStateStore) directory() string {
	return filepath.Join(s.stateDir, "port-ledger")
}

func (s *fileSystemdPortStateStore) jobPath(targetID, jobID string) string {
	return filepath.Join(s.directory(), "jobs", remoteStableKey(targetID, jobID)+".json")
}

func (s *fileSystemdPortStateStore) activePath(targetID string) string {
	return filepath.Join(s.directory(), "active", remoteStableKey(targetID)+".json")
}

func (s *fileSystemdPortStateStore) appliedPath(targetID string) string {
	return filepath.Join(s.directory(), "applied", remoteStableKey(targetID)+".json")
}

func (s *fileSystemdPortStateStore) ensureDirectory() error {
	for _, directory := range []string{
		s.stateDir, s.directory(), filepath.Join(s.directory(), "jobs"),
		filepath.Join(s.directory(), "active"), filepath.Join(s.directory(), "applied"),
	} {
		if err := s.ensureOneDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func (s *fileSystemdPortStateStore) ensureOneDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(directory)
		parentInfo, parentErr := os.Lstat(parent)
		if parentErr != nil ||
			systemdPortLinkOrReparse(parentInfo) ||
			!parentInfo.IsDir() {
			return errors.New("systemd port state parent directory is invalid")
		}
		if s.requireRootOwned && validateSecureRootPath(parent, true) != nil {
			return errors.New("systemd port state parent directory is not root-controlled")
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			return errors.New("create systemd port state directory")
		}
		info, err = os.Lstat(directory)
	}
	if err != nil ||
		systemdPortLinkOrReparse(info) ||
		!info.IsDir() {
		return errors.New("systemd port state directory is invalid")
	}
	// Never chmod before the non-link/reparse check above. An existing link
	// would otherwise cause chmod to alter its target rather than fail closed.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		if err := os.Chmod(directory, 0o700); err != nil {
			return errors.New("secure systemd port state directory")
		}
		secured, statErr := os.Lstat(directory)
		if statErr != nil ||
			systemdPortLinkOrReparse(secured) ||
			!secured.IsDir() ||
			!os.SameFile(info, secured) ||
			secured.Mode().Perm() != 0o700 {
			return errors.New("systemd port state directory changed while securing")
		}
		info = secured
	}
	if s.requireRootOwned && validateSecureRootPath(directory, true) != nil {
		return errors.New("systemd port state directory is not root-controlled")
	}
	return nil
}

func (s *fileSystemdPortStateStore) LoadActive(targetID string) (*systemdPortLedger, error) {
	if !identifierPattern.MatchString(targetID) {
		return nil, errors.New("systemd port state target identity is invalid")
	}
	var reference struct {
		TargetID string `json:"target_id"`
		JobID    string `json:"job_id"`
	}
	ok, err := s.readPrivateJSON(s.activePath(targetID), &reference, "systemd port active pointer")
	if err != nil || !ok {
		return nil, err
	}
	if reference.TargetID != targetID || !identifierPattern.MatchString(reference.JobID) {
		return nil, errors.New("systemd port active pointer is invalid")
	}
	ledger, err := s.LoadJob(targetID, reference.JobID)
	if err != nil || ledger == nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("systemd port active ledger is missing")
	}
	return ledger, nil
}

func (s *fileSystemdPortStateStore) LoadJob(targetID, jobID string) (*systemdPortLedger, error) {
	if !identifierPattern.MatchString(targetID) || !identifierPattern.MatchString(jobID) {
		return nil, errors.New("systemd port state identity is invalid")
	}
	var ledger systemdPortLedger
	ok, err := s.readPrivateJSON(s.jobPath(targetID, jobID), &ledger, "systemd port ledger")
	if err != nil || !ok {
		return nil, err
	}
	if err := ledger.validate(targetID); err != nil || ledger.Plan.JobID != jobID {
		return nil, errors.New("systemd port ledger identity is invalid")
	}
	return &ledger, nil
}

func (s *fileSystemdPortStateStore) Stage(ledger systemdPortLedger) error {
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	active, err := s.LoadActive(ledger.Plan.TargetID)
	if err != nil {
		return err
	}
	if active != nil && active.Plan.JobID != ledger.Plan.JobID &&
		active.State != systemdPortLedgerTerminal {
		return errors.New("systemd port target already has a non-terminal transaction")
	}
	if err := s.Save(ledger); err != nil {
		return err
	}
	reference := struct {
		TargetID string `json:"target_id"`
		JobID    string `json:"job_id"`
	}{TargetID: ledger.Plan.TargetID, JobID: ledger.Plan.JobID}
	return s.writePrivateJSON(s.activePath(ledger.Plan.TargetID), reference, "systemd port active pointer")
}

func (s *fileSystemdPortStateStore) readPrivateJSON(path string, out any, label string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil ||
		systemdPortLinkOrReparse(info) ||
		!info.Mode().IsRegular() ||
		runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 ||
		info.Size() > systemdPortLedgerMaxBytes ||
		s.requireRootOwned && !isRootOwner(info) {
		return false, errors.New(label + " is not a private regular file")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil ||
		openedInfo.Size() > systemdPortLedgerMaxBytes ||
		s.requireRootOwned && validateRootOwnedFileAndParents(path, openedInfo, "systemd port ledger") != nil {
		if file != nil {
			_ = file.Close()
		}
		return false, errors.New(label + " changed during secure open")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, systemdPortLedgerMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > systemdPortLedgerMaxBytes {
		return false, errors.New("read " + label)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return false, errors.New("decode " + label)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, errors.New(label + " contains trailing data")
	}
	return true, nil
}

func (s *fileSystemdPortStateStore) Save(ledger systemdPortLedger) error {
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	if err := s.ensureDirectory(); err != nil {
		return err
	}
	return s.writePrivateJSON(
		s.jobPath(ledger.Plan.TargetID, ledger.Plan.JobID), ledger, "systemd port ledger",
	)
}

func (s *fileSystemdPortStateStore) LoadApplied(targetID string) (*systemdPortAppliedState, error) {
	if !identifierPattern.MatchString(targetID) {
		return nil, errors.New("systemd applied port target identity is invalid")
	}
	var applied systemdPortAppliedState
	ok, err := s.readPrivateJSON(s.appliedPath(targetID), &applied, "systemd applied port state")
	if err != nil || !ok {
		return nil, err
	}
	if applied.TargetID != targetID {
		return nil, errors.New("systemd applied port state target mismatch")
	}
	return &applied, nil
}

func (s *fileSystemdPortStateStore) SaveApplied(applied systemdPortAppliedState) error {
	if applied.SchemaVersion != systemdPortPlanSchemaVersion ||
		!identifierPattern.MatchString(applied.TargetID) ||
		!validSystemdPortServiceType(applied.ServiceType) ||
		!validSystemdPort(applied.Port) ||
		applied.EndpointRevision < 1 || applied.ConfigRevision < 1 ||
		!digestPattern.MatchString(applied.ConfigSHA256) ||
		applied.SourcePolicyRevision < 1 ||
		applied.UpdaterPolicyRevision < 1 ||
		applied.ExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(applied.ExecutorPolicySHA256) ||
		applied.OwnershipEpoch < 1 {
		return errors.New("systemd applied port state is invalid")
	}
	if err := s.ensureDirectory(); err != nil {
		return err
	}
	return s.writePrivateJSON(
		s.appliedPath(applied.TargetID), applied, "systemd applied port state",
	)
}

func (s *fileSystemdPortStateStore) VerifyAppliedSidecar(
	target LocalExecutorTarget,
	applied systemdPortAppliedState,
) error {
	if err := applied.validateRecord(target); err != nil {
		return err
	}
	adapter, err := systemdPortAdapterFor(target.ServiceType, target.Systemd.Unit)
	if err != nil {
		return errors.New("systemd applied port sidecar adapter is invalid")
	}
	sidecarPath := adapter.SidecarPath
	if s.sidecarPathForTestOnly != "" {
		sidecarPath = s.sidecarPathForTestOnly
	}
	if !filepath.IsAbs(sidecarPath) {
		return errors.New("systemd applied port sidecar path is invalid")
	}
	parent := filepath.Dir(sidecarPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil ||
		systemdPortLinkOrReparse(parentInfo) ||
		!parentInfo.IsDir() ||
		runtime.GOOS != "windows" && parentInfo.Mode().Perm() != 0o700 {
		return errors.New("systemd applied port sidecar directory is invalid")
	}
	if s.requireRootOwned {
		if !isRootOwner(parentInfo) || validateSecureRootPath(parent, true) != nil {
			return errors.New("systemd applied port sidecar directory is not root-controlled")
		}
	}
	info, err := os.Lstat(sidecarPath)
	if err != nil ||
		systemdPortLinkOrReparse(info) ||
		!info.Mode().IsRegular() ||
		runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		return errors.New("systemd applied port sidecar is not a private regular file")
	}
	if s.requireRootOwned && !isRootOwner(info) {
		return errors.New("systemd applied port sidecar is not root-owned")
	}
	expected := systemdPortSidecarBytes(
		adapter.ServiceType,
		target.LocalListen.Host,
		applied.Port,
		applied.ConfigRevision,
	)
	if info.Size() != int64(len(expected)) || len(expected) == 0 ||
		len(expected) > systemdPortAppliedSidecarMaxBytes {
		return errors.New("systemd applied port sidecar size is invalid")
	}
	file, openedInfo, err := openVerifiedConfig(sidecarPath, info)
	if err != nil ||
		openedInfo.Size() != info.Size() ||
		s.requireRootOwned &&
			validateRootOwnedFileAndParents(
				sidecarPath, openedInfo, "systemd applied port sidecar",
			) != nil {
		if file != nil {
			_ = file.Close()
		}
		return errors.New("systemd applied port sidecar changed during secure open")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, systemdPortAppliedSidecarMaxBytes+1))
	if err != nil ||
		!bytes.Equal(body, expected) ||
		systemdPortSidecarSHA256(body) != applied.ConfigSHA256 {
		return errors.New("systemd applied port sidecar does not match durable state")
	}
	return nil
}

func (s *fileSystemdPortStateStore) writePrivateJSON(path string, value any, label string) error {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > systemdPortLedgerMaxBytes {
		return errors.New("encode " + label)
	}
	if err := writeAtomicFile(path, append(payload, '\n'), 0o600); err != nil {
		return errors.New("persist " + label)
	}
	return nil
}
