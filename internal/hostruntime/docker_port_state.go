package hostruntime

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// fileDockerPortStateStore keeps Docker port transactions in a namespace
// separate from systemd port ledgers while reusing the same fail-closed
// private-file implementation. The mapping sidecar itself is intentionally
// not copied into the applied-state record.
type fileDockerPortStateStore struct {
	files                  *fileSystemdPortStateStore
	sidecarPathForTestOnly string
}

func newFileDockerPortStateStore(
	stateDir string,
	requireRootOwned bool,
) (*fileDockerPortStateStore, error) {
	files, err := newFileSystemdPortStateStore(
		filepath.Join(filepath.Clean(stateDir), "docker-port"),
		requireRootOwned,
	)
	if err != nil {
		return nil, err
	}
	return &fileDockerPortStateStore{files: files}, nil
}

func (s *fileDockerPortStateStore) LoadActive(
	targetID string,
) (*dockerPortLedger, error) {
	if s == nil || s.files == nil || !identifierPattern.MatchString(targetID) {
		return nil, errors.New("Docker port state target identity is invalid")
	}
	var reference struct {
		TargetID string `json:"target_id"`
		JobID    string `json:"job_id"`
	}
	ok, err := s.files.readPrivateJSON(
		s.files.activePath(targetID), &reference, "Docker port active pointer",
	)
	if err != nil || !ok {
		return nil, err
	}
	if reference.TargetID != targetID ||
		!identifierPattern.MatchString(reference.JobID) {
		return nil, errors.New("Docker port active pointer is invalid")
	}
	ledger, err := s.LoadJob(targetID, reference.JobID)
	if err != nil || ledger == nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("Docker port active ledger is missing")
	}
	return ledger, nil
}

func (s *fileDockerPortStateStore) LoadJob(
	targetID string,
	jobID string,
) (*dockerPortLedger, error) {
	if s == nil || s.files == nil ||
		!identifierPattern.MatchString(targetID) ||
		!identifierPattern.MatchString(jobID) {
		return nil, errors.New("Docker port state identity is invalid")
	}
	var ledger dockerPortLedger
	ok, err := s.files.readPrivateJSON(
		s.files.jobPath(targetID, jobID), &ledger, "Docker port ledger",
	)
	if err != nil || !ok {
		return nil, err
	}
	if ledger.validate(targetID) != nil || ledger.Plan.JobID != jobID {
		return nil, errors.New("Docker port ledger identity is invalid")
	}
	return &ledger, nil
}

func (s *fileDockerPortStateStore) Stage(ledger dockerPortLedger) error {
	if s == nil || s.files == nil {
		return errors.New("Docker port state store is unavailable")
	}
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	active, err := s.LoadActive(ledger.Plan.TargetID)
	if err != nil {
		return err
	}
	if active != nil &&
		active.Plan.JobID != ledger.Plan.JobID &&
		active.State != dockerPortLedgerTerminal {
		return errors.New("Docker port target already has a non-terminal transaction")
	}
	if err := s.Save(ledger); err != nil {
		return err
	}
	reference := struct {
		TargetID string `json:"target_id"`
		JobID    string `json:"job_id"`
	}{TargetID: ledger.Plan.TargetID, JobID: ledger.Plan.JobID}
	return s.files.writePrivateJSON(
		s.files.activePath(ledger.Plan.TargetID),
		reference,
		"Docker port active pointer",
	)
}

func (s *fileDockerPortStateStore) Save(ledger dockerPortLedger) error {
	if s == nil || s.files == nil {
		return errors.New("Docker port state store is unavailable")
	}
	if err := ledger.validate(ledger.Plan.TargetID); err != nil {
		return err
	}
	if err := s.files.ensureDirectory(); err != nil {
		return err
	}
	return s.files.writePrivateJSON(
		s.files.jobPath(ledger.Plan.TargetID, ledger.Plan.JobID),
		ledger,
		"Docker port ledger",
	)
}

func (s *fileDockerPortStateStore) LoadDockerApplied(
	targetID string,
) (*dockerPortAppliedState, error) {
	if s == nil || s.files == nil || !identifierPattern.MatchString(targetID) {
		return nil, errors.New("Docker applied port target identity is invalid")
	}
	var applied dockerPortAppliedState
	ok, err := s.files.readPrivateJSON(
		s.files.appliedPath(targetID), &applied, "Docker applied port state",
	)
	if err != nil || !ok {
		return nil, err
	}
	if err := applied.validate(targetID); err != nil {
		return nil, err
	}
	return &applied, nil
}

func (s *fileDockerPortStateStore) SaveApplied(
	applied dockerPortAppliedState,
) error {
	if s == nil || s.files == nil {
		return errors.New("Docker port state store is unavailable")
	}
	if err := applied.validate(applied.TargetID); err != nil {
		return err
	}
	if err := s.files.ensureDirectory(); err != nil {
		return err
	}
	return s.files.writePrivateJSON(
		s.files.appliedPath(applied.TargetID),
		applied,
		"Docker applied port state",
	)
}

func (s *fileDockerPortStateStore) VerifyAppliedDockerSidecar(
	target LocalExecutorTarget,
	applied dockerPortAppliedState,
) error {
	if s == nil || s.files == nil {
		return errors.New("Docker applied port state store is unavailable")
	}
	if err := applied.validateRecord(target); err != nil {
		return err
	}
	adapter, err := dockerPortAdapterFor(target.ServiceType, target.Docker)
	if err != nil {
		return errors.New("Docker applied port sidecar adapter is invalid")
	}
	path := adapter.PortEnvFile
	if s.sidecarPathForTestOnly != "" {
		path = s.sidecarPathForTestOnly
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil ||
		systemdPortLinkOrReparse(parentInfo) ||
		!parentInfo.IsDir() ||
		runtime.GOOS != "windows" && parentInfo.Mode().Perm() != 0o700 {
		return errors.New("Docker applied port sidecar directory is invalid")
	}
	if s.files.requireRootOwned &&
		(!isRootOwner(parentInfo) ||
			validateSecureRootPath(parent, true) != nil) {
		return errors.New("Docker applied port sidecar directory is not root-controlled")
	}
	info, err := os.Lstat(path)
	if err != nil ||
		systemdPortLinkOrReparse(info) ||
		!info.Mode().IsRegular() ||
		runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 ||
		info.Size() > 64<<10 ||
		s.files.requireRootOwned && !isRootOwner(info) {
		return errors.New("Docker applied port sidecar is not a private regular file")
	}
	expected, err := dockerPortEnvBytes(
		adapter,
		applied.PublishedPort,
		applied.ContainerPort,
		applied.ConfigRevision,
	)
	if err != nil || info.Size() != int64(len(expected)) {
		return errors.New("Docker applied port sidecar size is invalid")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil ||
		openedInfo.Size() != info.Size() ||
		s.files.requireRootOwned &&
			validateRootOwnedFileAndParents(
				path, openedInfo, "Docker applied port sidecar",
			) != nil {
		if file != nil {
			_ = file.Close()
		}
		return errors.New("Docker applied port sidecar changed during secure open")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil ||
		!bytes.Equal(body, expected) ||
		dockerPortEnvSHA256(body) != applied.ConfigSHA256 {
		return errors.New("Docker applied port sidecar does not match durable state")
	}
	return nil
}
