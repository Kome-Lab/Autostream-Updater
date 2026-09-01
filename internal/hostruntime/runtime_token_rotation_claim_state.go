package hostruntime

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	runtimeTokenClaimStateFileName = "runtime-token-claim.json"
	runtimeTokenClaimStateVersion  = 1
	runtimeTokenClaimStateMaxBytes = 32 << 10
)

type RuntimeTokenClaimState struct {
	SchemaVersion               int       `json:"schema_version"`
	RotationID                  string    `json:"rotation_id"`
	ServiceID                   string    `json:"service_id"`
	ExecutionHostID             string    `json:"execution_host_id"`
	PreviousTokenID             string    `json:"previous_token_id"`
	StagedTokenID               string    `json:"staged_token_id"`
	ClaimID                     string    `json:"claim_id"`
	InitialRevision             int64     `json:"initial_revision"`
	OwnershipEpoch              int64     `json:"ownership_epoch"`
	SourcePolicyRevision        int64     `json:"source_policy_revision"`
	ProjectionRevision          int64     `json:"projection_revision"`
	LocalExecutorPolicyRevision int64     `json:"local_executor_policy_revision"`
	ExpiresAt                   time.Time `json:"expires_at"`
}

func (s RuntimeTokenClaimState) Validate() error {
	if s.SchemaVersion != runtimeTokenClaimStateVersion ||
		!identifierPattern.MatchString(s.RotationID) ||
		!identifierPattern.MatchString(s.ServiceID) ||
		!validExecutionHostID(s.ExecutionHostID) ||
		!identifierPattern.MatchString(s.PreviousTokenID) ||
		!identifierPattern.MatchString(s.StagedTokenID) ||
		s.PreviousTokenID == s.StagedTokenID ||
		!identifierPattern.MatchString(s.ClaimID) ||
		s.InitialRevision != 1 ||
		s.OwnershipEpoch < 1 ||
		s.SourcePolicyRevision < 1 ||
		s.ProjectionRevision < 1 ||
		s.LocalExecutorPolicyRevision < 1 {
		return errors.New("runtime token claim state is invalid")
	}
	if s.ExpiresAt.IsZero() || s.ExpiresAt.Location() != time.UTC {
		return errors.New("runtime token claim state expiry is invalid")
	}
	return nil
}

func (s RuntimeTokenClaimState) matches(
	rotation HostAgentRuntimeTokenRotation,
) bool {
	return s.RotationID == rotation.ID &&
		s.ServiceID == rotation.ServiceID &&
		s.ExecutionHostID == rotation.ExecutionHostID &&
		s.PreviousTokenID == rotation.PreviousTokenID &&
		s.StagedTokenID == rotation.StagedTokenID &&
		s.OwnershipEpoch == rotation.ExpectedOwnershipEpoch &&
		s.SourcePolicyRevision == rotation.ExpectedSourcePolicyRevision &&
		s.ProjectionRevision == rotation.ExpectedProjectionRevision &&
		s.LocalExecutorPolicyRevision ==
			rotation.ExpectedLocalExecutorPolicyRevision
}

type RuntimeTokenClaimStateStore interface {
	Load() (RuntimeTokenClaimState, bool, error)
	Save(RuntimeTokenClaimState) error
	Delete(RuntimeTokenClaimState) error
}

type FileRuntimeTokenClaimStateStore struct {
	StateDir string
}

func (s FileRuntimeTokenClaimStateStore) path() (string, error) {
	stateDir := filepath.Clean(s.StateDir)
	if !filepath.IsAbs(stateDir) ||
		filepath.Dir(stateDir) == stateDir {
		return "", errors.New(
			"runtime token claim state directory is invalid",
		)
	}
	return filepath.Join(stateDir, runtimeTokenClaimStateFileName), nil
}

func (s FileRuntimeTokenClaimStateStore) Load() (
	RuntimeTokenClaimState,
	bool,
	error,
) {
	path, err := s.path()
	if err != nil {
		return RuntimeTokenClaimState{}, false, err
	}
	if err := validateManagedDirectoryChain(filepath.Dir(path)); err != nil {
		return RuntimeTokenClaimState{}, false, errors.New(
			"runtime token claim state parent is unsafe",
		)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return RuntimeTokenClaimState{}, false, nil
	}
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Size() <= 0 ||
		info.Size() > runtimeTokenClaimStateMaxBytes ||
		(snapshotModeEnforced() && info.Mode().Perm() != 0o600) ||
		!managedSnapshotOwnedByCurrentUser(info) {
		return RuntimeTokenClaimState{}, false, errors.New(
			"runtime token claim state is unsafe",
		)
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil {
		return RuntimeTokenClaimState{}, false, errors.New(
			"open runtime token claim state",
		)
	}
	defer file.Close()
	if (snapshotModeEnforced() && openedInfo.Mode().Perm() != 0o600) ||
		!managedSnapshotOwnedByCurrentUser(openedInfo) {
		return RuntimeTokenClaimState{}, false, errors.New(
			"runtime token claim state owner changed during secure open",
		)
	}
	data, err := io.ReadAll(io.LimitReader(
		file, runtimeTokenClaimStateMaxBytes+1,
	))
	if err != nil ||
		len(data) == 0 ||
		len(data) > runtimeTokenClaimStateMaxBytes {
		return RuntimeTokenClaimState{}, false, errors.New(
			"read runtime token claim state",
		)
	}
	var state RuntimeTokenClaimState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return RuntimeTokenClaimState{}, false, errors.New(
			"decode runtime token claim state",
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RuntimeTokenClaimState{}, false, errors.New(
			"runtime token claim state contains trailing data",
		)
	}
	if err := state.Validate(); err != nil {
		return RuntimeTokenClaimState{}, false, err
	}
	return state, true, nil
}

func (s FileRuntimeTokenClaimStateStore) Save(
	state RuntimeTokenClaimState,
) error {
	if err := state.Validate(); err != nil {
		return err
	}
	path, err := s.path()
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := validateManagedDirectoryChain(parent); err != nil {
		return errors.New("runtime token claim state parent is unsafe")
	}
	_, existingErr := os.Lstat(path)
	if existingErr == nil {
		current, exists, err := s.Load()
		if err != nil {
			return err
		}
		if !exists || current != state {
			return errors.New(
				"runtime token claim state already exists with another binding",
			)
		}
		return nil
	}
	if !errors.Is(existingErr, os.ErrNotExist) {
		return errors.New("stat runtime token claim state")
	}
	data, err := json.Marshal(state)
	if err != nil ||
		len(data)+1 > runtimeTokenClaimStateMaxBytes {
		return errors.New("encode runtime token claim state")
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(parent, ".runtime-token-claim-*")
	if err != nil {
		return errors.New("create runtime token claim state")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return errors.New("secure runtime token claim state")
	}
	if _, err := temp.Write(data); err != nil ||
		temp.Sync() != nil {
		_ = temp.Close()
		return errors.New("write runtime token claim state")
	}
	tempInfo, err := temp.Stat()
	if err != nil ||
		(snapshotModeEnforced() && tempInfo.Mode().Perm() != 0o600) ||
		!managedSnapshotOwnedByCurrentUser(tempInfo) {
		_ = temp.Close()
		return errors.New("runtime token claim temporary state is unsafe")
	}
	if err := temp.Close(); err != nil {
		return errors.New("close runtime token claim state")
	}
	if err := validateManagedDirectoryChain(parent); err != nil {
		return errors.New(
			"runtime token claim state parent changed before install",
		)
	}
	if current, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New(
			"runtime token claim state destination appeared before install",
		)
	} else {
		_ = current
	}
	if err := os.Rename(tempPath, path); err != nil {
		switch inspectPreparedRenameOutcome(tempPath, path, tempInfo) {
		case preparedRenameInstalled:
			if syncErr := syncDirectory(parent); syncErr != nil {
				return errors.Join(err, syncErr)
			}
			return errors.New(
				"runtime token claim state installed but rename reported an error",
			)
		case preparedRenameNotInstalled:
			return errors.New("install runtime token claim state")
		default:
			return errors.New(
				"runtime token claim state install result is uncertain",
			)
		}
	}
	return syncDirectory(parent)
}

func (s FileRuntimeTokenClaimStateStore) Delete(
	expected RuntimeTokenClaimState,
) error {
	path, err := s.path()
	if err != nil {
		return err
	}
	current, exists, err := s.Load()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if current != expected {
		return errors.New(
			"runtime token claim state changed before cleanup",
		)
	}
	info, err := os.Lstat(path)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!managedSnapshotOwnedByCurrentUser(info) {
		return errors.New("runtime token claim state changed before unlink")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("remove runtime token claim state")
	}
	return syncDirectory(filepath.Dir(path))
}

func newRuntimeTokenClaimID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("generate runtime token claim identity")
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" +
		encoded[8:12] + "-" +
		encoded[12:16] + "-" +
		encoded[16:20] + "-" +
		encoded[20:32], nil
}
