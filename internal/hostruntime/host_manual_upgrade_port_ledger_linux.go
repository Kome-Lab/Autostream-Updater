//go:build linux

package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func scanManualHostPortLedgers(rt manualHostUpgradeRuntime) error {
	base := rt.paths.localExecutorStateRoot
	if err := scanManualHostPortLedgerNamespace(
		filepath.Join(base, "port-ledger"), false, rt,
	); err != nil {
		return err
	}
	if _, err := readOptionalManualHostDirectory(
		filepath.Join(base, "docker-port"), rt,
	); err != nil {
		return err
	}
	return scanManualHostPortLedgerNamespace(
		filepath.Join(base, "docker-port", "port-ledger"), true, rt,
	)
}

func scanManualHostPortLedgerNamespace(
	root string,
	docker bool,
	rt manualHostUpgradeRuntime,
) error {
	jobsRoot := filepath.Join(root, "jobs")
	entries, err := readOptionalManualHostDirectory(jobsRoot, rt)
	if err != nil {
		return err
	}
	type terminalJob struct {
		target string
		job    string
	}
	terminal := make(map[terminalJob]bool)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("port mutation ledger contains an unsafe entry")
		}
		if docker {
			var ledger dockerPortLedger
			if decodeManualHostPrivateJSON(
				filepath.Join(jobsRoot, entry.Name()),
				systemdPortLedgerMaxBytes, "Docker port mutation ledger",
				&ledger, rt,
			) != nil || ledger.validate(ledger.Plan.TargetID) != nil ||
				entry.Name() != remoteStableKey(
					ledger.Plan.TargetID, ledger.Plan.JobID,
				)+".json" {
				return errors.New("Docker port mutation ledger is invalid")
			}
			if ledger.State != dockerPortLedgerTerminal {
				return errors.New("a non-terminal Docker port mutation blocks upgrade")
			}
			terminal[terminalJob{ledger.Plan.TargetID, ledger.Plan.JobID}] = true
			continue
		}
		var ledger systemdPortLedger
		if decodeManualHostPrivateJSON(
			filepath.Join(jobsRoot, entry.Name()),
			systemdPortLedgerMaxBytes, "systemd port mutation ledger",
			&ledger, rt,
		) != nil || ledger.validate(ledger.Plan.TargetID) != nil ||
			entry.Name() != remoteStableKey(
				ledger.Plan.TargetID, ledger.Plan.JobID,
			)+".json" {
			return errors.New("systemd port mutation ledger is invalid")
		}
		if ledger.State != systemdPortLedgerTerminal {
			return errors.New("a non-terminal systemd port mutation blocks upgrade")
		}
		terminal[terminalJob{ledger.Plan.TargetID, ledger.Plan.JobID}] = true
	}
	activeRoot := filepath.Join(root, "active")
	entries, err = readOptionalManualHostDirectory(activeRoot, rt)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("port mutation active pointer contains an unsafe entry")
		}
		var reference struct {
			TargetID string `json:"target_id"`
			JobID    string `json:"job_id"`
		}
		if decodeManualHostPrivateJSON(
			filepath.Join(activeRoot, entry.Name()), 64<<10,
			"port mutation active pointer", &reference, rt,
		) != nil || entry.Name() != remoteStableKey(reference.TargetID)+".json" ||
			!terminal[terminalJob{reference.TargetID, reference.JobID}] {
			return errors.New("port mutation active pointer is not terminal")
		}
	}
	return nil
}

func readOptionalManualHostDirectory(
	path string,
	rt manualHostUpgradeRuntime,
) ([]os.DirEntry, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		(!rt.allowTestPaths &&
			(info.Mode().Perm() != 0o700 || !isRootOwner(info) ||
				validateSecureRootPath(path, true) != nil)) {
		return nil, errors.New("manual Host runtime state directory is unsafe")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, errors.New("read manual Host runtime state directory")
	}
	return entries, nil
}

func decodeManualHostPrivateJSON(
	path string,
	maximum int64,
	label string,
	out any,
	rt manualHostUpgradeRuntime,
) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > maximum ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return errors.New(label + " is not a private regular file")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil || !os.SameFile(info, openedInfo) ||
		(!rt.allowTestPaths &&
			validateRootOwnedFileAndParents(path, openedInfo, label) != nil) {
		if file != nil {
			_ = file.Close()
		}
		return errors.New(label + " changed during secure open")
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		return errors.New("read " + label)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errors.New("decode " + label)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New(label + " contains trailing data")
	}
	return nil
}

// rejectManualHostUpgradeGrant keeps manual upgrade preflight read-only with
// respect to the online Host self-update protocol. Only the normal healthy-slot
// Executor may converge or retire a durable grant.
func rejectManualHostUpgradeGrant(rt manualHostUpgradeRuntime) error {
	grant, err := loadHostSelfUpdateGrantState(
		rt.selfUpdate.grantStatePath, !rt.allowTestPaths,
	)
	if err != nil {
		return fmt.Errorf(
			"Host self-update grant blocks manual runtime upgrade; wait for the healthy-slot Local Executor to converge it: %w",
			err,
		)
	}
	if grant == nil {
		return nil
	}
	return errors.New(
		"an existing Host self-update grant blocks manual runtime upgrade; " +
			"wait for the healthy-slot Local Executor to converge it",
	)
}
