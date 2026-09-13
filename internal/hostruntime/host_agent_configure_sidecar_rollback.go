package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func (p *preparedSystemdPortSidecars) Rollback() error {
	if p == nil {
		return nil
	}
	rollbackErr := p.rollbackCreatedSidecars()
	if p.replaced {
		_, replacementErr := p.rollbackReplacement()
		rollbackErr = errors.Join(rollbackErr, replacementErr)
	}
	if rollbackErr == nil {
		p.committed = false
	}
	return rollbackErr
}

func (p *preparedSystemdPortSidecars) rollbackReplacement() (bool, error) {
	if p == nil || !p.replaced {
		return false, nil
	}
	entry := p.replacedEntry
	if p.replacementAmbiguous {
		return false, errors.New("systemd sidecar exchange state is ambiguous; preserved the adopted sidecar and rollback inode for recovery")
	}
	if entry == nil || !p.replacementPairMatches(entry, true) {
		return false, errors.New("adopted systemd sidecar changed before rollback; preserved the adopted sidecar and rollback inode for recovery")
	}
	if err := p.verifyLiveReplacementRollback(); err != nil {
		return false, errors.Join(
			err,
			errors.New("preserved the adopted sidecar and rollback inode for recovery"),
		)
	}
	// Recheck the inode/body pair after the potentially slow live proof. The
	// proof alone never authorizes exchanging pathnames that changed while it
	// was collected.
	if !p.replacementPairMatches(entry, true) {
		return false, errors.New("adopted systemd sidecar changed after rollback proof; preserved the adopted sidecar and rollback inode for recovery")
	}
	exchangeErr := p.exchange(p.replacementTempPath, entry.path)
	if exchangeErr == nil {
		// RENAME_EXCHANGE succeeded, so the path roles changed even if every
		// subsequent read fails. Record the conservative state and durability
		// fence before attempting the post-exchange CAS observation.
		p.replacementAmbiguous = true
		syncErr := p.syncParentDirectory()
		if !p.replacementPairMatches(entry, false) {
			return false, errors.Join(
				errors.New("adopted systemd sidecar rollback result is unsafe; preserved both systemd sidecar pathnames for recovery"),
				syncErr,
			)
		}
		if syncErr != nil {
			return false, errors.Join(
				errors.New("adopted systemd sidecar rollback was not durably fenced; preserved both systemd sidecar pathnames for recovery"),
				syncErr,
			)
		}
		p.replacementAmbiguous = false
		p.replaced = false
		p.replacedEntry = nil
		p.rollbackAuthority = nil
		return true, nil
	}
	oldPair := p.replacementPairMatches(entry, false)
	newPair := p.replacementPairMatches(entry, true)
	if newPair {
		return false, fmt.Errorf(
			"adopted systemd sidecar rollback reported an error without changing the recovery pair: %w",
			exchangeErr,
		)
	}
	p.replacementAmbiguous = true
	syncErr := p.syncParentDirectory()
	if oldPair {
		return false, errors.Join(
			fmt.Errorf("adopted systemd sidecar rollback reported an error after exchanging the recovery pair: %w", exchangeErr),
			errors.New("preserved both systemd sidecar pathnames for recovery"),
			syncErr,
		)
	}
	return false, errors.Join(
		fmt.Errorf("adopted systemd sidecar rollback result is uncertain: %w", exchangeErr),
		errors.New("preserved both systemd sidecar pathnames for recovery"),
		syncErr,
	)
}

func (p *preparedSystemdPortSidecars) rollbackCreatedSidecars() error {
	if p == nil {
		return nil
	}
	var rollbackErr error
	removed := false
	paths := make([]string, 0, len(p.entries))
	for path := range p.entries {
		paths = append(paths, path)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))
	for _, path := range paths {
		entry := p.entries[path]
		if !entry.created {
			continue
		}
		body, info, existed, err := readRootSystemdPortSidecarOptional(entry.path)
		if err != nil ||
			!existed ||
			entry.createdInfo == nil ||
			!os.SameFile(info, entry.createdInfo) ||
			!bytes.Equal(body, entry.installedBody) {
			rollbackErr = errors.Join(
				rollbackErr,
				fmt.Errorf(
					"new systemd port sidecar %s changed before rollback",
					filepath.Base(entry.path),
				),
			)
			continue
		}
		if err := os.Remove(entry.path); err != nil {
			rollbackErr = errors.Join(
				rollbackErr,
				fmt.Errorf(
					"remove new systemd port sidecar %s during rollback",
					filepath.Base(entry.path),
				),
			)
			continue
		}
		entry.created = false
		entry.createdInfo = nil
		removed = true
	}
	if removed {
		if err := p.syncParentDirectory(); err != nil {
			rollbackErr = errors.Join(
				rollbackErr,
				errors.New("sync systemd port sidecar directory during rollback"),
			)
		}
	}
	return rollbackErr
}

func (p *preparedSystemdPortSidecars) verifyLiveReplacementRollback() error {
	if p == nil || p.rollbackAuthority == nil || p.rollbackAuthority.verify == nil {
		return errors.New("live systemd sidecar rollback proof is unavailable")
	}
	authority := p.rollbackAuthority
	ctx, cancel := context.WithTimeout(
		context.Background(),
		hostAgentSidecarRollbackProofTimeout,
	)
	defer cancel()
	proof, err := authority.verify(
		ctx,
		authority.currentPolicy,
		authority.stagedPolicy,
		authority.currentTarget,
		authority.stagedTarget,
	)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			err = errors.Join(err, ctxErr)
		}
		return fmt.Errorf("verify live systemd sidecar target before rollback: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify live systemd sidecar target before rollback: %w", err)
	}
	if proof != authority.acceptedProof {
		return errors.New("live systemd sidecar target changed before rollback")
	}
	return nil
}

func (p *preparedSystemdPortSidecars) Finalize() error {
	if p == nil || p.finalized || !p.replaced {
		return nil
	}
	entry := p.replacedEntry
	if !p.committed || entry == nil || !p.replacementPairMatches(entry, true) {
		return errors.New("adopted systemd sidecar backup changed before cleanup")
	}
	backup, backupInfo, existed, err := readRootSystemdPortSidecarOptional(
		p.replacementTempPath,
	)
	if err != nil || !existed || !os.SameFile(backupInfo, entry.existingInfo) ||
		!bytes.Equal(backup, entry.existing) {
		return errors.New("adopted systemd sidecar backup is unsafe")
	}
	if p.replacementTemp != nil {
		if err := p.replacementTemp.Close(); err != nil {
			p.replacementTemp = nil
			return errors.New("close adopted systemd sidecar destination")
		}
		p.replacementTemp = nil
	}
	if err := os.Remove(p.replacementTempPath); err != nil {
		return errors.New("remove adopted systemd sidecar backup")
	}
	p.replacementTempPath = ""
	p.finalized = true
	if err := p.syncParentDirectory(); err != nil {
		return errors.New("sync systemd sidecar directory after backup cleanup")
	}
	return nil
}

func (p *preparedSystemdPortSidecars) Abort() {
	if p == nil {
		return
	}
	for _, entry := range p.entries {
		if entry.temp != nil {
			_ = entry.temp.Close()
			entry.temp = nil
		}
		if entry.tempPath != "" {
			_ = os.Remove(entry.tempPath)
			entry.tempPath = ""
		}
	}
	if p.replacementTemp != nil {
		_ = p.replacementTemp.Close()
		p.replacementTemp = nil
	}
	if p.replacementTempPath != "" && !p.replaced {
		if info, err := os.Lstat(p.replacementTempPath); err == nil &&
			p.replacementTempInfo != nil &&
			os.SameFile(info, p.replacementTempInfo) {
			_ = os.Remove(p.replacementTempPath)
			_ = p.syncParentDirectory()
		}
		p.replacementTempPath = ""
	}
}

func (p *preparedSystemdPortSidecars) syncParentDirectory() error {
	if p == nil || p.syncParent == nil {
		return errors.New("systemd port sidecar directory sync is unavailable")
	}
	return p.syncParent(p.parent)
}
