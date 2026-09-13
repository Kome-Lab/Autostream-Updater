package hostruntime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

func (e *preparedSystemdPortSidecar) prepareBody(body []byte) error {
	if e == nil || e.temp == nil || e.tempInfo == nil || e.created {
		return errors.New("initial systemd port sidecar temporary file is unavailable")
	}
	if err := e.verifyTemporaryFile(); err != nil {
		return err
	}
	if err := e.temp.Truncate(0); err != nil {
		return errors.New("truncate initial systemd port sidecar temporary file")
	}
	if _, err := e.temp.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind initial systemd port sidecar temporary file")
	}
	if _, err := e.temp.Write(body); err != nil {
		return errors.New("write initial systemd port sidecar temporary file")
	}
	if err := e.temp.Chown(0, 0); err != nil {
		return errors.New("restore initial systemd port sidecar temporary file ownership")
	}
	if err := e.temp.Chmod(0o600); err != nil {
		return errors.New("restore initial systemd port sidecar temporary file mode")
	}
	if err := e.temp.Sync(); err != nil {
		return errors.New("sync initial systemd port sidecar temporary file")
	}
	e.installedBody = append([]byte(nil), body...)
	return e.verifyTemporaryFile()
}

func (p *preparedSystemdPortSidecars) prepareReplacementBody(body []byte) error {
	if p == nil || p.replacementTemp == nil || p.replacementTempPath == "" ||
		p.replacementTempInfo == nil || p.replaced || len(body) == 0 ||
		len(body) > systemdPortSidecarConfigureMaxBytes {
		return errors.New("systemd sidecar adoption file is unavailable")
	}
	if err := p.verifyReplacementTemporaryFile(); err != nil {
		return err
	}
	if err := p.replacementTemp.Truncate(0); err != nil {
		return errors.New("truncate systemd sidecar adoption file")
	}
	if _, err := p.replacementTemp.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind systemd sidecar adoption file")
	}
	if _, err := p.replacementTemp.Write(body); err != nil {
		return errors.New("write systemd sidecar adoption file")
	}
	if err := p.replacementTemp.Chown(0, 0); err != nil {
		return errors.New("restore systemd sidecar adoption file ownership")
	}
	if err := p.replacementTemp.Chmod(0o600); err != nil {
		return errors.New("restore systemd sidecar adoption file mode")
	}
	if err := p.replacementTemp.Sync(); err != nil {
		return errors.New("sync systemd sidecar adoption file")
	}
	p.replacementBody = append([]byte(nil), body...)
	return p.verifyReplacementTemporaryFile()
}

func (p *preparedSystemdPortSidecars) exchangeReplacement(
	entry *preparedSystemdPortSidecar,
) error {
	if p == nil || entry == nil || !entry.existed || p.replaced ||
		len(p.replacementBody) == 0 || p.exchange == nil {
		return errors.New("systemd sidecar adoption is not ready")
	}
	if err := p.verifyDestinations(); err != nil {
		return err
	}
	exchangeErr := p.exchange(p.replacementTempPath, entry.path)
	if exchangeErr == nil {
		// A successful RENAME_EXCHANGE changes both pathnames atomically. Record
		// that transition before any fallible post-exchange read so Abort can
		// never unlink or forget the only exact rollback inode.
		p.replaced = true
		p.replacedEntry = entry
		if !p.replacementPairMatches(entry, true) {
			return p.preserveAmbiguousReplacement(
				entry,
				errors.New("live systemd sidecar exchange succeeded but its result could not be verified; preserved the adopted sidecar and rollback inode for recovery"),
			)
		}
	} else {
		oldPair := p.replacementPairMatches(entry, false)
		newPair := p.replacementPairMatches(entry, true)
		if oldPair {
			return fmt.Errorf("exchange live systemd sidecar: %w", exchangeErr)
		}
		if !newPair {
			return p.preserveAmbiguousReplacement(
				entry,
				errors.New("live systemd sidecar exchange result is uncertain; preserved the adopted sidecar and rollback inode for recovery"),
			)
		}
		p.replaced = true
		p.replacedEntry = entry
	}
	if err := p.syncParentDirectory(); err != nil {
		rollbackErr := p.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"sync adopted systemd sidecar directory: %v; rollback sidecar: %w",
				err,
				rollbackErr,
			)
		}
		return errors.New("sync adopted systemd sidecar directory")
	}
	if err := p.verifyDestinations(); err != nil {
		rollbackErr := p.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"verify adopted systemd sidecar: %v; rollback sidecar: %w",
				err,
				rollbackErr,
			)
		}
		return err
	}
	if exchangeErr != nil {
		rollbackErr := p.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"systemd sidecar exchange reported an error after a provable swap: %v; rollback sidecar: %w",
				exchangeErr,
				rollbackErr,
			)
		}
		return errors.New("systemd sidecar exchange reported an error after a provable swap")
	}
	return nil
}

func (p *preparedSystemdPortSidecars) preserveAmbiguousReplacement(
	entry *preparedSystemdPortSidecar,
	cause error,
) error {
	p.replaced = true
	p.replacedEntry = entry
	p.replacementAmbiguous = true
	if err := p.syncParentDirectory(); err != nil {
		return errors.Join(
			cause,
			errors.New("sync ambiguous systemd sidecar exchange for recovery"),
		)
	}
	return cause
}

func (p *preparedSystemdPortSidecars) replacementPairMatches(
	entry *preparedSystemdPortSidecar,
	swapped bool,
) bool {
	if p == nil || p.replacementPairVerifier == nil {
		return false
	}
	return p.replacementPairVerifier(entry, swapped)
}

func (p *preparedSystemdPortSidecars) replacementPairMatchesOnDisk(
	entry *preparedSystemdPortSidecar,
	swapped bool,
) bool {
	if p == nil || entry == nil || entry.existingInfo == nil ||
		p.replacementTempInfo == nil || p.replacementTempPath == "" {
		return false
	}
	destinationBody, destinationInfo, destinationExists, destinationErr :=
		readRootSystemdPortSidecarOptional(entry.path)
	temporaryBody, temporaryInfo, temporaryExists, temporaryErr :=
		readRootSystemdPortSidecarOptional(p.replacementTempPath)
	if destinationErr != nil || temporaryErr != nil ||
		!destinationExists || !temporaryExists ||
		destinationInfo.Mode()&os.ModeSymlink != 0 ||
		temporaryInfo.Mode()&os.ModeSymlink != 0 ||
		!destinationInfo.Mode().IsRegular() || !temporaryInfo.Mode().IsRegular() ||
		destinationInfo.Mode().Perm() != 0o600 || temporaryInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(destinationInfo, 0) ||
		!updaterConfigHasInstallOwner(temporaryInfo, 0) {
		return false
	}
	if swapped {
		return os.SameFile(destinationInfo, p.replacementTempInfo) &&
			os.SameFile(temporaryInfo, entry.existingInfo) &&
			bytes.Equal(destinationBody, p.replacementBody) &&
			bytes.Equal(temporaryBody, entry.existing)
	}
	return os.SameFile(destinationInfo, entry.existingInfo) &&
		os.SameFile(temporaryInfo, p.replacementTempInfo) &&
		bytes.Equal(destinationBody, entry.existing) &&
		bytes.Equal(temporaryBody, p.replacementBody)
}

func (e *preparedSystemdPortSidecar) installNoReplace() error {
	if e == nil || e.existed || e.created || len(e.installedBody) == 0 {
		return errors.New("initial systemd port sidecar is not ready for installation")
	}
	if err := e.verifyTemporaryFile(); err != nil {
		return err
	}
	if _, _, existed, err := readRootSystemdPortSidecarOptional(e.path); err != nil {
		return err
	} else if existed {
		return errors.New("systemd port sidecar destination appeared after preflight")
	}
	linkErr := os.Link(e.tempPath, e.path)
	pathInfo, pathErr := os.Lstat(e.path)
	if pathErr == nil && e.tempInfo != nil && os.SameFile(pathInfo, e.tempInfo) {
		e.created = true
		e.createdInfo = pathInfo
	} else if linkErr == nil {
		return errors.New("initial systemd port sidecar installed with an unsafe identity")
	}
	if linkErr != nil {
		if e.created {
			return errors.New("initial systemd port sidecar install result was uncertain")
		}
		return errors.New("install initial systemd port sidecar without replacing an existing file")
	}
	if !e.created ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() ||
		pathInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(pathInfo, 0) {
		return errors.New("initial systemd port sidecar installed with unsafe ownership or mode")
	}
	if err := os.Remove(e.tempPath); err != nil {
		return errors.New("initial systemd port sidecar installed but temporary link cleanup failed")
	}
	e.tempPath = ""
	return nil
}
