package hostruntime

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	dockerPortPreparePrefix  = ".port-prepare-"
	dockerPortRecreatePrefix = ".port-recreate-"
	dockerPortTransientMax   = 16 << 20
)

func cleanupDockerPortTransientOrphans(
	base string,
	requireRootOwned bool,
) error {
	if err := validateDockerPortTransientBase(base, requireRootOwned); err != nil {
		return err
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return errors.New("read Docker port work directory")
	}
	matched := 0
	for _, entry := range entries {
		if !isDockerPortTransientName(entry.Name()) {
			continue
		}
		matched++
		if matched > 64 {
			return errors.New("too many Docker port transient directories")
		}
		if err := secureRemoveDockerPortTransient(
			base, filepath.Join(base, entry.Name()), requireRootOwned,
		); err != nil {
			return err
		}
	}
	return nil
}

func secureRemoveDockerPortTransient(
	base string,
	directory string,
	requireRootOwned bool,
) error {
	base = filepath.Clean(base)
	directory = filepath.Clean(directory)
	if filepath.Dir(directory) != base ||
		!isDockerPortTransientName(filepath.Base(directory)) ||
		!pathWithin(base, directory) {
		return errors.New("Docker port transient path escaped its work directory")
	}
	if err := validateDockerPortTransientBase(base, requireRootOwned); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil ||
		systemdPortLinkOrReparse(info) ||
		!info.IsDir() ||
		runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 ||
		requireRootOwned && !isRootOwner(info) {
		return errors.New("Docker port transient directory is invalid")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) > 8 {
		return errors.New("Docker port transient directory is unreadable or unbounded")
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		entryInfo, statErr := os.Lstat(path)
		if statErr != nil ||
			systemdPortLinkOrReparse(entryInfo) ||
			!entryInfo.Mode().IsRegular() ||
			entryInfo.Size() < 0 ||
			entryInfo.Size() > dockerPortTransientMax ||
			runtime.GOOS != "windows" && entryInfo.Mode().Perm() != 0o600 ||
			requireRootOwned && !isRootOwner(entryInfo) {
			return errors.New("Docker port transient file is invalid")
		}
		if err := wipeAndUnlinkDockerPortTransientFile(
			path, entryInfo, requireRootOwned,
		); err != nil {
			return err
		}
	}
	if err := syncDirectory(directory); err != nil {
		return errors.New("sync wiped Docker port transient directory")
	}
	current, err := os.Lstat(directory)
	if err != nil || !os.SameFile(info, current) {
		return errors.New("Docker port transient directory changed before unlink")
	}
	if err := os.Remove(directory); err != nil {
		return errors.New("remove Docker port transient directory")
	}
	if err := syncDirectory(base); err != nil {
		return errors.New("sync Docker port work directory")
	}
	return nil
}

func wipeAndUnlinkDockerPortTransientFile(
	path string,
	expected os.FileInfo,
	requireRootOwned bool,
) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return errors.New("open Docker port transient file for wipe")
	}
	opened, statErr := file.Stat()
	if statErr != nil ||
		!opened.Mode().IsRegular() ||
		!os.SameFile(expected, opened) ||
		opened.Size() != expected.Size() ||
		opened.Mode() != expected.Mode() ||
		requireRootOwned &&
			validateRootOwnedFileAndParents(
				path, opened, "Docker port transient file",
			) != nil {
		_ = file.Close()
		return errors.New("Docker port transient file changed during secure open")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return errors.New("seek Docker port transient file for wipe")
	}
	zeroes := make([]byte, 32<<10)
	remaining := opened.Size()
	for remaining > 0 {
		chunk := int64(len(zeroes))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := file.Write(zeroes[:int(chunk)]); err != nil {
			_ = file.Close()
			return errors.New("wipe Docker port transient file")
		}
		remaining -= chunk
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync wiped Docker port transient file")
	}
	if err := file.Close(); err != nil {
		return errors.New("close wiped Docker port transient file")
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(expected, current) {
		return errors.New("Docker port transient file changed before unlink")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("unlink wiped Docker port transient file")
	}
	return nil
}

func validateDockerPortTransientBase(
	base string,
	requireRootOwned bool,
) error {
	if !filepath.IsAbs(base) {
		return errors.New("Docker port work directory is invalid")
	}
	info, err := os.Lstat(base)
	if err != nil ||
		systemdPortLinkOrReparse(info) ||
		!info.IsDir() ||
		runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		return errors.New("Docker port work directory is not private")
	}
	if requireRootOwned && validateSecureRootPath(base, true) != nil {
		return errors.New("Docker port work directory is not root-controlled")
	}
	return nil
}

func isDockerPortTransientName(name string) bool {
	return strings.HasPrefix(name, dockerPortPreparePrefix) ||
		strings.HasPrefix(name, dockerPortRecreatePrefix)
}
