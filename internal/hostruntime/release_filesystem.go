package hostruntime

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func installReleaseTree(source, dest, digest, version string) error {
	if info, err := os.Lstat(dest); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("release destination already exists and is not a directory")
		}
		if err := verifyManagedReleaseChecksums(dest); err != nil {
			return errors.New("existing release destination failed integrity verification")
		}
		existing, _ := os.ReadFile(filepath.Join(dest, ".artifact-sha256"))
		existingVersion, _ := os.ReadFile(filepath.Join(dest, ".version"))
		if strings.TrimSpace(string(existing)) != strings.ToLower(digest) || strings.TrimSpace(string(existingVersion)) != version {
			return errors.New("release destination already exists with a different digest")
		}
		// A release produced by an older helper may have correct immutable
		// contents but UMask-restricted 0700/0600 modes. Re-normalizing a
		// checksum-verified, identity-matched tree is safe and makes retries
		// self-healing instead of requiring operator deletion.
		if err := normalizeInstalledReleaseTreeModes(dest); err != nil {
			return err
		}
		return firstError(syncDirectoryTreeBottomUp(dest), syncDirectory(filepath.Dir(dest)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tempDest := dest + ".partial-" + shortID(digest+version)
	if !pathWithin(parent, tempDest) || filepath.Clean(tempDest) == filepath.Clean(parent) {
		return errors.New("partial release directory escaped release root")
	}
	if _, err := os.Lstat(tempDest); err == nil {
		if err := removeStaleReleasePartial(parent, tempDest); err != nil {
			return errors.New("stale partial release directory is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(tempDest, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tempDest, 0o755); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tempDest)
		}
	}()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || rel == "." {
			return err
		}
		out := filepath.Join(tempDest, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("staged release contains a symlink")
		}
		if entry.IsDir() {
			if err := os.Mkdir(out, 0o755); err != nil {
				return err
			}
			return os.Chmod(out, 0o755)
		}
		if !entry.Type().IsRegular() {
			return errors.New("staged release contains a non-regular file")
		}
		return copyRegularFile(path, out, info.Mode().Perm())
	})
	if err != nil {
		return err
	}
	if err := writeSyncedFile(filepath.Join(tempDest, ".artifact-sha256"), []byte(strings.ToLower(digest)+"\n"), 0o444); err != nil {
		return err
	}
	if err := writeSyncedFile(filepath.Join(tempDest, ".version"), []byte(version+"\n"), 0o444); err != nil {
		return err
	}
	// Do not publish a final release directory until the copied tree itself is
	// checksum-complete. The staged source was already verified, but this fence
	// prevents a partial copy or local I/O fault from stranding the deterministic
	// final destination and wedging every retry.
	if err := verifyManagedReleaseChecksums(tempDest); err != nil {
		return errors.New("copied release failed integrity verification")
	}
	if err := syncDirectoryTreeBottomUp(tempDest); err != nil {
		return err
	}
	if err := os.Rename(tempDest, dest); err != nil {
		return err
	}
	committed = true
	return syncDirectory(parent)
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	chmodErr := f.Chmod(mode)
	syncErr := f.Sync()
	closeErr := f.Close()
	return firstError(writeErr, chmodErr, syncErr, closeErr)
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func copyRegularFile(source, dest string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	mode = normalizedReleaseFileMode(mode)
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	chmodErr := out.Chmod(mode)
	syncErr := out.Sync()
	closeErr := out.Close()
	return firstError(copyErr, chmodErr, syncErr, closeErr)
}

func normalizedReleaseFileMode(source os.FileMode) os.FileMode {
	if source.Perm()&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

func normalizeInstalledReleaseTreeModes(root string) error {
	root = filepath.Clean(root)
	digestMarker := filepath.Join(root, ".artifact-sha256")
	versionMarker := filepath.Join(root, ".version")
	directories := make([]string, 0, 8)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("installed release contains a symlink")
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("installed release contains a non-regular file")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := os.FileMode(0o444)
		cleanPath := filepath.Clean(path)
		if cleanPath != digestMarker && cleanPath != versionMarker {
			mode = normalizedReleaseFileMode(info.Mode())
		}
		return chmodAndSyncRegularFile(path, info, mode)
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := os.Chmod(directories[index], 0o755); err != nil {
			return err
		}
	}
	return nil
}

func chmodAndSyncRegularFile(path string, expected os.FileInfo, mode os.FileMode) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	opened, statErr := f.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		_ = f.Close()
		return errors.New("installed release file changed during mode repair")
	}
	chmodErr := f.Chmod(mode)
	syncErr := f.Sync()
	closeErr := f.Close()
	return firstError(chmodErr, syncErr, closeErr)
}

func removeStaleReleasePartial(parent, partial string) error {
	parent = filepath.Clean(parent)
	partial = filepath.Clean(partial)
	if partial == parent || !pathWithin(parent, partial) {
		return errors.New("stale partial path escaped release root")
	}
	rootInfo, err := os.Lstat(partial)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !isRootOwner(rootInfo) {
		return errors.New("stale partial root is unsafe")
	}
	if err := filepath.WalkDir(partial, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("stale partial contains a symlink")
		}
		info, err := entry.Info()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) || !isRootOwner(info) {
			return errors.New("stale partial contains an unsafe entry")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := os.RemoveAll(partial); err != nil {
		return err
	}
	if _, err := os.Lstat(partial); !errors.Is(err, os.ErrNotExist) {
		return errors.New("stale partial removal was incomplete")
	}
	return syncDirectory(parent)
}

func syncDirectoryTreeBottomUp(root string) error {
	root = filepath.Clean(root)
	directories := make([]string, 0, 8)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("release tree contains a symlink")
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("release tree contains a non-regular file")
		}
		return nil
	}); err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
	}
	return nil
}
