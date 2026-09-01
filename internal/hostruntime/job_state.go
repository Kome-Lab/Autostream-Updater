package hostruntime

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

var jobDirectoryPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

func jobsRoot(stateDir string) string { return filepath.Join(stateDir, "jobs") }

func jobDirectory(stateDir, jobID string) string {
	return filepath.Join(jobsRoot(stateDir), shortID(jobID))
}

func ensurePrivateJobDirectory(stateDir, jobID string) (string, error) {
	root := jobsRoot(stateDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !privateJobDirectoryInfo(rootInfo) {
		return "", errors.New("jobs state root must be a private non-symlink directory")
	}
	path := jobDirectory(stateDir, jobID)
	if !pathWithin(root, path) || !jobDirectoryPattern.MatchString(filepath.Base(path)) {
		return "", errors.New("job state path is invalid")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return "", err
		}
		if err := syncDirectory(root); err != nil {
			return "", err
		}
		return path, nil
	}
	if err != nil || !privateJobDirectoryInfo(info) {
		return "", errors.New("job state path must be a private non-symlink directory")
	}
	return path, nil
}

func privateJobDirectoryInfo(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && (runtime.GOOS == "windows" || info.Mode().Perm()&0o077 == 0)
}

func cleanupJobDirectory(stateDir, jobID string) error {
	root := jobsRoot(stateDir)
	rootInfo, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("jobs state root is unsafe")
	}
	path := jobDirectory(stateDir, jobID)
	if !pathWithin(root, path) || !jobDirectoryPattern.MatchString(filepath.Base(path)) {
		return errors.New("refusing unsafe job state cleanup")
	}
	if err := removeBoundedJobEntry(path); err != nil {
		return err
	}
	return syncDirectory(root)
}

func removeBoundedJobEntry(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(path)
	}
	if !info.IsDir() {
		return errors.New("job state entry is not a directory")
	}
	count := 0
	err = filepath.WalkDir(path, func(_ string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 4096 {
			return errors.New("job state cleanup exceeds the bounded entry count")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(path)
}

func garbageCollectJobDirectories(stateDir string, journal *Journal) error {
	root := jobsRoot(stateDir)
	rootInfo, statErr := os.Lstat(root)
	if errors.Is(statErr, os.ErrNotExist) {
		return nil
	}
	if statErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("jobs state root is unsafe")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) > 1024 {
		return errors.New("jobs state root exceeds the bounded directory count")
	}
	protected := map[string]bool{}
	if active := journal.Active(); active != nil {
		protected[shortID(active.ID)] = true
	}
	for _, pending := range journal.Pending() {
		protected[shortID(pending.JobID)] = true
	}
	changed := false
	for _, entry := range entries {
		name := entry.Name()
		if !jobDirectoryPattern.MatchString(name) || protected[name] {
			continue
		}
		if err := removeBoundedJobEntry(filepath.Join(root, name)); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		return syncDirectory(root)
	}
	return nil
}
