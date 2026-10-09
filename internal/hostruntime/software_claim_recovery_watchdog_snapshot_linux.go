//go:build linux

package hostruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func snapshotSoftwareClaimWatchdogFile(ctx context.Context, path string, mode os.FileMode, allowTestPaths bool) (secureManualHostUpgradeFile, error) {
	var result secureManualHostUpgradeFile
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return result, softwareClaimWatchdogRefusal("slot_file")
	}
	before, err := os.Lstat(path)
	if err != nil || !softwareClaimWatchdogSnapshotInfoSafe(before, mode, allowTestPaths) ||
		(!allowTestPaths && validateSecureRootPath(path, false) != nil) || ctx.Err() != nil {
		return result, softwareClaimWatchdogRefusal("slot_file")
	}
	// Read the verified opened FD itself. O_NONBLOCK also prevents a raced FIFO
	// replacement from blocking before its type is rejected by Fstat.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return result, softwareClaimWatchdogRefusal("slot_file")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return result, softwareClaimWatchdogRefusal("slot_file")
	}
	defer file.Close()
	if err := verifySoftwareClaimWatchdogSnapshotFile(ctx, path, mode, allowTestPaths, before, file); err != nil {
		return result, err
	}
	digest, err := hashSoftwareClaimWatchdogReader(ctx, file, before.Size())
	if err != nil {
		return result, err
	}
	if err := verifySoftwareClaimWatchdogSnapshotFile(ctx, path, mode, allowTestPaths, before, file); err != nil {
		return result, err
	}
	return secureManualHostUpgradeFile{path: path, info: before, digest: digest}, nil
}

func verifySoftwareClaimWatchdogSnapshotFile(ctx context.Context, path string, mode os.FileMode, allowTestPaths bool, before os.FileInfo, file *os.File) error {
	if ctx == nil || ctx.Err() != nil || file == nil || !softwareClaimWatchdogSnapshotInfoSafe(before, mode, allowTestPaths) {
		return softwareClaimWatchdogRefusal("slot_file")
	}
	opened, openedErr := file.Stat()
	named, namedErr := os.Lstat(path)
	if openedErr != nil || namedErr != nil ||
		!softwareClaimWatchdogSnapshotInfoSafe(opened, mode, allowTestPaths) ||
		!softwareClaimWatchdogSnapshotInfoSafe(named, mode, allowTestPaths) ||
		!softwareClaimWatchdogSnapshotInfoMatches(before, opened) ||
		!softwareClaimWatchdogSnapshotInfoMatches(before, named) ||
		(!allowTestPaths && validateSecureRootPath(path, false) != nil) || ctx.Err() != nil {
		return softwareClaimWatchdogRefusal("slot_file")
	}
	return nil
}

func softwareClaimWatchdogSnapshotInfoSafe(info os.FileInfo, mode os.FileMode, allowTestPaths bool) bool {
	if info == nil || mode != mode.Perm() || !info.Mode().IsRegular() || info.Mode() != mode ||
		info.Size() <= 0 || info.Size() > defaultMaxArtifactBytes {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	uid, gid := uint32(0), uint32(0)
	if allowTestPaths {
		uid, gid = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	return ok && stat != nil && stat.Nlink == 1 && stat.Uid == uid && stat.Gid == gid && stat.Size == info.Size() &&
		stat.Mode&(syscall.S_IFMT|0o7777) == syscall.S_IFREG|uint32(mode)
}

func softwareClaimWatchdogSnapshotInfoMatches(want, got os.FileInfo) bool {
	if want == nil || got == nil || want.Mode() != got.Mode() ||
		want.Size() != got.Size() || !want.ModTime().Equal(got.ModTime()) {
		return false
	}
	first, firstOK := want.Sys().(*syscall.Stat_t)
	second, secondOK := got.Sys().(*syscall.Stat_t)
	return firstOK && secondOK && first != nil && second != nil && first.Dev == second.Dev && first.Ino == second.Ino &&
		first.Uid == second.Uid && first.Gid == second.Gid &&
		first.Nlink == second.Nlink && first.Mtim == second.Mtim && first.Ctim == second.Ctim
}

// This helper also hashes an already verified /proc/exe FD for the private
// watchdog reader. Its caller retains responsibility for that FD's authority.
func hashSoftwareClaimWatchdogReader(ctx context.Context, reader io.Reader, expectedSize int64) (string, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || expectedSize <= 0 || expectedSize > defaultMaxArtifactBytes {
		return "", softwareClaimWatchdogRefusal("slot_file")
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var total int64
	for total < expectedSize {
		if ctx.Err() != nil {
			return "", softwareClaimWatchdogRefusal("slot_file")
		}
		maximum := int64(len(buffer))
		if remaining := expectedSize - total; remaining < maximum {
			maximum = remaining
		}
		count, err := reader.Read(buffer[:int(maximum)])
		if ctx.Err() != nil || count < 0 || int64(count) > maximum || count == 0 {
			return "", softwareClaimWatchdogRefusal("slot_file")
		}
		_, _ = hash.Write(buffer[:count])
		total += int64(count)
		if err != nil && (err != io.EOF || total != expectedSize) {
			return "", softwareClaimWatchdogRefusal("slot_file")
		}
	}
	if ctx.Err() != nil {
		return "", softwareClaimWatchdogRefusal("slot_file")
	}
	var trailing [1]byte
	count, err := reader.Read(trailing[:])
	if ctx.Err() != nil || count != 0 || err != io.EOF {
		return "", softwareClaimWatchdogRefusal("slot_file")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
