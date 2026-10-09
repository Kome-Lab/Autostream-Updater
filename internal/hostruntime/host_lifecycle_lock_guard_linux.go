//go:build linux

package hostruntime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const heldHostLifecycleLockFileName = ".autostream-host-lifecycle.lock"

// The capability owns an actual locked file description, not a busy-lock
// observation. Its private test namespace never authorizes production reads.
type heldHostLifecycleLock struct {
	mu             sync.Mutex
	file           *os.File
	stat           syscall.Stat_t
	directory      syscall.Stat_t
	path           string
	ownerPID       int
	allowTestPaths bool
	minted         bool
	released       bool
}

func acquireHeldHostLifecycleLockAt(path string, allowTestPaths bool) (*heldHostLifecycleLock, error) {
	canonical := filepath.Join(privilegedLockDir(), heldHostLifecycleLockFileName)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Base(path) != heldHostLifecycleLockFileName || (!allowTestPaths && path != canonical) {
		return nil, errors.New("held Host lifecycle lock path is invalid")
	}
	uid, gid := uint32(0), uint32(0)
	if allowTestPaths {
		uid, gid = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	var directory syscall.Stat_t
	if syscall.Lstat(filepath.Dir(path), &directory) != nil || directory.Uid != uid || directory.Gid != gid ||
		directory.Mode&syscall.S_IFMT != syscall.S_IFDIR || directory.Mode&0o777 != 0o700 {
		return nil, errors.New("privileged Host lock directory is unsafe")
	}
	file, err := openAndLockManualHostUpgradeFile(path, uid, gid)
	if err != nil {
		return nil, err
	}
	held := &heldHostLifecycleLock{file: file, directory: directory, path: path, ownerPID: os.Getpid(),
		allowTestPaths: allowTestPaths, minted: true}
	if syscall.Fstat(int(file.Fd()), &held.stat) != nil {
		held.Release()
		return nil, errors.New("held Host lifecycle lock file is unavailable")
	}
	if err := held.Verify(); err != nil {
		held.Release()
		return nil, err
	}
	return held, nil
}

func (held *heldHostLifecycleLock) Verify() error {
	if held == nil {
		return errors.New("held Host lifecycle lock is unavailable")
	}
	held.mu.Lock()
	defer held.mu.Unlock()
	return held.verifyLocked()
}

func (held *heldHostLifecycleLock) verifyLocked() error {
	if !held.minted || held.released || held.file == nil || held.ownerPID != os.Getpid() ||
		!filepath.IsAbs(held.path) || filepath.Clean(held.path) != held.path ||
		filepath.Base(held.path) != heldHostLifecycleLockFileName ||
		(!held.allowTestPaths && held.path != filepath.Join(privilegedLockDir(), heldHostLifecycleLockFileName)) {
		return errors.New("held Host lifecycle lock is unavailable")
	}
	var opened, named, directory syscall.Stat_t
	if syscall.Fstat(int(held.file.Fd()), &opened) != nil ||
		syscall.Lstat(held.path, &named) != nil ||
		!heldHostLifecycleNodeMatches(opened, held.stat, syscall.S_IFREG|0o600) ||
		!heldHostLifecycleNodeMatches(named, held.stat, syscall.S_IFREG|0o600) || opened.Nlink != 1 || named.Nlink != 1 ||
		syscall.Lstat(filepath.Dir(held.path), &directory) != nil ||
		!heldHostLifecycleNodeMatches(directory, held.directory, syscall.S_IFDIR|0o700) {
		return errors.New("held Host lifecycle lock identity changed")
	}
	return held.verifyKernelOwnership(opened)
}

func heldHostLifecycleNodeMatches(got, want syscall.Stat_t, mode uint32) bool {
	return got.Dev == want.Dev && got.Ino == want.Ino && got.Uid == want.Uid && got.Gid == want.Gid &&
		got.Mode&(syscall.S_IFMT|0o777) == mode
}

func (held *heldHostLifecycleLock) verifyKernelOwnership(stat syscall.Stat_t) error {
	// fdinfo belongs to this process and actual retained FD. It does not reacquire
	// a lock or expose any kernel metadata through the RPC response or logs.
	path := "/proc/self/fdinfo/" + strconv.FormatUint(uint64(held.file.Fd()), 10)
	file, err := os.Open(path)
	if err != nil {
		return errors.New("held Host lifecycle kernel lock is unconfirmed")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, (16<<10)+1))
	if err != nil || len(body) == 0 || len(body) > 16<<10 {
		return errors.New("held Host lifecycle kernel lock is unconfirmed")
	}
	count := 0
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "lock:" {
			continue
		}
		count++
		if count != 1 || !heldHostLifecycleKernelRecordMatches(fields, stat, held.ownerPID) {
			return errors.New("held Host lifecycle kernel lock is unconfirmed")
		}
	}
	if count != 1 {
		return errors.New("held Host lifecycle kernel lock is unconfirmed")
	}
	return nil
}

func heldHostLifecycleKernelRecordMatches(fields []string, stat syscall.Stat_t, pid int) bool {
	if len(fields) != 9 || fields[0] != "lock:" || !strings.HasSuffix(fields[1], ":") ||
		fields[2] != "FLOCK" || fields[3] != "ADVISORY" || fields[4] != "WRITE" ||
		fields[5] != strconv.Itoa(pid) || fields[7] != "0" || fields[8] != "EOF" {
		return false
	}
	ordinal, err := strconv.ParseUint(strings.TrimSuffix(fields[1], ":"), 10, 64)
	if err != nil || ordinal < 1 {
		return false
	}
	device := strings.Split(fields[6], ":")
	if len(device) != 3 || device[2] != strconv.FormatUint(stat.Ino, 10) {
		return false
	}
	// Linux fdinfo prints device major/minor in hexadecimal, inode in decimal.
	major, majorErr := strconv.ParseUint(device[0], 16, 32)
	minor, minorErr := strconv.ParseUint(device[1], 16, 32)
	return majorErr == nil && minorErr == nil && uint32(major) == unix.Major(uint64(stat.Dev)) &&
		uint32(minor) == unix.Minor(uint64(stat.Dev))
}

// The caller supplies only a /proc/<validated-watchdog-pid>/root alias of the
// fixed lock. Equal dev/inode proves that watchdog's view shares our lease.
func (held *heldHostLifecycleLock) MatchesPath(path string) error {
	if held == nil {
		return errors.New("held Host lifecycle lock is unavailable")
	}
	held.mu.Lock()
	defer held.mu.Unlock()
	if err := held.verifyLocked(); err != nil {
		return err
	}
	parts := strings.SplitN(strings.TrimPrefix(path, "/proc/"), "/", 2)
	if !strings.HasPrefix(path, "/proc/") || len(parts) != 2 {
		return errors.New("watchdog Host lifecycle lock alias is invalid")
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid < 1 || parts[0] != strconv.Itoa(pid) ||
		path != "/proc/"+parts[0]+"/root"+held.path {
		return errors.New("watchdog Host lifecycle lock alias is invalid")
	}
	var named syscall.Stat_t
	if err := syscall.Lstat(path, &named); err != nil {
		return fmt.Errorf("watchdog Host lifecycle lock view is unconfirmed: %w", err)
	}
	if named.Nlink != 1 ||
		!heldHostLifecycleNodeMatches(named, held.stat, syscall.S_IFREG|0o600) {
		return errors.New("watchdog Host lifecycle lock view is unconfirmed")
	}
	return nil
}

func (held *heldHostLifecycleLock) Release() {
	if held == nil {
		return
	}
	held.mu.Lock()
	defer held.mu.Unlock()
	if held.released {
		return
	}
	held.released = true
	if held.minted && held.ownerPID == os.Getpid() && held.file != nil {
		_ = syscall.Flock(int(held.file.Fd()), syscall.LOCK_UN)
		_ = held.file.Close()
	}
}
