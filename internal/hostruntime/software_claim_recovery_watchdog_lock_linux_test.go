//go:build linux

package hostruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func softwareClaimRecoveryWatchdogLockChecks(t *testing.T) {
	for _, name := range []string{"held", "released", "closed", "raw_unlock", "read_lock", "mode", "hardlink", "replaced_inode", "directory_mode", "foreign_pid", "unminted", "bad_alias"} {
		t.Run("watchdog_lock/"+name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, heldHostLifecycleLockFileName)
			held, err := acquireHeldHostLifecycleLockAt(path, true)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Release()
			switch name {
			case "released":
				held.Release()
			case "closed":
				if held.file.Close() != nil {
					t.Fatal("fixture close failed")
				}
			case "raw_unlock":
				if syscall.Flock(int(held.file.Fd()), syscall.LOCK_UN) != nil {
					t.Fatal("fixture unlock failed")
				}
			case "read_lock":
				if syscall.Flock(int(held.file.Fd()), syscall.LOCK_SH) != nil {
					t.Fatal("fixture downgrade failed")
				}
			case "mode":
				if os.Chmod(path, 0o644) != nil {
					t.Fatal("fixture chmod failed")
				}
			case "hardlink":
				if os.Link(path, filepath.Join(root, "same-inode")) != nil {
					t.Fatal("fixture hardlink failed")
				}
			case "replaced_inode":
				if os.Rename(path, filepath.Join(root, "original-inode")) != nil || os.WriteFile(path, nil, 0o600) != nil {
					t.Fatal("fixture replacement failed")
				}
			case "directory_mode":
				if os.Chmod(root, 0o755) != nil {
					t.Fatal("fixture directory chmod failed")
				}
			case "foreign_pid":
				held.ownerPID++
			case "unminted":
				held.minted = false
			case "bad_alias":
				if held.MatchesPath("/proc/01/root"+path) == nil {
					t.Fatal("noncanonical process alias was accepted")
				}
				return
			}
			if err := held.Verify(); (name == "held") != (err == nil) {
				t.Fatalf("actual lock lifetime boundary: %v", err)
			}
			// A forged/released capability must not cause the test's actual FD to leak.
			if name == "foreign_pid" || name == "unminted" {
				held.ownerPID, held.minted = os.Getpid(), true
			}
		})
	}
	t.Run("watchdog_lock/kernel_record_closed", func(t *testing.T) {
		stat := syscall.Stat_t{Dev: 123, Ino: 456}
		line := fmt.Sprintf("lock: 1: FLOCK ADVISORY WRITE %d %x:%x:%d 0 EOF", os.Getpid(), unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)), stat.Ino)
		if !heldHostLifecycleKernelRecordMatches(strings.Fields(line), stat, os.Getpid()) {
			t.Fatal("valid closed kernel record was refused")
		}
		for _, change := range []struct{ old, new string }{{"FLOCK", "POSIX"}, {"ADVISORY", "MANDATORY"}, {"WRITE", "READ"}, {"1:", "unknown:"}, {"0 EOF", "1 EOF"}, {"EOF", "999"}, {strconv.Itoa(os.Getpid()), "-1"}, {":456", ":457"}} {
			if heldHostLifecycleKernelRecordMatches(strings.Fields(strings.Replace(line, change.old, change.new, 1)), stat, os.Getpid()) {
				t.Fatal("altered kernel lock record was accepted")
			}
		}
	})
}
