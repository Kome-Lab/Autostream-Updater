//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func softwareClaimRecoveryWatchdogProcessChecks(t *testing.T) {
	softwareClaimRecoveryR2InitialENOENTChecks(t)
	for _, name := range []string{"trusted_live", "gone_then_zero", "startup_then_zero", "foreign_exe", "foreign_command", "foreign_uid", "foreign_gid", "foreign_cgroup", "foreign_member", "too_many_members", "different_lock", "same_path_other_inode", "different_binary_namespace", "recycled_inode", "recycled_pid", "unit_changed", "cgroup_read_error", "malformed_identity", "never_settles", "deadline"} {
		t.Run("watchdog_process/"+name, func(t *testing.T) {
			root := "/protected-fixture/slots"
			group := "/system.slice/autostream-host-self-update-recovery@a.service"
			units := []softwareClaimRecoveryWatchdogUnit{{slot: "a", state: "activating", mainPID: 42, controlGroup: group, staticIdentity: "a"}, {slot: "b", state: "inactive", staticIdentity: "b"}}
			path := root + "/a/bin/autostream-local-executor"
			physical := filepath.Join(t.TempDir(), "executor")
			if err := os.WriteFile(physical, []byte("fixture executor\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			trustedInfo, err := os.Stat(physical)
			if err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(t.TempDir(), "executor")
			if err := os.WriteFile(foreign, []byte("fixture executor\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			foreignInfo, err := os.Stat(foreign)
			if err != nil {
				t.Fatal(err)
			}
			observation := softwareClaimWatchdogProcessObservation{start: 1, exe: path, exeInfo: trustedInfo, command: []byte(path + "\x00recover-self-update\x00--recovery-slot\x00a\x00"), credentials: []byte("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"), cgroup: []byte("0::" + group + "\n")}
			reads, joins, lockChecks := 0, 0, 0
			reader := softwareClaimWatchdogProcessRuntime{
				read: func(int) (softwareClaimWatchdogProcessObservation, error) {
					reads++
					value := observation
					switch name {
					case "gone_then_zero", "unit_changed":
						return value, os.ErrNotExist
					case "startup_then_zero":
						value.exe = "/usr/lib/systemd/systemd-executor"
					case "foreign_exe":
						value.exe = "/foreign"
					case "same_path_other_inode":
						value.exeInfo = foreignInfo
					case "recycled_inode":
						if reads > 1 {
							value.exeInfo = foreignInfo
						}
					case "foreign_command":
						value.command = []byte(path + "\x00run\x00")
					case "foreign_uid":
						value.credentials = []byte("Uid: 1 1 1 1\nGid: 0 0 0 0\n")
					case "foreign_gid":
						value.credentials = []byte("Uid: 0 0 0 0\nGid: 1 1 1 1\n")
					case "foreign_cgroup":
						value.cgroup = []byte("0::/another.service\n")
					case "recycled_pid":
						if reads > 1 {
							value.start = 2
						}
					case "malformed_identity":
						value.start = 0
					}
					return value, nil
				},
				binary: func(_ context.Context, _ int, _ string, info os.FileInfo) error {
					if name == "different_binary_namespace" || !sameSoftwareClaimWatchdogBinaryInfo(trustedInfo, info) {
						return errors.New("binary inode or namespace mismatch")
					}
					return nil
				},
				sameLock: func(int) error {
					lockChecks++
					if name == "different_lock" {
						return errors.New("not the same lock inode")
					}
					return nil
				},
				members: func(string) ([]int, error) {
					switch name {
					case "foreign_member":
						return []int{43}, nil
					case "too_many_members":
						return []int{42, 43, 44}, nil
					case "cgroup_read_error":
						return nil, errors.New("cgroup observation denied")
					case "never_settles":
						return nil, nil
					}
					return []int{42}, nil
				},
				units: func(context.Context) ([]softwareClaimRecoveryWatchdogUnit, error) {
					joins++
					next := append([]softwareClaimRecoveryWatchdogUnit(nil), units...)
					if name == "unit_changed" {
						next[0].staticIdentity = "changed"
					}
					if name == "gone_then_zero" || name == "startup_then_zero" {
						next[0].state, next[0].mainPID, next[0].controlGroup = "failed", 0, ""
					}
					return next, nil
				},
			}
			ctx := context.Background()
			if name == "deadline" {
				expired, cancel := context.WithTimeout(ctx, time.Nanosecond)
				defer cancel()
				<-expired.Done()
				ctx = expired
			}
			err = verifySoftwareClaimWatchdogProcessRuntime(ctx, root, units, nil, reader)
			positive := name == "trusted_live" || name == "gone_then_zero" || name == "startup_then_zero"
			if positive && err != nil || !positive && err == nil {
				t.Fatalf("watchdog identity boundary result: %v", err)
			}
			if name == "trusted_live" && (reads != 2 || lockChecks != 1 || joins != 0) {
				t.Fatal("trusted live process was not pinned without retries")
			}
			if (name == "gone_then_zero" || name == "startup_then_zero") && joins != 1 {
				t.Fatal("trusted transition was not joined exactly once")
			}
			if name == "never_settles" && joins != 3 {
				t.Fatal("read-only transition join was not bounded")
			}
		})
	}
	t.Run("watchdog_process/root_credentials_closed", func(t *testing.T) {
		for _, data := range []string{"", "Uid: 0 0 0 0\n", "Uid: 0 0 0 0\nUid: 0 0 0 0\nGid: 0 0 0 0\n", "Uid: 0 0 0\nGid: 0 0 0 0\n", "Uid: 0 0 0 0\nGid: 0 0 0 1\n"} {
			if softwareClaimWatchdogRootCredentials([]byte(data)) {
				t.Fatal("ambiguous root credentials were accepted")
			}
		}
	})
	t.Run("watchdog_process/closed_diagnostic_reason", func(t *testing.T) {
		d := newSoftwareClaimRecoveryRootRefusal(SoftwareClaimRecoveryRequest{})
		d.LifecycleHeld, d.Phase, d.WatchdogGuard = true, "watchdog_guard", "unit_exec_start"
		if !d.valid() {
			t.Fatal("closed watchdog refusal diagnostic is invalid")
		}
		for _, bad := range []string{"", "private-raw-value", "unit_property_unknown", strings.Repeat("x", 128)} {
			d.WatchdogGuard = bad
			if d.valid() {
				t.Fatal("unbounded watchdog reason was accepted")
			}
		}
	})
}
