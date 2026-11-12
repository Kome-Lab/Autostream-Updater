//go:build linux

package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const guardTestBoot = "12345678-1234-1234-1234-123456789abc"

func guardSyntheticStat(pid, ticks string) []byte {
	fields := make([]string, 20)
	fields[0] = "S"
	for index := 1; index < len(fields); index++ {
		fields[index] = "0"
	}
	fields[19] = ticks
	return []byte(pid + " (synthetic ) executor) " + strings.Join(fields, " "))
}

func TestSQLiteGuardLocalIdentityFixedPathsAndDetachedFacts(t *testing.T) {
	var paths []string
	reads := func(path string, maximum int64) ([]byte, error) {
		paths = append(paths, path)
		switch path {
		case "/proc/sys/kernel/random/boot_id":
			if maximum != 128 {
				t.Fatal("boot bound")
			}
			return []byte(guardTestBoot + "\n"), nil
		case "/proc/self/stat":
			if maximum != 64<<10 {
				t.Fatal("stat bound")
			}
			return guardSyntheticStat("123", "456"), nil
		default:
			t.Fatal("unapproved path")
			return nil, errors.New("unexpected")
		}
	}
	got, err := observeLocalExecutorIdentity(context.Background(), 123, reads)
	want := LocalExecutorIdentity{Knowledge: Known, BootID: guardTestBoot, ProcessID: 123, StartTicks: 456}
	if err != nil || got != want {
		t.Fatalf("identity=%+v err=%v", got, err)
	}
	expectedPaths := []string{"/proc/sys/kernel/random/boot_id", "/proc/self/stat", "/proc/sys/kernel/random/boot_id", "/proc/self/stat"}
	if !reflect.DeepEqual(paths, expectedPaths) {
		t.Fatalf("paths=%v", paths)
	}
}

func TestSQLiteGuardLocalIdentityMalformedAndChanged(t *testing.T) {
	cases := []struct {
		name string
		boot []byte
		stat []byte
		pid  uint64
	}{
		{"empty-boot", nil, guardSyntheticStat("123", "456"), 123},
		{"invalid-uuid", []byte("not-boot"), guardSyntheticStat("123", "456"), 123},
		{"uppercase-uuid", []byte(strings.ToUpper(guardTestBoot)), guardSyntheticStat("123", "456"), 123},
		{"wrong-pid", []byte(guardTestBoot), guardSyntheticStat("124", "456"), 123},
		{"zero-ticks", []byte(guardTestBoot), guardSyntheticStat("123", "0"), 123},
		{"overflow-ticks", []byte(guardTestBoot), guardSyntheticStat("123", "18446744073709551616"), 123},
		{"short-stat", []byte(guardTestBoot), []byte("123 (x) S"), 123},
		{"bad-comm", []byte(guardTestBoot), []byte("123 invalid S"), 123},
		{"oversize", []byte(guardTestBoot), []byte(strings.Repeat("x", 65<<10)), 123},
		{"zero-pid", []byte(guardTestBoot), guardSyntheticStat("123", "456"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLocalExecutorIdentity(tc.boot, tc.stat, tc.pid)
			if err == nil || got != (LocalExecutorIdentity{Knowledge: Unknown}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
	for _, change := range []string{"boot", "process"} {
		t.Run("changed-"+change, func(t *testing.T) {
			calls := 0
			got, err := observeLocalExecutorIdentity(context.Background(), 123, func(path string, _ int64) ([]byte, error) {
				calls++
				if path == "/proc/sys/kernel/random/boot_id" {
					if change == "boot" && calls > 2 {
						return []byte("22345678-1234-1234-1234-123456789abc"), nil
					}
					return []byte(guardTestBoot), nil
				}
				if change == "process" && calls > 2 {
					return guardSyntheticStat("123", "457"), nil
				}
				return guardSyntheticStat("123", "456"), nil
			})
			if err == nil || got != (LocalExecutorIdentity{Knowledge: Unknown}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestSQLiteGuardLocalIdentityCancellationAndSafeErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	got, err := observeLocalExecutorIdentity(ctx, 123, func(path string, _ int64) ([]byte, error) {
		calls++
		cancel()
		return []byte(guardTestBoot), nil
	})
	if !errors.Is(err, context.Canceled) || got.Knowledge != Unknown || calls != 1 {
		t.Fatalf("got=%+v err=%v calls=%d", got, err, calls)
	}
	for _, position := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+position)), func(t *testing.T) {
			n := 0
			got, err := observeLocalExecutorIdentity(context.Background(), 123, func(path string, _ int64) ([]byte, error) {
				n++
				if n == position {
					return nil, errors.New("private-path secret-value raw-error")
				}
				if path == "/proc/sys/kernel/random/boot_id" {
					return []byte(guardTestBoot), nil
				}
				return guardSyntheticStat("123", "456"), nil
			})
			if err == nil || got.Knowledge != Unknown || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe result=%+v error=%v", got, err)
			}
		})
	}
}

func TestSQLiteGuardLocalIdentityBoundedFiles(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		limit         int64
		ok            bool
	}{
		{"bounded", "synthetic", 9, true}, {"empty", "", 9, false}, {"oversized", "synthetic-extra", 9, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			data, err := readLocalIdentityFile(path, tc.limit)
			if tc.ok {
				if err != nil || string(data) != tc.content {
					t.Fatalf("data=%q err=%v", data, err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid fixture")
			}
		})
	}
}
