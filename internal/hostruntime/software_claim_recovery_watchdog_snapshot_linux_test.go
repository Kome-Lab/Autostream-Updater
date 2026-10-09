//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The existing required root parent calls this helper; it creates only small
// private files and never changes a service or production path.
func softwareClaimRecoveryWatchdogSnapshotChecks(t *testing.T) {
	for _, name := range []string{"regular", "missing", "symlink", "hardlink", "directory", "empty", "mode", "special_mode", "pre_cancel", "production_temp_refused"} {
		t.Run("watchdog_snapshot/file/"+name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-binary")
			contents := []byte("small private watchdog bytes\n")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			allowTestPaths := true
			switch name {
			case "missing":
				path += "-absent"
			case "symlink":
				link := path + "-link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "hardlink":
				if err := os.Link(path, path+"-link"); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = filepath.Dir(path)
			case "empty":
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "mode", "special_mode":
				mode := os.FileMode(0o644)
				if name == "special_mode" {
					mode = 0o600 | os.ModeSetuid
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			case "pre_cancel":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			case "production_temp_refused":
				allowTestPaths = false
			}
			result, err := snapshotSoftwareClaimWatchdogFile(ctx, path, 0o600, allowTestPaths)
			if name == "regular" {
				expected := sha256.Sum256(contents)
				if err != nil || result.path != path || result.info == nil || result.digest != hex.EncodeToString(expected[:]) {
					t.Fatal("safe private file snapshot did not retain exact bytes and identity")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(contents, after) {
					t.Fatal("read-only snapshot changed its private input")
				}
				return
			}
			assertSoftwareClaimWatchdogSnapshotRefusal(t, result.digest, err)
			if result.info != nil || result.path != "" {
				t.Fatal("refused file published a partial snapshot")
			}
		})
	}

	for _, name := range []string{"unchanged", "replaced_inode", "size", "mode", "mtime", "hardlink", "closed_fd"} {
		t.Run("watchdog_snapshot/opened/"+name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "opened-binary")
			contents := []byte("opened private bytes\n")
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			switch name {
			case "replaced_inode":
				if os.Rename(path, path+"-original") != nil || os.WriteFile(path, contents, 0o600) != nil {
					t.Fatal("private inode replacement failed")
				}
			case "size":
				if err := os.WriteFile(path, append(contents, 'x'), 0o600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "mtime":
				changed := before.ModTime().Add(time.Second)
				if err := os.Chtimes(path, changed, changed); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+"-link"); err != nil {
					t.Fatal(err)
				}
			case "closed_fd":
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err = verifySoftwareClaimWatchdogSnapshotFile(context.Background(), path, 0o600, true, before, file)
			if name == "unchanged" {
				if err != nil {
					t.Fatal("unchanged actual opened FD refused")
				}
			} else {
				assertSoftwareClaimWatchdogSnapshotRefusal(t, "", err)
			}
		})
	}

	t.Run("watchdog_snapshot/metadata_closed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "metadata-binary")
		if err := os.WriteFile(path, []byte("private metadata bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		original, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !softwareClaimWatchdogSnapshotInfoSafe(info, 0o600, true) {
			t.Fatal("actual fixture metadata is not safe")
		}
		unchanged := softwareClaimWatchdogSnapshotTestInfo{FileInfo: info, stat: *original, size: info.Size()}
		if !softwareClaimWatchdogSnapshotInfoMatches(info, unchanged) {
			t.Fatal("unchanged exact dev/inode metadata was refused")
		}
		for _, name := range []string{"uid", "gid", "link_count", "size_limit", "ctime"} {
			t.Run(name, func(t *testing.T) {
				changed := softwareClaimWatchdogSnapshotTestInfo{FileInfo: info, stat: *original, size: info.Size()}
				switch name {
				case "uid":
					changed.stat.Uid++
				case "gid":
					changed.stat.Gid++
				case "link_count":
					changed.stat.Nlink++
				case "size_limit":
					changed.size = defaultMaxArtifactBytes + 1
				case "ctime":
					changed.stat.Ctim.Nsec++
				}
				if name != "ctime" && softwareClaimWatchdogSnapshotInfoSafe(changed, 0o600, true) {
					t.Fatal("unsafe owner, links or size metadata was accepted")
				}
				if softwareClaimWatchdogSnapshotInfoMatches(info, changed) {
					t.Fatal("changed metadata matched the original opened file")
				}
			})
		}
	})
	softwareClaimRecoveryWatchdogHashChecks(t)
}

func softwareClaimRecoveryWatchdogHashChecks(t *testing.T) {
	for _, name := range []string{"exact", "partial_reads", "eof_with_data", "truncated", "trailing", "read_error", "no_progress", "invalid_count", "zero_size", "negative_size", "over_limit_size", "pre_cancel", "cancel_after_first_chunk", "cancel_final_probe"} {
		t.Run("watchdog_snapshot/hash/"+name, func(t *testing.T) {
			contents := bytes.Repeat([]byte{'x'}, (32<<10)+17)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &softwareClaimWatchdogSnapshotTestReader{source: bytes.NewReader(contents)}
			expectedSize := int64(len(contents))
			switch name {
			case "partial_reads":
				reader.maximum = 13
			case "eof_with_data":
				reader.eofWithData = true
			case "truncated":
				expectedSize++
			case "trailing":
				expectedSize--
			case "read_error":
				reader.failure = errors.New("synthetic reader error with private text")
			case "no_progress":
				reader.noProgress = true
			case "invalid_count":
				reader.invalidCount = true
			case "zero_size":
				expectedSize = 0
			case "negative_size":
				expectedSize = -1
			case "over_limit_size":
				expectedSize = defaultMaxArtifactBytes + 1
			case "pre_cancel":
				cancel()
			case "cancel_after_first_chunk":
				reader.afterRead = func(calls int) {
					if calls == 1 {
						cancel()
					}
				}
			case "cancel_final_probe":
				reader.afterRead = func(calls int) {
					if calls == 3 {
						cancel()
					}
				}
			}
			digest, err := hashSoftwareClaimWatchdogReader(ctx, reader, expectedSize)
			if name == "exact" || name == "partial_reads" || name == "eof_with_data" {
				expected := sha256.Sum256(contents)
				if err != nil || digest != hex.EncodeToString(expected[:]) || reader.maximumRequested > 32<<10 {
					t.Fatal("bounded exact reader hash did not match original bytes")
				}
				return
			}
			assertSoftwareClaimWatchdogSnapshotRefusal(t, digest, err)
			if name == "cancel_after_first_chunk" && (reader.calls != 1 || reader.consumed != 32<<10 || ctx.Err() != context.Canceled) {
				t.Fatal("mid-read cancellation did not occur after real first-chunk consumption")
			}
			if name == "cancel_final_probe" && (reader.calls != 3 || reader.consumed != len(contents) || ctx.Err() != context.Canceled) {
				t.Fatal("final probe cancellation was not tested after all expected bytes")
			}
			if (name == "zero_size" || name == "negative_size" || name == "over_limit_size" || name == "pre_cancel") && reader.calls != 0 {
				t.Fatal("inadmissible hash input read any bytes")
			}
		})
	}
}

func assertSoftwareClaimWatchdogSnapshotRefusal(t *testing.T, digest string, err error) {
	t.Helper()
	var authority softwareClaimWatchdogAuthorityError
	if digest != "" || !errors.As(err, &authority) || authority.reason != "slot_file" || err.Error() != "software claim watchdog authority is unconfirmed" {
		t.Fatal("refusal leaked data or failed to preserve the closed slot_file code")
	}
}

type softwareClaimWatchdogSnapshotTestInfo struct {
	os.FileInfo
	stat syscall.Stat_t
	size int64
}

func (i softwareClaimWatchdogSnapshotTestInfo) Sys() any    { return &i.stat }
func (i softwareClaimWatchdogSnapshotTestInfo) Size() int64 { return i.size }

type softwareClaimWatchdogSnapshotTestReader struct {
	source           *bytes.Reader
	maximum          int
	maximumRequested int
	calls            int
	consumed         int
	afterRead        func(int)
	failure          error
	noProgress       bool
	invalidCount     bool
	eofWithData      bool
}

func (r *softwareClaimWatchdogSnapshotTestReader) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > r.maximumRequested {
		r.maximumRequested = len(p)
	}
	if r.failure != nil {
		return 0, r.failure
	}
	if r.noProgress {
		return 0, nil
	}
	if r.invalidCount {
		return len(p) + 1, nil
	}
	if r.maximum > 0 && len(p) > r.maximum {
		p = p[:r.maximum]
	}
	n, err := r.source.Read(p)
	r.consumed += n
	if r.eofWithData && n > 0 && r.source.Len() == 0 {
		err = io.EOF
	}
	if r.afterRead != nil {
		r.afterRead(r.calls)
	}
	return n, err
}
