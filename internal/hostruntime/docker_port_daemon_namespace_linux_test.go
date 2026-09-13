//go:build linux

package hostruntime

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func prepareDockerPortSmokeMountNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv(dockerPortDaemonSmokeMountNSEnv) != "1" {
		t.Fatal(dockerPortDaemonSmokeMountNSEnv + "=1 is required")
	}
	selfNamespace, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("read Docker smoke mount namespace: %v", err)
	}
	initNamespace, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		t.Fatalf("read init mount namespace: %v", err)
	}
	if selfNamespace == initNamespace {
		t.Fatal("Docker port smoke requires a dedicated mount namespace")
	}
	requireDockerPortSmokePrivateRootPropagation(t)
	requireDockerPortSmokeRootAnchor(t, "/", 0o755)

	scratch := t.TempDir()
	mounted := make([]string, 0, 5)
	t.Cleanup(func() {
		for index := len(mounted) - 1; index >= 0; index-- {
			if err := syscall.Unmount(mounted[index], syscall.MNT_DETACH); err != nil {
				t.Errorf(
					"unmount Docker smoke fixture %s: %v",
					mounted[index], err,
				)
			}
		}
	})

	dockerPortSmokeOverlayRoot(t, scratch, "etc", "/etc", nil, &mounted)
	dockerPortSmokeOverlayRoot(
		t,
		scratch,
		"usr",
		"/usr",
		[]string{
			"bin",
			"sbin",
			"local",
			"local/bin",
			"local/sbin",
			"local/libexec",
		},
		&mounted,
	)
	if err := syscall.Mount(
		"autostream-docker-port-smoke-opt",
		"/opt",
		"tmpfs",
		uintptr(syscall.MS_NODEV|syscall.MS_NOSUID|syscall.MS_NOEXEC),
		"mode=0755,uid=0,gid=0",
	); err != nil {
		t.Fatalf("mount isolated Docker smoke /opt: %v", err)
	}
	mounted = append(mounted, "/opt")

	requireDockerPortSmokeFilesystem(t, "/etc", 0x794c7630)
	requireDockerPortSmokeFilesystem(t, "/usr", 0x794c7630)
	requireDockerPortSmokeFilesystem(t, "/opt", 0x01021994)
	for _, path := range []string{
		"/etc",
		"/usr",
		"/usr/bin",
		"/usr/local",
		"/usr/local/bin",
		"/usr/local/sbin",
		"/usr/local/libexec",
		"/opt",
	} {
		requireDockerPortSmokeRootAnchor(t, path, 0o755)
	}
}

func dockerPortSmokeOverlayRoot(
	t *testing.T,
	scratch, name, target string,
	upperDirectories []string,
	mounted *[]string,
) {
	t.Helper()
	root := filepath.Join(scratch, name)
	lower := filepath.Join(root, "lower")
	upper := filepath.Join(root, "upper")
	work := filepath.Join(root, "work")
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{path: root, mode: 0o700},
		{path: lower, mode: 0o700},
		{path: upper, mode: 0o755},
		{path: work, mode: 0o700},
	} {
		if err := os.Mkdir(directory.path, directory.mode); err != nil {
			t.Fatalf("create Docker smoke overlay directory %s: %v", directory.path, err)
		}
		if err := os.Chown(directory.path, 0, 0); err != nil {
			t.Fatalf("own Docker smoke overlay directory %s: %v", directory.path, err)
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			t.Fatalf("mode Docker smoke overlay directory %s: %v", directory.path, err)
		}
	}
	for _, relative := range upperDirectories {
		path := filepath.Join(upper, relative)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create Docker smoke overlay upper %s: %v", path, err)
		}
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatalf("own Docker smoke overlay upper %s: %v", path, err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatalf("mode Docker smoke overlay upper %s: %v", path, err)
		}
	}
	if err := syscall.Mount(
		target,
		lower,
		"",
		uintptr(syscall.MS_BIND|syscall.MS_REC),
		"",
	); err != nil {
		t.Fatalf("bind Docker smoke lower %s: %v", target, err)
	}
	*mounted = append(*mounted, lower)
	if err := syscall.Mount(
		"",
		lower,
		"",
		uintptr(syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY),
		"",
	); err != nil {
		t.Fatalf("make Docker smoke lower read-only %s: %v", target, err)
	}
	options := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := syscall.Mount(
		"overlay",
		target,
		"overlay",
		uintptr(syscall.MS_NODEV|syscall.MS_NOSUID),
		options,
	); err != nil {
		t.Fatalf("mount isolated Docker smoke %s: %v", target, err)
	}
	*mounted = append(*mounted, target)
}

func requireDockerPortSmokePrivateRootPropagation(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("read Docker smoke mount propagation: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 || fields[4] != "/" {
			continue
		}
		separator := -1
		for index := 6; index < len(fields); index++ {
			if fields[index] == "-" {
				separator = index
				break
			}
			if strings.HasPrefix(fields[index], "shared:") ||
				strings.HasPrefix(fields[index], "master:") {
				t.Fatal("Docker port smoke root mount propagation is not private")
			}
		}
		if separator < 0 {
			t.Fatal("Docker port smoke root mountinfo is malformed")
		}
		return
	}
	t.Fatal("Docker port smoke root mount was not found")
}

func requireDockerPortSmokeRootAnchor(
	t *testing.T,
	path string,
	mode os.FileMode,
) {
	t.Helper()
	info, err := os.Lstat(path)
	stat, ok := infoSyscallStat(info)
	if err != nil ||
		!ok ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		stat.Uid != 0 ||
		stat.Gid != 0 ||
		info.Mode().Perm() != mode {
		uid, gid := uint32(^uint32(0)), uint32(^uint32(0))
		actualMode := os.FileMode(0)
		if ok {
			uid, gid = stat.Uid, stat.Gid
		}
		if info != nil {
			actualMode = info.Mode()
		}
		t.Fatalf(
			"Docker port smoke root anchor %s must be a root:root non-symlink directory with mode %04o; uid=%d gid=%d mode=%v err=%v",
			path, mode, uid, gid, actualMode, err,
		)
	}
}

func infoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func requireDockerPortSmokeFilesystem(
	t *testing.T,
	path string,
	wantType int64,
) {
	t.Helper()
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		t.Fatalf("stat Docker smoke filesystem %s: %v", path, err)
	}
	if int64(stat.Type) != wantType {
		t.Fatalf(
			"Docker port smoke filesystem %s type=%#x want=%#x",
			path, stat.Type, wantType,
		)
	}
}

func hardenDockerPortSmokeProjectParent(t *testing.T) {
	t.Helper()
	parent := filepath.Dir(filepath.Clean(dockerPortSmokeProjectDir))
	info, err := os.Lstat(parent)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		!isRootOwner(info) {
		t.Fatalf(
			"Docker port smoke project parent %s must be a root-owned non-symlink directory",
			parent,
		)
	}
	originalMode := info.Mode()
	hardenedMode := originalMode &^ 0o022
	if hardenedMode != originalMode {
		if err := os.Chmod(parent, hardenedMode); err != nil {
			t.Fatalf("harden Docker port smoke project parent %s: %v", parent, err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(parent, originalMode); err != nil {
				t.Errorf(
					"restore Docker port smoke project parent %s mode: %v",
					parent, err,
				)
			}
		})
	}
	if err := validateSecureRootPath(parent, true); err != nil {
		t.Fatalf("secure Docker port smoke project parent %s: %v", parent, err)
	}
}
