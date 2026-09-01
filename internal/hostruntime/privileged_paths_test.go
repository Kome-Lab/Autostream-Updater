package hostruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecurePrivilegedSystemdTargetNeverCreatesReleaseRootAtRuntime(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix privileged path policy")
	}
	root := t.TempDir()
	releaseRoot := filepath.Join(root, "production", "releases")
	target := Target{
		TargetID: "worker-01", DeploymentMode: ModeSystemd,
		Systemd: &SystemdTarget{
			SystemctlPath: "/definitely/not/reached/systemctl", RunuserPath: "/definitely/not/reached/runuser",
			ReleaseRoot: releaseRoot, CurrentLink: filepath.Join(root, "production", "current"),
		},
	}
	_, err := securePrivilegedTarget(target)
	if err == nil || !strings.Contains(err.Error(), "release_root") {
		t.Fatalf("missing runtime release_root result = %v", err)
	}
	if _, statErr := os.Lstat(releaseRoot); !os.IsNotExist(statErr) {
		t.Fatalf("runtime validation created production release_root: %v", statErr)
	}
}
