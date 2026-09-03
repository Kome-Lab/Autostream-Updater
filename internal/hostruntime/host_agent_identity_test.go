package hostruntime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHostAgentIdentityUsesOnlyRequestedPath(t *testing.T) {
	want := Config{
		PanelURL:     "https://panel.example.com",
		NodeID:       "host-agent-a",
		RuntimeToken: "runtime-token",
		ServiceName:  "Host Agent A",
	}
	path := filepath.Join(t.TempDir(), "agent.yaml")
	data, err := marshalManagedBootstrapConfig(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := LoadHostAgentIdentity(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.PanelURL != want.PanelURL || got.NodeID != want.NodeID ||
		got.RuntimeToken != want.RuntimeToken || got.ServiceName != want.ServiceName {
		t.Fatal("loaded identity fields do not match the requested identity")
	}
}

func TestLoadHostAgentIdentityReturnsRequestedPathErrorWithoutFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	_, err := LoadHostAgentIdentity(path, false)
	var pathError *os.PathError
	if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathError) || pathError.Path != path {
		t.Fatalf("requested identity path error = %v", err)
	}
}

func TestValidateHostAgentIdentityWriteLayoutRequiresInputs(t *testing.T) {
	if err := validateHostAgentIdentityWriteLayout("", os.Lstat); err == nil {
		t.Fatal("empty identity path was accepted")
	}
	if err := validateHostAgentIdentityWriteLayout(HostAgentIdentityPath, nil); err == nil {
		t.Fatal("missing layout verifier was accepted")
	}
}

type hostAgentLayoutFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (info hostAgentLayoutFileInfo) Mode() os.FileMode { return info.mode }
func (info hostAgentLayoutFileInfo) IsDir() bool       { return info.mode.IsDir() }

func TestValidateHostAgentIdentityWriteLayoutChecksEachPathComponent(t *testing.T) {
	rootPath := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	rootInfo, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(rootPath, "identity-fixture", "updater", "agent.yaml")
	parent := filepath.Dir(identityPath)
	for _, test := range []struct {
		name        string
		invalidPath string
		mode        os.FileMode
		statErr     error
		wantErr     bool
	}{
		{name: "existing-private-identity", mode: 0o640},
		{name: "missing-identity-before-configure", invalidPath: identityPath, statErr: os.ErrNotExist},
		{name: "missing-parent", invalidPath: parent, statErr: os.ErrNotExist, wantErr: true},
		{name: "identity-stat-failed", invalidPath: identityPath, statErr: os.ErrPermission, wantErr: true},
		{name: "identity-symlink", invalidPath: identityPath, mode: os.ModeSymlink | 0o640, wantErr: true},
		{name: "identity-directory", invalidPath: identityPath, mode: os.ModeDir | 0o700, wantErr: true},
		{name: "identity-world-readable", invalidPath: identityPath, mode: 0o644, wantErr: true},
		{name: "identity-group-writable", invalidPath: identityPath, mode: 0o660, wantErr: true},
		{name: "parent-symlink", invalidPath: parent, mode: os.ModeDir | os.ModeSymlink | 0o755, wantErr: true},
		{name: "ancestor-group-writable", invalidPath: filepath.Dir(parent), mode: os.ModeDir | 0o775, wantErr: true},
		{name: "root-other-writable", invalidPath: rootPath, mode: os.ModeDir | 0o777, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			visited := map[string]bool{}
			err := validateHostAgentIdentityWriteLayout(identityPath, func(path string) (os.FileInfo, error) {
				visited[path] = true
				mode := os.ModeDir | 0o755
				if path == identityPath {
					mode = 0o640
				}
				if path == test.invalidPath {
					if test.statErr != nil {
						return nil, test.statErr
					}
					mode = test.mode
				}
				return hostAgentLayoutFileInfo{FileInfo: rootInfo, mode: mode}, nil
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("layout error = %v, want error %v", err, test.wantErr)
			}
			if !test.wantErr && (!visited[rootPath] || !visited[parent] || !visited[identityPath]) {
				t.Fatal("layout accepted without checking the complete identity path")
			}
		})
	}
}
