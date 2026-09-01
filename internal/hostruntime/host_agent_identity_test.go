package hostruntime

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestLoadHostAgentIdentityAcceptsCanonicalWhenLegacyIsInaccessible(t *testing.T) {
	want := Config{
		PanelURL:     "https://panel.example.com",
		NodeID:       "host-agent-a",
		RuntimeToken: "runtime-token",
		ServiceName:  "Host Agent A",
	}
	loaded := make([]string, 0, 1)
	probed := make([]string, 0, 1)

	got, err := loadHostAgentIdentity(
		HostAgentIdentityPath,
		true,
		hostAgentIdentityDependencies{
			load: func(path string, requireRootOwned bool) (Config, error) {
				loaded = append(loaded, path)
				if path != HostAgentIdentityPath || !requireRootOwned {
					t.Fatalf("load = path %q root-owned %v", path, requireRootOwned)
				}
				return want, nil
			},
			lstat: func(path string) (os.FileInfo, error) {
				probed = append(probed, path)
				return nil, os.ErrPermission
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != want.NodeID || got.RuntimeToken != want.RuntimeToken {
		t.Fatalf("identity = %#v", got)
	}
	if len(loaded) != 1 || loaded[0] != HostAgentIdentityPath {
		t.Fatalf("loaded paths = %#v", loaded)
	}
	if len(probed) != 1 || probed[0] != LegacyHostAgentIdentityPath {
		t.Fatalf("probed paths = %#v", probed)
	}
}

func TestLoadHostAgentIdentityRejectsInaccessibleLegacyWithoutCanonical(t *testing.T) {
	loadCalls := 0
	_, err := loadHostAgentIdentity(
		HostAgentIdentityPath,
		true,
		hostAgentIdentityDependencies{
			load: func(path string, _ bool) (Config, error) {
				loadCalls++
				if path != HostAgentIdentityPath {
					t.Fatalf("unexpected load path %q", path)
				}
				return Config{}, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
			},
			lstat: func(path string) (os.FileInfo, error) {
				if path != LegacyHostAgentIdentityPath {
					t.Fatalf("unexpected probe path %q", path)
				}
				return nil, os.ErrPermission
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "stat legacy Host Agent identity") {
		t.Fatalf("error = %v", err)
	}
	if loadCalls != 1 {
		t.Fatalf("load calls = %d", loadCalls)
	}
}

func TestLoadHostAgentIdentityRejectsVisibleDualIdentity(t *testing.T) {
	_, err := loadHostAgentIdentity(
		HostAgentIdentityPath,
		true,
		hostAgentIdentityDependencies{
			load: func(string, bool) (Config, error) {
				return Config{NodeID: "host-agent-a"}, nil
			},
			lstat: func(path string) (os.FileInfo, error) {
				if path != LegacyHostAgentIdentityPath {
					t.Fatalf("unexpected probe path %q", path)
				}
				return nil, nil
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "both current and legacy") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadHostAgentIdentityFallsBackToVisibleLegacy(t *testing.T) {
	loaded := make([]string, 0, 2)
	got, err := loadHostAgentIdentity(
		HostAgentIdentityPath,
		true,
		hostAgentIdentityDependencies{
			load: func(path string, requireRootOwned bool) (Config, error) {
				loaded = append(loaded, path)
				if !requireRootOwned {
					t.Fatal("legacy identity was not required to be root-owned")
				}
				if path == HostAgentIdentityPath {
					return Config{}, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
				}
				if path != LegacyHostAgentIdentityPath {
					t.Fatalf("unexpected load path %q", path)
				}
				return Config{NodeID: "legacy-host-agent"}, nil
			},
			lstat: func(path string) (os.FileInfo, error) {
				if path != LegacyHostAgentIdentityPath {
					t.Fatalf("unexpected probe path %q", path)
				}
				return nil, nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != "legacy-host-agent" {
		t.Fatalf("identity = %#v", got)
	}
	if len(loaded) != 2 || loaded[0] != HostAgentIdentityPath || loaded[1] != LegacyHostAgentIdentityPath {
		t.Fatalf("loaded paths = %#v", loaded)
	}
}

func TestLoadHostAgentIdentityRejectsUnexpectedLegacyProbeError(t *testing.T) {
	_, err := loadHostAgentIdentity(
		HostAgentIdentityPath,
		true,
		hostAgentIdentityDependencies{
			load: func(string, bool) (Config, error) {
				return Config{NodeID: "host-agent-a"}, nil
			},
			lstat: func(string) (os.FileInfo, error) {
				return nil, errors.New("synthetic I/O failure")
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "stat legacy Host Agent identity") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadHostAgentIdentityDoesNotFallbackFromInvalidCanonicalIdentity(t *testing.T) {
	probeCalled := false
	_, err := loadHostAgentIdentity(
		HostAgentIdentityPath,
		true,
		hostAgentIdentityDependencies{
			load: func(path string, _ bool) (Config, error) {
				if path != HostAgentIdentityPath {
					t.Fatalf("unexpected load path %q", path)
				}
				return Config{}, errors.New("canonical identity is invalid")
			},
			lstat: func(string) (os.FileInfo, error) {
				probeCalled = true
				return nil, nil
			},
		},
	)
	if err == nil || !strings.Contains(err.Error(), "canonical identity is invalid") {
		t.Fatalf("error = %v", err)
	}
	if probeCalled {
		t.Fatal("invalid canonical identity fell through to the legacy probe")
	}
}

func TestLoadHostAgentIdentityReportsCanonicalMissingWhenBothAreAbsent(t *testing.T) {
	_, err := loadHostAgentIdentity(
		HostAgentIdentityPath,
		true,
		hostAgentIdentityDependencies{
			load: func(path string, _ bool) (Config, error) {
				return Config{}, &os.PathError{Op: "stat", Path: path, Err: os.ErrNotExist}
			},
			lstat: func(string) (os.FileInfo, error) {
				return nil, os.ErrNotExist
			},
		},
	)
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Path != HostAgentIdentityPath ||
		!errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %#v", err)
	}
}

func TestLoadHostAgentIdentityLoadsCleanCustomPathDirectly(t *testing.T) {
	probeCalled := false
	got, err := loadHostAgentIdentity(
		"/root/custom-identity.json",
		true,
		hostAgentIdentityDependencies{
			load: func(path string, requireRootOwned bool) (Config, error) {
				if path != "/root/custom-identity.json" || !requireRootOwned {
					t.Fatalf("load = path %q root-owned %v", path, requireRootOwned)
				}
				return Config{NodeID: "custom-host-agent"}, nil
			},
			lstat: func(string) (os.FileInfo, error) {
				probeCalled = true
				return nil, nil
			},
		},
	)
	if err != nil || got.NodeID != "custom-host-agent" {
		t.Fatalf("identity = %#v, error = %v", got, err)
	}
	if probeCalled {
		t.Fatal("custom identity path probed the fixed legacy path")
	}
}

func TestLoadHostAgentIdentityRejectsUncleanCanonicalAlias(t *testing.T) {
	loadCalled := false
	_, err := loadHostAgentIdentity(
		"/etc/autostream-host-agent/./identity.json",
		true,
		hostAgentIdentityDependencies{
			load: func(string, bool) (Config, error) {
				loadCalled = true
				return Config{}, nil
			},
			lstat: os.Lstat,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "clean absolute path") {
		t.Fatalf("error = %v", err)
	}
	if loadCalled {
		t.Fatal("unclean path reached identity loader")
	}
}

func TestValidateHostAgentIdentityWriteLayoutRequiresLegacyAbsent(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		legacyErr error
		wantError string
		wantCalls int
	}{
		{name: "canonical absent", path: HostAgentIdentityPath, legacyErr: os.ErrNotExist, wantCalls: 1},
		{name: "canonical legacy exists", path: HostAgentIdentityPath, wantError: "legacy Host Agent identity already exists", wantCalls: 1},
		{name: "canonical legacy inaccessible", path: HostAgentIdentityPath, legacyErr: os.ErrPermission, wantError: "stat legacy Host Agent identity", wantCalls: 1},
		{name: "custom path", path: "/root/custom-identity.json", wantCalls: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			err := validateHostAgentIdentityWriteLayout(
				test.path,
				func(path string) (os.FileInfo, error) {
					calls++
					if path != LegacyHostAgentIdentityPath {
						t.Fatalf("unexpected probe path %q", path)
					}
					return nil, test.legacyErr
				},
			)
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want %q", err, test.wantError)
			}
			if calls != test.wantCalls {
				t.Fatalf("probe calls = %d, want %d", calls, test.wantCalls)
			}
		})
	}
}
