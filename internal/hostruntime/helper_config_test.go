package hostruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func validHelperTestConfig(t *testing.T) HelperConfig {
	t.Helper()
	root := t.TempDir()
	return HelperConfig{
		SchemaVersion: HelperConfigSchemaVersion,
		HostID:        "edge-01",
		PanelURL:      "https://panel.example.com",
		Arch:          runtime.GOARCH,
		StateDir:      filepath.Join(root, "state"),
		Targets: []Target{{
			TargetID: "worker-01", HostID: "edge-01", ServiceType: "worker", DeploymentMode: ModeSystemd,
			HealthURL: "http://127.0.0.1:8081/health", VersionURL: "http://127.0.0.1:8081/version",
			Systemd: &SystemdTarget{SystemctlPath: filepath.Join(root, "bin", "systemctl"), RunuserPath: filepath.Join(root, "bin", "runuser"), SmokeUser: "autostream", Unit: "autostream-worker.service", ReleaseRoot: filepath.Join(root, "releases"), CurrentLink: filepath.Join(root, "current"), BinaryPath: "bin/worker"},
		}},
	}
}

func writeHelperTestConfig(t *testing.T, cfg HelperConfig) string {
	t.Helper()
	payload, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "update-host.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestHelperConfigLoadsStrictTokenFreeRootPolicy(t *testing.T) {
	cfg := validHelperTestConfig(t)
	path := writeHelperTestConfig(t, cfg)
	loaded, err := LoadHelperConfig(path, false)
	if err != nil {
		t.Fatalf("load helper config: %v", err)
	}
	if loaded.HostID != cfg.HostID || len(loaded.Targets) != 1 {
		t.Fatalf("loaded helper config = %#v", loaded)
	}
	first, err := loaded.SHA256()
	if err != nil || !digestPattern.MatchString(first) {
		t.Fatalf("helper config digest = %q, %v", first, err)
	}
	second, err := cfg.SHA256()
	if err != nil || second != first {
		t.Fatalf("helper config digest is not canonical: %q != %q (%v)", first, second, err)
	}
	if target, ok := loaded.Target("worker-01"); !ok || target.Systemd == nil {
		t.Fatalf("target lookup = %#v, %v", target, ok)
	}
}

func TestHelperConfigRejectsLongLivedSecretsAndTrailingData(t *testing.T) {
	cfg := validHelperTestConfig(t)
	payload, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	withToken := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(`,"runtime_token":"must-not-be-stored"}`)...)
	path := filepath.Join(t.TempDir(), "with-token.json")
	if err := os.WriteFile(path, withToken, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHelperConfig(path, false); err == nil || !strings.Contains(err.Error(), "decode helper config") {
		t.Fatalf("long-lived token was not rejected: %v", err)
	}

	trailing := append(append([]byte(nil), payload...), []byte(` {}`)...)
	path = filepath.Join(t.TempDir(), "trailing.json")
	if err := os.WriteFile(path, trailing, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHelperConfig(path, false); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing helper config was not rejected: %v", err)
	}
}

func TestHelperConfigRequiresMatchingHostArchitectureAndFullTargetPolicy(t *testing.T) {
	t.Run("host binding", func(t *testing.T) {
		cfg := validHelperTestConfig(t)
		cfg.Targets[0].HostID = "edge-02"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "match helper host_id") {
			t.Fatalf("host mismatch result = %v", err)
		}
	})
	t.Run("runtime architecture", func(t *testing.T) {
		cfg := validHelperTestConfig(t)
		if runtime.GOARCH == "amd64" {
			cfg.Arch = "arm64"
		} else {
			cfg.Arch = "amd64"
		}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "runtime architecture") {
			t.Fatalf("architecture mismatch result = %v", err)
		}
	})
	t.Run("identity-only target", func(t *testing.T) {
		cfg := validHelperTestConfig(t)
		cfg.Targets[0] = Target{TargetID: "worker-01", HostID: "edge-01", ServiceType: "worker", DeploymentMode: ModeSystemd}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "health_url") {
			t.Fatalf("identity-only helper target result = %v", err)
		}
	})
	t.Run("schema", func(t *testing.T) {
		cfg := validHelperTestConfig(t)
		cfg.SchemaVersion = 2
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "schema_version") {
			t.Fatalf("schema result = %v", err)
		}
	})
}

func TestHelperConfigLoaderRejectsUnsafeFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership and mode policy")
	}
	cfg := validHelperTestConfig(t)
	path := writeHelperTestConfig(t, cfg)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHelperConfig(path, true); err == nil || !strings.Contains(err.Error(), "inaccessible to other users") {
		t.Fatalf("unsafe helper config mode result = %v", err)
	}

	link := filepath.Join(t.TempDir(), "helper-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHelperConfig(link, false); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("helper config symlink result = %v", err)
	}
}
