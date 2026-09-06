package hostruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func dockerListenerMaterializationFixture(t *testing.T, revision int64) ([]byte, *DockerTarget) {
	t.Helper()
	target := canonicalWorkerDockerPortTarget()
	raw := mustDockerNodeListenerModel(t, []byte(`{"name":"autostream","services":{"worker":{"image":"ghcr.io/kome-lab/autostream-docker/worker:v1.0.0","read_only":true,"cap_drop":["ALL"],"security_opt":["no-new-privileges"],"environment":{"KEEP":"fixed"},"ports":[{"host_ip":"127.0.0.1","target":8080,"published":"18081","protocol":"tcp"}]}},"networks":{"default":{}}}`), "worker", "0.0.0.0:8080", revision)
	target.ComposeConfigSHA256, _ = composeModelHash(raw, target.Service)
	return raw, target
}

func dockerListenerTestStore(t *testing.T) dockerNodeListenerStore {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix file ownership and 0700/0444 modes require Linux CI")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return dockerNodeListenerStore{root, acceptTestFixtureOwner, false}
}

func TestDockerNodeListenerExecutionChangesOnlyExactConfig(t *testing.T) {
	raw, target := dockerListenerMaterializationFixture(t, 7)
	before := bytes.Clone(raw)
	store := dockerNodeListenerStore{t.TempDir(), acceptTestFixtureOwner, false}
	plan, err := store.prepare(raw, target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, before) || !bytes.Equal(plan.canonical, before) {
		t.Fatal("canonical input changed")
	}
	var canonical, execution map[string]any
	if json.Unmarshal(raw, &canonical) != nil || json.Unmarshal(plan.execution, &execution) != nil {
		t.Fatal("invalid model")
	}
	definitions := canonical["configs"].(map[string]any)
	source := "worker-node-listener"
	content := definitions[source].(map[string]any)["content"].(string)
	if !bytes.Equal(plan.content, []byte(content)) || filepath.Dir(plan.path) != filepath.Join(store.root, "worker") {
		t.Fatal("listener bytes or generated path changed")
	}
	definitions[source] = map[string]any{"file": plan.path}
	if !reflect.DeepEqual(canonical, execution) {
		t.Fatal("execution differs outside the exact config source")
	}
	if _, err := store.prepare(plan.execution, target); err == nil {
		t.Fatal("derived file model accepted as canonical input")
	}
	derivedHash, _ := composeModelHash(plan.execution, target.Service)
	if derivedHash == target.ComposeConfigSHA256 {
		t.Fatal("execution model was presented as the canonical hash")
	}
	if entries, err := os.ReadDir(store.root); err != nil || len(entries) != 0 {
		t.Fatal("pure preparation wrote listener state")
	}
}

func TestDockerNodeListenerExecutionRejectsInvalidCanonicalInputs(t *testing.T) {
	cases := map[string]func(map[string]any){
		"file": func(m map[string]any) {
			m["configs"].(map[string]any)["worker-node-listener"].(map[string]any)["file"] = "/arbitrary/host"
		},
		"environment": func(m map[string]any) {
			m["configs"].(map[string]any)["worker-node-listener"].(map[string]any)["environment"] = "UNBOUND"
		},
		"external": func(m map[string]any) {
			m["configs"].(map[string]any)["worker-node-listener"].(map[string]any)["external"] = false
		},
		"multiple_listener": func(m map[string]any) {
			service := m["services"].(map[string]any)["worker"].(map[string]any)
			service["configs"] = append(service["configs"].([]any), service["configs"].([]any)[0])
		},
		"shared_same_service": func(m map[string]any) {
			service := m["services"].(map[string]any)["worker"].(map[string]any)
			service["configs"] = append(service["configs"].([]any), map[string]any{"source": "worker-node-listener", "target": "/elsewhere"})
		},
		"shared_other_service": func(m map[string]any) {
			m["services"].(map[string]any)["other"] = map[string]any{"image": "example:fixed", "configs": []any{map[string]any{"source": "worker-node-listener", "target": "/elsewhere"}}}
		},
		"service": func(m map[string]any) {
			definition := m["configs"].(map[string]any)["worker-node-listener"].(map[string]any)
			definition["content"] = strings.ReplaceAll(definition["content"].(string), `"worker"`, `"observability"`)
		},
		"bind": func(m map[string]any) {
			definition := m["configs"].(map[string]any)["worker-node-listener"].(map[string]any)
			definition["content"] = strings.ReplaceAll(definition["content"].(string), "0.0.0.0:8080", "127.0.0.1:8080")
		},
		"revision": func(m map[string]any) {
			definition := m["configs"].(map[string]any)["worker-node-listener"].(map[string]any)
			var listener map[string]any
			_ = json.Unmarshal([]byte(definition["content"].(string)), &listener)
			listener["config_revision"] = 0
			body, _ := json.Marshal(listener)
			definition["content"] = string(body)
		},
		"oversized": func(m map[string]any) {
			definition := m["configs"].(map[string]any)["worker-node-listener"].(map[string]any)
			definition["content"] = definition["content"].(string) + strings.Repeat(" ", dockerNodeListenerMaxBytes)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw, target := dockerListenerMaterializationFixture(t, 1)
			var model map[string]any
			if json.Unmarshal(raw, &model) != nil {
				t.Fatal("fixture")
			}
			mutate(model)
			raw, _ = json.Marshal(model)
			target.ComposeConfigSHA256, _ = composeModelHash(raw, target.Service)
			store := dockerNodeListenerStore{t.TempDir(), acceptTestFixtureOwner, false}
			if _, err := store.prepare(raw, target); err == nil {
				t.Fatal("invalid canonical input accepted")
			}
		})
	}
}

func TestDockerNodeListenerExecutionRejectsModelDrift(t *testing.T) {
	raw, target := dockerListenerMaterializationFixture(t, 1)
	store := dockerNodeListenerStore{t.TempDir(), acceptTestFixtureOwner, false}
	plan, err := store.prepare(raw, target)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"image", "ports", "read_only", "environment"} {
		t.Run(field, func(t *testing.T) {
			var execution map[string]any
			_ = json.Unmarshal(plan.execution, &execution)
			execution["services"].(map[string]any)["worker"].(map[string]any)[field] = "changed"
			changed, _ := json.Marshal(execution)
			if store.validate(plan, raw, changed, target) == nil {
				t.Fatal("execution drift accepted")
			}
		})
	}
	if store.validate(plan, append(bytes.Clone(raw), ' '), plan.execution, target) == nil {
		t.Fatal("canonical bytes drift accepted")
	}
}

func TestDockerNodeListenerMaterializationReuseAndRetention(t *testing.T) {
	store := dockerListenerTestStore(t)
	raw, target := dockerListenerMaterializationFixture(t, 1)
	plan, err := store.prepare(raw, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.materialize(plan); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(plan.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.materialize(plan); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Lstat(plan.path)
	if !os.SameFile(before, after) {
		t.Fatal("immutable generation was replaced")
	}
	if err := store.validate(plan, raw, plan.execution, target); err != nil {
		t.Fatal(err)
	}
	for revision := int64(2); revision <= dockerNodeListenerMaxGenerations; revision++ {
		raw, target := dockerListenerMaterializationFixture(t, revision)
		next, err := store.prepare(raw, target)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.materialize(next); err != nil {
			t.Fatal(err)
		}
	}
	raw, target = dockerListenerMaterializationFixture(t, dockerNodeListenerMaxGenerations+1)
	next, err := store.prepare(raw, target)
	if err != nil {
		t.Fatal(err)
	}
	if store.materialize(next) == nil {
		t.Fatal("generation capacity was not enforced")
	}
	if err := store.materialize(plan); err != nil {
		t.Fatal("rollback reuse failed at capacity")
	}
	after, _ = os.Lstat(plan.path)
	if !os.SameFile(before, after) {
		t.Fatal("old generation was removed or replaced")
	}
	if _, err := os.Lstat(next.path); !os.IsNotExist(err) {
		t.Fatal("capacity failure published a new generation")
	}
}

func TestDockerNodeListenerMaterializationRejectsFileTampering(t *testing.T) {
	for _, name := range []string{"content", "missing", "symlink", "directory", "mode", "owner", "root_mode", "root_symlink"} {
		t.Run(name, func(t *testing.T) {
			store := dockerListenerTestStore(t)
			raw, target := dockerListenerMaterializationFixture(t, 1)
			plan, err := store.prepare(raw, target)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.materialize(plan); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "content":
				if os.Chmod(plan.path, 0o600) != nil || os.WriteFile(plan.path, []byte("changed"), 0o600) != nil || os.Chmod(plan.path, 0o444) != nil {
					t.Fatal("mutation failed")
				}
			case "missing":
				if os.Remove(plan.path) != nil {
					t.Fatal("mutation failed")
				}
			case "symlink":
				other := filepath.Join(store.root, "other")
				if os.WriteFile(other, plan.content, 0o444) != nil || os.Remove(plan.path) != nil || os.Symlink(other, plan.path) != nil {
					t.Fatal("mutation failed")
				}
			case "directory":
				if os.Remove(plan.path) != nil || os.Mkdir(plan.path, 0o700) != nil {
					t.Fatal("mutation failed")
				}
			case "mode":
				if os.Chmod(plan.path, 0o644) != nil {
					t.Fatal("mutation failed")
				}
			case "owner":
				store.trustedOwner = func(info os.FileInfo) bool { return info.IsDir() }
			case "root_mode":
				if os.Chmod(store.root, 0o777) != nil {
					t.Fatal("mutation failed")
				}
				defer os.Chmod(store.root, 0o700)
			case "root_symlink":
				moved := store.root + "-moved"
				if os.Rename(store.root, moved) != nil || os.Symlink(moved, store.root) != nil {
					t.Fatal("mutation failed")
				}
				defer func() { _ = os.Remove(store.root); _ = os.Rename(moved, store.root) }()
			}
			if store.validate(plan, raw, plan.execution, target) == nil {
				t.Fatal("tampered listener accepted before execution")
			}
			if name != "missing" && store.materialize(plan) == nil {
				t.Fatal("unsafe existing generation was overwritten or accepted")
			}
		})
	}
}
