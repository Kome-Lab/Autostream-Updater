package hostruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestManagedBootstrapConfigYAMLPreservesExactlyFourStringFields(t *testing.T) {
	want := Config{
		PanelURL: "https://panel.example.com", NodeID: "host-agent-a",
		RuntimeToken: "opaque: # runtime-test-marker", ServiceName: "Host Agent A",
	}
	data, err := marshalManagedBootstrapConfig(want)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := yaml.Unmarshal(data, &wire); err != nil {
		t.Fatal("serialized identity is not YAML")
	}
	if len(wire) != 4 {
		t.Fatalf("identity field count = %d, want 4", len(wire))
	}
	for _, name := range []string{"panel_url", "node_id", "runtime_token", "service_name"} {
		if _, ok := wire[name].(string); !ok {
			t.Fatalf("identity field %s is absent or is not a string", name)
		}
	}
	got, err := decodeManagedBootstrapConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.PanelURL != want.PanelURL || got.NodeID != want.NodeID ||
		got.RuntimeToken != want.RuntimeToken || got.ServiceName != want.ServiceName {
		t.Fatal("YAML identity changed an identity field")
	}
}

func TestManagedBootstrapConfigYAMLRejectsOtherShapesWithoutSecretEcho(t *testing.T) {
	const valid = "panel_url: https://panel.example.com\nnode_id: host-agent-a\nruntime_token: runtime-test-marker\nservice_name: Host Agent A\n"
	for name, data := range map[string]string{
		"legacy-json": `{"panel_url":"https://panel.example.com","node_id":"host-agent-a","runtime_token":"runtime-test-marker","service_name":"Host Agent A"}`,
		"document-wrapped-json": "---\n" + `{"panel_url":"https://panel.example.com","node_id":"host-agent-a","runtime_token":"runtime-test-marker","service_name":"Host Agent A"}`,
		"flow-mapping": "{panel_url: https://panel.example.com, node_id: host-agent-a, runtime_token: runtime-test-marker, service_name: Host Agent A}",
		"extra-field": valid + "local_listen_port: 8080\n",
		"missing-field": strings.ReplaceAll(valid, "service_name: Host Agent A\n", ""),
		"duplicate-field": strings.ReplaceAll(valid, "service_name: Host Agent A", "runtime_token: second-runtime-test-marker"),
		"non-string-token": strings.ReplaceAll(valid, "runtime_token: runtime-test-marker", "runtime_token: 12345"),
		"null-token": strings.ReplaceAll(valid, "runtime_token: runtime-test-marker", "runtime_token: null"),
		"nested-token": strings.ReplaceAll(valid, "runtime_token: runtime-test-marker", "runtime_token:\n  value: runtime-test-marker"),
		"alias-token": strings.ReplaceAll(strings.ReplaceAll(valid, "node_id: host-agent-a", "node_id: &node host-agent-a"), "runtime_token: runtime-test-marker", "runtime_token: *node"),
		"second-document": valid + "---\n" + valid,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeManagedBootstrapConfig([]byte(data))
			if err == nil {
				t.Fatal("noncanonical identity format was accepted")
			}
			if strings.Contains(err.Error(), "runtime-test-marker") {
				t.Fatal("identity validation disclosed a credential")
			}
		})
	}
}

func TestLoadManagedBootstrapConfigRejectsJSONAtCanonicalYAMLPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	data := []byte(`{"panel_url":"https://panel.example.com","node_id":"host-agent-a","runtime_token":"runtime-test-marker","service_name":"Host Agent A"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManagedBootstrapConfig(path, false); err == nil {
		t.Fatal("JSON identity was accepted as the v2 YAML authority")
	}
}
