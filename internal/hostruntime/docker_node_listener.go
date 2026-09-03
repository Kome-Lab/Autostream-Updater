package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/example/autostream-contracts/pkg/contracts"
)

// dockerNodeListenerFromCompose follows the exact read-only config mount used
// by the Node. File/external inputs cannot substitute unbound listener bytes.
func dockerNodeListenerFromCompose(raw []byte, service string) (contracts.NodeListenerConfig, string, error) {
	type mount struct {
		Source string `json:"source"`
		Target string `json:"target"`
	}
	var model struct {
		Services map[string]struct {
			Environment map[string]any `json:"environment"`
			Configs     []mount        `json:"configs"`
		} `json:"services"`
		Configs map[string]struct {
			Content     string `json:"content"`
			File        string `json:"file"`
			Environment string `json:"environment"`
			External    any    `json:"external"`
		} `json:"configs"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&model) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return contracts.NodeListenerConfig{}, "", errors.New("Docker listener model is invalid JSON")
	}
	managed, ok := model.Services[service]
	if !ok || managed.Environment["CREDENTIALS_DIRECTORY"] != "/run/autostream-credentials" {
		return contracts.NodeListenerConfig{}, "", errors.New("Docker Node listener credential directory is unavailable")
	}
	for _, removed := range []string{"AUTOSTREAM_BIND_ADDR", "OBSERVABILITY_BIND_ADDR", "AUTOSTREAM_CONFIG_REVISION"} {
		if _, exists := managed.Environment[removed]; exists {
			return contracts.NodeListenerConfig{}, "", errors.New("Docker Node uses a removed listener environment input")
		}
	}
	source := ""
	for _, item := range managed.Configs {
		if item.Target != "/run/autostream-credentials/node-listener.json" {
			continue
		}
		if source != "" || item.Source == "" {
			return contracts.NodeListenerConfig{}, "", errors.New("Docker Node listener mount is ambiguous")
		}
		source = item.Source
	}
	definition, ok := model.Configs[source]
	if source == "" || !ok || definition.Content == "" || definition.File != "" || definition.Environment != "" || definition.External != nil {
		return contracts.NodeListenerConfig{}, "", errors.New("Docker Node requires an inline v2 listener configuration")
	}
	for name, other := range model.Services {
		if name == service {
			continue
		}
		for _, item := range other.Configs {
			if item.Source == source {
				return contracts.NodeListenerConfig{}, "", errors.New("Docker Node listener configuration must not be shared")
			}
		}
	}
	listener, err := contracts.ParseNodeListenerConfig([]byte(definition.Content))
	if err != nil || listener.ServiceType != strings.ReplaceAll(service, "-", "_") {
		return contracts.NodeListenerConfig{}, "", errors.New("Docker Node listener configuration has the wrong service identity or shape")
	}
	if _, err := dockerListenPort(listener.BindAddress); err != nil {
		return contracts.NodeListenerConfig{}, "", err
	}
	return listener, source, nil
}
