package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	ServiceTypeUpdateAgent = "update_agent"
	ModeSystemd            = "systemd"
	ModeDocker             = "docker"
	configMaxBytes         = 1 << 20
	ManagedUpdaterStateDir = "/var/lib/autostream-host-agent"
)

// Config is the durable, root-controlled Agent identity. It deliberately has
// exactly the four fields accepted by the existing pull_v2 installation.
type Config struct {
	PanelURL     string `json:"panel_url"`
	NodeID       string `json:"node_id"`
	RuntimeToken string `json:"runtime_token"`
	ServiceName  string `json:"service_name"`

	configFields map[string]bool
}

func (c *Config) UnmarshalJSON(data []byte) error {
	type identityWire struct {
		PanelURL     string `json:"panel_url"`
		NodeID       string `json:"node_id"`
		RuntimeToken string `json:"runtime_token"`
		ServiceName  string `json:"service_name"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded identityWire
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Agent identity contains trailing data")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*c = Config{
		PanelURL: decoded.PanelURL, NodeID: decoded.NodeID,
		RuntimeToken: decoded.RuntimeToken, ServiceName: decoded.ServiceName,
		configFields: make(map[string]bool, len(fields)),
	}
	for name := range fields {
		c.configFields[name] = true
	}
	return nil
}

func LoadManagedBootstrapConfig(path string, requireRootOwned bool) (Config, error) {
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("Agent identity path must be absolute")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("stat Agent identity: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() ||
		pathInfo.Size() <= 0 || pathInfo.Size() > configMaxBytes {
		return Config{}, errors.New("Agent identity must be a bounded regular non-symlink file")
	}
	file, openedInfo, err := openVerifiedConfig(path, pathInfo)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	if requireRootOwned {
		if openedInfo.Mode().Perm()&0o007 != 0 || openedInfo.Mode().Perm()&0o022 != 0 {
			return Config{}, errors.New("Agent identity has unsafe permissions")
		}
		if err := validateRootOwnedFileAndParents(path, openedInfo, "Agent identity"); err != nil {
			return Config{}, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, configMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > configMaxBytes {
		return Config{}, errors.New("read Agent identity")
	}
	var identity Config
	if err := json.Unmarshal(data, &identity); err != nil {
		return Config{}, errors.New("Agent identity must contain exactly four fields")
	}
	if err := identity.Validate(); err != nil {
		return Config{}, err
	}
	return identity, nil
}

func openVerifiedConfig(path string, expected os.FileInfo) (*os.File, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("open Agent identity")
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(expected, openedInfo) ||
		expected.Size() != openedInfo.Size() || expected.Mode() != openedInfo.Mode() ||
		!expected.ModTime().Equal(openedInfo.ModTime()) || openedInfo.Size() <= 0 ||
		openedInfo.Size() > configMaxBytes {
		_ = file.Close()
		return nil, nil, errors.New("Agent identity changed during secure open")
	}
	return file, openedInfo, nil
}

func (c Config) Validate() error {
	if err := validatePanelURL(strings.TrimSpace(c.PanelURL)); err != nil {
		return err
	}
	if !identifierPattern.MatchString(strings.TrimSpace(c.NodeID)) {
		return errors.New("node_id is invalid")
	}
	if strings.TrimSpace(c.RuntimeToken) == "" {
		return errors.New("runtime_token is required")
	}
	if strings.TrimSpace(c.ServiceName) == "" || len(strings.TrimSpace(c.ServiceName)) > 255 {
		return errors.New("service_name is invalid")
	}
	if len(c.configFields) > 0 {
		if len(c.configFields) != 4 {
			return errors.New("Agent identity must contain exactly four fields")
		}
		for _, field := range []string{"panel_url", "node_id", "runtime_token", "service_name"} {
			if !c.configFields[field] {
				return errors.New("Agent identity must contain exactly four fields")
			}
		}
	}
	return nil
}

func (c Config) IsManagedBootstrap() bool { return c.Validate() == nil }

func (c Config) EffectiveStateDir() string { return ManagedUpdaterStateDir }

func validatePanelURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("panel_url must be an absolute HTTP(S) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("panel_url must not contain credentials, query, or fragment")
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return errors.New("remote panel_url must use HTTPS")
	}
	return nil
}
