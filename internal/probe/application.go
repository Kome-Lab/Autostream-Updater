package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const maxIdentityBytes = 64 << 10

var versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$`)

type ExpectedIdentity struct {
	ServiceID      string
	ServiceType    string
	ConfigRevision int64
}

type Identity struct {
	Version        string `json:"version"`
	ServiceID      string `json:"service_id"`
	ServiceType    string `json:"service_type"`
	ConfigRevision int64  `json:"config_revision"`
}

type Client struct {
	HTTP *http.Client
}

// FetchApplicationIdentity performs a strict, bounded, non-cacheable identity
// probe against a loopback-only /updater/version endpoint. It follows no
// redirects and returns only allow-listed errors without response bodies.
func (c Client) FetchApplicationIdentity(
	ctx context.Context,
	endpoint string,
	expected ExpectedIdentity,
) (Identity, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.EscapedPath() != "/updater/version" {
		return Identity{}, errors.New("application identity endpoint is invalid")
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() || parsed.Port() == "" {
		return Identity{}, errors.New("application identity endpoint must be loopback-only")
	}
	if expected.ServiceID == "" || expected.ServiceID != strings.TrimSpace(expected.ServiceID) ||
		!validServiceType(expected.ServiceType) ||
		expected.ConfigRevision < 1 {
		return Identity{}, errors.New("expected application identity is invalid")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Identity{}, errors.New("create application identity request")
	}
	request.Header.Set("Accept", "application/json")
	client := http.Client{}
	if c.HTTP != nil {
		client = *c.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return Identity{}, errors.New("fetch application identity")
	}
	defer response.Body.Close()
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return Identity{}, errors.New("application identity response must use Cache-Control no-store")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxIdentityBytes))
		return Identity{}, fmt.Errorf("application identity endpoint returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxIdentityBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxIdentityBytes {
		return Identity{}, errors.New("application identity response is not bounded")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var identity Identity
	if err := decoder.Decode(&identity); err != nil {
		return Identity{}, errors.New("application identity response is invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Identity{}, errors.New("application identity response contains trailing data")
	}
	if !versionPattern.MatchString(identity.Version) ||
		identity.ServiceID != expected.ServiceID ||
		identity.ServiceType != expected.ServiceType ||
		identity.ConfigRevision != expected.ConfigRevision {
		return Identity{}, errors.New("application identity response does not match policy")
	}
	return identity, nil
}

func validServiceType(value string) bool {
	switch value {
	case "control_panel", "worker", "encoder_recorder", "discord_bot", "observability":
		return true
	default:
		return false
	}
}

func hasNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}
