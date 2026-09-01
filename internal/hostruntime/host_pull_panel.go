package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/version"
)

const (
	HostTransportPullV2      = "pull_v2"
	HostAgentProtocolVersion = "2"

	hostAgentControlResponseMaxBytes = 1 << 20
	hostAgentPolicyResponseMaxBytes  = 1 << 20
)

// HostAgentBinding is server-owned identity returned after the runtime token
// has been matched to its pre-created update_agent service. A Host Pull Agent
// never sends these values as self-asserted registration input.
type HostAgentBinding struct {
	ServiceID       string `json:"service_id"`
	ServiceType     string `json:"service_type"`
	TransportMode   string `json:"transport_mode"`
	ExecutionHostID string `json:"execution_host_id"`
	OwnershipEpoch  int64  `json:"ownership_epoch"`
}

type HostAgentPolicyRequest struct {
	ServiceID       string `json:"service_id"`
	CurrentRevision int64  `json:"current_revision"`
}

// HostAgentPolicy is the read-only pull_v2 view for one execution host. It is
// deliberately separate from obsolete policy shapes so strict decoders never
// receive pull-specific fields.
type HostAgentPolicy struct {
	ServiceID                   string                         `json:"service_id"`
	TransportMode               string                         `json:"transport_mode"`
	ExecutionHostID             string                         `json:"execution_host_id"`
	OwnershipEpoch              int64                          `json:"ownership_epoch"`
	Revision                    int64                          `json:"revision"`
	SourcePolicyRevision        int64                          `json:"source_policy_revision"`
	LocalExecutorPolicyRevision int64                          `json:"local_executor_policy_revision"`
	ObserveOnly                 bool                           `json:"observe_only"`
	LocalExecutorPolicySHA256   string                         `json:"local_executor_policy_sha256,omitempty"`
	RuntimeRequirement          *HostRuntimeRequirement        `json:"runtime_requirement,omitempty"`
	SelfUpdate                  *HostSelfUpdateRequest         `json:"self_update,omitempty"`
	SelfUpdateID                string                         `json:"self_update_id,omitempty"`
	SelfUpdateRevision          int64                          `json:"self_update_revision,omitempty"`
	SelfUpdateStatus            string                         `json:"self_update_status,omitempty"`
	RuntimeTokenRotation        *HostAgentRuntimeTokenRotation `json:"runtime_token_rotation,omitempty"`
	Targets                     []HostAgentPolicyTarget        `json:"targets"`
}

type HostAgentPolicyTarget struct {
	ServiceID             string             `json:"service_id"`
	ServiceType           string             `json:"service_type"`
	DeploymentMode        string             `json:"deployment_mode"`
	AppliedConfigRevision int64              `json:"applied_config_revision,omitempty"`
	AppliedConfigSHA256   string             `json:"applied_config_sha256,omitempty"`
	DesiredEndpoint       *HostAgentEndpoint `json:"desired_endpoint,omitempty"`
	AppliedEndpoint       *HostAgentEndpoint `json:"applied_endpoint,omitempty"`
	LocalListenEndpoint   *HostAgentEndpoint `json:"local_listen_endpoint,omitempty"`
	LocalHealthEndpoint   *HostAgentEndpoint `json:"local_health_endpoint,omitempty"`
}

type HostAgentEndpoint struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	SSLEnabled bool   `json:"ssl_enabled"`
	PublicURL  string `json:"public_url"`
}

type HostPullControlPlane interface {
	RegisterHostAgent(context.Context, Config, map[string]any) (HostAgentBinding, error)
	HeartbeatHostAgent(context.Context, Config, string, map[string]any) error
	FetchHostAgentPolicy(context.Context, string, int64) (*HostAgentPolicy, bool, error)
}

func (c PanelClient) RegisterHostAgent(ctx context.Context, cfg Config, capabilities map[string]any) (HostAgentBinding, error) {
	hostname, _ := os.Hostname()
	name := strings.TrimSpace(cfg.ServiceName)
	if name == "" {
		name = "Autostream Host Agent"
	}
	body := map[string]any{
		"service_id":     strings.TrimSpace(cfg.NodeID),
		"service_type":   ServiceTypeUpdateAgent,
		"service_name":   name,
		"transport_mode": HostTransportPullV2,
		"version":        c.runtimeVersion(),
		"commit":         version.Commit,
		"build_date":     version.BuildDate,
		"hostname":       hostname,
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"capabilities":   capabilities,
	}
	var binding HostAgentBinding
	if err := c.postHostAgent(ctx, "/services/register", body, &binding); err != nil {
		return HostAgentBinding{}, err
	}
	if err := binding.validateForService(cfg.NodeID); err != nil {
		return HostAgentBinding{}, err
	}
	return binding, nil
}

func (c PanelClient) HeartbeatHostAgent(ctx context.Context, cfg Config, status string, capabilities map[string]any) error {
	hostname, _ := os.Hostname()
	body := map[string]any{
		"service_id":   strings.TrimSpace(cfg.NodeID),
		"status":       strings.TrimSpace(status),
		"version":      c.runtimeVersion(),
		"commit":       version.Commit,
		"build_date":   version.BuildDate,
		"hostname":     hostname,
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"capabilities": capabilities,
	}
	return c.postHostAgent(ctx, "/services/heartbeat", body, nil)
}

func (c PanelClient) FetchHostAgentPolicy(ctx context.Context, serviceID string, currentRevision int64) (*HostAgentPolicy, bool, error) {
	serviceID = strings.TrimSpace(serviceID)
	if !identifierPattern.MatchString(serviceID) || currentRevision < 0 {
		return nil, false, errors.New("host agent policy request identity is invalid")
	}
	payload, err := json.Marshal(HostAgentPolicyRequest{ServiceID: serviceID, CurrentRevision: currentRevision})
	if err != nil {
		return nil, false, errors.New("encode host agent policy request")
	}
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/services/host-agent/policy", bytes.NewReader(payload))
	if err != nil {
		return nil, false, errors.New("create host agent policy request")
	}
	request.Header.Set("Authorization", "Bearer "+c.runtimeToken())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	configuredClient := *client
	if configuredClient.Timeout <= 0 {
		configuredClient.Timeout = 15 * time.Second
	}
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := configuredClient.Do(request)
	if err != nil {
		return nil, false, errors.New("fetch host agent policy")
	}
	defer response.Body.Close()
	if !responseNoStore(response.Header.Values("Cache-Control")) {
		return nil, false, errors.New("host agent policy response must use Cache-Control no-store")
	}
	if response.StatusCode == http.StatusNoContent {
		return nil, false, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		var apiError struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data, &apiError)
		return nil, false, &PanelHTTPError{Status: response.StatusCode, Code: safePanelErrorCode(apiError.Code)}
	}
	limited := &io.LimitedReader{R: response.Body, N: hostAgentPolicyResponseMaxBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil || len(data) == 0 || len(data) > hostAgentPolicyResponseMaxBytes {
		return nil, false, errors.New("read host agent policy response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy HostAgentPolicy
	if err := decoder.Decode(&policy); err != nil {
		return nil, false, errors.New("decode host agent policy response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, false, errors.New("host agent policy response contains trailing data")
	}
	if err := policy.validateForService(serviceID, currentRevision); err != nil {
		return nil, false, err
	}
	return &policy, true, nil
}

func (c PanelClient) postHostAgent(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return errors.New("encode host agent request")
	}
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(payload))
	if err != nil {
		return errors.New("create host agent request")
	}
	request.Header.Set("Authorization", "Bearer "+c.runtimeToken())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	configuredClient := *client
	if configuredClient.Timeout <= 0 {
		configuredClient.Timeout = 15 * time.Second
	}
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := configuredClient.Do(request)
	if err != nil {
		return errors.New("send host agent request")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		var apiError struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data, &apiError)
		return &PanelHTTPError{Status: response.StatusCode, Code: safePanelErrorCode(apiError.Code)}
	}
	if out == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	limited := &io.LimitedReader{R: response.Body, N: hostAgentControlResponseMaxBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil || len(data) == 0 || len(data) > hostAgentControlResponseMaxBytes {
		return errors.New("read host agent response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(out); err != nil {
		return errors.New("decode host agent response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("host agent response contains trailing data")
	}
	return nil
}

func (b HostAgentBinding) validateForService(serviceID string) error {
	trimmedServiceID := strings.TrimSpace(b.ServiceID)
	trimmedHostID := strings.TrimSpace(b.ExecutionHostID)
	if b.ServiceID != trimmedServiceID ||
		b.ExecutionHostID != trimmedHostID ||
		trimmedServiceID != strings.TrimSpace(serviceID) ||
		b.ServiceType != ServiceTypeUpdateAgent ||
		b.TransportMode != HostTransportPullV2 ||
		!validExecutionHostID(trimmedHostID) ||
		b.OwnershipEpoch < 0 {
		return errors.New("host agent registration binding is invalid")
	}
	return nil
}

func (p HostAgentPolicy) validateForService(serviceID string, currentRevision int64) error {
	binding := HostAgentBinding{
		ServiceID:       p.ServiceID,
		ServiceType:     ServiceTypeUpdateAgent,
		TransportMode:   p.TransportMode,
		ExecutionHostID: p.ExecutionHostID,
		OwnershipEpoch:  p.OwnershipEpoch,
	}
	if err := binding.validateForService(serviceID); err != nil ||
		p.Revision < 1 ||
		p.Revision < currentRevision ||
		p.SourcePolicyRevision < 1 ||
		p.ObserveOnly != (p.OwnershipEpoch == 0) {
		return errors.New("host agent policy identity, revision, or mode is invalid")
	}
	if p.OwnershipEpoch == 0 {
		if (p.LocalExecutorPolicyRevision == 0) != (p.LocalExecutorPolicySHA256 == "") ||
			p.LocalExecutorPolicyRevision < 0 ||
			(p.LocalExecutorPolicySHA256 != "" && !digestPattern.MatchString(p.LocalExecutorPolicySHA256)) {
			return errors.New("host agent local executor policy binding is invalid")
		}
	} else if p.LocalExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(p.LocalExecutorPolicySHA256) {
		return errors.New("host agent local executor policy digest is invalid")
	}
	if p.RuntimeRequirement != nil {
		if err := p.RuntimeRequirement.validate(); err != nil {
			return err
		}
	}
	if p.SelfUpdate != nil {
		if p.OwnershipEpoch < 1 ||
			p.RuntimeRequirement == nil ||
			p.SelfUpdate.validate() != nil ||
			!identifierPattern.MatchString(p.SelfUpdateID) ||
			p.SelfUpdateRevision < 1 ||
			!validHostSelfUpdateDirectiveStatus(p.SelfUpdateStatus) {
			return errors.New("host agent self-update directive is invalid")
		}
		targetRuntime := HostRuntimeCompatibility{
			AgentVersion:            p.SelfUpdate.AgentVersion,
			ExecutorVersion:         p.SelfUpdate.ExecutorVersion,
			AgentProtocolVersion:    p.SelfUpdate.AgentProtocolVersion,
			ExecutorProtocolVersion: p.SelfUpdate.ExecutorProtocolVersion,
			MutationProtocolVersion: p.SelfUpdate.MutationProtocolVersion,
			RecoveryProtocolVersion: p.SelfUpdate.RecoveryProtocolVersion,
		}
		if err := ValidateHostRuntimeCompatibility(
			targetRuntime, *p.RuntimeRequirement,
		); err != nil {
			return errors.New("host agent self-update does not satisfy the runtime requirement")
		}
	} else if p.SelfUpdateStatus == "cancel_requested" {
		if !identifierPattern.MatchString(p.SelfUpdateID) ||
			p.SelfUpdateRevision < 1 || p.RuntimeRequirement != nil {
			return errors.New("host agent self-update cancellation is invalid")
		}
	} else if p.SelfUpdateID != "" || p.SelfUpdateRevision != 0 ||
		p.SelfUpdateStatus != "" || p.RuntimeRequirement != nil {
		return errors.New("host agent self-update metadata is incomplete")
	}
	if p.RuntimeTokenRotation != nil {
		rotation := p.RuntimeTokenRotation
		if err := rotation.Validate(); err != nil ||
			p.OwnershipEpoch < 1 ||
			rotation.ServiceID != p.ServiceID ||
			rotation.ExecutionHostID != p.ExecutionHostID ||
			rotation.ExpectedOwnershipEpoch != p.OwnershipEpoch ||
			rotation.ExpectedSourcePolicyRevision != p.SourcePolicyRevision ||
			rotation.ExpectedProjectionRevision != p.Revision ||
			rotation.ExpectedLocalExecutorPolicyRevision != p.LocalExecutorPolicyRevision {
			return errors.New("host agent runtime token rotation directive is invalid")
		}
	}
	if p.RuntimeTokenRotation != nil && p.SelfUpdate != nil {
		return errors.New("host lifecycle directives overlap")
	}
	seen := make(map[string]struct{}, len(p.Targets))
	for _, target := range p.Targets {
		serviceID := strings.TrimSpace(target.ServiceID)
		serviceType := strings.TrimSpace(target.ServiceType)
		deploymentMode := strings.TrimSpace(target.DeploymentMode)
		if target.ServiceID != serviceID ||
			target.ServiceType != serviceType ||
			target.DeploymentMode != deploymentMode ||
			!identifierPattern.MatchString(serviceID) {
			return errors.New("host agent policy target identity is invalid")
		}
		if _, exists := seen[serviceID]; exists {
			return errors.New("host agent policy target identity is duplicated")
		}
		seen[serviceID] = struct{}{}
		switch serviceType {
		case "control_panel", "worker", "encoder_recorder", "discord_bot", "observability":
		default:
			return errors.New("host agent policy target type is invalid")
		}
		if deploymentMode != ModeSystemd && deploymentMode != ModeDocker {
			return errors.New("host agent policy deployment mode is invalid")
		}
		if target.AppliedConfigRevision < 0 ||
			(target.AppliedConfigSHA256 != "" && !digestPattern.MatchString(target.AppliedConfigSHA256)) {
			return errors.New("host agent policy target config revision is invalid")
		}
		if err := validateOptionalHostAgentEndpoint(target.DesiredEndpoint); err != nil {
			return err
		}
		if err := validateOptionalHostAgentEndpoint(target.AppliedEndpoint); err != nil {
			return err
		}
		if err := validateOptionalHostAgentEndpoint(target.LocalListenEndpoint); err != nil {
			return err
		}
		if target.LocalListenEndpoint != nil && target.LocalListenEndpoint.Port < 1024 {
			return errors.New("host agent local listen endpoint must use an unprivileged port")
		}
		if err := validateOptionalHostAgentEndpoint(target.LocalHealthEndpoint); err != nil {
			return err
		}
	}
	return nil
}

func validHostSelfUpdateDirectiveStatus(status string) bool {
	switch status {
	case "queued", "staging", "activating", "verifying", "rolling_back":
		return true
	default:
		return false
	}
}

func (t HostAgentPolicyTarget) appliedConfigRevision() int64 {
	if t.AppliedConfigRevision > 0 {
		return t.AppliedConfigRevision
	}
	// Migration bridge for services registered before applied config tracking
	// was introduced. The runtime contract started at revision one.
	return 1
}

func validateOptionalHostAgentEndpoint(endpoint *HostAgentEndpoint) error {
	if endpoint == nil {
		return nil
	}
	host := strings.TrimSpace(endpoint.Host)
	publicURL := strings.TrimSpace(endpoint.PublicURL)
	parsed, err := url.Parse(publicURL)
	if endpoint.Host != host ||
		endpoint.PublicURL != publicURL ||
		host == "" ||
		endpoint.Port < 1 || endpoint.Port > 65535 ||
		err != nil ||
		parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("host agent policy endpoint is invalid")
	}
	return nil
}

func validExecutionHostID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 1 || len(value) > 191 {
		return false
	}
	for index, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || (index > 0 && strings.ContainsRune("._:-", r)) {
			continue
		}
		return false
	}
	return true
}
