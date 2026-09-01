package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

const updaterConfigureResponseMaxBytes = 1 << 20

const updaterActivationAttempts = 3

type UpdaterRuntimeReport struct {
	Version   string
	Commit    string
	BuildDate string
	Hostname  string
	OS        string
	Arch      string
}

// UpdaterConfigureIdentity models the staged Control Panel response. Commit
// whitelists only panel_url, node_id, runtime_token, and service_name;
// service_type, transport_mode, and API are response assertions and are never
// merged into the root-owned local policy.
type UpdaterConfigureIdentity struct {
	PanelURL      string                       `json:"panel_url"`
	NodeID        string                       `json:"node_id"`
	RuntimeToken  string                       `json:"runtime_token"`
	ServiceName   string                       `json:"service_name"`
	ServiceType   string                       `json:"service_type"`
	TransportMode string                       `json:"transport_mode,omitempty"`
	API           UpdaterConfigureAPIAssertion `json:"api"`
}

// UpdaterConfigureAPIAssertion decodes only the bounded legacy API assertion
// returned by the Control Panel. It is never persisted and deliberately has
// no command, environment, argument, or filesystem-path fields.
type UpdaterConfigureAPIAssertion struct {
	Host       string `json:"host,omitempty"`
	Port       int    `json:"port,omitempty"`
	SSLEnabled bool   `json:"ssl_enabled,omitempty"`
}

type UpdaterStagedConfiguration struct {
	Config              UpdaterConfigureIdentity   `json:"config"`
	ConfigurationID     string                     `json:"configuration_id"`
	ActivationToken     string                     `json:"activation_token"`
	ActivationExpiresAt time.Time                  `json:"activation_expires_at"`
	ConfigureProtocol   int                        `json:"configure_protocol_version,omitempty"`
	LocalExecutorPolicy *ConfigurePolicyProjection `json:"local_executor_policy,omitempty"`
}

type UpdaterActivationResult struct {
	State                       string `json:"state"`
	ConfigurationID             string `json:"configuration_id"`
	ConfigureProtocol           int    `json:"configure_protocol_version,omitempty"`
	LocalExecutorPolicySHA256   string `json:"local_executor_policy_sha256,omitempty"`
	SourcePolicyRevision        int64  `json:"source_policy_revision,omitempty"`
	ProjectionRevision          int64  `json:"projection_revision,omitempty"`
	LocalExecutorPolicyRevision int64  `json:"local_executor_policy_revision,omitempty"`
}

type updaterConfigureAPIError struct {
	Code string `json:"code"`
}

type HostAgentConfigurePeerIdentity struct {
	UID uint32
	GID uint32
}

func StageHostAgentConfiguration(
	ctx context.Context,
	client *http.Client,
	panelURL, nodeID, configureToken string,
	peer HostAgentConfigurePeerIdentity,
	timeout time.Duration,
) (UpdaterStagedConfiguration, error) {
	if peer.UID == 0 || peer.GID == 0 {
		return UpdaterStagedConfiguration{}, errors.New("Host Agent configure peer identity must be non-root")
	}
	return stageUpdaterConfiguration(
		ctx,
		client,
		panelURL,
		nodeID,
		configureToken,
		peer,
		true,
		timeout,
	)
}

func stageUpdaterConfiguration(
	ctx context.Context,
	client *http.Client,
	panelURL, nodeID, configureToken string,
	peer HostAgentConfigurePeerIdentity,
	hostAgent bool,
	timeout time.Duration,
) (UpdaterStagedConfiguration, error) {
	panelURL = strings.TrimRight(strings.TrimSpace(panelURL), "/")
	nodeID = strings.TrimSpace(nodeID)
	configureToken = strings.TrimSpace(configureToken)
	if err := validatePanelURL(panelURL); err != nil {
		return UpdaterStagedConfiguration{}, err
	}
	if !identifierPattern.MatchString(nodeID) {
		return UpdaterStagedConfiguration{}, errors.New("node ID is invalid")
	}
	if configureToken == "" || len(configureToken) > 4096 {
		return UpdaterStagedConfiguration{}, errors.New("configure token is required")
	}
	if timeout <= 0 {
		return UpdaterStagedConfiguration{}, errors.New("configure timeout must be positive")
	}
	requestBody := struct {
		NodeID          string `json:"nodeId"`
		ConfigureToken  string `json:"configureToken"`
		ProtocolVersion int    `json:"protocolVersion,omitempty"`
		AgentUID        uint32 `json:"agentUid,omitempty"`
		AgentGID        uint32 `json:"agentGid,omitempty"`
	}{
		NodeID:         nodeID,
		ConfigureToken: configureToken,
	}
	if hostAgent {
		requestBody.ProtocolVersion = HostAgentConfigureProtocolVersion
		requestBody.AgentUID = peer.UID
		requestBody.AgentGID = peer.GID
	}
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return UpdaterStagedConfiguration{}, errors.New("encode updater stage request")
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, panelURL+"/api/node-agent/configure/stage", bytes.NewReader(payload))
	if err != nil {
		return UpdaterStagedConfiguration{}, errors.New("create updater stage request")
	}
	request.Header.Set("Content-Type", "application/json")
	configuredClient := updaterConfigureHTTPClient(client, timeout)
	response, err := configuredClient.Do(request)
	if err != nil {
		return UpdaterStagedConfiguration{}, fmt.Errorf("control panel stage request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := readUpdaterConfigureBody(response.Body)
	if err != nil {
		return UpdaterStagedConfiguration{}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return UpdaterStagedConfiguration{}, updaterConfigureStatusError("stage", response.StatusCode, body)
	}
	var staged UpdaterStagedConfiguration
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&staged); err != nil {
		return UpdaterStagedConfiguration{}, errors.New("decode control panel stage response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return UpdaterStagedConfiguration{}, errors.New("control panel stage response contains trailing data")
	}
	if err := validateUpdaterStagedConfiguration(staged, panelURL, nodeID, configureToken); err != nil {
		return UpdaterStagedConfiguration{}, err
	}
	if hostAgent {
		policy, err := configuredLocalExecutorPolicy(staged)
		if err != nil {
			return UpdaterStagedConfiguration{}, err
		}
		if policy.AgentUID != peer.UID || policy.AgentGID != peer.GID {
			return UpdaterStagedConfiguration{}, errors.New("staged Local Executor policy peer identity does not match the local service account")
		}
	}
	return staged, nil
}

func ActivateUpdaterConfiguration(ctx context.Context, client *http.Client, panelURL string, staged UpdaterStagedConfiguration, report UpdaterRuntimeReport, timeout time.Duration) (UpdaterActivationResult, error) {
	panelURL = strings.TrimRight(strings.TrimSpace(panelURL), "/")
	if timeout <= 0 {
		return UpdaterActivationResult{}, errors.New("activation timeout must be positive")
	}
	if err := validateUpdaterStagedConfiguration(staged, panelURL, staged.Config.NodeID, ""); err != nil {
		return UpdaterActivationResult{}, err
	}
	requestBody := struct {
		NodeID                      string `json:"nodeId"`
		ConfigurationID             string `json:"configurationId"`
		ActivationToken             string `json:"activationToken"`
		Version                     string `json:"version"`
		Commit                      string `json:"commit"`
		BuildDate                   string `json:"build_date"`
		Hostname                    string `json:"hostname"`
		OS                          string `json:"os"`
		Arch                        string `json:"arch"`
		ConfigureProtocolVersion    int    `json:"configureProtocolVersion,omitempty"`
		AgentUID                    uint32 `json:"agentUid,omitempty"`
		AgentGID                    uint32 `json:"agentGid,omitempty"`
		LocalExecutorPolicySHA256   string `json:"localExecutorPolicySha256,omitempty"`
		SourcePolicyRevision        int64  `json:"sourcePolicyRevision,omitempty"`
		ProjectionRevision          int64  `json:"projectionRevision,omitempty"`
		LocalExecutorPolicyRevision int64  `json:"localExecutorPolicyRevision,omitempty"`
	}{
		NodeID:          strings.TrimSpace(staged.Config.NodeID),
		ConfigurationID: strings.TrimSpace(staged.ConfigurationID),
		ActivationToken: strings.TrimSpace(staged.ActivationToken),
		Version:         strings.TrimSpace(report.Version),
		Commit:          strings.TrimSpace(report.Commit),
		BuildDate:       strings.TrimSpace(report.BuildDate),
		Hostname:        strings.TrimSpace(report.Hostname),
		OS:              strings.TrimSpace(report.OS),
		Arch:            strings.TrimSpace(report.Arch),
	}
	if staged.Config.TransportMode == "pull_v2" {
		policy, err := configuredLocalExecutorPolicy(staged)
		if err != nil {
			return UpdaterActivationResult{}, err
		}
		requestBody.ConfigureProtocolVersion = HostAgentConfigureProtocolVersion
		requestBody.AgentUID = policy.AgentUID
		requestBody.AgentGID = policy.AgentGID
		requestBody.LocalExecutorPolicySHA256 = staged.LocalExecutorPolicy.SHA256
		requestBody.SourcePolicyRevision = staged.LocalExecutorPolicy.SourcePolicyRevision
		requestBody.ProjectionRevision = staged.LocalExecutorPolicy.ProjectionRevision
		requestBody.LocalExecutorPolicyRevision = staged.LocalExecutorPolicy.PolicyRevision
	}
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return UpdaterActivationResult{}, errors.New("encode updater activation request")
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	configuredClient := updaterConfigureHTTPClient(client, 0)
	perAttemptTimeout := timeout / updaterActivationAttempts
	if perAttemptTimeout <= 0 {
		perAttemptTimeout = timeout
	}
	var lastErr error
	for attempt := 0; attempt < updaterActivationAttempts; attempt++ {
		if err := requestCtx.Err(); err != nil {
			return UpdaterActivationResult{}, err
		}
		attemptCtx, attemptCancel := context.WithTimeout(requestCtx, perAttemptTimeout)
		request, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, panelURL+"/api/node-agent/configure/activate", bytes.NewReader(payload))
		if err != nil {
			attemptCancel()
			return UpdaterActivationResult{}, errors.New("create updater activation request")
		}
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := configuredClient.Do(request)
		if requestErr != nil {
			attemptCancel()
			lastErr = fmt.Errorf("control panel activation request failed: %w", requestErr)
			if attempt+1 < updaterActivationAttempts && requestCtx.Err() == nil {
				continue
			}
			break
		}
		body, readErr := readUpdaterConfigureBody(response.Body)
		closeErr := response.Body.Close()
		statusCode := response.StatusCode
		attemptCancel()
		if statusCode >= http.StatusInternalServerError {
			if readErr != nil || closeErr != nil {
				lastErr = fmt.Errorf("control panel activation failed: HTTP %d", statusCode)
			} else {
				lastErr = updaterConfigureStatusError("activation", statusCode, body)
			}
			if attempt+1 < updaterActivationAttempts && requestCtx.Err() == nil {
				continue
			}
			break
		}
		if readErr != nil || closeErr != nil {
			return UpdaterActivationResult{}, errors.New("read control panel activation response")
		}
		if statusCode != http.StatusOK {
			return UpdaterActivationResult{}, updaterConfigureStatusError("activation", statusCode, body)
		}
		var result UpdaterActivationResult
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(&result); err != nil {
			return UpdaterActivationResult{}, errors.New("decode control panel activation response")
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return UpdaterActivationResult{}, errors.New("control panel activation response contains trailing data")
		}
		if result.ConfigurationID != staged.ConfigurationID || (result.State != "activated" && result.State != "already_activated") {
			return UpdaterActivationResult{}, errors.New("control panel activation response does not match the staged configuration")
		}
		if staged.Config.TransportMode == "pull_v2" &&
			(result.ConfigureProtocol != HostAgentConfigureProtocolVersion ||
				result.LocalExecutorPolicySHA256 != staged.LocalExecutorPolicy.SHA256 ||
				result.SourcePolicyRevision != staged.LocalExecutorPolicy.SourcePolicyRevision ||
				result.ProjectionRevision != staged.LocalExecutorPolicy.ProjectionRevision ||
				result.LocalExecutorPolicyRevision != staged.LocalExecutorPolicy.PolicyRevision) {
			return UpdaterActivationResult{}, errors.New("control panel activation response does not bind the installed Local Executor policy")
		}
		return result, nil
	}
	if lastErr != nil {
		return UpdaterActivationResult{}, lastErr
	}
	return UpdaterActivationResult{}, errors.New("control panel activation failed")
}

func updaterConfigureHTTPClient(client *http.Client, timeout time.Duration) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	configured := *client
	configured.Timeout = timeout
	configured.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &configured
}

func updaterConfigureStatusError(operation string, status int, body []byte) error {
	var apiErr updaterConfigureAPIError
	_ = json.Unmarshal(body, &apiErr)
	code := strings.TrimSpace(apiErr.Code)
	if identifierPattern.MatchString(code) {
		return fmt.Errorf("control panel %s failed: HTTP %d code %s", operation, status, code)
	}
	return fmt.Errorf("control panel %s failed: HTTP %d", operation, status)
}

func validateUpdaterStagedConfiguration(staged UpdaterStagedConfiguration, panelURL, expectedNodeID, configureToken string) error {
	if err := validateUpdaterConfigureIdentity(staged.Config, expectedNodeID, configureToken); err != nil {
		return err
	}
	if strings.TrimRight(strings.TrimSpace(staged.Config.PanelURL), "/") != strings.TrimRight(strings.TrimSpace(panelURL), "/") {
		return errors.New("configured panel URL does not match the requested Control Panel")
	}
	if !identifierPattern.MatchString(strings.TrimSpace(staged.ConfigurationID)) {
		return errors.New("staged configuration ID is invalid")
	}
	activationToken := strings.TrimSpace(staged.ActivationToken)
	if activationToken == "" || len(activationToken) > 4096 || activationToken == strings.TrimSpace(configureToken) || activationToken == strings.TrimSpace(staged.Config.RuntimeToken) || staged.ActivationExpiresAt.IsZero() {
		return errors.New("staged activation credential is invalid")
	}
	if staged.Config.TransportMode == "pull_v2" {
		if _, err := configuredLocalExecutorPolicy(staged); err != nil {
			return err
		}
	} else if staged.ConfigureProtocol != 0 || staged.LocalExecutorPolicy != nil {
		return errors.New("legacy updater stage unexpectedly contains a Local Executor policy")
	}
	return nil
}

func configuredLocalExecutorPolicy(staged UpdaterStagedConfiguration) (LocalExecutorPolicy, error) {
	if staged.ConfigureProtocol != HostAgentConfigureProtocolVersion ||
		staged.LocalExecutorPolicy == nil {
		return LocalExecutorPolicy{}, errors.New("pull_v2 configure response is missing the required Local Executor policy protocol")
	}
	projection := staged.LocalExecutorPolicy
	if err := ValidateConfigurePolicyActivation(
		projection.Policy,
		projection.SHA256,
		projection.SourcePolicyRevision,
		projection.ProjectionRevision,
		projection.PolicyRevision,
	); err != nil {
		return LocalExecutorPolicy{}, err
	}
	var policy LocalExecutorPolicy
	if err := json.Unmarshal(projection.Policy, &policy); err != nil {
		return LocalExecutorPolicy{}, errors.New("decode staged Local Executor policy")
	}
	return policy, nil
}

func ValidateInstalledUpdaterIdentity(path string, identity UpdaterConfigureIdentity) error {
	cfg, err := LoadManagedBootstrapConfig(path, true)
	if err != nil {
		return fmt.Errorf("validate installed updater config: %w", err)
	}
	if strings.TrimRight(strings.TrimSpace(cfg.PanelURL), "/") != strings.TrimRight(strings.TrimSpace(identity.PanelURL), "/") ||
		strings.TrimSpace(cfg.NodeID) != strings.TrimSpace(identity.NodeID) ||
		strings.TrimSpace(cfg.RuntimeToken) != strings.TrimSpace(identity.RuntimeToken) ||
		strings.TrimSpace(cfg.ServiceName) != strings.TrimSpace(identity.ServiceName) {
		return errors.New("installed updater identity does not match the staged configuration")
	}
	return nil
}

func readUpdaterConfigureBody(reader io.Reader) ([]byte, error) {
	limited := &io.LimitedReader{R: reader, N: updaterConfigureResponseMaxBytes + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, errors.New("read control panel configure response")
	}
	if len(body) == 0 || len(body) > updaterConfigureResponseMaxBytes {
		return nil, errors.New("control panel configure response is empty or too large")
	}
	return body, nil
}

func validateUpdaterConfigureIdentity(identity UpdaterConfigureIdentity, expectedNodeID, configureToken string) error {
	identity.PanelURL = strings.TrimSpace(identity.PanelURL)
	identity.NodeID = strings.TrimSpace(identity.NodeID)
	identity.RuntimeToken = strings.TrimSpace(identity.RuntimeToken)
	identity.ServiceName = strings.TrimSpace(identity.ServiceName)
	identity.ServiceType = strings.TrimSpace(identity.ServiceType)
	identity.TransportMode = strings.TrimSpace(identity.TransportMode)
	if err := validatePanelURL(identity.PanelURL); err != nil {
		return errors.New("configured panel URL is invalid")
	}
	if identity.NodeID != strings.TrimSpace(expectedNodeID) {
		return errors.New("configured node ID does not match the requested updater")
	}
	if identity.ServiceType != "update_agent" {
		return errors.New("configured node type does not match update_agent")
	}
	if identity.TransportMode != "" && identity.TransportMode != "pull_v2" {
		return errors.New("configured updater transport mode is invalid")
	}
	if identity.RuntimeToken == "" || len(identity.RuntimeToken) > 4096 || identity.RuntimeToken == strings.TrimSpace(configureToken) {
		return errors.New("configured runtime token is invalid")
	}
	if identity.ServiceName == "" || len(identity.ServiceName) > 255 {
		return errors.New("configured service name is invalid")
	}
	if identity.API.Host != "" || identity.API.Port != 0 || identity.API.SSLEnabled {
		host := strings.Trim(strings.TrimSpace(identity.API.Host), "[]")
		if host == "" || strings.ContainsAny(host, "/@?#") || identity.API.Port < 1 || identity.API.Port > 65535 {
			return errors.New("configured updater API identity is invalid")
		}
	}
	return nil
}

func mergeUpdaterConfiguredIdentity(existing []byte, identity UpdaterConfigureIdentity) ([]byte, error) {
	if err := validateUpdaterConfigureIdentity(identity, identity.NodeID, ""); err != nil {
		return nil, err
	}
	template, err := prepareUpdaterConfigTemplate(existing)
	if err != nil {
		return nil, err
	}
	return template.merge(identity)
}

type updaterConfigTemplate struct {
	fields map[string]json.RawMessage
}

func prepareUpdaterConfigTemplate(existing []byte) (updaterConfigTemplate, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return updaterConfigTemplate{fields: map[string]json.RawMessage{}}, nil
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(existing))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return updaterConfigTemplate{}, fmt.Errorf("decode existing updater config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return updaterConfigTemplate{}, errors.New("existing updater config contains trailing data")
	}
	if err := json.Unmarshal(existing, &fields); err != nil {
		return updaterConfigTemplate{}, errors.New("decode existing updater config fields")
	}
	return updaterConfigTemplate{fields: fields}, nil
}

func (t updaterConfigTemplate) merge(identity UpdaterConfigureIdentity) ([]byte, error) {
	if err := validateUpdaterConfigureIdentity(identity, identity.NodeID, ""); err != nil {
		return nil, err
	}
	fields := make(map[string]json.RawMessage, 4)
	for name, value := range map[string]string{
		"panel_url":     strings.TrimSpace(identity.PanelURL),
		"node_id":       strings.TrimSpace(identity.NodeID),
		"runtime_token": strings.TrimSpace(identity.RuntimeToken),
		"service_name":  strings.TrimSpace(identity.ServiceName),
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, errors.New("encode updater identity")
		}
		fields[name] = encoded
	}
	merged, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return nil, errors.New("format updater config")
	}
	return append(merged, '\n'), nil
}

func updaterConfigureRuntimeReport(version, commit, buildDate, hostname string) UpdaterRuntimeReport {
	return UpdaterRuntimeReport{Version: version, Commit: commit, BuildDate: buildDate, Hostname: hostname, OS: runtime.GOOS, Arch: runtime.GOARCH}
}
