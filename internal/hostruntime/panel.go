package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/version"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

type UpdateJob struct {
	ProtocolVersion int                              `json:"protocol_version,omitempty"`
	CommandID       string                           `json:"command_id,omitempty"`
	ID              string                           `json:"id"`
	Operation       string                           `json:"operation,omitempty"`
	PortReconfigure *SystemdPortMutationGrantBinding `json:"port_reconfigure,omitempty"`
	AgentServiceID  string                           `json:"updater_id,omitempty"`
	HostID          string                           `json:"host_id,omitempty"`
	TransportMode   string                           `json:"transport_mode,omitempty"`
	OwnershipEpoch  int64                            `json:"ownership_epoch,omitempty"`
	PolicyRevision  int64                            `json:"policy_revision,omitempty"`
	TargetID        string                           `json:"target_id"`
	TargetType      string                           `json:"target_type,omitempty"`
	ServiceType     string                           `json:"service_type"`
	DeploymentMode  string                           `json:"deployment_mode"`
	CurrentVersion  string                           `json:"current_version,omitempty"`
	TargetVersion   string                           `json:"target_version"`
	Version         string                           `json:"version,omitempty"`
	LeaseToken      string                           `json:"lease_token,omitempty"`
	ReleaseToken    BoundedSecret                    `json:"-"`
	LeaseExpiresAt  string                           `json:"lease_expires_at,omitempty"`
	Status          string                           `json:"status,omitempty"`
	Progress        int                              `json:"progress,omitempty"`
	Code            string                           `json:"code,omitempty"`
	Message         string                           `json:"message,omitempty"`
	ArtifactDigest  string                           `json:"artifact_digest,omitempty"`
	PreviousDigest  string                           `json:"previous_digest,omitempty"`
	Sequence        uint64                           `json:"sequence,omitempty"`
	// ReportSequence is local-only. Claim responses define it as the exact
	// sequence to use for the first report, while Sequence remains the last
	// sequence stored by the server.
	ReportSequence   uint64 `json:"-"`
	LeaseGeneration  uint64 `json:"lease_generation,omitempty"`
	RecoveryRequired bool   `json:"recovery_required,omitempty"`
	RecoveryClear    bool   `json:"-"`
}

const (
	updateJobOperationSoftwareUpdate  = "software_update"
	updateJobOperationPortReconfigure = "port_reconfigure"
	updateJobOperationBootstrap       = "bootstrap"
	updateJobOperationHostSelfUpdate  = "host_self_update"
)

func (j UpdateJob) EffectiveOperation() string {
	operation := strings.TrimSpace(j.Operation)
	if operation == "" {
		return updateJobOperationSoftwareUpdate
	}
	return operation
}

func (j UpdateJob) validateOperationUnion() error {
	switch j.EffectiveOperation() {
	case updateJobOperationSoftwareUpdate:
		if j.PortReconfigure != nil {
			return errors.New("software update job unexpectedly contains a port plan")
		}
	case updateJobOperationPortReconfigure:
		if j.Operation != updateJobOperationPortReconfigure ||
			j.PortReconfigure == nil ||
			j.PortReconfigure.validatePortJobContract(j.DeploymentMode) != nil {
			return errors.New("port reconfiguration job contract is invalid")
		}
	case updateJobOperationBootstrap, updateJobOperationHostSelfUpdate:
		if j.ProtocolVersion != 2 || j.PortReconfigure != nil {
			return errors.New("v2 updater job contract is invalid")
		}
	default:
		return errors.New("update job operation is invalid")
	}
	return nil
}

func (p SystemdPortMutationGrantBinding) validatePortJobContract(
	deploymentMode string,
) error {
	if p.NetworkNamespace != systemdPortNetworkNamespaceHost ||
		p.Protocol != systemdPortProtocolTCP ||
		p.OldPort < 1 || p.OldPort > 65535 ||
		p.NewPort < 1 || p.NewPort > 65535 ||
		p.ExpectedEndpointRevision < 1 ||
		p.TargetEndpointRevision != p.ExpectedEndpointRevision+1 ||
		p.ExpectedConfigRevision < 1 ||
		p.TargetConfigRevision != p.ExpectedConfigRevision+1 ||
		!digestPattern.MatchString(p.ExpectedConfigSHA256) ||
		!digestPattern.MatchString(p.TargetConfigSHA256) ||
		p.ExpectedConfigSHA256 == p.TargetConfigSHA256 ||
		p.ExpectedSourcePolicyRevision < 1 ||
		p.ExpectedUpdaterPolicyRevision < 1 ||
		p.ExpectedExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(p.ExpectedExecutorPolicySHA256) ||
		!mutationPlanHashPattern.MatchString(p.PortPlanSHA256) {
		return errors.New("port reconfiguration immutable fields are invalid")
	}
	switch deploymentMode {
	case ModeSystemd:
		if p.Docker != nil ||
			!validSystemdPort(p.OldPort) ||
			!validSystemdPort(p.NewPort) ||
			p.OldPort == p.NewPort {
			return errors.New("systemd port job contains Docker-only fields")
		}
		return nil
	case ModeDocker:
		if err := p.Docker.validate(p.ExpectedExecutorPolicyRevision); err != nil {
			return err
		}
		if p.OldPort == p.NewPort &&
			p.Docker.OldPublishedPort == p.Docker.NewPublishedPort &&
			p.Docker.OldContainerPort == p.Docker.NewContainerPort {
			return errors.New("Docker port job is a no-op")
		}
		return nil
	default:
		return errors.New("port reconfiguration deployment mode is invalid")
	}
}

func (j UpdateJob) EffectiveVersion() string {
	if strings.TrimSpace(j.TargetVersion) != "" {
		return strings.TrimSpace(j.TargetVersion)
	}
	return strings.TrimSpace(j.Version)
}

func (j UpdateJob) EffectiveType() string {
	if strings.TrimSpace(j.ServiceType) != "" {
		return strings.TrimSpace(j.ServiceType)
	}
	return strings.TrimSpace(j.TargetType)
}

type ClaimResponse struct {
	Job              *UpdateJob    `json:"job,omitempty"`
	LeaseToken       string        `json:"lease_token,omitempty"`
	ReleaseToken     BoundedSecret `json:"release_token,omitempty"`
	LeaseExpiresAt   string        `json:"lease_expires_at,omitempty"`
	ReportSequence   uint64        `json:"report_sequence,omitempty"`
	LeaseGeneration  uint64        `json:"lease_generation,omitempty"`
	RecoveryRequired bool          `json:"recovery_required,omitempty"`
	LastStatus       string        `json:"last_status,omitempty"`
	ClearActiveJobID bool          `json:"clear_active_job_id,omitempty"`
	TerminalJob      *UpdateJob    `json:"terminal_job,omitempty"`
	UpdateJob
}

type JobReport struct {
	ServiceID       string                        `json:"service_id"`
	LeaseToken      string                        `json:"lease_token"`
	Sequence        uint64                        `json:"sequence"`
	LeaseGeneration uint64                        `json:"lease_generation"`
	Status          string                        `json:"status"`
	Progress        int                           `json:"progress,omitempty"`
	Code            string                        `json:"code,omitempty"`
	Message         string                        `json:"message,omitempty"`
	ArtifactDigest  string                        `json:"artifact_digest,omitempty"`
	PreviousDigest  string                        `json:"previous_digest,omitempty"`
	PortReconfigure *PortReconfigurationJobReport `json:"port_reconfigure,omitempty"`
}

// PortReconfigurationJobReport is the complete public result contract sent to
// the Control Panel. The richer SystemdPortReconfigureResult is privileged
// local reconciliation state and must never be exposed in a job report.
type PortReconfigurationJobReport struct {
	Result string `json:"result"`
}

type MutationGrantBinding struct {
	LeaseGeneration uint64                           `json:"lease_generation"`
	HostID          string                           `json:"host_id"`
	TransportMode   string                           `json:"transport_mode,omitempty"`
	TargetID        string                           `json:"target_id"`
	ServiceType     string                           `json:"service_type,omitempty"`
	TargetVersion   string                           `json:"target_version"`
	DeploymentMode  string                           `json:"deployment_mode"`
	JobOperation    string                           `json:"job_operation,omitempty"`
	Operation       string                           `json:"operation"`
	PlanSHA256      string                           `json:"plan_sha256"`
	SessionID       string                           `json:"session_id"`
	OwnershipEpoch  int64                            `json:"ownership_epoch,omitempty"`
	PolicyRevision  int64                            `json:"policy_revision,omitempty"`
	PortReconfigure *SystemdPortMutationGrantBinding `json:"port_reconfigure,omitempty"`
}

// SystemdPortMutationGrantBinding mirrors the public nested grant contract
// without accepting any privileged local path, unit, command, URL, image, or
// environment variable name.
type SystemdPortMutationGrantBinding struct {
	NetworkNamespace               string                          `json:"network_namespace"`
	Protocol                       string                          `json:"protocol"`
	OldPort                        int                             `json:"old_port"`
	NewPort                        int                             `json:"new_port"`
	ExpectedEndpointRevision       int64                           `json:"expected_endpoint_revision"`
	TargetEndpointRevision         int64                           `json:"target_endpoint_revision"`
	ExpectedConfigRevision         int64                           `json:"expected_config_revision"`
	TargetConfigRevision           int64                           `json:"target_config_revision"`
	ExpectedConfigSHA256           string                          `json:"expected_config_sha256"`
	TargetConfigSHA256             string                          `json:"target_config_sha256"`
	ExpectedSourcePolicyRevision   int64                           `json:"expected_source_policy_revision"`
	ExpectedUpdaterPolicyRevision  int64                           `json:"expected_updater_policy_revision"`
	ExpectedExecutorPolicyRevision int64                           `json:"expected_executor_policy_revision"`
	ExpectedExecutorPolicySHA256   string                          `json:"expected_executor_policy_sha256"`
	PortPlanSHA256                 string                          `json:"port_plan_sha256"`
	Docker                         *DockerPortMutationGrantBinding `json:"docker,omitempty"`
}

type DockerPortMutationGrantBinding struct {
	PublishedHostIP             string `json:"published_host_ip"`
	OldPublishedPort            int    `json:"old_published_port"`
	NewPublishedPort            int    `json:"new_published_port"`
	OldContainerPort            int    `json:"old_container_port"`
	NewContainerPort            int    `json:"new_container_port"`
	OldHealthPort               int    `json:"old_health_port"`
	NewHealthPort               int    `json:"new_health_port"`
	ApprovedComposeConfigSHA256 string `json:"approved_compose_config_sha256"`
	ApprovedComposeRevision     int64  `json:"approved_compose_revision"`
	ExpectedVersionEnvSHA256    string `json:"expected_version_env_sha256"`
	ExpectedContainerID         string `json:"expected_container_id"`
	ExpectedImageID             string `json:"expected_image_id"`
	ExpectedRepositoryDigest    string `json:"expected_repository_digest"`
}

func (d *DockerPortMutationGrantBinding) validate(
	expectedExecutorPolicyRevision int64,
) error {
	if d == nil ||
		d.PublishedHostIP != "127.0.0.1" ||
		!validSystemdPort(d.OldPublishedPort) ||
		!validSystemdPort(d.NewPublishedPort) ||
		!validSystemdPort(d.OldContainerPort) ||
		!validSystemdPort(d.NewContainerPort) ||
		d.OldHealthPort != d.OldPublishedPort ||
		d.NewHealthPort != d.NewPublishedPort ||
		!mutationPlanHashPattern.MatchString(d.ApprovedComposeConfigSHA256) ||
		d.ApprovedComposeRevision != expectedExecutorPolicyRevision ||
		!digestPattern.MatchString(d.ExpectedVersionEnvSHA256) ||
		!dockerContainerIDPattern.MatchString(d.ExpectedContainerID) ||
		!digestPattern.MatchString(d.ExpectedImageID) ||
		!digestPattern.MatchString(d.ExpectedRepositoryDigest) {
		return errors.New("Docker port job runtime baseline is invalid")
	}
	return nil
}

type MutationGrantRequest struct {
	ServiceID  string `json:"service_id"`
	LeaseToken string `json:"lease_token"`
	MutationGrantBinding
}

type MutationGrant struct {
	Token     string                                 `json:"grant_token"`
	ExpiresAt string                                 `json:"expires_at"`
	V2Binding *contracts.UpdaterMutationGrantBinding `json:"-"`
}

type PanelClient struct {
	BaseURL         string
	Token           string
	HTTP            *http.Client
	TokenProvider   func() string
	VersionProvider func() string
}

func (c PanelClient) runtimeToken() string {
	if c.TokenProvider != nil {
		if token := c.TokenProvider(); token != "" {
			return token
		}
	}
	return c.Token
}

func (c PanelClient) runtimeVersion() string {
	if c.VersionProvider != nil {
		if value := strings.TrimSpace(c.VersionProvider()); value != "" {
			return value
		}
	}
	return version.Current()
}

func (c PanelClient) ClaimHost(ctx context.Context, serviceID, hostID, activeJobID string) (*UpdateJob, bool, error) {
	var response ClaimResponse
	body := map[string]string{"service_id": serviceID}
	if strings.TrimSpace(hostID) != "" {
		body["host_id"] = strings.TrimSpace(hostID)
	}
	if strings.TrimSpace(activeJobID) != "" {
		body["active_job_id"] = strings.TrimSpace(activeJobID)
	}
	err := c.post(ctx, "/services/update-jobs/claim", body, &response)
	if errors.Is(err, errNoContent) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if response.ClearActiveJobID {
		terminal := response.TerminalJob
		if strings.TrimSpace(activeJobID) == "" || terminal == nil ||
			terminal.ID != strings.TrimSpace(activeJobID) ||
			terminal.AgentServiceID != strings.TrimSpace(serviceID) ||
			!isTerminalUpdateStatus(terminal.Status) ||
			terminal.LeaseToken != "" || !terminal.ReleaseToken.Empty() ||
			terminal.validateOperationUnion() != nil {
			return nil, false, errors.New(
				"claim response terminal recovery proof is invalid",
			)
		}
		copy := *terminal
		return &copy, true, nil
	}
	job := response.Job
	if job == nil && response.UpdateJob.ID != "" {
		copy := response.UpdateJob
		job = &copy
	}
	if job == nil || strings.TrimSpace(job.ID) == "" {
		return nil, false, errors.New("claim response did not include a job")
	}
	if job.LeaseToken == "" {
		job.LeaseToken = response.LeaseToken
	}
	if job.ReleaseToken.Empty() {
		job.ReleaseToken = response.ReleaseToken
	}
	if job.LeaseExpiresAt == "" {
		job.LeaseExpiresAt = response.LeaseExpiresAt
	}
	if response.ReportSequence > 0 {
		job.ReportSequence = response.ReportSequence
	}
	if response.LeaseGeneration > 0 {
		job.LeaseGeneration = response.LeaseGeneration
	}
	if response.RecoveryRequired {
		job.RecoveryRequired = true
	}
	if response.LastStatus != "" {
		job.Status = response.LastStatus
	}
	if job.LeaseToken == "" {
		return nil, false, errors.New("claim response did not include a lease token")
	}
	return job, false, nil
}

func (c PanelClient) Report(ctx context.Context, jobID string, report JobReport) error {
	if !isTerminalUpdateStatus(report.Status) {
		return c.post(
			ctx,
			"/services/update-jobs/"+url.PathEscape(jobID)+"/report",
			report,
			nil,
		)
	}
	var committed UpdateJob
	if err := c.post(
		ctx,
		"/services/update-jobs/"+url.PathEscape(jobID)+"/report",
		report,
		&committed,
	); err != nil {
		return err
	}
	if committed.ID != strings.TrimSpace(jobID) ||
		committed.AgentServiceID != strings.TrimSpace(report.ServiceID) ||
		committed.LeaseGeneration != report.LeaseGeneration ||
		committed.Sequence != report.Sequence ||
		committed.Status != strings.TrimSpace(report.Status) ||
		committed.Progress != report.Progress ||
		committed.Code != strings.TrimSpace(report.Code) ||
		canonicalReportDigest(committed.ArtifactDigest) != canonicalReportDigest(report.ArtifactDigest) ||
		canonicalReportDigest(committed.PreviousDigest) != canonicalReportDigest(report.PreviousDigest) {
		return errors.New("report response does not match the committed update job")
	}
	return nil
}

func (c PanelClient) IssueMutationGrant(ctx context.Context, jobID string, request MutationGrantRequest) (MutationGrant, error) {
	var grant MutationGrant
	err := c.post(ctx, "/services/update-jobs/"+url.PathEscape(jobID)+"/mutation-grants", request, &grant)
	if err != nil {
		return MutationGrant{}, err
	}
	if strings.TrimSpace(grant.Token) == "" || strings.TrimSpace(grant.ExpiresAt) == "" {
		return MutationGrant{}, errors.New("mutation grant response is incomplete")
	}
	return grant, nil
}

func ConsumeMutationGrant(ctx context.Context, panelURL, jobID, grantToken string, binding MutationGrantBinding, client *http.Client) error {
	configuredClient := &http.Client{Timeout: 15 * time.Second}
	if client != nil {
		cloned := *client
		configuredClient = &cloned
	}
	// The one-time grant is scoped to the root-owned Panel base URL. Never
	// replay its bearer credential to a redirect target, even when a caller
	// supplied a client whose default policy would follow redirects.
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return (PanelClient{BaseURL: panelURL, Token: grantToken, HTTP: configuredClient}).post(ctx, "/services/update-jobs/"+url.PathEscape(jobID)+"/mutation-grants/consume", binding, nil)
}

type PanelHTTPError struct {
	Status int
	Code   string
}

func (e *PanelHTTPError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("panel returned HTTP %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("panel returned HTTP %d", e.Status)
}

func safePanelErrorCode(code string) string {
	switch strings.TrimSpace(code) {
	case "system_update_job_not_found",
		"system_update_lease_invalid",
		"system_update_sequence_stale",
		"system_update_transition_invalid",
		"system_update_recovery_proof_unavailable",
		"system_update_terminal_proof_upgrade_required",
		"invalid_system_update_report",
		"report_system_update_failed",
		"system_update_authorization_state_invalid",
		"system_update_authorization_mismatch",
		"invalid_system_update_authorization",
		"authorize_system_update_failed",
		"system_update_mutation_grant_required",
		"system_update_mutation_grant_unavailable",
		"system_update_mutation_grant_state_invalid",
		"system_update_mutation_grant_binding_mismatch",
		"system_update_mutation_grant_conflict",
		"invalid_system_update_mutation_grant",
		"invalid_system_update_mutation_grant_consumption",
		"issue_system_update_mutation_grant_failed",
		"consume_system_update_mutation_grant_failed":
		return strings.TrimSpace(code)
	case "updater_policy_not_configured",
		"updater_policy_revision_ahead",
		"updater_policy_revision_invalid",
		"invalid_updater_policy_request",
		"bootstrap_job_not_found",
		"bootstrap_job_conflict",
		"bootstrap_job_expired",
		"bootstrap_lease_invalid",
		"bootstrap_policy_revision_mismatch",
		"updater_release_token_not_configured",
		"secure_transport_required":
		return strings.TrimSpace(code)
	default:
		return ""
	}
}

func IsPermanentReportError(err error) bool {
	var httpErr *PanelHTTPError
	if !errors.As(err, &httpErr) {
		return false
	}
	return httpErr.Status == http.StatusNotFound ||
		(httpErr.Status == http.StatusConflict && (httpErr.Code == "system_update_lease_invalid" ||
			httpErr.Code == "system_update_sequence_stale" || httpErr.Code == "stale_generation" ||
			httpErr.Code == "stale_fence"))
}

var errNoContent = errors.New("no content")

func (c PanelClient) post(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	base := strings.TrimRight(c.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.runtimeToken())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		if out != nil {
			return errNoContent
		}
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data, &body)
		return &PanelHTTPError{Status: resp.StatusCode, Code: safePanelErrorCode(body.Code)}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return nil
}
