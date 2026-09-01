package hostruntime

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/controlplane"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

var (
	_ HostPullControlPlane          = (*V2PanelClient)(nil)
	_ HostPullExecutionControlPlane = (*V2PanelClient)(nil)
)

// V2PanelClient retains the established host-registration and policy methods
// from PanelClient while replacing the execution protocol with the strict v2
// Contracts envelopes. A lease is deliberately kept only in memory: its full
// command is the authority for subsequent progress, result, and mutation-grant
// requests and must not be reconstructed from the legacy journal projection.
type V2PanelClient struct {
	PanelClient

	// Now is optional and exists so expiry-sensitive adapter behavior can be
	// characterized without weakening the production wall-clock check.
	Now func() time.Time

	leaseMu sync.Mutex
	lease   *v2PanelLeaseBinding
}

type v2PanelLeaseBinding struct {
	lease   contracts.UpdaterLeaseEnvelope
	job     UpdateJob
	reports map[uint64]v2PanelMappedReport
}

type v2PanelMappedReport struct {
	source   JobReport
	progress *contracts.UpdaterProgressEnvelope
	result   *contracts.UpdaterResultEnvelope
}

// NewV2PanelClient preserves the caller's existing host-control configuration.
// Execution calls use the same base URL, bounded HTTP client, and rotating
// runtime-token provider, but always require the v2 transport confirmation.
func NewV2PanelClient(panel PanelClient) *V2PanelClient {
	return &V2PanelClient{PanelClient: panel}
}

func (c *V2PanelClient) ClaimHost(
	ctx context.Context,
	serviceID, hostID, activeJobID string,
) (*UpdateJob, bool, error) {
	if c == nil || serviceID != strings.TrimSpace(serviceID) ||
		!identifierPattern.MatchString(serviceID) || hostID != "" ||
		(activeJobID != "" && (activeJobID != strings.TrimSpace(activeJobID) ||
			!identifierPattern.MatchString(activeJobID))) {
		return nil, false, errors.New("v2 updater claim identity is invalid")
	}

	lease, clear, err := c.v2ControlPlane().Claim(ctx, contracts.UpdateAgentClaimRequest{
		ServiceID:   serviceID,
		ActiveJobID: activeJobID,
	})
	if err != nil {
		return nil, false, v2PanelControlPlaneError("claim", err)
	}
	if clear {
		job, err := c.v2ClearJob(serviceID, activeJobID)
		if err != nil {
			return nil, false, err
		}
		return job, true, nil
	}
	if lease == nil {
		if activeJobID == "" {
			c.leaseMu.Lock()
			c.lease = nil
			c.leaseMu.Unlock()
		}
		return nil, false, nil
	}
	if contracts.ValidateUpdaterLease(c.now(), *lease) != nil ||
		lease.Command.MutationAuthorization.UpdaterID != serviceID {
		return nil, false, errors.New("v2 updater lease does not match the claiming service")
	}

	job, err := mapV2LeaseToUpdateJob(*lease, activeJobID)
	if err != nil {
		return nil, false, err
	}
	c.leaseMu.Lock()
	c.lease = &v2PanelLeaseBinding{
		lease:   *lease,
		job:     cloneV2PanelJob(job),
		reports: make(map[uint64]v2PanelMappedReport),
	}
	c.leaseMu.Unlock()
	return &job, false, nil
}

func (c *V2PanelClient) Report(
	ctx context.Context,
	jobID string,
	report JobReport,
) error {
	lease, mapped, err := c.v2MappedReport(jobID, report)
	if err != nil {
		return err
	}
	client := c.v2ControlPlane()
	if mapped.progress != nil {
		err = client.ReportProgress(ctx, lease, *mapped.progress)
	} else if mapped.result != nil {
		err = client.ReportResult(ctx, lease, *mapped.result)
	} else {
		return errors.New("v2 updater report mapping is incomplete")
	}
	if err != nil {
		return v2PanelControlPlaneError("report", err)
	}
	return nil
}

func (c *V2PanelClient) IssueMutationGrant(
	ctx context.Context,
	jobID string,
	request MutationGrantRequest,
) (MutationGrant, error) {
	if c == nil {
		return MutationGrant{}, errors.New("v2 updater mutation grant client is unavailable")
	}
	now := c.now()
	c.leaseMu.Lock()
	if c.lease == nil || c.lease.job.ID != jobID {
		c.leaseMu.Unlock()
		return MutationGrant{}, errors.New("v2 updater mutation grant has no matching lease")
	}
	lease := c.lease.lease
	job := cloneV2PanelJob(c.lease.job)
	c.leaseMu.Unlock()

	binding, err := mapV2MutationGrantBinding(now, lease, job, jobID, request)
	if err != nil {
		return MutationGrant{}, err
	}
	response, err := c.v2ControlPlane().IssueMutationGrant(
		ctx,
		jobID,
		contracts.UpdaterMutationGrantIssueRequest{Binding: binding},
	)
	if err != nil {
		return MutationGrant{}, v2PanelControlPlaneError("mutation grant", err)
	}
	return MutationGrant{
		Token:     response.GrantToken,
		ExpiresAt: response.ExpiresAt.UTC().Format(time.RFC3339Nano),
		V2Binding: &binding,
	}, nil
}

func (c *V2PanelClient) v2ControlPlane() controlplane.Client {
	return controlplane.Client{
		BaseURL:       c.BaseURL,
		HTTP:          c.HTTP,
		TokenProvider: c.runtimeToken,
		Now:           c.Now,
	}
}

func (c *V2PanelClient) now() time.Time {
	if c != nil && c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *V2PanelClient) v2ClearJob(
	serviceID, activeJobID string,
) (*UpdateJob, error) {
	if activeJobID == "" {
		return nil, errors.New("v2 clear instruction did not identify an active job")
	}
	// The strict response is authoritative for the exact active_job_id in the
	// request. It must remain usable after restart, when the intentionally
	// ephemeral lease map is absent but the durable active cursor still exists.
	job := UpdateJob{
		ProtocolVersion: 2,
		ID:              activeJobID,
		AgentServiceID:  serviceID,
		Status:          "canceled",
		RecoveryClear:   true,
	}
	return &job, nil
}

func mapV2LeaseToUpdateJob(
	lease contracts.UpdaterLeaseEnvelope,
	activeJobID string,
) (UpdateJob, error) {
	command := lease.Command
	authorization := command.MutationAuthorization
	target := authorization.Target
	job := UpdateJob{
		ProtocolVersion: 2,
		CommandID:       command.CommandID,
		ID:              authorization.JobID,
		Operation:       string(command.DesiredOperation.Operation),
		AgentServiceID:  authorization.UpdaterID,
		HostID:          authorization.HostID,
		TransportMode:   HostTransportPullV2,
		OwnershipEpoch:  authorization.Fence,
		PolicyRevision:  authorization.DesiredRevision,
		TargetID:        target.ServiceID,
		TargetType:      string(target.ServiceType),
		ServiceType:     string(target.ServiceType),
		DeploymentMode:  string(target.DeploymentMode),
		LeaseExpiresAt:  lease.LeaseExpiresAt.UTC().Format(time.RFC3339Nano),
		Status:          "claimed",
		ReportSequence:  1,
		LeaseGeneration: uint64(lease.LeaseGeneration),
		RecoveryRequired: activeJobID != "" &&
			authorization.JobID == activeJobID,
	}

	switch desired := command.DesiredOperation; desired.Operation {
	case contracts.UpdaterDesiredSoftwareUpdate:
		if desired.SoftwareUpdate == nil {
			return UpdateJob{}, errors.New("v2 software update intent is unavailable")
		}
		job.CurrentVersion = desired.SoftwareUpdate.ExpectedCurrentVersion
		job.TargetVersion = desired.SoftwareUpdate.TargetVersion
	case contracts.UpdaterDesiredPortReconfigure:
		if desired.PortReconfigure == nil {
			return UpdateJob{}, errors.New("v2 port reconfiguration intent is unavailable")
		}
		job.PortReconfigure = mapV2PortReconfiguration(desired.PortReconfigure)
		// Port v2 is deliberately versionless. Do not invent a compatibility
		// version merely to satisfy assumptions in an older execution path.
	case contracts.UpdaterDesiredBootstrap:
		if desired.Bootstrap == nil {
			return UpdateJob{}, errors.New("v2 bootstrap intent is unavailable")
		}
		job.TargetVersion = desired.Bootstrap.TargetVersion
	case contracts.UpdaterDesiredHostSelfUpdate:
		if desired.HostSelfUpdate == nil {
			return UpdateJob{}, errors.New("v2 host self-update intent is unavailable")
		}
		job.TargetVersion = desired.HostSelfUpdate.AgentVersion
	default:
		return UpdateJob{}, errors.New("v2 updater operation is unsupported")
	}
	return job, nil
}

func mapV2PortReconfiguration(
	plan *contracts.SystemUpdatePortReconfiguration,
) *SystemdPortMutationGrantBinding {
	if plan == nil {
		return nil
	}
	mapped := &SystemdPortMutationGrantBinding{
		NetworkNamespace:               plan.NetworkNamespace,
		Protocol:                       string(plan.Protocol),
		OldPort:                        plan.OldPort,
		NewPort:                        plan.NewPort,
		ExpectedEndpointRevision:       plan.ExpectedEndpointRevision,
		TargetEndpointRevision:         plan.TargetEndpointRevision,
		ExpectedConfigRevision:         plan.ExpectedConfigRevision,
		TargetConfigRevision:           plan.TargetConfigRevision,
		ExpectedConfigSHA256:           plan.ExpectedConfigSHA256,
		TargetConfigSHA256:             plan.TargetConfigSHA256,
		ExpectedSourcePolicyRevision:   plan.ExpectedSourcePolicyRevision,
		ExpectedUpdaterPolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		ExpectedExecutorPolicyRevision: plan.ExpectedExecutorPolicyRevision,
		ExpectedExecutorPolicySHA256:   plan.ExpectedExecutorPolicySHA256,
		PortPlanSHA256:                 plan.PortPlanSHA256,
	}
	if plan.Docker != nil {
		mapped.Docker = &DockerPortMutationGrantBinding{
			PublishedHostIP:             plan.Docker.PublishedHostIP,
			OldPublishedPort:            plan.Docker.OldPublishedPort,
			NewPublishedPort:            plan.Docker.NewPublishedPort,
			OldContainerPort:            plan.Docker.OldContainerPort,
			NewContainerPort:            plan.Docker.NewContainerPort,
			OldHealthPort:               plan.Docker.OldHealthPort,
			NewHealthPort:               plan.Docker.NewHealthPort,
			ApprovedComposeConfigSHA256: plan.Docker.ApprovedComposeConfigSHA256,
			ApprovedComposeRevision:     plan.Docker.ApprovedComposeRevision,
			ExpectedVersionEnvSHA256:    plan.Docker.ExpectedVersionEnvSHA256,
			ExpectedContainerID:         plan.Docker.ExpectedContainerID,
			ExpectedImageID:             plan.Docker.ExpectedImageID,
			ExpectedRepositoryDigest:    plan.Docker.ExpectedRepositoryDigest,
		}
	}
	return mapped
}

func (c *V2PanelClient) v2MappedReport(
	jobID string,
	report JobReport,
) (contracts.UpdaterLeaseEnvelope, v2PanelMappedReport, error) {
	if c == nil {
		return contracts.UpdaterLeaseEnvelope{}, v2PanelMappedReport{},
			errors.New("v2 updater report client is unavailable")
	}
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if c.lease == nil || c.lease.job.ID != jobID {
		return contracts.UpdaterLeaseEnvelope{}, v2PanelMappedReport{},
			errors.New("v2 updater report has no matching lease")
	}
	if err := validateV2PanelReportBinding(c.lease.lease, c.lease.job, jobID, report); err != nil {
		return contracts.UpdaterLeaseEnvelope{}, v2PanelMappedReport{}, err
	}
	if cached, ok := c.lease.reports[report.Sequence]; ok {
		if !sameV2PanelReport(cached.source, report) {
			return contracts.UpdaterLeaseEnvelope{}, v2PanelMappedReport{},
				errors.New("v2 updater report sequence was reused with different content")
		}
		return c.lease.lease, cached, nil
	}
	observedAt := c.now()
	if !observedAt.Before(c.lease.lease.LeaseExpiresAt) {
		return contracts.UpdaterLeaseEnvelope{}, v2PanelMappedReport{},
			errors.New("v2 updater lease expired before report mapping")
	}
	mapped, err := mapV2JobReport(c.lease.lease, report, observedAt)
	if err != nil {
		return contracts.UpdaterLeaseEnvelope{}, v2PanelMappedReport{}, err
	}
	c.lease.reports[report.Sequence] = mapped
	return c.lease.lease, mapped, nil
}

func validateV2PanelReportBinding(
	lease contracts.UpdaterLeaseEnvelope,
	job UpdateJob,
	jobID string,
	report JobReport,
) error {
	if jobID != lease.Command.MutationAuthorization.JobID || job.ID != jobID ||
		report.ServiceID != lease.Command.MutationAuthorization.UpdaterID ||
		report.LeaseToken != "" ||
		report.LeaseGeneration != uint64(lease.LeaseGeneration) ||
		report.Sequence > uint64(math.MaxInt64) || report.Progress < 0 || report.Progress > 100 {
		return errors.New("v2 updater report lease binding is invalid")
	}
	isTerminal := isTerminalUpdateStatus(report.Status)
	if lease.Command.DesiredOperation.Operation != contracts.UpdaterDesiredPortReconfigure {
		if report.PortReconfigure != nil {
			return errors.New("v2 non-port report contains a port result")
		}
		return nil
	}
	if !isTerminal {
		if report.PortReconfigure != nil {
			return errors.New("v2 non-terminal port report contains a result")
		}
		return nil
	}
	if report.PortReconfigure == nil {
		return errors.New("v2 terminal port report omitted its result")
	}
	result := report.PortReconfigure.Result
	valid := (report.Status == "succeeded" &&
		(result == systemdPortResultApplied || result == systemdPortResultUnchanged)) ||
		(report.Status == "rolled_back" && result == systemdPortResultRolledBack) ||
		(report.Status == "failed" && result == systemdPortResultRollbackFailed)
	if !valid {
		return errors.New("v2 terminal port report result does not match its status")
	}
	return nil
}

func mapV2JobReport(
	lease contracts.UpdaterLeaseEnvelope,
	report JobReport,
	observedAt time.Time,
) (v2PanelMappedReport, error) {
	mapped := v2PanelMappedReport{source: cloneV2PanelReport(report)}
	command := lease.Command
	authorization := command.MutationAuthorization
	if !isTerminalUpdateStatus(report.Status) {
		phase, ok := v2ProgressPhase(report.Status)
		if !ok {
			return v2PanelMappedReport{}, errors.New("v2 updater progress status is unsupported")
		}
		progress := contracts.UpdaterProgressEnvelope{
			ProtocolVersion:    2,
			CommandID:          command.CommandID,
			JobID:              authorization.JobID,
			UpdaterID:          authorization.UpdaterID,
			HostID:             authorization.HostID,
			LeaseID:            lease.LeaseID,
			LeaseGeneration:    lease.LeaseGeneration,
			Sequence:           int64(report.Sequence),
			Phase:              phase,
			Progress:           report.Progress,
			DesiredRevision:    authorization.DesiredRevision,
			Fence:              authorization.Fence,
			AuditCorrelationID: command.AuditCorrelationID,
			ObservedAt:         observedAt.UTC(),
		}
		if contracts.ValidateUpdaterProgress(lease, progress) != nil {
			return v2PanelMappedReport{}, errors.New("v2 updater progress mapping is invalid")
		}
		mapped.progress = &progress
		return mapped, nil
	}

	artifact, err := v2ReportDigest(report.ArtifactDigest)
	if err != nil {
		return v2PanelMappedReport{}, err
	}
	previous, err := v2ReportDigest(report.PreviousDigest)
	if err != nil {
		return v2PanelMappedReport{}, err
	}
	result := contracts.UpdaterResultEnvelope{
		ProtocolVersion:        2,
		CommandID:              command.CommandID,
		JobID:                  authorization.JobID,
		UpdaterID:              authorization.UpdaterID,
		HostID:                 authorization.HostID,
		LeaseID:                lease.LeaseID,
		LeaseGeneration:        lease.LeaseGeneration,
		IdempotencyKey:         command.IdempotencyKey,
		CanonicalPayloadDigest: command.CanonicalPayloadDigest,
		AuthorizationID:        authorization.AuthorizationID,
		DesiredRevision:        authorization.DesiredRevision,
		Fence:                  authorization.Fence,
		Status:                 contracts.SystemUpdateStatus(report.Status),
		AutomaticResendAllowed: false,
		AuditCorrelationID:     command.AuditCorrelationID,
	}
	evidence := contracts.UpdaterEvidence{
		EvidenceCode:     "phase_observed",
		ObservedAt:       observedAt.UTC(),
		ObservedRevision: authorization.DesiredRevision,
		ArtifactDigest:   artifact,
	}
	switch report.Status {
	case "succeeded":
		result.Outcome = contracts.UpdaterOutcomeSucceeded
		result.AppliedRevision = authorization.DesiredRevision
		switch authorization.Target.TargetKind {
		case contracts.UpdaterTargetApplication:
			evidence.EvidenceCode = "application_probe_verified"
		case contracts.UpdaterTargetHostRuntime:
			evidence.EvidenceCode = "host_runtime_verified"
		}
	case "rolled_back":
		result.Outcome = contracts.UpdaterOutcomeRolledBack
		evidence.EvidenceCode = "rollback_verified"
		if authorization.Target.ExpectedConfigRevision > 0 {
			evidence.ObservedRevision = authorization.Target.ExpectedConfigRevision
		}
		if previous != "" {
			evidence.ArtifactDigest = previous
		}
	case "failed":
		result.Outcome = contracts.UpdaterOutcomeFailed
		if authorization.Target.ExpectedConfigRevision > 0 {
			evidence.ObservedRevision = authorization.Target.ExpectedConfigRevision
		}
		result.SafeError = &contracts.V2UpdaterSafeError{
			Code:      "execution_failed",
			Message:   "updater execution failed",
			Retryable: false,
		}
	default:
		return v2PanelMappedReport{}, errors.New("v2 updater terminal status is unsupported")
	}
	result.Evidence = []contracts.UpdaterEvidence{evidence}
	if contracts.ValidateUpdaterResult(lease, result) != nil {
		return v2PanelMappedReport{}, errors.New("v2 updater result mapping is invalid")
	}
	mapped.result = &result
	return mapped, nil
}

func v2ProgressPhase(status string) (string, bool) {
	switch status {
	case "claimed":
		return "accepted", true
	case "downloading", "staging":
		return "preparing", true
	case "installing":
		return "executing", true
	case "verifying", "health_checking":
		return "verifying", true
	case "rolling_back":
		return "rolling_back", true
	case "reconciling":
		return "reconciling", true
	default:
		return "", false
	}
}

func v2ReportDigest(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	canonical := canonicalReportDigest(value)
	if canonical == "" {
		return "", errors.New("v2 updater report digest is invalid")
	}
	return canonical, nil
}

func mapV2MutationGrantBinding(
	now time.Time,
	lease contracts.UpdaterLeaseEnvelope,
	job UpdateJob,
	jobID string,
	request MutationGrantRequest,
) (contracts.UpdaterMutationGrantBinding, error) {
	authorization := lease.Command.MutationAuthorization
	target := authorization.Target
	operation := contracts.UpdaterMutationOperation(request.Operation)
	expectedJobOperation := ""
	if lease.Command.DesiredOperation.Operation == contracts.UpdaterDesiredPortReconfigure {
		expectedJobOperation = updateJobOperationPortReconfigure
	}
	if jobID != authorization.JobID || job.ID != jobID ||
		request.ServiceID != authorization.UpdaterID || request.LeaseToken != "" ||
		request.LeaseGeneration != uint64(lease.LeaseGeneration) ||
		request.HostID != authorization.HostID || request.TransportMode != HostTransportPullV2 ||
		request.OwnershipEpoch != authorization.Fence ||
		request.PolicyRevision != authorization.DesiredRevision ||
		request.TargetID != target.ServiceID || request.ServiceType != string(target.ServiceType) ||
		request.DeploymentMode != string(target.DeploymentMode) ||
		request.TargetVersion != job.EffectiveVersion() ||
		request.JobOperation != expectedJobOperation ||
		!mutationPlanHashPattern.MatchString(request.PlanSHA256) ||
		!mutationSessionPattern.MatchString(request.SessionID) {
		return contracts.UpdaterMutationGrantBinding{},
			errors.New("v2 updater mutation grant binding does not match its lease")
	}
	if lease.Command.DesiredOperation.Operation == contracts.UpdaterDesiredPortReconfigure {
		if request.PortReconfigure == nil ||
			request.PortReconfigure.PortPlanSHA256 != request.PlanSHA256 ||
			!v2PortGrantMatchesDesired(
				request.PortReconfigure,
				lease.Command.DesiredOperation.PortReconfigure,
			) {
			return contracts.UpdaterMutationGrantBinding{},
				errors.New("v2 updater port mutation grant changed the desired plan")
		}
	} else if request.PortReconfigure != nil {
		return contracts.UpdaterMutationGrantBinding{},
			errors.New("v2 updater non-port mutation grant contains a port plan")
	}
	binding := contracts.UpdaterMutationGrantBinding{
		Lease:     lease,
		Operation: operation,
		SessionID: request.SessionID,
	}
	if contracts.ValidateUpdaterMutationGrantBinding(now, binding) != nil {
		return contracts.UpdaterMutationGrantBinding{},
			errors.New("v2 updater mutation grant operation is invalid")
	}
	return binding, nil
}

func v2PortGrantMatchesDesired(
	actual *SystemdPortMutationGrantBinding,
	desired *contracts.SystemUpdatePortReconfiguration,
) bool {
	if actual == nil || desired == nil ||
		actual.NetworkNamespace != desired.NetworkNamespace ||
		actual.Protocol != string(desired.Protocol) ||
		actual.OldPort != desired.OldPort || actual.NewPort != desired.NewPort ||
		actual.ExpectedEndpointRevision != desired.ExpectedEndpointRevision ||
		actual.TargetEndpointRevision != desired.TargetEndpointRevision ||
		actual.ExpectedConfigRevision != desired.ExpectedConfigRevision ||
		actual.TargetConfigRevision != desired.TargetConfigRevision ||
		actual.ExpectedConfigSHA256 != desired.ExpectedConfigSHA256 ||
		actual.TargetConfigSHA256 != desired.TargetConfigSHA256 ||
		actual.ExpectedSourcePolicyRevision != desired.ExpectedSourcePolicyRevision ||
		actual.ExpectedUpdaterPolicyRevision != desired.ExpectedUpdaterPolicyRevision ||
		actual.ExpectedExecutorPolicyRevision != desired.ExpectedExecutorPolicyRevision ||
		actual.ExpectedExecutorPolicySHA256 != desired.ExpectedExecutorPolicySHA256 {
		return false
	}
	if actual.Docker == nil || desired.Docker == nil {
		return actual.Docker == nil && desired.Docker == nil
	}
	return actual.Docker.PublishedHostIP == desired.Docker.PublishedHostIP &&
		actual.Docker.OldPublishedPort == desired.Docker.OldPublishedPort &&
		actual.Docker.NewPublishedPort == desired.Docker.NewPublishedPort &&
		actual.Docker.OldContainerPort == desired.Docker.OldContainerPort &&
		actual.Docker.NewContainerPort == desired.Docker.NewContainerPort &&
		actual.Docker.OldHealthPort == desired.Docker.OldHealthPort &&
		actual.Docker.NewHealthPort == desired.Docker.NewHealthPort &&
		actual.Docker.ApprovedComposeConfigSHA256 == desired.Docker.ApprovedComposeConfigSHA256 &&
		actual.Docker.ApprovedComposeRevision == desired.Docker.ApprovedComposeRevision &&
		actual.Docker.ExpectedVersionEnvSHA256 == desired.Docker.ExpectedVersionEnvSHA256 &&
		actual.Docker.ExpectedContainerID == desired.Docker.ExpectedContainerID &&
		actual.Docker.ExpectedImageID == desired.Docker.ExpectedImageID &&
		actual.Docker.ExpectedRepositoryDigest == desired.Docker.ExpectedRepositoryDigest
}

func cloneV2PanelJob(job UpdateJob) UpdateJob {
	copy := job
	if job.PortReconfigure != nil {
		port := *job.PortReconfigure
		port.Docker = cloneDockerPortMutationGrantBinding(job.PortReconfigure.Docker)
		copy.PortReconfigure = &port
	}
	return copy
}

func cloneV2PanelReport(report JobReport) JobReport {
	copy := report
	if report.PortReconfigure != nil {
		port := *report.PortReconfigure
		copy.PortReconfigure = &port
	}
	return copy
}

func sameV2PanelReport(left, right JobReport) bool {
	if left.ServiceID != right.ServiceID || left.LeaseToken != right.LeaseToken ||
		left.Sequence != right.Sequence || left.LeaseGeneration != right.LeaseGeneration ||
		left.Status != right.Status || left.Progress != right.Progress || left.Code != right.Code ||
		left.Message != right.Message || left.ArtifactDigest != right.ArtifactDigest ||
		left.PreviousDigest != right.PreviousDigest {
		return false
	}
	if left.PortReconfigure == nil || right.PortReconfigure == nil {
		return left.PortReconfigure == nil && right.PortReconfigure == nil
	}
	return *left.PortReconfigure == *right.PortReconfigure
}

func v2PanelControlPlaneError(operation string, err error) error {
	var responseError *controlplane.HTTPError
	if errors.As(err, &responseError) {
		return &PanelHTTPError{
			Status: responseError.Status,
			Code:   safeV2PanelHTTPErrorCode(responseError.Code),
		}
	}
	return errors.New("v2 control plane " + operation + " failed")
}

func safeV2PanelHTTPErrorCode(code string) string {
	if safe := safePanelErrorCode(code); safe != "" {
		return safe
	}
	switch code {
	case "contract_major_unsupported", "protocol_version_unsupported",
		"request_schema_invalid", "revision_conflict", "stale_generation",
		"stale_fence", "semantic_validation_failed":
		return code
	default:
		return ""
	}
}
