package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/controlplane"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

func TestV2PanelClientMapsLeaseReportsAndMutationGrant(t *testing.T) {
	now := time.Date(2026, 9, 2, 1, 2, 3, 0, time.UTC)
	lease := v2PanelSoftwareLease(t, now)
	reportKinds := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get(controlplane.ContractMajorHeader) != controlplane.ContractMajorV2 {
			t.Errorf("contract major = %q", request.Header.Get(controlplane.ContractMajorHeader))
		}
		if request.Header.Get("Authorization") != "Bearer runtime-token" {
			t.Error("runtime authorization was not supplied")
		}
		switch request.URL.Path {
		case "/services/update-jobs/claim":
			var claim contracts.UpdateAgentClaimRequest
			if err := json.NewDecoder(request.Body).Decode(&claim); err != nil ||
				claim.ServiceID != lease.Command.MutationAuthorization.UpdaterID ||
				claim.HostID != "" {
				t.Errorf("claim=%+v err=%v", claim, err)
			}
			writeV2PanelJSON(t, w, http.StatusOK, lease)
		case "/services/update-jobs/job-01/report":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read report: %v", err)
			}
			var discriminator map[string]json.RawMessage
			if err := json.Unmarshal(body, &discriminator); err != nil {
				t.Errorf("decode report discriminator: %v", err)
			}
			if _, ok := discriminator["phase"]; ok {
				if err := contracts.ValidateUpdaterProgressEnvelope(lease, body); err != nil {
					t.Errorf("progress contract: %v", err)
				}
				var progress contracts.UpdaterProgressEnvelope
				if err := json.Unmarshal(body, &progress); err != nil || progress.Phase != "accepted" {
					t.Errorf("progress=%+v err=%v", progress, err)
				}
				reportKinds = append(reportKinds, "progress")
			} else {
				if err := contracts.ValidateUpdaterResultEnvelope(lease, body); err != nil {
					t.Errorf("result contract: %v", err)
				}
				var result contracts.UpdaterResultEnvelope
				if err := json.Unmarshal(body, &result); err != nil ||
					result.Outcome != contracts.UpdaterOutcomeSucceeded ||
					result.AppliedRevision != lease.Command.MutationAuthorization.DesiredRevision ||
					len(result.Evidence) != 1 ||
					result.Evidence[0].EvidenceCode != "application_probe_verified" {
					t.Errorf("result=%+v err=%v", result, err)
				}
				reportKinds = append(reportKinds, "result")
			}
			writeV2PanelJSON(t, w, http.StatusOK, nil)
		case "/services/update-jobs/job-01/mutation-grants":
			body, err := io.ReadAll(request.Body)
			if err != nil || contracts.ValidateUpdaterMutationGrantIssueRequest(now, body) != nil {
				t.Errorf("mutation grant request is invalid: %v", err)
			}
			var issue contracts.UpdaterMutationGrantIssueRequest
			if err := json.Unmarshal(body, &issue); err != nil ||
				issue.Binding.Operation != contracts.UpdaterMutationApply ||
				issue.Binding.SessionID != "session-1234567890abcdef" {
				t.Errorf("issue=%+v err=%v", issue, err)
			}
			writeV2PanelJSON(t, w, http.StatusCreated, contracts.UpdaterMutationGrantIssueResponse{
				GrantToken: strings.Repeat("g", 32),
				ExpiresAt:  now.Add(2 * time.Minute),
			})
		default:
			t.Errorf("unexpected path %s", request.URL.Path)
			writeV2PanelJSON(t, w, http.StatusNotFound, nil)
		}
	}))
	defer server.Close()

	client := NewV2PanelClient(PanelClient{
		BaseURL: server.URL,
		Token:   "runtime-token",
		HTTP:    server.Client(),
	})
	client.Now = func() time.Time { return now }
	job, clear, err := client.ClaimHost(context.Background(), "updater-01", "", "")
	if err != nil || clear || job == nil {
		t.Fatalf("job=%+v clear=%v err=%v", job, clear, err)
	}
	if job.ProtocolVersion != 2 || job.CommandID != "command-01" ||
		job.ID != "job-01" || job.Operation != updateJobOperationSoftwareUpdate ||
		job.AgentServiceID != "updater-01" || job.HostID != "host-01" ||
		job.TargetID != "worker-01" || job.CurrentVersion != "v1.2.3" ||
		job.TargetVersion != "v1.2.4" || job.LeaseToken != "" ||
		job.LeaseGeneration != 3 || job.ReportSequence != 1 {
		t.Fatalf("mapped job = %+v", job)
	}

	progress := JobReport{
		ServiceID:       "updater-01",
		LeaseToken:      "",
		Sequence:        1,
		LeaseGeneration: 3,
		Status:          "claimed",
		Progress:        5,
	}
	if err := client.Report(context.Background(), job.ID, progress); err != nil {
		t.Fatalf("report progress: %v", err)
	}
	grant, err := client.IssueMutationGrant(context.Background(), job.ID, MutationGrantRequest{
		ServiceID:  "updater-01",
		LeaseToken: "",
		MutationGrantBinding: MutationGrantBinding{
			LeaseGeneration: 3,
			HostID:          "host-01",
			TransportMode:   HostTransportPullV2,
			TargetID:        "worker-01",
			ServiceType:     "worker",
			TargetVersion:   "v1.2.4",
			DeploymentMode:  ModeSystemd,
			Operation:       "apply",
			PlanSHA256:      strings.Repeat("a", 64),
			SessionID:       "session-1234567890abcdef",
			OwnershipEpoch:  9,
			PolicyRevision:  7,
		},
	})
	if err != nil || grant.Token != strings.Repeat("g", 32) || grant.V2Binding == nil ||
		grant.V2Binding.Operation != contracts.UpdaterMutationApply ||
		grant.V2Binding.Lease.LeaseID != lease.LeaseID {
		t.Fatalf("grant_valid=%v binding_present=%v err=%v",
			grant.Token == strings.Repeat("g", 32), grant.V2Binding != nil, err)
	}
	if err := client.Report(context.Background(), job.ID, JobReport{
		ServiceID:       "updater-01",
		LeaseToken:      "",
		Sequence:        2,
		LeaseGeneration: 3,
		Status:          "succeeded",
		Progress:        100,
		ArtifactDigest:  "sha256:" + strings.Repeat("a", 64),
		PreviousDigest:  "sha256:" + strings.Repeat("b", 64),
	}); err != nil {
		t.Fatalf("report result: %v", err)
	}
	if strings.Join(reportKinds, ",") != "progress,result" {
		t.Fatalf("report kinds = %v", reportKinds)
	}
}

func TestV2PanelClientClearSurvivesRestartWithoutLeaseCredential(t *testing.T) {
	now := time.Date(2026, 9, 2, 2, 0, 0, 0, time.UTC)
	lease := v2PanelSoftwareLease(t, now)
	claims := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		claims++
		var claim contracts.UpdateAgentClaimRequest
		if err := json.NewDecoder(request.Body).Decode(&claim); err != nil ||
			claim.ServiceID != "updater-01" ||
			(claims == 1 && claim.ActiveJobID != "") ||
			(claims > 1 && claim.ActiveJobID != "job-01") {
			t.Errorf("claim=%+v err=%v", claim, err)
		}
		if claims == 1 {
			writeV2PanelJSON(t, w, http.StatusOK, lease)
			return
		}
		writeV2PanelJSON(t, w, http.StatusOK, contracts.UpdateAgentClearActiveJobResponse{
			ClearActiveJobID: true,
		})
	}))
	defer server.Close()
	client := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
	client.Now = func() time.Time { return now }
	job, _, err := client.ClaimHost(context.Background(), "updater-01", "", "")
	if err != nil || job == nil {
		t.Fatalf("initial claim job=%+v err=%v", job, err)
	}
	cleared, clear, err := client.ClaimHost(context.Background(), "updater-01", "", job.ID)
	if err != nil || !clear || cleared == nil || cleared.ID != job.ID ||
		cleared.Status != "canceled" || !cleared.RecoveryClear || cleared.LeaseToken != "" {
		t.Fatalf("clear job=%+v clear=%v err=%v", cleared, clear, err)
	}

	fresh := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
	fresh.Now = func() time.Time { return now }
	restarted, clear, err := fresh.ClaimHost(context.Background(), "updater-01", "", job.ID)
	if err != nil || !clear || restarted == nil || restarted.ID != job.ID ||
		restarted.AgentServiceID != "updater-01" || !restarted.RecoveryClear ||
		restarted.LeaseToken != "" {
		t.Fatalf("restart clear job=%+v clear=%v err=%v", restarted, clear, err)
	}
}

func TestV2PanelClientRejectsLegacyAndMalformedClaimsWithoutFallback(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		activeJobID string
	}{
		{name: "legacy", body: `{"job":{"id":"legacy"},"lease_token":"legacy-secret"}`},
		{name: "null", body: `null`},
		{name: "missing", body: `{}`, activeJobID: "job-01"},
		{name: "clear false", body: `{"clear_active_job_id":false}`, activeJobID: "job-01"},
		{name: "clear unknown", body: `{"clear_active_job_id":true,"unknown":1}`, activeJobID: "job-01"},
		{name: "clear duplicate", body: `{"clear_active_job_id":true,"clear_active_job_id":true}`, activeJobID: "job-01"},
		{name: "clear trailing", body: `{"clear_active_job_id":true}{}`, activeJobID: "job-01"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(controlplane.ContractMajorHeader, controlplane.ContractMajorV2)
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			client := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
			if job, clear, err := client.ClaimHost(
				context.Background(), "updater-01", "", test.activeJobID,
			); err == nil || job != nil || clear {
				t.Fatalf("unsafe response job=%+v clear=%v err=%v", job, clear, err)
			}
		})
	}
}

func TestV2PanelClientConvertsOnlySafeHTTPErrorFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeV2PanelJSON(t, w, http.StatusConflict, map[string]any{
			"contract_major": 2,
			"code":           "stale_fence",
			"message":        "must-not-escape-secret-marker",
			"retryable":      false,
		})
	}))
	defer server.Close()
	client := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
	_, _, err := client.ClaimHost(context.Background(), "updater-01", "", "")
	var responseError *PanelHTTPError
	if !errors.As(err, &responseError) || responseError.Status != http.StatusConflict ||
		responseError.Code != "stale_fence" || strings.Contains(err.Error(), "secret-marker") {
		t.Fatalf("safe error conversion err=%v", err)
	}
}

func TestV2ReportFenceAndGenerationConflictsArePermanent(t *testing.T) {
	for _, code := range []string{"stale_generation", "stale_fence"} {
		if !IsPermanentReportError(&PanelHTTPError{Status: http.StatusConflict, Code: code}) {
			t.Fatalf("v2 report conflict %q was not classified as permanent", code)
		}
	}
	if IsPermanentReportError(&PanelHTTPError{Status: http.StatusConflict, Code: "revision_conflict"}) {
		t.Fatal("retry-policy revision conflict was incorrectly made permanent")
	}
}

func TestMapV2PortLeasePreservesVersionlessImmutablePlan(t *testing.T) {
	now := time.Date(2026, 9, 2, 3, 0, 0, 0, time.UTC)
	lease := v2PanelPortLease(t, now)
	if err := contracts.ValidateUpdaterLease(now, lease); err != nil {
		t.Fatalf("port fixture: %v", err)
	}
	job, err := mapV2LeaseToUpdateJob(lease, "job-01")
	if err != nil {
		t.Fatal(err)
	}
	if job.Operation != updateJobOperationPortReconfigure || !job.RecoveryRequired ||
		job.CurrentVersion != "" || job.TargetVersion != "" || job.PortReconfigure == nil ||
		job.PortReconfigure.OldPort != 4000 || job.PortReconfigure.NewPort != 4001 ||
		job.PortReconfigure.ExpectedUpdaterPolicyRevision != 7 ||
		job.PortReconfigure.PortPlanSHA256 != strings.Repeat("4", 64) {
		t.Fatalf("versionless port job = %+v", job)
	}
}

func TestMapV2BootstrapAndSelfUpdateRemainExplicitlyNonSoftware(t *testing.T) {
	now := time.Date(2026, 9, 2, 3, 30, 0, 0, time.UTC)
	tests := []struct {
		name          string
		lease         contracts.UpdaterLeaseEnvelope
		operation     string
		targetVersion string
	}{
		{
			name:          "bootstrap",
			lease:         v2PanelBootstrapLease(t, now),
			operation:     updateJobOperationBootstrap,
			targetVersion: "v1.2.4",
		},
		{
			name:          "host self update",
			lease:         v2PanelSelfUpdateLease(t, now),
			operation:     updateJobOperationHostSelfUpdate,
			targetVersion: "v1.2.4",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := contracts.ValidateUpdaterLease(now, test.lease); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			job, err := mapV2LeaseToUpdateJob(test.lease, "")
			if err != nil {
				t.Fatal(err)
			}
			if job.Operation != test.operation || job.CurrentVersion != "" ||
				job.TargetVersion != test.targetVersion || job.PortReconfigure != nil ||
				job.ProtocolVersion != 2 {
				t.Fatalf("mapped job = %+v", job)
			}
		})
	}
}

func TestV2PanelClientRejectsChangedReportAndGrantBinding(t *testing.T) {
	now := time.Date(2026, 9, 2, 4, 0, 0, 0, time.UTC)
	lease := v2PanelSoftwareLease(t, now)
	reports := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/services/update-jobs/claim":
			writeV2PanelJSON(t, w, http.StatusOK, lease)
		case "/services/update-jobs/job-01/report":
			reports++
			writeV2PanelJSON(t, w, http.StatusOK, nil)
		default:
			t.Errorf("unexpected request %s", request.URL.Path)
			writeV2PanelJSON(t, w, http.StatusNotFound, nil)
		}
	}))
	defer server.Close()
	client := NewV2PanelClient(PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()})
	client.Now = func() time.Time { return now }
	job, _, err := client.ClaimHost(context.Background(), "updater-01", "", "")
	if err != nil {
		t.Fatal(err)
	}
	report := JobReport{
		ServiceID:       "updater-01",
		LeaseToken:      "",
		LeaseGeneration: 3,
		Sequence:        1,
		Status:          "claimed",
		Progress:        5,
	}
	if err := client.Report(context.Background(), job.ID, report); err != nil {
		t.Fatal(err)
	}
	report.Progress = 6
	if err := client.Report(context.Background(), job.ID, report); err == nil {
		t.Fatal("changed report reused an existing sequence")
	}
	if reports != 1 {
		t.Fatalf("report requests = %d", reports)
	}
	if _, err := client.IssueMutationGrant(context.Background(), job.ID, MutationGrantRequest{
		ServiceID:  "updater-01",
		LeaseToken: "wrong-lease",
		MutationGrantBinding: MutationGrantBinding{
			LeaseGeneration: 3,
			HostID:          "host-01",
			TransportMode:   HostTransportPullV2,
			TargetID:        "worker-01",
			ServiceType:     "worker",
			TargetVersion:   "v1.2.4",
			DeploymentMode:  ModeSystemd,
			Operation:       "apply",
			PlanSHA256:      strings.Repeat("a", 64),
			SessionID:       "session-1234567890abcdef",
			OwnershipEpoch:  9,
			PolicyRevision:  7,
		},
	}); err == nil {
		t.Fatal("mutation grant with a changed lease binding was accepted")
	}
}

func v2PanelSoftwareLease(t *testing.T, now time.Time) contracts.UpdaterLeaseEnvelope {
	t.Helper()
	desired := contracts.UpdaterDesiredOperation{
		Operation: contracts.UpdaterDesiredSoftwareUpdate,
		SoftwareUpdate: &contracts.UpdaterSoftwareUpdateDesiredOperation{
			ExpectedCurrentVersion: "v1.2.3",
			TargetVersion:          "v1.2.4",
			Strategy:               contracts.SystemUpdateWhenIdle,
		},
	}
	target := contracts.UpdaterTargetIdentity{
		TargetKind:             contracts.UpdaterTargetApplication,
		ServiceID:              "worker-01",
		ServiceType:            contracts.SystemUpdateTargetWorker,
		DeploymentMode:         contracts.SystemUpdateDeploymentSystemd,
		ExpectedConfigRevision: 4,
	}
	return v2PanelLease(t, now, desired, target, contracts.UpdaterCapabilityUpdate)
}

func v2PanelPortLease(t *testing.T, now time.Time) contracts.UpdaterLeaseEnvelope {
	t.Helper()
	desired := contracts.UpdaterDesiredOperation{
		Operation: contracts.UpdaterDesiredPortReconfigure,
		PortReconfigure: &contracts.SystemUpdatePortReconfiguration{
			NetworkNamespace:               "host",
			Protocol:                       contracts.SystemUpdatePortProtocolTCP,
			OldPort:                        4000,
			NewPort:                        4001,
			ExpectedEndpointRevision:       3,
			TargetEndpointRevision:         4,
			ExpectedConfigRevision:         4,
			TargetConfigRevision:           5,
			ExpectedConfigSHA256:           "sha256:" + strings.Repeat("1", 64),
			TargetConfigSHA256:             "sha256:" + strings.Repeat("2", 64),
			ExpectedSourcePolicyRevision:   6,
			ExpectedUpdaterPolicyRevision:  7,
			ExpectedExecutorPolicyRevision: 8,
			ExpectedExecutorPolicySHA256:   "sha256:" + strings.Repeat("3", 64),
			PortPlanSHA256:                 strings.Repeat("4", 64),
		},
	}
	target := contracts.UpdaterTargetIdentity{
		TargetKind:             contracts.UpdaterTargetApplication,
		ServiceID:              "worker-01",
		ServiceType:            contracts.SystemUpdateTargetWorker,
		DeploymentMode:         contracts.SystemUpdateDeploymentSystemd,
		ExpectedConfigRevision: 4,
	}
	return v2PanelLease(t, now, desired, target, contracts.UpdaterCapabilityPort)
}

func v2PanelBootstrapLease(t *testing.T, now time.Time) contracts.UpdaterLeaseEnvelope {
	t.Helper()
	desired := contracts.UpdaterDesiredOperation{
		Operation: contracts.UpdaterDesiredBootstrap,
		Bootstrap: &contracts.UpdaterBootstrapDesiredOperation{
			ExpectedState: "absent",
			TargetVersion: "v1.2.4",
		},
	}
	target := contracts.UpdaterTargetIdentity{
		TargetKind:      contracts.UpdaterTargetUpdateAgent,
		ServiceID:       "update-agent-01",
		ServiceType:     contracts.SystemUpdateTargetUpdateAgent,
		DeploymentMode:  contracts.SystemUpdateDeploymentSystemd,
		ExecutionHostID: "host-01",
	}
	return v2PanelLease(t, now, desired, target, contracts.UpdaterCapabilityBootstrap)
}

func v2PanelSelfUpdateLease(t *testing.T, now time.Time) contracts.UpdaterLeaseEnvelope {
	t.Helper()
	desired := contracts.UpdaterDesiredOperation{
		Operation: contracts.UpdaterDesiredHostSelfUpdate,
		HostSelfUpdate: &contracts.HostAgentSelfUpdateDirective{
			Generation:              "123e4567-e89b-42d3-a456-426614174000",
			AgentVersion:            "v1.2.4",
			ExecutorVersion:         "v1.2.4",
			Commit:                  strings.Repeat("a", 40),
			ArtifactSHA256:          "sha256:" + strings.Repeat("b", 64),
			AgentProtocolVersion:    2,
			ExecutorProtocolVersion: 2,
			MutationProtocolVersion: 2,
			RecoveryProtocolVersion: 2,
			Release: contracts.HostSelfUpdateReleaseBinding{
				Tag:                     "v1.2.4",
				Commit:                  strings.Repeat("a", 40),
				PublishedAt:             now.Add(-2 * time.Hour),
				ManifestAssetID:         10,
				ManifestAssetName:       "host-agent-manifest.json",
				ManifestSHA256:          strings.Repeat("c", 64),
				ManifestChecksumAssetID: 11,
				ManifestChecksumSHA256:  strings.Repeat("d", 64),
				ArchiveAssetID:          12,
				ArchiveAssetName:        "autostream-host-agent_v1.2.4_linux_amd64.tar.gz",
				ArchiveSize:             1024,
				ArchiveSHA256:           strings.Repeat("e", 64),
				ArchiveChecksumAssetID:  13,
				ArchiveChecksumSHA256:   strings.Repeat("f", 64),
				Arch:                    "amd64",
				AgentProtocolVersion:    2,
				ExecutorProtocolVersion: 2,
				MutationProtocolVersion: 2,
				RecoveryProtocolVersion: 2,
				MinimumPanelVersion:     "v1.2.3",
			},
			StagedAt: now.Add(-time.Hour),
		},
	}
	target := contracts.UpdaterTargetIdentity{
		TargetKind:      contracts.UpdaterTargetHostRuntime,
		ServiceID:       "update-agent-01",
		ServiceType:     contracts.SystemUpdateTargetUpdateAgent,
		DeploymentMode:  contracts.SystemUpdateDeploymentSystemd,
		ExecutionHostID: "host-01",
	}
	return v2PanelLease(t, now, desired, target, contracts.UpdaterCapabilitySelfUpdate)
}

func v2PanelLease(
	t *testing.T,
	now time.Time,
	desired contracts.UpdaterDesiredOperation,
	target contracts.UpdaterTargetIdentity,
	capability contracts.UpdaterCapability,
) contracts.UpdaterLeaseEnvelope {
	t.Helper()
	digest, err := contracts.ComputeUpdaterCommandCanonicalDigest(target, 7, 9, desired)
	if err != nil {
		t.Fatalf("compute command digest: %v", err)
	}
	return contracts.UpdaterLeaseEnvelope{
		ProtocolVersion: 2,
		LeaseID:         "lease-01",
		LeaseGeneration: 3,
		LeaseExpiresAt:  now.Add(5 * time.Minute),
		Command: contracts.UpdaterCommandEnvelope{
			ProtocolVersion: 2,
			CommandID:       "command-01",
			Issuer: contracts.UpdaterCommandIssuer{
				ServiceID:      "control-panel-01",
				ServiceType:    "control_panel",
				Authentication: "assignment_bound_rotating_service_identity",
				Permission:     "updates.authorize",
			},
			IdempotencyKey:         "idempotency-01",
			CanonicalPayloadDigest: digest,
			MutationAuthorization: contracts.UpdaterMutationAuthorization{
				AuthorizationID:         "authorization-01",
				NonceID:                 "nonce-1234567890abcdef",
				JobID:                   "job-01",
				UpdaterID:               "updater-01",
				HostID:                  "host-01",
				ActionType:              capability,
				Target:                  target,
				CanonicalArgumentDigest: digest,
				DesiredRevision:         7,
				Fence:                   9,
				ExpiresAt:               now.Add(10 * time.Minute),
				RequiredCapability:      capability,
				OneTime:                 true,
			},
			DesiredOperation:   desired,
			AuditCorrelationID: "audit-01",
		},
	}
}

func writeV2PanelJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set(controlplane.ContractMajorHeader, controlplane.ContractMajorV2)
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	if value != nil {
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Errorf("encode v2 response: %v", err)
		}
	}
}
