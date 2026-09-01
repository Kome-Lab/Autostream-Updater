package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestJobReportPortReconfigureExposesOnlyPublicResult(t *testing.T) {
	payload, err := json.Marshal(JobReport{
		ServiceID:       "host-agent-a",
		LeaseToken:      "lease-token",
		Sequence:        3,
		LeaseGeneration: 2,
		Status:          "succeeded",
		Progress:        100,
		PortReconfigure: &PortReconfigurationJobReport{Result: systemdPortResultApplied},
	})
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]json.RawMessage
	if err := json.Unmarshal(payload, &report); err != nil {
		t.Fatal(err)
	}
	var port map[string]json.RawMessage
	if err := json.Unmarshal(report["port_reconfigure"], &port); err != nil {
		t.Fatal(err)
	}
	if len(port) != 1 || string(port["result"]) != `"applied"` {
		t.Fatalf("public port result leaked local reconciliation state: %s", payload)
	}
}

func TestPanelClaimHostAcceptsExactTerminalRecoveryProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/services/update-jobs/claim" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["service_id"] != "updater-1" || body["host_id"] != "host-a" || body["active_job_id"] != "job-one" {
			t.Errorf("claim body = %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"clear_active_job_id":true,
			"terminal_job":{
				"id":"job-one",
				"updater_id":"updater-1",
				"host_id":"host-a",
				"target_id":"worker-one",
				"target_type":"worker",
				"deployment_mode":"systemd",
				"current_version":"v1.0.0",
				"target_version":"v1.1.0",
				"status":"failed",
				"progress":100,
				"code":"remote_stage_missing",
				"lease_generation":4,
				"sequence":6
			}
		}`))
	}))
	defer server.Close()

	client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
	job, clear, err := client.ClaimHost(context.Background(), "updater-1", "host-a", "job-one")
	if err != nil || !clear || job == nil || job.ID != "job-one" || job.AgentServiceID != "updater-1" ||
		job.TargetID != "worker-one" || job.EffectiveType() != "worker" || job.Status != "failed" ||
		job.Progress != 100 || job.Code != "remote_stage_missing" || job.LeaseGeneration != 4 || job.Sequence != 6 {
		t.Fatalf("terminal recovery proof job=%#v clear=%v err=%v", job, clear, err)
	}
}

func TestPanelClaimHostRejectsBareOrMismatchedTerminalRecoveryProof(t *testing.T) {
	validTerminal := map[string]any{
		"id":              "job-one",
		"updater_id":      "updater-1",
		"target_id":       "worker-one",
		"target_type":     "worker",
		"deployment_mode": "systemd",
		"target_version":  "v1.1.0",
		"status":          "failed",
		"progress":        100,
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any) map[string]any
	}{
		{name: "bare clear", mutate: func(map[string]any) map[string]any { return nil }},
		{name: "wrong job", mutate: func(job map[string]any) map[string]any { job["id"] = "job-two"; return job }},
		{name: "wrong agent", mutate: func(job map[string]any) map[string]any { job["updater_id"] = "updater-2"; return job }},
		{name: "nonterminal status", mutate: func(job map[string]any) map[string]any { job["status"] = "reconciling"; return job }},
		{name: "lease credential present", mutate: func(job map[string]any) map[string]any { job["lease_token"] = "must-not-be-returned"; return job }},
		{name: "invalid operation union", mutate: func(job map[string]any) map[string]any { job["operation"] = "port_reconfigure"; return job }},
	} {
		t.Run(test.name, func(t *testing.T) {
			terminal := make(map[string]any, len(validTerminal))
			for key, value := range validTerminal {
				terminal[key] = value
			}
			response := map[string]any{"clear_active_job_id": true}
			if mutated := test.mutate(terminal); mutated != nil {
				response["terminal_job"] = mutated
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()

			client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
			job, clear, err := client.ClaimHost(context.Background(), "updater-1", "host-a", "job-one")
			if err == nil || job != nil || clear || !strings.Contains(err.Error(), "terminal recovery proof is invalid") {
				t.Fatalf("mismatched terminal proof job=%#v clear=%v err=%v", job, clear, err)
			}
		})
	}
}

func TestPanelReportAcceptsExactTerminalCommitResponse(t *testing.T) {
	report := JobReport{
		ServiceID:       "updater-1",
		LeaseToken:      "lease-token",
		LeaseGeneration: 7,
		Sequence:        11,
		Status:          "failed",
		Progress:        100,
		Code:            "remote_stage_missing",
		Message:         "no durable mutation state remains",
		ArtifactDigest:  strings.Repeat("A", 64),
		PreviousDigest:  "sha256:" + strings.Repeat("b", 64),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/services/update-jobs/job%2Fone/report" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
		}
		var got JobReport
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		if got != report {
			t.Errorf("report body = %#v, want %#v", got, report)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(UpdateJob{
			ID: "job/one", AgentServiceID: "updater-1", LeaseGeneration: 7, Sequence: 11,
			Status: "failed", Progress: 100, Code: "remote_stage_missing",
			ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
			PreviousDigest: "sha256:" + strings.Repeat("b", 64),
		})
	}))
	defer server.Close()

	client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
	if err := client.Report(context.Background(), "job/one", report); err != nil {
		t.Fatal(err)
	}
}

func TestPanelReportRejectsMismatchedTerminalCommitResponse(t *testing.T) {
	const artifact = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const previous = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	report := JobReport{
		ServiceID: "updater-1", LeaseToken: "lease-token", LeaseGeneration: 7, Sequence: 11,
		Status: "failed", Progress: 100, Code: "remote_stage_missing", ArtifactDigest: artifact, PreviousDigest: previous,
	}
	valid := UpdateJob{
		ID: "job-one", AgentServiceID: "updater-1", LeaseGeneration: 7, Sequence: 11,
		Status: "failed", Progress: 100, Code: "remote_stage_missing", ArtifactDigest: artifact, PreviousDigest: previous,
	}
	for _, test := range []struct {
		name   string
		mutate func(*UpdateJob)
	}{
		{name: "job", mutate: func(job *UpdateJob) { job.ID = "job-two" }},
		{name: "agent", mutate: func(job *UpdateJob) { job.AgentServiceID = "updater-2" }},
		{name: "lease generation", mutate: func(job *UpdateJob) { job.LeaseGeneration++ }},
		{name: "sequence", mutate: func(job *UpdateJob) { job.Sequence++ }},
		{name: "status", mutate: func(job *UpdateJob) { job.Status = "rolled_back" }},
		{name: "progress", mutate: func(job *UpdateJob) { job.Progress = 99 }},
		{name: "code", mutate: func(job *UpdateJob) { job.Code = "different_code" }},
		{name: "artifact digest", mutate: func(job *UpdateJob) { job.ArtifactDigest = "sha256:" + strings.Repeat("c", 64) }},
		{name: "previous digest", mutate: func(job *UpdateJob) { job.PreviousDigest = "sha256:" + strings.Repeat("c", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			committed := valid
			test.mutate(&committed)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(committed); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()

			client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
			err := client.Report(context.Background(), "job-one", report)
			if err == nil || !strings.Contains(err.Error(), "does not match the committed update job") {
				t.Fatalf("mismatched terminal report response error = %v", err)
			}
		})
	}
}

func TestPanelErrorDoesNotExposeUntrustedResponseBody(t *testing.T) {
	const secret = "lease-token-must-not-reach-logs"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"code":"` + secret + `","reflected":"` + secret + `"}`))
	}))
	defer server.Close()

	client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
	err := client.post(context.Background(), "/test-error", map[string]any{}, nil)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("panel error exposed untrusted response: %v", err)
	}
	var httpErr *PanelHTTPError
	if !errors.As(err, &httpErr) || httpErr.Code != "" || httpErr.Status != http.StatusBadGateway {
		t.Fatalf("panel error = %#v", err)
	}
}

func TestPanelErrorAllowsMutationGrantConsumptionContractCode(t *testing.T) {
	const code = "invalid_system_update_mutation_grant_consumption"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"` + code + `"}`))
	}))
	defer server.Close()

	client := PanelClient{BaseURL: server.URL, Token: "runtime-token", HTTP: server.Client()}
	err := client.post(context.Background(), "/test-error", map[string]any{}, nil)
	var httpErr *PanelHTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusBadRequest || httpErr.Code != code {
		t.Fatalf("panel error = %#v", err)
	}
}

func TestConsumeMutationGrantNeverFollowsRedirect(t *testing.T) {
	var redirectedCalls atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Errorf("mutation grant reached redirect target: %q", authorization)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirectTarget.Close()

	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", redirectTarget.URL+"/credential-capture")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirectSource.Close()

	err := ConsumeMutationGrant(
		context.Background(),
		redirectSource.URL,
		"job-one",
		"one-time-mutation-grant",
		MutationGrantBinding{},
		redirectSource.Client(),
	)
	var panelError *PanelHTTPError
	if !errors.As(err, &panelError) || panelError.Status != http.StatusTemporaryRedirect {
		t.Fatalf("redirect response error = %v", err)
	}
	if redirectedCalls.Load() != 0 {
		t.Fatalf("mutation grant followed %d redirects", redirectedCalls.Load())
	}
}
