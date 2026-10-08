//go:build linux

package httpapi

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/autostream-control-panel/internal/security"
	"github.com/example/autostream-control-panel/internal/store"
	"github.com/example/autostream-control-panel/internal/updateradapter"
	"github.com/example/autostream-control-panel/internal/version"
)

type softwareUpdateChainCPConfig struct {
	stPortChainCPConfig
	Software struct {
		Source     int64  `json:"source"`
		Projection int64  `json:"projection"`
		Executor   int64  `json:"executor"`
		CPCommit   string `json:"cp_commit"`
	} `json:"software"`
}

// This overlay is compiled separately into each immutable CP source tree.
// The existing process/IPC fixture, production MariaDB stores, HTTP handlers,
// authentication and fixed configure projection remain the authority.
func TestSoftwareUpdateFullChainControlPanelProcess(t *testing.T) {
	if os.Getenv("AUTOSTREAM_ST_PORT_CHAIN_CHILD") != "cp" || os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_FULL_CHAIN") != "1" {
		t.Skip("software-update disposable process fixture is not selected")
	}
	in, out := os.NewFile(3, "software-cp-command"), os.NewFile(4, "software-cp-observation")
	if in == nil || out == nil {
		t.Fatal("private inherited process pipes unavailable")
	}
	defer in.Close()
	defer out.Close()
	ready := false
	setupPhase := "software_setup_config"
	defer func() {
		if !ready {
			_ = json.NewEncoder(out).Encode(stPortChainCPResponse{ErrorCode: setupPhase})
		}
	}()
	body, err := stPortChainReadRootFile(os.Getenv("AUTOSTREAM_ST_PORT_CHAIN_CONFIG"), false)
	var cfg softwareUpdateChainCPConfig
	if err != nil || stPortChainDecode(body, &cfg) != nil || cfg.PanelURL != "https://localhost:18443" || cfg.ListenAddr != "127.0.0.1:18443" ||
		cfg.Mode != "systemd" || cfg.AgentUID == 0 || cfg.AgentGID == 0 || !filepath.IsAbs(cfg.FixtureDir) ||
		(cfg.Software.CPCommit != "0315845e3af01eff6b97c6164db3ddc3109b55af" && cfg.Software.CPCommit != "9c75188147daf8435d005651a8266ae31ce39653") ||
		!((cfg.Software.Source == 8 && cfg.Software.Projection == 8 && cfg.Software.Executor == 8) || (cfg.Software.Source == 11 && cfg.Software.Projection == 13 && cfg.Software.Executor == 17)) {
		t.Fatal("invalid bounded software CP configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 34*time.Minute)
	defer cancel()
	t.Setenv("AUTOSTREAM_SERVICE_PUBLIC_ALLOWED_HOSTS", "worker.example.test")
	t.Setenv("AUTOSTREAM_BIND_ADDR", "127.0.0.1:18080")
	t.Setenv("AUTOSTREAM_CONFIG_REVISION", "1")
	for _, target := range append(append([]versionUpdateTarget{controlPanelVersionUpdateTarget}, nodeVersionUpdateTargets...), dockerVersionUpdateTarget) {
		t.Setenv(target.latestVersionEnv, "v2.0.1")
	}
	// A version override is deliberately manifest_unverified in the real CP.
	// Keep this target on its fixed GitHub HTTPS release/manifest/checksum path;
	// only DNS/TLS and the immutable provider bytes are isolated by the harness.
	t.Setenv(controlPanelVersionUpdateTarget.latestVersionEnv, "")
	t.Setenv(controlPanelVersionUpdateTarget.updateCheckURLEnv, "")
	version.Version = "v2.0.0" // The synthetic target application's starting version.
	setupPhase = "software_setup_database"
	f, err := stPortChainOpenCP(ctx, cfg.stPortChainCPConfig)
	if err != nil {
		t.Fatal("open isolated actual CP stores")
	}
	defer f.db.Close()
	defer f.reads.Close()
	defer f.client.CloseIdleConnections()
	setupPhase = "software_setup_authority"
	if err := softwareUpdateChainSeed(ctx, f, cfg); err != nil {
		for message, phase := range map[string]string{
			"read fixture policy":                         "software_setup_policy_read",
			"read exact bootstrap ownership":              "software_setup_ownership_read",
			"replace bootstrap target through policy CAS": "software_setup_policy_cas",
			"read replaced CP policy bindings":            "software_setup_binding_read",
			"verify independent CP revisions":             "software_setup_revision_check",
			"restart authority changed":                   "software_setup_restart_check",
			"setup refuses existing jobs":                 "software_setup_existing_job",
		} {
			if err.Error() == message {
				setupPhase = phase
				break
			}
		}
		t.Fatal("initialize bounded software target authority")
	}
	setupPhase = "software_setup_tls"
	cert, certErr := stPortChainReadRootFile(cfg.TLSCert, false)
	key, keyErr := stPortChainReadRootFile(cfg.TLSKey, true)
	identity, tlsErr := tls.X509KeyPair(cert, key)
	if certErr != nil || keyErr != nil || tlsErr != nil {
		t.Fatal("load isolated normal TLS identity")
	}
	setupPhase = "software_setup_listener"
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatal("bind isolated CP listener")
	}
	wire := &softwareUpdateChainCPWire{}
	server := &http.Server{Handler: softwareUpdateChainTransport(f, wire), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, IdleTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	setupPhase = "software_setup_login"
	if f.login(ctx) != nil {
		t.Fatal("authenticate isolated operator with actual CP HTTPS")
	}
	ready = true
	decoder, encoder := bufio.NewScanner(in), json.NewEncoder(out)
	decoder.Buffer(make([]byte, 4096), stPortChainBound)
	for decoder.Scan() {
		var command stPortChainCPCommand
		response := stPortChainCPResponse{ErrorCode: "invalid_command"}
		if stPortChainDecode(decoder.Bytes(), &command) == nil {
			response = softwareUpdateChainCommand(ctx, f, cfg, wire, command)
		}
		wire.mu.Lock()
		safeWire := wire.snapshot()
		wire.mu.Unlock()
		if encoder.Encode(struct {
			stPortChainCPResponse
			SoftwareWire any `json:"software_wire"`
		}{response, safeWire}) != nil {
			t.Fatal("private CP observation pipe closed")
		}
	}
	if decoder.Err() != nil {
		t.Fatal("private CP command exceeded bounds")
	}
}

func softwareUpdateChainProjection(f *stPortChainCP, policy store.UpdaterPolicy) (updateradapter.ConfigurePolicyProjection, error) {
	service, err := controlPanelSystemUpdateService()
	if err != nil || len(policy.Targets) != 1 || policy.Targets[0].ServiceID != "control-panel" {
		return updateradapter.ConfigurePolicyProjection{}, errors.New("invalid isolated CP target")
	}
	return updateradapter.BuildHostAgentConfigurePolicy(updateradapter.HostAgentConfigurePolicySource{PanelURL: f.config.PanelURL, ExecutionHostID: stPortChainHost,
		AgentUID: f.config.AgentUID, AgentGID: f.config.AgentGID, SourcePolicyRevision: policy.Revision, ProjectionRevision: policy.ProjectionRevision, LocalExecutorPolicyRevision: policy.LocalExecutorPolicyRevision,
		Targets: []updateradapter.HostAgentConfigurePolicyTarget{{ServiceID: service.ServiceID, ServiceType: service.ServiceType, DeploymentMode: "systemd", DatabaseName: "autostream_panel",
			EndpointRevision: service.EndpointRevision, AppliedConfigRevision: service.AppliedConfigRevision, AppliedConfigSHA256: service.AppliedConfigSHA256, AppliedEndpointPort: service.Port, LocalListenPort: service.Port}}})
}

func softwareUpdateChainSeed(ctx context.Context, f *stPortChainCP, cfg softwareUpdateChainCPConfig) error {
	policy, err := f.policies.GetUpdaterPolicy(ctx, stPortChainAgent)
	if err != nil {
		return errors.New("read fixture policy")
	}
	if len(policy.Targets) == 1 && policy.Targets[0].ServiceID == "control-panel" {
		// A CP process restart must retain the original policy/job/lease/grants.
		projection, err := softwareUpdateChainProjection(f, policy)
		if err != nil || projection.SHA256 != policy.LocalExecutorPolicySHA256 || policy.Revision != cfg.Software.Source || policy.ProjectionRevision != cfg.Software.Projection || policy.LocalExecutorPolicyRevision != cfg.Software.Executor {
			return errors.New("restart authority changed")
		}
		return nil
	}
	var jobs int
	if f.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_update_jobs").Scan(&jobs) != nil || jobs != 0 {
		return errors.New("setup refuses existing jobs")
	}
	ownership, err := f.updates.GetSystemUpdateExecutionHost(ctx, stPortChainHost)
	if err != nil || ownership.AgentServiceID != stPortChainAgent || ownership.PolicyRevision != policy.ProjectionRevision || ownership.OwnershipEpoch < 1 {
		return errors.New("read exact bootstrap ownership")
	}
	// CP's listener is owned by controlPanelSystemUpdateService, so its policy
	// target must have no explicit listener binding. Use the real policy CAS to
	// replace the initial Worker target and its revision-bound listener rows.
	policy.Targets = []store.UpdaterPolicyTarget{{TargetID: "control-panel", ServiceID: "control-panel", ServiceType: "control_panel", DeploymentMode: "systemd", DatabaseName: "autostream_panel"}}
	policy, err = f.policies.SavePullUpdaterPolicy(ctx, f.updates, stPortChainAgent, policy.Revision, ownership.OwnershipEpoch, policy)
	if err != nil {
		return errors.New("replace bootstrap target through policy CAS")
	}
	policy.Revision, policy.ProjectionRevision, policy.LocalExecutorPolicyRevision = cfg.Software.Source, cfg.Software.Projection, cfg.Software.Executor
	projection, err := softwareUpdateChainProjection(f, policy)
	if err != nil {
		return err
	}
	policy.LocalExecutorPolicySHA256 = projection.SHA256
	encoded, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	// The existing fixture already uses fresh-database setup SQL to separate
	// revisions. No job/lease/grant/report is manufactured by these setup writes.
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"UPDATE update_agent_policies SET revision=?,projection_revision=?,local_executor_policy_revision=?,policy_json=? WHERE service_id=?", []any{cfg.Software.Source, cfg.Software.Projection, cfg.Software.Executor, encoded, stPortChainAgent}},
		{"UPDATE system_update_execution_hosts SET ownership_epoch=3,policy_revision=? WHERE execution_host_id=?", []any{cfg.Software.Projection, stPortChainHost}},
		{"UPDATE services SET ownership_epoch=3 WHERE service_id=?", []any{stPortChainAgent}},
		{"UPDATE update_agent_target_databases SET binding_policy_revision=? WHERE updater_service_id=? AND target_id=?", []any{cfg.Software.Source, stPortChainAgent, "control-panel"}},
	} {
		if _, err := f.db.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			return errors.New("seed bounded disposable authority")
		}
	}
	// Read through the production snapshot reader before accepting setup. In
	// particular, it must reject any explicit CP listener or stale Worker row.
	bound, err := f.policies.GetUpdaterPolicy(ctx, stPortChainAgent)
	if err != nil || len(bound.Targets) != 1 || bound.Targets[0].ServiceID != "control-panel" || bound.Targets[0].LocalListenPort != 0 || bound.Targets[0].DatabaseName != "autostream_panel" {
		return errors.New("read replaced CP policy bindings")
	}
	verified, err := softwareUpdateChainProjection(f, bound)
	if err != nil || verified.SHA256 != bound.LocalExecutorPolicySHA256 || bound.Revision != cfg.Software.Source || bound.ProjectionRevision != cfg.Software.Projection || bound.LocalExecutorPolicyRevision != cfg.Software.Executor {
		return errors.New("verify independent CP revisions")
	}
	return nil
}

func softwareUpdateChainCommand(ctx context.Context, f *stPortChainCP, cfg softwareUpdateChainCPConfig, wire *softwareUpdateChainCPWire, command stPortChainCPCommand) stPortChainCPResponse {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	switch command.Command {
	case "init":
		policy, err := f.policies.GetUpdaterPolicy(ctx, stPortChainAgent)
		if err != nil {
			return stPortChainCPResponse{ErrorCode: "software_profile_policy_unavailable"}
		}
		response := stPortChainCPResponse{DBSourcePolicyRevision: policy.Revision, DBProjectionRevision: policy.ProjectionRevision, DBExecutorRevision: policy.LocalExecutorPolicyRevision}
		projection, projectionErr := softwareUpdateChainProjection(f, policy)
		if projectionErr != nil {
			response.ErrorCode = "software_profile_projection_unavailable"
			return response
		}
		if projection.SHA256 != policy.LocalExecutorPolicySHA256 {
			response.ErrorCode = "software_profile_digest_mismatch"
			return response
		}
		agent, agentErr := f.auth.GetService(ctx, stPortChainAgent)
		if agentErr != nil {
			response.ErrorCode = "software_profile_identity_unavailable"
			return response
		}
		token, tokenErr := security.DecryptSecret(agent.NodeTokenCiphertext, agent.NodeTokenNonce, f.key)
		if tokenErr != nil || token == "" {
			response.ErrorCode = "software_profile_token_unavailable"
			return response
		}
		f.rememberSecret(token)
		quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
		identity := fmt.Sprintf("panel_url: %s\nnode_id: %s\nruntime_token: %s\nservice_name: %s\n", quote(cfg.PanelURL), quote(stPortChainAgent), quote(token), quote(stPortChainAgent))
		response.OK, response.RootPolicy, response.AgentIdentityYAML = true, projection.Policy, identity
		return response
	case "create", "retry_create":
		if command.IdempotencyKey == "" || len(command.IdempotencyKey) > 160 {
			return stPortChainCPResponse{ErrorCode: "invalid_create_intent"}
		}
		body, _ := json.Marshal(map[string]string{"operation": "software_update", "target_id": "control-panel", "strategy": "when_idle", "idempotency_key": command.IdempotencyKey})
		status, body, err := f.request(ctx, http.MethodPost, "/system-updates", body)
		if err != nil || status != http.StatusAccepted {
			var failure struct {
				Code string `json:"code"`
			}
			if err == nil && len(body) <= stPortChainBound {
				_ = json.Unmarshal(body, &failure)
			}
			// Only source-derived closed codes cross the private pipe. The actual
			// response may also contain a target or recovery details: omit it.
			return stPortChainCPResponse{ErrorCode: "create_rejected", FailureStage: "create", FailureHTTPStatus: status, FailureCode: softwareUpdateChainCreateCode(failure.Code)}
		}
		var job store.SystemUpdateJob
		if json.Unmarshal(body, &job) != nil || job.TargetID != "control-panel" || job.PolicyRevision != cfg.Software.Projection || job.OwnershipEpoch != 3 {
			return stPortChainCPResponse{ErrorCode: "create_response_invalid"}
		}
		return stPortChainCPResponse{OK: true, Job: body}
	case "observe", "lookup":
		result := softwareUpdateChainObservedAuthority(ctx, f)
		if !result.OK {
			return result
		}
		f.mu.Lock()
		result.ClaimCount, result.ConsumeCount, result.TerminalCount, result.DroppedCount = f.claims, f.consumes, f.terminals, f.dropped
		result.TerminalBodySHA256, result.LastTerminalBodySHA256 = f.firstTerminalSHA, f.lastTerminalSHA
		f.mu.Unlock()
		if command.JobID != "" {
			job, err := store.NewMariaDBSystemUpdateStore(f.reads).GetSystemUpdateJob(ctx, command.JobID)
			if err != nil || job.TargetID != "control-panel" {
				return stPortChainCPResponse{ErrorCode: "fixture_job_unavailable"}
			}
			result.Job, _ = json.Marshal(job)
		}
		return result
	case "get":
		return f.command(ctx, command)
	case "claimed_guards":
		job, err := f.updates.GetSystemUpdateJob(ctx, command.JobID)
		if err != nil || job.Status != store.SystemUpdateStatusClaimed || job.TargetID != "control-panel" {
			return stPortChainCPResponse{ErrorCode: "fixture_job_unavailable"}
		}
		status, body, err := f.request(ctx, http.MethodPost, "/system-updates/"+job.ID+"/cancel", nil)
		var failure struct {
			Code string `json:"code"`
		}
		if err != nil || status != http.StatusConflict || json.Unmarshal(body, &failure) != nil || failure.Code != "system_update_not_cancellable" {
			return stPortChainCPResponse{ErrorCode: "claimed_cancel_guard_failed"}
		}
		// Exercise the real atomic lifecycle lane fence. The syntactically valid
		// release metadata is test-only: this deliberately cannot publish or
		// prove an attestation, because a claimed job must reject before readiness.
		now := time.Now().UTC()
		digest := strings.Repeat("a", 64)
		_, _, selfErr := f.updates.CreateSystemUpdateHostSelfUpdate(ctx, f.auth, f.policies, store.CreateSystemUpdateHostSelfUpdateParams{ExecutionHostID: stPortChainHost, TargetVersion: "v2.0.1", IdempotencyKey: "software-claimed-self-update-guard", RequestedByUserID: f.userID, RequestedByUsername: stPortChainAdmin, Now: now,
			Release: store.SystemUpdateHostReleaseMetadata{Tag: "v2.0.1", Commit: cfg.Software.CPCommit, PublishedAt: now, AttestationVerifiedAt: now,
				ManifestAssetID: 1, ManifestAssetName: "host-agent-manifest.json", ManifestSHA256: digest, ManifestChecksumAssetID: 2, ManifestChecksumSHA256: digest,
				ArchiveAssetID: 3, ArchiveAssetName: "autostream-host-agent_v2.0.1_linux_amd64.tar.gz", ArchiveSize: 1, ArchiveSHA256: digest, ArchiveChecksumAssetID: 4, ArchiveChecksumSHA256: digest,
				Arch: "amd64", AgentProtocolVersion: 2, ExecutorProtocolVersion: 2, MutationProtocolVersion: 2, RecoveryProtocolVersion: 1, MinimumPanelVersion: "v2.0.0"}})
		if !errors.Is(selfErr, store.ErrSystemUpdateExecutionHostBusy) {
			return stPortChainCPResponse{ErrorCode: "claimed_self_update_guard_failed"}
		}
		var count int
		if f.reads.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_update_host_self_updates").Scan(&count) != nil || count != 0 {
			return stPortChainCPResponse{ErrorCode: "claimed_self_update_guard_changed_state"}
		}
		return stPortChainCPResponse{OK: true, FailureHTTPStatus: status, FailureCode: failure.Code, ErrorCode: "host_lifecycle_busy"}
	case "arm_fault":
		if command.Fault != "terminal_after" && command.Fault != "claim_after" && command.Fault != "progress_claimed_after" && command.Fault != "progress_verifying_after" {
			return stPortChainCPResponse{ErrorCode: "unknown_fault"}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fault != "" {
			return stPortChainCPResponse{ErrorCode: "fault_already_armed"}
		}
		f.fault = command.Fault
		return stPortChainCPResponse{OK: true}
	case "arm_expiry_probe":
		wire.mu.Lock()
		defer wire.mu.Unlock()
		if wire.expiryProbe {
			return stPortChainCPResponse{ErrorCode: "expiry_probe_already_armed"}
		}
		wire.expiryProbe = true
		return stPortChainCPResponse{OK: true}
	default:
		return stPortChainCPResponse{ErrorCode: "unknown_command"}
	}
}

// Observation reads the current persisted authority independently of the
// tuple supplied to fixture setup. The returned projection stays private and
// lets the consumer compare it with the original frozen root-policy bytes.
func softwareUpdateChainObservedAuthority(ctx context.Context, f *stPortChainCP) stPortChainCPResponse {
	policy, err := f.policies.GetUpdaterPolicy(ctx, stPortChainAgent)
	if err != nil {
		return stPortChainCPResponse{ErrorCode: "software_observer_policy_unavailable"}
	}
	response := stPortChainCPResponse{DBSourcePolicyRevision: policy.Revision, DBProjectionRevision: policy.ProjectionRevision, DBExecutorRevision: policy.LocalExecutorPolicyRevision}
	if policy.UpdaterID != stPortChainAgent || policy.ExecutionHostID != stPortChainHost || policy.TransportMode != store.SystemUpdateTransportPullV2 || len(policy.Targets) != 1 {
		response.ErrorCode = "software_observer_binding_mismatch"
		return response
	}
	target := policy.Targets[0]
	if target.TargetID != "control-panel" || target.ServiceID != "control-panel" || target.ServiceType != "control_panel" || target.HostID != stPortChainHost || target.DeploymentMode != "systemd" || target.LocalListenPort != 0 || target.DatabaseName != "autostream_panel" {
		response.ErrorCode = "software_observer_binding_mismatch"
		return response
	}
	owner, err := f.updates.GetSystemUpdateExecutionHost(ctx, stPortChainHost)
	if err != nil {
		response.ErrorCode = "software_observer_owner_unavailable"
		return response
	}
	if owner.ExecutionHostID != stPortChainHost || owner.AgentServiceID != stPortChainAgent || owner.TransportMode != store.SystemUpdateTransportPullV2 || owner.OwnershipEpoch != 3 || owner.PolicyRevision != policy.ProjectionRevision {
		response.ErrorCode = "software_observer_binding_mismatch"
		return response
	}
	projection, err := softwareUpdateChainProjection(f, policy)
	if err != nil || projection.SHA256 != policy.LocalExecutorPolicySHA256 {
		response.ErrorCode = "software_observer_projection_mismatch"
		return response
	}
	response.OK, response.RootPolicy = true, projection.Policy
	return response
}

// These are the closed create/eligibility errors from the immutable CP's
// createSystemUpdate, buildSystemUpdateTarget and approved pull-policy paths.
func softwareUpdateChainCreateCode(code string) string {
	switch code {
	case "system_update_port_contract_required", "idempotency_key_conflict", "system_update_port_idempotency_conflict", "system_update_target_unavailable", "system_update_target_busy", "system_update_target_active", "system_update_ownership_conflict":
		return code
	case "updater_missing", "updater_policy_failed", "updater_policy_pending", "updater_policy_mismatch", "updater_policy_target_type_mismatch", "updater_offline", "target_unreachable", "target_reachability_unknown", "unsupported_deployment_mode", "current_version_unknown":
		return code
	case "release_manifest_unavailable", "release_version_invalid", "update_not_available", "release_manifest_missing", "release_manifest_invalid", "manifest_unverified", "updater_version_incompatible":
		return code
	default:
		return "unknown"
	}
}
