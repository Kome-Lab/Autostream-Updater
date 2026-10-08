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
	defer func() {
		if !ready {
			_ = json.NewEncoder(out).Encode(stPortChainCPResponse{ErrorCode: "cp_setup_failed"})
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
	version.Version = "v2.0.0" // The synthetic target application's starting version.
	f, err := stPortChainOpenCP(ctx, cfg.stPortChainCPConfig)
	if err != nil {
		t.Fatal("open isolated actual CP stores")
	}
	defer f.db.Close()
	defer f.reads.Close()
	defer f.client.CloseIdleConnections()
	if err := softwareUpdateChainSeed(ctx, f, cfg); err != nil {
		t.Fatal("initialize bounded software target authority")
	}
	cert, certErr := stPortChainReadRootFile(cfg.TLSCert, false)
	key, keyErr := stPortChainReadRootFile(cfg.TLSKey, true)
	identity, tlsErr := tls.X509KeyPair(cert, key)
	if certErr != nil || keyErr != nil || tlsErr != nil {
		t.Fatal("load isolated normal TLS identity")
	}
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		t.Fatal("bind isolated CP listener")
	}
	wire := &softwareUpdateChainCPWire{}
	server := &http.Server{Handler: softwareUpdateChainTransport(f, wire), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, IdleTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, ErrorLog: log.New(io.Discard, "", 0)}
	defer server.Close()
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
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
	policy.Revision, policy.ProjectionRevision, policy.LocalExecutorPolicyRevision = cfg.Software.Source, cfg.Software.Projection, cfg.Software.Executor
	policy.Targets = []store.UpdaterPolicyTarget{{TargetID: "control-panel", ServiceID: "control-panel", ServiceType: "control_panel", DeploymentMode: "systemd", DatabaseName: "autostream_panel", LocalListenPort: 18080}}
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
		{"INSERT INTO update_agent_target_databases (updater_service_id,target_id,binding_policy_revision,database_name,updated_at) VALUES (?,?,?,?,?)", []any{stPortChainAgent, "control-panel", cfg.Software.Source, "autostream_panel", time.Now().UTC()}},
		{"INSERT INTO update_agent_target_local_listeners (updater_service_id,target_id,binding_policy_revision,local_listen_port,updated_at) VALUES (?,?,?,?,?)", []any{stPortChainAgent, "control-panel", cfg.Software.Source, 18080, time.Now().UTC()}},
	} {
		if _, err := f.db.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			return errors.New("seed bounded disposable authority")
		}
	}
	return nil
}

func softwareUpdateChainCommand(ctx context.Context, f *stPortChainCP, cfg softwareUpdateChainCPConfig, wire *softwareUpdateChainCPWire, command stPortChainCPCommand) stPortChainCPResponse {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	switch command.Command {
	case "init":
		policy, err := f.policies.GetUpdaterPolicy(ctx, stPortChainAgent)
		projection, projectionErr := softwareUpdateChainProjection(f, policy)
		agent, agentErr := f.auth.GetService(ctx, stPortChainAgent)
		token, tokenErr := security.DecryptSecret(agent.NodeTokenCiphertext, agent.NodeTokenNonce, f.key)
		if err != nil || projectionErr != nil || projection.SHA256 != policy.LocalExecutorPolicySHA256 || agentErr != nil || tokenErr != nil || token == "" {
			return stPortChainCPResponse{ErrorCode: "fixture_identity_unavailable"}
		}
		f.rememberSecret(token)
		quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
		identity := fmt.Sprintf("panel_url: %s\nnode_id: %s\nruntime_token: %s\nservice_name: %s\n", quote(cfg.PanelURL), quote(stPortChainAgent), quote(token), quote(stPortChainAgent))
		return stPortChainCPResponse{OK: true, RootPolicy: projection.Policy, AgentIdentityYAML: identity}
	case "create", "retry_create":
		if command.IdempotencyKey == "" || len(command.IdempotencyKey) > 160 {
			return stPortChainCPResponse{ErrorCode: "invalid_create_intent"}
		}
		body, _ := json.Marshal(map[string]string{"operation": "software_update", "target_id": "control-panel", "strategy": "when_idle", "idempotency_key": command.IdempotencyKey})
		status, body, err := f.request(ctx, http.MethodPost, "/system-updates", body)
		if err != nil || status != http.StatusAccepted {
			return stPortChainCPResponse{ErrorCode: "create_rejected", FailureStage: "create", FailureHTTPStatus: status}
		}
		var job store.SystemUpdateJob
		if json.Unmarshal(body, &job) != nil || job.TargetID != "control-panel" || job.PolicyRevision != cfg.Software.Projection || job.OwnershipEpoch != 3 {
			return stPortChainCPResponse{ErrorCode: "create_response_invalid"}
		}
		return stPortChainCPResponse{OK: true, Job: body}
	case "observe", "lookup":
		result := stPortChainCPResponse{OK: true, DBSourcePolicyRevision: cfg.Software.Source, DBProjectionRevision: cfg.Software.Projection, DBExecutorRevision: cfg.Software.Executor}
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
