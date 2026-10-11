//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var ui185PreparationDownloads int

type ui185ChainHistory struct {
	roots    []string
	before   map[string]ui185FileObservation
	evidence map[string]any
}

func ui185PrepareChainHistory(t *testing.T, h *softwareUpdateChainHarness, requestedJob string) ui185ChainHistory {
	t.Helper()
	cfg := HelperConfig{StateDir: LocalExecutorMutationStateDir, Arch: "amd64"}
	if ensureExecutorStateDirectories(cfg) != nil {
		t.Fatal("prepare isolated root stage namespace")
	}
	rt := defaultExecutorMutationRuntime()
	rt.publicArtifactsOnly = true
	history := ui185ChainHistory{evidence: map[string]any{"schema_version": 1, "base": "1569e55db8c76cab24739fc971765c8aac11c840", "updater_sha": os.Getenv("AUTOSTREAM_ST_PORT_UPDATER_SHA"), "control_panel_sha": os.Getenv("AUTOSTREAM_ST_PORT_CONTROL_PANEL_SHA"), "tuple": os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_REVISION_TUPLE"), "producer": "prepareExecutorStage", "terminal_records": 2, "requested_target_old_job": true, "before_refused": false, "inspect_uds_passed": false, "terminal_clear_passed": false}}
	for index, id := range []string{"control-panel", "history-control-panel"} {
		target := h.rootPolicy.Targets[0].runtimeTarget(h.rootPolicy.HostID)
		target.TargetID = id
		// The second synthetic history profile shares the verified process/release,
		// but has its own application identity endpoint and independent ledger.
		if index == 1 {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				_ = json.NewEncoder(w).Encode(map[string]any{"version": "v2.0.0", "service_id": id, "service_type": "control_panel", "config_revision": 1})
			}))
			defer server.Close()
			target.HealthURL, target.VersionURL = server.URL+"/health", server.URL+"/updater/version"
		}
		plan := MutationPlan{JobID: "ui185-terminal-history-" + id, HostID: h.rootPolicy.HostID, TargetID: id, ServiceType: target.ServiceType, DeploymentMode: ModeSystemd, CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ConfigSHA256: h.rootPolicy.Targets[0].ConfigSHA256, LeaseGeneration: 1, ArtifactDigest: strings.TrimPrefix(h.artifactDigest, "sha256:"), ExpectedVersion: "v2.0.1", SessionID: "session-0123456789abcdef"}
		var err error
		plan.PlanSHA256, err = plan.ComputePlanSHA256()
		if err != nil || plan.Validate() != nil {
			t.Fatal("invalid genuine stage generation plan")
		}
		stage, err := prepareExecutorStage(h.ctx, cfg, target, plan, BoundedSecret(""), rt)
		if err != nil {
			t.Fatal("actual prepareExecutorStage did not produce retained nested history")
		}
		container, err := remoteStageRoot(cfg, plan)
		if err != nil || filepath.Dir(filepath.Dir(filepath.Dir(stage.RootDir))) != container {
			t.Fatal("producer did not return its nested artifact root")
		}
		ledger := executorMutationLedger{SchemaVersion: 1, JobID: plan.JobID, TargetID: id, PlanSHA256: plan.PlanSHA256, SessionID: plan.SessionID, LeaseGeneration: 1, Intent: newRemoteMutationIntent(plan), Operation: "reconcile", State: remoteLedgerTerminal, Stage: &stage, Result: &ApplyResult{Status: "succeeded"}}
		if ledger.validate(id) != nil || saveExecutorMutationLedger(cfg, ledger) != nil {
			t.Fatal("save validated synthetic terminal history")
		}
		history.roots = append(history.roots, remoteLedgerPath(cfg, id), container)
		ui185PreparationDownloads++
	}
	h.requireDownloads(t, 0, 0)
	history.before = ui185Snapshot(t, history.roots...)
	baselineInput := ui185Snapshot(t, cfg.StateDir)
	baseline := os.Getenv("AUTOSTREAM_UI185_BASE_TEST_BINARY")
	if !filepath.IsAbs(baseline) {
		t.Fatal("fixed-base stage reference oracle missing")
	}
	ctx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, baseline, "-test.run=^TestUI185FixedBaseStageInspectionProcess$", "-test.v", "-test.count=1", "-test.timeout=25s")
	command.Env = append(os.Environ(), "AUTOSTREAM_UI185_BASE_PROCESS=1", "AUTOSTREAM_UI185_RECORD_ROOT="+cfg.StateDir, "AUTOSTREAM_UI185_JOB="+requestedJob)
	output, err := command.CombinedOutput()
	marker := strings.Index(string(output), "UI185_BASE=")
	var baselineProof struct {
		Base      string `json:"base"`
		SameInput bool   `json:"same_generated_input"`
		Refused   bool   `json:"refused"`
		Class     string `json:"refusal_class"`
		Preserved bool   `json:"bytes_metadata_preserved"`
		SHA256    string `json:"input_snapshot_sha256"`
	}
	if err != nil || marker < 0 {
		t.Fatal("fixed UI185 base comparison process did not complete")
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)[marker+len("UI185_BASE="):]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&baselineProof) != nil || baselineProof.Base != "1569e55db8c76cab24739fc971765c8aac11c840" || !baselineProof.SameInput || !baselineProof.Refused || !baselineProof.Preserved || baselineProof.Class != "orphan_or_unsafe_root_stage" || baselineProof.SHA256 != ui185SnapshotDigest(baselineInput) {
		t.Fatal("fixed UI185 base did not reject the identical genuine producer input")
	}
	ui185RequireSnapshot(t, baselineInput, cfg.StateDir)
	ui185RequireSnapshot(t, history.before, history.roots...)
	history.evidence["before_refused"], history.evidence["before_bytes_metadata_preserved"] = true, true
	history.evidence["same_input_snapshot_sha256"] = baselineProof.SHA256
	history.evidence["terminal_history_snapshot_sha256"] = ui185SnapshotDigest(history.before)
	history.evidence["terminal_ledger_sha256"] = []string{history.before[history.roots[0]].SHA256, history.before[history.roots[2]].SHA256}
	history.evidence["terminal_ledger_bytes"] = []int64{history.before[history.roots[0]].Size, history.before[history.roots[2]].Size}
	history.evidence["history_snapshot_entries"] = len(history.before)
	history.evidence["snapshot_non_atomic"] = true
	history.evidence["nested_layout"] = "hash/artifact/extracted/package"
	history.evidence["preparation_root_downloads"] = ui185PreparationDownloads
	history.evidence["producer_stage_calls"] = 2
	history.evidence["producer_apply_calls"] = 0
	history.evidence["positive_fixture_has_unknown_stage"] = false
	ui185IndependentChainNegative(t, h, &history)
	ui185WriteChainEvidence(t, h, history)
	return history
}

func ui185IndependentChainNegative(t *testing.T, h *softwareUpdateChainHarness, history *ui185ChainHistory) {
	t.Helper()
	root, err := os.MkdirTemp(stPortChainRoot, "ui185-negative-")
	if err != nil {
		t.Fatal("create independent unknown-stage fixture")
	}
	for _, id := range []string{"control-panel", "history-control-panel"} {
		ui185SaveLedger(t, root, ui185ExtractedLedger(t, root, id, "old-terminal-"+id))
	}
	unknown := filepath.Join(root, "stages", "autostream-manual-smoke-v1.9.16")
	manualHostUpgradeLinuxMkdir(t, unknown, 0o700)
	before := ui185Snapshot(t, root)
	err = scanSoftwareClaimRecoveryRemoteRecords("new-unapplied-job", root, defaultManualHostUpgradeRuntime())
	if err == nil || err.Error() != "software claim recovery has an orphan or unsafe root stage" {
		t.Fatal("unknown stage was exempted by its name")
	}
	ui185RequireSnapshot(t, before, root)
	history.evidence["independent_unknown_stage_refused"] = true
	history.evidence["negative_bytes_metadata_preserved"] = true
	history.evidence["negative_fixture_repaired"] = false
}

func ui185InspectChainHistory(t *testing.T, h *softwareUpdateChainHarness, recovery *stPortChainProcess, job string, history *ui185ChainHistory) {
	t.Helper()
	protected := []string{LocalExecutorMutationStateDir, HostPullAgentStateDir, HostAgentIdentityPath, DefaultLocalExecutorPolicyPath}
	before := ui185Snapshot(t, protected...)
	centralBefore := h.readSoftware(t, job)
	response := recovery.call(t, stPortChainCommand{Command: "inspect", JobID: job, LeaseGeneration: 1})
	calls := softwareUpdateChainDecodeCalls(t, response)
	if !response.OK || calls.Inspections != 1 || calls.Stage != 0 || calls.Apply != 0 || calls.Reconcile != 0 {
		t.Fatal("nested history did not pass read-only real UDS inspection")
	}
	ui185RequireSnapshot(t, before, protected...)
	ui185RequireSnapshot(t, history.before, history.roots...)
	if h.readSoftware(t, job) != centralBefore {
		t.Fatal("read-only nested history inspect changed the central claim")
	}
	h.requireDownloads(t, 0, 0)
	history.evidence["inspect_uds_passed"] = true
	history.evidence["inspect_bytes_metadata_preserved"] = true
	history.evidence["inspect_central_claim_preserved"] = true
	history.evidence["inspect_stage_calls"], history.evidence["inspect_apply_calls"], history.evidence["inspect_reconcile_calls"] = 0, 0, 0
	ui185WriteChainEvidence(t, h, *history)
}

func ui185WriteChainEvidence(t *testing.T, h *softwareUpdateChainHarness, history ui185ChainHistory) {
	t.Helper()
	data, err := json.MarshalIndent(history.evidence, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(h.evidence, "artifacts", "ui185-stage-reference.json"), append(data, '\n'), 0o644) != nil {
		t.Fatal("write bounded stage reference evidence")
	}
}
