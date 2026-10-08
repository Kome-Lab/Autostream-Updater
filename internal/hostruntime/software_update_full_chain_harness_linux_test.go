//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type softwareUpdateChainHarness struct {
	*stPortChainHarness
	provider                      *stPortChainProcess
	artifactDigest                string
	initialPolicy                 []byte
	baselineRelease               string
	oldBinary                     string
	source, projection, executor  int64
	agentDownloads, rootDownloads int
	boundaries                    []softwareUpdateChainBoundaryEvidence
}

func newSoftwareUpdateChainHarness(t *testing.T) *softwareUpdateChainHarness {
	t.Helper()
	if os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_FULL_CHAIN") != "1" {
		t.Skip("disposable actual CP software update process fixture is not selected")
	}
	marker, err := os.ReadFile(filepath.Join(stPortChainRoot, "isolated"))
	container, containerErr := os.ReadFile("/run/systemd/container")
	if os.Geteuid() != 0 || err != nil || string(marker) != "ST-PORT disposable integration namespace v1\n" || containerErr != nil || strings.TrimSpace(string(container)) == "" {
		t.Fatal("software mutation fixture requires its fresh network-none systemd container")
	}
	for _, path := range []string{HostAgentIdentityPath, localExecutorPortPolicyPath, LocalExecutorMutationStateDir, HostPullAgentStateDir, "/opt/autostream/control-panel/current", "/opt/autostream/local-executor/ports"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("fixture refuses a pre-existing runtime installation")
		}
	}
	commit := os.Getenv("AUTOSTREAM_ST_PORT_CONTROL_PANEL_SHA")
	if commit != "0315845e3af01eff6b97c6164db3ddc3109b55af" && commit != "9c75188147daf8435d005651a8266ae31ce39653" {
		t.Fatal("immutable CP source identity unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Minute)
	base := &stPortChainHarness{ctx: ctx, cancel: cancel, uid: 16531, gid: 16531, cpBinary: os.Getenv("AUTOSTREAM_ST_PORT_CP_TEST_BINARY"), evidence: os.Getenv("AUTOSTREAM_ST_PORT_EVIDENCE"), runtimeMode: "software"}
	if !filepath.IsAbs(base.cpBinary) || !filepath.IsAbs(base.evidence) {
		t.Fatal("immutable process inputs incomplete")
	}
	h := &softwareUpdateChainHarness{stPortChainHarness: base, source: 8, projection: 8, executor: 8, oldBinary: os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_BEFORE_TEST_BINARY")}
	if !filepath.IsAbs(h.oldBinary) {
		t.Fatal("immutable original Updater process input is required")
	}
	if os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_REVISION_TUPLE") == "distinct" {
		h.source, h.projection, h.executor = 11, 13, 17
	} else if os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_REVISION_TUPLE") != "equal" {
		t.Fatal("bounded revision tuple is required")
	}
	for _, dir := range []string{"/opt/autostream/software-test", "/etc/autostream/updater", "/opt/autostream/control-panel/releases", "/opt/autostream/local-executor", "/var/lib/autostream", h.evidence, filepath.Join(h.evidence, "processes"), filepath.Join(h.evidence, "artifacts")} {
		if os.MkdirAll(dir, 0o755) != nil {
			t.Fatal("prepare isolated fixture paths")
		}
	}
	if os.Mkdir("/opt/autostream/local-executor/ports", 0o700) != nil {
		t.Fatal("create private root sidecar path")
	}
	stPortChainRun(t, "/usr/sbin/groupadd", "--gid", strconv.Itoa(int(h.gid)), "autostream-host-agent")
	stPortChainRun(t, "/usr/sbin/useradd", "--uid", strconv.Itoa(int(h.uid)), "--gid", strconv.Itoa(int(h.gid)), "--no-create-home", "--shell", "/usr/sbin/nologin", "autostream-host-agent")
	if os.Chown("/etc/autostream/updater", 0, int(h.gid)) != nil || os.Chmod("/etc/autostream/updater", 0o750) != nil {
		t.Fatal("prepare canonical protected identity directory")
	}
	stPortChainRun(t, "/usr/sbin/groupadd", "--gid", "16532", "autostream")
	stPortChainRun(t, "/usr/sbin/useradd", "--uid", "16532", "--gid", "16532", "--no-create-home", "--shell", "/usr/sbin/nologin", "autostream")
	if os.Mkdir(HostPullAgentStateDir, 0o700) != nil || os.Chown(HostPullAgentStateDir, int(h.uid), int(h.gid)) != nil {
		t.Fatal("prepare isolated non-root journal")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal("locate compiled process fixture")
	}
	h.testBinary = "/opt/autostream/software-test/hostruntime.test"
	stPortChainCopy(t, self, h.testBinary, 0o755)
	stPortChainWriteNamedCA(t, []string{"localhost", "api.github.com"})
	// Normal production binaries launched by systemd use the namespace's
	// standard trust store; neither installer nor runtime receives TLS overrides.
	stPortChainCopy(t, filepath.Join(stPortChainRoot, "tls.crt"), "/usr/local/share/ca-certificates/software-update-fixture.crt", 0o644)
	stPortChainRun(t, "/usr/sbin/update-ca-certificates")
	hosts, err := os.OpenFile("/etc/hosts", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal("isolated provider DNS unavailable")
	}
	_, err = hosts.WriteString("\n127.0.0.1 api.github.com\n")
	closeErr := hosts.Close()
	if err != nil || closeErr != nil {
		t.Fatal("install isolated provider name")
	}
	privateCP := filepath.Join(stPortChainRoot, "cp-private")
	if os.Mkdir(privateCP, 0o700) != nil {
		t.Fatal("exclusive private CP bootstrap path")
	}
	h.configPath = filepath.Join(stPortChainRoot, "cp-config.json")
	cfg := map[string]any{"dsn_file": os.Getenv("AUTOSTREAM_ST_PORT_DSN_FILE"), "panel_url": "https://localhost:18443", "listen_addr": "127.0.0.1:18443", "tls_cert": filepath.Join(stPortChainRoot, "tls.crt"), "tls_key": filepath.Join(stPortChainRoot, "tls.key"), "agent_uid": h.uid, "agent_gid": h.gid, "worker_version": "v2.0.0", "mode": "systemd", "fixture_dir": privateCP,
		"software": map[string]any{"source": h.source, "projection": h.projection, "executor": h.executor, "cp_commit": commit}}
	cfgBytes, _ := json.Marshal(cfg)
	if os.WriteFile(h.configPath, cfgBytes, 0o600) != nil {
		t.Fatal("write protected CP fixture input")
	}
	t.Cleanup(func() {
		h.agent.stop()
		h.root.stop()
		h.cp.stop()
		h.provider.stop()
		h.cancel()
		_ = exec.Command("/usr/bin/systemctl", "stop", "autostream-control-panel.service").Run()
	})
	h.cp = h.start(t, "cp", h.cpBinary, "TestSoftwareUpdateFullChainControlPanelProcess", 0, 0)
	initial := h.cp.call(t, stPortChainCommand{Command: "init"})
	decoded := json.Unmarshal(initial.RootPolicy, &h.rootPolicy) == nil
	valid := decoded && h.rootPolicy.Validate() == nil
	var configRevision int64
	var exactTarget bool
	if len(h.rootPolicy.Targets) == 1 {
		configRevision, exactTarget = h.rootPolicy.Targets[0].ConfigRevision, h.rootPolicy.Targets[0].ServiceID == "control-panel"
	}
	t.Logf("SOFTWARE CP profile: ok=%t phase=%s identity_present=%t policy_decoded=%t policy_valid=%t source=%d projection=%d executor=%d DB_source=%d DB_projection=%d DB_executor=%d targets=%d exact_target=%t C=%d expected_source=%d expected_projection=%d expected_executor=%d", initial.OK, softwareUpdateChainSafeCode(initial.ErrorCode), initial.AgentIdentityYAML != "", decoded, valid, softwareUpdateChainSafeCount(h.rootPolicy.SourcePolicyRevision), softwareUpdateChainSafeCount(h.rootPolicy.ProjectionRevision), softwareUpdateChainSafeCount(h.rootPolicy.PolicyRevision), softwareUpdateChainSafeCount(initial.DBSourcePolicyRevision), softwareUpdateChainSafeCount(initial.DBProjectionRevision), softwareUpdateChainSafeCount(initial.DBExecutorPolicyRevision), softwareUpdateChainSafeCount(int64(len(h.rootPolicy.Targets))), exactTarget, softwareUpdateChainSafeCount(configRevision), h.source, h.projection, h.executor)
	if !initial.OK || initial.AgentIdentityYAML == "" || !decoded || !valid || h.rootPolicy.SourcePolicyRevision != h.source || h.rootPolicy.ProjectionRevision != h.projection || h.rootPolicy.PolicyRevision != h.executor || initial.DBSourcePolicyRevision != h.source || initial.DBProjectionRevision != h.projection || initial.DBExecutorPolicyRevision != h.executor || len(h.rootPolicy.Targets) != 1 || configRevision != 1 || !exactTarget {
		t.Fatal("actual CP fixed profile did not establish independent revisions")
	}
	h.initialPolicy = append([]byte(nil), initial.RootPolicy...)
	if os.WriteFile(localExecutorPortPolicyPath, initial.RootPolicy, 0o600) != nil || os.WriteFile(HostAgentIdentityPath, []byte(initial.AgentIdentityYAML), 0o640) != nil || os.Chown(HostAgentIdentityPath, 0, int(h.gid)) != nil {
		t.Fatal("install isolated protected policy and identity")
	}
	initial.AgentIdentityYAML = ""
	h.artifactDigest = softwareUpdateChainPrepareRelease(t, base, commit)
	h.baselineRelease, err = filepath.EvalSymlinks("/opt/autostream/control-panel/current")
	if err != nil {
		t.Fatal("read baseline release")
	}
	h.installApplication(t)
	h.provider = h.start(t, "release", h.testBinary, "TestSoftwareUpdateFullChainReleaseProcess", 0, 0)
	if !h.provider.call(t, stPortChainCommand{Command: "init"}).OK {
		t.Fatal("verified immutable provider not ready")
	}
	h.root = h.start(t, "root", h.oldBinary, "TestSTPortFullChainRuntimeProcess", 0, 0)
	h.waitRoot(t)
	h.agent = h.start(t, "agent", h.oldBinary, "TestSTPortFullChainRuntimeProcess", h.uid, h.gid)
	baseline := h.agent.call(t, stPortChainCommand{Command: "observe"})
	if !baseline.OK || !baseline.TargetVerified {
		t.Fatal("actual root PID/listener/config observation did not reach CP readiness")
	}
	return h
}

func (h *softwareUpdateChainHarness) installApplication(t *testing.T) {
	t.Helper()
	bytes := systemdPortSidecarBytes("control_panel", "127.0.0.1", 18080, 1)
	if systemdPortSidecarSHA256(bytes) != h.rootPolicy.Targets[0].ConfigSHA256 || os.WriteFile("/opt/autostream/local-executor/ports/control-panel.env", bytes, 0o600) != nil {
		t.Fatal("configure-only CP sidecar does not match actual CP projection")
	}
	if os.MkdirAll("/usr/local/sbin", 0o755) != nil {
		t.Fatal("create isolated fixed backup profile")
	}
	backup := "#!/bin/sh\nset -eu\n[ \"$#\" -eq 1 ]\n[ \"$1\" = autostream_panel ]\nprintf '%s\\n' isolated-backup >> /run/autostream-st-port-full-chain/backup-observations\n"
	if os.WriteFile("/usr/local/sbin/autostream-backup-control-panel", []byte(backup), 0o755) != nil {
		t.Fatal("install synthetic backup command")
	}
	unit := "[Unit]\nDescription=Isolated software-update synthetic target\nStartLimitIntervalSec=0\n[Service]\nType=simple\nUser=autostream\nGroup=autostream\nWorkingDirectory=/opt/autostream/control-panel/current\nEnvironment=AUTOSTREAM_SOFTWARE_UPDATE_FULL_CHAIN=1\nEnvironmentFile=/opt/autostream/local-executor/ports/control-panel.env\nExecStart=/opt/autostream/control-panel/current/bin/control-panel -test.run=^TestSoftwareUpdateFullChainApplicationProcess$ -test.count=1 -test.timeout=32m\nRestart=no\nTimeoutStartSec=15\nTimeoutStopSec=15\n"
	if os.WriteFile("/run/systemd/system/autostream-control-panel.service", []byte(unit), 0o644) != nil {
		t.Fatal("install isolated standard CP unit")
	}
	stPortChainRun(t, "/usr/bin/systemctl", "daemon-reload")
	stPortChainRun(t, "/usr/bin/systemctl", "start", "autostream-control-panel.service")
	stPortChainWait(t, 20*time.Second, func() bool {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:18080", 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}
