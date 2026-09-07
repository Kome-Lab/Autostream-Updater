//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

const stPortChainRoot = "/run/autostream-st-port-full-chain"
const stPortChainWorkerStateDir = "/var/lib/autostream/worker"

type stPortChainCommand struct {
	Command        string `json:"command"`
	Mode           string `json:"mode,omitempty"`
	LocalPort      int    `json:"local_port,omitempty"`
	PublishedPort  int    `json:"published_port,omitempty"`
	ContainerPort  int    `json:"container_port,omitempty"`
	AdvertisedPort int    `json:"advertised_port,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	JobID          string `json:"job_id,omitempty"`
	Fault          string `json:"fault,omitempty"`
}

type stPortChainResponse struct {
	OK                       bool                                   `json:"ok"`
	ErrorCode                string                                 `json:"error_code,omitempty"`
	FailureStage             string                                 `json:"failure_stage,omitempty"`
	FailureClass             string                                 `json:"failure_class,omitempty"`
	FailureHTTPStatus        int                                    `json:"failure_http_status,omitempty"`
	FirstRootFailure         string                                 `json:"first_root_failure,omitempty"`
	LastRootFailure          string                                 `json:"last_root_failure,omitempty"`
	ActivePlanPresent        bool                                   `json:"active_plan_present,omitempty"`
	PanelFailures            []stPortChainPanelFailure              `json:"panel_failures,omitempty"`
	RootPolicy               json.RawMessage                        `json:"root_policy,omitempty"`
	AgentIdentityYAML        string                                 `json:"agent_identity_yaml,omitempty"`
	WorkerIdentityYAML       string                                 `json:"worker_identity_yaml,omitempty"`
	Job                      json.RawMessage                        `json:"job,omitempty"`
	Snapshot                 *contracts.SystemUpdatePortSnapshotRef `json:"snapshot,omitempty"`
	JobsCount                int                                    `json:"jobs_count,omitempty"`
	Reservations             int                                    `json:"reservations,omitempty"`
	ClaimCount               int                                    `json:"claim_count,omitempty"`
	ConsumeCount             int                                    `json:"consume_count,omitempty"`
	TerminalCount            int                                    `json:"terminal_count,omitempty"`
	DroppedCount             int                                    `json:"dropped_count,omitempty"`
	RootCalls                int                                    `json:"root_calls,omitempty"`
	TargetVerified           bool                                   `json:"target_verified,omitempty"`
	ActiveJobID              string                                 `json:"active_job_id,omitempty"`
	ActiveResult             *contracts.SystemUpdatePortResultV2    `json:"active_result,omitempty"`
	TerminalResult           *contracts.SystemUpdatePortResultV2    `json:"terminal_result,omitempty"`
	TerminalBodySHA256       string                                 `json:"terminal_body_sha256,omitempty"`
	LastTerminalBodySHA256   string                                 `json:"last_terminal_body_sha256,omitempty"`
	SystemUpdates            json.RawMessage                        `json:"system_updates,omitempty"`
	C11Phase                 string                                 `json:"c11_phase,omitempty"`
	C11JobID                 string                                 `json:"c11_job_id,omitempty"`
	C11BodySHA256            string                                 `json:"c11_body_sha256,omitempty"`
	ConsumePhase             string                                 `json:"consume_phase,omitempty"`
	ConsumeJobID             string                                 `json:"consume_job_id,omitempty"`
	DBSourcePolicyRevision   int64                                  `json:"db_source_policy_revision,omitempty"`
	DBProjectionRevision     int64                                  `json:"db_projection_revision,omitempty"`
	DBExecutorPolicyRevision int64                                  `json:"db_executor_policy_revision,omitempty"`
}

type stPortChainJob struct {
	ID               string                                     `json:"id"`
	Status           string                                     `json:"status"`
	PolicyRevision   int64                                      `json:"policy_revision"`
	LeaseGeneration  uint64                                     `json:"lease_generation"`
	RecoveryRequired bool                                       `json:"recovery_required"`
	PortResult       *contracts.SystemUpdatePortResultV2        `json:"port_result"`
	PortReconfigure  *contracts.SystemUpdatePortReconfiguration `json:"port_reconfigure"`
}

type stPortChainProcess struct {
	command     *exec.Cmd
	in          *os.File
	out         *os.File
	encoder     *json.Encoder
	decoder     *json.Decoder
	done        chan error
	mu          sync.Mutex
	diagnostics int
}

func (p *stPortChainProcess) call(t *testing.T, command stPortChainCommand) stPortChainResponse {
	t.Helper()
	response, err := p.exchange(command)
	if err != nil {
		t.Fatal("private process command/observation failed")
	}
	if !response.OK || len(response.PanelFailures) != 0 {
		p.mu.Lock()
		if p.diagnostics < 24 {
			p.diagnostics++
			// Only fixed codes and bounded counts cross into public test output.
			// The response also carries private credentials and hashes: never log it.
			code := "other"
			switch response.ErrorCode {
			case "agent_operation_failed", "agent_operation_recovered", "create_rejected", "baseline_not_ready", "response_lost", "canonical_get_failed", "canonical_get_invalid", "invalid_create_intent", "create_response_invalid", "snapshot_unavailable":
				code = response.ErrorCode
			}
			stage := "none"
			switch response.FailureStage {
			case "register", "policy", "recovery_policy", "heartbeat", "execute", "flush":
				stage = response.FailureStage
			}
			status := response.FailureHTTPStatus
			if status < 100 || status > 599 {
				status = 0
			}
			calls := response.RootCalls
			if calls < 0 || calls > 1000000 {
				calls = -1
			}
			t.Logf("ST-PORT process failure: code=%s stage=%s class=%s http_status=%d root_calls=%d first_root=%s last_root=%s active_job=%t active_plan=%t active_result=%t", code, stage, stPortChainSafeFailureClass(response.FailureClass), status, calls, stPortChainSafeFailureClass(response.FirstRootFailure), stPortChainSafeFailureClass(response.LastRootFailure), response.ActiveJobID != "", response.ActivePlanPresent, response.ActiveResult != nil)
			for i, failure := range response.PanelFailures {
				if i >= stPortChainPanelFailureLimit {
					break
				}
				failure = stPortChainSafePanelFailure(failure)
				origin := "subsequent_observed"
				if i == 0 {
					origin = "first_observed"
				}
				t.Logf("ST-PORT operation failure: origin=%s operation=%s route=%s step=%s class=%s http_status=%d code=%s root_calls=%d", origin, failure.Operation, failure.Route, failure.Step, failure.Class, failure.HTTPStatus, failure.Code, failure.RootCalls)
			}
		}
		p.mu.Unlock()
	}
	return response
}

func (p *stPortChainProcess) exchange(command stPortChainCommand) (stPortChainResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	deadline := time.Now().Add(8 * time.Minute)
	if err := p.in.SetWriteDeadline(deadline); err != nil {
		return stPortChainResponse{}, err
	}
	if err := p.out.SetReadDeadline(deadline); err != nil {
		return stPortChainResponse{}, err
	}
	if err := p.encoder.Encode(command); err != nil {
		return stPortChainResponse{}, err
	}
	var response stPortChainResponse
	if err := p.decoder.Decode(&response); err != nil {
		return stPortChainResponse{}, err
	}
	return response, nil
}

func (p *stPortChainProcess) stop() {
	if p == nil || p.command == nil || p.command.Process == nil {
		return
	}
	_ = p.command.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		_ = p.command.Process.Kill()
		<-p.done
	}
	if p.in != nil {
		_ = p.in.Close()
	}
	if p.out != nil {
		_ = p.out.Close()
	}
	p.command = nil
}

type stPortChainHarness struct {
	ctx           context.Context
	cancel        context.CancelFunc
	cp            *stPortChainProcess
	agent         *stPortChainProcess
	root          *stPortChainProcess
	uid, gid      uint32
	configPath    string
	testBinary    string
	cpBinary      string
	evidence      string
	workerVersion string
	rootPolicy    LocalExecutorPolicy
	processSerial int
	webCases      []stPortChainWebCase
	runtimeMode   string
}

type stPortChainRuntimeAdapter struct {
	Mode             string
	InitialLocalPort int
	Prepare          func(*testing.T, *stPortChainHarness) map[string]any
	Install          func(*testing.T, *stPortChainHarness)
	Cleanup          func(*testing.T, *stPortChainHarness)
}

func newSTPortChainHarness(t *testing.T) *stPortChainHarness {
	t.Helper()
	return newSTPortChainHarnessWithRuntime(t, stPortChainRuntimeAdapter{
		Mode: "systemd", InitialLocalPort: 18084,
		Install: func(t *testing.T, h *stPortChainHarness) { h.installWorker(t) },
		Cleanup: func(_ *testing.T, _ *stPortChainHarness) {
			_ = exec.Command("/usr/bin/systemctl", "stop", "autostream-worker.service").Run()
		},
	})
}

func newSTPortChainHarnessWithRuntime(t *testing.T, adapter stPortChainRuntimeAdapter) *stPortChainHarness {
	t.Helper()
	if os.Getenv("AUTOSTREAM_ST_PORT_FULL_CHAIN") != "1" {
		t.Skip("isolated ST-PORT real-process integration is not selected")
	}
	marker, err := os.ReadFile(filepath.Join(stPortChainRoot, "isolated"))
	container, containerErr := os.ReadFile("/run/systemd/container")
	if os.Geteuid() != 0 || err != nil || string(marker) != "ST-PORT disposable integration namespace v1\n" || containerErr != nil || strings.TrimSpace(string(container)) == "" {
		t.Fatal("real-process integration requires its disposable systemd container")
	}
	for _, path := range []string{HostAgentIdentityPath, localExecutorPortPolicyPath, LocalExecutorMutationStateDir, HostPullAgentStateDir, "/opt/autostream/worker/current", stPortChainWorkerStateDir} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("integration refuses a pre-existing runtime installation")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	h := &stPortChainHarness{ctx: ctx, cancel: cancel, uid: 16531, gid: 16531, cpBinary: os.Getenv("AUTOSTREAM_ST_PORT_CP_TEST_BINARY"), evidence: os.Getenv("AUTOSTREAM_ST_PORT_EVIDENCE"), workerVersion: os.Getenv("AUTOSTREAM_ST_PORT_WORKER_VERSION"), runtimeMode: adapter.Mode}
	if h.cpBinary == "" || h.evidence == "" || !versionPattern.MatchString(h.workerVersion) || adapter.Mode != "systemd" && adapter.Mode != "docker" || adapter.InitialLocalPort < 1 || adapter.InitialLocalPort > 65535 || adapter.Install == nil {
		t.Fatal("immutable integration inputs are incomplete")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal("locate integration binary")
	}
	h.testBinary = "/opt/autostream/st-port-test/hostruntime.test"
	for _, directory := range []string{"/opt/autostream/st-port-test", "/etc/autostream/updater", "/etc/autostream/worker", "/opt/autostream/local-executor/ports", "/var/lib/autostream", h.evidence, filepath.Join(h.evidence, "processes"), filepath.Join(h.evidence, "artifacts")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal("prepare isolated fixture directories")
		}
	}
	// Match the canonical Worker's installer-owned parent and service state path.
	if err := os.Chmod("/var/lib/autostream", 0o755); err != nil {
		t.Fatal("prepare canonical Worker state parent")
	}
	stPortChainCopy(t, self, h.testBinary, 0o755)
	for _, directory := range []string{HostPullAgentStateDir, stPortChainWorkerStateDir} {
		owner := int(h.uid)
		mode := os.FileMode(0o700)
		if directory == stPortChainWorkerStateDir {
			owner = 16532
			mode = 0o750
		}
		if err := os.MkdirAll(directory, mode); err != nil || os.Chown(directory, owner, owner) != nil || os.Chmod(directory, mode) != nil {
			t.Fatal("prepare non-root fixture state")
		}
	}
	stPortChainRun(t, "/usr/sbin/groupadd", "--gid", strconv.Itoa(int(h.gid)), "autostream-st-port-agent")
	stPortChainRun(t, "/usr/sbin/useradd", "--uid", strconv.Itoa(int(h.uid)), "--gid", strconv.Itoa(int(h.gid)), "--no-create-home", "--shell", "/usr/sbin/nologin", "autostream-st-port-agent")
	stPortChainRun(t, "/usr/sbin/groupadd", "--gid", "16532", "autostream")
	stPortChainRun(t, "/usr/sbin/useradd", "--uid", "16532", "--gid", "16532", "--no-create-home", "--shell", "/usr/sbin/nologin", "autostream")
	stPortChainWriteCA(t)
	privateCPDir := filepath.Join(stPortChainRoot, "cp-private")
	if err := os.Mkdir(privateCPDir, 0o700); err != nil {
		t.Fatal("prepare private CP bootstrap state")
	}
	h.configPath = filepath.Join(stPortChainRoot, "cp-config.json")
	config := map[string]any{"dsn_file": os.Getenv("AUTOSTREAM_ST_PORT_DSN_FILE"), "panel_url": "https://localhost:18443", "listen_addr": "127.0.0.1:18443", "tls_cert": filepath.Join(stPortChainRoot, "tls.crt"), "tls_key": filepath.Join(stPortChainRoot, "tls.key"), "agent_uid": h.uid, "agent_gid": h.gid, "worker_version": h.workerVersion, "mode": adapter.Mode, "fixture_dir": privateCPDir}
	if adapter.Prepare != nil {
		for key, value := range adapter.Prepare(t, h) {
			if _, exists := config[key]; exists || key != "docker" {
				t.Fatal("runtime fixture attempted to replace fixed CP authority")
			}
			config[key] = value
		}
	}
	configBytes, err := json.Marshal(config)
	if err != nil || os.WriteFile(h.configPath, configBytes, 0o600) != nil {
		t.Fatal("write private CP fixture configuration")
	}
	t.Cleanup(func() {
		h.agent.stop()
		h.root.stop()
		h.cp.stop()
		h.cancel()
		if adapter.Cleanup != nil {
			adapter.Cleanup(t, h)
		}
	})
	h.cp = h.start(t, "cp", h.cpBinary, "TestSTPortFullChainControlPanelProcess", 0, 0)
	initial := h.cp.call(t, stPortChainCommand{Command: "init"})
	if !initial.OK || len(initial.RootPolicy) == 0 || initial.AgentIdentityYAML == "" || initial.WorkerIdentityYAML == "" {
		t.Fatalf("real CP initial authority is unavailable: %s", initial.ErrorCode)
	}
	if json.Unmarshal(initial.RootPolicy, &h.rootPolicy) != nil || h.rootPolicy.Validate() != nil || h.rootPolicy.AgentUID != h.uid || h.rootPolicy.AgentGID != h.gid {
		t.Fatal("CP fixed profile does not match the runtime fixture")
	}
	if err := os.WriteFile(localExecutorPortPolicyPath, initial.RootPolicy, 0o600); err != nil {
		t.Fatal("install CP-owned initial policy")
	}
	for path, body := range map[string]string{HostAgentIdentityPath: initial.AgentIdentityYAML, "/etc/autostream/worker/node.yaml": initial.WorkerIdentityYAML} {
		group := int(h.gid)
		if path != HostAgentIdentityPath {
			group = 16532
		}
		if os.WriteFile(path, []byte(body), 0o640) != nil || os.Chown(path, 0, group) != nil {
			t.Fatal("install protected fixture identity")
		}
	}
	// Credentials only cross private pipes and these canonical protected files.
	initial.AgentIdentityYAML, initial.WorkerIdentityYAML = "", ""
	adapter.Install(t, h)
	h.root = h.start(t, "root", h.testBinary, "TestSTPortFullChainRuntimeProcess", 0, 0)
	h.waitRoot(t)
	h.agent = h.start(t, "agent", h.testBinary, "TestSTPortFullChainRuntimeProcess", h.uid, h.gid)
	if response := h.agent.call(t, stPortChainCommand{Command: "observe"}); !response.OK || !response.TargetVerified {
		t.Fatal("real Agent registration/probe/heartbeat baseline failed")
	}
	baseline := h.cp.call(t, stPortChainCommand{Command: "observe"})
	if !baseline.OK || baseline.Snapshot == nil || baseline.Snapshot.LocalListenPort != adapter.InitialLocalPort || baseline.Snapshot.AdvertisedPort != 443 {
		t.Fatal("CP did not bind the actual root baseline")
	}
	return h
}

func (h *stPortChainHarness) start(t *testing.T, role, binary, test string, uid, gid uint32) *stPortChainProcess {
	t.Helper()
	readCommand, writeCommand, err := os.Pipe()
	if err != nil {
		t.Fatal("create private control pipe")
	}
	readResponse, writeResponse, err := os.Pipe()
	if err != nil {
		t.Fatal("create private observation pipe")
	}
	command := exec.CommandContext(h.ctx, binary, "-test.run=^"+test+"$", "-test.count=1", "-test.timeout=34m")
	command.Env = append(os.Environ(), "AUTOSTREAM_ST_PORT_CHAIN_CHILD="+role, "AUTOSTREAM_ST_PORT_CHAIN_CONFIG="+h.configPath, "SSL_CERT_FILE="+filepath.Join(stPortChainRoot, "tls.crt"))
	command.ExtraFiles = []*os.File{readCommand, writeResponse}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}, Setpgid: true}
	h.processSerial++
	log, err := os.OpenFile(filepath.Join(h.evidence, "processes", fmt.Sprintf("process-%s-%02d-%s.log", h.runtimeMode, h.processSerial, role)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("open bounded process evidence")
	}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal("start real process fixture")
	}
	_ = readCommand.Close()
	_ = writeResponse.Close()
	p := &stPortChainProcess{command: command, in: writeCommand, out: readResponse, encoder: json.NewEncoder(writeCommand), decoder: json.NewDecoder(io.LimitReader(readResponse, 16<<20)), done: make(chan error, 1)}
	go func() { p.done <- command.Wait(); _ = log.Close() }()
	return p
}

func (h *stPortChainHarness) installWorker(t *testing.T) {
	t.Helper()
	listenerReady := false
	defer func() {
		if !listenerReady {
			h.diagnoseWorkerStartup(t)
		}
	}()
	target, ok := h.rootPolicy.Target("worker-smoke")
	if !ok || target.Systemd == nil || target.LocalListen.Port != 18084 {
		t.Fatal("canonical Worker profile unavailable")
	}
	release := filepath.Join(target.Systemd.ReleaseRoot, "st-port-chain-"+h.workerVersion)
	if os.MkdirAll(filepath.Join(release, "bin"), 0o755) != nil {
		t.Fatal("prepare canonical Worker release")
	}
	worker := filepath.Join(release, target.Systemd.BinaryPath)
	stPortChainCopy(t, os.Getenv("AUTOSTREAM_ST_PORT_WORKER_BINARY"), worker, 0o755)
	digest, err := hashFile(worker)
	if err != nil {
		t.Fatal("verify immutable Worker input")
	}
	for name, body := range map[string]string{".version": h.workerVersion + "\n", ".artifact-sha256": digest + "\n", "checksums.txt": digest + "  " + target.Systemd.BinaryPath + "\n"} {
		if os.WriteFile(filepath.Join(release, name), []byte(body), 0o644) != nil {
			t.Fatal("write fixture release markers")
		}
	}
	if os.Symlink(release, target.Systemd.CurrentLink) != nil || verifyManagedReleaseChecksums(release) != nil {
		t.Fatal("install canonical Worker release")
	}
	body := systemdPortSidecarBytes("worker", "127.0.0.1", 18084, target.ConfigRevision)
	if systemdPortSidecarSHA256(body) != target.ConfigSHA256 || os.WriteFile("/opt/autostream/local-executor/ports/worker.json", body, 0o600) != nil {
		t.Fatal("initial CP listener bytes differ from the runtime")
	}
	gate := fmt.Sprintf(`#!/usr/bin/python3
import json, os, stat, sys
names = ('actor_match node_env_match node_ancestors_traversable node_file_safe node_read_ok node_required_fields node_type_match node_listener_match credential_env_valid credential_ancestors_traversable credential_file_safe credential_read_ok credential_json_v2_match credential_service_match credential_revision_match credential_bind_match').split()
observed = dict.fromkeys(names, False)
def traversable(path):
    parents = []
    while path != '/':
        path = os.path.dirname(path)
        parents.append(path)
        if len(parents) > 16: return False
    return all(os.access(parent, os.X_OK) for parent in parents)
try:
    observed['actor_match'] = os.getuid() == 16532 and os.getgid() == 16532
    path = '/etc/autostream/worker/node.yaml'
    observed['node_env_match'] = os.environ.get('AUTOSTREAM_NODE_CONFIG') == path
    observed['node_ancestors_traversable'] = traversable(path)
    info = os.lstat(path)
    observed['node_file_safe'] = stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 16532 and stat.S_IMODE(info.st_mode) == 0o640
    with open(path) as f: body = f.read(65537)
    observed['node_read_ok'] = len(body) <= 65536
    fields, section = {}, ''
    for raw in body.splitlines() if observed['node_read_ok'] else []:
        line = raw.strip()
        if not line or line.startswith('#'): continue
        if not raw.startswith(' ') and line.endswith(':'):
            section = line[:-1]
            continue
        key, sep, value = line.partition(':')
        if not sep: continue
        value = value.strip()
        if value.startswith('"'):
            try: value = json.loads(value)
            except ValueError: value = value.strip('\'"')
        else: value = value.strip('\'"')
        fields[section + '.' + key.strip()] = value
    observed['node_required_fields'] = all(fields.get(key) for key in ('panel.url', 'node.id', 'node.name', 'api.host', 'api.port', 'auth.token')) and int(fields.get('api.port', '0')) > 0
    observed['node_type_match'] = fields.get('node.type') == 'worker'
    observed['node_listener_match'] = fields.get('listener.credential') == 'node-listener.json'
except Exception:
    pass
try:
    directory = os.environ.get('CREDENTIALS_DIRECTORY', '')
    observed['credential_env_valid'] = os.path.isabs(directory) and os.path.normpath(directory) == directory and len(directory) <= 1024
    if observed['credential_env_valid']:
        path = os.path.join(directory, 'node-listener.json')
        observed['credential_ancestors_traversable'] = traversable(path)
        info = os.lstat(path)
        observed['credential_file_safe'] = stat.S_ISREG(info.st_mode) and not (stat.S_IMODE(info.st_mode) & 0o022) and 0 < info.st_size <= 4096
        with open(path) as f: body = f.read(4097)
        observed['credential_read_ok'] = 0 < len(body) <= 4096
        if observed['credential_read_ok']:
            pairs = json.loads(body, object_pairs_hook=list)
            listener = dict(pairs)
            observed['credential_json_v2_match'] = len(pairs) == len(listener) == 4 and set(listener) == {'schema_version', 'service_type', 'bind_address', 'config_revision'} and listener['schema_version'] == 2
            observed['credential_service_match'] = listener.get('service_type') == 'worker'
            observed['credential_revision_match'] = listener.get('config_revision') == %d
            observed['credential_bind_match'] = listener.get('bind_address') == '127.0.0.1:18084'
except Exception:
    pass
for name in names:
    print('st-port-worker-config: ' + name + '=' + ('true' if observed[name] else 'false'), flush=True)
# Preserve the existing runtime fault gate and its exit behavior.
p='/run/autostream-st-port-full-chain/runtime-fault.json'
if not os.path.exists(p): sys.exit(0)
with open(p) as f: fault=json.load(f)
with open(os.path.join(os.environ['CREDENTIALS_DIRECTORY'],'node-listener.json')) as f: listener=json.load(f)
c=listener['config_revision']
sys.exit(1 if (c >= fault['revision'] if fault['mode']=='at_or_after' else c==fault['revision']) else 0)
`, target.ConfigRevision)
	if os.WriteFile("/opt/autostream/st-port-test/worker-start-gate", []byte(gate), 0o755) != nil {
		t.Fatal("write isolated runtime fault gate")
	}
	unit := "[Unit]\nDescription=ST-PORT canonical Worker integration fixture\nStartLimitIntervalSec=0\n[Service]\nType=simple\nUser=autostream\nGroup=autostream\nWorkingDirectory=" + stPortChainWorkerStateDir + "\nEnvironment=AUTOSTREAM_NODE_CONFIG=/etc/autostream/worker/node.yaml\nEnvironment=SSL_CERT_FILE=/run/autostream-st-port-full-chain/tls.crt\nLoadCredential=node-listener.json:/opt/autostream/local-executor/ports/worker.json\nExecStartPre=/opt/autostream/st-port-test/worker-start-gate\nExecStart=" + target.Systemd.CurrentLink + "/" + target.Systemd.BinaryPath + "\nRestart=no\nTimeoutStartSec=15\nTimeoutStopSec=15\n"
	if os.WriteFile("/run/systemd/system/autostream-worker.service", []byte(unit), 0o644) != nil {
		t.Fatal("write isolated canonical Worker unit")
	}
	stPortChainRun(t, "/usr/bin/systemctl", "daemon-reload")
	stPortChainRun(t, "/usr/bin/systemctl", "start", "autostream-worker.service")
	stPortChainWait(t, 30*time.Second, func() bool {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:18084", 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
	listenerReady = true
}

func (h *stPortChainHarness) diagnoseWorkerStartup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 3*time.Second)
	defer cancel()
	runner := OSCommandRunner{NewProcessGroup: true}
	state, err := runner.Run(ctx, "", nil, "/usr/bin/systemctl", "show", "autostream-worker.service",
		"--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID")
	t.Logf("ST-PORT Worker listener readiness: unit_observation_available=%t", err == nil)
	if err == nil {
		for _, line := range strings.Split(state, "\n") {
			key, value, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			switch key {
			case "ExecMainCode", "ExecMainStatus", "MainPID":
				if number, parseErr := strconv.ParseUint(value, 10, 32); parseErr == nil {
					t.Logf("ST-PORT Worker unit: %s=%d", key, number)
				}
			case "ActiveState", "SubState", "Result":
				switch value {
				case "active", "inactive", "failed", "activating", "deactivating", "running", "dead", "exited", "start-pre", "start", "success", "exit-code", "signal", "timeout", "resources", "start-limit-hit", "oom-kill":
					t.Logf("ST-PORT Worker unit: %s=%s", key, value)
				default:
					t.Logf("ST-PORT Worker unit: %s=other", key)
				}
			}
		}
	}
	// Read only this fixture's bounded startup tail in memory. Publish fixed
	// classes, never a journal line, credential, environment or command argv.
	journal, journalErr := runner.Run(ctx, "", nil, "/usr/bin/journalctl", "--unit=autostream-worker.service", "--no-pager", "--lines=32", "--output=cat")
	t.Logf("ST-PORT Worker startup: journal_observation_available=%t", journalErr == nil)
	if journalErr == nil {
		for _, key := range strings.Fields("actor_match node_env_match node_ancestors_traversable node_file_safe node_read_ok node_required_fields node_type_match node_listener_match credential_env_valid credential_ancestors_traversable credential_file_safe credential_read_ok credential_json_v2_match credential_service_match credential_revision_match credential_bind_match") {
			for _, value := range []string{"true", "false"} {
				if strings.Contains(journal, "st-port-worker-config: "+key+"="+value) {
					t.Logf("ST-PORT Worker initial configuration: %s=%s", key, value)
				}
			}
		}
		for _, class := range []struct{ text, name string }{
			{"invalid node listener credential bind_address:", "listener_config_invalid"},
			{"invalid updater identity:", "updater_identity_invalid"},
			{"load stopped target receipts:", "receipt_state_unavailable"},
			{"initialize worker scene renderer:", "scene_renderer_unavailable"},
			{"control panel registration is required in this environment:", "registration_failed"},
			{"control panel runtime config is required in this environment", "runtime_config_unavailable"},
			{"node config invalid:", "node_config_invalid"},
			{"panel-managed node config is required in this environment", "node_config_missing"},
			{"error while loading shared libraries:", "shared_library_missing"},
			{"Permission denied", "permission_denied"},
			{"permission denied", "permission_denied"},
			{"autostream-worker listening on", "listener_started"},
		} {
			if strings.Contains(journal, class.text) {
				t.Logf("ST-PORT Worker startup: class=%s", class.name)
			}
		}
	}
}

func stPortChainRun(t *testing.T, command string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, command, args...).Run(); err != nil {
		t.Fatal("isolated runtime command failed")
	}
}

func (h *stPortChainHarness) waitRoot(t *testing.T) {
	t.Helper()
	stPortChainWait(t, 20*time.Second, func() bool {
		conn, err := net.DialTimeout("unix", LocalExecutorSocketPath, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	})
}

func stPortChainFileInfo(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("required runtime file observation is unavailable")
	}
	return info
}

func stPortChainWait(t *testing.T, duration time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("bounded integration state observation timed out")
}

func stPortChainCopy(t *testing.T, source, target string, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("immutable binary input is unavailable")
	}
	in, err := os.Open(source)
	if err != nil {
		t.Fatal("open immutable input")
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal("create isolated runtime input")
	}
	if _, err := io.Copy(out, in); err != nil || out.Sync() != nil || out.Close() != nil {
		t.Fatal("persist isolated runtime input")
	}
}

func stPortChainWriteCA(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate isolated TLS trust")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal("generate isolated TLS identity")
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ST-PORT isolated CP"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("issue isolated TLS certificate")
	}
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal("encode isolated TLS private key")
	}
	if os.WriteFile(filepath.Join(stPortChainRoot, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0o644) != nil || os.WriteFile(filepath.Join(stPortChainRoot, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0o600) != nil {
		t.Fatal("persist isolated TLS trust")
	}
}

func stPortChainDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func stPortChainSameResult(left, right *contracts.SystemUpdatePortResultV2) bool {
	return left != nil && right != nil && contracts.EqualSystemUpdatePortResults(*left, *right)
}

func stPortChainSameBytes(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("accepted operation unexpectedly changed runtime bytes")
	}
}
