package hostruntime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSystemdAppliedStateAllowsOnlyExactRootPolicyLineageMigration(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 10
	policy.ProjectionRevision = 11
	policy.PolicyRevision = 12
	policy.Targets[0].EndpointRevision = 5
	adapter, err := systemdPortAdapterFor(
		policy.Targets[0].ServiceType,
		policy.Targets[0].Systemd.Unit,
	)
	if err != nil {
		t.Fatal(err)
	}
	policy.Targets[0].ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.ServiceType,
		policy.Targets[0].LocalListen.Host,
		policy.Targets[0].LocalListen.Port,
		policy.Targets[0].ConfigRevision,
	))
	applied := systemdPortAppliedState{
		SchemaVersion:    systemdPortPlanSchemaVersion,
		TargetID:         policy.Targets[0].ServiceID,
		ServiceType:      policy.Targets[0].ServiceType,
		Port:             policy.Targets[0].LocalListen.Port,
		EndpointRevision: policy.Targets[0].EndpointRevision,
		ConfigRevision:   policy.Targets[0].ConfigRevision,
		ConfigSHA256:     policy.Targets[0].ConfigSHA256,
		// Deliberately stale lineage from the policy that performed the port
		// transaction. The newly installed policy already contains the exact
		// endpoint, so the overlay is redundant rather than authoritative.
		SourcePolicyRevision:   6,
		UpdaterPolicyRevision:  7,
		ExecutorPolicyRevision: 8,
		ExecutorPolicySHA256:   "sha256:" + strings.Repeat("e", 64),
		OwnershipEpoch:         3,
	}
	state := newMemorySystemdPortStateStore()
	if err := state.SaveApplied(applied); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveSystemdPortAppliedTarget(
		policy, policy.Targets[0], state,
	)
	if err != nil || resolved != policy.Targets[0] {
		t.Fatalf("exact lineage migration resolved=%+v err=%v", resolved, err)
	}

	applied.Port++
	applied.ConfigSHA256 = systemdPortSidecarSHA256(systemdPortSidecarBytes(
		adapter.ServiceType,
		policy.Targets[0].LocalListen.Host,
		applied.Port,
		applied.ConfigRevision,
	))
	if err := state.SaveApplied(applied); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSystemdPortAppliedTarget(
		policy, policy.Targets[0], state,
	); err == nil {
		t.Fatal("stale lineage with a different endpoint was accepted")
	}
}

func TestFileSystemdAppliedStateVerifierRejectsModeAndSymlinkDrift(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	policy.SourcePolicyRevision = 6
	policy.ProjectionRevision = 7
	policy.PolicyRevision = 8
	policy.Targets[0].EndpointRevision = 4
	adapter, err := systemdPortAdapterFor(
		policy.Targets[0].ServiceType,
		policy.Targets[0].Systemd.Unit,
	)
	if err != nil {
		t.Fatal(err)
	}
	body := systemdPortSidecarBytes(
		adapter.ServiceType,
		policy.Targets[0].LocalListen.Host,
		policy.Targets[0].LocalListen.Port,
		policy.Targets[0].ConfigRevision,
	)
	policy.Targets[0].ConfigSHA256 = systemdPortSidecarSHA256(body)
	policySHA, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	applied := systemdPortAppliedState{
		SchemaVersion:          systemdPortPlanSchemaVersion,
		TargetID:               policy.Targets[0].ServiceID,
		ServiceType:            policy.Targets[0].ServiceType,
		Port:                   policy.Targets[0].LocalListen.Port,
		EndpointRevision:       policy.Targets[0].EndpointRevision,
		ConfigRevision:         policy.Targets[0].ConfigRevision,
		ConfigSHA256:           policy.Targets[0].ConfigSHA256,
		SourcePolicyRevision:   policy.SourcePolicyRevision,
		UpdaterPolicyRevision:  policy.ProjectionRevision,
		ExecutorPolicyRevision: policy.PolicyRevision,
		ExecutorPolicySHA256:   policySHA,
		OwnershipEpoch:         3,
	}
	state, err := newFileSystemdPortStateStore(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	sidecarDir := filepath.Join(t.TempDir(), "ports")
	if err := os.Mkdir(sidecarDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sidecarPath := filepath.Join(sidecarDir, "worker.json")
	writeTestFile(t, sidecarPath, string(body), 0o600)
	state.sidecarPathForTestOnly = sidecarPath
	if err := state.VerifyAppliedSidecar(policy.Targets[0], applied); err != nil {
		t.Fatalf("canonical sidecar: %v", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(sidecarPath, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := state.VerifyAppliedSidecar(policy.Targets[0], applied); err == nil {
			t.Fatal("group-readable sidecar was accepted")
		}
		if err := os.Chmod(sidecarPath, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linkTarget := filepath.Join(sidecarDir, "target.json")
	writeTestFile(t, linkTarget, string(body), 0o600)
	if err := os.Remove(sidecarPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, sidecarPath); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := state.VerifyAppliedSidecar(policy.Targets[0], applied); err == nil {
		t.Fatal("sidecar symlink was accepted")
	}
}

func TestFileSystemdStateStoreRejectsDirectoryLinkWithoutChangingTarget(t *testing.T) {
	parent := t.TempDir()
	victim := filepath.Join(parent, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(parent, "state")
	if err := os.Symlink(victim, stateDir); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	before, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newFileSystemdPortStateStore(stateDir, false); err == nil {
		t.Fatal("linked state directory was accepted")
	}
	after, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf(
			"linked target mode changed from %o to %o",
			before.Mode().Perm(), after.Mode().Perm(),
		)
	}
}

func TestFileSystemdStateStoreRejectsNestedDirectoryLinkWithoutChangingTarget(t *testing.T) {
	parent := t.TempDir()
	victim := filepath.Join(parent, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(parent, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(stateDir, "port-ledger")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	before, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newFileSystemdPortStateStore(stateDir, false); err == nil {
		t.Fatal("linked nested state directory was accepted")
	}
	after, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf(
			"nested linked target mode changed from %o to %o",
			before.Mode().Perm(), after.Mode().Perm(),
		)
	}
}

func TestLocalExecutorProbeRejectsFakeHealthAndWrongCgroup(t *testing.T) {
	basePolicy := validLocalExecutorPolicy(t)
	baseTarget := basePolicy.Targets[0]

	t.Run("fake health identity", func(t *testing.T) {
		server := newLocalExecutorProbeServer(t, baseTarget, "v1.2.3", baseTarget.ConfigRevision)
		defer server.Close()
		policy := cloneLocalExecutorPolicy(t, basePolicy)
		policy.Targets[0].LocalListen = endpointFromServer(t, server)
		observation := validLocalProcessObservation(policy.Targets[0], "v1.2.3")
		observation.ServiceID = "attacker"
		response := handleLocalExecutorRequest(context.Background(), policy,
			LocalExecutorRequest{Version: 1, Operation: "probe", ServiceID: baseTarget.ServiceID},
			&fakeLocalTargetVerifier{observations: []LocalProcessObservation{observation}},
			server.Client(),
		)
		if response.Error == nil || response.Error.Code != "target_unavailable" {
			t.Fatalf("response=%+v", response)
		}
	})

	t.Run("wrong listener cgroup", func(t *testing.T) {
		server := newLocalExecutorProbeServer(t, baseTarget, "v1.2.3", baseTarget.ConfigRevision)
		defer server.Close()
		policy := cloneLocalExecutorPolicy(t, basePolicy)
		policy.Targets[0].LocalListen = endpointFromServer(t, server)
		observation := validLocalProcessObservation(policy.Targets[0], "v1.2.3")
		observation.ListenerControlGroup = "/system.slice/attacker.service"
		response := handleLocalExecutorRequest(context.Background(), policy,
			LocalExecutorRequest{Version: 1, Operation: "probe", ServiceID: baseTarget.ServiceID},
			&fakeLocalTargetVerifier{observations: []LocalProcessObservation{observation}},
			server.Client(),
		)
		if response.Error == nil || response.Error.Code != "target_unavailable" {
			t.Fatalf("response=%+v", response)
		}
	})

	t.Run("revision mismatch", func(t *testing.T) {
		server := newLocalExecutorProbeServer(t, baseTarget, "v1.2.3", baseTarget.ConfigRevision+1)
		defer server.Close()
		policy := cloneLocalExecutorPolicy(t, basePolicy)
		policy.Targets[0].LocalListen = endpointFromServer(t, server)
		response := handleLocalExecutorRequest(context.Background(), policy,
			LocalExecutorRequest{Version: 1, Operation: "probe", ServiceID: baseTarget.ServiceID},
			&fakeLocalTargetVerifier{observations: []LocalProcessObservation{
				validLocalProcessObservation(policy.Targets[0], "v1.2.3"),
			}},
			server.Client(),
		)
		if response.Error == nil || response.Error.Code != "target_unavailable" {
			t.Fatalf("response=%+v", response)
		}
	})
}

func TestLocalExecutorHTTPProbeBypassesConfiguredProxy(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	target := policy.Targets[0]
	targetServer := newLocalExecutorProbeServer(t, target, "v1.2.3", target.ConfigRevision)
	defer targetServer.Close()
	target.LocalListen = endpointFromServer(t, targetServer)

	var proxyCalls int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","version":"v1.2.3","service_id":"worker-01","service_type":"worker","config_revision":11}`)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	poisoned := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	if err := verifyLocalExecutorHTTP(context.Background(), target, "v1.2.3", poisoned); err != nil {
		t.Fatalf("direct local probe failed: %v", err)
	}
	if proxyCalls != 0 {
		t.Fatalf("local probe used configured proxy %d times", proxyCalls)
	}
}

func TestLocalExecutorProbeRejectsMutationWithoutTouchingRuntime(t *testing.T) {
	policy := validLocalExecutorPolicy(t)
	verifier := &fakeLocalTargetVerifier{}
	response := handleLocalExecutorRequest(context.Background(), policy,
		LocalExecutorRequest{Version: 1, Operation: "apply", ServiceID: policy.Targets[0].ServiceID},
		verifier,
		http.DefaultClient,
	)
	if response.Error == nil || response.Error.Code != "invalid_request" || verifier.calls != 0 {
		t.Fatalf("response=%+v calls=%d", response, verifier.calls)
	}
}
