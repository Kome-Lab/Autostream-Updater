//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

func TestLinuxSystemdPortRuntimeWritesAndRestoresExactSidecar(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := systemdPortAdapter{
		Unit:         "autostream-worker.service",
		SidecarPath:  filepath.Join(directory, "worker.env"),
		BindVariable: "AUTOSTREAM_BIND_ADDR",
	}
	oldBody := systemdPortSidecarBytes("AUTOSTREAM_BIND_ADDR", "127.0.0.1", 8084, 11)
	newBody := systemdPortSidecarBytes("AUTOSTREAM_BIND_ADDR", "127.0.0.1", 18084, 12)
	if err := os.WriteFile(adapter.SidecarPath, oldBody, 0o600); err != nil {
		t.Fatal(err)
	}
	portRuntime := &linuxSystemdPortRuntime{
		adapter: adapter, requireRootOwned: false,
	}
	checkpoint, err := portRuntime.Checkpoint(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := portRuntime.Write(adapter, checkpoint, newBody); err != nil {
		t.Fatal(err)
	}
	written, err := portRuntime.Checkpoint(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if !written.Existed || written.Mode != 0o600 || string(written.Bytes) != string(newBody) {
		t.Fatalf("written checkpoint=%+v", written)
	}
	if err := portRuntime.Restore(adapter, checkpoint, newBody); err != nil {
		t.Fatal(err)
	}
	restored, err := portRuntime.Checkpoint(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSystemdPortCheckpoint(restored, checkpoint) {
		t.Fatalf("restored=%+v checkpoint=%+v", restored, checkpoint)
	}
}

func TestLinuxSystemdPortRuntimeRefusesConcurrentSidecarDrift(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := systemdPortAdapter{
		Unit:         "autostream-worker.service",
		SidecarPath:  filepath.Join(directory, "worker.env"),
		BindVariable: "AUTOSTREAM_BIND_ADDR",
	}
	oldBody := systemdPortSidecarBytes("AUTOSTREAM_BIND_ADDR", "127.0.0.1", 8084, 11)
	if err := os.WriteFile(adapter.SidecarPath, oldBody, 0o600); err != nil {
		t.Fatal(err)
	}
	portRuntime := &linuxSystemdPortRuntime{
		adapter: adapter, requireRootOwned: false,
	}
	checkpoint, err := portRuntime.Checkpoint(adapter)
	if err != nil {
		t.Fatal(err)
	}
	drift := systemdPortSidecarBytes("AUTOSTREAM_BIND_ADDR", "127.0.0.1", 19000, 99)
	if err := os.WriteFile(adapter.SidecarPath, drift, 0o600); err != nil {
		t.Fatal(err)
	}
	target := systemdPortSidecarBytes("AUTOSTREAM_BIND_ADDR", "127.0.0.1", 18084, 12)
	if err := portRuntime.Write(adapter, checkpoint, target); err == nil {
		t.Fatal("concurrent sidecar drift was overwritten")
	}
	current, err := os.ReadFile(adapter.SidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(drift) {
		t.Fatalf("drift was changed: %q", current)
	}
}

func TestLinuxSystemdPortRuntimeRestoresAbsentSidecar(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	adapter := systemdPortAdapter{
		Unit:         "autostream-worker.service",
		SidecarPath:  filepath.Join(directory, "worker.env"),
		BindVariable: "AUTOSTREAM_BIND_ADDR",
	}
	portRuntime := &linuxSystemdPortRuntime{
		adapter: adapter, requireRootOwned: false,
	}
	checkpoint, err := portRuntime.Checkpoint(adapter)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.Existed {
		t.Fatal("initial sidecar unexpectedly exists")
	}
	target := systemdPortSidecarBytes("AUTOSTREAM_BIND_ADDR", "127.0.0.1", 18084, 12)
	if err := portRuntime.Write(adapter, checkpoint, target); err != nil {
		t.Fatal(err)
	}
	if err := portRuntime.Restore(adapter, checkpoint, target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(adapter.SidecarPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent sidecar was not restored: %v", err)
	}
}

func TestLinuxSystemdPortRuntimeChecksExactLoopbackPortAvailability(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if !validSystemdPort(port) {
		_ = listener.Close()
		t.Skipf("kernel selected a privileged test port %d", port)
	}
	portRuntime := &linuxSystemdPortRuntime{listenHost: "127.0.0.1"}
	endpoint := LocalExecutorEndpoint{Host: "127.0.0.1", Port: port}
	if err := portRuntime.EnsurePortAvailable(endpoint); err == nil {
		_ = listener.Close()
		t.Fatal("occupied port was reported available")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := portRuntime.EnsurePortAvailable(endpoint); err != nil {
		t.Fatalf("released port was not reported available: %v", err)
	}
	if err := portRuntime.EnsurePortAvailable(
		LocalExecutorEndpoint{Host: "::1", Port: port},
	); err == nil {
		t.Fatal("a different loopback host escaped the root policy binding")
	}
}

func TestLinuxSystemdPortRuntimeConsumesExactPortGrantBinding(t *testing.T) {
	plan := validSystemdPortReconfigurePlan(t)
	var gotPanelURL, gotJobID, gotToken string
	var gotBinding MutationGrantBinding
	portRuntime := &linuxSystemdPortRuntime{
		hostID: "host-a", serviceID: "worker-01", serviceType: "worker",
		panelURL: "https://panel.example.com",
		consumeGrant: func(
			_ context.Context,
			panelURL, jobID, token string,
			binding MutationGrantBinding,
			_ *http.Client,
		) error {
			gotPanelURL, gotJobID, gotToken, gotBinding =
				panelURL, jobID, token, binding
			return nil
		},
	}
	if err := portRuntime.ConsumeGrant(
		context.Background(), plan, "port_reconfigure", "v1.2.3",
		NewBoundedSecret("one-time-mutation-grant"),
	); err != nil {
		t.Fatal(err)
	}
	if gotPanelURL != portRuntime.panelURL ||
		gotJobID != plan.JobID ||
		gotToken != "one-time-mutation-grant" {
		t.Fatalf("grant destination mismatch panel=%q job=%q", gotPanelURL, gotJobID)
	}
	expected := MutationGrantBinding{
		LeaseGeneration: plan.LeaseGeneration,
		HostID:          plan.HostID,
		TransportMode:   HostTransportPullV2,
		TargetID:        plan.TargetID,
		ServiceType:     plan.ServiceType,
		TargetVersion:   "v1.2.3",
		DeploymentMode:  ModeSystemd,
		JobOperation:    "port_reconfigure",
		Operation:       "port_reconfigure",
		PlanSHA256:      plan.PortPlanSHA256,
		SessionID:       plan.SessionID,
		OwnershipEpoch:  plan.OwnershipEpoch,
		PolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		PortReconfigure: plan.mutationGrantBinding(),
	}
	if !reflect.DeepEqual(gotBinding, expected) {
		t.Fatalf("grant binding=%+v expected=%+v", gotBinding, expected)
	}
}

func TestLinuxSystemdPortRuntimeConsumesExactV2BindingOnce(t *testing.T) {
	plan := validSystemdPortReconfigurePlan(t)
	fixedNow := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	v2Binding := contracts.UpdaterMutationGrantBinding{
		Lease: contracts.UpdaterLeaseEnvelope{
			ProtocolVersion: 2,
			LeaseID:         "lease-port-one",
			LeaseGeneration: int64(plan.LeaseGeneration),
		},
		Operation: contracts.UpdaterMutationPortReconfigure,
		SessionID: plan.SessionID,
	}
	legacyCalls := 0
	v2Calls := 0
	var gotRequest contracts.UpdaterMutationGrantConsumeRequest
	var gotNow time.Time
	portRuntime := &linuxSystemdPortRuntime{
		hostID: "host-a", serviceID: "worker-01", serviceType: "worker",
		panelURL: "https://panel.example.com",
		consumeGrant: func(context.Context, string, string, string, MutationGrantBinding, *http.Client) error {
			legacyCalls++
			return nil
		},
		consumeV2Grant: func(
			_ context.Context,
			_, _, _ string,
			request contracts.UpdaterMutationGrantConsumeRequest,
			_ *http.Client,
			now time.Time,
		) error {
			v2Calls++
			gotRequest = request
			gotNow = now
			return nil
		},
		v2GrantBinding: &v2Binding,
		now:            func() time.Time { return fixedNow },
	}
	if err := portRuntime.ConsumeGrant(
		context.Background(), plan, "port_reconfigure", "v1.2.3",
		NewBoundedSecret("one-time-v2-mutation-grant"),
	); err != nil {
		t.Fatal(err)
	}
	if legacyCalls != 0 || v2Calls != 1 {
		t.Fatalf("legacy/v2 consume calls=%d/%d", legacyCalls, v2Calls)
	}
	if !reflect.DeepEqual(gotRequest, contracts.UpdaterMutationGrantConsumeRequest{Binding: v2Binding}) || !gotNow.Equal(fixedNow) {
		t.Fatal("root port gate did not consume the exact v2 binding at the injected time")
	}
}

type linuxSystemdPortRunner struct {
	name string
	args []string
	err  error
}

func (r *linuxSystemdPortRunner) Run(
	_ context.Context,
	_ string,
	_ []string,
	name string,
	args ...string,
) (string, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	return "", r.err
}

func TestLinuxSystemdPortRuntimeRestartUsesOnlyFixedSystemctlAndUnit(t *testing.T) {
	target := validLocalExecutorPolicy(t).Targets[0]
	runner := &linuxSystemdPortRunner{}
	portRuntime := &linuxSystemdPortRuntime{
		adapter: systemdPortAdapter{
			Unit:         target.Systemd.Unit,
			SidecarPath:  "/opt/autostream/local-executor/ports/worker.env",
			BindVariable: "AUTOSTREAM_BIND_ADDR",
		},
		serviceID: target.ServiceID, serviceType: target.ServiceType,
		listenHost:    target.LocalListen.Host,
		systemctlPath: "/usr/bin/systemctl", runner: runner,
	}
	if err := portRuntime.Restart(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if runner.name != "/usr/bin/systemctl" ||
		!reflect.DeepEqual(runner.args, []string{"restart", "autostream-worker.service"}) {
		t.Fatalf("command=%q args=%q", runner.name, runner.args)
	}
	runner.err = errors.New("restart failed")
	if err := portRuntime.Restart(context.Background(), target); err == nil {
		t.Fatal("systemctl failure was ignored")
	}
}
