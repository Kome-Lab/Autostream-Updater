//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/example/autostream-contracts/pkg/contracts"
)

// Test-only synthetic application identity is packaged inside a checksummed
// release. The real runuser smoke, systemd PID/executable, HTTP and root stage
// checks inspect this application; it does not impersonate a CP source build.
func init() {
	if len(os.Args) == 2 && os.Args[1] == "--version" && filepath.Base(os.Args[0]) == "control-panel" {
		version, err := softwareUpdateChainApplicationVersion()
		if err != nil {
			os.Exit(2)
		}
		fmt.Println(version)
		os.Exit(0)
	}
}

func softwareUpdateChainApplicationVersion() (string, error) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		// Root deliberately chdirs before runuser drops credentials. A relative
		// read keeps the stage/state ancestors private to root during smoke.
		body, err := os.ReadFile("artifact-manifest.json")
		var identity struct {
			Version string `json:"version"`
		}
		if err != nil || len(body) > 4096 || json.Unmarshal(body, &identity) != nil || (identity.Version != "v2.0.0" && identity.Version != "v2.0.1") {
			return "", fmt.Errorf("bounded smoke identity unavailable")
		}
		return identity.Version, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", err
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(executable)), "artifact-manifest.json"))
	var manifest struct {
		Version string `json:"version"`
	}
	if err != nil || len(body) > 4096 || json.Unmarshal(body, &manifest) != nil || (manifest.Version != "v2.0.0" && manifest.Version != "v2.0.1") {
		return "", fmt.Errorf("bounded synthetic application manifest unavailable")
	}
	return manifest.Version, nil
}

func TestSoftwareUpdateFullChainApplicationProcess(t *testing.T) {
	if filepath.Base(os.Args[0]) != "control-panel" || os.Geteuid() == 0 || os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_FULL_CHAIN") != "1" {
		t.Skip("launched only by the isolated target systemd unit")
	}
	version, err := softwareUpdateChainApplicationVersion()
	if err != nil {
		t.Fatal("read checksummed synthetic target identity")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "service_id": "control-panel", "service_type": "control_panel"})
	})
	mux.HandleFunc("GET /updater/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"version": version, "service_id": "control-panel", "service_type": "control_panel", "config_revision": 1})
	})
	server := &http.Server{Addr: "127.0.0.1:18080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		_ = server.Close()
	case <-done:
		t.Fatal("synthetic target listener stopped before systemd cancellation")
	}
}

type softwareUpdateChainCountingClient struct {
	LocalExecutorClient
	stages, applies, reconciles atomic.Int64
	mu                          sync.Mutex
	fault                       string
	deliveryLosses              atomic.Int64
	blockedReconciles           atomic.Int64
	stageRequiredResponse       atomic.Bool
}

func (c *softwareUpdateChainCountingClient) Stage(ctx context.Context, p MutationPlan, f LocalExecutorMutationFence) (MutationStageResult, error) {
	c.stages.Add(1)
	result, err := c.LocalExecutorClient.Stage(ctx, p, f)
	if err == nil && c.takeFault("stage_after", "") {
		c.deliveryLosses.Add(1)
		return MutationStageResult{}, errors.New("isolated Stage response lost after real root success")
	}
	return result, err
}
func (c *softwareUpdateChainCountingClient) ApplyV2(ctx context.Context, p MutationPlan, f LocalExecutorMutationFence, g V2MutationGrant) (ApplyResult, error) {
	c.applies.Add(1)
	result, err := c.LocalExecutorClient.ApplyV2(ctx, p, f, g)
	if err == nil && c.takeFault("apply_after", "reconcile_blocked") {
		c.deliveryLosses.Add(1)
		return ApplyResult{}, errors.New("isolated Apply response lost after real root success")
	}
	return result, err
}
func (c *softwareUpdateChainCountingClient) ReconcileV2(ctx context.Context, p MutationPlan, f LocalExecutorMutationFence, g V2MutationGrant) (ApplyResult, error) {
	if c.takeFault("reconcile_blocked", "") {
		c.blockedReconciles.Add(1)
		return ApplyResult{}, errors.New("isolated same-process reconcile delivery stopped before root")
	}
	c.reconciles.Add(1)
	result, err := c.LocalExecutorClient.ReconcileV2(ctx, p, f, g)
	var response *LocalExecutorClientError
	if errors.As(err, &response) && response.Code == "stage_required" {
		c.stageRequiredResponse.Store(true)
	}
	return result, err
}
func (c *softwareUpdateChainCountingClient) arm(fault string) error {
	if fault != "stage_after" && fault != "apply_after" {
		return errors.New("unknown bounded software socket fault")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != "" {
		return errors.New("software socket fault already armed")
	}
	c.fault = fault
	return nil
}
func (c *softwareUpdateChainCountingClient) takeFault(expected, next string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != expected {
		return false
	}
	c.fault = next
	return true
}
func (c *softwareUpdateChainCountingClient) snapshot() any {
	return struct {
		Stage                 int64 `json:"stage"`
		Apply                 int64 `json:"apply"`
		Reconcile             int64 `json:"reconcile"`
		DeliveryLosses        int64 `json:"delivery_losses"`
		BlockedReconciles     int64 `json:"blocked_reconciles"`
		StageRequiredResponse bool  `json:"stage_required_response"`
	}{c.stages.Load(), c.applies.Load(), c.reconciles.Load(), c.deliveryLosses.Load(), c.blockedReconciles.Load(), c.stageRequiredResponse.Load()}
}

func softwareUpdateChainProbeExpiredGrant(ctx context.Context, agent *HostPullAgent, panel *V2PanelClient, binding HostAgentBinding, policy HostAgentPolicy) error {
	active, plan := agent.Journal.Active(), agent.Journal.ActivePlan()
	if active == nil || plan == nil || active.ID != plan.JobID {
		return errors.New("expiry proof requires the real retained software plan")
	}
	panel.leaseMu.Lock()
	if panel.lease == nil {
		panel.leaseMu.Unlock()
		return errors.New("expiry proof has no original CP lease")
	}
	lease := panel.lease.lease
	panel.leaseMu.Unlock()
	now := time.Now().UTC()
	expired := lease.LeaseExpiresAt.Add(time.Microsecond)
	if contracts.ValidateUpdaterLease(now, lease) != nil || !expired.After(now) || contracts.ValidateUpdaterLease(expired, lease) == nil {
		return errors.New("original production CP lease did not establish a valid-to-expired boundary")
	}
	previousClock := panel.Now
	panel.Now = func() time.Time { return expired }
	defer func() { panel.Now = previousClock }()
	_, err := agent.invokeExecutionMutation(ctx, panel, binding, policy, *active, *plan, "apply")
	if err == nil {
		return errors.New("expired original CP lease unexpectedly authorized mutation")
	}
	if err.Error() != "v2 updater mutation grant operation is invalid" {
		return errors.New("expiry boundary failed for a reason other than expired grant validation")
	}
	return err
}
