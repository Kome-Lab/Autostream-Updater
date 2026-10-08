//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

func TestSoftwareUpdateFullChainRecoveryProcess(t *testing.T) {
	if os.Getenv("AUTOSTREAM_ST_PORT_CHAIN_CHILD") != "recovery" || os.Getenv("AUTOSTREAM_SOFTWARE_UPDATE_FULL_CHAIN") != "1" {
		t.Skip("separate stopped-daemon recovery process is not selected")
	}
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Fatal("software recovery must run as the managed non-root Agent")
	}
	identity, err := LoadManagedBootstrapConfig(HostAgentIdentityPath, true)
	if err != nil {
		t.Fatal("canonical recovery identity unavailable")
	}
	executor := &softwareUpdateChainRecoveryClient{softwareUpdateChainCountingClient: &softwareUpdateChainCountingClient{LocalExecutorClient: LocalExecutorClient{SocketPath: LocalExecutorSocketPath}}}
	agent, err := NewHostPullAgent(identity, HostPullAgentOptions{Executor: executor, AgentVersion: controlversion.Current(), RecoveryOnly: true, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal("create installed recovery Agent")
	}
	in, out := os.NewFile(3, "recovery-command"), os.NewFile(4, "recovery-observation")
	defer in.Close()
	defer out.Close()
	decoder, encoder := json.NewDecoder(io.LimitReader(in, 1<<20)), json.NewEncoder(out)
	for {
		var command stPortChainCommand
		if decoder.Decode(&command) != nil {
			return
		}
		request := SoftwareClaimRecoveryRequest{JobID: command.JobID, LeaseGeneration: command.LeaseGeneration, TargetID: "control-panel", CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ConfigRevision: 1, OwnershipEpoch: 3}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		var operationErr error
		switch command.Command {
		case "inspect":
			_, operationErr = agent.InspectSoftwareClaim(ctx, request)
		case "recover":
			operationErr = agent.RecoverSoftwareClaim(ctx, request)
		case "recover_plan":
			operationErr = agent.RecoverSoftwarePlanAfterGenerationRead(ctx, request)
		default:
			t.Fatal("unknown bounded software recovery command")
		}
		cancel()
		response := stPortChainResponse{OK: operationErr == nil, RootCalls: int(executor.stages.Load() + executor.applies.Load() + executor.reconciles.Load())}
		response.SoftwareWire, _ = json.Marshal(executor.snapshot())
		if operationErr != nil {
			response.ErrorCode = "software_recovery_rejected"
		}
		if agent.Journal != nil && agent.Journal.Active() != nil {
			response.ActiveJobID = agent.Journal.Active().ID
			response.ActivePlanPresent = agent.Journal.ActivePlan() != nil
		}
		if encoder.Encode(response) != nil {
			return
		}
	}
}

// Keep the recovery-specific API out of the overlay compiled into b1. The
// inspection count proves the old root's actual protocol rejection separately
// from the zero Stage/Apply/Reconcile mutation count.
type softwareUpdateChainRecoveryClient struct {
	*softwareUpdateChainCountingClient
	inspections atomic.Int64
}

func (c *softwareUpdateChainRecoveryClient) InspectSoftwareClaimRecovery(ctx context.Context, inspection SoftwareClaimRecoveryInspection, fence LocalExecutorMutationFence) (SoftwareClaimRecoveryProof, error) {
	c.inspections.Add(1)
	return c.LocalExecutorClient.InspectSoftwareClaimRecovery(ctx, inspection, fence)
}
func (c *softwareUpdateChainRecoveryClient) snapshot() any {
	return struct {
		Stage       int64 `json:"stage"`
		Apply       int64 `json:"apply"`
		Reconcile   int64 `json:"reconcile"`
		Inspections int64 `json:"inspections"`
	}{c.stages.Load(), c.applies.Load(), c.reconciles.Load(), c.inspections.Load()}
}
