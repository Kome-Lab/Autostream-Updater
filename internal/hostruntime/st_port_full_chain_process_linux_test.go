//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// This entry is a separate OS process. The fixture controls cadence only:
// registration, policy decoding, heartbeat, grants, journal and every Executor
// request use production implementations and the real authenticated socket.
// In particular, no CP, listener, policy or mutation result is synthesized.
func TestSTPortFullChainRuntimeProcess(t *testing.T) {
	role := os.Getenv("AUTOSTREAM_ST_PORT_CHAIN_CHILD")
	if role != "agent" && role != "root" {
		t.Skip("ST-PORT full-chain process entry is selected only by its isolated harness")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if role == "root" {
		if os.Geteuid() != 0 {
			t.Fatal("root Executor child has the wrong identity")
		}
		if err := ServeLocalExecutor(ctx, localExecutorPortPolicyPath); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal("production root Executor stopped unexpectedly")
		}
		return
	}
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Fatal("Agent child must have a non-root UID and GID")
	}
	identity, err := LoadManagedBootstrapConfig(HostAgentIdentityPath, true)
	if err != nil {
		t.Fatal("canonical Agent identity is unavailable")
	}
	portClient := &stPortChainCountingClient{LocalExecutorClient: LocalExecutorClient{SocketPath: LocalExecutorSocketPath}}
	agent, err := NewHostPullAgent(identity, HostPullAgentOptions{
		PortExecutor: portClient,
		AgentVersion: "v2.0.0",
		Logf:         func(string, ...any) {},
	})
	if err != nil {
		t.Fatal("production Agent initialization failed")
	}
	agent.Journal, err = OpenJournal(agent.StateDir)
	if err != nil {
		t.Fatal("production Agent journal initialization failed")
	}
	in, out := os.NewFile(3, "st-port-agent-control"), os.NewFile(4, "st-port-agent-observations")
	if in == nil || out == nil {
		t.Fatal("private fixture control descriptors are required")
	}
	defer in.Close()
	defer out.Close()
	decoder, encoder := json.NewDecoder(io.LimitReader(in, 1<<20)), json.NewEncoder(out)
	for {
		var command stPortChainCommand
		if err := decoder.Decode(&command); errors.Is(err, io.EOF) {
			return
		} else if err != nil {
			t.Fatal("invalid private Agent fixture command")
		}
		stepCtx, stop := context.WithTimeout(ctx, 7*time.Minute)
		var operationErr error
		targetVerified := false
		switch command.Command {
		case "poll", "observe":
			binding, registerErr := agent.ControlPlane.RegisterHostAgent(stepCtx, identity, agent.capabilities(HostAgentBinding{}, nil, nil, false))
			operationErr = registerErr
			if operationErr == nil {
				var policy *HostAgentPolicy
				policy, _, operationErr = agent.ControlPlane.FetchHostAgentPolicy(stepCtx, identity.NodeID, 0)
				if operationErr == nil && policy == nil {
					operationErr = errors.New("policy unavailable")
				}
				if operationErr == nil {
					var selected HostAgentPolicy
					selected, operationErr = agent.portRecoveryPolicy(*policy)
					if operationErr == nil {
						observations, failed := agent.observe(stepCtx, selected)
						targetVerified = !failed && len(observations) == 1 && observations[0].ServiceID == "worker-smoke" && observations[0].Availability == TargetAvailabilityAvailable && observations[0].PortContractVersion == 2 && observations[0].PolicyTransitionVersion == 1
						operationErr = agent.ControlPlane.HeartbeatHostAgent(stepCtx, identity, "online", agent.capabilities(binding, &selected, observations, failed))
						if operationErr == nil && command.Command == "poll" {
							operationErr = agent.executeOnce(stepCtx, binding, selected)
						}
					}
				}
			}
		case "flush":
			panel, ok := agent.ControlPlane.(HostPullExecutionControlPlane)
			if !ok {
				operationErr = errors.New("execution transport unavailable")
			} else {
				operationErr = agent.flushExecutionReports(stepCtx, panel)
			}
		case "metrics":
		case "stop":
			stop()
			return
		default:
			operationErr = errors.New("unsupported private Agent fixture command")
		}
		stop()
		response := stPortChainResponse{OK: operationErr == nil, RootCalls: int(portClient.calls.Load()), TargetVerified: targetVerified}
		if operationErr != nil {
			response.ErrorCode = "agent_operation_failed"
		}
		if active := agent.Journal.Active(); active != nil {
			response.ActiveJobID = active.ID
			response.ActiveResult = clonePortResult(active.PortResult)
		}
		if err := encoder.Encode(response); err != nil {
			t.Fatal("private Agent observation channel closed")
		}
	}
}

type stPortChainCountingClient struct {
	LocalExecutorClient
	calls atomic.Int64
}

func (c *stPortChainCountingClient) PortReconfigureV2(ctx context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (SystemdPortReconfigureResult, error) {
	c.calls.Add(1)
	return c.LocalExecutorClient.PortReconfigureV2(ctx, plan, fence, grant)
}

func (c *stPortChainCountingClient) PortReconfigureReconcileV2(ctx context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (SystemdPortReconfigureResult, error) {
	c.calls.Add(1)
	return c.LocalExecutorClient.PortReconfigureReconcileV2(ctx, plan, fence, grant)
}
