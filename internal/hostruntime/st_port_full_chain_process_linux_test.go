//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
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
		stage := ""
		portClient.resetFailures()
		targetVerified := false
		switch command.Command {
		case "poll", "observe":
			stage = "register"
			binding, registerErr := agent.ControlPlane.RegisterHostAgent(stepCtx, identity, agent.capabilities(HostAgentBinding{}, nil, nil, false))
			operationErr = registerErr
			if operationErr == nil {
				var policy *HostAgentPolicy
				stage = "policy"
				policy, _, operationErr = agent.ControlPlane.FetchHostAgentPolicy(stepCtx, identity.NodeID, 0)
				if operationErr == nil && policy == nil {
					operationErr = errors.New("policy unavailable")
				}
				if operationErr == nil {
					var selected HostAgentPolicy
					stage = "recovery_policy"
					selected, operationErr = agent.portRecoveryPolicy(*policy)
					if operationErr == nil {
						observations, failed := agent.observe(stepCtx, selected)
						targetVerified = !failed && len(observations) == 1 && observations[0].ServiceID == "worker-smoke" && observations[0].Availability == TargetAvailabilityAvailable && observations[0].PortContractVersion == 2 && observations[0].PolicyTransitionVersion == 1
						stage = "heartbeat"
						operationErr = agent.ControlPlane.HeartbeatHostAgent(stepCtx, identity, "online", agent.capabilities(binding, &selected, observations, failed))
						if operationErr == nil && command.Command == "poll" {
							stage = "execute"
							operationErr = agent.executeOnce(stepCtx, binding, selected)
						}
					}
				}
			}
		case "flush":
			stage = "flush"
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
			response.FailureStage = stage
			response.FailureClass = stPortChainClassifyError(operationErr)
			var panelErr *PanelHTTPError
			if errors.As(operationErr, &panelErr) && panelErr.Status >= 100 && panelErr.Status <= 599 {
				response.FailureHTTPStatus = panelErr.Status
			}
			response.FirstRootFailure, response.LastRootFailure = portClient.failures()
			response.ActivePlanPresent = agent.Journal.ActivePortPlan() != nil
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
	calls        atomic.Int64
	mu           sync.Mutex
	firstFailure string
	lastFailure  string
}

func (c *stPortChainCountingClient) PortReconfigureV2(ctx context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (SystemdPortReconfigureResult, error) {
	c.calls.Add(1)
	result, err := c.LocalExecutorClient.PortReconfigureV2(ctx, plan, fence, grant)
	c.recordFailure(err)
	return result, err
}

func (c *stPortChainCountingClient) PortReconfigureReconcileV2(ctx context.Context, plan SystemdPortReconfigurePlan, fence LocalExecutorMutationFence, grant V2MutationGrant) (SystemdPortReconfigureResult, error) {
	c.calls.Add(1)
	result, err := c.LocalExecutorClient.PortReconfigureReconcileV2(ctx, plan, fence, grant)
	c.recordFailure(err)
	return result, err
}

func (c *stPortChainCountingClient) resetFailures() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.firstFailure, c.lastFailure = "", ""
}

func (c *stPortChainCountingClient) recordFailure(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	code := stPortChainClassifyError(err)
	if c.firstFailure == "" {
		c.firstFailure = code
	}
	c.lastFailure = code
}

func (c *stPortChainCountingClient) failures() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstFailure, c.lastFailure
}

func stPortChainSafeFailureClass(code string) string {
	if code == "" {
		return "none"
	}
	if validLocalExecutorFailureCode(code) || safePanelErrorCode(code) == code {
		return code
	}
	switch code {
	case "none", "other", "panel_http", "deadline", "canceled", "permission", "not_exist", "runtime_compatibility", "claim_binding", "port_policy_fence", "root_transport", "port_plan_invalid", "port_binding_invalid":
		return code
	default:
		return "other"
	}
}

func stPortChainClassifyError(err error) string {
	if err == nil {
		return "none"
	}
	var rootErr *LocalExecutorClientError
	if errors.As(err, &rootErr) {
		return stPortChainSafeFailureClass(rootErr.Code)
	}
	var panelErr *PanelHTTPError
	if errors.As(err, &panelErr) {
		if code := safePanelErrorCode(panelErr.Code); code != "" {
			return code
		}
		return "panel_http"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrNotExist):
		return "not_exist"
	}
	// Exact fixed source messages become enums; error strings never leave memory.
	switch err.Error() {
	case "host runtime compatibility cannot be established", "host runtime compatibility probe failed", "host runtime self-update is not stable", "host runtime self-update target is not active":
		return "runtime_compatibility"
	case "pull_v2 claim ownership or lease binding is invalid", "pull_v2 v2 claim credential or command binding is invalid", "pull_v2 port claim does not match its original snapshot and policy", "pull_v2 claim target does not match the active policy":
		return "claim_binding"
	case "port v2 job policy fence is stale", "port job policy fence is stale":
		return "port_policy_fence"
	case "connect to local executor", "read local executor port mutation response", "send local executor port mutation request", "finish local executor port mutation request":
		return "root_transport"
	case "local executor port plan is invalid":
		return "port_plan_invalid"
	case "local executor v2 port binding is invalid":
		return "port_binding_invalid"
	default:
		return "other"
	}
}
