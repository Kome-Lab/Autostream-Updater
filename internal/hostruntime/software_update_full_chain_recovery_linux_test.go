//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
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
	executor.agent = agent
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
		executor.observeDiagnosticPolicy(ctx, request)
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
		executor.recordOperationDiagnostic(operationErr)
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
	inspections  atomic.Int64
	agent        *HostPullAgent
	diagnosticMu sync.Mutex
	policy       softwareUpdateChainInspectionPolicy
	diagnostic   softwareUpdateChainInspectionDiagnostic
	history      []softwareUpdateChainInspectionDiagnostic
}

// These expectations are a separate read-only observation, never authority for
// the real operation. The operation still fetches and validates its own policy.
type softwareUpdateChainInspectionPolicy struct {
	Observed                             bool
	UpdaterID, HostID, Digest, ErrorCode string
	Source, Projection, Executor, Epoch  int64
}

type softwareUpdateChainInspectionDiagnostic struct {
	Ordinal                    int64  `json:"ordinal"`
	ErrorCode                  string `json:"error_code"`
	OperationClass             string `json:"operation_class"`
	ProofReturned              bool   `json:"proof_returned"`
	PolicyObserved             bool   `json:"policy_observed"`
	PolicyErrorCode            string `json:"policy_error_code"`
	PolicyMatchesFence         bool   `json:"policy_matches_fence"`
	ProofValid                 bool   `json:"proof_valid"`
	RequestMatches             bool   `json:"request_matches"`
	UpdaterMatches             bool   `json:"updater_matches"`
	HostMatches                bool   `json:"host_matches"`
	SourceMatches              bool   `json:"source_matches"`
	ProjectionMatches          bool   `json:"projection_matches"`
	ExecutorMatches            bool   `json:"executor_matches"`
	DigestMatches              bool   `json:"digest_matches"`
	EpochMatches               bool   `json:"epoch_matches"`
	RuntimeMatchesAgent        bool   `json:"runtime_matches_agent"`
	CurrentVersionMatchesBuild bool   `json:"current_version_matches_build"`
	ObservedNotFuture          bool   `json:"observed_not_future"`
	ObservedFresh              bool   `json:"observed_fresh"`
}

func (c *softwareUpdateChainRecoveryClient) observeDiagnosticPolicy(ctx context.Context, request SoftwareClaimRecoveryRequest) {
	binding, policy, err := c.agent.softwareClaimRecoveryPolicy(ctx, request)
	c.diagnosticMu.Lock()
	defer c.diagnosticMu.Unlock()
	c.policy = softwareUpdateChainInspectionPolicy{Observed: err == nil, ErrorCode: softwareUpdateChainPolicyObservationCode(err)}
	c.diagnostic = softwareUpdateChainInspectionDiagnostic{
		ErrorCode: "none", OperationClass: "none", PolicyObserved: c.policy.Observed, PolicyErrorCode: c.policy.ErrorCode,
		CurrentVersionMatchesBuild: c.agent.currentAgentVersion() == controlversion.Current(),
	}
	c.history = nil
	if err == nil {
		c.policy.UpdaterID, c.policy.HostID, c.policy.Digest = c.agent.Bootstrap.NodeID, binding.ExecutionHostID, policy.LocalExecutorPolicySHA256
		c.policy.Source, c.policy.Projection, c.policy.Executor, c.policy.Epoch = policy.SourcePolicyRevision, policy.Revision, policy.LocalExecutorPolicyRevision, binding.OwnershipEpoch
	}
}

func (c *softwareUpdateChainRecoveryClient) InspectSoftwareClaimRecovery(ctx context.Context, inspection SoftwareClaimRecoveryInspection, fence LocalExecutorMutationFence) (SoftwareClaimRecoveryProof, error) {
	ordinal := c.inspections.Add(1)
	proof, err := c.LocalExecutorClient.InspectSoftwareClaimRecovery(ctx, inspection, fence)
	c.diagnosticMu.Lock()
	defer c.diagnosticMu.Unlock()
	c.diagnostic = softwareUpdateChainInspectionDiagnostic{
		Ordinal:   ordinal,
		ErrorCode: softwareUpdateChainInspectionErrorCode(err), OperationClass: "none",
		ProofReturned: err == nil, PolicyObserved: c.policy.Observed, PolicyErrorCode: c.policy.ErrorCode,
		PolicyMatchesFence: c.policy.Observed && c.policy.Source == fence.SourcePolicyRevision &&
			c.policy.Projection == fence.OwnershipPolicyRevision && c.policy.Executor == fence.ExecutorPolicyRevision &&
			c.policy.Epoch == fence.OwnershipEpoch && c.policy.Digest == inspection.ExecutorPolicySHA256,
		CurrentVersionMatchesBuild: c.agent.currentAgentVersion() == controlversion.Current(),
	}
	if err == nil {
		now := time.Now().UTC()
		c.diagnostic.ProofValid = proof.Validate() == nil
		c.diagnostic.RequestMatches = proof.RequestSHA256 == inspection.Request.sha256()
		c.diagnostic.UpdaterMatches = c.policy.Observed && proof.UpdaterID == c.policy.UpdaterID
		c.diagnostic.HostMatches = c.policy.Observed && proof.HostID == c.policy.HostID
		c.diagnostic.SourceMatches = proof.SourcePolicyRevision == fence.SourcePolicyRevision
		c.diagnostic.ProjectionMatches = proof.ProjectionRevision == fence.OwnershipPolicyRevision
		c.diagnostic.ExecutorMatches = proof.ExecutorPolicyRevision == fence.ExecutorPolicyRevision
		c.diagnostic.DigestMatches = proof.ExecutorPolicySHA256 == inspection.ExecutorPolicySHA256
		c.diagnostic.EpochMatches = proof.OwnershipEpoch == inspection.Request.OwnershipEpoch
		c.diagnostic.RuntimeMatchesAgent = proof.RuntimeVersion == c.agent.currentAgentVersion()
		c.diagnostic.ObservedNotFuture = !proof.ObservedAt.After(now.Add(time.Second))
		c.diagnostic.ObservedFresh = now.Sub(proof.ObservedAt) <= localExecutorClientTimeout
	}
	if len(c.history) < 16 {
		c.history = append(c.history, c.diagnostic)
	}
	return proof, err
}

func softwareUpdateChainPolicyObservationCode(err error) string {
	if err == nil {
		return "none"
	}
	switch err.Error() {
	case "authenticate software claim recovery policy":
		return "policy_authentication"
	case "authenticate software claim recovery host binding":
		return "host_authentication"
	case "software claim recovery request does not match the current authenticated target and ownership policy":
		return "policy_binding"
	default:
		return "other"
	}
}

func softwareUpdateChainInspectionErrorCode(err error) string {
	if err == nil {
		return "none"
	}
	var response *LocalExecutorClientError
	if errors.As(err, &response) && validLocalExecutorFailureCode(response.Code) {
		return response.Code
	}
	return "transport_other"
}

func (c *softwareUpdateChainRecoveryClient) recordOperationDiagnostic(err error) {
	c.diagnosticMu.Lock()
	defer c.diagnosticMu.Unlock()
	class := "other"
	switch {
	case err == nil:
		class = "none"
	case errors.Is(err, context.DeadlineExceeded):
		class = "deadline"
	case errors.Is(err, context.Canceled):
		class = "canceled"
	case err.Error() == "software claim recovery absence proof does not match the authenticated policy and installed runtime":
		class = "agent_proof_binding"
	case err.Error() == "software mutation grant lacks its fixed policy authority":
		class = "grant_fixed_policy_authority"
	case softwareUpdateChainInspectionErrorCode(err) != "transport_other":
		class = "root_response"
	}
	c.diagnostic.OperationClass = class
	if len(c.history) > 0 {
		c.history[len(c.history)-1].OperationClass = class
	}
}
func (c *softwareUpdateChainRecoveryClient) snapshot() any {
	c.diagnosticMu.Lock()
	defer c.diagnosticMu.Unlock()
	return struct {
		Stage                 int64                                     `json:"stage"`
		Apply                 int64                                     `json:"apply"`
		Reconcile             int64                                     `json:"reconcile"`
		Inspections           int64                                     `json:"inspections"`
		StageRequiredResponse bool                                      `json:"stage_required_response"`
		InspectionDiagnostic  softwareUpdateChainInspectionDiagnostic   `json:"inspection_diagnostic"`
		InspectionHistory     []softwareUpdateChainInspectionDiagnostic `json:"inspection_history"`
	}{c.stages.Load(), c.applies.Load(), c.reconciles.Load(), c.inspections.Load(), c.stageRequiredResponse.Load(), c.diagnostic, append([]softwareUpdateChainInspectionDiagnostic(nil), c.history...)}
}
