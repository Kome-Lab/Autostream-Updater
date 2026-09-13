package hostruntime

import (
	"context"
	"errors"
	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	RuntimeCredentialStatePath     = "/var/lib/autostream-local-executor/runtime-credential.json"
	runtimeCredentialStateMaxBytes = 64 << 10
	runtimeCredentialStagedMaxAge  = 24 * time.Hour
)

type runtimeCredentialExecutorRuntime struct {
	identityDir          string
	activeIdentity       string
	stagedIdentity       string
	wipingIdentity       string
	statePath            string
	httpClient           *http.Client
	now                  func() time.Time
	executorVersion      string
	allowTestPaths       bool
	verifyIdentityLayout func() error
	writeStagedIdentity  func(string, []byte, uint32, bool) error
	acknowledgeStage     func(context.Context, string, string, int64, string, *http.Client) (HostAgentRuntimeTokenRotation, error)
	activate             func(context.Context, string, string, int64, string, *http.Client) (HostAgentRuntimeTokenRotation, error)
}

type runtimeCredentialStateFile struct {
	RuntimeCredentialStatus
	PreviousRuntimeTokenSHA256 string `json:"previous_runtime_token_sha256"`
	StagedRuntimeTokenSHA256   string `json:"staged_runtime_token_sha256,omitempty"`
	ActiveRuntimeTokenSHA256   string `json:"active_runtime_token_sha256,omitempty"`
	ServiceName                string `json:"service_name"`
}

func defaultRuntimeCredentialExecutorRuntime() runtimeCredentialExecutorRuntime {
	return runtimeCredentialExecutorRuntime{
		identityDir:     HostAgentIdentityDir,
		activeIdentity:  HostAgentIdentityPath,
		stagedIdentity:  HostAgentStagedIdentityPath,
		wipingIdentity:  HostAgentWipingIdentityPath,
		statePath:       RuntimeCredentialStatePath,
		now:             time.Now,
		executorVersion: controlversion.Current(),
		verifyIdentityLayout: func() error {
			return validateHostAgentIdentityWriteLayout(
				HostAgentIdentityPath,
				os.Lstat,
			)
		},
		acknowledgeStage: AcknowledgeRuntimeTokenRotationLocalStage,
		activate:         ActivateRuntimeTokenRotationAtPanel,
	}
}

func handleLocalExecutorRuntimeCredential(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	rt runtimeCredentialExecutorRuntime,
) LocalExecutorResponse {
	if err := request.Validate(); err != nil ||
		!strings.HasPrefix(request.Operation, "runtime_credential_") {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "invalid_request",
		)
	}
	if err := policy.Validate(); err != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "policy_invalid",
		)
	}
	if err := rt.validatePaths(); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}
	if err := rt.validateIdentityLayout(); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_invalid",
		)
	}
	status, exists, err := rt.loadAndReconcileStatus(policy.AgentGID)
	if err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_invalid",
		)
	}
	if request.Operation == "runtime_credential_status" {
		if !exists {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "target_not_found",
			)
		}
		if status.ServiceID != request.ServiceID {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "config_mismatch",
			)
		}
		return runtimeCredentialResponse(status)
	}
	if request.RuntimeCredential == nil ||
		request.RuntimeCredential.ExecutionHostID != policy.HostID ||
		request.SourcePolicyRevision != policy.SourcePolicyRevision ||
		request.OwnershipPolicyRevision != policy.ProjectionRevision ||
		request.ExecutorPolicyRevision != policy.PolicyRevision {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "config_mismatch",
		)
	}
	active, activeBytes, _, err := rt.loadIdentity(
		rt.activeIdentity, policy.AgentGID,
	)
	if err != nil ||
		active.NodeID != request.ServiceID ||
		active.PanelURL != policy.Mutation.PanelURL {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "config_mismatch",
		)
	}
	if exists && !runtimeCredentialRequestMatchesStatus(
		request, status,
	) {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "config_mismatch",
		)
	}

	var next RuntimeCredentialStatus
	switch request.Operation {
	case "runtime_credential_prepare":
		next, err = rt.prepare(
			policy, request, active, activeBytes, status, exists,
		)
	case "runtime_credential_stage":
		next, err = rt.stage(
			ctx, policy, request, active, activeBytes, status, exists,
		)
	case "runtime_credential_proof_ready":
		next, err = rt.markProofReady(request, status, exists, policy.AgentGID)
	case "runtime_credential_activate":
		next, err = rt.activateCredential(
			ctx, policy, request, status, exists,
		)
	case "runtime_credential_cancel":
		next, err = rt.cancel(
			policy, request, status, exists,
		)
	case "runtime_credential_finalize":
		next, err = rt.finalize(
			policy, request, status, exists,
		)
	default:
		err = errors.New("unsupported runtime credential operation")
	}
	if err == nil {
		err = rt.validateIdentityLayout()
	}
	if err != nil {
		code := "state_invalid"
		var panelErr *PanelHTTPError
		switch {
		case errors.Is(err, errRuntimeCredentialBusy):
			code = "target_busy"
		case errors.Is(err, errRuntimeCredentialPrecondition):
			code = "mutation_precondition_failed"
		case errors.Is(err, errRuntimeCredentialStateUnavailable):
			code = "state_unavailable"
		case errors.As(err, &panelErr):
			code = "mutation_precondition_failed"
		}
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, code,
		)
	}
	return runtimeCredentialResponse(next)
}

var (
	errRuntimeCredentialBusy             = errors.New("runtime credential busy")
	errRuntimeCredentialPrecondition     = errors.New("runtime credential precondition failed")
	errRuntimeCredentialStateUnavailable = errors.New("runtime credential state unavailable")
)

func (rt runtimeCredentialExecutorRuntime) validatePaths() error {
	for _, candidate := range []string{
		rt.identityDir,
		rt.activeIdentity,
		rt.stagedIdentity,
		rt.wipingIdentity,
		rt.statePath,
	} {
		if !filepath.IsAbs(candidate) ||
			filepath.Clean(candidate) == string(filepath.Separator) {
			return errors.New("runtime credential path is invalid")
		}
	}
	if filepath.Dir(rt.activeIdentity) != filepath.Clean(rt.identityDir) ||
		filepath.Dir(rt.stagedIdentity) != filepath.Clean(rt.identityDir) ||
		filepath.Dir(rt.wipingIdentity) != filepath.Clean(rt.identityDir) ||
		rt.activeIdentity == rt.stagedIdentity ||
		rt.activeIdentity == rt.wipingIdentity ||
		rt.stagedIdentity == rt.wipingIdentity {
		return errors.New("runtime credential identity paths escaped their fixed root")
	}
	if !rt.allowTestPaths &&
		(rt.identityDir != HostAgentIdentityDir ||
			rt.activeIdentity != HostAgentIdentityPath ||
			rt.stagedIdentity != HostAgentStagedIdentityPath ||
			rt.wipingIdentity != HostAgentWipingIdentityPath ||
			rt.statePath != RuntimeCredentialStatePath) {
		return errors.New("runtime credential paths are not fixed production paths")
	}
	return nil
}

func (rt runtimeCredentialExecutorRuntime) validateIdentityLayout() error {
	if rt.verifyIdentityLayout != nil {
		return rt.verifyIdentityLayout()
	}
	if rt.allowTestPaths {
		return nil
	}
	return validateHostAgentIdentityWriteLayout(rt.activeIdentity, os.Lstat)
}

func (rt runtimeCredentialExecutorRuntime) currentTime() time.Time {
	if rt.now == nil {
		return time.Now().UTC()
	}
	return rt.now().UTC()
}

func (rt runtimeCredentialExecutorRuntime) currentExecutorVersion() string {
	if value := strings.TrimSpace(rt.executorVersion); value != "" {
		return value
	}
	return controlversion.Current()
}
