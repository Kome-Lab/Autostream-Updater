package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
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

func (rt runtimeCredentialExecutorRuntime) prepare(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	active Config,
	activeBytes []byte,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	mutation := *request.RuntimeCredential
	if mutation.RotationRevision != 1 {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: initial rotation revision is required",
			errRuntimeCredentialPrecondition,
		)
	}
	if exists {
		if current.Phase ==
			RuntimeCredentialPhaseClaimPrepared &&
			current.RotationRevision ==
				mutation.RotationRevision {
			return current, nil
		}
		return RuntimeCredentialStatus{},
			errRuntimeCredentialBusy
	}
	if _, err := os.Lstat(rt.stagedIdentity); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		if err == nil {
			return RuntimeCredentialStatus{},
				errRuntimeCredentialBusy
		}
		return RuntimeCredentialStatus{}, errors.New(
			"stat staged runtime credential before claim preparation",
		)
	}
	policySHA256, err := policy.SHA256()
	if err != nil {
		return RuntimeCredentialStatus{}, err
	}
	previousDigest := runtimeCredentialDigest(activeBytes)
	current = RuntimeCredentialStatus{
		SchemaVersion:               runtimeCredentialStateSchemaVersion,
		Phase:                       RuntimeCredentialPhaseClaimPrepared,
		RotationID:                  mutation.RotationID,
		ServiceID:                   request.ServiceID,
		ExecutionHostID:             mutation.ExecutionHostID,
		PreviousTokenID:             mutation.PreviousTokenID,
		StagedTokenID:               mutation.StagedTokenID,
		RotationRevision:            mutation.RotationRevision,
		OwnershipEpoch:              request.OwnershipEpoch,
		SourcePolicyRevision:        request.SourcePolicyRevision,
		ProjectionRevision:          request.OwnershipPolicyRevision,
		LocalExecutorPolicyRevision: request.ExecutorPolicyRevision,
		StagedIdentitySHA256:        runtimeCredentialDigest(nil),
		PreviousIdentitySHA256:      previousDigest,
		LocalExecutorPolicySHA256:   policySHA256,
		ExecutorVersion:             rt.currentExecutorVersion(),
		ExecutorProtocolVersion:     LocalExecutorMutationProtocolVersion,
		MutationProtocolVersion:     LocalExecutorMutationProtocolVersion,
		StagedExpiresAt:             rt.currentTime().Add(runtimeCredentialStagedMaxAge),
		previousRuntimeTokenSHA256:  runtimeCredentialTokenDigest(active.RuntimeToken),
		serviceName:                 active.ServiceName,
	}
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) stage(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	active Config,
	activeBytes []byte,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	mutation := *request.RuntimeCredential
	if mutation.RotationRevision != 2 {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: claim revision is required", errRuntimeCredentialPrecondition,
		)
	}
	prepared := exists &&
		current.Phase == RuntimeCredentialPhaseClaimPrepared
	if exists {
		switch current.Phase {
		case RuntimeCredentialPhaseClaimPrepared:
			if current.RotationRevision+1 !=
				mutation.RotationRevision {
				return RuntimeCredentialStatus{}, fmt.Errorf(
					"%w: prepared claim revision changed",
					errRuntimeCredentialPrecondition,
				)
			}
		case RuntimeCredentialPhaseLocalStaged,
			RuntimeCredentialPhaseProofReady,
			RuntimeCredentialPhaseActivated:
			return current, nil
		case RuntimeCredentialPhaseStageBound,
			RuntimeCredentialPhaseStaged:
			if current.RotationRevision != mutation.RotationRevision {
				return RuntimeCredentialStatus{}, fmt.Errorf(
					"%w: staged revision changed", errRuntimeCredentialPrecondition,
				)
			}
		default:
			return RuntimeCredentialStatus{}, errRuntimeCredentialBusy
		}
	}
	if !exists || prepared ||
		current.Phase == RuntimeCredentialPhaseStageBound ||
		current.Phase == RuntimeCredentialPhaseStaged {
		if active.RuntimeToken == mutation.RuntimeToken.Reveal() {
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: staged token equals active token", errRuntimeCredentialPrecondition,
			)
		}
		staged := active
		staged.RuntimeToken = mutation.RuntimeToken.Reveal()
		stagedBytes, err := marshalRuntimeCredentialIdentity(staged)
		if err != nil {
			return RuntimeCredentialStatus{}, err
		}
		if bytes.Equal(stagedBytes, activeBytes) {
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: staged identity is unchanged", errRuntimeCredentialPrecondition,
			)
		}
		stagedDigest := runtimeCredentialDigest(stagedBytes)
		stagedTokenDigest := runtimeCredentialTokenDigest(
			staged.RuntimeToken,
		)
		if current.Phase == RuntimeCredentialPhaseStageBound ||
			current.Phase == RuntimeCredentialPhaseStaged {
			if current.StagedIdentitySHA256 != stagedDigest ||
				current.stagedRuntimeTokenSHA256 !=
					stagedTokenDigest ||
				current.PreviousIdentitySHA256 !=
					runtimeCredentialDigest(activeBytes) ||
				current.previousRuntimeTokenSHA256 !=
					runtimeCredentialTokenDigest(
						active.RuntimeToken,
					) ||
				current.serviceName != active.ServiceName {
				return RuntimeCredentialStatus{}, fmt.Errorf(
					"%w: staged credential replay changed its root binding",
					errRuntimeCredentialPrecondition,
				)
			}
		}
		if _, wipingErr := os.Lstat(
			rt.wipingIdentity,
		); !errors.Is(wipingErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, errors.New(
				"runtime credential cleanup is incomplete before staging",
			)
		}
		stagedExists := false
		if _, stagedErr := os.Lstat(rt.stagedIdentity); stagedErr == nil {
			_, existingStagedBytes, _, loadErr := rt.loadIdentity(
				rt.stagedIdentity, policy.AgentGID,
			)
			if loadErr != nil ||
				!bytes.Equal(existingStagedBytes, stagedBytes) {
				return RuntimeCredentialStatus{}, errors.New(
					"orphaned staged runtime credential does not match claim replay",
				)
			}
			stagedExists = true
		} else if !errors.Is(stagedErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, errors.New(
				"stat staged runtime credential before install",
			)
		}
		if current.Phase != RuntimeCredentialPhaseStageBound &&
			current.Phase != RuntimeCredentialPhaseStaged {
			if prepared {
				current.Phase = RuntimeCredentialPhaseStageBound
				current.RotationRevision =
					mutation.RotationRevision
				current.StagedIdentitySHA256 =
					stagedDigest
				current.stagedRuntimeTokenSHA256 =
					stagedTokenDigest
			} else {
				current = RuntimeCredentialStatus{
					SchemaVersion:               runtimeCredentialStateSchemaVersion,
					Phase:                       RuntimeCredentialPhaseStageBound,
					RotationID:                  mutation.RotationID,
					ServiceID:                   request.ServiceID,
					ExecutionHostID:             mutation.ExecutionHostID,
					PreviousTokenID:             mutation.PreviousTokenID,
					StagedTokenID:               mutation.StagedTokenID,
					RotationRevision:            mutation.RotationRevision,
					OwnershipEpoch:              request.OwnershipEpoch,
					SourcePolicyRevision:        request.SourcePolicyRevision,
					ProjectionRevision:          request.OwnershipPolicyRevision,
					LocalExecutorPolicyRevision: request.ExecutorPolicyRevision,
					StagedIdentitySHA256:        stagedDigest,
					PreviousIdentitySHA256:      runtimeCredentialDigest(activeBytes),
					ExecutorVersion:             rt.currentExecutorVersion(),
					ExecutorProtocolVersion:     LocalExecutorMutationProtocolVersion,
					MutationProtocolVersion:     LocalExecutorMutationProtocolVersion,
					StagedExpiresAt:             rt.currentTime().Add(runtimeCredentialStagedMaxAge),
					previousRuntimeTokenSHA256:  runtimeCredentialTokenDigest(active.RuntimeToken),
					stagedRuntimeTokenSHA256:    stagedTokenDigest,
					serviceName:                 active.ServiceName,
				}
				policySHA256, digestErr := policy.SHA256()
				if digestErr != nil {
					return RuntimeCredentialStatus{}, digestErr
				}
				current.LocalExecutorPolicySHA256 =
					policySHA256
			}
			// Bind the exact claimed identity and token hash in the root-only
			// ledger before creating the staged secret file. A stop on either
			// side of the following write is replayable from this phase.
			if err := rt.saveStatus(current); err != nil {
				return RuntimeCredentialStatus{}, err
			}
		}
		if !stagedExists {
			writeStagedIdentity := rt.writeIdentityAtomic
			if rt.writeStagedIdentity != nil {
				writeStagedIdentity = rt.writeStagedIdentity
			}
			if err := writeStagedIdentity(
				rt.stagedIdentity,
				stagedBytes,
				policy.AgentGID,
				false,
			); err != nil {
				return RuntimeCredentialStatus{}, err
			}
		}
		_, verified, _, err := rt.loadIdentity(
			rt.stagedIdentity, policy.AgentGID,
		)
		if err != nil || !bytes.Equal(verified, stagedBytes) {
			return RuntimeCredentialStatus{}, errors.New(
				"staged runtime credential secure reread failed",
			)
		}
		if current.Phase == RuntimeCredentialPhaseStageBound {
			current.Phase = RuntimeCredentialPhaseStaged
			if err := rt.saveStatus(current); err != nil {
				return RuntimeCredentialStatus{}, err
			}
		}
	}
	_, stagedBytes, _, err := rt.loadIdentity(
		rt.stagedIdentity, policy.AgentGID,
	)
	if err != nil ||
		runtimeCredentialDigest(stagedBytes) != current.StagedIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"staged runtime credential no longer matches durable state",
		)
	}
	if rt.acknowledgeStage == nil {
		return RuntimeCredentialStatus{}, errRuntimeCredentialStateUnavailable
	}
	rotation, err := rt.acknowledgeStage(
		ctx,
		policy.Mutation.PanelURL,
		current.RotationID,
		current.RotationRevision,
		mutation.RuntimeToken.Reveal(),
		rt.httpClient,
	)
	if err != nil {
		// A transport failure can be a lost successful response. Preserve the
		// fixed staged slot and replay the same expected revision.
		return RuntimeCredentialStatus{}, err
	}
	if err := validateRuntimeCredentialPanelTransition(
		rotation, current, "local_staged", current.RotationRevision+1,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	current.Phase = RuntimeCredentialPhaseLocalStaged
	current.RotationRevision = rotation.Revision
	current.LocalStageReceiptID = rotation.LocalStageReceiptID
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) markProofReady(
	request LocalExecutorRequest,
	current RuntimeCredentialStatus,
	exists bool,
	agentGID uint32,
) (RuntimeCredentialStatus, error) {
	if !exists {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: staged credential is unavailable", errRuntimeCredentialPrecondition,
		)
	}
	if current.Phase == RuntimeCredentialPhaseProofReady ||
		current.Phase == RuntimeCredentialPhaseActivated {
		if request.RuntimeCredential.RotationRevision != current.RotationRevision {
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: proof revision changed", errRuntimeCredentialPrecondition,
			)
		}
		return current, nil
	}
	if current.Phase != RuntimeCredentialPhaseLocalStaged ||
		request.RuntimeCredential.RotationRevision != current.RotationRevision+1 {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: heartbeat proof revision is invalid", errRuntimeCredentialPrecondition,
		)
	}
	_, stagedBytes, _, err := rt.loadIdentity(rt.stagedIdentity, agentGID)
	if err != nil ||
		runtimeCredentialDigest(stagedBytes) != current.StagedIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"staged runtime credential proof input changed",
		)
	}
	current.Phase = RuntimeCredentialPhaseProofReady
	current.RotationRevision = request.RuntimeCredential.RotationRevision
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) activateCredential(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	if !exists {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: staged credential is unavailable", errRuntimeCredentialPrecondition,
		)
	}
	if current.Phase == RuntimeCredentialPhaseActivated {
		return current, nil
	}
	if current.Phase != RuntimeCredentialPhaseProofReady ||
		request.RuntimeCredential.RotationRevision != current.RotationRevision {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: heartbeat proof is required", errRuntimeCredentialPrecondition,
		)
	}
	staged, stagedBytes, _, err := rt.loadIdentity(
		rt.stagedIdentity, policy.AgentGID,
	)
	if err != nil ||
		staged.NodeID != current.ServiceID ||
		staged.PanelURL != policy.Mutation.PanelURL ||
		runtimeCredentialDigest(stagedBytes) != current.StagedIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"staged runtime credential activation input changed",
		)
	}
	if rt.activate == nil {
		return RuntimeCredentialStatus{}, errRuntimeCredentialStateUnavailable
	}
	rotation, err := rt.activate(
		ctx,
		policy.Mutation.PanelURL,
		current.RotationID,
		current.RotationRevision,
		staged.RuntimeToken,
		rt.httpClient,
	)
	if err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := validateRuntimeCredentialPanelTransition(
		rotation, current, "activated", current.RotationRevision+1,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.validateIdentityLayout(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.writeIdentityAtomic(
		rt.activeIdentity, stagedBytes, policy.AgentGID, true,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.validateIdentityLayout(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	_, activeBytes, _, err := rt.loadIdentity(
		rt.activeIdentity, policy.AgentGID,
	)
	if err != nil ||
		runtimeCredentialDigest(activeBytes) != current.StagedIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"activated runtime credential secure reread failed",
		)
	}
	current.Phase = RuntimeCredentialPhaseActivated
	current.RotationRevision = rotation.Revision
	current.ActiveIdentitySHA256 = current.StagedIdentitySHA256
	current.activeRuntimeTokenSHA256 =
		current.stagedRuntimeTokenSHA256
	if err := rt.saveStatus(current); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	if err := rt.wipeAndRemoveIdentity(
		rt.stagedIdentity, policy.AgentGID, current.StagedIdentitySHA256,
	); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) cancel(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	if !exists {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: tracked runtime credential state is unavailable",
			errRuntimeCredentialPrecondition,
		)
	}
	if current.Phase == RuntimeCredentialPhaseActivated {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: activated credential cannot be cancelled", errRuntimeCredentialPrecondition,
		)
	}
	if request.RuntimeCredential.RotationRevision < current.RotationRevision {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: cancel revision is stale", errRuntimeCredentialPrecondition,
		)
	}
	switch current.Phase {
	case RuntimeCredentialPhaseCancelReady:
		switch request.RuntimeCredential.RotationRevision {
		case current.RotationRevision:
			// Idempotent replay after the first cancel response was lost.
			return current, nil
		case current.RotationRevision + 1:
		default:
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: cancel acknowledgement revision is invalid",
				errRuntimeCredentialPrecondition,
			)
		}
		current.Phase = RuntimeCredentialPhaseCancelled
		current.RotationRevision = request.RuntimeCredential.RotationRevision
		if err := rt.removeState(); err != nil {
			return RuntimeCredentialStatus{}, err
		}
		return current, nil
	case RuntimeCredentialPhaseClaimPrepared,
		RuntimeCredentialPhaseStageBound,
		RuntimeCredentialPhaseStaged,
		RuntimeCredentialPhaseLocalStaged,
		RuntimeCredentialPhaseProofReady,
		RuntimeCredentialPhaseExpired:
		if request.RuntimeCredential.RotationRevision !=
			current.RotationRevision+1 {
			return RuntimeCredentialStatus{}, fmt.Errorf(
				"%w: cancel request revision is invalid",
				errRuntimeCredentialPrecondition,
			)
		}
		_, activeBytes, _, err := rt.loadIdentity(
			rt.activeIdentity, policy.AgentGID,
		)
		if err != nil ||
			runtimeCredentialDigest(activeBytes) !=
				current.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, errors.New(
				"previous Host Agent identity changed before cancel",
			)
		}
		current.Phase = RuntimeCredentialPhaseCancelReady
		current.RotationRevision =
			request.RuntimeCredential.RotationRevision
		current.ActiveIdentitySHA256 =
			current.PreviousIdentitySHA256
		current.activeRuntimeTokenSHA256 =
			current.previousRuntimeTokenSHA256
		if err := rt.saveStatus(current); err != nil {
			return RuntimeCredentialStatus{}, err
		}
		// Persist cancel_ready before destroying the staged secret. If this
		// process stops during the wipe, loadAndReconcileStatus completes the
		// exact-digest cleanup before the panel acknowledgement is allowed.
		if err := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity, policy.AgentGID, current.StagedIdentitySHA256,
		); err != nil {
			return RuntimeCredentialStatus{}, err
		}
		return current, nil
	default:
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: rotation cannot be cancelled from this phase",
			errRuntimeCredentialPrecondition,
		)
	}
}

func (rt runtimeCredentialExecutorRuntime) finalize(
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	current RuntimeCredentialStatus,
	exists bool,
) (RuntimeCredentialStatus, error) {
	if !exists ||
		(current.Phase != RuntimeCredentialPhaseActivated &&
			current.Phase != RuntimeCredentialPhaseManualRecovered) ||
		request.RuntimeCredential.RotationRevision !=
			current.RotationRevision {
		return RuntimeCredentialStatus{}, fmt.Errorf(
			"%w: terminal runtime credential state is unavailable",
			errRuntimeCredentialPrecondition,
		)
	}
	_, activeBytes, _, err := rt.loadIdentity(
		rt.activeIdentity, policy.AgentGID,
	)
	if err != nil ||
		runtimeCredentialDigest(activeBytes) != current.ActiveIdentitySHA256 {
		return RuntimeCredentialStatus{}, errors.New(
			"terminal runtime credential active identity changed",
		)
	}
	if !rt.identityCleanupComplete() {
		return RuntimeCredentialStatus{}, errors.New(
			"terminal runtime credential staged cleanup is incomplete",
		)
	}
	if err := rt.removeState(); err != nil {
		return RuntimeCredentialStatus{}, err
	}
	return current, nil
}

func (rt runtimeCredentialExecutorRuntime) loadAndReconcileStatus(
	agentGID uint32,
) (RuntimeCredentialStatus, bool, error) {
	status, exists, err := rt.loadStatus()
	if err != nil {
		return status, exists, err
	}
	if !exists {
		if err := rt.cleanupExpiredOrphanedStagedIdentity(agentGID); err != nil {
			return RuntimeCredentialStatus{}, false, err
		}
		return RuntimeCredentialStatus{}, false, nil
	}
	switch status.Phase {
	case RuntimeCredentialPhaseClaimPrepared:
		active, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false,
				errors.New(
					"claim-prepared runtime credential active identity changed",
				)
		}
		if _, wipingErr := os.Lstat(
			rt.wipingIdentity,
		); !errors.Is(wipingErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, false,
				errors.New(
					"claim-prepared runtime credential has an unfinished identity wipe",
				)
		}
		status, stagedExists, err := rt.bindClaimPreparedStagedIdentity(
			status,
			agentGID,
			active.PanelURL,
		)
		if err != nil {
			return RuntimeCredentialStatus{}, false, err
		}
		if !rt.currentTime().Before(status.StagedExpiresAt) {
			status.Phase = RuntimeCredentialPhaseExpired
			status.ActiveIdentitySHA256 =
				status.PreviousIdentitySHA256
			status.activeRuntimeTokenSHA256 =
				status.previousRuntimeTokenSHA256
			if err := rt.saveStatus(status); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
			if stagedExists {
				if err := rt.wipeAndRemoveIdentity(
					rt.stagedIdentity,
					agentGID,
					status.StagedIdentitySHA256,
				); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
			}
		}
	case RuntimeCredentialPhaseStageBound:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity,
			agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"active runtime credential changed before stage-bound replay",
			)
		}
		status, stagedExists, bindErr :=
			rt.bindStageBoundInstalledIdentity(
				status,
				agentGID,
				"",
			)
		if bindErr != nil {
			return RuntimeCredentialStatus{}, false, bindErr
		}
		if !rt.currentTime().Before(status.StagedExpiresAt) {
			status.Phase = RuntimeCredentialPhaseExpired
			status.ActiveIdentitySHA256 =
				status.PreviousIdentitySHA256
			status.activeRuntimeTokenSHA256 =
				status.previousRuntimeTokenSHA256
			if err := rt.saveStatus(status); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
			if stagedExists {
				if err := rt.wipeAndRemoveIdentity(
					rt.stagedIdentity,
					agentGID,
					status.StagedIdentitySHA256,
				); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
			}
		}
	case RuntimeCredentialPhaseStaged:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity,
			agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"active runtime credential changed before staged replay",
			)
		}
		stagedExists := false
		if _, stagedErr := os.Lstat(
			rt.stagedIdentity,
		); stagedErr == nil {
			_, stagedBytes, _, loadErr := rt.loadIdentity(
				rt.stagedIdentity,
				agentGID,
			)
			if loadErr != nil ||
				runtimeCredentialDigest(stagedBytes) !=
					status.StagedIdentitySHA256 {
				return RuntimeCredentialStatus{}, false, errors.New(
					"staged runtime credential state is inconsistent",
				)
			}
			stagedExists = true
		} else if !errors.Is(stagedErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, false, errors.New(
				"stat staged runtime credential during replay",
			)
		}
		if _, wipingErr := os.Lstat(
			rt.wipingIdentity,
		); !errors.Is(wipingErr, os.ErrNotExist) {
			return RuntimeCredentialStatus{}, false, errors.New(
				"staged runtime credential has an unfinished identity wipe",
			)
		}
		if !rt.currentTime().Before(status.StagedExpiresAt) {
			status.Phase = RuntimeCredentialPhaseExpired
			status.ActiveIdentitySHA256 =
				status.PreviousIdentitySHA256
			status.activeRuntimeTokenSHA256 =
				status.previousRuntimeTokenSHA256
			if err := rt.saveStatus(status); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
			if stagedExists {
				if err := rt.wipeAndRemoveIdentity(
					rt.stagedIdentity,
					agentGID,
					status.StagedIdentitySHA256,
				); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
			}
		}
	case RuntimeCredentialPhaseLocalStaged,
		RuntimeCredentialPhaseProofReady:
		_, stagedBytes, _, stagedErr := rt.loadIdentity(
			rt.stagedIdentity, agentGID,
		)
		if stagedErr != nil ||
			runtimeCredentialDigest(stagedBytes) != status.StagedIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"staged runtime credential state is inconsistent",
			)
		}
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil {
			return RuntimeCredentialStatus{}, false, activeErr
		}
		activeDigest := runtimeCredentialDigest(activeBytes)
		if status.Phase == RuntimeCredentialPhaseProofReady &&
			activeDigest == status.StagedIdentitySHA256 {
			// The server activation and atomic identity replacement completed,
			// but the process stopped before writing its secret-free metadata.
			status.Phase = RuntimeCredentialPhaseActivated
			status.RotationRevision++
			status.ActiveIdentitySHA256 = status.StagedIdentitySHA256
			status.activeRuntimeTokenSHA256 =
				status.stagedRuntimeTokenSHA256
			if err := rt.saveStatus(status); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
			if err := rt.wipeAndRemoveIdentity(
				rt.stagedIdentity, agentGID, status.StagedIdentitySHA256,
			); err != nil {
				return RuntimeCredentialStatus{}, false, err
			}
		} else {
			if activeDigest != status.PreviousIdentitySHA256 {
				return RuntimeCredentialStatus{}, false, errors.New(
					"active runtime credential changed before staged expiry",
				)
			}
			if !rt.currentTime().Before(status.StagedExpiresAt) {
				// The control plane is unreachable or the lane was abandoned.
				// Keep the active identity byte-for-byte unchanged, persist a
				// root-owned tombstone, and remove only the staged secret.
				status.Phase = RuntimeCredentialPhaseExpired
				status.ActiveIdentitySHA256 =
					status.PreviousIdentitySHA256
				status.activeRuntimeTokenSHA256 =
					status.previousRuntimeTokenSHA256
				if err := rt.saveStatus(status); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
				if err := rt.wipeAndRemoveIdentity(
					rt.stagedIdentity,
					agentGID,
					status.StagedIdentitySHA256,
				); err != nil {
					return RuntimeCredentialStatus{}, false, err
				}
			}
		}
	case RuntimeCredentialPhaseActivated:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) != status.ActiveIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"active runtime credential state is inconsistent",
			)
		}
		if err := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity, agentGID, status.StagedIdentitySHA256,
		); err != nil {
			return RuntimeCredentialStatus{}, false, err
		}
	case RuntimeCredentialPhaseCancelReady:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"cancel-ready runtime credential active identity changed",
			)
		}
		if wipeErr := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity,
			agentGID,
			status.StagedIdentitySHA256,
		); wipeErr != nil {
			return RuntimeCredentialStatus{}, false, wipeErr
		}
		if !rt.identityCleanupComplete() {
			return RuntimeCredentialStatus{}, false, errors.New(
				"cancel-ready runtime credential cleanup is incomplete",
			)
		}
	case RuntimeCredentialPhaseExpired:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.PreviousIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"expired runtime credential active identity changed",
			)
		}
		if wipeErr := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity,
			agentGID,
			status.StagedIdentitySHA256,
		); wipeErr != nil {
			return RuntimeCredentialStatus{}, false, wipeErr
		}
	case RuntimeCredentialPhaseManualRecovered:
		_, activeBytes, _, activeErr := rt.loadIdentity(
			rt.activeIdentity, agentGID,
		)
		if activeErr != nil ||
			runtimeCredentialDigest(activeBytes) !=
				status.ActiveIdentitySHA256 {
			return RuntimeCredentialStatus{}, false, errors.New(
				"manually recovered runtime credential active identity changed",
			)
		}
		if wipeErr := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity,
			agentGID,
			status.StagedIdentitySHA256,
		); wipeErr != nil {
			return RuntimeCredentialStatus{}, false, wipeErr
		}
	}
	return status, true, nil
}

func (rt runtimeCredentialExecutorRuntime) bindClaimPreparedStagedIdentity(
	status RuntimeCredentialStatus,
	agentGID uint32,
	panelURL string,
) (RuntimeCredentialStatus, bool, error) {
	if status.Phase != RuntimeCredentialPhaseClaimPrepared {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential claim binding phase is invalid",
		)
	}
	if _, wipingErr := os.Lstat(
		rt.wipingIdentity,
	); !errors.Is(wipingErr, os.ErrNotExist) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"claim-prepared runtime credential has an unfinished identity wipe",
		)
	}
	if _, stagedErr := os.Lstat(
		rt.stagedIdentity,
	); errors.Is(stagedErr, os.ErrNotExist) {
		return status, false, nil
	} else if stagedErr != nil {
		return RuntimeCredentialStatus{}, false, errors.New(
			"stat claim-prepared staged runtime credential",
		)
	}
	staged, stagedBytes, _, err := rt.loadIdentity(
		rt.stagedIdentity,
		agentGID,
	)
	stagedTokenDigest := runtimeCredentialTokenDigest(
		staged.RuntimeToken,
	)
	if err != nil ||
		staged.PanelURL != panelURL ||
		staged.NodeID != status.ServiceID ||
		staged.ServiceName != status.serviceName ||
		!validBoundedSecret(staged.RuntimeToken) ||
		stagedTokenDigest == status.previousRuntimeTokenSHA256 {
		return RuntimeCredentialStatus{}, false, errors.New(
			"claim-prepared staged runtime credential is unsafe",
		)
	}
	// Compatibility recovery for an older executor that wrote the fixed
	// staged slot before advancing its root ledger. New executors persist this
	// exact digest and token hash before creating the file.
	status.Phase = RuntimeCredentialPhaseStaged
	status.RotationRevision++
	status.StagedIdentitySHA256 =
		runtimeCredentialDigest(stagedBytes)
	status.stagedRuntimeTokenSHA256 = stagedTokenDigest
	if err := rt.saveStatus(status); err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	return status, true, nil
}

func (rt runtimeCredentialExecutorRuntime) bindStageBoundInstalledIdentity(
	status RuntimeCredentialStatus,
	agentGID uint32,
	panelURL string,
) (RuntimeCredentialStatus, bool, error) {
	if status.Phase != RuntimeCredentialPhaseStageBound {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential stage-bound phase is invalid",
		)
	}
	if _, wipingErr := os.Lstat(
		rt.wipingIdentity,
	); !errors.Is(wipingErr, os.ErrNotExist) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"stage-bound runtime credential has an unfinished identity wipe",
		)
	}
	if _, stagedErr := os.Lstat(
		rt.stagedIdentity,
	); errors.Is(stagedErr, os.ErrNotExist) {
		return status, false, nil
	} else if stagedErr != nil {
		return RuntimeCredentialStatus{}, false, errors.New(
			"stat stage-bound runtime credential",
		)
	}
	staged, stagedBytes, _, err := rt.loadIdentity(
		rt.stagedIdentity,
		agentGID,
	)
	if err != nil ||
		staged.NodeID != status.ServiceID ||
		staged.ServiceName != status.serviceName ||
		(panelURL != "" && staged.PanelURL != panelURL) ||
		runtimeCredentialDigest(stagedBytes) !=
			status.StagedIdentitySHA256 ||
		runtimeCredentialTokenDigest(staged.RuntimeToken) !=
			status.stagedRuntimeTokenSHA256 {
		return RuntimeCredentialStatus{}, false, errors.New(
			"stage-bound runtime credential file changed",
		)
	}
	status.Phase = RuntimeCredentialPhaseStaged
	if err := rt.saveStatus(status); err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	return status, true, nil
}

func (rt runtimeCredentialExecutorRuntime) cleanupExpiredOrphanedStagedIdentity(
	agentGID uint32,
) error {
	if _, err := os.Lstat(rt.wipingIdentity); err == nil {
		if wipeErr := rt.wipeAndRemoveIdentity(
			rt.stagedIdentity,
			agentGID,
			"",
		); wipeErr != nil {
			return wipeErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("stat orphaned Host Agent identity wipe")
	}
	if _, err := os.Lstat(rt.stagedIdentity); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("stat orphaned staged Host Agent identity")
	}
	staged, stagedBytes, stagedInfo, err := rt.loadIdentity(
		rt.stagedIdentity, agentGID,
	)
	if err != nil {
		return err
	}
	if rt.currentTime().Before(
		stagedInfo.ModTime().UTC().Add(runtimeCredentialStagedMaxAge),
	) {
		return nil
	}
	active, _, _, err := rt.loadIdentity(rt.activeIdentity, agentGID)
	if err != nil ||
		staged.PanelURL != active.PanelURL ||
		staged.NodeID != active.NodeID ||
		staged.ServiceName != active.ServiceName ||
		staged.RuntimeToken == active.RuntimeToken {
		return errors.New(
			"expired orphaned staged Host Agent identity is unsafe",
		)
	}
	return rt.wipeAndRemoveIdentity(
		rt.stagedIdentity,
		agentGID,
		runtimeCredentialDigest(stagedBytes),
	)
}

func runtimeCredentialRequestMatchesStatus(
	request LocalExecutorRequest,
	status RuntimeCredentialStatus,
) bool {
	mutation := request.RuntimeCredential
	return mutation != nil &&
		request.ServiceID == status.ServiceID &&
		mutation.RotationID == status.RotationID &&
		mutation.ExecutionHostID == status.ExecutionHostID &&
		mutation.PreviousTokenID == status.PreviousTokenID &&
		mutation.StagedTokenID == status.StagedTokenID &&
		request.OwnershipEpoch == status.OwnershipEpoch &&
		request.SourcePolicyRevision == status.SourcePolicyRevision &&
		request.OwnershipPolicyRevision == status.ProjectionRevision &&
		request.ExecutorPolicyRevision == status.LocalExecutorPolicyRevision
}

func validateRuntimeCredentialPanelTransition(
	rotation HostAgentRuntimeTokenRotation,
	current RuntimeCredentialStatus,
	expectedStatus string,
	expectedRevision int64,
) error {
	if err := rotation.Validate(); err != nil ||
		rotation.ID != current.RotationID ||
		rotation.ServiceID != current.ServiceID ||
		rotation.ExecutionHostID != current.ExecutionHostID ||
		rotation.PreviousTokenID != current.PreviousTokenID ||
		rotation.StagedTokenID != current.StagedTokenID ||
		rotation.ExpectedOwnershipEpoch != current.OwnershipEpoch ||
		rotation.ExpectedSourcePolicyRevision != current.SourcePolicyRevision ||
		rotation.ExpectedProjectionRevision != current.ProjectionRevision ||
		rotation.ExpectedLocalExecutorPolicyRevision != current.LocalExecutorPolicyRevision ||
		rotation.Status != expectedStatus ||
		rotation.Revision != expectedRevision {
		return fmt.Errorf(
			"%w: panel transition binding is invalid",
			errRuntimeCredentialPrecondition,
		)
	}
	return nil
}

func runtimeCredentialResponse(
	status RuntimeCredentialStatus,
) LocalExecutorResponse {
	response := LocalExecutorResponse{
		Version:           LocalExecutorMutationProtocolVersion,
		RuntimeCredential: &status,
	}
	if err := response.Validate(); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "internal_error",
		)
	}
	return response
}

func marshalRuntimeCredentialIdentity(identity Config) ([]byte, error) {
	return marshalManagedBootstrapConfig(identity)
}

func decodeRuntimeCredentialIdentity(data []byte) (Config, error) {
	return decodeManagedBootstrapConfig(data)
}

func runtimeCredentialDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func runtimeCredentialTokenDigest(token string) string {
	return runtimeCredentialDigest([]byte(token))
}

func (rt runtimeCredentialExecutorRuntime) secureMode(
	actual os.FileMode,
	expected os.FileMode,
) bool {
	// Windows does not faithfully round-trip Unix permission bits. Production
	// execution always uses the fixed Linux paths, so only explicit test roots
	// may skip that platform-inapplicable assertion.
	return actual.Perm() == expected ||
		(rt.allowTestPaths && !snapshotModeEnforced())
}

func (rt runtimeCredentialExecutorRuntime) validateIdentityDirectory(
	agentGID uint32,
) error {
	info, err := os.Lstat(rt.identityDir)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		!rt.secureMode(info.Mode(), 0o750) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, agentGID)) {
		return errors.New(
			"Host Agent identity directory must be root:agent-group 0750",
		)
	}
	return nil
}

func (rt runtimeCredentialExecutorRuntime) loadIdentity(
	path string,
	agentGID uint32,
) (Config, []byte, os.FileInfo, error) {
	if err := rt.validateIdentityDirectory(agentGID); err != nil {
		return Config{}, nil, nil, err
	}
	info, err := os.Lstat(path)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!rt.secureMode(info.Mode(), 0o640) ||
		info.Size() <= 0 ||
		info.Size() > configMaxBytes ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, agentGID)) {
		return Config{}, nil, nil, errors.New(
			"Host Agent identity must be a bounded root:agent-group 0640 regular file",
		)
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil {
		return Config{}, nil, nil, err
	}
	defer file.Close()
	if (!rt.allowTestPaths &&
		!runtimeCredentialOwnedBy(openedInfo, 0, agentGID)) ||
		!rt.secureMode(openedInfo.Mode(), 0o640) {
		return Config{}, nil, nil, errors.New(
			"Host Agent identity owner or mode changed during secure open",
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, configMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > configMaxBytes {
		return Config{}, nil, nil, errors.New("read Host Agent identity")
	}
	identity, err := decodeRuntimeCredentialIdentity(data)
	if err != nil {
		return Config{}, nil, nil, err
	}
	return identity, data, openedInfo, nil
}

func (rt runtimeCredentialExecutorRuntime) writeIdentityAtomic(
	path string,
	data []byte,
	agentGID uint32,
	replace bool,
) error {
	if err := rt.validateIdentityDirectory(agentGID); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > configMaxBytes {
		return errors.New("runtime credential identity payload is invalid")
	}
	if existing, err := os.Lstat(path); err == nil {
		if !replace {
			return errRuntimeCredentialBusy
		}
		if existing.Mode()&os.ModeSymlink != 0 ||
			!existing.Mode().IsRegular() ||
			!rt.secureMode(existing.Mode(), 0o640) ||
			(!rt.allowTestPaths &&
				!runtimeCredentialOwnedBy(existing, 0, agentGID)) {
			return errors.New("existing Host Agent identity is unsafe")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("stat Host Agent identity destination")
	}
	temp, err := os.CreateTemp(rt.identityDir, ".identity.runtime-*")
	if err != nil {
		return errRuntimeCredentialStateUnavailable
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if !rt.allowTestPaths {
		if err := temp.Chown(0, int(agentGID)); err != nil {
			_ = temp.Close()
			return errRuntimeCredentialStateUnavailable
		}
	}
	if err := temp.Chmod(0o640); err != nil {
		_ = temp.Close()
		return errRuntimeCredentialStateUnavailable
	}
	if _, err := temp.Write(data); err != nil ||
		temp.Sync() != nil {
		_ = temp.Close()
		return errRuntimeCredentialStateUnavailable
	}
	tempInfo, err := temp.Stat()
	if err != nil ||
		!rt.secureMode(tempInfo.Mode(), 0o640) ||
		(!rt.allowTestPaths &&
			!runtimeCredentialOwnedBy(tempInfo, 0, agentGID)) {
		_ = temp.Close()
		return errors.New("runtime credential temporary identity is unsafe")
	}
	if err := temp.Close(); err != nil {
		return errRuntimeCredentialStateUnavailable
	}
	if err := rt.validateIdentityDirectory(agentGID); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		switch inspectPreparedRenameOutcome(tempPath, path, tempInfo) {
		case preparedRenameInstalled:
			if syncErr := syncDirectory(rt.identityDir); syncErr != nil {
				return errors.Join(err, syncErr)
			}
			return fmt.Errorf(
				"runtime credential identity installed but rename reported an error: %w",
				err,
			)
		case preparedRenameNotInstalled:
			return fmt.Errorf("install runtime credential identity: %w", err)
		default:
			return fmt.Errorf(
				"runtime credential identity install result is uncertain: %w",
				err,
			)
		}
	}
	return syncDirectory(rt.identityDir)
}

func (rt runtimeCredentialExecutorRuntime) loadStatus() (
	RuntimeCredentialStatus,
	bool,
	error,
) {
	info, err := os.Lstat(rt.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return RuntimeCredentialStatus{}, false, nil
	}
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!rt.secureMode(info.Mode(), 0o600) ||
		info.Size() <= 0 ||
		info.Size() > runtimeCredentialStateMaxBytes ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, 0)) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential metadata is unsafe",
		)
	}
	file, openedInfo, err := openVerifiedConfig(rt.statePath, info)
	if err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	defer file.Close()
	if !rt.secureMode(openedInfo.Mode(), 0o600) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(openedInfo, 0, 0)) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential metadata owner changed during secure open",
		)
	}
	data, err := io.ReadAll(io.LimitReader(
		file, runtimeCredentialStateMaxBytes+1,
	))
	if err != nil ||
		len(data) == 0 ||
		len(data) > runtimeCredentialStateMaxBytes {
		return RuntimeCredentialStatus{}, false, errors.New(
			"read runtime credential metadata",
		)
	}
	var persisted runtimeCredentialStateFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&persisted); err != nil {
		return RuntimeCredentialStatus{}, false, errors.New(
			"decode runtime credential metadata",
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RuntimeCredentialStatus{}, false, errors.New(
			"runtime credential metadata contains trailing data",
		)
	}
	status := persisted.RuntimeCredentialStatus
	status.previousRuntimeTokenSHA256 =
		persisted.PreviousRuntimeTokenSHA256
	status.stagedRuntimeTokenSHA256 =
		persisted.StagedRuntimeTokenSHA256
	status.activeRuntimeTokenSHA256 =
		persisted.ActiveRuntimeTokenSHA256
	status.serviceName = persisted.ServiceName
	if err := status.Validate(); err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	if err := status.validateRootTokenBindings(); err != nil {
		return RuntimeCredentialStatus{}, false, err
	}
	return status, true, nil
}

func (rt runtimeCredentialExecutorRuntime) saveStatus(
	status RuntimeCredentialStatus,
) error {
	if err := status.Validate(); err != nil {
		return err
	}
	if err := status.validateRootTokenBindings(); err != nil {
		return err
	}
	parent := filepath.Dir(rt.statePath)
	info, err := os.Lstat(parent)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		!rt.secureMode(info.Mode(), 0o700) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, 0)) {
		return errors.New("runtime credential state directory is unsafe")
	}
	data, err := json.Marshal(runtimeCredentialStateFile{
		RuntimeCredentialStatus:    status,
		PreviousRuntimeTokenSHA256: status.previousRuntimeTokenSHA256,
		StagedRuntimeTokenSHA256:   status.stagedRuntimeTokenSHA256,
		ActiveRuntimeTokenSHA256:   status.activeRuntimeTokenSHA256,
		ServiceName:                status.serviceName,
	})
	if err != nil || len(data) == 0 ||
		len(data)+1 > runtimeCredentialStateMaxBytes {
		return errors.New("encode runtime credential metadata")
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(parent, ".runtime-credential-*")
	if err != nil {
		return errRuntimeCredentialStateUnavailable
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if !rt.allowTestPaths {
		if err := temp.Chown(0, 0); err != nil {
			_ = temp.Close()
			return errRuntimeCredentialStateUnavailable
		}
	}
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return errRuntimeCredentialStateUnavailable
	}
	if _, err := temp.Write(data); err != nil ||
		temp.Sync() != nil {
		_ = temp.Close()
		return errRuntimeCredentialStateUnavailable
	}
	tempInfo, err := temp.Stat()
	if err != nil ||
		!rt.secureMode(tempInfo.Mode(), 0o600) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(tempInfo, 0, 0)) {
		_ = temp.Close()
		return errors.New("runtime credential temporary metadata is unsafe")
	}
	if err := temp.Close(); err != nil {
		return errRuntimeCredentialStateUnavailable
	}
	if err := os.Rename(tempPath, rt.statePath); err != nil {
		switch inspectPreparedRenameOutcome(tempPath, rt.statePath, tempInfo) {
		case preparedRenameInstalled:
			if syncErr := syncDirectory(parent); syncErr != nil {
				return errors.Join(err, syncErr)
			}
			return fmt.Errorf(
				"runtime credential metadata installed but rename reported an error: %w",
				err,
			)
		case preparedRenameNotInstalled:
			return fmt.Errorf("install runtime credential metadata: %w", err)
		default:
			return fmt.Errorf(
				"runtime credential metadata install result is uncertain: %w",
				err,
			)
		}
	}
	return syncDirectory(parent)
}

func (rt runtimeCredentialExecutorRuntime) removeState() error {
	info, err := os.Lstat(rt.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!rt.secureMode(info.Mode(), 0o600) ||
		(!rt.allowTestPaths && !runtimeCredentialOwnedBy(info, 0, 0)) {
		return errors.New("runtime credential metadata is unsafe")
	}
	if err := os.Remove(rt.statePath); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(rt.statePath))
}

func (rt runtimeCredentialExecutorRuntime) wipeAndRemoveIdentity(
	path string,
	agentGID uint32,
	expectedDigest string,
) error {
	if path != rt.stagedIdentity {
		return errors.New("runtime credential cleanup path is invalid")
	}
	stagedInfo, stagedErr := os.Lstat(rt.stagedIdentity)
	wipingInfo, wipingErr := os.Lstat(rt.wipingIdentity)
	if stagedErr != nil && !errors.Is(stagedErr, os.ErrNotExist) {
		return errors.New("stat staged Host Agent identity for cleanup")
	}
	if wipingErr != nil && !errors.Is(wipingErr, os.ErrNotExist) {
		return errors.New("stat quarantined Host Agent identity for cleanup")
	}
	if stagedErr == nil && wipingErr == nil {
		return errors.New(
			"staged and quarantined Host Agent identities both exist",
		)
	}
	if errors.Is(wipingErr, os.ErrNotExist) {
		if errors.Is(stagedErr, os.ErrNotExist) {
			return nil
		}
		if !rt.secureStagedIdentityInfo(stagedInfo, agentGID, false) {
			return errors.New("staged Host Agent identity is unsafe")
		}
		file, openedInfo, err := openVerifiedConfig(
			rt.stagedIdentity,
			stagedInfo,
		)
		if err != nil ||
			!rt.secureStagedIdentityInfo(openedInfo, agentGID, false) {
			if file != nil {
				_ = file.Close()
			}
			return errors.New(
				"staged Host Agent identity changed before cleanup",
			)
		}
		data, readErr := io.ReadAll(
			io.LimitReader(file, configMaxBytes+1),
		)
		closeErr := file.Close()
		if readErr != nil ||
			closeErr != nil ||
			len(data) == 0 ||
			len(data) > configMaxBytes ||
			runtimeCredentialDigest(data) != expectedDigest {
			return errors.New(
				"staged Host Agent identity digest changed before cleanup",
			)
		}
		if err := os.Rename(
			rt.stagedIdentity,
			rt.wipingIdentity,
		); err != nil {
			return errors.New(
				"quarantine staged Host Agent identity for cleanup",
			)
		}
		if err := syncDirectory(rt.identityDir); err != nil {
			return errors.New(
				"sync Host Agent identity quarantine",
			)
		}
		wipingInfo, wipingErr = os.Lstat(rt.wipingIdentity)
		if wipingErr != nil ||
			!os.SameFile(stagedInfo, wipingInfo) {
			return errors.New(
				"quarantined Host Agent identity changed during cleanup",
			)
		}
	}
	if !rt.secureStagedIdentityInfo(wipingInfo, agentGID, true) {
		return errors.New("quarantined Host Agent identity is unsafe")
	}
	file, err := os.OpenFile(rt.wipingIdentity, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil ||
		!os.SameFile(wipingInfo, openedInfo) ||
		!rt.secureStagedIdentityInfo(openedInfo, agentGID, true) {
		_ = file.Close()
		return errors.New(
			"quarantined Host Agent identity changed before cleanup",
		)
	}
	var wipeErr error
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		wipeErr = errors.Join(wipeErr, errors.New("seek staged Host Agent identity for cleanup"))
	} else {
		zeroes := make([]byte, 32*1024)
		remaining := openedInfo.Size()
		for remaining > 0 {
			chunk := int64(len(zeroes))
			if remaining < chunk {
				chunk = remaining
			}
			if _, err := file.Write(zeroes[:int(chunk)]); err != nil {
				wipeErr = errors.Join(
					wipeErr,
					errors.New("overwrite staged Host Agent identity during cleanup"),
				)
				break
			}
			remaining -= chunk
		}
		if err := file.Sync(); err != nil {
			wipeErr = errors.Join(
				wipeErr,
				errors.New("sync staged Host Agent identity overwrite"),
			)
		}
		if err := file.Truncate(0); err != nil {
			wipeErr = errors.Join(
				wipeErr,
				errors.New("truncate staged Host Agent identity during cleanup"),
			)
		}
		if err := file.Sync(); err != nil {
			wipeErr = errors.Join(
				wipeErr,
				errors.New("sync staged Host Agent identity truncation"),
			)
		}
	}
	if err := file.Close(); err != nil {
		wipeErr = errors.Join(
			wipeErr,
			errors.New("close staged Host Agent identity during cleanup"),
		)
	}
	current, err := os.Lstat(rt.wipingIdentity)
	if err != nil || !os.SameFile(wipingInfo, current) {
		return errors.New(
			"quarantined Host Agent identity changed before unlink",
		)
	}
	if err := os.Remove(rt.wipingIdentity); err != nil {
		return err
	}
	if err := syncDirectory(rt.identityDir); err != nil {
		wipeErr = errors.Join(
			wipeErr,
			errors.New("sync Host Agent identity directory after cleanup"),
		)
	}
	return wipeErr
}

func (rt runtimeCredentialExecutorRuntime) secureStagedIdentityInfo(
	info os.FileInfo,
	agentGID uint32,
	allowEmpty bool,
) bool {
	if info == nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!rt.secureMode(info.Mode(), 0o640) ||
		info.Size() > configMaxBytes ||
		(!allowEmpty && info.Size() <= 0) {
		return false
	}
	return rt.allowTestPaths ||
		runtimeCredentialOwnedBy(info, 0, agentGID)
}

func (rt runtimeCredentialExecutorRuntime) identityCleanupComplete() bool {
	_, stagedErr := os.Lstat(rt.stagedIdentity)
	_, wipingErr := os.Lstat(rt.wipingIdentity)
	return errors.Is(stagedErr, os.ErrNotExist) &&
		errors.Is(wipingErr, os.ErrNotExist)
}
