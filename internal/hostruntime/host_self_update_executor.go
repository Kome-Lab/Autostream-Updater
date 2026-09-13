package hostruntime

import (
	"context"
	"errors"
	"fmt"
	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	hostSelfUpdateServiceUnit           = "autostream-host-agent.service"
	hostSelfUpdateExecutorServiceUnit   = "autostream-local-executor.service"
	hostSelfUpdateExecutorSocketUnit    = "autostream-local-executor.socket"
	hostSelfUpdateBinaryIdentityTimeout = 2 * time.Second
	hostSelfUpdateDetachedVerifyTimeout = 3 * time.Second
	hostSelfUpdateSystemdExecutorProbes = 8
)

type hostAgentReleaseDownloader interface {
	DownloadHostAgentRelease(context.Context, string, string, string) (HostAgentRelease, error)
}

type hostSelfUpdateExecutorRuntime struct {
	installRoot         string
	currentLink         string
	slotsRoot           string
	stateRoot           string
	statePath           string
	grantStatePath      string
	downloadRoot        string
	arch                string
	executorVersion     string
	downloader          hostAgentReleaseDownloader
	runner              CommandRunner
	identityRunner      CommandRunner
	now                 func() time.Time
	verificationTimeout time.Duration
	verificationParent  context.Context
	switchCurrentHook   func(string) error
	consumeGrant        hostSelfUpdateGrantConsumer
	resolveProcessExe   func(int) (string, error)
	waitExecutorStable  func(context.Context) error
	watchdogStatus      func(context.Context) (HostSelfUpdateRuntimeStatus, error)
	syncDir             func(string) error
	writeState          func(string, []byte, os.FileMode) error
	allowTestPaths      bool
}

func defaultHostSelfUpdateExecutorRuntime() hostSelfUpdateExecutorRuntime {
	return hostSelfUpdateExecutorRuntime{
		installRoot:         HostSelfUpdateInstallRoot,
		currentLink:         HostSelfUpdateCurrentLink,
		slotsRoot:           HostSelfUpdateSlotsRoot,
		stateRoot:           HostSelfUpdateStateRoot,
		statePath:           HostSelfUpdateStatePath,
		grantStatePath:      HostSelfUpdateGrantStatePath,
		downloadRoot:        filepath.Join(HostSelfUpdateStateRoot, "downloads"),
		arch:                runtime.GOARCH,
		executorVersion:     controlversion.Current(),
		downloader:          ReleaseDownloader{TrustedPublicOnly: true},
		runner:              OSCommandRunner{NewProcessGroup: true},
		identityRunner:      hostSelfUpdateIdentityCommandRunner{},
		now:                 time.Now,
		verificationTimeout: defaultHostSelfUpdateVerificationTimeout,
		consumeGrant:        consumeHostSelfUpdateGrant,
		resolveProcessExe: func(pid int) (string, error) {
			return filepath.EvalSymlinks(
				fmt.Sprintf("/proc/%d/exe", pid),
			)
		},
		waitExecutorStable: func(ctx context.Context) error {
			timer := time.NewTimer(250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
		watchdogStatus: (LocalExecutorClient{
			SocketPath: LocalExecutorSocketPath,
		}).HostSelfUpdateWatchdogStatus,
		syncDir:    syncDirectory,
		writeState: writeAtomicFile,
	}
}

func handleLocalExecutorHostSelfUpdate(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	rt hostSelfUpdateExecutorRuntime,
) LocalExecutorResponse {
	if err := request.Validate(); err != nil ||
		!strings.HasPrefix(request.Operation, "host_self_update_") {
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
	if request.ServiceID != policy.HostID ||
		request.SourcePolicyRevision != policy.SourcePolicyRevision ||
		request.OwnershipPolicyRevision != policy.ProjectionRevision ||
		request.ExecutorPolicyRevision != policy.PolicyRevision {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "config_mismatch",
		)
	}
	rt.verificationParent = ctx
	if err := rt.prepare(); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "state_unavailable",
		)
	}

	var (
		status HostSelfUpdateRuntimeStatus
		err    error
	)
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    request.SourcePolicyRevision,
		OwnershipEpoch:          request.OwnershipEpoch,
		OwnershipPolicyRevision: request.OwnershipPolicyRevision,
		ExecutorPolicyRevision:  request.ExecutorPolicyRevision,
	}
	switch request.Operation {
	case "host_self_update_status":
		status, err = rt.status()
	case "host_self_update_stage":
		status, err = rt.status()
		if err != nil {
			break
		}
		authorization := *request.HostSelfUpdateGrant
		if err = validateHostSelfUpdateGrantReplayBinding(
			policy,
			fence,
			"stage",
			request.HostSelfUpdate,
			nil,
			authorization,
		); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "authorization_failed",
			)
		}
		var grantPhase string
		var grantMatches bool
		grantPhase, grantMatches, err = rt.hostSelfUpdateGrantPhase(
			authorization,
		)
		if err != nil {
			break
		}
		if grantMatches &&
			grantPhase == hostSelfUpdateGrantPhaseApplied {
			if !rt.hostSelfUpdateStateEffectMatchesGrant(
				status.State,
				authorization.Binding,
			) {
				err = errors.New(
					"applied host self-update stage grant contradicts runtime state",
				)
			}
			break
		}
		if grantMatches &&
			grantPhase == hostSelfUpdateGrantPhaseFailed {
			if status.State.Phase != HostSelfUpdatePhaseStable ||
				status.State.FailedGeneration !=
					authorization.Binding.AttemptGeneration {
				err = errors.New(
					"failed host self-update stage grant contradicts runtime state",
				)
			}
			break
		}
		if grantMatches &&
			grantPhase == hostSelfUpdateGrantPhaseConsumed &&
			status.State.Phase == HostSelfUpdatePhaseStaged &&
			rt.hostSelfUpdateStateEffectMatchesGrant(
				status.State,
				authorization.Binding,
			) {
			err = rt.markHostSelfUpdateGrantApplied(authorization)
			break
		}
		if err = validateHostSelfUpdateGrantForOperation(
			policy,
			fence,
			"stage",
			request.HostSelfUpdate,
			status.State,
			authorization,
		); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "authorization_failed",
			)
		}
		if err = rt.authorizeHostSelfUpdate(
			ctx,
			policy.Mutation.PanelURL,
			authorization,
		); err != nil {
			if errors.Is(err, errHostSelfUpdateGrantUncertain) {
				status, err = rt.failClosedUncertainStage(
					status,
					*request.HostSelfUpdate,
					authorization,
				)
				break
			}
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion,
				"authorization_failed",
			)
		}
		var applied bool
		applied, err = rt.hostSelfUpdateGrantApplied(authorization)
		if err != nil {
			break
		}
		if applied {
			if !rt.hostSelfUpdateStateEffectMatchesGrant(
				status.State,
				authorization.Binding,
			) {
				err = errors.New(
					"applied host self-update stage grant contradicts runtime state",
				)
			}
			break
		}
		status, err = rt.stage(ctx, *request.HostSelfUpdate)
		if err != nil {
			stageErr := err
			var applied bool
			var convergenceErr error
			status, applied, convergenceErr =
				rt.convergeHostSelfUpdateStageAfterError(
					*request.HostSelfUpdate,
					authorization,
				)
			switch {
			case convergenceErr != nil:
				err = errors.Join(
					stageErr,
					fmt.Errorf(
						"converge host self-update stage error: %w",
						convergenceErr,
					),
				)
			case applied:
				err = nil
			default:
				err = stageErr
			}
			break
		}
		err = rt.markHostSelfUpdateGrantApplied(authorization)
	case "host_self_update_activate":
		status, err = rt.activate(ctx, request.HostSelfUpdateGeneration)
	case "host_self_update_reconcile":
		status, err = rt.status()
		if err != nil {
			break
		}
		if request.HostSelfUpdateGrant == nil {
			if status.State.Phase != HostSelfUpdatePhaseStable ||
				status.CurrentSlot == status.State.ActiveSlot ||
				*request.HostSelfUpdateProof != (HostSelfUpdateAgentProof{}) {
				return localExecutorFailureForVersion(
					LocalExecutorMutationProtocolVersion, "authorization_failed",
				)
			}
			status, err = rt.reconcile(ctx, *request.HostSelfUpdateProof)
			break
		}
		authorization := *request.HostSelfUpdateGrant
		if err = validateHostSelfUpdateGrantReplayBinding(
			policy,
			fence,
			"reconcile",
			nil,
			request.HostSelfUpdateProof,
			authorization,
		); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "authorization_failed",
			)
		}
		var grantPhase string
		var grantMatches bool
		grantPhase, grantMatches, err = rt.hostSelfUpdateGrantPhase(
			authorization,
		)
		if err != nil {
			break
		}
		if grantMatches &&
			grantPhase == hostSelfUpdateGrantPhaseApplied {
			if !rt.hostSelfUpdateStateEffectMatchesGrant(
				status.State,
				authorization.Binding,
			) {
				err = errors.New(
					"applied host self-update reconcile grant contradicts runtime state",
				)
			}
			break
		}
		if grantMatches &&
			grantPhase == hostSelfUpdateGrantPhaseConsumed &&
			status.State.Phase == HostSelfUpdatePhaseStable &&
			rt.hostSelfUpdateStateEffectMatchesGrant(
				status.State,
				authorization.Binding,
			) {
			err = rt.markHostSelfUpdateGrantApplied(authorization)
			break
		}
		if err = validateHostSelfUpdateGrantForOperation(
			policy,
			fence,
			"reconcile",
			nil,
			status.State,
			authorization,
		); err != nil {
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, "authorization_failed",
			)
		}
		if err = rt.authorizeHostSelfUpdate(
			ctx,
			policy.Mutation.PanelURL,
			authorization,
		); err != nil {
			code := "authorization_failed"
			if errors.Is(err, errHostSelfUpdateGrantUncertain) {
				code = "authorization_uncertain"
			}
			return localExecutorFailureForVersion(
				LocalExecutorMutationProtocolVersion, code,
			)
		}
		var applied bool
		applied, err = rt.hostSelfUpdateGrantApplied(authorization)
		if err != nil {
			break
		}
		if applied {
			if !rt.hostSelfUpdateStateEffectMatchesGrant(
				status.State,
				authorization.Binding,
			) {
				err = errors.New(
					"applied host self-update reconcile grant contradicts runtime state",
				)
			}
			break
		}
		status, err = rt.reconcile(ctx, *request.HostSelfUpdateProof)
		if err == nil {
			err = rt.markHostSelfUpdateGrantApplied(authorization)
		}
	default:
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "invalid_request",
		)
	}
	if err != nil {
		code := "state_invalid"
		switch {
		case errors.Is(err, errHostSelfUpdateBusy):
			code = "target_busy"
		case errors.Is(err, errHostSelfUpdateStage):
			code = "stage_failed"
		case errors.Is(err, errHostSelfUpdateRollback):
			code = "rollback_failed"
		case errors.Is(err, errHostSelfUpdatePrecondition):
			code = "mutation_precondition_failed"
		}
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, code,
		)
	}
	response := LocalExecutorResponse{
		Version:        LocalExecutorMutationProtocolVersion,
		HostSelfUpdate: &status,
	}
	if err := response.Validate(); err != nil {
		return localExecutorFailureForVersion(
			LocalExecutorMutationProtocolVersion, "internal_error",
		)
	}
	return response
}

var (
	errHostSelfUpdateBusy         = errors.New("host self-update busy")
	errHostSelfUpdateStage        = errors.New("host self-update stage failed")
	errHostSelfUpdateRollback     = errors.New("host self-update rollback failed")
	errHostSelfUpdatePrecondition = errors.New("host self-update precondition failed")
)
