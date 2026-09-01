package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
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

func (rt *hostSelfUpdateExecutorRuntime) prepare() error {
	if rt.arch == "" {
		rt.arch = runtime.GOARCH
	}
	if rt.executorVersion == "" {
		rt.executorVersion = controlversion.Current()
	}
	if rt.downloader == nil {
		rt.downloader = ReleaseDownloader{TrustedPublicOnly: true}
	}
	if rt.runner == nil {
		rt.runner = OSCommandRunner{NewProcessGroup: true}
	}
	if rt.now == nil {
		rt.now = time.Now
	}
	if rt.verificationTimeout == 0 {
		rt.verificationTimeout = defaultHostSelfUpdateVerificationTimeout
	}
	if rt.grantStatePath == "" && rt.allowTestPaths {
		rt.grantStatePath = filepath.Join(rt.stateRoot, "grant.json")
	}
	if rt.verificationTimeout < 30*time.Second ||
		rt.verificationTimeout > 30*time.Minute {
		return errors.New("host self-update verification timeout is invalid")
	}
	if rt.consumeGrant == nil {
		rt.consumeGrant = consumeHostSelfUpdateGrant
	}
	if rt.resolveProcessExe == nil {
		rt.resolveProcessExe = func(pid int) (string, error) {
			return filepath.EvalSymlinks(
				fmt.Sprintf("/proc/%d/exe", pid),
			)
		}
	}
	if rt.waitExecutorStable == nil {
		rt.waitExecutorStable = func(ctx context.Context) error {
			timer := time.NewTimer(250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}
	if rt.watchdogStatus == nil {
		rt.watchdogStatus = (LocalExecutorClient{
			SocketPath: LocalExecutorSocketPath,
		}).HostSelfUpdateWatchdogStatus
	}
	if rt.syncDir == nil {
		rt.syncDir = syncDirectory
	}
	if !rt.allowTestPaths {
		if rt.installRoot != HostSelfUpdateInstallRoot ||
			rt.currentLink != HostSelfUpdateCurrentLink ||
			rt.slotsRoot != HostSelfUpdateSlotsRoot ||
			rt.stateRoot != HostSelfUpdateStateRoot ||
			rt.statePath != HostSelfUpdateStatePath ||
			rt.grantStatePath != HostSelfUpdateGrantStatePath ||
			rt.downloadRoot != filepath.Join(HostSelfUpdateStateRoot, "downloads") {
			return errors.New("host self-update paths are not the fixed production roots")
		}
	}
	for _, candidate := range []string{
		rt.installRoot, rt.currentLink, rt.slotsRoot,
		rt.stateRoot, rt.statePath, rt.grantStatePath, rt.downloadRoot,
	} {
		if !filepath.IsAbs(candidate) ||
			filepath.Clean(candidate) == string(filepath.Separator) {
			return errors.New("host self-update path is invalid")
		}
	}
	if filepath.Dir(rt.currentLink) != filepath.Clean(rt.installRoot) ||
		filepath.Dir(rt.slotsRoot) != filepath.Clean(rt.installRoot) ||
		filepath.Dir(rt.statePath) != filepath.Clean(rt.stateRoot) ||
		filepath.Dir(rt.grantStatePath) != filepath.Clean(rt.stateRoot) ||
		filepath.Dir(rt.downloadRoot) != filepath.Clean(rt.stateRoot) {
		return errors.New("host self-update paths escaped their fixed roots")
	}
	if rt.arch != "amd64" && rt.arch != "arm64" {
		return errors.New("host self-update architecture is unsupported")
	}
	if !versionPattern.MatchString(rt.executorVersion) {
		return errors.New("host self-update executor version is invalid")
	}
	if err := rt.ensureRoots(); err != nil {
		return err
	}
	return rt.recoverHostSelfUpdateSlotArtifacts()
}

func (rt hostSelfUpdateExecutorRuntime) ensureRoots() error {
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{rt.installRoot, 0o755},
		{rt.slotsRoot, 0o755},
		{rt.stateRoot, 0o700},
		{rt.downloadRoot, 0o700},
	} {
		if _, err := missingHostSelfUpdateDirectories(directory.path); err != nil {
			return err
		}
		if err := os.MkdirAll(directory.path, directory.mode); err != nil {
			return err
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return err
		}
		info, err := os.Lstat(directory.path)
		if err != nil || !info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != directory.mode.Perm() {
			return errors.New("host self-update directory is unsafe")
		}
		if !rt.allowTestPaths && !isRootOwner(info) {
			return errors.New("host self-update directory is not root-owned")
		}
		for current := filepath.Clean(directory.path); ; {
			if err := rt.syncHostSelfUpdateDirectory(current); err != nil {
				return fmt.Errorf(
					"sync host self-update directory %s: %w",
					filepath.Base(current),
					err,
				)
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	return nil
}

func missingHostSelfUpdateDirectories(path string) ([]string, error) {
	path = filepath.Clean(path)
	missing := make([]string, 0, 4)
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New(
					"host self-update directory ancestor is unsafe",
				)
			}
			return missing, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return nil, errors.New(
				"host self-update directory has no durable ancestor",
			)
		}
	}
}

func (rt hostSelfUpdateExecutorRuntime) recoverHostSelfUpdateSlotArtifacts() error {
	entries, err := os.ReadDir(rt.slotsRoot)
	if err != nil {
		return err
	}
	type artifacts struct {
		newPaths []string
		oldPaths []string
	}
	bySlot := map[string]*artifacts{
		HostSelfUpdateSlotA: {},
		HostSelfUpdateSlotB: {},
	}
	for _, entry := range entries {
		slot, suffix, ok := parseHostSelfUpdateSlotArtifactName(entry.Name())
		if !ok {
			if looksLikeReservedHostSelfUpdateSlotArtifactName(entry.Name()) {
				return errors.New(
					"host self-update slot artifact name is malformed",
				)
			}
			continue
		}
		info, err := entry.Info()
		if err != nil ||
			!info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			(runtime.GOOS != "windows" &&
				info.Mode().Perm()&0o022 != 0) ||
			(!rt.allowTestPaths && !isRootOwner(info)) {
			return errors.New("host self-update slot artifact is unsafe")
		}
		path := filepath.Join(rt.slotsRoot, entry.Name())
		if !pathWithin(rt.slotsRoot, path) {
			return errors.New("host self-update slot artifact escaped the slots root")
		}
		if suffix == "new" {
			bySlot[slot].newPaths = append(bySlot[slot].newPaths, path)
		} else {
			bySlot[slot].oldPaths = append(bySlot[slot].oldPaths, path)
		}
	}
	for _, slot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		if len(bySlot[slot].newPaths) > 1 ||
			len(bySlot[slot].oldPaths) > 1 {
			return errors.New(
				"multiple host self-update slot artifacts require manual recovery",
			)
		}
	}
	var (
		recoveryState       *HostSelfUpdateState
		recoveryStateLoaded bool
	)
	loadRecoveryState := func() (*HostSelfUpdateState, error) {
		if recoveryStateLoaded {
			return recoveryState, nil
		}
		recoveryStateLoaded = true
		state, err := rt.loadPersistedState()
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		recoveryState = &state
		return recoveryState, nil
	}
	for _, slot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		slotArtifacts := bySlot[slot]
		slotRoot := filepath.Join(rt.slotsRoot, slot)
		info, slotErr := os.Lstat(slotRoot)
		switch {
		case slotErr == nil:
			if !info.IsDir() ||
				info.Mode()&os.ModeSymlink != 0 ||
				(runtime.GOOS != "windows" &&
					info.Mode().Perm()&0o022 != 0) ||
				(!rt.allowTestPaths && !isRootOwner(info)) {
				return errors.New("host self-update slot is unsafe")
			}
			if len(slotArtifacts.oldPaths) == 1 {
				state, err := loadRecoveryState()
				if err != nil {
					return fmt.Errorf(
						"load host self-update state for slot recovery: %w",
						err,
					)
				}
				if state == nil {
					return errors.New(
						"host self-update slot backup requires durable state",
					)
				}
				switch {
				case state.Phase == HostSelfUpdatePhaseStable &&
					slot != state.ActiveSlot:
					if len(slotArtifacts.newPaths) != 0 {
						return errors.New(
							"ambiguous host self-update candidate recovery requires manual recovery",
						)
					}
					if err := rt.restoreUncommittedHostSelfUpdateSlot(
						slotRoot,
						slotArtifacts.oldPaths[0],
					); err != nil {
						return err
					}
					slotArtifacts.oldPaths = nil
				case state.Phase != HostSelfUpdatePhaseStable &&
					slot == state.PendingSlot:
					if err := rt.verifyPendingHostSelfUpdateSlotForRecovery(
						*state,
						slotRoot,
					); err != nil {
						return fmt.Errorf(
							"pending host self-update slot cannot release its backup: %w",
							err,
						)
					}
				case slot == state.ActiveSlot &&
					slot == state.HealthySlot:
					// A live healthy slot is authoritative. The backup is a
					// stale artifact from an already durable prior transaction.
				default:
					return errors.New(
						"host self-update slot backup contradicts durable state",
					)
				}
			} else {
				state, err := loadRecoveryState()
				if err != nil {
					return fmt.Errorf(
						"load host self-update state for slot recovery: %w",
						err,
					)
				}
				if state != nil &&
					state.Phase != HostSelfUpdatePhaseStable &&
					slot == state.PendingSlot {
					if err := rt.verifyPendingHostSelfUpdateSlotForRecovery(
						*state,
						slotRoot,
					); err != nil {
						return fmt.Errorf(
							"pending host self-update slot is invalid: %w",
							err,
						)
					}
				}
			}
		case errors.Is(slotErr, os.ErrNotExist):
			if len(slotArtifacts.oldPaths) == 1 {
				if err := os.Rename(
					slotArtifacts.oldPaths[0],
					slotRoot,
				); err != nil {
					return err
				}
				if err := rt.syncHostSelfUpdateDirectory(
					rt.slotsRoot,
				); err != nil {
					return err
				}
				slotArtifacts.oldPaths = nil
			} else {
				state, err := loadRecoveryState()
				if err != nil {
					return fmt.Errorf(
						"load host self-update state for slot recovery: %w",
						err,
					)
				}
				if state != nil &&
					state.Phase != HostSelfUpdatePhaseStable &&
					slot == state.PendingSlot {
					if len(slotArtifacts.newPaths) != 1 {
						return errors.New(
							"pending host self-update slot candidate is unavailable",
						)
					}
					temporary := filepath.Join(
						rt.slotsRoot,
						"."+slot+"-"+shortID(state.PendingGeneration)+".new",
					)
					if filepath.Clean(slotArtifacts.newPaths[0]) !=
						filepath.Clean(temporary) {
						return errors.New(
							"pending host self-update slot candidate contradicts durable state",
						)
					}
					if err := rt.verifyPendingHostSelfUpdateSlotForRecovery(
						*state,
						temporary,
					); err != nil {
						return fmt.Errorf(
							"pending host self-update slot candidate is invalid: %w",
							err,
						)
					}
					if err := os.Rename(temporary, slotRoot); err != nil {
						return err
					}
					if err := rt.syncHostSelfUpdateDirectory(
						rt.slotsRoot,
					); err != nil {
						return fmt.Errorf(
							"sync promoted host self-update slot: %w",
							err,
						)
					}
					if err := rt.verifyPendingHostSelfUpdateSlotForRecovery(
						*state,
						slotRoot,
					); err != nil {
						return fmt.Errorf(
							"promoted host self-update slot is invalid: %w",
							err,
						)
					}
					slotArtifacts.newPaths = nil
				}
			}
		default:
			return slotErr
		}
		for _, artifact := range append(
			slotArtifacts.newPaths,
			slotArtifacts.oldPaths...,
		) {
			if err := rt.removeHostSelfUpdateSlotArtifact(artifact); err != nil {
				return err
			}
		}
	}
	return rt.syncHostSelfUpdateDirectory(rt.slotsRoot)
}

func (rt hostSelfUpdateExecutorRuntime) restoreUncommittedHostSelfUpdateSlot(
	slotRoot string,
	backup string,
) error {
	if filepath.Dir(filepath.Clean(slotRoot)) != filepath.Clean(rt.slotsRoot) ||
		filepath.Dir(filepath.Clean(backup)) != filepath.Clean(rt.slotsRoot) ||
		!strings.HasSuffix(backup, ".old") {
		return errors.New("host self-update recovery paths are invalid")
	}
	temporary := strings.TrimSuffix(backup, ".old") + ".new"
	if _, err := os.Lstat(temporary); err == nil {
		return errors.New(
			"host self-update recovery quarantine already exists",
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := rt.restoreHostSelfUpdateSlot(
		slotRoot,
		temporary,
		backup,
		true,
	); err != nil {
		return err
	}
	return rt.removeHostSelfUpdateSlotArtifact(temporary)
}

func (rt hostSelfUpdateExecutorRuntime) verifyPendingHostSelfUpdateSlotForRecovery(
	state HostSelfUpdateState,
	slotRoot string,
) error {
	if state.Phase == HostSelfUpdatePhaseStable ||
		!validHostSelfUpdateSlot(state.PendingSlot) ||
		!pathWithin(rt.slotsRoot, slotRoot) ||
		(filepath.Clean(slotRoot) !=
			filepath.Join(rt.slotsRoot, state.PendingSlot) &&
			filepath.Dir(filepath.Clean(slotRoot)) !=
				filepath.Clean(rt.slotsRoot)) {
		return errors.New("pending host self-update recovery state is invalid")
	}
	request := HostSelfUpdateRequest{
		Generation:              state.PendingGeneration,
		AgentVersion:            state.PendingAgentVersion,
		ExecutorVersion:         state.PendingExecutorVersion,
		Commit:                  state.PendingCommit,
		ArtifactSHA256:          state.PendingArtifactSHA256,
		AgentProtocolVersion:    state.PendingAgentProtocol,
		ExecutorProtocolVersion: state.PendingExecutorProtocol,
		MutationProtocolVersion: state.PendingMutationProtocol,
		RecoveryProtocolVersion: state.PendingRecoveryProtocol,
		Release:                 state.PendingRelease,
	}
	ctx, cancel := rt.hostSelfUpdateDetachedVerificationContext()
	defer cancel()
	return rt.verifyHostSelfUpdateSlot(
		ctx,
		state.PendingSlot,
		slotRoot,
		request,
		hostSelfUpdateSlotDigests{
			AgentSHA256:    state.PendingAgentSHA256,
			ExecutorSHA256: state.PendingExecutorSHA256,
		},
	)
}

func (rt hostSelfUpdateExecutorRuntime) hostSelfUpdateDetachedVerificationContext() (
	context.Context,
	context.CancelFunc,
) {
	parent := rt.verificationParent
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, hostSelfUpdateDetachedVerifyTimeout)
}

func parseHostSelfUpdateSlotArtifactName(
	name string,
) (string, string, bool) {
	for _, slot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		prefix := "." + slot + "-"
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		for _, suffix := range []string{"new", "old"} {
			ending := "." + suffix
			if !strings.HasSuffix(name, ending) {
				continue
			}
			digest := strings.TrimSuffix(
				strings.TrimPrefix(name, prefix),
				ending,
			)
			if len(digest) != 12 {
				return "", "", false
			}
			for _, character := range digest {
				if (character < '0' || character > '9') &&
					(character < 'a' || character > 'f') {
					return "", "", false
				}
			}
			return slot, suffix, true
		}
	}
	return "", "", false
}

func looksLikeReservedHostSelfUpdateSlotArtifactName(name string) bool {
	for _, slot := range []string{
		HostSelfUpdateSlotA,
		HostSelfUpdateSlotB,
	} {
		if strings.HasPrefix(name, "."+slot+"-") &&
			(strings.HasSuffix(name, ".new") ||
				strings.HasSuffix(name, ".old")) {
			return true
		}
	}
	return false
}

func (rt hostSelfUpdateExecutorRuntime) status() (HostSelfUpdateRuntimeStatus, error) {
	return rt.statusWithGrantRecovery(true)
}

func (rt hostSelfUpdateExecutorRuntime) mutationStatus() (
	HostSelfUpdateRuntimeStatus,
	error,
) {
	return rt.statusWithGrantRecovery(false)
}

func (rt hostSelfUpdateExecutorRuntime) statusWithGrantRecovery(
	recoverGrant bool,
) (HostSelfUpdateRuntimeStatus, error) {
	currentSlot, err := rt.readCurrentSlot()
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	state, err := rt.loadState(currentSlot)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if recoverGrant {
		state, err = rt.recoverDurableHostSelfUpdateGrant(state)
		if err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	}
	status := HostSelfUpdateRuntimeStatus{
		State: state, CurrentSlot: currentSlot,
		ExecutorVersion:         rt.executorVersion,
		ExecutorProtocolVersion: LocalExecutorMutationProtocolVersion,
		LastAction:              HostSelfUpdateActionNone,
	}
	if err := status.validate(); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	return status, nil
}

func (rt hostSelfUpdateExecutorRuntime) stage(
	ctx context.Context,
	request HostSelfUpdateRequest,
) (HostSelfUpdateRuntimeStatus, error) {
	current, err := rt.mutationStatus()
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if current.State.Phase != HostSelfUpdatePhaseStable {
		return HostSelfUpdateRuntimeStatus{}, errHostSelfUpdateBusy
	}
	if current.CurrentSlot != current.State.ActiveSlot ||
		current.CurrentSlot != current.State.HealthySlot {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf(
				"%w: stable current slot drift must be reconciled",
				errHostSelfUpdatePrecondition,
			)
	}
	if request.Generation == current.State.FailedGeneration {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf("%w: failed generation replay rejected", errHostSelfUpdatePrecondition)
	}
	if !updaterReleaseSemverAtLeast(
		request.AgentVersion, current.State.ActiveAgentVersion,
	) || !updaterReleaseSemverAtLeast(
		request.ExecutorVersion, current.State.ActiveExecutorVersion,
	) {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf("%w: downgrade rejected", errHostSelfUpdatePrecondition)
	}

	downloadDir := filepath.Join(
		rt.downloadRoot, "generation-"+shortID(request.Generation),
	)
	if !pathWithin(rt.downloadRoot, downloadDir) {
		return HostSelfUpdateRuntimeStatus{}, errHostSelfUpdateStage
	}
	if err := os.RemoveAll(downloadDir); err != nil {
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf("%w: clear download", errHostSelfUpdateStage)
	}
	if err := os.Mkdir(downloadDir, 0o700); err != nil {
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf("%w: create download", errHostSelfUpdateStage)
	}
	defer os.RemoveAll(downloadDir)
	release, err := rt.downloader.DownloadHostAgentRelease(
		ctx, request.AgentVersion, rt.arch, downloadDir,
	)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf("%w: verify release", errHostSelfUpdateStage)
	}
	if !hostSelfUpdateReleaseMatchesRequest(release, request) {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf("%w: release binding mismatch", errHostSelfUpdatePrecondition)
	}
	slotDigests, err := hostSelfUpdateArtifactBinaryDigests(
		release.Artifact.RootDir,
	)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf("%w: binary identity: %v", errHostSelfUpdateStage, err)
	}
	next, err := StageHostSelfUpdate(
		current.State,
		request,
		HostLifecycleBlockers{},
		slotDigests,
	)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf("%w: %v", errHostSelfUpdatePrecondition, err)
	}
	if err := rt.stageSlot(
		ctx,
		next.PendingSlot,
		release.Artifact.RootDir,
		request,
		slotDigests,
	); err != nil {
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf("%w: %v", errHostSelfUpdateStage, err)
	}
	if err := rt.saveState(next); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := rt.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf("finalize staged host self-update slot: %w", err)
	}
	current.State = next
	current.LastAction = HostSelfUpdateActionNone
	return current, nil
}

func hostSelfUpdateReleaseMatchesRequest(
	release HostAgentRelease,
	request HostSelfUpdateRequest,
) bool {
	return release.Request.validate() == nil &&
		request.validate() == nil &&
		release.Request.AgentVersion == request.AgentVersion &&
		release.Request.ExecutorVersion == request.ExecutorVersion &&
		release.Request.Commit == request.Commit &&
		release.Request.ArtifactSHA256 == request.ArtifactSHA256 &&
		release.Request.AgentProtocolVersion == request.AgentProtocolVersion &&
		release.Request.ExecutorProtocolVersion == request.ExecutorProtocolVersion &&
		release.Request.MutationProtocolVersion == request.MutationProtocolVersion &&
		release.Request.RecoveryProtocolVersion == request.RecoveryProtocolVersion &&
		sameHostSelfUpdateReleaseIdentity(
			release.Request.Release,
			request.Release,
		) &&
		release.PublishedAt.Equal(request.Release.PublishedAt) &&
		release.MinimumPanelVersion == request.Release.MinimumPanelVersion
}

func (rt hostSelfUpdateExecutorRuntime) stageSlot(
	ctx context.Context,
	slot, artifactRoot string,
	request HostSelfUpdateRequest,
	slotDigests hostSelfUpdateSlotDigests,
) (resultErr error) {
	if !validHostSelfUpdateSlot(slot) ||
		!filepath.IsAbs(artifactRoot) ||
		request.validate() != nil ||
		slotDigests.validate() != nil {
		return errors.New("host self-update stage identity is invalid")
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	if !pathWithin(rt.slotsRoot, slotRoot) {
		return errors.New("host self-update slot escaped the slots root")
	}
	if err := rt.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return fmt.Errorf("recover interrupted host self-update slot: %w", err)
	}
	temporary := filepath.Join(
		rt.slotsRoot, "."+slot+"-"+shortID(request.Generation)+".new",
	)
	backup := filepath.Join(
		rt.slotsRoot, "."+slot+"-"+shortID(request.Generation)+".old",
	)
	for _, candidate := range []string{temporary, backup} {
		if !pathWithin(rt.slotsRoot, candidate) {
			return errors.New("host self-update temporary slot escaped the slots root")
		}
		if err := rt.removeHostSelfUpdateSlotArtifact(candidate); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(temporary, "bin"), 0o755); err != nil {
		return err
	}
	for _, directory := range []string{
		temporary,
		filepath.Join(temporary, "bin"),
	} {
		if err := os.Chmod(directory, 0o755); err != nil {
			return err
		}
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if err := rt.removeHostSelfUpdateSlotArtifact(temporary); err != nil &&
			resultErr == nil {
			resultErr = err
		}
	}()

	binaryDigests := make(map[string]string, 2)
	for _, binary := range []struct {
		name    string
		version string
	}{
		{"autostream-host-agent", request.AgentVersion},
		{"autostream-local-executor", request.ExecutorVersion},
	} {
		source := filepath.Join(artifactRoot, "bin", binary.name)
		destination := filepath.Join(temporary, "bin", binary.name)
		if err := copyHostSelfUpdateBinary(source, destination); err != nil {
			return err
		}
		if err := rt.verifyHostSelfUpdateBinaryIdentity(
			ctx,
			temporary,
			binary.name,
			binary.version,
			request,
		); err != nil {
			return err
		}
		digest, err := hashFile(destination)
		if err != nil || !isCanonicalBareSHA256(digest) {
			return fmt.Errorf("hash staged %s", binary.name)
		}
		expectedDigest := slotDigests.AgentSHA256
		if binary.name == "autostream-local-executor" {
			expectedDigest = slotDigests.ExecutorSHA256
		}
		if digest != expectedDigest {
			return fmt.Errorf("staged %s digest changed during copy", binary.name)
		}
		binaryDigests[binary.name] = digest
	}
	markers, err := hostSelfUpdateSlotMarkers(request, binaryDigests)
	if err != nil {
		return err
	}
	for name, value := range markers {
		if err := writeAtomicFile(
			filepath.Join(temporary, name), value, 0o444,
		); err != nil {
			return err
		}
	}
	if err := rt.syncHostSelfUpdateDirectory(
		filepath.Join(temporary, "bin"),
	); err != nil {
		return fmt.Errorf("sync staged host self-update binaries: %w", err)
	}
	if err := rt.syncHostSelfUpdateDirectory(temporary); err != nil {
		return fmt.Errorf("sync staged host self-update slot: %w", err)
	}
	if err := rt.verifyHostSelfUpdateSlot(
		ctx,
		slot,
		temporary,
		request,
		slotDigests,
	); err != nil {
		return err
	}

	hadBackup := false
	if info, err := os.Lstat(slotRoot); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("inactive host self-update slot is unsafe")
		}
		if err := os.Rename(slotRoot, backup); err != nil {
			return err
		}
		hadBackup = true
		if err := rt.syncHostSelfUpdateDirectory(rt.slotsRoot); err != nil {
			restoreErr := rt.restoreHostSelfUpdateSlot(
				slotRoot, temporary, backup, hadBackup,
			)
			return errors.Join(
				fmt.Errorf("sync host self-update slot backup: %w", err),
				restoreErr,
			)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !hadBackup {
		if err := rt.syncHostSelfUpdateDirectory(rt.slotsRoot); err != nil {
			return fmt.Errorf(
				"sync reserved host self-update slot candidate: %w",
				err,
			)
		}
		committed = true
		return nil
	}
	if err := os.Rename(temporary, slotRoot); err != nil {
		restoreErr := rt.restoreHostSelfUpdateSlot(
			slotRoot, temporary, backup, hadBackup,
		)
		return errors.Join(err, restoreErr)
	}
	if err := rt.syncHostSelfUpdateDirectory(rt.slotsRoot); err != nil {
		restoreErr := rt.restoreHostSelfUpdateSlot(
			slotRoot, temporary, backup, hadBackup,
		)
		return errors.Join(
			fmt.Errorf("sync committed host self-update slot: %w", err),
			restoreErr,
		)
	}
	if err := rt.verifyHostSelfUpdateSlot(
		ctx,
		slot,
		slotRoot,
		request,
		slotDigests,
	); err != nil {
		restoreErr := rt.restoreHostSelfUpdateSlot(
			slotRoot, temporary, backup, hadBackup,
		)
		return errors.Join(err, restoreErr)
	}
	committed = true
	return nil
}

func hostSelfUpdateArtifactBinaryDigests(
	artifactRoot string,
) (hostSelfUpdateSlotDigests, error) {
	if !filepath.IsAbs(artifactRoot) {
		return hostSelfUpdateSlotDigests{},
			errors.New("host self-update artifact root is invalid")
	}
	var digests hostSelfUpdateSlotDigests
	for _, binary := range []struct {
		name        string
		destination *string
	}{
		{"autostream-host-agent", &digests.AgentSHA256},
		{"autostream-local-executor", &digests.ExecutorSHA256},
	} {
		path := filepath.Join(artifactRoot, "bin", binary.name)
		if !pathWithin(artifactRoot, path) {
			return hostSelfUpdateSlotDigests{},
				errors.New("host self-update artifact binary escaped its root")
		}
		info, err := os.Lstat(path)
		if err != nil ||
			!info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 {
			return hostSelfUpdateSlotDigests{},
				fmt.Errorf("host self-update artifact %s is unsafe", binary.name)
		}
		digest, err := hashFile(path)
		if err != nil || !isCanonicalBareSHA256(digest) {
			return hostSelfUpdateSlotDigests{},
				fmt.Errorf("hash host self-update artifact %s", binary.name)
		}
		*binary.destination = digest
	}
	if err := digests.validate(); err != nil {
		return hostSelfUpdateSlotDigests{}, err
	}
	return digests, nil
}

func (rt hostSelfUpdateExecutorRuntime) syncHostSelfUpdateDirectory(
	path string,
) error {
	if rt.syncDir != nil {
		return rt.syncDir(path)
	}
	return syncDirectory(path)
}

func (rt hostSelfUpdateExecutorRuntime) removeHostSelfUpdateSlotArtifact(
	path string,
) error {
	if !pathWithin(rt.slotsRoot, path) ||
		filepath.Dir(filepath.Clean(path)) != filepath.Clean(rt.slotsRoot) {
		return errors.New("host self-update slot artifact escaped the slots root")
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return rt.syncHostSelfUpdateDirectory(rt.slotsRoot)
}

func (rt hostSelfUpdateExecutorRuntime) restoreHostSelfUpdateSlot(
	slotRoot, temporary, backup string,
	hadBackup bool,
) error {
	if info, err := os.Lstat(slotRoot); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("failed host self-update slot is unsafe")
		}
		if _, temporaryErr := os.Lstat(temporary); temporaryErr == nil {
			if err := os.RemoveAll(temporary); err != nil {
				return err
			}
		} else if !errors.Is(temporaryErr, os.ErrNotExist) {
			return temporaryErr
		}
		if err := os.Rename(slotRoot, temporary); err != nil {
			return err
		}
		if err := rt.syncHostSelfUpdateDirectory(rt.slotsRoot); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if hadBackup {
		info, err := os.Lstat(backup)
		if err != nil ||
			!info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 {
			return errors.New("host self-update slot backup is unavailable")
		}
		if err := os.Rename(backup, slotRoot); err != nil {
			return err
		}
		if err := rt.syncHostSelfUpdateDirectory(rt.slotsRoot); err != nil {
			return err
		}
	}
	return nil
}

func hostSelfUpdateSlotMarkers(
	request HostSelfUpdateRequest,
	binaryDigests map[string]string,
) (map[string][]byte, error) {
	if err := request.validate(); err != nil ||
		!isCanonicalBareSHA256(
			binaryDigests["autostream-host-agent"],
		) ||
		!isCanonicalBareSHA256(
			binaryDigests["autostream-local-executor"],
		) {
		return nil, errors.New("host self-update slot binding is invalid")
	}
	releaseJSON, err := json.Marshal(request.Release)
	if err != nil {
		return nil, err
	}
	line := func(value string) []byte {
		return []byte(value + "\n")
	}
	return map[string][]byte{
		".generation":            line(request.Generation),
		".agent-version":         line(request.AgentVersion),
		".executor-version":      line(request.ExecutorVersion),
		".commit":                line(request.Commit),
		".artifact-sha256":       line(request.ArtifactSHA256),
		".agent-protocol":        line(strconv.Itoa(request.AgentProtocolVersion)),
		".executor-protocol":     line(strconv.Itoa(request.ExecutorProtocolVersion)),
		".mutation-protocol":     line(strconv.Itoa(request.MutationProtocolVersion)),
		".recovery-protocol":     line(strconv.Itoa(request.RecoveryProtocolVersion)),
		".agent-sha256":          line(binaryDigests["autostream-host-agent"]),
		".local-executor-sha256": line(binaryDigests["autostream-local-executor"]),
		".release-binding.json":  append(releaseJSON, '\n'),
	}, nil
}

func (rt hostSelfUpdateExecutorRuntime) verifyHostSelfUpdateSlot(
	ctx context.Context,
	slot, slotRoot string,
	request HostSelfUpdateRequest,
	slotDigests hostSelfUpdateSlotDigests,
) error {
	if !validHostSelfUpdateSlot(slot) ||
		filepath.Clean(slotRoot) != filepath.Join(rt.slotsRoot, slot) &&
			filepath.Dir(filepath.Clean(slotRoot)) != filepath.Clean(rt.slotsRoot) ||
		!pathWithin(rt.slotsRoot, slotRoot) ||
		request.validate() != nil ||
		slotDigests.validate() != nil {
		return errors.New("host self-update slot verification identity is invalid")
	}
	if err := rt.validateHostSelfUpdateSlotTreeRoot(slotRoot); err != nil {
		return err
	}
	releaseJSON, err := json.Marshal(request.Release)
	if err != nil {
		return err
	}
	expected := map[string][]byte{
		".generation":           []byte(request.Generation + "\n"),
		".agent-version":        []byte(request.AgentVersion + "\n"),
		".executor-version":     []byte(request.ExecutorVersion + "\n"),
		".commit":               []byte(request.Commit + "\n"),
		".artifact-sha256":      []byte(request.ArtifactSHA256 + "\n"),
		".agent-protocol":       []byte(strconv.Itoa(request.AgentProtocolVersion) + "\n"),
		".executor-protocol":    []byte(strconv.Itoa(request.ExecutorProtocolVersion) + "\n"),
		".mutation-protocol":    []byte(strconv.Itoa(request.MutationProtocolVersion) + "\n"),
		".recovery-protocol":    []byte(strconv.Itoa(request.RecoveryProtocolVersion) + "\n"),
		".release-binding.json": append(releaseJSON, '\n'),
	}
	for name, want := range expected {
		got, err := readHostSelfUpdateSlotMarker(
			filepath.Join(slotRoot, name),
			!rt.allowTestPaths,
		)
		if err != nil || !bytes.Equal(got, want) {
			return fmt.Errorf("host self-update slot marker %s is invalid", name)
		}
	}
	for _, binary := range []struct {
		name         string
		version      string
		digestMarker string
	}{
		{
			"autostream-host-agent",
			request.AgentVersion,
			".agent-sha256",
		},
		{
			"autostream-local-executor",
			request.ExecutorVersion,
			".local-executor-sha256",
		},
	} {
		digestBytes, err := readHostSelfUpdateSlotMarker(
			filepath.Join(slotRoot, binary.digestMarker),
			!rt.allowTestPaths,
		)
		digest := strings.TrimSuffix(string(digestBytes), "\n")
		if err != nil || !isCanonicalBareSHA256(digest) {
			return fmt.Errorf(
				"host self-update slot digest %s is invalid",
				binary.digestMarker,
			)
		}
		binaryPath := filepath.Join(slotRoot, "bin", binary.name)
		actualDigest, err := hashFile(binaryPath)
		if err != nil || actualDigest != digest {
			return fmt.Errorf(
				"host self-update slot binary %s digest is invalid",
				binary.name,
			)
		}
		expectedDigest := slotDigests.AgentSHA256
		if binary.name == "autostream-local-executor" {
			expectedDigest = slotDigests.ExecutorSHA256
		}
		if digest != expectedDigest {
			return fmt.Errorf(
				"host self-update slot binary %s digest contradicts durable state",
				binary.name,
			)
		}
		if err := rt.verifyHostSelfUpdateBinaryIdentity(
			ctx,
			slotRoot,
			binary.name,
			binary.version,
			request,
		); err != nil {
			return err
		}
	}
	return nil
}

func readHostSelfUpdateSlotMarker(
	path string,
	requireRootOwner bool,
) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o444) ||
		(requireRootOwner && !isRootOwner(info)) {
		return nil, errors.New("host self-update slot marker is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(body) == 0 || len(body) > 4096 ||
		body[len(body)-1] != '\n' ||
		bytes.Contains(body[:len(body)-1], []byte{'\n'}) {
		return nil, errors.New("host self-update slot marker is invalid")
	}
	return body, nil
}

func (rt hostSelfUpdateExecutorRuntime) verifyHostSelfUpdateBinaryIdentity(
	ctx context.Context,
	slotRoot, binary, version string,
	request HostSelfUpdateRequest,
) error {
	binaryPath := filepath.Join(slotRoot, "bin", binary)
	if err := validateHostSelfUpdateSlotBinary(
		binaryPath,
		!rt.allowTestPaths,
	); err != nil {
		return fmt.Errorf("staged %s is unsafe", binary)
	}
	// The two fixed slot binaries are checked sequentially. Bounding each
	// identity command at two seconds keeps the complete server-side process
	// validation budget below the Local Executor client's five-second
	// deadline, including the identity runner's short WaitDelay.
	identityContext, cancel := context.WithTimeout(
		ctx,
		hostSelfUpdateBinaryIdentityTimeout,
	)
	defer cancel()
	output, err := hostSelfUpdateIdentityRunner(
		rt.identityRunner,
		rt.runner,
	).Run(
		identityContext,
		slotRoot,
		nil,
		binaryPath,
		"--version",
	)
	if err != nil ||
		!hostSelfUpdateVersionOutputHasLine(
			output,
			binary+" "+version,
		) ||
		!hostSelfUpdateVersionOutputHasLine(
			output,
			"commit: "+request.Commit,
		) {
		return fmt.Errorf("staged %s did not report the trusted identity", binary)
	}
	if binary == "autostream-local-executor" &&
		(!hostSelfUpdateVersionOutputHasLine(
			output,
			fmt.Sprintf(
				"mutation_protocol: %d",
				request.MutationProtocolVersion,
			),
		) ||
			!hostSelfUpdateVersionOutputHasLine(
				output,
				fmt.Sprintf(
					"recovery_protocol: %d",
					request.RecoveryProtocolVersion,
				),
			)) {
		return errors.New(
			"staged autostream-local-executor protocol identity is invalid",
		)
	}
	return nil
}

func hostSelfUpdateVersionOutputHasLine(output, want string) bool {
	for _, line := range strings.Split(
		strings.ReplaceAll(output, "\r\n", "\n"),
		"\n",
	) {
		if line == want {
			return true
		}
	}
	return false
}

func isCanonicalBareSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func copyHostSelfUpdateBinary(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 {
		return errors.New("host self-update binary source is unsafe")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(
		destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755,
	)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = output.Close()
		if remove {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Chmod(0o755); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) activate(
	ctx context.Context,
	generation string,
) (HostSelfUpdateRuntimeStatus, error) {
	status, err := rt.status()
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if status.State.Phase != HostSelfUpdatePhaseStaged ||
		status.State.PendingGeneration != generation {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf("%w: generation is not staged", errHostSelfUpdatePrecondition)
	}
	if status.CurrentSlot != status.State.HealthySlot {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf(
				"%w: healthy rollback slot is not current",
				errHostSelfUpdatePrecondition,
			)
	}
	if err := rt.validateHostSelfUpdateSlotTree(
		status.State.HealthySlot,
	); err != nil {
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf(
				"%w: healthy rollback slot is unsafe: %v",
				errHostSelfUpdatePrecondition,
				err,
			)
	}
	if err := rt.verifyPendingHostSelfUpdateSlot(ctx, status.State); err != nil {
		failed, failErr := rt.failStagedHostSelfUpdate(status.State)
		if failErr != nil {
			return HostSelfUpdateRuntimeStatus{}, errors.Join(err, failErr)
		}
		status.State = failed
		return HostSelfUpdateRuntimeStatus{},
			fmt.Errorf(
				"%w: staged slot verification failed: %v",
				errHostSelfUpdatePrecondition,
				err,
			)
	}
	next, err := BeginHostSelfUpdateActivation(
		status.State,
		rt.now().UTC(),
		rt.verificationTimeout,
	)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := rt.saveState(next); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	if err := rt.switchCurrent(next.PendingSlot); err != nil {
		rollback := beginHostSelfUpdateRollback(next)
		if saveErr := rt.saveState(rollback); saveErr != nil {
			return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
				"%w: switch current failed and rollback fence could not be persisted: %v",
				errHostSelfUpdateRollback,
				saveErr,
			)
		}
		return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
			"%w: switch current failed: %v",
			errHostSelfUpdateRollback,
			err,
		)
	}
	status.State = next
	status.CurrentSlot = next.PendingSlot
	status.LastAction = HostSelfUpdateActionSwitchCurrent
	status.RestartRequested = true
	if err := rt.restartHostAgent(ctx); err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	return status, nil
}

func (rt hostSelfUpdateExecutorRuntime) reconcile(
	ctx context.Context,
	proof HostSelfUpdateAgentProof,
) (HostSelfUpdateRuntimeStatus, error) {
	status, err := rt.mutationStatus()
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	observation := HostSelfUpdateObservation{
		CurrentSlot:           status.CurrentSlot,
		RunningAgentVersion:   proof.RunningAgentVersion,
		PanelHeartbeatVersion: proof.PanelHeartbeatVersion,
		HeartbeatGeneration:   proof.HeartbeatGeneration,
		ExecutorVersion:       rt.executorVersion,
		ExecutorProtocol:      LocalExecutorMutationProtocolVersion,
	}
	if status.State.Phase != HostSelfUpdatePhaseStable &&
		(status.State.Phase == HostSelfUpdatePhaseRollingBack ||
			status.CurrentSlot == status.State.PendingSlot) {
		observation.ExecutorProbeGeneration = status.State.PendingGeneration
		expectedExecutor := status.State.PendingExecutorVersion
		if status.State.Phase == HostSelfUpdatePhaseRollingBack {
			expectedExecutor = status.State.ActiveExecutorVersion
		}
		observation.ExecutorHealthy = rt.executorVersion == expectedExecutor
		if !observation.ExecutorHealthy {
			observation.ExecutorFailureCode = "executor_probe_failed"
		}
	}
	if proof.FailureCode != "" {
		observation.ExecutorHealthy = false
		observation.ExecutorFailureCode = proof.FailureCode
	}
	if (status.State.Phase == HostSelfUpdatePhaseActivating ||
		status.State.Phase == HostSelfUpdatePhaseVerifying) &&
		!rt.now().UTC().Before(status.State.ActivationDeadline) {
		observation.ExecutorHealthy = false
		observation.ExecutorFailureCode = "verification_timeout"
	}
	next, action, err := ReconcileHostSelfUpdate(status.State, observation)
	if err != nil {
		return HostSelfUpdateRuntimeStatus{}, err
	}
	status.State = next
	status.LastAction = action
	switch action {
	case HostSelfUpdateActionSwitchCurrent:
		if err := rt.verifyPendingHostSelfUpdateSlot(ctx, next); err != nil {
			rollback := beginHostSelfUpdateRollback(next)
			if saveErr := rt.saveState(rollback); saveErr != nil {
				return HostSelfUpdateRuntimeStatus{}, errors.Join(
					fmt.Errorf(
						"%w: resumed staged slot verification failed: %v",
						errHostSelfUpdateRollback,
						err,
					),
					saveErr,
				)
			}
			return HostSelfUpdateRuntimeStatus{},
				fmt.Errorf(
					"%w: resumed staged slot verification failed: %v",
					errHostSelfUpdateRollback,
					err,
				)
		}
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		if err := rt.switchCurrent(next.PendingSlot); err != nil {
			rollback := beginHostSelfUpdateRollback(next)
			if saveErr := rt.saveState(rollback); saveErr != nil {
				return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
					"%w: switch current failed and rollback fence could not be persisted: %v",
					errHostSelfUpdateRollback,
					saveErr,
				)
			}
			return HostSelfUpdateRuntimeStatus{}, fmt.Errorf(
				"%w: switch current failed: %v",
				errHostSelfUpdateRollback,
				err,
			)
		}
		status.CurrentSlot = next.PendingSlot
		status.RestartRequested = true
		if err := rt.restartHostAgent(ctx); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	case HostSelfUpdateActionRestoreHealthy:
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		if err := rt.switchCurrent(next.HealthySlot); err != nil {
			return HostSelfUpdateRuntimeStatus{},
				fmt.Errorf("%w: restore current slot", errHostSelfUpdateRollback)
		}
		status.CurrentSlot = next.HealthySlot
		status.RollbackRequested = true
		status.RestartRequested = true
		if err := rt.restartHostAgent(ctx); err != nil {
			return HostSelfUpdateRuntimeStatus{},
				fmt.Errorf("%w: restart healthy agent", errHostSelfUpdateRollback)
		}
	case HostSelfUpdateActionRestartAgent:
		if err := rt.verifyPendingHostSelfUpdateSlot(ctx, next); err != nil {
			rollback := beginHostSelfUpdateRollback(next)
			if saveErr := rt.saveState(rollback); saveErr != nil {
				return HostSelfUpdateRuntimeStatus{}, errors.Join(
					fmt.Errorf(
						"%w: resumed pending slot verification failed: %v",
						errHostSelfUpdateRollback,
						err,
					),
					saveErr,
				)
			}
			return HostSelfUpdateRuntimeStatus{},
				fmt.Errorf(
					"%w: resumed pending slot verification failed: %v",
					errHostSelfUpdateRollback,
					err,
				)
		}
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		status.RestartRequested = true
		if err := rt.restartHostAgent(ctx); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	case HostSelfUpdateActionRestartHealthy:
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
		status.RestartRequested = true
		if err := rt.restartHostAgent(ctx); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	default:
		if err := rt.saveState(next); err != nil {
			return HostSelfUpdateRuntimeStatus{}, err
		}
	}
	return status, nil
}

func (rt hostSelfUpdateExecutorRuntime) verifyPendingHostSelfUpdateSlot(
	ctx context.Context,
	state HostSelfUpdateState,
) error {
	if err := state.validate(); err != nil ||
		state.Phase == HostSelfUpdatePhaseStable {
		return errors.New("pending host self-update state is invalid")
	}
	request := HostSelfUpdateRequest{
		Generation:              state.PendingGeneration,
		AgentVersion:            state.PendingAgentVersion,
		ExecutorVersion:         state.PendingExecutorVersion,
		Commit:                  state.PendingCommit,
		ArtifactSHA256:          state.PendingArtifactSHA256,
		AgentProtocolVersion:    state.PendingAgentProtocol,
		ExecutorProtocolVersion: state.PendingExecutorProtocol,
		MutationProtocolVersion: state.PendingMutationProtocol,
		RecoveryProtocolVersion: state.PendingRecoveryProtocol,
		Release:                 state.PendingRelease,
	}
	return rt.verifyHostSelfUpdateSlot(
		ctx,
		state.PendingSlot,
		filepath.Join(rt.slotsRoot, state.PendingSlot),
		request,
		hostSelfUpdateSlotDigests{
			AgentSHA256:    state.PendingAgentSHA256,
			ExecutorSHA256: state.PendingExecutorSHA256,
		},
	)
}

func (rt hostSelfUpdateExecutorRuntime) failStagedHostSelfUpdate(
	state HostSelfUpdateState,
) (HostSelfUpdateState, error) {
	if err := state.validate(); err != nil ||
		state.Phase != HostSelfUpdatePhaseStaged {
		return HostSelfUpdateState{},
			errors.New("staged host self-update failure state is invalid")
	}
	failed := clearRolledBackHostSelfUpdate(state)
	if err := rt.saveState(failed); err != nil {
		return HostSelfUpdateState{}, err
	}
	if err := rt.cleanFailedHostSelfUpdateGrant(failed); err != nil {
		return HostSelfUpdateState{}, err
	}
	return failed, nil
}

func (rt hostSelfUpdateExecutorRuntime) restartHostAgent(
	ctx context.Context,
) error {
	_, err := rt.runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl",
		"restart", hostSelfUpdateServiceUnit,
	)
	if err != nil {
		return errors.New("restart Host Agent")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) restartLocalExecutor(
	ctx context.Context,
) error {
	_, err := rt.runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl",
		"restart", hostSelfUpdateExecutorServiceUnit,
	)
	if err != nil {
		return errors.New("restart Local Executor")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) verifyHealthyLocalExecutor(
	ctx context.Context,
	healthySlot string,
	state HostSelfUpdateState,
) error {
	if !validHostSelfUpdateSlot(healthySlot) ||
		state.HealthySlot != healthySlot ||
		state.ActiveExecutorVersion == "" {
		return errors.New("healthy Local Executor identity is invalid")
	}
	if err := rt.validateHostSelfUpdateSlotTree(healthySlot); err != nil {
		return errors.New("healthy host self-update slot is unsafe")
	}
	expected := filepath.Join(
		rt.slotsRoot,
		healthySlot,
		"bin",
		"autostream-local-executor",
	)
	info, err := os.Lstat(expected)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 {
		return errors.New("healthy Local Executor binary is unsafe")
	}
	firstPID, err := rt.acquireHealthyLocalExecutorPID(ctx, expected)
	if err != nil {
		return err
	}
	if err := rt.waitExecutorStable(ctx); err != nil {
		return fmt.Errorf("wait for healthy Local Executor stability: %w", err)
	}
	secondPID, err := rt.healthyLocalExecutorPID(ctx, expected)
	if err != nil {
		return err
	}
	if firstPID != secondPID {
		return errors.New(
			"healthy Local Executor MainPID changed during stability probe",
		)
	}
	identityContext, cancel := context.WithTimeout(
		ctx,
		hostSelfUpdateBinaryIdentityTimeout,
	)
	defer cancel()
	versionOutput, err := hostSelfUpdateIdentityRunner(
		rt.identityRunner,
		rt.runner,
	).Run(
		identityContext,
		"/",
		nil,
		expected,
		"--version",
	)
	if err != nil ||
		!strings.Contains(
			versionOutput,
			"autostream-local-executor "+
				state.ActiveExecutorVersion+"\n",
		) ||
		!strings.Contains(
			versionOutput,
			fmt.Sprintf(
				"mutation_protocol: %d\n",
				LocalExecutorMutationProtocolVersion,
			),
		) ||
		!strings.Contains(
			versionOutput,
			fmt.Sprintf(
				"recovery_protocol: %d\n",
				state.RecoveryProtocolVersion,
			),
		) {
		return errors.New(
			"healthy Local Executor version or protocol is invalid",
		)
	}
	socketStatus, err := rt.watchdogStatus(ctx)
	if err != nil ||
		socketStatus.State != state ||
		socketStatus.CurrentSlot != healthySlot ||
		socketStatus.ExecutorVersion != state.ActiveExecutorVersion ||
		socketStatus.ExecutorProtocolVersion !=
			LocalExecutorMutationProtocolVersion ||
		socketStatus.State.RecoveryProtocolVersion !=
			HostSelfUpdateRecoveryProtocolVersion ||
		socketStatus.LastAction != HostSelfUpdateActionNone ||
		socketStatus.RollbackRequested ||
		socketStatus.RestartRequested {
		return errors.New(
			"healthy Local Executor watchdog status handshake is invalid",
		)
	}
	return nil
}

func isHostRuntimeSystemdExecutor(executable string) bool {
	switch filepath.Clean(executable) {
	case "/usr/lib/systemd/systemd-executor",
		"/lib/systemd/systemd-executor":
		return true
	default:
		return false
	}
}

func (rt hostSelfUpdateExecutorRuntime) acquireHealthyLocalExecutorPID(
	ctx context.Context,
	expected string,
) (int, error) {
	pinnedPID := 0
	for probe := 0; probe < hostSelfUpdateSystemdExecutorProbes; probe++ {
		pid, running, err := rt.healthyLocalExecutorProcess(ctx)
		if err != nil {
			return 0, err
		}
		if pinnedPID == 0 {
			pinnedPID = pid
		} else if pid != pinnedPID {
			return 0, errors.New(
				"healthy Local Executor MainPID changed during systemd-executor transition",
			)
		}
		if filepath.Clean(running) == filepath.Clean(expected) {
			return pid, nil
		}
		if !isHostRuntimeSystemdExecutor(running) {
			return 0, errors.New(
				"Local Executor is not running the healthy slot binary",
			)
		}
		if probe+1 == hostSelfUpdateSystemdExecutorProbes {
			return 0, errors.New(
				"healthy Local Executor remained in systemd-executor beyond the startup probe limit",
			)
		}
		if err := rt.waitExecutorStable(ctx); err != nil {
			return 0, fmt.Errorf(
				"wait for healthy Local Executor systemd-executor transition: %w",
				err,
			)
		}
	}
	return 0, errors.New("healthy Local Executor startup probe limit is invalid")
}

func (rt hostSelfUpdateExecutorRuntime) healthyLocalExecutorPID(
	ctx context.Context,
	expected string,
) (int, error) {
	pid, running, err := rt.healthyLocalExecutorProcess(ctx)
	if err != nil {
		return 0, err
	}
	if filepath.Clean(running) != filepath.Clean(expected) {
		return 0, errors.New(
			"Local Executor is not running the healthy slot binary",
		)
	}
	return pid, nil
}

func (rt hostSelfUpdateExecutorRuntime) healthyLocalExecutorProcess(
	ctx context.Context,
) (int, string, error) {
	if err := ctx.Err(); err != nil {
		return 0, "", fmt.Errorf(
			"verify healthy Local Executor process: %w",
			err,
		)
	}
	for _, unit := range []string{
		hostSelfUpdateExecutorSocketUnit,
		hostSelfUpdateExecutorServiceUnit,
	} {
		if _, err := rt.runner.Run(
			ctx,
			"/",
			nil,
			"/usr/bin/systemctl",
			"is-active",
			"--quiet",
			unit,
		); err != nil {
			return 0, "", fmt.Errorf("%s is not active", unit)
		}
	}
	output, err := rt.runner.Run(
		ctx,
		"/",
		nil,
		"/usr/bin/systemctl",
		"show",
		"--property=MainPID",
		"--value",
		hostSelfUpdateExecutorServiceUnit,
	)
	if err != nil {
		return 0, "", errors.New("read healthy Local Executor MainPID")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil || pid <= 0 {
		return 0, "", errors.New("healthy Local Executor has no MainPID")
	}
	running, err := rt.resolveProcessExe(pid)
	if err != nil {
		return 0, "", errors.New("resolve healthy Local Executor executable")
	}
	return pid, running, nil
}

func (rt hostSelfUpdateExecutorRuntime) switchCurrent(slot string) error {
	return rt.replaceCurrent(slot, false)
}

// reconstructCurrent is reserved for the root-owned fixed-slot watchdog. It
// deliberately does not inspect or follow the existing current path: recovery
// must remain possible when a power loss leaves that path missing, malformed,
// dangling, or replaced by a non-symlink. The final rename is atomic.
func (rt hostSelfUpdateExecutorRuntime) reconstructCurrent(slot string) error {
	return rt.replaceCurrent(slot, true)
}

func (rt hostSelfUpdateExecutorRuntime) replaceCurrent(
	slot string,
	replaceMalformed bool,
) error {
	if rt.switchCurrentHook != nil {
		return rt.switchCurrentHook(slot)
	}
	if !validHostSelfUpdateSlot(slot) {
		return errors.New("host self-update target slot is invalid")
	}
	if err := rt.validateHostSelfUpdateSlotTree(slot); err != nil {
		return err
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	temporary := filepath.Join(
		rt.installRoot, ".current-"+slot+"-"+shortID(slotRoot)+".new",
	)
	if !pathWithin(rt.installRoot, temporary) {
		return errors.New("host self-update temporary link escaped install root")
	}
	_ = os.Remove(temporary)
	relativeTarget, err := filepath.Rel(rt.installRoot, slotRoot)
	if err != nil || strings.HasPrefix(relativeTarget, "..") {
		return errors.New("host self-update slot cannot be linked")
	}
	if err := os.Symlink(relativeTarget, temporary); err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if !replaceMalformed {
		if current, err := os.Lstat(rt.currentLink); err == nil {
			if current.Mode()&os.ModeSymlink == 0 {
				return errors.New("host self-update current path is not a symlink")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(temporary, rt.currentLink); err != nil {
		return err
	}
	remove = false
	return syncDirectory(rt.installRoot)
}

func (rt hostSelfUpdateExecutorRuntime) readCurrentSlot() (string, error) {
	info, err := os.Lstat(rt.currentLink)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", errors.New("host self-update current symlink is unavailable")
	}
	if !rt.allowTestPaths && !isRootOwner(info) {
		return "", errors.New("host self-update current symlink is not root-owned")
	}
	target, err := os.Readlink(rt.currentLink)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(rt.currentLink), target)
	}
	target = filepath.Clean(target)
	for _, slot := range []string{HostSelfUpdateSlotA, HostSelfUpdateSlotB} {
		if target == filepath.Join(rt.slotsRoot, slot) {
			if err := rt.validateHostSelfUpdateSlotDirectory(
				slot,
			); err != nil {
				return "", err
			}
			return slot, nil
		}
	}
	return "", errors.New("host self-update current symlink points outside fixed slots")
}

func (rt hostSelfUpdateExecutorRuntime) validateHostSelfUpdateSlotDirectory(
	slot string,
) error {
	if !validHostSelfUpdateSlot(slot) {
		return errors.New("host self-update target slot is invalid")
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	if !pathWithin(rt.slotsRoot, slotRoot) {
		return errors.New("host self-update target slot escaped the slots root")
	}
	info, err := os.Lstat(slotRoot)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" &&
			info.Mode().Perm() != 0o755) {
		return errors.New("host self-update target slot is unavailable or unsafe")
	}
	if !rt.allowTestPaths && !isRootOwner(info) {
		return errors.New("host self-update target slot is not root-owned")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) validateHostSelfUpdateSlotTree(
	slot string,
) error {
	if err := rt.validateHostSelfUpdateSlotDirectory(slot); err != nil {
		return err
	}
	return rt.validateHostSelfUpdateSlotTreeRoot(
		filepath.Join(rt.slotsRoot, slot),
	)
}

func (rt hostSelfUpdateExecutorRuntime) validateHostSelfUpdateSlotTreeRoot(
	slotRoot string,
) error {
	info, err := os.Lstat(slotRoot)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o755) ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return errors.New("host self-update slot directory is unsafe")
	}
	binRoot := filepath.Join(slotRoot, "bin")
	if !pathWithin(slotRoot, binRoot) {
		return errors.New("host self-update slot bin escaped its root")
	}
	info, err = os.Lstat(binRoot)
	if err != nil ||
		!info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o755) ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return errors.New("host self-update slot bin directory is unsafe")
	}
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		if err := validateHostSelfUpdateSlotBinary(
			filepath.Join(binRoot, binary),
			!rt.allowTestPaths,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateHostSelfUpdateSlotBinary(
	path string,
	requireRootOwner bool,
) error {
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		(runtime.GOOS != "windows" && info.Mode().Perm() != 0o755) ||
		(requireRootOwner && !isRootOwner(info)) {
		return errors.New("host self-update slot binary is unsafe")
	}
	return nil
}

func (rt hostSelfUpdateExecutorRuntime) loadState(
	currentSlot string,
) (HostSelfUpdateState, error) {
	state, err := rt.loadPersistedState()
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return HostSelfUpdateState{}, err
	}
	if currentSlot != HostSelfUpdateSlotA {
		return HostSelfUpdateState{}, errors.New(
			"host self-update state is unavailable for a non-bootstrap slot",
		)
	}
	hasBinding, err := rt.hostSelfUpdateSlotHasBinding(currentSlot)
	if err != nil {
		return HostSelfUpdateState{}, err
	}
	if hasBinding {
		return HostSelfUpdateState{}, errors.New(
			"host self-update state is unavailable for a bound slot",
		)
	}
	state, stateErr := NewHostSelfUpdateState(
		rt.executorVersion, rt.executorVersion,
	)
	if stateErr != nil {
		return HostSelfUpdateState{}, stateErr
	}
	state.ActiveSlot = currentSlot
	state.HealthySlot = currentSlot
	if err := rt.saveState(state); err != nil {
		return HostSelfUpdateState{}, err
	}
	return state, nil
}

func (rt hostSelfUpdateExecutorRuntime) hostSelfUpdateSlotHasBinding(
	slot string,
) (bool, error) {
	if !validHostSelfUpdateSlot(slot) {
		return false, errors.New("host self-update slot is invalid")
	}
	slotRoot := filepath.Join(rt.slotsRoot, slot)
	for _, name := range []string{
		".generation",
		".agent-version",
		".executor-version",
		".commit",
		".artifact-sha256",
		".agent-protocol",
		".executor-protocol",
		".mutation-protocol",
		".recovery-protocol",
		".agent-sha256",
		".local-executor-sha256",
		".release-binding.json",
	} {
		path := filepath.Join(slotRoot, name)
		if !pathWithin(slotRoot, path) {
			return false, errors.New(
				"host self-update slot binding escaped its root",
			)
		}
		if _, err := os.Lstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func (rt hostSelfUpdateExecutorRuntime) loadPersistedState() (HostSelfUpdateState, error) {
	info, err := os.Lstat(rt.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return HostSelfUpdateState{}, os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > 64<<10 ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return HostSelfUpdateState{}, errors.New("host self-update state is unsafe")
	}
	payload, err := os.ReadFile(rt.statePath)
	if err != nil {
		return HostSelfUpdateState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state HostSelfUpdateState
	if err := decoder.Decode(&state); err != nil {
		return HostSelfUpdateState{}, errors.New("decode host self-update state")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return HostSelfUpdateState{}, errors.New("host self-update state contains trailing data")
	}
	if err := state.validate(); err != nil {
		return HostSelfUpdateState{}, err
	}
	return state, nil
}

func (rt hostSelfUpdateExecutorRuntime) saveState(
	state HostSelfUpdateState,
) error {
	if err := state.validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode host self-update state")
	}
	writer := rt.writeState
	if writer == nil {
		writer = writeAtomicFile
	}
	if err := writer(
		rt.statePath, append(payload, '\n'), 0o600,
	); err != nil {
		return err
	}
	info, err := os.Lstat(rt.statePath)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return errors.New("host self-update state security verification failed")
	}
	return nil
}
