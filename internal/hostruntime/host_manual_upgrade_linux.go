//go:build linux

package hostruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	manualHostUpgradeAgentUser       = "autostream-host-agent"
	manualHostUpgradeAgentGroup      = "autostream-host-agent"
	manualHostUpgradeRecoveryTimeout = 2 * time.Minute
	legacyUpdateHostInstallLockPath  = "/run/autostream-update-host-install.lock"
)

type manualHostUpgradePaths struct {
	identityPath              string
	legacyIdentityPath        string
	stagedIdentityPath        string
	wipingIdentityPath        string
	policyPath                string
	hostStateRoot             string
	localExecutorStateRoot    string
	runtimeCredentialPath     string
	publicAgentPath           string
	publicExecutorPath        string
	installedAgentUnit        string
	installedExecutorUnit     string
	installedExecutorSocket   string
	installedExecutorTmpfiles string
	installedRecoveryService  string
	installedRecoveryTimer    string
	legacyHelperConfigPath    string
}

type manualHostUpgradeRuntime struct {
	selfUpdate         hostSelfUpdateExecutorRuntime
	paths              manualHostUpgradePaths
	runner             CommandRunner
	identityRunner     CommandRunner
	now                func() time.Time
	waitStable         func(context.Context) error
	resolveProcessExe  func(int) (string, error)
	mkdirStateRoot     func(string, os.FileMode) error
	acquireLocks       func() (func(), error)
	acquireTargetLocks func(LocalExecutorPolicy, []Target) (func(), error)
	fixedCheckpoints   []Target
	allowTestPaths     bool
}

type manualHostBinaryIdentity struct {
	Name             string
	Version          string
	Commit           string
	BuildDate        time.Time
	MutationProtocol int
	RecoveryProtocol int
}

type manualHostRuntimeObservation struct {
	Slot     string
	Agent    manualHostBinaryIdentity
	Executor manualHostBinaryIdentity
}

type manualHostUpgradeSnapshot struct {
	identity                  secureManualHostUpgradeFile
	policy                    secureManualHostUpgradeFile
	installedFiles            []secureManualHostUpgradeFile
	publicLinks               []secureManualHostUpgradeLink
	stateParent               secureManualHostUpgradeDirectory
	stateRoot                 secureManualHostUpgradeDirectory
	recoveryUnitConfig        *manualHostRecoveryUnitMigrationConfig
	recoveryUnitFinal         bool
	executorUnitConfig        *manualHostExecutorUnitMigrationConfig
	executorUnitFinal         bool
	executorPolicy            LocalExecutorPolicy
	legacyHelperConfig        HelperConfig
	legacyHelperConfigFile    secureManualHostUpgradeFile
	legacyHelperConfigPresent bool
}

type secureManualHostUpgradeLink struct {
	path   string
	info   os.FileInfo
	target string
}

type secureManualHostUpgradeFile struct {
	path   string
	info   os.FileInfo
	digest string
}

type secureManualHostUpgradeDirectory struct {
	path    string
	info    os.FileInfo
	mode    os.FileMode
	present bool
	created bool
}

func defaultManualHostUpgradeRuntime() manualHostUpgradeRuntime {
	selfUpdate := defaultHostSelfUpdateExecutorRuntime()
	return manualHostUpgradeRuntime{
		selfUpdate: selfUpdate,
		paths: manualHostUpgradePaths{
			identityPath:              HostAgentIdentityPath,
			legacyIdentityPath:        LegacyHostAgentIdentityPath,
			stagedIdentityPath:        HostAgentStagedIdentityPath,
			wipingIdentityPath:        HostAgentWipingIdentityPath,
			policyPath:                DefaultLocalExecutorPolicyPath,
			hostStateRoot:             HostPullAgentStateDir,
			localExecutorStateRoot:    LocalExecutorMutationStateDir,
			runtimeCredentialPath:     RuntimeCredentialStatePath,
			publicAgentPath:           "/usr/local/bin/autostream-host-agent",
			publicExecutorPath:        "/usr/local/libexec/autostream-local-executor",
			installedAgentUnit:        "/etc/systemd/system/autostream-host-agent.service",
			installedExecutorUnit:     "/etc/systemd/system/autostream-local-executor.service",
			installedExecutorSocket:   "/etc/systemd/system/autostream-local-executor.socket",
			installedExecutorTmpfiles: "/etc/tmpfiles.d/autostream-local-executor.conf",
			installedRecoveryService:  "/etc/systemd/system/autostream-host-self-update-recovery@.service",
			installedRecoveryTimer:    "/etc/systemd/system/autostream-host-self-update-recovery@.timer",
			legacyHelperConfigPath:    "/etc/autostream/update-host.json",
		},
		runner:             selfUpdate.runner,
		identityRunner:     selfUpdate.identityRunner,
		now:                time.Now,
		waitStable:         selfUpdate.waitExecutorStable,
		resolveProcessExe:  selfUpdate.resolveProcessExe,
		acquireLocks:       acquireManualHostUpgradeLocks,
		acquireTargetLocks: acquireManualHostUpgradeTargetLocks,
		fixedCheckpoints:   manualHostUpgradeFixedSystemdCheckpointTargets(),
	}
}

func upgradeHostRuntimeFromVerifiedBundle(
	ctx context.Context,
	request ManualHostUpgradeRequest,
) (ManualHostUpgradeResult, error) {
	if os.Geteuid() != 0 {
		return ManualHostUpgradeResult{}, errors.New(
			"manual Host runtime upgrade requires root",
		)
	}
	return upgradeHostRuntimeWithRuntime(
		ctx,
		request,
		defaultManualHostUpgradeRuntime(),
	)
}

func inspectHostUpdateRecovery() (bool, error) {
	if os.Geteuid() != 0 {
		return false, errors.New(
			"Host update recovery inspection requires root",
		)
	}
	rt := defaultManualHostUpgradeRuntime()
	if err := validateManualHostUpgradeStateRoots(rt); err != nil {
		return false, err
	}
	journal, err := readManualHostUpgradeJournal(rt)
	if err != nil {
		return false, err
	}
	return manualHostUpgradeJournalRecoveryActive(journal)
}

func manualHostUpgradeJournalRecoveryActive(
	journal journalData,
) (bool, error) {
	if journal.ActiveJob == nil {
		if journal.ActivePlan != nil || journal.ActivePortPlan != nil {
			return false, errors.New(
				"Host Agent journal has a plan without an active job",
			)
		}
		return false, nil
	}
	if journal.ActiveJob.validateOperationUnion() != nil ||
		(journal.ActivePlan != nil && journal.ActivePortPlan != nil) {
		return false, errors.New("Host Agent recovery journal is invalid")
	}
	switch journal.ActiveJob.EffectiveOperation() {
	case updateJobOperationSoftwareUpdate:
		if journal.ActivePortPlan != nil || journal.ActivePlan == nil ||
			journal.ActivePlan.JobID != journal.ActiveJob.ID ||
			journal.ActivePlan.Validate() != nil {
			return false, errors.New(
				"Host Agent software recovery plan is invalid",
			)
		}
	case updateJobOperationPortReconfigure:
		if journal.ActivePlan != nil || journal.ActivePortPlan == nil ||
			journal.ActivePortPlan.JobID != journal.ActiveJob.ID ||
			journal.ActivePortPlan.Validate() != nil {
			return false, errors.New(
				"Host Agent port recovery plan is invalid",
			)
		}
	default:
		return false, errors.New("Host Agent recovery operation is invalid")
	}
	return true, nil
}

func upgradeHostRuntimeWithRuntime(
	ctx context.Context,
	input ManualHostUpgradeRequest,
	rt manualHostUpgradeRuntime,
) (ManualHostUpgradeResult, error) {
	if err := prepareManualHostUpgradeRuntime(&rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	artifact, err := inspectManualHostUpgradeArtifact(ctx, input, rt)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	request, err := newManualHostSelfUpdateRequest(artifact, input)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}

	unlock, err := rt.acquireLocks()
	if err != nil {
		return ManualHostUpgradeResult{}, errors.New(
			"another Host runtime setup or lifecycle operation is active",
		)
	}
	defer unlock()

	snapshot, err := validateManualHostUpgradeInstallation(ctx, input.ArtifactRoot, rt)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	targetsUnlock, err := rt.acquireTargetLocks(
		snapshot.executorPolicy,
		snapshot.legacyHelperConfig.Targets,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, errors.New(
			"another managed target mutation is active",
		)
	}
	defer targetsUnlock()
	if err := validateManualHostUpgradeCoreServicePreconditions(
		ctx,
		rt,
		input.AgentStoppedForRecovery,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := validateManualHostUpgradeRecoveryServicePreconditions(
		ctx, rt, true,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	currentSlot, err := rt.selfUpdate.readCurrentSlot()
	if err != nil {
		return ManualHostUpgradeResult{}, errors.New(
			"managed Host runtime current slot is invalid",
		)
	}
	current, err := observeManualHostRuntimeForUpgrade(
		ctx,
		currentSlot,
		input.AgentStoppedForRecovery,
		rt,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	state, persisted, err := loadManualHostUpgradeState(current, rt)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := validateManualHostUpgradeCurrentState(
		ctx, current, state, persisted, rt,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := validateManualHostUpgradeRecoveryServicePreconditions(
		ctx,
		rt,
		!persisted && snapshot.recoveryUnitConfig != nil,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := inspectManualHostUpgradeDurableBlockers(
		ctx,
		state,
		snapshot.executorPolicy,
		snapshot.legacyHelperConfig.Targets,
		!persisted,
		rt,
	); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}

	targetDigests, err := hostSelfUpdateArtifactBinaryDigests(
		input.ArtifactRoot,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, errors.New(
			"verified Host runtime bundle binaries are unavailable",
		)
	}
	if current.Agent.Version != current.Executor.Version ||
		current.Agent.Commit != current.Executor.Commit ||
		current.Agent.BuildDate != current.Executor.BuildDate {
		return ManualHostUpgradeResult{}, errors.New(
			"installed Host Agent and Local Executor are a mixed runtime",
		)
	}
	sameVersion := request.AgentVersion == current.Agent.Version
	if sameVersion {
		exact, exactErr := manualHostUpgradeAlreadyCurrent(
			currentSlot, current, request, targetDigests, rt,
		)
		if exactErr != nil {
			return ManualHostUpgradeResult{}, exactErr
		}
		if !exact {
			return ManualHostUpgradeResult{}, errors.New(
				"same-version Host runtime content drift is not upgradeable",
			)
		}
	} else if !updaterReleaseSemverAtLeast(
		request.AgentVersion,
		current.Agent.Version,
	) {
		return ManualHostUpgradeResult{}, errors.New(
			"manual Host runtime downgrade is rejected",
		)
	}
	if err := rt.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return ManualHostUpgradeResult{}, fmt.Errorf(
			"recover interrupted Host runtime slot transition: %w", err,
		)
	}
	if err := rejectManualHostUpgradeTransitionResidue(rt.selfUpdate); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if sameVersion {
		executorUnitNeedsRestart := snapshot.executorUnitConfig != nil &&
			!snapshot.executorUnitFinal
		if snapshot.recoveryUnitConfig != nil && !snapshot.recoveryUnitFinal {
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
			recheckedArtifact, recheckErr := inspectManualHostUpgradeArtifact(
				ctx, input, rt,
			)
			if recheckErr != nil || recheckedArtifact != artifact {
				return ManualHostUpgradeResult{}, errors.New(
					"verified Host runtime bundle changed before recovery unit migration",
				)
			}
			if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
				slot != currentSlot {
				return ManualHostUpgradeResult{}, errors.New(
					"managed Host runtime current slot changed before recovery unit migration",
				)
			}
			snapshot, err = migrateManualHostUpgradeRecoveryUnit(ctx, snapshot)
			if err != nil {
				return ManualHostUpgradeResult{}, err
			}
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		if snapshot.executorUnitConfig != nil && !snapshot.executorUnitFinal {
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
			recheckedArtifact, recheckErr := inspectManualHostUpgradeArtifact(
				ctx, input, rt,
			)
			if recheckErr != nil || recheckedArtifact != artifact {
				return ManualHostUpgradeResult{}, errors.New(
					"verified Host runtime bundle changed before Local Executor unit migration",
				)
			}
			if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
				slot != currentSlot {
				return ManualHostUpgradeResult{}, errors.New(
					"managed Host runtime current slot changed before Local Executor unit migration",
				)
			}
			snapshot, err = migrateManualHostUpgradeExecutorUnit(ctx, snapshot)
			if err != nil {
				return ManualHostUpgradeResult{}, err
			}
			if executorUnitNeedsRestart {
				if err := restartManualHostUpgradeLocalExecutor(ctx, currentSlot, current.Executor, rt); err != nil {
					return ManualHostUpgradeResult{}, err
				}
				executorUnitNeedsRestart = false
			}
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		if executorUnitNeedsRestart {
			if err := restartManualHostUpgradeLocalExecutor(ctx, currentSlot, current.Executor, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		if !persisted && snapshot.recoveryUnitConfig != nil {
			if err := normalizeManualHostUpgradeRecoveryServices(
				ctx, snapshot, rt,
			); err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		if !persisted {
			if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
				return ManualHostUpgradeResult{}, err
			}
			recheckedArtifact, err := inspectManualHostUpgradeArtifact(
				ctx, input, rt,
			)
			if err != nil || recheckedArtifact != artifact {
				return ManualHostUpgradeResult{}, errors.New(
					"verified Host runtime bundle changed before bootstrap persistence",
				)
			}
			if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
				slot != currentSlot {
				return ManualHostUpgradeResult{}, errors.New(
					"managed Host runtime current slot changed before bootstrap persistence",
				)
			}
			snapshot, err = persistManualHostUpgradeBootstrapState(
				state, snapshot, rt,
			)
			if err != nil {
				return ManualHostUpgradeResult{}, err
			}
		}
		return ManualHostUpgradeResult{
			PreviousSlot:   currentSlot,
			ActiveSlot:     currentSlot,
			Version:        request.AgentVersion,
			AlreadyCurrent: true,
		}, nil
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	recheckedArtifact, err := inspectManualHostUpgradeArtifact(ctx, input, rt)
	if err != nil || recheckedArtifact != artifact {
		return ManualHostUpgradeResult{}, errors.New(
			"verified Host runtime bundle changed before staging",
		)
	}
	if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
		slot != currentSlot {
		return ManualHostUpgradeResult{}, errors.New(
			"managed Host runtime current slot changed before staging",
		)
	}
	snapshot, err = migrateManualHostUpgradeRecoveryUnit(ctx, snapshot)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	recheckedArtifact, err = inspectManualHostUpgradeArtifact(ctx, input, rt)
	if err != nil || recheckedArtifact != artifact {
		return ManualHostUpgradeResult{}, errors.New(
			"verified Host runtime bundle changed after recovery unit migration",
		)
	}
	if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
		slot != currentSlot {
		return ManualHostUpgradeResult{}, errors.New(
			"managed Host runtime current slot changed after recovery unit migration",
		)
	}
	snapshot, err = migrateManualHostUpgradeExecutorUnit(ctx, snapshot)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return ManualHostUpgradeResult{}, err
	}
	recheckedArtifact, err = inspectManualHostUpgradeArtifact(ctx, input, rt)
	if err != nil || recheckedArtifact != artifact {
		return ManualHostUpgradeResult{}, errors.New(
			"verified Host runtime bundle changed after Local Executor unit migration",
		)
	}
	if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
		slot != currentSlot {
		return ManualHostUpgradeResult{}, errors.New(
			"managed Host runtime current slot changed after Local Executor unit migration",
		)
	}
	if !persisted && snapshot.recoveryUnitConfig != nil {
		if err := normalizeManualHostUpgradeRecoveryServices(
			ctx, snapshot, rt,
		); err != nil {
			return ManualHostUpgradeResult{}, err
		}
	}

	staged, err := StageHostSelfUpdate(
		state, request, HostLifecycleBlockers{}, targetDigests,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, fmt.Errorf(
			"stage manual Host runtime state: %w", err,
		)
	}
	_, err = manualHostUpgradeSlotExists(
		staged.PendingSlot, rt,
	)
	if err != nil {
		return ManualHostUpgradeResult{}, err
	}
	statePersistedInitially := persisted
	if !persisted {
		snapshot, err = persistManualHostUpgradeBootstrapState(
			state, snapshot, rt,
		)
		if err != nil {
			return ManualHostUpgradeResult{}, err
		}
		persisted = true
	}
	abortBeforeFence := func(cause error) (ManualHostUpgradeResult, error) {
		recoveryCtx, cancel := context.WithTimeout(
			context.Background(), manualHostUpgradeRecoveryTimeout,
		)
		defer cancel()
		recoveryErr := recoverManualHostUpgradeBeforeFence(
			recoveryCtx,
			state,
			statePersistedInitially,
			current,
			snapshot,
			input.AgentStoppedForRecovery,
			rt,
		)
		return ManualHostUpgradeResult{}, errors.Join(cause, recoveryErr)
	}
	if err := rt.selfUpdate.stageSlot(
		ctx,
		staged.PendingSlot,
		input.ArtifactRoot,
		request,
		targetDigests,
	); err != nil {
		return abortBeforeFence(fmt.Errorf(
			"stage manual Host runtime slot: %w", err,
		))
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return abortBeforeFence(err)
	}
	activating, err := BeginHostSelfUpdateActivation(
		staged,
		rt.now().UTC(),
		rt.selfUpdate.verificationTimeout,
	)
	if err != nil {
		return abortBeforeFence(err)
	}
	rollbackAfterFence := func(cause error) (ManualHostUpgradeResult, error) {
		rollbackCtx, cancel := context.WithTimeout(
			context.Background(), manualHostUpgradeRecoveryTimeout,
		)
		defer cancel()
		rollbackErr := rollbackManualHostUpgrade(
			rollbackCtx, activating, current, rt,
		)
		return ManualHostUpgradeResult{}, errors.Join(cause, rollbackErr)
	}
	if err := rt.selfUpdate.saveState(activating); err != nil {
		return rollbackAfterFence(fmt.Errorf(
			"persist manual Host runtime activation fence: %w", err,
		))
	}
	if err := rt.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return rollbackAfterFence(fmt.Errorf(
			"promote manual Host runtime candidate slot: %w", err,
		))
	}
	remainingActivationTime := activating.ActivationDeadline.Sub(rt.now().UTC())
	if remainingActivationTime <= 0 {
		return rollbackAfterFence(errors.New(
			"manual Host runtime activation deadline expired",
		))
	}
	postFenceCtx, cancelPostFence := context.WithTimeout(
		ctx,
		remainingActivationTime,
	)
	defer cancelPostFence()
	if err := verifyManualHostUpgradeSnapshot(postFenceCtx, snapshot, rt); err != nil {
		return rollbackAfterFence(err)
	}
	if err := stopManualHostAgent(postFenceCtx, rt); err != nil {
		return rollbackAfterFence(err)
	}
	if err := inspectManualHostUpgradeDurableBlockers(
		postFenceCtx,
		activating,
		snapshot.executorPolicy,
		snapshot.legacyHelperConfig.Targets,
		false,
		rt,
	); err != nil {
		return rollbackAfterFence(err)
	}
	if err := verifyManualHostUpgradeSnapshot(postFenceCtx, snapshot, rt); err != nil {
		return rollbackAfterFence(err)
	}
	recheckedArtifact, err = inspectManualHostUpgradeArtifact(postFenceCtx, input, rt)
	if err != nil || recheckedArtifact != artifact {
		return rollbackAfterFence(errors.New(
			"verified Host runtime bundle changed before activation",
		))
	}
	if slot, readErr := rt.selfUpdate.readCurrentSlot(); readErr != nil ||
		slot != currentSlot {
		return rollbackAfterFence(errors.New(
			"managed Host runtime current slot changed before activation",
		))
	}
	if err := activateManualHostUpgrade(
		postFenceCtx, activating, request, snapshot, rt,
	); err != nil {
		return rollbackAfterFence(err)
	}
	return ManualHostUpgradeResult{
		PreviousSlot: currentSlot,
		ActiveSlot:   activating.PendingSlot,
		Version:      request.AgentVersion,
	}, nil
}

func prepareManualHostUpgradeRuntime(rt *manualHostUpgradeRuntime) error {
	if rt == nil {
		return errors.New("manual Host runtime upgrade is unavailable")
	}
	if rt.runner == nil {
		rt.runner = OSCommandRunner{NewProcessGroup: true}
	}
	if rt.identityRunner == nil {
		rt.identityRunner = rt.runner
	}
	if rt.now == nil {
		rt.now = time.Now
	}
	if rt.waitStable == nil {
		rt.waitStable = rt.selfUpdate.waitExecutorStable
	}
	if rt.resolveProcessExe == nil {
		rt.resolveProcessExe = rt.selfUpdate.resolveProcessExe
	}
	if rt.mkdirStateRoot == nil {
		rt.mkdirStateRoot = os.Mkdir
	}
	if rt.acquireTargetLocks == nil && rt.allowTestPaths {
		rt.acquireTargetLocks = func(LocalExecutorPolicy, []Target) (func(), error) {
			return func() {}, nil
		}
	}
	if len(rt.fixedCheckpoints) == 0 && !rt.allowTestPaths {
		rt.fixedCheckpoints = manualHostUpgradeFixedSystemdCheckpointTargets()
	}
	if rt.acquireLocks == nil || rt.acquireTargetLocks == nil || rt.waitStable == nil ||
		rt.resolveProcessExe == nil || rt.mkdirStateRoot == nil {
		return errors.New("manual Host runtime upgrade dependencies are incomplete")
	}
	if rt.selfUpdate.verificationTimeout < 30*time.Second ||
		rt.selfUpdate.verificationTimeout > 30*time.Minute {
		return errors.New("manual Host runtime verification timeout is invalid")
	}
	rt.selfUpdate.runner = rt.runner
	rt.selfUpdate.identityRunner = rt.identityRunner
	rt.selfUpdate.resolveProcessExe = rt.resolveProcessExe
	rt.selfUpdate.waitExecutorStable = rt.waitStable
	return nil
}

type manualHostArtifactManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	SourceVersion string `json:"source_version"`
	Commit        string `json:"commit"`
	BuildDate     string `json:"build_date"`
	Platform      struct {
		OS   string `json:"os"`
		Arch string `json:"arch"`
	} `json:"platform"`
	Archive struct {
		Name string `json:"name"`
		Root string `json:"root"`
	} `json:"archive"`
	Compatibility struct {
		MinimumAgentVersion *string `json:"minimum_agent_version"`
		MinimumPanelVersion string  `json:"minimum_panel_version"`
		RollbackCompatible  bool    `json:"rollback_compatible"`
		DatabaseSchema      string  `json:"database_schema"`
	} `json:"compatibility"`
}

func inspectManualHostUpgradeArtifact(
	ctx context.Context,
	input ManualHostUpgradeRequest,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradeArtifact, error) {
	root := filepath.Clean(input.ArtifactRoot)
	if !filepath.IsAbs(root) || root == string(filepath.Separator) ||
		!isCanonicalBareSHA256(strings.TrimSpace(input.ArchiveSHA256)) ||
		input.ArchiveSize < 1 || input.ArchiveSize > defaultMaxArtifactBytes {
		return manualHostUpgradeArtifact{}, errors.New(
			"manual Host runtime bundle arguments are invalid",
		)
	}
	if err := validateManualHostUpgradeArtifactTree(root, rt.allowTestPaths); err != nil {
		return manualHostUpgradeArtifact{}, err
	}
	if err := verifyManualHostUpgradeChecksumInventory(root); err != nil {
		return manualHostUpgradeArtifact{}, err
	}
	manifestPath := filepath.Join(root, "artifact-manifest.json")
	manifestPayload, err := readBoundedManualHostUpgradeFile(
		manifestPath, 64<<10,
	)
	if err != nil {
		return manualHostUpgradeArtifact{}, errors.New(
			"read manual Host runtime artifact manifest",
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestPayload))
	decoder.DisallowUnknownFields()
	var manifest manualHostArtifactManifest
	if err := decoder.Decode(&manifest); err != nil {
		return manualHostUpgradeArtifact{}, errors.New(
			"decode manual Host runtime artifact manifest",
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return manualHostUpgradeArtifact{}, errors.New(
			"manual Host runtime artifact manifest contains trailing data",
		)
	}
	buildDate, err := time.Parse("2006-01-02T15:04:05Z", manifest.BuildDate)
	if err != nil || buildDate.Format("2006-01-02T15:04:05Z") != manifest.BuildDate {
		return manualHostUpgradeArtifact{}, errors.New(
			"manual Host runtime artifact build date is invalid",
		)
	}
	expectedRoot := "autostream-host-agent_" + manifest.SourceVersion +
		"_linux_" + manifest.Platform.Arch
	expectedArchive := expectedRoot + ".tar.gz"
	if manifest.SchemaVersion != 1 || manifest.Component != "host-agent" ||
		!versionPattern.MatchString(manifest.SourceVersion) ||
		!updaterReleaseCommitPattern.MatchString(manifest.Commit) ||
		manifest.Platform.OS != "linux" ||
		(manifest.Platform.Arch != "amd64" && manifest.Platform.Arch != "arm64") ||
		manifest.Platform.Arch != rt.selfUpdate.arch ||
		manifest.Archive.Name != expectedArchive ||
		manifest.Archive.Root != expectedRoot ||
		(!rt.allowTestPaths && filepath.Base(root) != expectedRoot) ||
		manifest.Compatibility.MinimumAgentVersion != nil ||
		manifest.Compatibility.MinimumPanelVersion != manifest.SourceVersion ||
		!manifest.Compatibility.RollbackCompatible ||
		manifest.Compatibility.DatabaseSchema != "none" {
		return manualHostUpgradeArtifact{}, errors.New(
			"artifact-manifest.json does not authorize this manual Host runtime bundle",
		)
	}
	manifestDigest := sha256.Sum256(manifestPayload)
	checksumsPayload, err := readBoundedManualHostUpgradeFile(
		filepath.Join(root, "checksums.txt"), 4<<20,
	)
	if err != nil {
		return manualHostUpgradeArtifact{}, errors.New(
			"read manual Host runtime checksum inventory",
		)
	}
	checksumsDigest := sha256.Sum256(checksumsPayload)
	artifact := manualHostUpgradeArtifact{
		Version:         manifest.SourceVersion,
		Commit:          manifest.Commit,
		BuildDate:       buildDate.UTC(),
		Arch:            manifest.Platform.Arch,
		MinimumPanel:    manifest.Compatibility.MinimumPanelVersion,
		ManifestSHA256:  hex.EncodeToString(manifestDigest[:]),
		ChecksumsSHA256: hex.EncodeToString(checksumsDigest[:]),
	}
	if err := artifact.validate(); err != nil {
		return manualHostUpgradeArtifact{}, err
	}
	for _, binary := range []string{
		"autostream-host-agent",
		"autostream-local-executor",
	} {
		identity, identityErr := readManualHostBinaryIdentity(
			ctx,
			filepath.Join(root, "bin", binary),
			binary,
			rt.identityRunner,
		)
		if identityErr != nil || identity.Version != artifact.Version ||
			identity.Commit != artifact.Commit ||
			!identity.BuildDate.Equal(artifact.BuildDate) ||
			(binary == "autostream-local-executor" &&
				(identity.MutationProtocol != LocalExecutorMutationProtocolVersion ||
					identity.RecoveryProtocol != HostSelfUpdateRecoveryProtocolVersion)) {
			return manualHostUpgradeArtifact{}, fmt.Errorf(
				"%s does not match the verified manual Host runtime identity",
				binary,
			)
		}
	}
	return artifact, nil
}

func validateManualHostUpgradeArtifactTree(root string, allowTestPaths bool) error {
	if err := validateManualHostUpgradeArtifactStagingPath(
		root,
		allowTestPaths,
	); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("manual Host runtime artifact root is unsafe")
	}
	if !allowTestPaths && !isRootOwner(rootInfo) {
		return errors.New("manual Host runtime artifact root is not root-owned")
	}
	count := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > 4096 || !pathWithin(root, path) {
			return errors.New("manual Host runtime artifact tree is too large")
		}
		info, infoErr := entry.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 ||
			(!info.IsDir() && !info.Mode().IsRegular()) ||
			info.Mode().Perm()&0o022 != 0 ||
			(!allowTestPaths && !isRootOwner(info)) {
			return errors.New("manual Host runtime artifact tree contains an unsafe entry")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func validateManualHostUpgradeArtifactStagingPath(
	root string,
	allowTestPaths bool,
) error {
	if allowTestPaths {
		return nil
	}
	const stagingParent = "/var/tmp"
	unpack := filepath.Dir(root)
	stage := filepath.Dir(unpack)
	if filepath.Clean(root) != root || filepath.Base(root) == "." ||
		filepath.Base(root) == string(filepath.Separator) ||
		filepath.Base(unpack) != "unpack" || filepath.Dir(stage) != stagingParent ||
		!isManualHostInstallerStageName(filepath.Base(stage)) {
		return errors.New(
			"manual Host runtime artifact root is outside the installer staging directory",
		)
	}
	if err := validateSecureRootPath("/var", true); err != nil {
		return errors.New("manual Host runtime staging parent is unsafe")
	}
	varTmpInfo, err := os.Lstat(stagingParent)
	if err != nil || !varTmpInfo.IsDir() ||
		varTmpInfo.Mode()&os.ModeSymlink != 0 || !isRootOwner(varTmpInfo) ||
		varTmpInfo.Mode().Perm() != 0o777 ||
		varTmpInfo.Mode()&os.ModeSticky == 0 {
		return errors.New("manual Host runtime staging parent is unsafe")
	}
	for _, path := range []string{stage, unpack} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			!isRootOwner(info) || info.Mode().Perm() != 0o700 {
			return errors.New(
				"manual Host runtime installer staging directory is unsafe",
			)
		}
	}
	return nil
}

func isManualHostInstallerStageName(name string) bool {
	const prefix = "autostream-host-agent-install."
	suffix := strings.TrimPrefix(name, prefix)
	if suffix == name || len(suffix) != 8 {
		return false
	}
	for _, character := range suffix {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func verifyManualHostUpgradeChecksumInventory(root string) error {
	checksumsPath := filepath.Join(root, "checksums.txt")
	payload, err := readBoundedManualHostUpgradeFile(checksumsPath, 4<<20)
	if err != nil || len(payload) == 0 || payload[len(payload)-1] != '\n' {
		return errors.New("manual Host runtime checksum inventory is invalid")
	}
	listed := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 4096), 16<<10)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 69 || line[64:68] != "  ./" ||
			!isCanonicalBareSHA256(line[:64]) {
			return errors.New("manual Host runtime checksum entry is invalid")
		}
		name := line[68:]
		clean := filepath.Clean(filepath.FromSlash(name))
		if name == "" || name == "checksums.txt" || clean == "." ||
			filepath.IsAbs(clean) || clean != filepath.FromSlash(name) ||
			strings.Contains(name, "\\") ||
			strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
			listed[clean] != "" {
			return errors.New("manual Host runtime checksum path is unsafe or duplicated")
		}
		path := filepath.Join(root, clean)
		if !pathWithin(root, path) {
			return errors.New("manual Host runtime checksum path escaped its root")
		}
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 {
			return errors.New("manual Host runtime checksum path is not a regular file")
		}
		digest, hashErr := hashFile(path)
		if hashErr != nil || digest != line[:64] {
			return errors.New("manual Host runtime checksum verification failed")
		}
		listed[clean] = digest
	}
	if err := scanner.Err(); err != nil || len(listed) == 0 {
		return errors.New("manual Host runtime checksum inventory is unreadable")
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Clean(path) == filepath.Clean(checksumsPath) {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil || listed[relative] == "" {
			return errors.New("manual Host runtime file is absent from checksums.txt")
		}
		return nil
	})
	return err
}

func readBoundedManualHostUpgradeFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 ||
		info.Size() > maximum {
		return nil, errors.New("manual Host runtime file is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, errors.New("manual Host runtime file is unreadable")
	}
	return payload, nil
}

func readManualHostBinaryIdentity(
	ctx context.Context,
	path, name string,
	runner CommandRunner,
) (manualHostBinaryIdentity, error) {
	if runner == nil || (name != "autostream-host-agent" &&
		name != "autostream-local-executor") {
		return manualHostBinaryIdentity{}, errors.New(
			"manual Host runtime binary identity request is invalid",
		)
	}
	identityContext, cancel := context.WithTimeout(
		ctx, hostSelfUpdateBinaryIdentityTimeout,
	)
	defer cancel()
	output, err := runner.Run(identityContext, "/", nil, path, "--version")
	if err != nil {
		return manualHostBinaryIdentity{}, errors.New(
			"manual Host runtime binary identity command failed",
		)
	}
	lines := strings.Split(strings.TrimSuffix(
		strings.ReplaceAll(output, "\r\n", "\n"), "\n",
	), "\n")
	expectedLines := 3
	if name == "autostream-local-executor" {
		expectedLines = 5
	}
	if len(lines) != expectedLines || !strings.HasPrefix(lines[0], name+" ") {
		return manualHostBinaryIdentity{}, errors.New(
			"manual Host runtime binary identity output is invalid",
		)
	}
	identity := manualHostBinaryIdentity{
		Name:    name,
		Version: strings.TrimPrefix(lines[0], name+" "),
	}
	seen := make(map[string]bool)
	for _, line := range lines[1:] {
		key, value, found := strings.Cut(line, ": ")
		if !found || seen[key] {
			return manualHostBinaryIdentity{}, errors.New(
				"manual Host runtime binary identity output is invalid",
			)
		}
		seen[key] = true
		switch key {
		case "commit":
			identity.Commit = value
		case "build_date":
			identity.BuildDate, err = time.Parse("2006-01-02T15:04:05Z", value)
		case "mutation_protocol":
			identity.MutationProtocol, err = strconv.Atoi(value)
		case "recovery_protocol":
			identity.RecoveryProtocol, err = strconv.Atoi(value)
		default:
			err = errors.New("unexpected identity field")
		}
		if err != nil {
			return manualHostBinaryIdentity{}, errors.New(
				"manual Host runtime binary identity output is invalid",
			)
		}
	}
	if !versionPattern.MatchString(identity.Version) ||
		!updaterReleaseCommitPattern.MatchString(identity.Commit) ||
		identity.BuildDate.IsZero() || identity.BuildDate.Location() != time.UTC ||
		!seen["commit"] || !seen["build_date"] ||
		(name == "autostream-local-executor" &&
			(!seen["mutation_protocol"] || !seen["recovery_protocol"])) {
		return manualHostBinaryIdentity{}, errors.New(
			"manual Host runtime binary identity is invalid",
		)
	}
	return identity, nil
}

func validateManualHostUpgradeInstallation(
	ctx context.Context,
	artifactRoot string,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradeSnapshot, error) {
	for _, path := range []string{
		rt.paths.legacyIdentityPath,
		rt.paths.stagedIdentityPath,
		rt.paths.wipingIdentityPath,
	} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return manualHostUpgradeSnapshot{}, errors.New(
				"Host Agent identity migration or rotation state blocks upgrade",
			)
		}
	}
	if _, err := LoadManagedBootstrapConfig(
		rt.paths.identityPath, !rt.allowTestPaths,
	); err != nil {
		return manualHostUpgradeSnapshot{}, errors.New(
			"managed Host Agent identity is unavailable or unsafe",
		)
	}
	executorPolicy, err := LoadLocalExecutorPolicy(
		rt.paths.policyPath, !rt.allowTestPaths,
	)
	if err != nil {
		return manualHostUpgradeSnapshot{}, errors.New(
			"managed Local Executor policy is unavailable or unsafe",
		)
	}
	identity, err := snapshotManualHostUpgradeFile(rt.paths.identityPath)
	if err != nil {
		return manualHostUpgradeSnapshot{}, err
	}
	policy, err := snapshotManualHostUpgradeFile(rt.paths.policyPath)
	if err != nil {
		return manualHostUpgradeSnapshot{}, err
	}
	var (
		legacyHelperConfig        HelperConfig
		legacyHelperConfigFile    secureManualHostUpgradeFile
		legacyHelperConfigPresent bool
	)
	if _, statErr := os.Lstat(rt.paths.legacyHelperConfigPath); statErr == nil {
		legacyHelperConfig, err = LoadHelperConfig(
			rt.paths.legacyHelperConfigPath,
			!rt.allowTestPaths,
		)
		if err != nil {
			return manualHostUpgradeSnapshot{}, errors.New(
				"legacy update helper configuration is unsafe",
			)
		}
		legacyHelperConfigFile, err = snapshotManualHostUpgradeFile(
			rt.paths.legacyHelperConfigPath,
		)
		if err != nil {
			return manualHostUpgradeSnapshot{}, err
		}
		legacyHelperConfigPresent = true
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return manualHostUpgradeSnapshot{}, errors.New(
			"legacy update helper configuration is unsafe",
		)
	}
	publicLinks := make([]secureManualHostUpgradeLink, 0, 2)
	for _, link := range []struct {
		path   string
		target string
	}{
		{rt.paths.publicAgentPath, filepath.Join(
			rt.selfUpdate.currentLink, "bin", "autostream-host-agent",
		)},
		{rt.paths.publicExecutorPath, filepath.Join(
			rt.selfUpdate.currentLink, "bin", "autostream-local-executor",
		)},
	} {
		protected, linkErr := snapshotManualHostUpgradePublicLink(
			link.path,
			link.target,
			rt.allowTestPaths,
		)
		if linkErr != nil {
			return manualHostUpgradeSnapshot{}, linkErr
		}
		publicLinks = append(publicLinks, protected)
	}
	unitPairs := [][2]string{
		{rt.paths.installedAgentUnit, filepath.Join(
			artifactRoot, "systemd", "autostream-host-agent.service",
		)},
		{rt.paths.installedExecutorUnit, filepath.Join(
			artifactRoot, "systemd", "autostream-local-executor.service",
		)},
		{rt.paths.installedExecutorSocket, filepath.Join(
			artifactRoot, "systemd", "autostream-local-executor.socket",
		)},
		{rt.paths.installedExecutorTmpfiles, filepath.Join(
			artifactRoot, "systemd", "autostream-local-executor.tmpfiles",
		)},
		{rt.paths.installedRecoveryService, filepath.Join(
			artifactRoot, "systemd", "autostream-host-self-update-recovery@.service",
		)},
		{rt.paths.installedRecoveryTimer, filepath.Join(
			artifactRoot, "systemd", "autostream-host-self-update-recovery@.timer",
		)},
	}
	installedFiles := make([]secureManualHostUpgradeFile, 0, len(unitPairs))
	var recoveryUnitConfig *manualHostRecoveryUnitMigrationConfig
	recoveryUnitFinal := false
	var executorUnitConfig *manualHostExecutorUnitMigrationConfig
	executorUnitFinal := false
	for _, pair := range unitPairs {
		installed, snapshotErr := snapshotManualHostUpgradeFile(pair[0])
		if snapshotErr != nil {
			return manualHostUpgradeSnapshot{}, errors.New(
				"installed Host runtime unit is unavailable or unsafe",
			)
		}
		source, snapshotErr := snapshotManualHostUpgradeFile(pair[1])
		if snapshotErr != nil {
			return manualHostUpgradeSnapshot{}, errors.New(
				"manual Host runtime upgrade requires unchanged systemd unit templates",
			)
		}
		if pair[0] == rt.paths.installedExecutorUnit &&
			manualHostExecutorUnitDigestIsCorrected(source.digest) {
			config := manualHostExecutorUnitMigrationConfig{
				CandidatePath:  pair[1],
				InstalledPath:  pair[0],
				Runner:         rt.runner,
				AllowTestPaths: rt.allowTestPaths,
				SyncDirectory:  rt.selfUpdate.syncDir,
			}
			if err := prepareManualHostExecutorUnitMigrationConfig(&config); err != nil {
				return manualHostUpgradeSnapshot{}, err
			}
			executorSnapshot, inspectErr := inspectManualHostExecutorUnitMigration(
				ctx, config,
			)
			if inspectErr != nil {
				return manualHostUpgradeSnapshot{}, inspectErr
			}
			executorUnitConfig = &config
			executorUnitFinal = manualHostExecutorUnitMigrationIsFinal(executorSnapshot)
		} else if pair[0] == rt.paths.installedRecoveryService &&
			manualHostRecoveryUnitDigestIsCorrected(source.digest) {
			config := manualHostRecoveryUnitMigrationConfig{
				CandidatePath:  pair[1],
				InstalledPath:  pair[0],
				Runner:         rt.runner,
				AllowTestPaths: rt.allowTestPaths,
				SyncDirectory:  rt.selfUpdate.syncDir,
			}
			if err := prepareManualHostRecoveryUnitMigrationConfig(&config); err != nil {
				return manualHostUpgradeSnapshot{}, err
			}
			recoverySnapshot, inspectErr := inspectManualHostRecoveryUnitMigration(
				ctx, config,
			)
			if inspectErr != nil {
				return manualHostUpgradeSnapshot{}, inspectErr
			}
			recoveryUnitConfig = &config
			recoveryUnitFinal =
				manualHostRecoveryUnitDigestIsCorrected(
					recoverySnapshot.installed.digest,
				) &&
					!recoverySnapshot.dropInDir.present &&
					len(recoverySnapshot.dropIns) == 0 &&
					manualHostRecoveryUnitEffectiveIsFinal(recoverySnapshot.effective)
		} else if installed.digest != source.digest {
			return manualHostUpgradeSnapshot{}, errors.New(
				"manual Host runtime upgrade requires unchanged systemd unit templates",
			)
		}
		if !rt.allowTestPaths &&
			(installed.info.Mode().Perm() != 0o644 || !isRootOwner(installed.info)) {
			return manualHostUpgradeSnapshot{}, errors.New(
				"installed Host runtime unit ownership or mode is unsafe",
			)
		}
		installedFiles = append(installedFiles, installed)
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{rt.selfUpdate.installRoot, 0o755},
		{rt.selfUpdate.slotsRoot, 0o755},
	} {
		info, statErr := os.Lstat(directory.path)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			(!rt.allowTestPaths &&
				(info.Mode().Perm() != directory.mode || !isRootOwner(info) ||
					validateSecureRootPath(directory.path, true) != nil)) {
			return manualHostUpgradeSnapshot{}, errors.New(
				"managed Host runtime directory layout is unsafe",
			)
		}
	}
	stateParent, stateRoot, err := snapshotManualHostUpgradeStateLayout(rt)
	if err != nil {
		return manualHostUpgradeSnapshot{}, err
	}
	return manualHostUpgradeSnapshot{
		identity: identity, policy: policy, executorPolicy: executorPolicy,
		installedFiles:            installedFiles,
		publicLinks:               publicLinks,
		stateParent:               stateParent,
		stateRoot:                 stateRoot,
		recoveryUnitConfig:        recoveryUnitConfig,
		recoveryUnitFinal:         recoveryUnitFinal,
		executorUnitConfig:        executorUnitConfig,
		executorUnitFinal:         executorUnitFinal,
		legacyHelperConfig:        legacyHelperConfig,
		legacyHelperConfigFile:    legacyHelperConfigFile,
		legacyHelperConfigPresent: legacyHelperConfigPresent,
	}, nil
}

func snapshotManualHostUpgradeStateLayout(
	rt manualHostUpgradeRuntime,
) (secureManualHostUpgradeDirectory, secureManualHostUpgradeDirectory, error) {
	parentPath := filepath.Clean(rt.paths.localExecutorStateRoot)
	stateRootPath := filepath.Clean(rt.selfUpdate.stateRoot)
	if !filepath.IsAbs(parentPath) || !filepath.IsAbs(stateRootPath) ||
		stateRootPath != filepath.Join(parentPath, "host-self-update") {
		return secureManualHostUpgradeDirectory{},
			secureManualHostUpgradeDirectory{},
			errors.New("managed Host runtime state root is outside its exact parent")
	}
	parent, err := snapshotManualHostUpgradeDirectory(
		parentPath, 0o700, rt.allowTestPaths,
	)
	if err != nil {
		return secureManualHostUpgradeDirectory{},
			secureManualHostUpgradeDirectory{},
			errors.New("managed Host runtime state parent is unsafe")
	}
	stateRoot, err := snapshotManualHostUpgradeDirectory(
		stateRootPath, 0o700, rt.allowTestPaths,
	)
	if errors.Is(err, os.ErrNotExist) {
		return parent, secureManualHostUpgradeDirectory{
			path: stateRootPath,
			mode: 0o700,
		}, nil
	}
	if err != nil {
		return secureManualHostUpgradeDirectory{},
			secureManualHostUpgradeDirectory{},
			errors.New("managed Host runtime state root is unsafe")
	}
	return parent, stateRoot, nil
}

func migrateManualHostUpgradeRecoveryUnit(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
) (manualHostUpgradeSnapshot, error) {
	if snapshot.recoveryUnitConfig == nil || snapshot.recoveryUnitFinal {
		return snapshot, nil
	}
	if err := migrateManualHostRecoveryUnitForward(
		ctx, *snapshot.recoveryUnitConfig,
	); err != nil {
		return snapshot, err
	}
	installed, err := snapshotManualHostUpgradeFile(
		snapshot.recoveryUnitConfig.InstalledPath,
	)
	if err != nil || !manualHostRecoveryUnitDigestIsCorrected(installed.digest) {
		return snapshot, errors.New(
			"snapshot corrected Host recovery unit after migration",
		)
	}
	replaced := false
	for index := range snapshot.installedFiles {
		if snapshot.installedFiles[index].path ==
			snapshot.recoveryUnitConfig.InstalledPath {
			snapshot.installedFiles[index] = installed
			replaced = true
			break
		}
	}
	if !replaced {
		return snapshot, errors.New(
			"Host recovery unit migration snapshot is incomplete",
		)
	}
	snapshot.recoveryUnitFinal = true
	return snapshot, nil
}

func migrateManualHostUpgradeExecutorUnit(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
) (manualHostUpgradeSnapshot, error) {
	if snapshot.executorUnitConfig == nil || snapshot.executorUnitFinal {
		return snapshot, nil
	}
	if err := migrateManualHostExecutorUnitForward(
		ctx, *snapshot.executorUnitConfig,
	); err != nil {
		return snapshot, err
	}
	installed, err := snapshotManualHostUpgradeFile(
		snapshot.executorUnitConfig.InstalledPath,
	)
	if err != nil || !manualHostExecutorUnitDigestIsCorrected(installed.digest) {
		return snapshot, errors.New(
			"snapshot corrected Local Executor unit after migration",
		)
	}
	replaced := false
	for index := range snapshot.installedFiles {
		if snapshot.installedFiles[index].path ==
			snapshot.executorUnitConfig.InstalledPath {
			snapshot.installedFiles[index] = installed
			replaced = true
			break
		}
	}
	if !replaced {
		return snapshot, errors.New(
			"Local Executor unit migration snapshot is incomplete",
		)
	}
	snapshot.executorUnitFinal = true
	return snapshot, nil
}

func restartManualHostUpgradeLocalExecutor(
	ctx context.Context,
	slot string,
	expected manualHostBinaryIdentity,
	rt manualHostUpgradeRuntime,
) error {
	if err := rt.selfUpdate.restartLocalExecutor(ctx); err != nil {
		return errors.New("restart Local Executor after unit migration")
	}
	actual, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			slot,
			"bin",
			"autostream-local-executor",
		),
		"autostream-local-executor",
		rt,
	)
	if err != nil || actual != expected {
		return errors.New("Local Executor identity after unit migration is invalid")
	}
	return nil
}

func snapshotManualHostUpgradeDirectory(
	path string,
	mode os.FileMode,
	allowTestPaths bool,
) (secureManualHostUpgradeDirectory, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return secureManualHostUpgradeDirectory{}, err
	}
	if err := validateManualHostUpgradeDirectoryInfo(
		path, info, mode, allowTestPaths,
	); err != nil {
		return secureManualHostUpgradeDirectory{}, err
	}
	return secureManualHostUpgradeDirectory{
		path: path, info: info, mode: mode, present: true,
	}, nil
}

func validateManualHostUpgradeDirectoryInfo(
	path string,
	info os.FileInfo,
	mode os.FileMode,
	allowTestPaths bool,
) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != mode {
		return errors.New("manual Host runtime directory mode or type is unsafe")
	}
	if !allowTestPaths &&
		(!isRootOwner(info) || validateSecureRootPath(path, true) != nil) {
		return errors.New("manual Host runtime directory ownership is unsafe")
	}
	return nil
}

func snapshotManualHostUpgradeFile(path string) (secureManualHostUpgradeFile, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 ||
		info.Size() > defaultMaxArtifactBytes {
		return secureManualHostUpgradeFile{}, errors.New(
			"manual Host runtime protected file is unsafe",
		)
	}
	digest, err := hashFile(path)
	if err != nil || !isCanonicalBareSHA256(digest) {
		return secureManualHostUpgradeFile{}, errors.New(
			"hash manual Host runtime protected file",
		)
	}
	return secureManualHostUpgradeFile{path: path, info: info, digest: digest}, nil
}

func verifyManualHostUpgradeSnapshot(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, expected := range []secureManualHostUpgradeFile{
		snapshot.identity,
		snapshot.policy,
	} {
		if !manualHostUpgradeProtectedFileMatches(expected) {
			return errors.New(
				"Host Agent identity or Local Executor policy changed during upgrade",
			)
		}
	}
	for _, expected := range snapshot.installedFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !manualHostUpgradeProtectedFileMatches(expected) {
			return errors.New("installed Host runtime unit changed during upgrade")
		}
	}
	for _, expected := range snapshot.publicLinks {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := snapshotManualHostUpgradePublicLink(
			expected.path,
			expected.target,
			rt.allowTestPaths,
		)
		if err != nil || !os.SameFile(expected.info, current.info) ||
			expected.info.Mode() != current.info.Mode() ||
			expected.target != current.target {
			return errors.New("managed Host runtime public binary link changed during upgrade")
		}
	}
	if snapshot.legacyHelperConfigPresent {
		expected := snapshot.legacyHelperConfigFile
		if !manualHostUpgradeProtectedFileMatches(expected) {
			return errors.New("legacy update helper configuration changed during upgrade")
		}
	} else if _, err := os.Lstat(rt.paths.legacyHelperConfigPath); err == nil ||
		!errors.Is(err, os.ErrNotExist) {
		return errors.New("legacy update helper configuration appeared during upgrade")
	}
	if _, err := os.Lstat(rt.paths.legacyIdentityPath); err == nil ||
		!errors.Is(err, os.ErrNotExist) {
		return errors.New("legacy Host Agent identity appeared during upgrade")
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) {
		return errors.New("managed Host runtime state parent changed during upgrade")
	}
	if snapshot.stateRoot.present {
		if !manualHostUpgradeDirectoryMatches(
			snapshot.stateRoot, rt.allowTestPaths,
		) {
			return errors.New("managed Host runtime state root changed during upgrade")
		}
	} else if _, err := os.Lstat(snapshot.stateRoot.path); err == nil ||
		!errors.Is(err, os.ErrNotExist) {
		return errors.New("managed Host runtime state root appeared during upgrade")
	}
	if snapshot.recoveryUnitConfig != nil {
		current, err := inspectManualHostRecoveryUnitMigration(
			ctx, *snapshot.recoveryUnitConfig,
		)
		if err != nil {
			return err
		}
		if snapshot.recoveryUnitFinal &&
			(!manualHostRecoveryUnitDigestIsCorrected(current.installed.digest) ||
				current.dropInDir.present ||
				len(current.dropIns) != 0 ||
				!manualHostRecoveryUnitEffectiveIsFinal(current.effective)) {
			return errors.New("corrected Host recovery unit changed during upgrade")
		}
	}
	if snapshot.executorUnitConfig != nil {
		current, err := inspectManualHostExecutorUnitMigration(
			ctx, *snapshot.executorUnitConfig,
		)
		if err != nil {
			return err
		}
		if snapshot.executorUnitFinal &&
			!manualHostExecutorUnitMigrationIsFinal(current) {
			return errors.New("corrected Local Executor unit changed during upgrade")
		}
	}
	return ctx.Err()
}

func manualHostUpgradeDirectoryMatches(
	expected secureManualHostUpgradeDirectory,
	allowTestPaths bool,
) bool {
	if !expected.present || expected.info == nil {
		return false
	}
	current, err := os.Lstat(expected.path)
	return err == nil && os.SameFile(expected.info, current) &&
		expected.info.Mode() == current.Mode() &&
		validateManualHostUpgradeDirectoryInfo(
			expected.path, current, expected.mode, allowTestPaths,
		) == nil
}

func manualHostUpgradeProtectedFileMatches(
	expected secureManualHostUpgradeFile,
) bool {
	current, err := snapshotManualHostUpgradeFile(expected.path)
	return err == nil && os.SameFile(expected.info, current.info) &&
		expected.info.Mode() == current.info.Mode() &&
		expected.info.Size() == current.info.Size() &&
		expected.digest == current.digest
}

func snapshotManualHostUpgradePublicLink(
	path, expectedTarget string,
	allowTestPaths bool,
) (secureManualHostUpgradeLink, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 ||
		(!allowTestPaths &&
			(!isRootOwner(info) ||
				validateSecureRootPath(filepath.Dir(path), true) != nil)) {
		return secureManualHostUpgradeLink{}, errors.New(
			"managed Host runtime public binary link is unsafe",
		)
	}
	target, err := os.Readlink(path)
	if err != nil || target != expectedTarget {
		return secureManualHostUpgradeLink{}, errors.New(
			"managed Host runtime public binary link has drifted",
		)
	}
	return secureManualHostUpgradeLink{path: path, info: info, target: target}, nil
}

func rejectManualHostUpgradeTransitionResidue(
	rt hostSelfUpdateExecutorRuntime,
) error {
	entries, err := os.ReadDir(rt.slotsRoot)
	if err != nil {
		return errors.New("read managed Host runtime slots")
	}
	for _, entry := range entries {
		if entry.Name() != HostSelfUpdateSlotA &&
			entry.Name() != HostSelfUpdateSlotB {
			return errors.New(
				"an interrupted Host runtime slot transition must be recovered before upgrade",
			)
		}
	}
	entries, err = os.ReadDir(rt.installRoot)
	if err != nil {
		return errors.New("read managed Host runtime root")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".current-") {
			return errors.New(
				"an interrupted Host runtime current-link transition must be recovered before upgrade",
			)
		}
	}
	return nil
}

func validateManualHostUpgradeCoreServicePreconditions(
	ctx context.Context,
	rt manualHostUpgradeRuntime,
	agentStoppedForRecovery bool,
) error {
	if agentStoppedForRecovery {
		state, pid, err := readManualHostUpgradeRecoveryServiceState(
			ctx,
			rt.runner,
			hostSelfUpdateServiceUnit,
		)
		if err != nil || state != "inactive" || pid != 0 {
			return errors.New(
				"Host Agent stopped-recovery handoff is not safely quiescent",
			)
		}
	} else if err := requireManualHostSystemdState(
		ctx,
		rt.runner,
		"is-active",
		hostSelfUpdateServiceUnit,
		"active",
	); err != nil {
		return err
	}
	for _, unit := range []string{
		hostSelfUpdateExecutorServiceUnit,
		hostSelfUpdateExecutorSocketUnit,
		"autostream-host-self-update-recovery@a.timer",
		"autostream-host-self-update-recovery@b.timer",
	} {
		if err := requireManualHostSystemdState(
			ctx, rt.runner, "is-active", unit, "active",
		); err != nil {
			return err
		}
	}
	for _, unit := range []string{
		hostSelfUpdateServiceUnit,
		hostSelfUpdateExecutorSocketUnit,
		"autostream-host-self-update-recovery@a.timer",
		"autostream-host-self-update-recovery@b.timer",
	} {
		if err := requireManualHostSystemdState(
			ctx, rt.runner, "is-enabled", unit, "enabled",
		); err != nil {
			return err
		}
	}
	return nil
}

func validateManualHostUpgradeRecoveryServicePreconditions(
	ctx context.Context,
	rt manualHostUpgradeRuntime,
	allowFailedBootstrap bool,
) error {
	for _, unit := range manualHostRecoveryUnitInstances {
		state, pid, err := readManualHostUpgradeRecoveryServiceState(
			ctx, rt.runner, unit,
		)
		if err != nil {
			return err
		}
		if pid != 0 ||
			(state != "inactive" && !(allowFailedBootstrap && state == "failed")) {
			return fmt.Errorf("%s must be inactive and have no MainPID", unit)
		}
	}
	return nil
}

func readManualHostUpgradeRecoveryServiceState(
	ctx context.Context,
	runner CommandRunner,
	unit string,
) (string, int, error) {
	output, _ := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "is-active", unit,
	)
	state := strings.TrimSpace(output)
	if state == "" {
		return "", 0, fmt.Errorf("read %s active state", unit)
	}
	pidOutput, err := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", "show",
		"--property=MainPID", "--value", unit,
	)
	if err != nil {
		return "", 0, fmt.Errorf("read %s MainPID", unit)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(pidOutput))
	if err != nil || pid < 0 {
		return "", 0, fmt.Errorf("%s MainPID is invalid", unit)
	}
	return state, pid, nil
}

func normalizeManualHostUpgradeRecoveryServices(
	ctx context.Context,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	if snapshot.recoveryUnitConfig == nil || !snapshot.recoveryUnitFinal {
		return errors.New("corrected Host recovery unit is unavailable for bootstrap")
	}
	for _, unit := range manualHostRecoveryUnitInstances {
		state, pid, err := readManualHostUpgradeRecoveryServiceState(
			ctx, rt.runner, unit,
		)
		if err != nil || pid != 0 {
			return fmt.Errorf("%s is not safely quiescent", unit)
		}
		if state == "failed" {
			if _, err := rt.runner.Run(
				ctx, "/", nil, "/usr/bin/systemctl", "reset-failed", unit,
			); err != nil {
				return fmt.Errorf("reset failed bootstrap recovery unit %s", unit)
			}
		} else if state != "inactive" {
			return fmt.Errorf("%s is not inactive", unit)
		}
	}
	return validateManualHostUpgradeRecoveryServicePreconditions(ctx, rt, false)
}

func requireManualHostSystemdState(
	ctx context.Context,
	runner CommandRunner,
	operation, unit, expected string,
) error {
	output, err := runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl", operation, unit,
	)
	actual := strings.TrimSpace(output)
	if expected == "inactive" {
		if actual == expected {
			return nil
		}
	} else if err == nil && actual == expected {
		return nil
	}
	return fmt.Errorf("%s must be %s", unit, expected)
}

func stopManualHostAgent(ctx context.Context, rt manualHostUpgradeRuntime) error {
	if _, err := rt.runner.Run(
		ctx, "/", nil, "/usr/bin/systemctl",
		"stop", hostSelfUpdateServiceUnit,
	); err != nil {
		return errors.New("stop Host Agent for manual runtime upgrade")
	}
	if err := requireManualHostSystemdState(
		ctx, rt.runner, "is-active", hostSelfUpdateServiceUnit, "inactive",
	); err != nil {
		return errors.New("Host Agent did not become inactive for manual runtime upgrade")
	}
	return nil
}

func manualHostUpgradeSlotExists(
	slot string,
	rt manualHostUpgradeRuntime,
) (bool, error) {
	if !validHostSelfUpdateSlot(slot) {
		return false, errors.New("manual Host runtime pending slot is invalid")
	}
	path := filepath.Join(rt.selfUpdate.slotsRoot, slot)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, errors.New("inspect manual Host runtime pending slot")
	}
	if err := rt.selfUpdate.validateHostSelfUpdateSlotTree(slot); err != nil {
		return false, errors.New("manual Host runtime inactive slot is unsafe")
	}
	return true, nil
}

func persistManualHostUpgradeBootstrapState(
	state HostSelfUpdateState,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradeSnapshot, error) {
	updated, err := ensureManualHostUpgradeBootstrapStateRoot(snapshot, rt)
	if err != nil {
		return snapshot, err
	}
	if err := rt.selfUpdate.saveState(state); err != nil {
		restoreErr := restoreManualHostUpgradeOriginalState(
			state, false, updated, rt,
		)
		return snapshot, errors.Join(
			fmt.Errorf("persist bootstrap Host runtime stable state: %w", err),
			restoreErr,
		)
	}
	return updated, nil
}

func ensureManualHostUpgradeBootstrapStateRoot(
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) (manualHostUpgradeSnapshot, error) {
	if snapshot.stateRoot.present {
		if !manualHostUpgradeDirectoryMatches(
			snapshot.stateParent, rt.allowTestPaths,
		) || !manualHostUpgradeDirectoryMatches(
			snapshot.stateRoot, rt.allowTestPaths,
		) {
			return snapshot, errors.New(
				"managed Host runtime state layout changed before bootstrap persistence",
			)
		}
		return snapshot, nil
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) {
		return snapshot, errors.New(
			"managed Host runtime state parent changed before bootstrap persistence",
		)
	}
	if err := rt.mkdirStateRoot(snapshot.stateRoot.path, 0o700); err != nil {
		return snapshot, fmt.Errorf(
			"create bootstrap Host self-update state root: %w", err,
		)
	}
	createdInfo, err := os.Lstat(snapshot.stateRoot.path)
	if err != nil {
		return snapshot, errors.New(
			"inspect created bootstrap Host self-update state root",
		)
	}
	snapshot.stateRoot.info = createdInfo
	snapshot.stateRoot.present = true
	snapshot.stateRoot.created = true
	fail := func(cause error) (manualHostUpgradeSnapshot, error) {
		cleanupErr := cleanupManualHostUpgradeCreatedStateRoot(snapshot, rt)
		return snapshot, errors.Join(cause, cleanupErr)
	}
	if err := validateManualHostUpgradeDirectoryInfo(
		snapshot.stateRoot.path,
		createdInfo,
		snapshot.stateRoot.mode,
		rt.allowTestPaths,
	); err != nil {
		return fail(errors.New(
			"created bootstrap Host self-update state root is unsafe",
		))
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) {
		return fail(errors.New(
			"managed Host runtime state parent changed during root creation",
		))
	}
	if err := syncManualHostUpgradeDirectory(
		snapshot.stateRoot.path, rt,
	); err != nil {
		return fail(fmt.Errorf(
			"sync bootstrap Host self-update state root: %w", err,
		))
	}
	if err := syncManualHostUpgradeDirectory(
		snapshot.stateParent.path, rt,
	); err != nil {
		return fail(fmt.Errorf(
			"sync bootstrap Host self-update state parent: %w", err,
		))
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) || !manualHostUpgradeDirectoryMatches(
		snapshot.stateRoot, rt.allowTestPaths,
	) {
		return fail(errors.New(
			"bootstrap Host self-update state layout changed after sync",
		))
	}
	return snapshot, nil
}

func cleanupManualHostUpgradeCreatedStateRoot(
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	created := snapshot.stateRoot
	if !created.created {
		return nil
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) || !manualHostUpgradeDirectoryMatches(
		created, rt.allowTestPaths,
	) {
		return errors.New(
			"created bootstrap Host self-update state root is not safely removable",
		)
	}
	entries, err := os.ReadDir(created.path)
	if err != nil || len(entries) != 0 {
		return errors.New(
			"created bootstrap Host self-update state root is not empty",
		)
	}
	if err := os.Remove(created.path); err != nil {
		return errors.New("remove created bootstrap Host self-update state root")
	}
	if err := syncManualHostUpgradeDirectory(
		snapshot.stateParent.path, rt,
	); err != nil {
		return fmt.Errorf(
			"sync created bootstrap Host self-update state root removal: %w", err,
		)
	}
	if _, err := os.Lstat(created.path); !errors.Is(err, os.ErrNotExist) {
		return errors.New(
			"created bootstrap Host self-update state root still exists",
		)
	}
	if !manualHostUpgradeDirectoryMatches(
		snapshot.stateParent, rt.allowTestPaths,
	) {
		return errors.New(
			"managed Host runtime state parent changed during root removal",
		)
	}
	return nil
}

func syncManualHostUpgradeDirectory(
	path string,
	rt manualHostUpgradeRuntime,
) error {
	if rt.selfUpdate.syncDir != nil {
		return rt.selfUpdate.syncDir(path)
	}
	return syncDirectory(path)
}

func restoreManualHostUpgradeOriginalState(
	state HostSelfUpdateState,
	originallyPersisted bool,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	current, err := rt.selfUpdate.loadPersistedState()
	if originallyPersisted {
		if err != nil || current != state {
			return errors.New("original Host self-update state changed during recovery")
		}
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return cleanupManualHostUpgradeCreatedStateRoot(snapshot, rt)
	}
	if err != nil || current != state {
		return errors.New("temporary Host self-update state is not safely removable")
	}
	if err := os.Remove(rt.selfUpdate.statePath); err != nil {
		return errors.New("remove temporary bootstrap Host self-update state")
	}
	if err := syncManualHostUpgradeDirectory(rt.selfUpdate.stateRoot, rt); err != nil {
		return errors.New("sync temporary bootstrap Host self-update state removal")
	}
	if _, err := os.Lstat(rt.selfUpdate.statePath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("temporary bootstrap Host self-update state still exists")
	}
	return cleanupManualHostUpgradeCreatedStateRoot(snapshot, rt)
}

func recoverManualHostUpgradeBeforeFence(
	ctx context.Context,
	state HostSelfUpdateState,
	originallyPersisted bool,
	healthy manualHostRuntimeObservation,
	snapshot manualHostUpgradeSnapshot,
	agentStoppedForRecovery bool,
	rt manualHostUpgradeRuntime,
) error {
	currentState, err := rt.selfUpdate.loadPersistedState()
	if err != nil || currentState != state {
		return errors.New("stable Host self-update recovery state is unavailable")
	}
	if err := rt.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return fmt.Errorf("recover manual Host runtime candidate before activation: %w", err)
	}
	if err := rejectManualHostUpgradeTransitionResidue(rt.selfUpdate); err != nil {
		return err
	}
	currentSlot, err := rt.selfUpdate.readCurrentSlot()
	if err != nil || currentSlot != healthy.Slot {
		return errors.New("manual Host runtime current slot changed before recovery")
	}
	actual, err := observeManualHostRuntimeForUpgrade(
		ctx,
		healthy.Slot,
		agentStoppedForRecovery,
		rt,
	)
	if err != nil || actual != healthy {
		return errors.New("healthy Host runtime changed during pre-activation recovery")
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return err
	}
	return restoreManualHostUpgradeOriginalState(
		state, originallyPersisted, snapshot, rt,
	)
}

func ensureManualHostUpgradeDeadline(
	state HostSelfUpdateState,
	now time.Time,
) error {
	if state.ActivationDeadline.IsZero() ||
		!now.UTC().Before(state.ActivationDeadline) {
		return errors.New("manual Host runtime activation deadline expired")
	}
	return nil
}

func observeManualHostRuntime(
	ctx context.Context,
	slot string,
	rt manualHostUpgradeRuntime,
) (manualHostRuntimeObservation, error) {
	return observeManualHostRuntimeForUpgrade(ctx, slot, false, rt)
}

func observeManualHostRuntimeForUpgrade(
	ctx context.Context,
	slot string,
	agentStoppedForRecovery bool,
	rt manualHostUpgradeRuntime,
) (manualHostRuntimeObservation, error) {
	if err := rt.selfUpdate.validateHostSelfUpdateSlotTree(slot); err != nil {
		return manualHostRuntimeObservation{}, errors.New(
			"managed Host runtime active slot is unsafe",
		)
	}
	root := filepath.Join(rt.selfUpdate.slotsRoot, slot, "bin")
	agentPath := filepath.Join(root, "autostream-host-agent")
	var agent manualHostBinaryIdentity
	var err error
	if agentStoppedForRecovery {
		agent, err = verifyStoppedManualHostAgentIdentity(ctx, agentPath, rt)
	} else {
		agent, err = verifyManualHostUnitProcess(
			ctx,
			hostSelfUpdateServiceUnit,
			agentPath,
			"autostream-host-agent",
			rt,
		)
	}
	if err != nil {
		return manualHostRuntimeObservation{}, err
	}
	executor, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		filepath.Join(root, "autostream-local-executor"),
		"autostream-local-executor",
		rt,
	)
	if err != nil {
		return manualHostRuntimeObservation{}, err
	}
	if executor.MutationProtocol != LocalExecutorMutationProtocolVersion ||
		executor.RecoveryProtocol != HostSelfUpdateRecoveryProtocolVersion {
		return manualHostRuntimeObservation{}, errors.New(
			"installed Local Executor protocol identity is incompatible",
		)
	}
	if agent.Version != executor.Version ||
		agent.Commit != executor.Commit ||
		!agent.BuildDate.Equal(executor.BuildDate) {
		return manualHostRuntimeObservation{}, errors.New(
			"installed Host Agent and Local Executor are a mixed runtime",
		)
	}
	return manualHostRuntimeObservation{
		Slot: slot, Agent: agent, Executor: executor,
	}, nil
}

func verifyStoppedManualHostAgentIdentity(
	ctx context.Context,
	expectedPath string,
	rt manualHostUpgradeRuntime,
) (manualHostBinaryIdentity, error) {
	readInfo := func() (os.FileInfo, error) {
		info, err := os.Lstat(expectedPath)
		if err != nil || !info.Mode().IsRegular() ||
			info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o755 ||
			(!rt.allowTestPaths && !isRootOwner(info)) {
			return nil, errors.New("stopped Host Agent binary is unsafe")
		}
		return info, nil
	}
	sameInfo := func(first, second os.FileInfo) bool {
		return os.SameFile(first, second) &&
			first.Mode() == second.Mode() &&
			first.Size() == second.Size() &&
			first.ModTime().Equal(second.ModTime())
	}

	firstInfo, err := readInfo()
	if err != nil {
		return manualHostBinaryIdentity{}, err
	}
	first, err := readManualHostBinaryIdentity(
		ctx,
		expectedPath,
		"autostream-host-agent",
		rt.identityRunner,
	)
	if err != nil {
		return manualHostBinaryIdentity{}, err
	}
	if err := rt.waitStable(ctx); err != nil {
		return manualHostBinaryIdentity{}, fmt.Errorf(
			"wait for stopped Host Agent identity stability: %w",
			err,
		)
	}
	secondInfo, err := readInfo()
	if err != nil || !sameInfo(firstInfo, secondInfo) {
		return manualHostBinaryIdentity{}, errors.New(
			"stopped Host Agent binary changed during identity verification",
		)
	}
	second, err := readManualHostBinaryIdentity(
		ctx,
		expectedPath,
		"autostream-host-agent",
		rt.identityRunner,
	)
	if err != nil {
		return manualHostBinaryIdentity{}, err
	}
	finalInfo, err := readInfo()
	if err != nil || !sameInfo(firstInfo, finalInfo) || first != second {
		return manualHostBinaryIdentity{}, errors.New(
			"stopped Host Agent identity changed during verification",
		)
	}
	return first, nil
}

func verifyManualHostUnitProcess(
	ctx context.Context,
	unit, expectedPath, binaryName string,
	rt manualHostUpgradeRuntime,
) (manualHostBinaryIdentity, error) {
	type processObservation struct {
		pid        int
		executable string
	}
	readProcess := func() (processObservation, error) {
		if err := ctx.Err(); err != nil {
			return processObservation{}, fmt.Errorf(
				"verify Host runtime process: %w",
				err,
			)
		}
		if err := requireManualHostSystemdState(
			ctx, rt.runner, "is-active", unit, "active",
		); err != nil {
			return processObservation{}, err
		}
		output, err := rt.runner.Run(
			ctx, "/", nil, "/usr/bin/systemctl", "show",
			"--property=MainPID", "--value", unit,
		)
		if err != nil {
			return processObservation{}, errors.New("read Host runtime MainPID")
		}
		pid, err := strconv.Atoi(strings.TrimSpace(output))
		if err != nil || pid <= 0 {
			return processObservation{}, errors.New("Host runtime unit has no MainPID")
		}
		executable, err := rt.resolveProcessExe(pid)
		if err != nil {
			return processObservation{}, errors.New(
				"resolve Host runtime unit executable",
			)
		}
		return processObservation{pid: pid, executable: executable}, nil
	}
	expectedPath = filepath.Clean(expectedPath)
	pinnedPID := 0
	first := processObservation{}
	for probe := 0; probe < hostSelfUpdateSystemdExecutorProbes; probe++ {
		observed, err := readProcess()
		if err != nil {
			return manualHostBinaryIdentity{}, err
		}
		if pinnedPID == 0 {
			pinnedPID = observed.pid
		} else if observed.pid != pinnedPID {
			return manualHostBinaryIdentity{}, errors.New(
				"Host runtime MainPID changed during systemd-executor transition",
			)
		}
		if filepath.Clean(observed.executable) == expectedPath {
			first = observed
			break
		}
		if !isHostRuntimeSystemdExecutor(observed.executable) {
			return manualHostBinaryIdentity{}, errors.New(
				"Host runtime unit is executing outside the selected slot",
			)
		}
		if probe+1 == hostSelfUpdateSystemdExecutorProbes {
			return manualHostBinaryIdentity{}, errors.New(
				"Host runtime unit remained in systemd-executor beyond the startup probe limit",
			)
		}
		if err := rt.waitStable(ctx); err != nil {
			return manualHostBinaryIdentity{}, fmt.Errorf(
				"wait for Host runtime systemd-executor transition: %w",
				err,
			)
		}
	}
	if err := rt.waitStable(ctx); err != nil {
		return manualHostBinaryIdentity{}, fmt.Errorf(
			"wait for Host runtime process stability: %w",
			err,
		)
	}
	second, err := readProcess()
	if err != nil {
		return manualHostBinaryIdentity{}, err
	}
	if first.pid != second.pid {
		return manualHostBinaryIdentity{}, errors.New(
			"Host runtime MainPID changed during stability verification",
		)
	}
	if filepath.Clean(second.executable) != expectedPath {
		return manualHostBinaryIdentity{}, errors.New(
			"Host runtime unit is executing outside the selected slot",
		)
	}
	return readManualHostBinaryIdentity(
		ctx, expectedPath, binaryName, rt.identityRunner,
	)
}

func loadManualHostUpgradeState(
	current manualHostRuntimeObservation,
	rt manualHostUpgradeRuntime,
) (HostSelfUpdateState, bool, error) {
	state, err := rt.selfUpdate.loadPersistedState()
	if err == nil {
		return state, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) || current.Slot != HostSelfUpdateSlotA {
		return HostSelfUpdateState{}, false, errors.New(
			"managed Host runtime self-update state is unavailable",
		)
	}
	hasBinding, err := rt.selfUpdate.hostSelfUpdateSlotHasBinding(current.Slot)
	if err != nil || hasBinding {
		return HostSelfUpdateState{}, false, errors.New(
			"bootstrap Host runtime state is missing or ambiguously bound",
		)
	}
	state, err = NewHostSelfUpdateState(
		current.Agent.Version, current.Executor.Version,
	)
	if err != nil {
		return HostSelfUpdateState{}, false, err
	}
	state.ActiveSlot = current.Slot
	state.HealthySlot = current.Slot
	return state, false, nil
}

func validateManualHostUpgradeCurrentState(
	ctx context.Context,
	current manualHostRuntimeObservation,
	state HostSelfUpdateState,
	persisted bool,
	rt manualHostUpgradeRuntime,
) error {
	if err := state.validate(); err != nil ||
		state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != current.Slot ||
		state.HealthySlot != current.Slot ||
		state.ActiveAgentVersion != current.Agent.Version ||
		state.ActiveExecutorVersion != current.Executor.Version {
		return errors.New(
			"managed Host runtime state is not a stable healthy current pair",
		)
	}
	hasBinding, err := rt.selfUpdate.hostSelfUpdateSlotHasBinding(current.Slot)
	if err != nil {
		return errors.New("inspect active Host runtime slot binding")
	}
	if !hasBinding {
		if current.Slot != HostSelfUpdateSlotA || !persisted &&
			state.RollbackSlot != "" {
			return errors.New("unbound Host runtime is not the bootstrap slot")
		}
		return nil
	}
	request, digests, err := readManualHostUpdateSlotBinding(
		current.Slot, rt.selfUpdate,
	)
	if err != nil || request.AgentVersion != current.Agent.Version ||
		request.ExecutorVersion != current.Executor.Version ||
		request.Commit != current.Agent.Commit ||
		rt.selfUpdate.verifyHostSelfUpdateSlot(
			ctx,
			current.Slot,
			filepath.Join(rt.selfUpdate.slotsRoot, current.Slot),
			request,
			digests,
		) != nil {
		return errors.New("active Host runtime slot binding is invalid")
	}
	return nil
}

func readManualHostUpdateSlotBinding(
	slot string,
	rt hostSelfUpdateExecutorRuntime,
) (HostSelfUpdateRequest, hostSelfUpdateSlotDigests, error) {
	root := filepath.Join(rt.slotsRoot, slot)
	read := func(name string) (string, error) {
		payload, err := readHostSelfUpdateSlotMarker(
			filepath.Join(root, name), !rt.allowTestPaths,
		)
		if err != nil {
			return "", err
		}
		return strings.TrimSuffix(string(payload), "\n"), nil
	}
	values := make(map[string]string)
	for _, name := range []string{
		".generation", ".agent-version", ".executor-version", ".commit",
		".artifact-sha256", ".agent-protocol", ".executor-protocol",
		".mutation-protocol", ".recovery-protocol", ".agent-sha256",
		".local-executor-sha256",
	} {
		value, err := read(name)
		if err != nil {
			return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
		}
		values[name] = value
	}
	parseProtocol := func(name string) (int, error) {
		return strconv.Atoi(values[name])
	}
	agentProtocol, err := parseProtocol(".agent-protocol")
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	executorProtocol, err := parseProtocol(".executor-protocol")
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	mutationProtocol, err := parseProtocol(".mutation-protocol")
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	recoveryProtocol, err := parseProtocol(".recovery-protocol")
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	releasePayload, err := readHostSelfUpdateSlotMarker(
		filepath.Join(root, ".release-binding.json"), !rt.allowTestPaths,
	)
	if err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	var release HostSelfUpdateReleaseIdentity
	decoder := json.NewDecoder(bytes.NewReader(releasePayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&release); err != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, err
	}
	request := HostSelfUpdateRequest{
		Generation:              values[".generation"],
		AgentVersion:            values[".agent-version"],
		ExecutorVersion:         values[".executor-version"],
		Commit:                  values[".commit"],
		ArtifactSHA256:          values[".artifact-sha256"],
		AgentProtocolVersion:    agentProtocol,
		ExecutorProtocolVersion: executorProtocol,
		MutationProtocolVersion: mutationProtocol,
		RecoveryProtocolVersion: recoveryProtocol,
		Release:                 release,
	}
	digests := hostSelfUpdateSlotDigests{
		AgentSHA256:    values[".agent-sha256"],
		ExecutorSHA256: values[".local-executor-sha256"],
	}
	if err := request.validate(); err != nil || digests.validate() != nil {
		return HostSelfUpdateRequest{}, hostSelfUpdateSlotDigests{}, errors.New(
			"Host runtime slot binding is invalid",
		)
	}
	return request, digests, nil
}

func manualHostUpgradeAlreadyCurrent(
	slot string,
	current manualHostRuntimeObservation,
	target HostSelfUpdateRequest,
	targetDigests hostSelfUpdateSlotDigests,
	rt manualHostUpgradeRuntime,
) (bool, error) {
	if current.Agent.Commit != target.Commit ||
		current.Executor.Commit != target.Commit {
		return false, nil
	}
	currentDigests, err := hostSelfUpdateArtifactBinaryDigests(
		filepath.Join(rt.selfUpdate.slotsRoot, slot),
	)
	if err != nil || currentDigests != targetDigests {
		return false, nil
	}
	hasBinding, err := rt.selfUpdate.hostSelfUpdateSlotHasBinding(slot)
	if err != nil {
		return false, err
	}
	if !hasBinding {
		return true, nil
	}
	bound, _, err := readManualHostUpdateSlotBinding(slot, rt.selfUpdate)
	if err != nil {
		return false, err
	}
	return sameManualHostUpgradeArchiveContent(bound, target), nil
}

func sameManualHostUpgradeArchiveContent(
	bound HostSelfUpdateRequest,
	target HostSelfUpdateRequest,
) bool {
	return bound.validate() == nil && target.validate() == nil &&
		bound.AgentVersion == target.AgentVersion &&
		bound.ExecutorVersion == target.ExecutorVersion &&
		bound.Commit == target.Commit &&
		bound.ArtifactSHA256 == target.ArtifactSHA256 &&
		bound.AgentProtocolVersion == target.AgentProtocolVersion &&
		bound.ExecutorProtocolVersion == target.ExecutorProtocolVersion &&
		bound.MutationProtocolVersion == target.MutationProtocolVersion &&
		bound.RecoveryProtocolVersion == target.RecoveryProtocolVersion &&
		bound.Release.ArchiveAssetName == target.Release.ArchiveAssetName &&
		bound.Release.ArchiveSize == target.Release.ArchiveSize &&
		bound.Release.ArchiveSHA256 == target.Release.ArchiveSHA256 &&
		bound.Release.Arch == target.Release.Arch &&
		bound.Release.MinimumPanelVersion == target.Release.MinimumPanelVersion
}

func inspectManualHostUpgradeDurableBlockers(
	ctx context.Context,
	state HostSelfUpdateState,
	policy LocalExecutorPolicy,
	legacyTargets []Target,
	allowMissingState bool,
	rt manualHostUpgradeRuntime,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateManualHostUpgradeStateRoots(rt); err != nil {
		return err
	}
	current, err := rt.selfUpdate.loadPersistedState()
	if errors.Is(err, os.ErrNotExist) && allowMissingState &&
		state.Phase == HostSelfUpdatePhaseStable {
		current = state
		err = nil
	}
	if err != nil || current != state || state.validate() != nil ||
		(state.Phase != HostSelfUpdatePhaseStable &&
			state.Phase != HostSelfUpdatePhaseActivating) {
		return errors.New("Host self-update state changed or is not upgrade-owned")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	journal, err := readManualHostUpgradeJournal(rt)
	if err != nil {
		return err
	}
	if journal.ActiveJob != nil || journal.ActivePlan != nil ||
		journal.ActivePortPlan != nil {
		return errors.New("an active Host Agent job blocks manual runtime upgrade")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rejectManualHostUpgradeStateFile(
		filepath.Join(rt.paths.hostStateRoot, runtimeTokenClaimStateFileName),
		"Host Agent runtime token claim",
		rt,
	); err != nil {
		return err
	}
	credentialRuntime := defaultRuntimeCredentialExecutorRuntime()
	credentialRuntime.statePath = rt.paths.runtimeCredentialPath
	credentialRuntime.allowTestPaths = rt.allowTestPaths
	if _, exists, err := credentialRuntime.loadStatus(); err != nil || exists {
		if err != nil {
			return errors.New("Local Executor runtime credential state is unsafe")
		}
		return errors.New("Local Executor runtime credential rotation blocks upgrade")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanManualHostRemoteMutationLedgers(rt); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanManualHostLegacyHelperState(rt); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanManualHostUpdateCheckpoints(
		policy,
		legacyTargets,
		rt,
	); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := scanManualHostPortLedgers(rt); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rejectManualHostUpgradeGrant(rt); err != nil {
		return err
	}
	return nil
}

func validateManualHostUpgradeStateRoots(rt manualHostUpgradeRuntime) error {
	localInfo, err := os.Lstat(rt.paths.localExecutorStateRoot)
	if err != nil || !localInfo.IsDir() ||
		localInfo.Mode()&os.ModeSymlink != 0 ||
		(!rt.allowTestPaths &&
			(localInfo.Mode().Perm() != 0o700 || !isRootOwner(localInfo) ||
				validateSecureRootPath(rt.paths.localExecutorStateRoot, true) != nil)) {
		return errors.New("Local Executor state root is unsafe")
	}
	hostInfo, err := os.Lstat(rt.paths.hostStateRoot)
	if rt.allowTestPaths && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !hostInfo.IsDir() || hostInfo.Mode()&os.ModeSymlink != 0 ||
		hostInfo.Mode().Perm() != 0o700 {
		return errors.New("Host Agent state root is unsafe")
	}
	if !rt.allowTestPaths {
		identity, identityErr := LookupManagedServiceIdentity(
			manualHostUpgradeAgentUser, manualHostUpgradeAgentGroup,
		)
		stat, ok := hostInfo.Sys().(*syscall.Stat_t)
		if identityErr != nil || !ok || stat.Uid != identity.UID ||
			stat.Gid != identity.GID ||
			validateSecureRootPath(filepath.Dir(rt.paths.hostStateRoot), true) != nil {
			return errors.New("Host Agent state root owner is invalid")
		}
	}
	return nil
}

func readManualHostUpgradeJournal(
	rt manualHostUpgradeRuntime,
) (journalData, error) {
	path := filepath.Join(rt.paths.hostStateRoot, "journal.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return journalData{}, nil
	}
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > 4<<20 {
		return journalData{}, errors.New("Host Agent journal is unsafe")
	}
	if !rt.allowTestPaths {
		identity, identityErr := LookupManagedServiceIdentity(
			manualHostUpgradeAgentUser,
			manualHostUpgradeAgentGroup,
		)
		stat, ok := info.Sys().(*syscall.Stat_t)
		if identityErr != nil || !ok || stat.Uid != identity.UID ||
			stat.Gid != identity.GID {
			return journalData{}, errors.New("Host Agent journal owner is invalid")
		}
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil || !os.SameFile(info, openedInfo) {
		if file != nil {
			_ = file.Close()
		}
		return journalData{}, errors.New("Host Agent journal changed during secure open")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	decoder.DisallowUnknownFields()
	var journal journalData
	if err := decoder.Decode(&journal); err != nil {
		return journalData{}, errors.New("decode Host Agent journal")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return journalData{}, errors.New("Host Agent journal contains trailing data")
	}
	return journal, nil
}

func rejectManualHostUpgradeStateFile(
	path, label string,
	rt manualHostUpgradeRuntime,
) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > 1<<20 {
		return fmt.Errorf("%s state is unsafe", label)
	}
	return fmt.Errorf("%s blocks manual runtime upgrade", label)
}

func scanManualHostRemoteMutationLedgers(rt manualHostUpgradeRuntime) error {
	return scanManualHostRemoteMutationLedgersAt(
		rt.paths.localExecutorStateRoot,
		rt,
	)
}

func scanManualHostRemoteMutationLedgersAt(
	stateRoot string,
	rt manualHostUpgradeRuntime,
) error {
	root := filepath.Join(stateRoot, "ledger")
	entries, err := readOptionalManualHostDirectory(root, rt)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("Local Executor mutation ledger contains an unsafe entry")
		}
		var ledger executorMutationLedger
		if decodeManualHostPrivateJSON(
			filepath.Join(root, entry.Name()), 64<<10,
			"Local Executor mutation ledger", &ledger, rt,
		) != nil || ledger.validate(ledger.TargetID) != nil ||
			entry.Name() != "target-"+remoteStableKey(ledger.TargetID)+".json" {
			return errors.New("Local Executor mutation ledger is invalid")
		}
		if ledger.State != remoteLedgerTerminal {
			return errors.New("a non-terminal Local Executor mutation blocks upgrade")
		}
	}
	return nil
}

func scanManualHostLegacyHelperState(rt manualHostUpgradeRuntime) error {
	path := rt.paths.legacyHelperConfigPath
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("legacy update helper configuration is unsafe")
	}
	cfg, err := LoadHelperConfig(path, !rt.allowTestPaths)
	if err != nil {
		return errors.New("legacy update helper configuration is unsafe")
	}
	if err := scanManualHostRemoteMutationLedgersAt(cfg.StateDir, rt); err != nil {
		return err
	}
	return nil
}

func manualHostUpgradeFixedSystemdCheckpointTargets() []Target {
	targets := make([]Target, 0, len(manualHostUpgradeFixedSystemdServiceTypes))
	for _, serviceType := range manualHostUpgradeFixedSystemdServiceTypes {
		profile, ok := standardSystemdProfileFor(serviceType)
		if !ok {
			continue
		}
		targets = append(targets, Target{
			TargetID:       serviceType,
			ServiceType:    serviceType,
			DeploymentMode: ModeSystemd,
			Systemd: &SystemdTarget{
				Unit:        profile.unit,
				ReleaseRoot: profile.releaseRoot,
			},
		})
	}
	return targets
}

func scanManualHostUpdateCheckpoints(
	policy LocalExecutorPolicy,
	legacyTargets []Target,
	rt manualHostUpgradeRuntime,
) error {
	if err := policy.Validate(); err != nil {
		return errors.New("Local Executor policy changed before checkpoint inspection")
	}
	type checkpointExpectation struct {
		target   Target
		expected bool
	}
	known := make(map[string]checkpointExpectation,
		len(policy.Targets)+len(legacyTargets)+len(rt.fixedCheckpoints))
	add := func(path string, target Target, expected bool) error {
		path = filepath.Clean(path)
		if current, exists := known[path]; exists {
			if current.expected && expected &&
				(current.target.TargetID != target.TargetID ||
					current.target.DeploymentMode != target.DeploymentMode) {
				return errors.New(
					"managed target configurations disagree about an update checkpoint",
				)
			}
			if current.expected || !expected {
				return nil
			}
		}
		known[path] = checkpointExpectation{target: target, expected: expected}
		return nil
	}
	for _, target := range rt.fixedCheckpoints {
		if target.DeploymentMode != ModeSystemd || target.Systemd == nil {
			return errors.New("fixed systemd checkpoint target is invalid")
		}
		if err := add(checkpointPath(target), target, false); err != nil {
			return err
		}
	}
	for _, localTarget := range policy.Targets {
		target := localTarget.runtimeTarget(policy.HostID)
		path := checkpointPath(target)
		if filepath.Dir(path) == filepath.Clean(LocalExecutorMutationStateDir) &&
			filepath.Clean(rt.paths.localExecutorStateRoot) !=
				filepath.Clean(LocalExecutorMutationStateDir) {
			path = filepath.Join(rt.paths.localExecutorStateRoot, filepath.Base(path))
		}
		if err := add(path, target, true); err != nil {
			return err
		}
	}
	for _, target := range legacyTargets {
		if err := add(checkpointPath(target), target, true); err != nil {
			return err
		}
	}
	seen := make(map[string]bool, len(known))
	entries, err := readOptionalManualHostDirectory(
		rt.paths.localExecutorStateRoot, rt,
	)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".autostream-updater-") ||
			!strings.HasSuffix(entry.Name(), ".checkpoint.json") {
			continue
		}
		path := filepath.Join(rt.paths.localExecutorStateRoot, entry.Name())
		expectation, expectedPath := known[filepath.Clean(path)]
		if err := inspectManualHostUpdateCheckpoint(
			path,
			expectation.target,
			expectedPath && expectation.expected,
			rt,
		); err != nil {
			return err
		}
		seen[filepath.Clean(path)] = true
	}
	for path, expectation := range known {
		if seen[path] {
			continue
		}
		if err := inspectManualHostUpdateCheckpoint(
			path,
			expectation.target,
			expectation.expected,
			rt,
		); err != nil {
			return err
		}
	}
	return nil
}

func inspectManualHostUpdateCheckpoint(
	path string,
	target Target,
	expected bool,
	rt manualHostUpgradeRuntime,
) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("Local Executor update checkpoint is unsafe")
	}
	var checkpoint updateCheckpoint
	if err := decodeManualHostPrivateJSON(
		path, 1<<20, "Local Executor update checkpoint", &checkpoint, rt,
	); err != nil || checkpoint.SchemaVersion != checkpointSchemaVersion ||
		!identifierPattern.MatchString(checkpoint.JobID) ||
		!identifierPattern.MatchString(checkpoint.TargetID) ||
		(checkpoint.DeploymentMode != ModeSystemd &&
			checkpoint.DeploymentMode != ModeDocker) ||
		!versionPattern.MatchString(checkpoint.TargetVersion) ||
		(expected &&
			(checkpoint.TargetID != target.TargetID ||
				checkpoint.DeploymentMode != target.DeploymentMode)) {
		return errors.New("Local Executor update checkpoint is invalid")
	}
	if checkpoint.Phase != "succeeded" && checkpoint.Phase != "rolled_back" {
		return errors.New("a non-terminal Local Executor update checkpoint blocks upgrade")
	}
	return nil
}

func scanManualHostPortLedgers(rt manualHostUpgradeRuntime) error {
	base := rt.paths.localExecutorStateRoot
	if err := scanManualHostPortLedgerNamespace(
		filepath.Join(base, "port-ledger"), false, rt,
	); err != nil {
		return err
	}
	if _, err := readOptionalManualHostDirectory(
		filepath.Join(base, "docker-port"), rt,
	); err != nil {
		return err
	}
	return scanManualHostPortLedgerNamespace(
		filepath.Join(base, "docker-port", "port-ledger"), true, rt,
	)
}

func scanManualHostPortLedgerNamespace(
	root string,
	docker bool,
	rt manualHostUpgradeRuntime,
) error {
	jobsRoot := filepath.Join(root, "jobs")
	entries, err := readOptionalManualHostDirectory(jobsRoot, rt)
	if err != nil {
		return err
	}
	type terminalJob struct {
		target string
		job    string
	}
	terminal := make(map[terminalJob]bool)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("port mutation ledger contains an unsafe entry")
		}
		if docker {
			var ledger dockerPortLedger
			if decodeManualHostPrivateJSON(
				filepath.Join(jobsRoot, entry.Name()),
				systemdPortLedgerMaxBytes, "Docker port mutation ledger",
				&ledger, rt,
			) != nil || ledger.validate(ledger.Plan.TargetID) != nil ||
				entry.Name() != remoteStableKey(
					ledger.Plan.TargetID, ledger.Plan.JobID,
				)+".json" {
				return errors.New("Docker port mutation ledger is invalid")
			}
			if ledger.State != dockerPortLedgerTerminal {
				return errors.New("a non-terminal Docker port mutation blocks upgrade")
			}
			terminal[terminalJob{ledger.Plan.TargetID, ledger.Plan.JobID}] = true
			continue
		}
		var ledger systemdPortLedger
		if decodeManualHostPrivateJSON(
			filepath.Join(jobsRoot, entry.Name()),
			systemdPortLedgerMaxBytes, "systemd port mutation ledger",
			&ledger, rt,
		) != nil || ledger.validate(ledger.Plan.TargetID) != nil ||
			entry.Name() != remoteStableKey(
				ledger.Plan.TargetID, ledger.Plan.JobID,
			)+".json" {
			return errors.New("systemd port mutation ledger is invalid")
		}
		if ledger.State != systemdPortLedgerTerminal {
			return errors.New("a non-terminal systemd port mutation blocks upgrade")
		}
		terminal[terminalJob{ledger.Plan.TargetID, ledger.Plan.JobID}] = true
	}
	activeRoot := filepath.Join(root, "active")
	entries, err = readOptionalManualHostDirectory(activeRoot, rt)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("port mutation active pointer contains an unsafe entry")
		}
		var reference struct {
			TargetID string `json:"target_id"`
			JobID    string `json:"job_id"`
		}
		if decodeManualHostPrivateJSON(
			filepath.Join(activeRoot, entry.Name()), 64<<10,
			"port mutation active pointer", &reference, rt,
		) != nil || entry.Name() != remoteStableKey(reference.TargetID)+".json" ||
			!terminal[terminalJob{reference.TargetID, reference.JobID}] {
			return errors.New("port mutation active pointer is not terminal")
		}
	}
	return nil
}

func readOptionalManualHostDirectory(
	path string,
	rt manualHostUpgradeRuntime,
) ([]os.DirEntry, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		(!rt.allowTestPaths &&
			(info.Mode().Perm() != 0o700 || !isRootOwner(info) ||
				validateSecureRootPath(path, true) != nil)) {
		return nil, errors.New("manual Host runtime state directory is unsafe")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, errors.New("read manual Host runtime state directory")
	}
	return entries, nil
}

func decodeManualHostPrivateJSON(
	path string,
	maximum int64,
	label string,
	out any,
	rt manualHostUpgradeRuntime,
) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > maximum ||
		(!rt.allowTestPaths && !isRootOwner(info)) {
		return errors.New(label + " is not a private regular file")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil || !os.SameFile(info, openedInfo) ||
		(!rt.allowTestPaths &&
			validateRootOwnedFileAndParents(path, openedInfo, label) != nil) {
		if file != nil {
			_ = file.Close()
		}
		return errors.New(label + " changed during secure open")
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		return errors.New("read " + label)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errors.New("decode " + label)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New(label + " contains trailing data")
	}
	return nil
}

// rejectManualHostUpgradeGrant keeps manual upgrade preflight read-only with
// respect to the online Host self-update protocol. Only the normal healthy-slot
// Executor may converge or retire a durable grant.
func rejectManualHostUpgradeGrant(rt manualHostUpgradeRuntime) error {
	grant, err := loadHostSelfUpdateGrantState(
		rt.selfUpdate.grantStatePath, !rt.allowTestPaths,
	)
	if err != nil {
		return fmt.Errorf(
			"Host self-update grant blocks manual runtime upgrade; wait for the healthy-slot Local Executor to converge it: %w",
			err,
		)
	}
	if grant == nil {
		return nil
	}
	return errors.New(
		"an existing Host self-update grant blocks manual runtime upgrade; " +
			"wait for the healthy-slot Local Executor to converge it",
	)
}

func activateManualHostUpgrade(
	ctx context.Context,
	state HostSelfUpdateState,
	request HostSelfUpdateRequest,
	snapshot manualHostUpgradeSnapshot,
	rt manualHostUpgradeRuntime,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ensureManualHostUpgradeDeadline(state, rt.now()); err != nil {
		return err
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return err
	}
	if err := rt.selfUpdate.switchCurrent(state.PendingSlot); err != nil {
		return fmt.Errorf("switch manual Host runtime current slot: %w", err)
	}
	if err := rt.selfUpdate.restartLocalExecutor(ctx); err != nil {
		return err
	}
	executor, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateExecutorServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			state.PendingSlot,
			"bin",
			"autostream-local-executor",
		),
		"autostream-local-executor",
		rt,
	)
	if err != nil {
		return fmt.Errorf(
			"new Local Executor failed live binary verification: %w",
			err,
		)
	}
	if executor.Version != request.ExecutorVersion ||
		executor.Commit != request.Commit ||
		executor.MutationProtocol != request.MutationProtocolVersion ||
		executor.RecoveryProtocol != request.RecoveryProtocolVersion {
		return errors.New(
			"new Local Executor failed live binary verification: runtime identity mismatch",
		)
	}
	if rt.selfUpdate.watchdogStatus == nil {
		return errors.New("Local Executor watchdog verification is unavailable")
	}
	watchdog, err := rt.selfUpdate.watchdogStatus(ctx)
	if err != nil || watchdog.State != state ||
		watchdog.CurrentSlot != state.PendingSlot ||
		watchdog.ExecutorVersion != request.ExecutorVersion ||
		watchdog.ExecutorProtocolVersion != request.ExecutorProtocolVersion {
		return errors.New("new Local Executor watchdog handshake is invalid")
	}
	if err := rt.selfUpdate.restartHostAgent(ctx); err != nil {
		return err
	}
	agent, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			state.PendingSlot,
			"bin",
			"autostream-host-agent",
		),
		"autostream-host-agent",
		rt,
	)
	if err != nil {
		return fmt.Errorf(
			"new Host Agent failed live binary verification: %w",
			err,
		)
	}
	if agent.Version != request.AgentVersion ||
		agent.Commit != request.Commit {
		return errors.New(
			"new Host Agent failed live binary verification: runtime identity mismatch",
		)
	}
	if err := verifyManualHostUpgradeSnapshot(ctx, snapshot, rt); err != nil {
		return err
	}
	if err := ensureManualHostUpgradeDeadline(state, rt.now()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	committed := commitHostSelfUpdate(state)
	if err := rt.selfUpdate.saveState(committed); err != nil {
		return errors.New("commit manual Host runtime state")
	}
	return nil
}

func rollbackManualHostUpgrade(
	ctx context.Context,
	state HostSelfUpdateState,
	healthy manualHostRuntimeObservation,
	rt manualHostUpgradeRuntime,
) error {
	rollback := beginHostSelfUpdateRollback(state)
	if err := rt.selfUpdate.saveState(rollback); err != nil {
		return errors.New("persist manual Host runtime rollback fence")
	}
	if err := rt.selfUpdate.switchCurrent(rollback.HealthySlot); err != nil {
		return errors.New("restore healthy Host runtime current slot")
	}
	if err := rt.selfUpdate.restartLocalExecutor(ctx); err != nil {
		return errors.New("restart healthy Local Executor during rollback")
	}
	if err := rt.selfUpdate.verifyHealthyLocalExecutor(
		ctx, rollback.HealthySlot, rollback,
	); err != nil {
		return errors.New("verify healthy Local Executor during rollback")
	}
	if err := rt.selfUpdate.restartHostAgent(ctx); err != nil {
		return errors.New("restart healthy Host Agent during rollback")
	}
	actualAgent, err := verifyManualHostUnitProcess(
		ctx,
		hostSelfUpdateServiceUnit,
		filepath.Join(
			rt.selfUpdate.slotsRoot,
			rollback.HealthySlot,
			"bin",
			"autostream-host-agent",
		),
		"autostream-host-agent",
		rt,
	)
	if err != nil || actualAgent != healthy.Agent {
		return errors.New("verify healthy Host Agent during rollback")
	}
	restored := clearRolledBackHostSelfUpdate(rollback)
	if err := rt.selfUpdate.saveState(restored); err != nil {
		return errors.New("commit manual Host runtime rollback")
	}
	if err := rt.selfUpdate.recoverHostSelfUpdateSlotArtifacts(); err != nil {
		return errors.New("clean manual Host runtime rollback artifacts")
	}
	if restored.ActiveAgentVersion != healthy.Agent.Version ||
		restored.ActiveExecutorVersion != healthy.Executor.Version {
		return errors.New("manual Host runtime rollback identity is inconsistent")
	}
	return nil
}

func acquireManualHostUpgradeLocks() (func(), error) {
	directory := privilegedLockDir()
	setupUnlock, err := AcquireHostRuntimeSetupLock()
	if err != nil {
		return func() {}, err
	}
	lifecycleUnlock, err := lockManualHostUpgradeFile(
		filepath.Join(directory, ".autostream-host-lifecycle.lock"),
	)
	if err != nil {
		setupUnlock()
		return func() {}, err
	}
	legacyInstallerUnlock, err := lockManualHostUpgradeFile(
		legacyUpdateHostInstallLockPath,
	)
	if err != nil {
		lifecycleUnlock()
		setupUnlock()
		return func() {}, err
	}
	return func() {
		legacyInstallerUnlock()
		lifecycleUnlock()
		setupUnlock()
	}, nil
}

func lockManualHostUpgradeFile(path string) (func(), error) {
	fd, err := syscall.Open(
		path,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return func() {}, err
	}
	file := os.NewFile(uintptr(fd), path)
	failure := func(err error) (func(), error) {
		_ = file.Close()
		return func() {}, err
	}
	var opened syscall.Stat_t
	if err := syscall.Fstat(fd, &opened); err != nil ||
		opened.Uid != 0 || opened.Gid != 0 || opened.Nlink != 1 ||
		opened.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		opened.Mode&0o777 != 0o600 {
		return failure(errors.New("privileged Host lifecycle lock file is unsafe"))
	}
	var named syscall.Stat_t
	if err := syscall.Lstat(path, &named); err != nil ||
		named.Dev != opened.Dev || named.Ino != opened.Ino {
		return failure(errors.New("privileged Host lifecycle lock identity changed"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return failure(errors.New("another privileged Host lifecycle operation is active"))
	}
	if err := syscall.Lstat(path, &named); err != nil ||
		named.Dev != opened.Dev || named.Ino != opened.Ino ||
		named.Uid != 0 || named.Gid != 0 || named.Nlink != 1 ||
		named.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		named.Mode&0o777 != 0o600 {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		return failure(errors.New("privileged Host lifecycle lock changed after acquisition"))
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
