//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type softwareClaimRecoveryRootRuntime struct {
	manual           manualHostUpgradeRuntime
	readPolicy       func(context.Context, LocalExecutorPolicy) (HostAgentPolicy, error)
	acquireLifecycle func() (*heldHostLifecycleLock, error)
	lifecycle        *heldHostLifecycleLock
}

func defaultSoftwareClaimRecoveryRootRuntime(client *http.Client) softwareClaimRecoveryRootRuntime {
	return softwareClaimRecoveryRootRuntime{
		manual: defaultManualHostUpgradeRuntime(), acquireLifecycle: acquireHeldHostLifecycleLock,
		readPolicy: func(ctx context.Context, policy LocalExecutorPolicy) (HostAgentPolicy, error) {
			identity, err := LoadManagedBootstrapConfig(HostAgentIdentityPath, true)
			if err != nil || !identity.IsManagedBootstrap() || policy.Mutation == nil || identity.PanelURL != policy.Mutation.PanelURL {
				return HostAgentPolicy{}, errors.New("canonical recovery policy identity is unavailable")
			}
			configured := &http.Client{Timeout: 2 * time.Second}
			if client != nil {
				copy := *client
				configured = &copy
				if configured.Timeout <= 0 || configured.Timeout > 2*time.Second {
					configured.Timeout = 2 * time.Second
				}
			}
			panel := PanelClient{BaseURL: policy.Mutation.PanelURL, Token: identity.RuntimeToken, HTTP: configured}
			current, changed, err := panel.FetchHostAgentPolicy(ctx, identity.NodeID, 0)
			if err != nil || !changed || current == nil {
				return HostAgentPolicy{}, errors.New("authenticated root recovery policy is unavailable")
			}
			return *current, nil
		},
	}
}

func handleLocalExecutorSoftwareClaimRecovery(ctx context.Context, policy LocalExecutorPolicy, request LocalExecutorRequest, rt softwareClaimRecoveryRootRuntime) LocalExecutorResponse {
	if request.Operation != localExecutorSoftwareClaimRecoveryOperation || request.Validate() != nil ||
		rt.readPolicy == nil || rt.acquireLifecycle == nil {
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "invalid_request")
	}
	diagnostic := newSoftwareClaimRecoveryRootRefusal(request.SoftwareClaimRecovery.Request)
	held, err := rt.acquireLifecycle()
	if err == nil {
		err = held.Verify()
	}
	if err != nil {
		held.Release()
		diagnostic.Phase = "lifecycle_lock"
		logSoftwareClaimRecoveryRootRefusal(diagnostic)
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	defer held.Release()
	rt.lifecycle = held
	diagnostic.LifecycleHeld = true
	if rt.manual.runner != nil {
		rt.manual.runner = softwareClaimRecoveryDiagnosticRunner{CommandRunner: rt.manual.runner, diagnostic: &diagnostic}
	}
	proof, err := inspectSoftwareClaimRecoveryRoot(ctx, policy, request, rt)
	if err != nil {
		// The reply intentionally omits filenames, state bytes and credentials.
		diagnostic.Phase = softwareClaimRecoveryRefusalPhase(err)
		var authority softwareClaimWatchdogAuthorityError
		if errors.As(err, &authority) && softwareClaimWatchdogDiagnosticReasonAllowed(authority.reason) {
			diagnostic.WatchdogGuard = authority.reason
		}
		logSoftwareClaimRecoveryRootRefusal(diagnostic)
		return localExecutorFailureForVersion(LocalExecutorMutationProtocolVersion, "state_unavailable")
	}
	return LocalExecutorResponse{Version: LocalExecutorMutationProtocolVersion, SoftwareClaimRecovery: &proof}
}

func inspectSoftwareClaimRecoveryRoot(ctx context.Context, policy LocalExecutorPolicy, request LocalExecutorRequest, runtime softwareClaimRecoveryRootRuntime) (SoftwareClaimRecoveryProof, error) {
	rt := runtime.manual
	if ctx.Err() != nil || request.Validate() != nil || policy.Validate() != nil ||
		request.Operation != localExecutorSoftwareClaimRecoveryOperation || policy.ProtocolVersion != 2 ||
		policy.SourcePolicyRevision != request.SourcePolicyRevision || policy.ProjectionRevision != request.OwnershipPolicyRevision ||
		policy.PolicyRevision != request.ExecutorPolicyRevision {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery root policy fence is invalid")
	}
	if runtime.lifecycle == nil || runtime.lifecycle.allowTestPaths != rt.allowTestPaths || runtime.lifecycle.Verify() != nil {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery lacks its actual held lifecycle lock")
	}
	digest, err := policy.SHA256()
	if err != nil || digest != request.SoftwareClaimRecovery.ExecutorPolicySHA256 {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery root policy digest changed")
	}
	if !rt.allowTestPaths {
		current, err := LoadLocalExecutorPolicy(DefaultLocalExecutorPolicyPath, true)
		currentDigest, digestErr := current.SHA256()
		if err != nil || digestErr != nil || currentDigest != digest {
			return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery canonical root policy changed")
		}
	}
	rootTarget, exists := policy.Target(request.ServiceID)
	if !exists || rootTarget.ConfigRevision != request.SoftwareClaimRecovery.Request.ConfigRevision {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery root target config binding is invalid")
	}
	current, err := runtime.readPolicy(ctx, policy)
	if err != nil || current.validateForService(current.ServiceID, 0) != nil || current.ExecutionHostID != policy.HostID ||
		current.SourcePolicyRevision != policy.SourcePolicyRevision || current.Revision != policy.ProjectionRevision ||
		current.LocalExecutorPolicyRevision != policy.PolicyRevision || current.LocalExecutorPolicySHA256 != digest {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery authenticated policy disagrees with root policy")
	}
	binding := HostAgentBinding{ServiceID: current.ServiceID, ServiceType: ServiceTypeUpdateAgent,
		TransportMode: current.TransportMode, ExecutionHostID: current.ExecutionHostID, OwnershipEpoch: current.OwnershipEpoch}
	if validateSoftwareClaimRecoveryPolicy(request.SoftwareClaimRecovery.Request, binding, current) != nil {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery ownership fence is invalid")
	}
	authTarget, _ := hostPullPolicyTarget(current, request.ServiceID)
	if authTarget.ServiceType != rootTarget.ServiceType || authTarget.DeploymentMode != rootTarget.DeploymentMode ||
		(authTarget.AppliedConfigSHA256 != "" && authTarget.AppliedConfigSHA256 != rootTarget.ConfigSHA256) {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery root target differs from authenticated target")
	}
	if err := validateManualHostUpgradeStateRoots(rt); err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	owner := func(info os.FileInfo) bool {
		if rt.allowTestPaths {
			return managedSnapshotOwnedByCurrentUser(info)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && stat.Uid == policy.AgentUID && stat.Gid == policy.AgentGID
	}
	snapshot, hasIntent, err := loadSoftwareClaimRecoverySnapshot(rt.paths.hostStateRoot, owner)
	intent := snapshot.Intent
	if err != nil || (hasIntent && !intent.policyMatches(current)) {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery durable intent disagrees with the request")
	}
	rotating := hasIntent && !intent.Original.sameIntent(request.SoftwareClaimRecovery.Request)
	if rotating && (intent.SchemaVersion != 2 || !intent.Settled || intent.TerminalClear == nil ||
		intent.Original.JobID == request.SoftwareClaimRecovery.Request.JobID) {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery cannot replace an unsettled or legacy root intent")
	}
	blockedJobs := map[string]bool{request.SoftwareClaimRecovery.Request.JobID: true}
	if hasIntent {
		blockedJobs[intent.Original.JobID] = true
		if validateSoftwareClaimRecoveryPolicy(intent.Original, binding, current) != nil {
			return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery previous intent no longer matches current policy")
		}
	}
	for _, archive := range snapshot.Archives {
		if !archive.Intent.policyMatches(current) || validateSoftwareClaimRecoveryPolicy(archive.Intent.Original, binding, current) != nil ||
			(rotating && archive.Intent.Original.JobID == request.SoftwareClaimRecovery.Request.JobID) {
			return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery immutable archive has another identity or policy")
		}
		blockedJobs[archive.Intent.Original.JobID] = true
	}
	journal, err := readManualHostUpgradeJournal(rt)
	if err != nil || validateJournalData(journal) != nil || journal.ActivePlan != nil || journal.ActivePortPlan != nil ||
		journal.ActivePortPolicy != nil || journal.ActiveStageFailure != nil || !softwareClaimRecoveryPendingAllowed(journal) {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery journal contains execution or pending report state")
	}
	cursorIntent := intent
	if !hasIntent || rotating {
		// This is a bounded read-only preflight, never a migration or claim.
		// Durable intent is required before a subsequent CP request can occur.
		cursorIntent = newSoftwareClaimRecoveryIntent(request.SoftwareClaimRecovery.Request, current.ServiceID, current.ExecutionHostID, current)
		if rotating {
			cursorIntent.PreviousSettledRawSHA256 = softwareClaimRecoveryRawSHA256(snapshot.Raw)
		}
	}
	maximumGeneration := request.SoftwareClaimRecovery.Request.LeaseGeneration
	if hasIntent && !rotating {
		maximumGeneration++
	}
	if journal.ActiveJob != nil && ((hasIntent && intent.Settled && !rotating) ||
		!softwareClaimRecoveryCursorMatches(cursorIntent, *journal.ActiveJob) ||
		journal.ActiveJob.EffectiveType() != rootTarget.ServiceType || journal.ActiveJob.DeploymentMode != rootTarget.DeploymentMode ||
		journal.ActiveJob.LeaseGeneration < 1 || journal.ActiveJob.LeaseGeneration > maximumGeneration ||
		journal.ActiveJob.LeaseToken != "" || !journal.ActiveJob.ReleaseToken.Empty()) {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery journal has another or an executing cursor")
	}
	for _, path := range []string{
		filepath.Join(rt.paths.hostStateRoot, journalActiveClearMarkerName),
		filepath.Join(rt.paths.hostStateRoot, journalActiveClearMarkerName+".tmp"),
		filepath.Join(rt.paths.hostStateRoot, runtimeTokenClaimStateFileName),
		rt.paths.stagedIdentityPath, rt.paths.wipingIdentityPath,
	} {
		if err := rejectSoftwareClaimRecoveryStateFile(path); err != nil {
			return SoftwareClaimRecoveryProof{}, err
		}
	}
	credential := defaultRuntimeCredentialExecutorRuntime()
	credential.statePath, credential.allowTestPaths = rt.paths.runtimeCredentialPath, rt.allowTestPaths
	if _, exists, err := credential.loadStatus(); err != nil || exists {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery is blocked by runtime credential state")
	}
	if err := rejectManualHostUpgradeGrant(rt); err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	state, err := rt.selfUpdate.loadPersistedState()
	if err != nil || state.validate() != nil || state.Phase != HostSelfUpdatePhaseStable ||
		state.ActiveSlot != state.HealthySlot || state.PendingGeneration != "" ||
		state.ActiveAgentVersion != state.ActiveExecutorVersion || state.ActiveExecutorVersion != rt.selfUpdate.executorVersion {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery requires a stable matched installed runtime")
	}
	currentSlot, err := rt.selfUpdate.readCurrentSlot()
	if err != nil || currentSlot != state.ActiveSlot {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery runtime slot changed")
	}
	agentState, pid, err := readManualHostUpgradeRecoveryServiceState(ctx, rt.runner, hostSelfUpdateServiceUnit)
	if err != nil || (agentState != "active" && (agentState != "inactive" || pid != 0)) {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery Agent service is not safely active or stopped")
	}
	observed, err := observeManualHostRuntimeForUpgrade(ctx, currentSlot, agentState == "inactive", rt)
	if err != nil || observed.Agent.Version != state.ActiveAgentVersion || observed.Executor.Version != state.ActiveExecutorVersion {
		return SoftwareClaimRecoveryProof{}, errors.New("software claim recovery installed runtime pair is unconfirmed")
	}
	watchdogs, err := inspectSoftwareClaimRecoveryWatchdogs(ctx, rt, observed, runtime.lifecycle)
	if err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	for jobID := range blockedJobs {
		if err := scanSoftwareClaimRecoveryRootRecords(jobID, policy, rt); err != nil {
			return SoftwareClaimRecoveryProof{}, err
		}
	}
	if err := watchdogs.Verify(ctx, rt, runtime.lifecycle); err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	if err := runtime.lifecycle.Verify(); err != nil {
		return SoftwareClaimRecoveryProof{}, err
	}
	if ctx.Err() != nil {
		return SoftwareClaimRecoveryProof{}, ctx.Err()
	}
	proof := SoftwareClaimRecoveryProof{
		RequestSHA256: request.SoftwareClaimRecovery.Request.sha256(), UpdaterID: current.ServiceID, HostID: policy.HostID,
		SourcePolicyRevision: policy.SourcePolicyRevision, ProjectionRevision: policy.ProjectionRevision,
		ExecutorPolicyRevision: policy.PolicyRevision, ExecutorPolicySHA256: digest,
		OwnershipEpoch: current.OwnershipEpoch, RuntimeVersion: observed.Agent.Version,
		NoMutation: true, ObservedAt: time.Now().UTC(),
		PriorSettledRawSHA256: cursorIntent.PreviousSettledRawSHA256,
	}
	return proof, proof.Validate()
}

func rejectSoftwareClaimRecoveryStateFile(path string) error {
	if path == "" {
		return nil
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.New("software claim recovery is blocked by other durable lifecycle state")
}

func scanSoftwareClaimRecoveryRootRecords(jobID string, policy LocalExecutorPolicy, rt manualHostUpgradeRuntime) error {
	if err := scanSoftwareClaimRecoveryRemoteRecords(jobID, rt.paths.localExecutorStateRoot, rt); err != nil {
		return err
	}
	var legacy []Target
	if _, err := os.Lstat(rt.paths.legacyHelperConfigPath); err == nil {
		cfg, err := LoadHelperConfig(rt.paths.legacyHelperConfigPath, !rt.allowTestPaths)
		if err != nil {
			return errors.New("software claim recovery legacy authority is unsafe")
		}
		legacy = cfg.Targets
		if err := scanSoftwareClaimRecoveryRemoteRecords(jobID, cfg.StateDir, rt); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("software claim recovery legacy authority is unsafe")
	}
	if err := scanManualHostUpdateCheckpoints(policy, legacy, rt); err != nil {
		return err
	}
	paths := make(map[string]bool)
	for _, target := range append(append([]Target(nil), rt.fixedCheckpoints...), legacy...) {
		paths[checkpointPath(target)] = true
	}
	for _, target := range policy.Targets {
		path := checkpointPath(target.runtimeTarget(policy.HostID))
		if filepath.Dir(path) == filepath.Clean(LocalExecutorMutationStateDir) && rt.allowTestPaths {
			path = filepath.Join(rt.paths.localExecutorStateRoot, filepath.Base(path))
		}
		paths[path] = true
	}
	entries, err := readOptionalManualHostDirectory(rt.paths.localExecutorStateRoot, rt)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".autostream-updater-") && strings.HasSuffix(entry.Name(), ".checkpoint.json") {
			paths[filepath.Join(rt.paths.localExecutorStateRoot, entry.Name())] = true
		}
	}
	for path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		var checkpoint updateCheckpoint
		if decodeManualHostPrivateJSON(path, 1<<20, "software claim recovery checkpoint", &checkpoint, rt) != nil || checkpoint.JobID == jobID {
			return errors.New("software claim recovery cannot discard a requested-job checkpoint, including a terminal checkpoint")
		}
	}
	if err := scanManualHostPortLedgers(rt); err != nil {
		return err
	}
	for _, namespace := range []struct {
		root   string
		docker bool
	}{
		{filepath.Join(rt.paths.localExecutorStateRoot, "port-ledger", "jobs"), false},
		{filepath.Join(rt.paths.localExecutorStateRoot, "docker-port", "port-ledger", "jobs"), true},
	} {
		entries, err := readOptionalManualHostDirectory(namespace.root, rt)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			path := filepath.Join(namespace.root, entry.Name())
			if namespace.docker {
				var ledger dockerPortLedger
				if decodeManualHostPrivateJSON(path, systemdPortLedgerMaxBytes, "software claim recovery port ledger", &ledger, rt) != nil || ledger.Plan.JobID == jobID {
					return errors.New("software claim recovery requested job has a root port record")
				}
			} else {
				var ledger systemdPortLedger
				if decodeManualHostPrivateJSON(path, systemdPortLedgerMaxBytes, "software claim recovery port ledger", &ledger, rt) != nil || ledger.Plan.JobID == jobID {
					return errors.New("software claim recovery requested job has a root port record")
				}
			}
		}
	}
	return nil
}

func scanSoftwareClaimRecoveryRemoteRecords(jobID, root string, rt manualHostUpgradeRuntime) error {
	ledgerRoot := filepath.Join(root, "ledger")
	entries, err := readOptionalManualHostDirectory(ledgerRoot, rt)
	if err != nil {
		return err
	}
	terminalStages := make(map[string]bool)
	for _, entry := range entries {
		var ledger executorMutationLedger
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" ||
			decodeManualHostPrivateJSON(filepath.Join(ledgerRoot, entry.Name()), 64<<10, "software claim recovery mutation ledger", &ledger, rt) != nil ||
			ledger.validate(ledger.TargetID) != nil || entry.Name() != "target-"+remoteStableKey(ledger.TargetID)+".json" ||
			ledger.State != remoteLedgerTerminal || ledger.JobID == jobID {
			return errors.New("software claim recovery cannot discard a requested-job or non-terminal root mutation record")
		}
		if ledger.Stage != nil {
			terminalStages[filepath.Clean(ledger.Stage.RootDir)] = true
		}
	}
	for _, directory := range []string{"requests", "results"} {
		entries, err := readOptionalManualHostDirectory(filepath.Join(root, directory), rt)
		if err != nil || len(entries) != 0 {
			return errors.New("software claim recovery has unconfirmed root execution residue")
		}
	}
	stages := filepath.Join(root, "stages")
	entries, err = readOptionalManualHostDirectory(stages, rt)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(stages, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
			!terminalStages[path] || (!rt.allowTestPaths && (!isRootOwner(info) || info.Mode().Perm()&0o022 != 0)) {
			return errors.New("software claim recovery has an orphan or unsafe root stage")
		}
	}
	return nil
}

// The parent mutation dispatcher calls this after acquiring the canonical
// lifecycle lock. A malformed intent blocks just as an unsettled one does.
func softwareClaimRecoveryIntentBlocksHost(policy LocalExecutorPolicy) error {
	return softwareClaimRecoveryIntentBlocksHostRuntime(policy, defaultManualHostUpgradeRuntime())
}

func softwareClaimRecoveryIntentBlocksHostRuntime(policy LocalExecutorPolicy, rt manualHostUpgradeRuntime) error {
	_, headErr := os.Lstat(filepath.Join(rt.paths.hostStateRoot, softwareClaimRecoveryIntentName))
	_, historyErr := os.Lstat(filepath.Join(rt.paths.hostStateRoot, softwareClaimRecoveryHistoryName))
	if errors.Is(headErr, os.ErrNotExist) && errors.Is(historyErr, os.ErrNotExist) {
		return nil
	}
	if err := validateManualHostUpgradeStateRoots(rt); err != nil {
		return errors.New("software claim recovery lifecycle marker is unsafe")
	}
	intent, exists, err := loadSoftwareClaimRecoveryIntent(rt.paths.hostStateRoot, func(info os.FileInfo) bool {
		if rt.allowTestPaths {
			return managedSnapshotOwnedByCurrentUser(info)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		return ok && stat.Uid == policy.AgentUID && stat.Gid == policy.AgentGID
	})
	if err != nil || (exists && !intent.Settled) {
		return errors.New("a terminal-only software claim recovery intent blocks host mutation")
	}
	return nil
}
