//go:build linux

package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

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
