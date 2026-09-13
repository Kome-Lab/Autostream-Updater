package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

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
