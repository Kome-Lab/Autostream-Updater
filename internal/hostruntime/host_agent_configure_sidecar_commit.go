package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func prepareSystemdPortSidecarsWithOptions(
	parent string,
	options HostAgentConfigurationOptions,
) (*preparedSystemdPortSidecars, error) {
	if err := validateSystemdPortSidecarDirectory(parent); err != nil {
		return nil, err
	}
	paths, err := canonicalSystemdPortSidecarPaths(parent)
	if err != nil {
		return nil, err
	}
	prepared := &preparedSystemdPortSidecars{
		parent:     parent,
		entries:    make(map[string]*preparedSystemdPortSidecar, len(paths)),
		exchange:   exchangeHostAgentSystemdSidecar,
		syncParent: syncDirectory,
		verifyLive: verifyHostAgentLiveSystemdSidecar,
	}
	prepared.replacementPairVerifier = prepared.replacementPairMatchesOnDisk
	failed := true
	defer func() {
		if failed {
			prepared.Abort()
		}
	}()
	for _, path := range paths {
		body, info, existed, err := readRootSystemdPortSidecarOptional(path)
		if err != nil {
			return nil, err
		}
		entry := &preparedSystemdPortSidecar{
			path:         path,
			existed:      existed,
			existing:     body,
			existingInfo: info,
		}
		prepared.entries[path] = entry
		if !existed {
			temp, err := os.CreateTemp(parent, "."+filepath.Base(path)+".configure-*")
			if err != nil {
				return nil, errors.New("create initial systemd port sidecar temporary file")
			}
			entry.temp = temp
			entry.tempPath = temp.Name()
			if err := temp.Chown(0, 0); err != nil {
				return nil, errors.New("set initial systemd port sidecar temporary file ownership")
			}
			if err := temp.Chmod(0o600); err != nil {
				return nil, errors.New("set initial systemd port sidecar temporary file mode")
			}
			if err := temp.Sync(); err != nil {
				return nil, errors.New("sync initial systemd port sidecar temporary file")
			}
			entry.tempInfo, err = temp.Stat()
			if err != nil ||
				!entry.tempInfo.Mode().IsRegular() ||
				entry.tempInfo.Mode().Perm() != 0o600 ||
				!updaterConfigHasInstallOwner(entry.tempInfo, 0) {
				return nil, errors.New("initial systemd port sidecar temporary file is unsafe")
			}
		}
	}
	if options.AdoptLiveSystemdSidecar {
		prepared.replacementTemp,
			prepared.replacementTempPath,
			prepared.replacementTempInfo,
			err = prepareHostAgentSystemdSidecarExchange(parent)
		if err != nil {
			return nil, err
		}
	}
	if err := prepared.verifyDestinations(); err != nil {
		return nil, err
	}
	if err := syncDirectory(parent); err != nil {
		return nil, errors.New("sync systemd port sidecar directory during preflight")
	}
	failed = false
	return prepared, nil
}

func (p *preparedSystemdPortSidecars) Commit(
	policy LocalExecutorPolicy,
) error {
	return p.CommitContext(
		context.Background(),
		policy,
		UpdaterConfigureIdentity{},
		nil,
		nil,
		HostAgentConfigurationOptions{},
	)
}

type hostAgentSystemdSidecarAdoption struct {
	plan          initialSystemdPortSidecarPlan
	currentPolicy LocalExecutorPolicy
	currentTarget LocalExecutorTarget
	stagedTarget  LocalExecutorTarget
}

func (p *preparedSystemdPortSidecars) CommitContext(
	ctx context.Context,
	policy LocalExecutorPolicy,
	identity UpdaterConfigureIdentity,
	currentIdentityBytes []byte,
	currentPolicyBytes []byte,
	options HostAgentConfigurationOptions,
) error {
	if p == nil || p.committed {
		return errors.New("initial systemd port sidecar update is not prepared")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	plans, err := initialSystemdPortSidecarPlans(policy, p.parent)
	if err != nil {
		return err
	}
	if err := p.verifyDestinations(); err != nil {
		return err
	}
	snapshots := make(map[string]initialSystemdPortSidecarSnapshot, len(p.entries))
	for path, entry := range p.entries {
		snapshots[path] = initialSystemdPortSidecarSnapshot{
			Existed: entry.existed,
			Body:    append([]byte(nil), entry.existing...),
		}
	}
	var adoption *hostAgentSystemdSidecarAdoption
	if options.AdoptLiveSystemdSidecar {
		adoption, err = authorizeHostAgentSystemdSidecarAdoption(
			policy,
			identity,
			currentIdentityBytes,
			currentPolicyBytes,
			plans,
			snapshots,
			p.parent,
		)
		if err != nil {
			return err
		}
		if p.replacementTemp == nil || p.replacementTempPath == "" ||
			p.replacementTempInfo == nil || p.exchange == nil || p.verifyLive == nil {
			return errors.New("live systemd sidecar adoption was not preflighted")
		}
	} else if err := validateInitialSystemdPortSidecarSnapshots(
		plans,
		snapshots,
	); err != nil {
		return err
	}
	for _, plan := range plans {
		entry, ok := p.entries[plan.Path]
		if !ok {
			return errors.New("canonical systemd port sidecar was not preflighted")
		}
		if entry.existed {
			continue
		}
		if err := entry.prepareBody(plan.Body); err != nil {
			return err
		}
	}
	if adoption != nil {
		if err := p.prepareReplacementBody(adoption.plan.Body); err != nil {
			return err
		}
	}
	if err := p.verifyDestinations(); err != nil {
		return err
	}
	var liveProof hostAgentLiveSystemdSidecarProof
	if adoption != nil {
		liveProof, err = p.verifyLive(
			ctx,
			adoption.currentPolicy,
			policy,
			adoption.currentTarget,
			adoption.stagedTarget,
		)
		if err != nil {
			return fmt.Errorf("verify live systemd sidecar target before adoption: %w", err)
		}
		if err := p.verifyDestinations(); err != nil {
			return err
		}
		p.rollbackAuthority = &hostAgentSystemdSidecarRollbackAuthority{
			verify:        p.verifyLive,
			currentPolicy: adoption.currentPolicy,
			stagedPolicy:  policy,
			currentTarget: adoption.currentTarget,
			stagedTarget:  adoption.stagedTarget,
			acceptedProof: liveProof,
		}
		entry, ok := p.entries[adoption.plan.Path]
		if !ok || !entry.existed {
			return errors.New("live systemd sidecar adoption destination was not preflighted")
		}
		if err := p.exchangeReplacement(entry); err != nil {
			return err
		}
	}
	for _, plan := range plans {
		entry := p.entries[plan.Path]
		if entry.existed {
			continue
		}
		if err := entry.installNoReplace(); err != nil {
			rollbackErr := p.Rollback()
			if rollbackErr != nil {
				return fmt.Errorf(
					"install initial systemd port sidecar: %v; rollback sidecars: %w",
					err,
					rollbackErr,
				)
			}
			return err
		}
	}
	if err := p.syncParentDirectory(); err != nil {
		rollbackErr := p.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"sync initial systemd port sidecars: %v; rollback sidecars: %w",
				err,
				rollbackErr,
			)
		}
		return errors.New("sync initial systemd port sidecars")
	}
	if err := p.verifyDestinations(); err != nil {
		rollbackErr := p.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"verify installed initial systemd port sidecars: %v; rollback sidecars: %w",
				err,
				rollbackErr,
			)
		}
		return err
	}
	if adoption != nil {
		postProof, verifyErr := p.verifyLive(
			ctx,
			adoption.currentPolicy,
			policy,
			adoption.currentTarget,
			adoption.stagedTarget,
		)
		if verifyErr != nil || postProof != liveProof {
			// A changed process may already have consumed the newly exchanged
			// sidecar. Restoring the old inode would then manufacture a second
			// unverified restart target. Preserve the complete staged sidecar
			// and its exact root-only backup for explicit recovery instead of
			// performing a blind rollback.
			preserveErr := errors.New("live systemd sidecar target changed after adoption; preserved the adopted sidecar and rollback inode for recovery")
			if verifyErr != nil {
				preserveErr = fmt.Errorf(
					"verify live systemd sidecar target after adoption: %v; preserved the adopted sidecar and rollback inode for recovery",
					verifyErr,
				)
			}
			return errors.Join(preserveErr, p.rollbackCreatedSidecars())
		}
		p.rollbackAuthority.acceptedProof = postProof
	}
	p.committed = true
	return nil
}
