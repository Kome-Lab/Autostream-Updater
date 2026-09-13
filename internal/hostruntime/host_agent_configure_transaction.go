package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	DefaultLocalExecutorPolicyPath       = "/etc/autostream/updater/executor-policy.json"
	defaultSystemdPortSidecarDirectory   = "/opt/autostream/local-executor/ports"
	systemdPortSidecarConfigureMaxBytes  = 1 << 10
	hostAgentSidecarRollbackProofTimeout = 15 * time.Second
)

// HostAgentConfigurationOptions contains the single narrow recovery authority
// that may be granted by an operator. No caller-controlled service, path,
// port, revision, or digest is accepted; those values remain bound to the
// current and staged root policies.
type HostAgentConfigurationOptions struct {
	AdoptLiveSystemdSidecar bool
}

type hostAgentConfigurationInstalledError struct {
	cause error
}

func (e hostAgentConfigurationInstalledError) Error() string {
	return e.cause.Error()
}

func (e hostAgentConfigurationInstalledError) Unwrap() error {
	return e.cause
}

// HostAgentConfigurationInstalled reports an error that happened only after
// the sidecar, policy, and identity tuple was installed. Callers must preserve
// that tuple and classify the failure as post-install rather than retrying or
// rolling it back as an uncommitted transaction.
func HostAgentConfigurationInstalled(err error) bool {
	var installed hostAgentConfigurationInstalledError
	return errors.As(err, &installed)
}

type hostAgentLiveSystemdSidecarProof struct {
	Observation          LocalProcessObservation
	MainPIDStartTime     uint64
	ListenerPIDStartTime uint64
	SystemdUnitID        string
	LoadCredential       string
}

type hostAgentLiveSystemdSidecarVerifier func(
	context.Context,
	LocalExecutorPolicy,
	LocalExecutorPolicy,
	LocalExecutorTarget,
	LocalExecutorTarget,
) (hostAgentLiveSystemdSidecarProof, error)

// PreparedHostAgentConfiguration preflights both root-owned destinations
// before a one-time Configure Token is read. Commit initializes only missing
// canonical systemd sidecars, then installs the exact canonical policy and the
// inactive staged identity. If the identity rename has definitely not
// happened, the policy and newly created sidecars are rolled back.
type PreparedHostAgentConfiguration struct {
	identity             *PreparedUpdaterConfig
	policy               *preparedLocalExecutorPolicy
	sidecars             *preparedSystemdPortSidecars
	options              HostAgentConfigurationOptions
	verifyIdentityLayout func() error
}

func PrepareHostAgentConfigurationWithOptions(
	identityPath, policyPath, installGroup string,
	options HostAgentConfigurationOptions,
) (*PreparedHostAgentConfiguration, error) {
	if err := validateHostAgentIdentityWriteLayout(identityPath, os.Lstat); err != nil {
		return nil, err
	}
	identity, err := PrepareManagedIdentityConfig(identityPath, installGroup)
	if err != nil {
		return nil, err
	}
	policy, err := prepareLocalExecutorPolicy(policyPath)
	if err != nil {
		identity.Abort()
		return nil, err
	}
	sidecars, err := prepareSystemdPortSidecarsWithOptions(
		defaultSystemdPortSidecarDirectory,
		options,
	)
	if err != nil {
		policy.Abort()
		identity.Abort()
		return nil, err
	}
	return &PreparedHostAgentConfiguration{
		identity: identity,
		policy:   policy,
		sidecars: sidecars,
		options:  options,
		verifyIdentityLayout: func() error {
			return validateHostAgentIdentityWriteLayout(identityPath, os.Lstat)
		},
	}, nil
}

func (p *PreparedHostAgentConfiguration) Commit(
	identity UpdaterConfigureIdentity,
	projection ConfigurePolicyProjection,
) error {
	return p.CommitContext(context.Background(), identity, projection)
}

func (p *PreparedHostAgentConfiguration) CommitContext(
	ctx context.Context,
	identity UpdaterConfigureIdentity,
	projection ConfigurePolicyProjection,
) error {
	if p == nil || p.identity == nil || p.policy == nil || p.sidecars == nil ||
		p.verifyIdentityLayout == nil {
		return errors.New("Host Agent configuration transaction is not prepared")
	}
	if err := p.verifyIdentityLayout(); err != nil {
		return fmt.Errorf("validate Host Agent identity layout before configuration: %w", err)
	}
	canonicalPolicy, err := configurePolicyProjectionPolicy(projection)
	if err != nil {
		return err
	}
	if err := p.sidecars.CommitContext(
		ctx,
		canonicalPolicy,
		identity,
		p.identity.existing,
		p.policy.existing,
		p.options,
	); err != nil {
		return err
	}
	if err := p.policy.Commit(projection); err != nil {
		policyRollbackErr := p.policy.Rollback()
		var sidecarRollbackErr error
		if !p.policy.committed {
			sidecarRollbackErr = p.sidecars.Rollback()
		}
		if policyRollbackErr != nil || sidecarRollbackErr != nil {
			return fmt.Errorf(
				"install Local Executor policy: %v; rollback configuration: %w",
				err,
				errors.Join(policyRollbackErr, sidecarRollbackErr),
			)
		}
		return err
	}
	if err := p.verifyIdentityLayout(); err != nil {
		layoutErr := fmt.Errorf(
			"Host Agent identity layout changed before identity installation: %w",
			err,
		)
		policyRollbackErr := p.policy.Rollback()
		var sidecarRollbackErr error
		if !p.policy.committed {
			sidecarRollbackErr = p.sidecars.Rollback()
		}
		if policyRollbackErr != nil || sidecarRollbackErr != nil {
			return fmt.Errorf(
				"%v; rollback configuration: %w",
				layoutErr,
				errors.Join(policyRollbackErr, sidecarRollbackErr),
			)
		}
		return layoutErr
	}
	if err := p.identity.Commit(identity); err != nil {
		if !p.identity.committed {
			policyRollbackErr := p.policy.Rollback()
			var sidecarRollbackErr error
			if !p.policy.committed {
				sidecarRollbackErr = p.sidecars.Rollback()
			}
			if policyRollbackErr != nil || sidecarRollbackErr != nil {
				return fmt.Errorf(
					"install Host Agent identity: %v; rollback configuration: %w",
					err,
					errors.Join(policyRollbackErr, sidecarRollbackErr),
				)
			}
		}
		if p.identity.committed {
			return hostAgentConfigurationInstalledError{cause: fmt.Errorf(
				"Host Agent identity, policy, and systemd sidecars were installed but identity commit reported an error: %w",
				err,
			)}
		}
		return err
	}
	if err := p.sidecars.Finalize(); err != nil {
		return hostAgentConfigurationInstalledError{cause: fmt.Errorf(
			"Host Agent identity and policy were installed but adopted systemd sidecar cleanup failed: %w",
			err,
		)}
	}
	return nil
}

func (p *PreparedHostAgentConfiguration) Abort() {
	if p == nil {
		return
	}
	if p.identity != nil {
		p.identity.Abort()
	}
	if p.policy != nil {
		p.policy.Abort()
	}
	if p.sidecars != nil {
		p.sidecars.Abort()
	}
}

func ValidateInstalledHostAgentConfiguration(
	identityPath, policyPath string,
	staged UpdaterStagedConfiguration,
) error {
	if err := validateHostAgentIdentityWriteLayout(identityPath, os.Lstat); err != nil {
		return fmt.Errorf("validate installed Host Agent identity layout: %w", err)
	}
	if err := ValidateInstalledUpdaterIdentity(identityPath, staged.Config); err != nil {
		return err
	}
	if staged.LocalExecutorPolicy == nil {
		return errors.New("staged Local Executor policy is missing")
	}
	payload, err := readRootPolicySnapshot(policyPath)
	if err != nil {
		return err
	}
	projection := staged.LocalExecutorPolicy
	if err := ValidateConfigurePolicyActivation(
		payload,
		projection.SHA256,
		projection.SourcePolicyRevision,
		projection.ProjectionRevision,
		projection.PolicyRevision,
	); err != nil {
		return fmt.Errorf("validate installed Local Executor policy: %w", err)
	}
	if !bytes.Equal(payload, projection.Policy) {
		return errors.New("installed Local Executor policy bytes do not match the staged projection")
	}
	policy, err := configurePolicyProjectionPolicy(*projection)
	if err != nil {
		return err
	}
	if err := validateInstalledSystemdPortSidecars(
		policy,
		defaultSystemdPortSidecarDirectory,
	); err != nil {
		return err
	}
	return nil
}

func configurePolicyProjectionPolicy(
	projection ConfigurePolicyProjection,
) (LocalExecutorPolicy, error) {
	if err := ValidateConfigurePolicyActivation(
		projection.Policy,
		projection.SHA256,
		projection.SourcePolicyRevision,
		projection.ProjectionRevision,
		projection.PolicyRevision,
	); err != nil {
		return LocalExecutorPolicy{}, err
	}
	var policy LocalExecutorPolicy
	if err := json.Unmarshal(projection.Policy, &policy); err != nil {
		return LocalExecutorPolicy{}, errors.New("decode canonical Local Executor policy")
	}
	return policy, nil
}
