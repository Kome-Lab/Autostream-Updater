package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	DefaultLocalExecutorPolicyPath       = "/etc/autostream-local-executor/policy.json"
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
	EnvironmentFiles     string
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

type initialSystemdPortSidecarPlan struct {
	ServiceID string
	Path      string
	Body      []byte
	SHA256    string
}

type initialSystemdPortSidecarSnapshot struct {
	Existed bool
	Body    []byte
}

func initialSystemdPortSidecarPlans(
	policy LocalExecutorPolicy,
	parent string,
) ([]initialSystemdPortSidecarPlan, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion {
		return nil, errors.New("initial systemd port sidecars require the mutation policy protocol")
	}
	if !cleanAbsoluteSystemdSidecarDirectory(parent) {
		return nil, errors.New("systemd port sidecar directory must be a clean absolute path")
	}
	plans := make([]initialSystemdPortSidecarPlan, 0, len(policy.Targets))
	seen := make(map[string]struct{}, len(policy.Targets))
	for _, target := range policy.Targets {
		if target.DeploymentMode != ModeSystemd {
			continue
		}
		if target.Systemd == nil {
			return nil, errors.New("systemd target is missing its fixed service definition")
		}
		adapter, err := hostAgentConfigureSystemdPortAdapterFor(
			target.ServiceType,
			target.Systemd.Unit,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"derive initial systemd port sidecar for %s: %w",
				target.ServiceID,
				err,
			)
		}
		if path.Dir(adapter.SidecarPath) != defaultSystemdPortSidecarDirectory {
			return nil, errors.New("fixed systemd port sidecar escaped its canonical directory")
		}
		sidecarPath := joinSystemdSidecarPath(
			parent,
			path.Base(adapter.SidecarPath),
		)
		if _, exists := seen[sidecarPath]; exists {
			return nil, errors.New("duplicate fixed systemd port sidecar path")
		}
		seen[sidecarPath] = struct{}{}
		body := systemdPortSidecarBytes(
			adapter.BindVariable,
			target.LocalListen.Host,
			target.LocalListen.Port,
			target.ConfigRevision,
		)
		digest := systemdPortSidecarSHA256(body)
		if target.ConfigSHA256 != digest {
			return nil, fmt.Errorf(
				"canonical systemd port sidecar digest does not match target %s",
				target.ServiceID,
			)
		}
		if bytes.Count(body, []byte{'\n'}) != 2 ||
			len(body) == 0 ||
			len(body) > systemdPortSidecarConfigureMaxBytes ||
			body[len(body)-1] != '\n' {
			return nil, errors.New("canonical systemd port sidecar is not exactly two bounded lines")
		}
		plans = append(plans, initialSystemdPortSidecarPlan{
			ServiceID: target.ServiceID,
			Path:      sidecarPath,
			Body:      append([]byte(nil), body...),
			SHA256:    digest,
		})
	}
	sort.Slice(plans, func(i, j int) bool {
		return plans[i].Path < plans[j].Path
	})
	return plans, nil
}

type preparedSystemdPortSidecar struct {
	path          string
	existed       bool
	existing      []byte
	existingInfo  os.FileInfo
	tempPath      string
	temp          *os.File
	tempInfo      os.FileInfo
	created       bool
	createdInfo   os.FileInfo
	installedBody []byte
}

type preparedSystemdPortSidecars struct {
	parent                  string
	entries                 map[string]*preparedSystemdPortSidecar
	replacementTempPath     string
	replacementTemp         *os.File
	replacementTempInfo     os.FileInfo
	replacementBody         []byte
	replacedEntry           *preparedSystemdPortSidecar
	replaced                bool
	replacementAmbiguous    bool
	finalized               bool
	exchange                func(string, string) error
	syncParent              func(string) error
	replacementPairVerifier func(*preparedSystemdPortSidecar, bool) bool
	verifyLive              hostAgentLiveSystemdSidecarVerifier
	rollbackAuthority       *hostAgentSystemdSidecarRollbackAuthority
	committed               bool
}

type hostAgentSystemdSidecarRollbackAuthority struct {
	verify        hostAgentLiveSystemdSidecarVerifier
	currentPolicy LocalExecutorPolicy
	stagedPolicy  LocalExecutorPolicy
	currentTarget LocalExecutorTarget
	stagedTarget  LocalExecutorTarget
	acceptedProof hostAgentLiveSystemdSidecarProof
}

func canonicalSystemdPortSidecarPaths(parent string) ([]string, error) {
	fixed := []struct {
		serviceType string
		unit        string
	}{
		{serviceType: "control_panel", unit: "autostream-control-panel.service"},
		{serviceType: "worker", unit: "autostream-worker.service"},
		{serviceType: "encoder_recorder", unit: "autostream-encoder-recorder.service"},
		{serviceType: "discord_bot", unit: "autostream-discord-bot.service"},
		{serviceType: "observability", unit: "autostream-observability.service"},
	}
	paths := make([]string, 0, len(fixed))
	for _, item := range fixed {
		adapter, err := hostAgentConfigureSystemdPortAdapterFor(
			item.serviceType,
			item.unit,
		)
		if err != nil {
			return nil, err
		}
		if path.Dir(adapter.SidecarPath) != defaultSystemdPortSidecarDirectory {
			return nil, errors.New("fixed systemd port sidecar escaped its canonical directory")
		}
		paths = append(
			paths,
			joinSystemdSidecarPath(parent, path.Base(adapter.SidecarPath)),
		)
	}
	sort.Strings(paths)
	return paths, nil
}

func cleanAbsoluteSystemdSidecarDirectory(value string) bool {
	if strings.HasPrefix(value, "/") {
		return path.IsAbs(value) && path.Clean(value) == value
	}
	return filepath.IsAbs(value) && filepath.Clean(value) == value
}

func joinSystemdSidecarPath(parent, name string) string {
	if strings.HasPrefix(parent, "/") {
		return path.Join(parent, name)
	}
	return filepath.Join(parent, name)
}

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

func authorizeHostAgentSystemdSidecarAdoption(
	stagedPolicy LocalExecutorPolicy,
	stagedIdentity UpdaterConfigureIdentity,
	currentIdentityBytes []byte,
	currentPolicyBytes []byte,
	plans []initialSystemdPortSidecarPlan,
	snapshots map[string]initialSystemdPortSidecarSnapshot,
	parent string,
) (*hostAgentSystemdSidecarAdoption, error) {
	if validateUpdaterConfigureIdentity(
		stagedIdentity,
		stagedIdentity.NodeID,
		"",
	) != nil ||
		stagedIdentity.ServiceType != ServiceTypeUpdateAgent ||
		stagedIdentity.TransportMode != HostTransportPullV2 ||
		stagedIdentity.API != (UpdaterConfigureAPIAssertion{}) {
		return nil, errors.New("live systemd sidecar staged identity is invalid")
	}
	currentIdentity, err := decodeManagedHostAgentIdentity(currentIdentityBytes)
	if err != nil ||
		!sameConfiguredPanelURL(currentIdentity.PanelURL, stagedIdentity.PanelURL) ||
		currentIdentity.NodeID != stagedIdentity.NodeID {
		return nil, errors.New("live systemd sidecar identity binding changed")
	}
	currentPolicy, err := decodeCanonicalLocalExecutorPolicy(currentPolicyBytes)
	if err != nil {
		return nil, errors.New("live systemd sidecar current policy is unavailable")
	}
	if currentPolicy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		currentPolicy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		currentPolicy.Mutation == nil || stagedPolicy.Mutation == nil ||
		currentPolicy.HostID != stagedPolicy.HostID ||
		currentPolicy.AgentUID != stagedPolicy.AgentUID ||
		currentPolicy.AgentGID != stagedPolicy.AgentGID ||
		currentPolicy.SocketPath != stagedPolicy.SocketPath ||
		!sameConfiguredPanelURL(
			currentPolicy.Mutation.PanelURL,
			stagedPolicy.Mutation.PanelURL,
		) ||
		!sameConfiguredPanelURL(
			stagedPolicy.Mutation.PanelURL,
			stagedIdentity.PanelURL,
		) ||
		stagedPolicy.SourcePolicyRevision <= currentPolicy.SourcePolicyRevision ||
		stagedPolicy.ProjectionRevision <= currentPolicy.ProjectionRevision ||
		stagedPolicy.PolicyRevision <= currentPolicy.PolicyRevision {
		return nil, errors.New("live systemd sidecar policy authority did not strictly advance")
	}
	mismatches := make([]initialSystemdPortSidecarPlan, 0, 1)
	for _, plan := range plans {
		snapshot, ok := snapshots[plan.Path]
		if !ok {
			return nil, errors.New("canonical systemd port sidecar was not preflighted")
		}
		if snapshot.Existed && !bytes.Equal(snapshot.Body, plan.Body) {
			mismatches = append(mismatches, plan)
		}
	}
	if len(mismatches) != 1 {
		return nil, errors.New("live systemd sidecar adoption requires exactly one existing mismatch")
	}
	plan := mismatches[0]
	stagedTarget, ok := stagedPolicy.Target(plan.ServiceID)
	if !ok || stagedTarget.DeploymentMode != ModeSystemd ||
		stagedTarget.Systemd == nil ||
		!validSystemdPortServiceType(stagedTarget.ServiceType) {
		return nil, errors.New("live systemd sidecar target is not eligible")
	}
	currentTarget, ok := currentPolicy.Target(plan.ServiceID)
	if !ok || currentTarget.DeploymentMode != ModeSystemd ||
		currentTarget.Systemd == nil ||
		currentTarget.ServiceID != stagedTarget.ServiceID ||
		currentTarget.ServiceType != stagedTarget.ServiceType ||
		currentTarget.DatabaseName != stagedTarget.DatabaseName ||
		currentTarget.EndpointRevision != stagedTarget.EndpointRevision ||
		currentTarget.ConfigRevision != stagedTarget.ConfigRevision ||
		currentTarget.LocalListen.Host != stagedTarget.LocalListen.Host ||
		currentTarget.LocalListen.Port == stagedTarget.LocalListen.Port ||
		!reflect.DeepEqual(currentTarget.Systemd, stagedTarget.Systemd) {
		return nil, errors.New("live systemd sidecar target changed beyond its loopback port")
	}
	adapter, err := systemdPortAdapterFor(
		stagedTarget.ServiceType,
		stagedTarget.Systemd.Unit,
	)
	if err != nil || filepath.Base(adapter.SidecarPath) != filepath.Base(plan.Path) {
		return nil, errors.New("live systemd sidecar target adapter is invalid")
	}
	currentPlans, err := initialSystemdPortSidecarPlans(currentPolicy, parent)
	if err != nil {
		return nil, errors.New("derive live systemd sidecar current policy")
	}
	var currentPlan *initialSystemdPortSidecarPlan
	for index := range currentPlans {
		if currentPlans[index].Path == plan.Path &&
			currentPlans[index].ServiceID == plan.ServiceID {
			currentPlan = &currentPlans[index]
			break
		}
	}
	snapshot := snapshots[plan.Path]
	if currentPlan == nil || !snapshot.Existed ||
		!bytes.Equal(snapshot.Body, currentPlan.Body) ||
		currentTarget.ConfigSHA256 != currentPlan.SHA256 ||
		stagedTarget.ConfigSHA256 != plan.SHA256 {
		return nil, errors.New("existing systemd sidecar is not canonical for the current root policy")
	}
	return &hostAgentSystemdSidecarAdoption{
		plan:          plan,
		currentPolicy: currentPolicy,
		currentTarget: currentTarget,
		stagedTarget:  stagedTarget,
	}, nil
}

func decodeManagedHostAgentIdentity(data []byte) (Config, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Config{}, errors.New("managed Host Agent identity is missing")
	}
	var identity Config
	if err := json.Unmarshal(data, &identity); err != nil ||
		identity.Validate() != nil || !identity.IsManagedBootstrap() {
		return Config{}, errors.New("managed Host Agent identity is invalid")
	}
	return identity, nil
}

func decodeCanonicalLocalExecutorPolicy(data []byte) (LocalExecutorPolicy, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return LocalExecutorPolicy{}, errors.New("Local Executor policy is missing")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy LocalExecutorPolicy
	if err := decoder.Decode(&policy); err != nil {
		return LocalExecutorPolicy{}, errors.New("decode Local Executor policy")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return LocalExecutorPolicy{}, errors.New("Local Executor policy contains trailing data")
	}
	projection, err := BuildConfigurePolicyProjection(policy)
	if err != nil || !bytes.Equal(data, projection.Policy) {
		return LocalExecutorPolicy{}, errors.New("Local Executor policy is not canonical")
	}
	return policy, nil
}

func sameConfiguredPanelURL(left, right string) bool {
	return strings.TrimRight(strings.TrimSpace(left), "/") ==
		strings.TrimRight(strings.TrimSpace(right), "/")
}

func validateInitialSystemdPortSidecarSnapshots(
	plans []initialSystemdPortSidecarPlan,
	snapshots map[string]initialSystemdPortSidecarSnapshot,
) error {
	for _, plan := range plans {
		snapshot, ok := snapshots[plan.Path]
		if !ok {
			return errors.New("canonical systemd port sidecar was not preflighted")
		}
		if snapshot.Existed && !bytes.Equal(snapshot.Body, plan.Body) {
			return fmt.Errorf(
				"existing systemd port sidecar for %s differs from the active policy target",
				plan.ServiceID,
			)
		}
	}
	return nil
}

func (e *preparedSystemdPortSidecar) prepareBody(body []byte) error {
	if e == nil || e.temp == nil || e.tempInfo == nil || e.created {
		return errors.New("initial systemd port sidecar temporary file is unavailable")
	}
	if err := e.verifyTemporaryFile(); err != nil {
		return err
	}
	if err := e.temp.Truncate(0); err != nil {
		return errors.New("truncate initial systemd port sidecar temporary file")
	}
	if _, err := e.temp.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind initial systemd port sidecar temporary file")
	}
	if _, err := e.temp.Write(body); err != nil {
		return errors.New("write initial systemd port sidecar temporary file")
	}
	if err := e.temp.Chown(0, 0); err != nil {
		return errors.New("restore initial systemd port sidecar temporary file ownership")
	}
	if err := e.temp.Chmod(0o600); err != nil {
		return errors.New("restore initial systemd port sidecar temporary file mode")
	}
	if err := e.temp.Sync(); err != nil {
		return errors.New("sync initial systemd port sidecar temporary file")
	}
	e.installedBody = append([]byte(nil), body...)
	return e.verifyTemporaryFile()
}

func (p *preparedSystemdPortSidecars) prepareReplacementBody(body []byte) error {
	if p == nil || p.replacementTemp == nil || p.replacementTempPath == "" ||
		p.replacementTempInfo == nil || p.replaced || len(body) == 0 ||
		len(body) > systemdPortSidecarConfigureMaxBytes {
		return errors.New("systemd sidecar adoption file is unavailable")
	}
	if err := p.verifyReplacementTemporaryFile(); err != nil {
		return err
	}
	if err := p.replacementTemp.Truncate(0); err != nil {
		return errors.New("truncate systemd sidecar adoption file")
	}
	if _, err := p.replacementTemp.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind systemd sidecar adoption file")
	}
	if _, err := p.replacementTemp.Write(body); err != nil {
		return errors.New("write systemd sidecar adoption file")
	}
	if err := p.replacementTemp.Chown(0, 0); err != nil {
		return errors.New("restore systemd sidecar adoption file ownership")
	}
	if err := p.replacementTemp.Chmod(0o600); err != nil {
		return errors.New("restore systemd sidecar adoption file mode")
	}
	if err := p.replacementTemp.Sync(); err != nil {
		return errors.New("sync systemd sidecar adoption file")
	}
	p.replacementBody = append([]byte(nil), body...)
	return p.verifyReplacementTemporaryFile()
}

func (p *preparedSystemdPortSidecars) exchangeReplacement(
	entry *preparedSystemdPortSidecar,
) error {
	if p == nil || entry == nil || !entry.existed || p.replaced ||
		len(p.replacementBody) == 0 || p.exchange == nil {
		return errors.New("systemd sidecar adoption is not ready")
	}
	if err := p.verifyDestinations(); err != nil {
		return err
	}
	exchangeErr := p.exchange(p.replacementTempPath, entry.path)
	if exchangeErr == nil {
		// A successful RENAME_EXCHANGE changes both pathnames atomically. Record
		// that transition before any fallible post-exchange read so Abort can
		// never unlink or forget the only exact rollback inode.
		p.replaced = true
		p.replacedEntry = entry
		if !p.replacementPairMatches(entry, true) {
			return p.preserveAmbiguousReplacement(
				entry,
				errors.New("live systemd sidecar exchange succeeded but its result could not be verified; preserved the adopted sidecar and rollback inode for recovery"),
			)
		}
	} else {
		oldPair := p.replacementPairMatches(entry, false)
		newPair := p.replacementPairMatches(entry, true)
		if oldPair {
			return fmt.Errorf("exchange live systemd sidecar: %w", exchangeErr)
		}
		if !newPair {
			return p.preserveAmbiguousReplacement(
				entry,
				errors.New("live systemd sidecar exchange result is uncertain; preserved the adopted sidecar and rollback inode for recovery"),
			)
		}
		p.replaced = true
		p.replacedEntry = entry
	}
	if err := p.syncParentDirectory(); err != nil {
		rollbackErr := p.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"sync adopted systemd sidecar directory: %v; rollback sidecar: %w",
				err,
				rollbackErr,
			)
		}
		return errors.New("sync adopted systemd sidecar directory")
	}
	if err := p.verifyDestinations(); err != nil {
		rollbackErr := p.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"verify adopted systemd sidecar: %v; rollback sidecar: %w",
				err,
				rollbackErr,
			)
		}
		return err
	}
	if exchangeErr != nil {
		rollbackErr := p.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf(
				"systemd sidecar exchange reported an error after a provable swap: %v; rollback sidecar: %w",
				exchangeErr,
				rollbackErr,
			)
		}
		return errors.New("systemd sidecar exchange reported an error after a provable swap")
	}
	return nil
}

func (p *preparedSystemdPortSidecars) preserveAmbiguousReplacement(
	entry *preparedSystemdPortSidecar,
	cause error,
) error {
	p.replaced = true
	p.replacedEntry = entry
	p.replacementAmbiguous = true
	if err := p.syncParentDirectory(); err != nil {
		return errors.Join(
			cause,
			errors.New("sync ambiguous systemd sidecar exchange for recovery"),
		)
	}
	return cause
}

func (p *preparedSystemdPortSidecars) replacementPairMatches(
	entry *preparedSystemdPortSidecar,
	swapped bool,
) bool {
	if p == nil || p.replacementPairVerifier == nil {
		return false
	}
	return p.replacementPairVerifier(entry, swapped)
}

func (p *preparedSystemdPortSidecars) replacementPairMatchesOnDisk(
	entry *preparedSystemdPortSidecar,
	swapped bool,
) bool {
	if p == nil || entry == nil || entry.existingInfo == nil ||
		p.replacementTempInfo == nil || p.replacementTempPath == "" {
		return false
	}
	destinationBody, destinationInfo, destinationExists, destinationErr :=
		readRootSystemdPortSidecarOptional(entry.path)
	temporaryBody, temporaryInfo, temporaryExists, temporaryErr :=
		readRootSystemdPortSidecarOptional(p.replacementTempPath)
	if destinationErr != nil || temporaryErr != nil ||
		!destinationExists || !temporaryExists ||
		destinationInfo.Mode()&os.ModeSymlink != 0 ||
		temporaryInfo.Mode()&os.ModeSymlink != 0 ||
		!destinationInfo.Mode().IsRegular() || !temporaryInfo.Mode().IsRegular() ||
		destinationInfo.Mode().Perm() != 0o600 || temporaryInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(destinationInfo, 0) ||
		!updaterConfigHasInstallOwner(temporaryInfo, 0) {
		return false
	}
	if swapped {
		return os.SameFile(destinationInfo, p.replacementTempInfo) &&
			os.SameFile(temporaryInfo, entry.existingInfo) &&
			bytes.Equal(destinationBody, p.replacementBody) &&
			bytes.Equal(temporaryBody, entry.existing)
	}
	return os.SameFile(destinationInfo, entry.existingInfo) &&
		os.SameFile(temporaryInfo, p.replacementTempInfo) &&
		bytes.Equal(destinationBody, entry.existing) &&
		bytes.Equal(temporaryBody, p.replacementBody)
}

func (e *preparedSystemdPortSidecar) installNoReplace() error {
	if e == nil || e.existed || e.created || len(e.installedBody) == 0 {
		return errors.New("initial systemd port sidecar is not ready for installation")
	}
	if err := e.verifyTemporaryFile(); err != nil {
		return err
	}
	if _, _, existed, err := readRootSystemdPortSidecarOptional(e.path); err != nil {
		return err
	} else if existed {
		return errors.New("systemd port sidecar destination appeared after preflight")
	}
	linkErr := os.Link(e.tempPath, e.path)
	pathInfo, pathErr := os.Lstat(e.path)
	if pathErr == nil && e.tempInfo != nil && os.SameFile(pathInfo, e.tempInfo) {
		e.created = true
		e.createdInfo = pathInfo
	} else if linkErr == nil {
		return errors.New("initial systemd port sidecar installed with an unsafe identity")
	}
	if linkErr != nil {
		if e.created {
			return errors.New("initial systemd port sidecar install result was uncertain")
		}
		return errors.New("install initial systemd port sidecar without replacing an existing file")
	}
	if !e.created ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() ||
		pathInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(pathInfo, 0) {
		return errors.New("initial systemd port sidecar installed with unsafe ownership or mode")
	}
	if err := os.Remove(e.tempPath); err != nil {
		return errors.New("initial systemd port sidecar installed but temporary link cleanup failed")
	}
	e.tempPath = ""
	return nil
}

func (p *preparedSystemdPortSidecars) Rollback() error {
	if p == nil {
		return nil
	}
	rollbackErr := p.rollbackCreatedSidecars()
	if p.replaced {
		_, replacementErr := p.rollbackReplacement()
		rollbackErr = errors.Join(rollbackErr, replacementErr)
	}
	if rollbackErr == nil {
		p.committed = false
	}
	return rollbackErr
}

func (p *preparedSystemdPortSidecars) rollbackReplacement() (bool, error) {
	if p == nil || !p.replaced {
		return false, nil
	}
	entry := p.replacedEntry
	if p.replacementAmbiguous {
		return false, errors.New("systemd sidecar exchange state is ambiguous; preserved the adopted sidecar and rollback inode for recovery")
	}
	if entry == nil || !p.replacementPairMatches(entry, true) {
		return false, errors.New("adopted systemd sidecar changed before rollback; preserved the adopted sidecar and rollback inode for recovery")
	}
	if err := p.verifyLiveReplacementRollback(); err != nil {
		return false, errors.Join(
			err,
			errors.New("preserved the adopted sidecar and rollback inode for recovery"),
		)
	}
	// Recheck the inode/body pair after the potentially slow live proof. The
	// proof alone never authorizes exchanging pathnames that changed while it
	// was collected.
	if !p.replacementPairMatches(entry, true) {
		return false, errors.New("adopted systemd sidecar changed after rollback proof; preserved the adopted sidecar and rollback inode for recovery")
	}
	exchangeErr := p.exchange(p.replacementTempPath, entry.path)
	if exchangeErr == nil {
		// RENAME_EXCHANGE succeeded, so the path roles changed even if every
		// subsequent read fails. Record the conservative state and durability
		// fence before attempting the post-exchange CAS observation.
		p.replacementAmbiguous = true
		syncErr := p.syncParentDirectory()
		if !p.replacementPairMatches(entry, false) {
			return false, errors.Join(
				errors.New("adopted systemd sidecar rollback result is unsafe; preserved both systemd sidecar pathnames for recovery"),
				syncErr,
			)
		}
		if syncErr != nil {
			return false, errors.Join(
				errors.New("adopted systemd sidecar rollback was not durably fenced; preserved both systemd sidecar pathnames for recovery"),
				syncErr,
			)
		}
		p.replacementAmbiguous = false
		p.replaced = false
		p.replacedEntry = nil
		p.rollbackAuthority = nil
		return true, nil
	}
	oldPair := p.replacementPairMatches(entry, false)
	newPair := p.replacementPairMatches(entry, true)
	if newPair {
		return false, fmt.Errorf(
			"adopted systemd sidecar rollback reported an error without changing the recovery pair: %w",
			exchangeErr,
		)
	}
	p.replacementAmbiguous = true
	syncErr := p.syncParentDirectory()
	if oldPair {
		return false, errors.Join(
			fmt.Errorf("adopted systemd sidecar rollback reported an error after exchanging the recovery pair: %w", exchangeErr),
			errors.New("preserved both systemd sidecar pathnames for recovery"),
			syncErr,
		)
	}
	return false, errors.Join(
		fmt.Errorf("adopted systemd sidecar rollback result is uncertain: %w", exchangeErr),
		errors.New("preserved both systemd sidecar pathnames for recovery"),
		syncErr,
	)
}

func (p *preparedSystemdPortSidecars) rollbackCreatedSidecars() error {
	if p == nil {
		return nil
	}
	var rollbackErr error
	removed := false
	paths := make([]string, 0, len(p.entries))
	for path := range p.entries {
		paths = append(paths, path)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))
	for _, path := range paths {
		entry := p.entries[path]
		if !entry.created {
			continue
		}
		body, info, existed, err := readRootSystemdPortSidecarOptional(entry.path)
		if err != nil ||
			!existed ||
			entry.createdInfo == nil ||
			!os.SameFile(info, entry.createdInfo) ||
			!bytes.Equal(body, entry.installedBody) {
			rollbackErr = errors.Join(
				rollbackErr,
				fmt.Errorf(
					"new systemd port sidecar %s changed before rollback",
					filepath.Base(entry.path),
				),
			)
			continue
		}
		if err := os.Remove(entry.path); err != nil {
			rollbackErr = errors.Join(
				rollbackErr,
				fmt.Errorf(
					"remove new systemd port sidecar %s during rollback",
					filepath.Base(entry.path),
				),
			)
			continue
		}
		entry.created = false
		entry.createdInfo = nil
		removed = true
	}
	if removed {
		if err := p.syncParentDirectory(); err != nil {
			rollbackErr = errors.Join(
				rollbackErr,
				errors.New("sync systemd port sidecar directory during rollback"),
			)
		}
	}
	return rollbackErr
}

func (p *preparedSystemdPortSidecars) verifyLiveReplacementRollback() error {
	if p == nil || p.rollbackAuthority == nil || p.rollbackAuthority.verify == nil {
		return errors.New("live systemd sidecar rollback proof is unavailable")
	}
	authority := p.rollbackAuthority
	ctx, cancel := context.WithTimeout(
		context.Background(),
		hostAgentSidecarRollbackProofTimeout,
	)
	defer cancel()
	proof, err := authority.verify(
		ctx,
		authority.currentPolicy,
		authority.stagedPolicy,
		authority.currentTarget,
		authority.stagedTarget,
	)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
			err = errors.Join(err, ctxErr)
		}
		return fmt.Errorf("verify live systemd sidecar target before rollback: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify live systemd sidecar target before rollback: %w", err)
	}
	if proof != authority.acceptedProof {
		return errors.New("live systemd sidecar target changed before rollback")
	}
	return nil
}

func (p *preparedSystemdPortSidecars) Finalize() error {
	if p == nil || p.finalized || !p.replaced {
		return nil
	}
	entry := p.replacedEntry
	if !p.committed || entry == nil || !p.replacementPairMatches(entry, true) {
		return errors.New("adopted systemd sidecar backup changed before cleanup")
	}
	backup, backupInfo, existed, err := readRootSystemdPortSidecarOptional(
		p.replacementTempPath,
	)
	if err != nil || !existed || !os.SameFile(backupInfo, entry.existingInfo) ||
		!bytes.Equal(backup, entry.existing) {
		return errors.New("adopted systemd sidecar backup is unsafe")
	}
	if p.replacementTemp != nil {
		if err := p.replacementTemp.Close(); err != nil {
			p.replacementTemp = nil
			return errors.New("close adopted systemd sidecar destination")
		}
		p.replacementTemp = nil
	}
	if err := os.Remove(p.replacementTempPath); err != nil {
		return errors.New("remove adopted systemd sidecar backup")
	}
	p.replacementTempPath = ""
	p.finalized = true
	if err := p.syncParentDirectory(); err != nil {
		return errors.New("sync systemd sidecar directory after backup cleanup")
	}
	return nil
}

func (p *preparedSystemdPortSidecars) Abort() {
	if p == nil {
		return
	}
	for _, entry := range p.entries {
		if entry.temp != nil {
			_ = entry.temp.Close()
			entry.temp = nil
		}
		if entry.tempPath != "" {
			_ = os.Remove(entry.tempPath)
			entry.tempPath = ""
		}
	}
	if p.replacementTemp != nil {
		_ = p.replacementTemp.Close()
		p.replacementTemp = nil
	}
	if p.replacementTempPath != "" && !p.replaced {
		if info, err := os.Lstat(p.replacementTempPath); err == nil &&
			p.replacementTempInfo != nil &&
			os.SameFile(info, p.replacementTempInfo) {
			_ = os.Remove(p.replacementTempPath)
			_ = p.syncParentDirectory()
		}
		p.replacementTempPath = ""
	}
}

func (p *preparedSystemdPortSidecars) syncParentDirectory() error {
	if p == nil || p.syncParent == nil {
		return errors.New("systemd port sidecar directory sync is unavailable")
	}
	return p.syncParent(p.parent)
}

func (p *preparedSystemdPortSidecars) verifyDestinations() error {
	if p == nil {
		return errors.New("initial systemd port sidecar update is not prepared")
	}
	if err := validateSystemdPortSidecarDirectory(p.parent); err != nil {
		return err
	}
	for _, entry := range p.entries {
		if p.replaced && entry == p.replacedEntry {
			body, info, existed, err := readRootSystemdPortSidecarOptional(entry.path)
			if err != nil || !existed ||
				!os.SameFile(info, p.replacementTempInfo) ||
				!bytes.Equal(body, p.replacementBody) {
				return errors.New("adopted systemd sidecar changed after exchange")
			}
			backup, backupInfo, backupExists, err := readRootSystemdPortSidecarOptional(
				p.replacementTempPath,
			)
			if err != nil || !backupExists ||
				!os.SameFile(backupInfo, entry.existingInfo) ||
				!bytes.Equal(backup, entry.existing) {
				return errors.New("adopted systemd sidecar backup changed after exchange")
			}
			continue
		}
		body, info, existed, err := readRootSystemdPortSidecarOptional(entry.path)
		if err != nil {
			return err
		}
		if entry.created {
			if !existed ||
				entry.createdInfo == nil ||
				!os.SameFile(info, entry.createdInfo) ||
				!bytes.Equal(body, entry.installedBody) {
				return errors.New("new systemd port sidecar changed during configuration")
			}
			continue
		}
		if !entry.existed {
			if existed {
				return errors.New("systemd port sidecar destination appeared after preflight")
			}
			if err := entry.verifyTemporaryFile(); err != nil {
				return err
			}
			continue
		}
		if !existed ||
			!os.SameFile(info, entry.existingInfo) ||
			!bytes.Equal(body, entry.existing) {
			return errors.New("existing systemd port sidecar changed after preflight")
		}
	}
	if p.replacementTempPath != "" && !p.replaced {
		if err := p.verifyReplacementTemporaryFile(); err != nil {
			return err
		}
	}
	return nil
}

func (p *preparedSystemdPortSidecars) verifyReplacementTemporaryFile() error {
	if p == nil || p.replacementTemp == nil || p.replacementTempPath == "" ||
		p.replacementTempInfo == nil || p.replaced {
		return errors.New("systemd sidecar adoption file is unavailable")
	}
	pathInfo, err := os.Lstat(p.replacementTempPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() ||
		pathInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(pathInfo, 0) {
		return errors.New("systemd sidecar adoption file changed after preflight")
	}
	openedInfo, err := p.replacementTemp.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) ||
		!os.SameFile(p.replacementTempInfo, openedInfo) {
		return errors.New("systemd sidecar adoption file changed after preflight")
	}
	return nil
}

func (e *preparedSystemdPortSidecar) verifyTemporaryFile() error {
	if e == nil || e.temp == nil || e.tempPath == "" || e.tempInfo == nil {
		return errors.New("initial systemd port sidecar temporary file is unavailable")
	}
	pathInfo, err := os.Lstat(e.tempPath)
	if err != nil ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() {
		return errors.New("initial systemd port sidecar temporary file changed after preflight")
	}
	openedInfo, err := e.temp.Stat()
	if err != nil ||
		!os.SameFile(pathInfo, openedInfo) ||
		!os.SameFile(e.tempInfo, openedInfo) ||
		openedInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(openedInfo, 0) {
		return errors.New("initial systemd port sidecar temporary file changed after preflight")
	}
	return nil
}

func validateInstalledSystemdPortSidecars(
	policy LocalExecutorPolicy,
	parent string,
) error {
	if err := validateSystemdPortSidecarDirectory(parent); err != nil {
		return err
	}
	plans, err := initialSystemdPortSidecarPlans(policy, parent)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		body, _, existed, err := readRootSystemdPortSidecarOptional(plan.Path)
		if err != nil {
			return err
		}
		if !existed || !bytes.Equal(body, plan.Body) {
			return fmt.Errorf(
				"installed systemd port sidecar for %s does not match the staged policy",
				plan.ServiceID,
			)
		}
	}
	return nil
}

func validateSystemdPortSidecarDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("systemd port sidecar directory must be a clean absolute path")
	}
	if err := validateSecureRootPath(path, true); err != nil {
		return fmt.Errorf("systemd port sidecar directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm() != 0o700 ||
		!updaterConfigHasInstallOwner(info, 0) {
		return errors.New("systemd port sidecar directory must be root:root 0700")
	}
	return nil
}

func readRootSystemdPortSidecarOptional(
	path string,
) ([]byte, os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, errors.New("stat systemd port sidecar")
	}
	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Size() <= 0 ||
		info.Size() > systemdPortSidecarConfigureMaxBytes ||
		info.Mode().Perm() != 0o600 {
		return nil, nil, false, errors.New("systemd port sidecar must be a bounded root:root 0600 regular non-symlink file")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil {
		return nil, nil, false, errors.New("open systemd port sidecar")
	}
	defer file.Close()
	if !updaterConfigHasInstallOwner(openedInfo, 0) {
		return nil, nil, false, errors.New("systemd port sidecar must be owned by root")
	}
	if err := validateRootOwnedFileAndParents(
		path,
		openedInfo,
		"systemd port sidecar",
	); err != nil {
		return nil, nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(
		file,
		systemdPortSidecarConfigureMaxBytes+1,
	))
	if err != nil ||
		len(data) == 0 ||
		len(data) > systemdPortSidecarConfigureMaxBytes {
		return nil, nil, false, errors.New("read systemd port sidecar")
	}
	return data, openedInfo, true, nil
}

type preparedLocalExecutorPolicy struct {
	path          string
	parent        string
	tempPath      string
	temp          *os.File
	tempInfo      os.FileInfo
	existing      []byte
	existingInfo  os.FileInfo
	existed       bool
	renamePath    func(string, string) error
	committed     bool
	committedInfo os.FileInfo
}

func prepareLocalExecutorPolicy(path string) (*preparedLocalExecutorPolicy, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Local Executor policy path must be a clean absolute path")
	}
	if _, err := updaterConfigInstallGID("root"); err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	if err := validateSecureRootPath(parent, true); err != nil {
		return nil, fmt.Errorf("Local Executor policy parent: %w", err)
	}
	existing, existingInfo, existed, err := readRootPolicySnapshotOptional(path)
	if err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(parent, ".policy.json.configure-*")
	if err != nil {
		return nil, errors.New("create Local Executor policy temporary file")
	}
	prepared := &preparedLocalExecutorPolicy{
		path: path, parent: parent, tempPath: temp.Name(), temp: temp,
		existing: existing, existingInfo: existingInfo, existed: existed,
		renamePath: os.Rename,
	}
	failed := true
	defer func() {
		if failed {
			prepared.Abort()
		}
	}()
	if err := temp.Chown(0, 0); err != nil {
		return nil, errors.New("set Local Executor policy temporary file ownership")
	}
	if err := temp.Chmod(0o600); err != nil {
		return nil, errors.New("set Local Executor policy temporary file mode")
	}
	if _, err := temp.Write([]byte("{}")); err != nil {
		return nil, errors.New("write Local Executor policy preflight file")
	}
	if err := temp.Sync(); err != nil {
		return nil, errors.New("sync Local Executor policy preflight file")
	}
	prepared.tempInfo, err = temp.Stat()
	if err != nil || !prepared.tempInfo.Mode().IsRegular() ||
		prepared.tempInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(prepared.tempInfo, 0) {
		return nil, errors.New("Local Executor policy temporary file ownership or mode is unsafe")
	}
	if err := prepared.verifyDestination(); err != nil {
		return nil, err
	}
	if err := syncDirectory(parent); err != nil {
		return nil, errors.New("sync Local Executor policy directory during preflight")
	}
	failed = false
	return prepared, nil
}

func (p *preparedLocalExecutorPolicy) Commit(projection ConfigurePolicyProjection) error {
	if p == nil || p.temp == nil || p.committed {
		return errors.New("Local Executor policy update is not prepared")
	}
	if err := ValidateConfigurePolicyActivation(
		projection.Policy,
		projection.SHA256,
		projection.SourcePolicyRevision,
		projection.ProjectionRevision,
		projection.PolicyRevision,
	); err != nil {
		return err
	}
	if err := p.verifyTemporaryFile(); err != nil {
		return err
	}
	if err := p.verifyDestination(); err != nil {
		return err
	}
	if err := p.temp.Truncate(0); err != nil {
		return errors.New("truncate Local Executor policy temporary file")
	}
	if _, err := p.temp.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind Local Executor policy temporary file")
	}
	if _, err := io.Copy(p.temp, bytes.NewReader(projection.Policy)); err != nil {
		return errors.New("write canonical Local Executor policy")
	}
	if err := p.temp.Chown(0, 0); err != nil {
		return errors.New("restore Local Executor policy temporary file ownership")
	}
	if err := p.temp.Chmod(0o600); err != nil {
		return errors.New("restore Local Executor policy temporary file mode")
	}
	if err := p.temp.Sync(); err != nil {
		return errors.New("sync canonical Local Executor policy")
	}
	if err := p.verifyTemporaryFile(); err != nil {
		return err
	}
	if err := p.verifyDestination(); err != nil {
		return err
	}
	if p.renamePath == nil {
		return errors.New("Local Executor policy update is not prepared")
	}
	if err := p.renamePath(p.tempPath, p.path); err != nil {
		switch inspectPreparedRenameOutcome(p.tempPath, p.path, p.tempInfo) {
		case preparedRenameNotInstalled:
			return fmt.Errorf("install canonical Local Executor policy: %w", err)
		case preparedRenameInstalled:
			return p.finishCommittedInstall(
				p.tempInfo,
				fmt.Errorf(
					"canonical Local Executor policy was installed but rename reported an error: %w",
					err,
				),
			)
		default:
			return p.finishCommittedInstall(
				nil,
				fmt.Errorf(
					"canonical Local Executor policy install result is uncertain; inspect %s and %s before retrying: %w",
					p.path,
					p.tempPath,
					err,
				),
			)
		}
	}
	return p.finishCommittedInstall(p.tempInfo, nil)
}

func (p *preparedLocalExecutorPolicy) finishCommittedInstall(
	committedInfo os.FileInfo,
	finalErr error,
) error {
	p.committed = true
	p.committedInfo = committedInfo
	closeErr := p.temp.Close()
	p.temp = nil
	if closeErr != nil {
		finalErr = errors.Join(
			finalErr,
			errors.New("Local Executor policy installed but close failed"),
		)
	}
	if err := syncDirectory(p.parent); err != nil {
		finalErr = errors.Join(
			finalErr,
			errors.New("Local Executor policy installed but directory sync failed"),
		)
	}
	return finalErr
}

func (p *preparedLocalExecutorPolicy) Rollback() error {
	if p == nil || !p.committed {
		return nil
	}
	current, currentInfo, existed, err := readRootPolicySnapshotOptional(p.path)
	if err != nil || !existed || p.committedInfo == nil ||
		!os.SameFile(currentInfo, p.committedInfo) {
		return errors.New("installed Local Executor policy changed before rollback")
	}
	if !p.existed {
		if err := os.Remove(p.path); err != nil {
			return errors.New("remove newly installed Local Executor policy during rollback")
		}
		p.committed = false
		return syncDirectory(p.parent)
	}
	_ = current
	temp, err := os.CreateTemp(p.parent, ".policy.json.rollback-*")
	if err != nil {
		return errors.New("create Local Executor policy rollback file")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chown(0, 0); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(p.existing); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, p.path); err != nil {
		return errors.New("restore previous Local Executor policy")
	}
	p.committed = false
	return syncDirectory(p.parent)
}

func (p *preparedLocalExecutorPolicy) Abort() {
	if p == nil || p.committed {
		return
	}
	if p.temp != nil {
		_ = p.temp.Close()
		p.temp = nil
	}
	if p.tempPath != "" {
		_ = os.Remove(p.tempPath)
	}
}

func (p *preparedLocalExecutorPolicy) verifyDestination() error {
	if err := validateSecureRootPath(p.parent, true); err != nil {
		return fmt.Errorf("Local Executor policy parent changed after preflight: %w", err)
	}
	current, currentInfo, existed, err := readRootPolicySnapshotOptional(p.path)
	if err != nil {
		return err
	}
	if !p.existed {
		if existed {
			return errors.New("Local Executor policy destination appeared after preflight")
		}
		return nil
	}
	if !existed || !os.SameFile(currentInfo, p.existingInfo) ||
		!bytes.Equal(current, p.existing) {
		return errors.New("Local Executor policy changed after preflight")
	}
	return nil
}

func (p *preparedLocalExecutorPolicy) verifyTemporaryFile() error {
	pathInfo, err := os.Lstat(p.tempPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!pathInfo.Mode().IsRegular() {
		return errors.New("Local Executor policy temporary file changed after preflight")
	}
	openedInfo, err := p.temp.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) ||
		!os.SameFile(p.tempInfo, openedInfo) ||
		openedInfo.Mode().Perm() != 0o600 ||
		!updaterConfigHasInstallOwner(openedInfo, 0) {
		return errors.New("Local Executor policy temporary file changed after preflight")
	}
	return nil
}

func readRootPolicySnapshot(path string) ([]byte, error) {
	data, _, existed, err := readRootPolicySnapshotOptional(path)
	if err != nil {
		return nil, err
	}
	if !existed {
		return nil, errors.New("installed Local Executor policy is missing")
	}
	return data, nil
}

func readRootPolicySnapshotOptional(path string) ([]byte, os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("stat Local Executor policy: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() <= 0 || info.Size() > localExecutorPolicyMaxBytes ||
		info.Mode().Perm() != 0o600 {
		return nil, nil, false, errors.New("Local Executor policy must be a bounded root:root 0600 regular non-symlink file")
	}
	file, openedInfo, err := openVerifiedConfig(path, info)
	if err != nil {
		return nil, nil, false, err
	}
	defer file.Close()
	if !updaterConfigHasInstallOwner(openedInfo, 0) {
		return nil, nil, false, errors.New("Local Executor policy must be owned by root")
	}
	if err := validateRootOwnedFileAndParents(path, openedInfo, "Local Executor policy"); err != nil {
		return nil, nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(file, localExecutorPolicyMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > localExecutorPolicyMaxBytes {
		return nil, nil, false, errors.New("read Local Executor policy")
	}
	return data, openedInfo, true, nil
}
