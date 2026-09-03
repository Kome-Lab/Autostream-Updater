package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
)

const (
	HostPullAgentStateDir = "/var/lib/autostream-host-agent"

	TargetAvailabilityUnknown     = "unknown"
	TargetAvailabilityAvailable   = "available"
	TargetAvailabilityUnavailable = "unavailable"
)

type HostTargetObservation struct {
	ServiceID              string
	Availability           string
	AvailabilityCode       string
	ReportedPort           int
	ReportedServiceType    string
	ReportedDeploymentMode string
	PolicyRevision         int64
	PolicySHA256           string
	ConfigRevision         int64
	ConfigSHA256           string
	Docker                 *HostDockerPortObservation
}

type HostDockerPortObservation struct {
	CapabilityVersion   string
	AdvertisedPort      int
	PublishedPort       int
	ContainerPort       int
	HealthPort          int
	ComposePolicySHA256 string
	ComposeRevision     int64
	VersionEnvSHA256    string
	ContainerID         string
	ImageID             string
	RepositoryDigest    string
}

type HostTargetObserver func(context.Context, HostAgentPolicy) ([]HostTargetObservation, error)

type HostPullAgentOptions struct {
	StateDir                  string
	HTTPClient                *http.Client
	ControlPlane              HostPullControlPlane
	PollInterval              time.Duration
	HeartbeatInterval         time.Duration
	ObserveTargets            HostTargetObserver
	Executor                  LocalExecutorMutationClient
	PortExecutor              LocalExecutorPortMutationClient
	RuntimeCredentialExecutor LocalExecutorRuntimeCredentialClient
	RuntimeTokenRotationPanel HostRuntimeTokenRotationControlPlane
	RuntimeTokenClaimState    RuntimeTokenClaimStateStore
	LoadRuntimeIdentity       func(string, bool) (Config, error)
	NewRuntimeTokenClaimID    func() (string, error)
	AgentVersion              string
	Downloader                ReleaseArtifactDownloader
	NewSessionID              func() (string, error)
	OpenJournal               func(string) (*Journal, error)
	SelfUpdateExecutor        HostSelfUpdateExecutor
	SelfUpdateGrantIssuer     HostSelfUpdateGrantIssuer
	LifecycleBlockers         func() HostLifecycleBlockers
	RecoveryOnly              bool
	Logf                      func(string, ...any)
}

// HostPullAgent is the portless pull_v2 control loop. Epoch zero is an
// observation/readiness bridge. After the server atomically assigns a positive
// ownership epoch and returns an active policy, the same outbound loop can
// claim, report and execute software updates through the root local executor.
type HostPullAgent struct {
	Bootstrap                  Config
	StateDir                   string
	ControlPlane               HostPullControlPlane
	Journal                    *Journal
	PollInterval               time.Duration
	HeartbeatInterval          time.Duration
	ObserveTargets             HostTargetObserver
	Executor                   LocalExecutorMutationClient
	PortExecutor               LocalExecutorPortMutationClient
	RuntimeCredentialExecutor  LocalExecutorRuntimeCredentialClient
	RuntimeTokenRotationPanel  HostRuntimeTokenRotationControlPlane
	RuntimeTokenClaimState     RuntimeTokenClaimStateStore
	LoadRuntimeIdentity        func(string, bool) (Config, error)
	NewRuntimeTokenClaimID     func() (string, error)
	AgentVersion               string
	Downloader                 ReleaseArtifactDownloader
	NewSessionID               func() (string, error)
	OpenJournal                func(string) (*Journal, error)
	SelfUpdate                 *HostSelfUpdateController
	SelfUpdateGrantIssuer      HostSelfUpdateGrantIssuer
	LifecycleBlockers          func() HostLifecycleBlockers
	RecoveryOnly               bool
	Logf                       func(string, ...any)
	executionRunning           atomic.Bool
	rotationRunning            atomic.Bool
	selfUpdateStatus           atomic.Pointer[HostSelfUpdateRuntimeStatus]
	selfUpdateProof            atomic.Pointer[HostSelfUpdateAgentProof]
	selfUpdateChecked          atomic.Int64
	runtimeCredentialStatus    atomic.Pointer[RuntimeCredentialStatus]
	runtimeCredentialHeartbeat atomic.Pointer[RuntimeCredentialStatus]
	identityMu                 sync.RWMutex
	currentBootstrap           Config
}

func NewHostPullAgent(bootstrap Config, options HostPullAgentOptions) (*HostPullAgent, error) {
	if !bootstrap.IsManagedBootstrap() {
		return nil, errors.New("host pull agent requires an identity-only updater bootstrap")
	}
	if err := bootstrap.Validate(); err != nil {
		return nil, err
	}
	stateDir := strings.TrimSpace(options.StateDir)
	if stateDir == "" {
		stateDir = HostPullAgentStateDir
	}
	if !deploymentAbsolutePath(stateDir) || filepath.Clean(stateDir) == string(filepath.Separator) {
		return nil, errors.New("host pull agent state_dir must be a non-root absolute path")
	}
	controlPlane := options.ControlPlane
	pollInterval := options.PollInterval
	if pollInterval <= 0 {
		pollInterval = 15 * time.Second
	}
	heartbeatInterval := options.HeartbeatInterval
	if heartbeatInterval <= 0 {
		heartbeatInterval = 30 * time.Second
	}
	openJournal := options.OpenJournal
	if openJournal == nil {
		openJournal = OpenJournal
	}
	logf := options.Logf
	if logf == nil {
		logf = log.Printf
	}
	observeTargets := options.ObserveTargets
	if observeTargets == nil {
		observeTargets = NewLocalExecutorTargetObserver(LocalExecutorClient{SocketPath: LocalExecutorSocketPath})
	}
	executor := options.Executor
	if executor == nil {
		executor = LocalExecutorClient{SocketPath: LocalExecutorSocketPath}
	}
	portExecutor := options.PortExecutor
	if portExecutor == nil {
		portExecutor = LocalExecutorClient{SocketPath: LocalExecutorSocketPath}
	}
	runtimeCredentialExecutor := options.RuntimeCredentialExecutor
	if runtimeCredentialExecutor == nil {
		runtimeCredentialExecutor = LocalExecutorClient{
			SocketPath: LocalExecutorSocketPath,
		}
	}
	runtimeTokenRotationPanel := options.RuntimeTokenRotationPanel
	if runtimeTokenRotationPanel == nil {
		runtimeTokenRotationPanel = panelRuntimeTokenRotationControlPlane{
			HTTPClient: options.HTTPClient,
		}
	}
	runtimeTokenClaimState := options.RuntimeTokenClaimState
	if runtimeTokenClaimState == nil {
		runtimeTokenClaimState = FileRuntimeTokenClaimStateStore{
			StateDir: stateDir,
		}
	}
	loadRuntimeIdentity := options.LoadRuntimeIdentity
	if loadRuntimeIdentity == nil {
		loadRuntimeIdentity = LoadHostAgentIdentity
	}
	claimIDGenerator := options.NewRuntimeTokenClaimID
	if claimIDGenerator == nil {
		claimIDGenerator = newRuntimeTokenClaimID
	}
	agentVersion := strings.TrimSpace(options.AgentVersion)
	if agentVersion == "" {
		agentVersion = controlversion.Current()
	} else if !versionPattern.MatchString(agentVersion) {
		return nil, errors.New("host pull agent version is invalid")
	}
	downloader := options.Downloader
	if downloader == nil {
		downloader = ReleaseDownloader{TrustedPublicOnly: true}
	}
	newSessionID := options.NewSessionID
	if newSessionID == nil {
		newSessionID = newHostPullSessionID
	}
	selfUpdateExecutor := options.SelfUpdateExecutor
	if selfUpdateExecutor == nil {
		selfUpdateExecutor = LocalExecutorClient{SocketPath: LocalExecutorSocketPath}
	}
	selfUpdate, err := NewHostSelfUpdateController(
		selfUpdateExecutor,
		HostSelfUpdateControllerOptions{},
	)
	if err != nil {
		return nil, err
	}
	lifecycleBlockers := options.LifecycleBlockers
	if lifecycleBlockers == nil {
		lifecycleBlockers = func() HostLifecycleBlockers {
			return HostLifecycleBlockers{}
		}
	}
	agent := &HostPullAgent{
		Bootstrap:                 bootstrap,
		currentBootstrap:          bootstrap,
		StateDir:                  stateDir,
		ControlPlane:              controlPlane,
		PollInterval:              pollInterval,
		HeartbeatInterval:         heartbeatInterval,
		ObserveTargets:            observeTargets,
		Executor:                  executor,
		PortExecutor:              portExecutor,
		RuntimeCredentialExecutor: runtimeCredentialExecutor,
		RuntimeTokenRotationPanel: runtimeTokenRotationPanel,
		RuntimeTokenClaimState:    runtimeTokenClaimState,
		LoadRuntimeIdentity:       loadRuntimeIdentity,
		NewRuntimeTokenClaimID:    claimIDGenerator,
		AgentVersion:              agentVersion,
		Downloader:                downloader,
		NewSessionID:              newSessionID,
		OpenJournal:               openJournal,
		SelfUpdate:                selfUpdate,
		SelfUpdateGrantIssuer:     options.SelfUpdateGrantIssuer,
		LifecycleBlockers:         lifecycleBlockers,
		RecoveryOnly:              options.RecoveryOnly,
		Logf:                      logf,
	}
	if agent.ControlPlane == nil {
		agent.ControlPlane = NewV2PanelClient(PanelClient{
			BaseURL: bootstrap.PanelURL,
			Token:   bootstrap.RuntimeToken,
			HTTP:    options.HTTPClient,
			TokenProvider: func() string {
				return agent.currentIdentity().RuntimeToken
			},
			VersionProvider: func() string {
				return agent.currentAgentVersion()
			},
		})
	}
	if agent.SelfUpdateGrantIssuer == nil {
		agent.SelfUpdateGrantIssuer = PanelClient{
			BaseURL: bootstrap.PanelURL,
			Token:   bootstrap.RuntimeToken,
			HTTP:    options.HTTPClient,
			TokenProvider: func() string {
				return agent.currentIdentity().RuntimeToken
			},
		}
	}
	if agent.RecoveryOnly {
		execution, ok := agent.ControlPlane.(HostPullExecutionControlPlane)
		if !ok {
			return nil, errors.New("recovery-only host pull agent requires an execution control plane")
		}
		agent.ControlPlane = recoveryOnlyHostPullControlPlane{
			HostPullControlPlane: agent.ControlPlane,
			execution:            execution,
		}
	}
	return agent, nil
}

// recoveryOnlyHostPullControlPlane prevents the operator recovery command from
// ever drifting into a normal claim. The underlying Panel client validates a
// structured terminal proof before returning clearActive; executeOnce then
// matches that proof to the durable active job before clearing the cursor.
type recoveryOnlyHostPullControlPlane struct {
	HostPullControlPlane
	execution HostPullExecutionControlPlane
}

func (c recoveryOnlyHostPullControlPlane) ClaimHost(
	ctx context.Context,
	request HostPullClaimRequest,
) (*UpdateJob, bool, error) {
	if strings.TrimSpace(request.ActiveJobID) == "" {
		return nil, false, errors.New("recovery-only claim requires an active job cursor")
	}
	job, clearActive, err := c.execution.ClaimHost(ctx, request)
	if err != nil {
		return nil, false, err
	}
	if clearActive && (job == nil || job.ID != strings.TrimSpace(request.ActiveJobID) ||
		(!isTerminalUpdateStatus(job.Status) &&
			!(job.RecoveryClear && job.ProtocolVersion == 2 &&
				isV2RecoveryClearStatus(job.Status)))) {
		return nil, false, errors.New("recovery-only claim received an unproven active cursor clear")
	}
	return job, clearActive, nil
}

func (c recoveryOnlyHostPullControlPlane) Report(
	ctx context.Context,
	jobID string,
	report JobReport,
) error {
	return c.execution.Report(ctx, jobID, report)
}

func (c recoveryOnlyHostPullControlPlane) IssueMutationGrant(
	ctx context.Context,
	jobID string,
	request MutationGrantRequest,
) (MutationGrant, error) {
	return c.execution.IssueMutationGrant(ctx, jobID, request)
}

func (a *HostPullAgent) Run(ctx context.Context) error {
	if a == nil || !a.currentIdentity().IsManagedBootstrap() || a.ControlPlane == nil || a.OpenJournal == nil {
		return errors.New("host pull agent dependencies are incomplete")
	}
	journal, err := a.OpenJournal(a.StateDir)
	if err != nil {
		return fmt.Errorf("open host pull agent journal: %w", err)
	}
	if journal == nil {
		return errors.New("open host pull agent journal returned nil")
	}
	if err := garbageCollectJobDirectories(a.StateDir, journal); err != nil {
		return fmt.Errorf("clean stale update job state: %w", err)
	}
	a.Journal = journal
	if a.RecoveryOnly {
		return a.runRecoveryOnly(ctx)
	}
	if !a.hasActiveRecovery() {
		if err := a.recoverRuntimeTokenRotation(ctx); err != nil &&
			ctx.Err() == nil {
			a.Logf("host runtime token rotation recovery failed: %v", err)
		}
	}

	var binding HostAgentBinding
	var policy *HostAgentPolicy
	var observations []HostTargetObservation
	var observationFailed bool

	register := func() bool {
		if !a.hasActiveRecovery() {
			if recoveryErr := a.recoverRuntimeTokenRotation(ctx); recoveryErr != nil {
				if ctx.Err() == nil {
					a.Logf(
						"host runtime token rotation recovery failed: %v",
						recoveryErr,
					)
				}
				// Registration is read-only and remains useful while the local
				// executor is unavailable. Reconciliation still fails closed before
				// any runtime-token mutation is attempted.
			}
		}
		capabilities := a.capabilities(binding, policy, observations, observationFailed)
		registered, registerErr := a.ControlPlane.RegisterHostAgent(ctx, a.currentIdentity(), capabilities)
		if registerErr != nil {
			if ctx.Err() == nil {
				a.Logf("host pull agent register failed: %v", registerErr)
			}
			return false
		}
		if binding.ExecutionHostID != "" &&
			(binding.ExecutionHostID != registered.ExecutionHostID || binding.OwnershipEpoch != registered.OwnershipEpoch) {
			policy = nil
			observations = nil
			observationFailed = false
		}
		binding = registered
		return true
	}
	refreshPolicy := func() bool {
		if binding.ExecutionHostID == "" {
			return true
		}
		currentRevision := int64(0)
		if policy != nil {
			currentRevision = policy.Revision
		}
		next, changed, fetchErr := a.ControlPlane.FetchHostAgentPolicy(ctx, a.Bootstrap.NodeID, currentRevision)
		if fetchErr != nil {
			if ctx.Err() == nil {
				a.Logf("host pull agent policy refresh failed: %v", fetchErr)
			}
			return false
		}
		if !changed || next == nil {
			if policy != nil && !a.hasActiveRecovery() {
				if rotationErr := a.reconcileRuntimeTokenRotation(ctx, policy); rotationErr != nil {
					if ctx.Err() == nil {
						a.Logf(
							"host runtime token rotation reconcile failed: %v",
							rotationErr,
						)
					}
					return false
				}
			}
			return true
		}
		if next.ExecutionHostID != binding.ExecutionHostID ||
			next.OwnershipEpoch != binding.OwnershipEpoch ||
			next.TransportMode != binding.TransportMode {
			a.Logf("host pull agent policy binding mismatch")
			return false
		}
		policy = next
		observations, observationFailed = a.observe(ctx, *policy)
		if a.hasActiveRecovery() {
			return true
		}
		if rotationErr := a.reconcileRuntimeTokenRotation(ctx, policy); rotationErr != nil {
			if ctx.Err() == nil {
				a.Logf(
					"host runtime token rotation reconcile failed: %v",
					rotationErr,
				)
			}
			return false
		}
		return true
	}
	heartbeat := func() bool {
		if policy != nil {
			observations, observationFailed = a.observe(ctx, *policy)
		}
		capabilities := a.capabilities(binding, policy, observations, observationFailed)
		if heartbeatErr := a.ControlPlane.HeartbeatHostAgent(
			ctx, a.currentIdentity(), "online", capabilities,
		); heartbeatErr != nil {
			if ctx.Err() == nil {
				a.Logf("host pull agent heartbeat failed: %v", heartbeatErr)
			}
			return false
		}
		a.recordRuntimeTokenRotationHeartbeat()
		a.recordSelfUpdateHeartbeat(policy)
		return ctx.Err() == nil
	}

	registerRetry := newHostAgentRetryState(a.HeartbeatInterval, a.Bootstrap.NodeID, "register")
	policyRetry := newHostAgentRetryState(a.PollInterval, a.Bootstrap.NodeID, "policy")
	heartbeatRetry := newHostAgentRetryState(a.HeartbeatInterval, a.Bootstrap.NodeID, "heartbeat")

	now := time.Now()
	registerRetry.record(now, register())
	policyRetry.record(now, refreshPolicy())
	heartbeatRetry.record(now, heartbeat())
	if a.hasActiveRecovery() {
		a.startExecutionCycle(ctx, binding, policy, observations, observationFailed)
	} else {
		a.startSelfUpdate(ctx, binding, policy)
		a.startExecutionCycle(ctx, binding, policy, observations, observationFailed)
	}

	pollTicker := time.NewTicker(hostAgentJitteredInterval(a.PollInterval, a.Bootstrap.NodeID, "policy-cadence"))
	defer pollTicker.Stop()
	heartbeatTicker := time.NewTicker(hostAgentJitteredInterval(a.HeartbeatInterval, a.Bootstrap.NodeID, "heartbeat-cadence"))
	defer heartbeatTicker.Stop()
	for {
		if err := a.Journal.Err(); err != nil {
			return fmt.Errorf("host pull agent journal requires restart: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pollTicker.C:
			now = time.Now()
			if policyRetry.ready(now) {
				policyRetry.record(now, refreshPolicy())
			}
			if a.hasActiveRecovery() {
				a.startExecutionCycle(ctx, binding, policy, observations, observationFailed)
			} else {
				a.startSelfUpdate(ctx, binding, policy)
				a.startExecutionCycle(ctx, binding, policy, observations, observationFailed)
			}
		case <-heartbeatTicker.C:
			now = time.Now()
			if registerRetry.ready(now) {
				registerRetry.record(now, register())
			}
			if heartbeatRetry.ready(now) {
				heartbeatRetry.record(now, heartbeat())
			}
			if !a.hasActiveRecovery() {
				a.startSelfUpdate(ctx, binding, policy)
			}
		}
	}
}

func (a *HostPullAgent) runRecoveryOnly(ctx context.Context) error {
	if a == nil || a.Journal == nil {
		return errors.New("host update recovery journal is unavailable")
	}
	if err := a.Journal.Err(); err != nil {
		return fmt.Errorf("host update recovery journal requires restart: %w", err)
	}
	if !a.hasActiveRecovery() {
		return nil
	}
	var lastErr error
	for {
		if err := a.Journal.Err(); err != nil {
			return fmt.Errorf("host update recovery journal requires restart: %w", err)
		}
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return fmt.Errorf("host update recovery did not converge: %v: %w", lastErr, err)
			}
			return err
		}
		if !a.hasActiveRecovery() {
			return nil
		}

		binding, err := a.ControlPlane.RegisterHostAgent(
			ctx,
			a.currentIdentity(),
			a.capabilities(HostAgentBinding{}, nil, nil, false),
		)
		if err == nil {
			var policy *HostAgentPolicy
			policy, _, err = a.ControlPlane.FetchHostAgentPolicy(
				ctx, a.Bootstrap.NodeID, 0,
			)
			if err == nil && policy == nil {
				err = errors.New("recovery-only policy is unavailable")
			}
			if err == nil && !a.recoveryExecutionReady(binding, policy) {
				err = errors.New("recovery-only ownership policy is not ready")
			}
			var observations []HostTargetObservation
			var observationFailed bool
			if err == nil {
				observations, observationFailed = a.observe(ctx, *policy)
				err = a.ControlPlane.HeartbeatHostAgent(
					ctx,
					a.currentIdentity(),
					"online",
					a.capabilities(binding, policy, observations, observationFailed),
				)
				if err != nil {
					err = fmt.Errorf("refresh recovery-only heartbeat: %w", err)
				}
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil && a.hasActiveRecovery() {
				err = a.executeOnce(ctx, binding, *policy)
			}
		}
		if err != nil {
			lastErr = err
			if journalErr := a.Journal.Err(); journalErr != nil {
				return fmt.Errorf(
					"host update recovery journal commit failed: %w",
					errors.Join(err, journalErr),
				)
			}
			// executeOnce may have durably cleared ActiveJob and then failed to
			// remove/fsync its clear fence. Recovery-only installation must not
			// reinterpret that error as convergence merely because Active() is
			// now nil in this process.
			if !a.hasActiveRecovery() {
				return fmt.Errorf("host update recovery failed while clearing active state: %w", err)
			}
			if ctx.Err() == nil {
				a.Logf("host pull agent recovery-only attempt failed: %v", err)
			}
		}
		if !a.hasActiveRecovery() {
			return nil
		}

		timer := time.NewTimer(a.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (a *HostPullAgent) hasActiveRecovery() bool {
	return a != nil && a.Journal != nil && a.Journal.Active() != nil
}

func (a *HostPullAgent) recoveryExecutionReady(
	binding HostAgentBinding,
	policy *HostAgentPolicy,
) bool {
	if !a.hasActiveRecovery() || policy == nil ||
		binding.ServiceID != a.Bootstrap.NodeID ||
		binding.ServiceType != ServiceTypeUpdateAgent ||
		binding.TransportMode != HostTransportPullV2 ||
		binding.ExecutionHostID == "" ||
		binding.OwnershipEpoch < 1 ||
		policy.ServiceID != a.Bootstrap.NodeID ||
		policy.TransportMode != HostTransportPullV2 ||
		policy.ExecutionHostID != binding.ExecutionHostID ||
		policy.OwnershipEpoch != binding.OwnershipEpoch ||
		policy.Revision < 1 ||
		policy.SourcePolicyRevision < 1 ||
		policy.LocalExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(policy.LocalExecutorPolicySHA256) {
		return false
	}
	if _, ok := a.ControlPlane.(HostPullExecutionControlPlane); !ok {
		return false
	}
	active := a.Journal.Active()
	if active == nil {
		return false
	}
	switch active.EffectiveOperation() {
	case updateJobOperationSoftwareUpdate:
		return a.Executor != nil
	case updateJobOperationPortReconfigure:
		return a.PortExecutor != nil
	default:
		return false
	}
}

func (a *HostPullAgent) startExecutionCycle(
	ctx context.Context,
	binding HostAgentBinding,
	policy *HostAgentPolicy,
	observations []HostTargetObservation,
	observationFailed bool,
) {
	if !a.hasActiveRecovery() {
		a.startExecution(ctx, binding, policy, observations, observationFailed)
		return
	}
	if !a.recoveryExecutionReady(binding, policy) ||
		!a.executionRunning.CompareAndSwap(false, true) {
		return
	}
	policySnapshot := *policy
	policySnapshot.Targets = append(
		[]HostAgentPolicyTarget(nil), policy.Targets...,
	)
	go func() {
		defer a.executionRunning.Store(false)
		if !a.hasActiveRecovery() {
			return
		}
		if err := a.executeOnce(ctx, binding, policySnapshot); err != nil &&
			ctx.Err() == nil {
			a.Logf("host pull agent recovery poll failed: %v", err)
		}
	}()
}

func (a *HostPullAgent) currentIdentity() Config {
	if a == nil {
		return Config{}
	}
	a.identityMu.RLock()
	defer a.identityMu.RUnlock()
	if a.currentBootstrap.IsManagedBootstrap() {
		return a.currentBootstrap
	}
	return a.Bootstrap
}

func (a *HostPullAgent) currentAgentVersion() string {
	if a == nil || strings.TrimSpace(a.AgentVersion) == "" {
		return controlversion.Current()
	}
	return strings.TrimSpace(a.AgentVersion)
}

func (a *HostPullAgent) replaceRuntimeIdentity(identity Config) error {
	if a == nil || !identity.IsManagedBootstrap() {
		return errors.New("replacement Host Agent identity is invalid")
	}
	current := a.currentIdentity()
	if identity.PanelURL != current.PanelURL ||
		identity.NodeID != current.NodeID ||
		identity.ServiceName != current.ServiceName {
		return errors.New("runtime token rotation changed immutable Host Agent identity")
	}
	a.identityMu.Lock()
	a.currentBootstrap = identity
	a.identityMu.Unlock()
	return nil
}

func (a *HostPullAgent) observe(ctx context.Context, policy HostAgentPolicy) ([]HostTargetObservation, bool) {
	if a.ObserveTargets == nil {
		observations := make([]HostTargetObservation, 0, len(policy.Targets))
		for _, target := range policy.Targets {
			observations = append(observations, HostTargetObservation{
				ServiceID: target.ServiceID, Availability: TargetAvailabilityUnknown,
			})
		}
		return observations, false
	}
	observations, err := a.ObserveTargets(ctx, policy)
	if err != nil {
		if ctx.Err() == nil {
			a.Logf("host pull agent target observation failed")
		}
		return nil, true
	}
	allowedTargets := make(map[string]struct{}, len(policy.Targets))
	for _, target := range policy.Targets {
		allowedTargets[target.ServiceID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(observations))
	filtered := make([]HostTargetObservation, 0, len(observations))
	for _, observation := range observations {
		observation.ServiceID = strings.TrimSpace(observation.ServiceID)
		if _, allowed := allowedTargets[observation.ServiceID]; !allowed {
			continue
		}
		if _, duplicate := seen[observation.ServiceID]; duplicate {
			continue
		}
		switch observation.Availability {
		case TargetAvailabilityAvailable, TargetAvailabilityUnavailable, TargetAvailabilityUnknown:
		default:
			observation.Availability = TargetAvailabilityUnknown
		}
		if observation.ReportedPort < 0 || observation.ReportedPort > 65535 {
			observation.ReportedPort = 0
		}
		if observation.ReportedServiceType != "" && !validLocalExecutorServiceType(observation.ReportedServiceType) {
			observation.ReportedServiceType = ""
		}
		if observation.ReportedDeploymentMode != "" &&
			observation.ReportedDeploymentMode != ModeSystemd &&
			observation.ReportedDeploymentMode != ModeDocker {
			observation.ReportedDeploymentMode = ""
		}
		if observation.PolicyRevision < 0 {
			observation.PolicyRevision = 0
		}
		if observation.PolicySHA256 != "" && !digestPattern.MatchString(observation.PolicySHA256) {
			observation.PolicySHA256 = ""
		}
		if observation.ConfigRevision < 0 {
			observation.ConfigRevision = 0
		}
		if observation.ConfigSHA256 != "" && !digestPattern.MatchString(observation.ConfigSHA256) {
			observation.ConfigSHA256 = ""
		}
		if observation.Docker != nil &&
			!validHostDockerPortObservation(*observation.Docker) {
			observation.Docker = nil
		}
		if !identifierPattern.MatchString(strings.TrimSpace(observation.AvailabilityCode)) {
			observation.AvailabilityCode = ""
		}
		seen[observation.ServiceID] = struct{}{}
		filtered = append(filtered, observation)
	}
	return filtered, false
}

func (a *HostPullAgent) capabilities(binding HostAgentBinding, policy *HostAgentPolicy, observations []HostTargetObservation, observationFailed bool) map[string]any {
	executorReady := a.executorReady(policy, observations, observationFailed)
	mutationReady := a.mutationCapabilityReady(
		binding, policy, observations, observationFailed,
	)
	hostCapabilities := []string{
		"outbound_control",
		"policy_refresh",
		"target_availability",
		"port_drift",
	}
	if executorReady {
		hostCapabilities = append(hostCapabilities, "software_update_v1", "durable_reconcile_v1")
	}
	capabilities := map[string]any{
		"host_agent":                true,
		"observe_only":              !mutationReady,
		"update_executor":           executorReady,
		"mutation_enabled":          mutationReady,
		"transport_mode":            HostTransportPullV2,
		"agent_version":             a.currentAgentVersion(),
		"agent_protocol_version":    HostAgentProtocolVersion,
		"host_capabilities":         hostCapabilities,
		"os":                        runtime.GOOS,
		"arch":                      runtime.GOARCH,
		"executor_version":          controlversion.Current(),
		"executor_protocol_version": LocalExecutorMutationProtocolVersion,
		"mutation_protocol_version": LocalExecutorMutationProtocolVersion,
		"recovery_protocol_version": HostSelfUpdateRecoveryProtocolVersion,
	}
	if a.Journal != nil && a.Journal.Active() != nil {
		capabilities["recovery_pending"] = true
	} else {
		capabilities["recovery_pending"] = false
	}
	if selfUpdate := a.selfUpdateStatus.Load(); selfUpdate != nil {
		capabilities["self_update_phase"] = selfUpdate.State.Phase
		capabilities["self_update_active_agent_version"] = selfUpdate.State.ActiveAgentVersion
		capabilities["self_update_active_executor_version"] = selfUpdate.State.ActiveExecutorVersion
		capabilities["self_update_pending_generation"] = selfUpdate.State.PendingGeneration
		capabilities["self_update_failed_generation"] = selfUpdate.State.FailedGeneration
		capabilities["self_update_current_slot"] = selfUpdate.CurrentSlot
		capabilities["executor_version"] = selfUpdate.ExecutorVersion
		capabilities["executor_protocol_version"] = selfUpdate.ExecutorProtocolVersion
		capabilities["self_update_ready"] = selfUpdate.State.Phase == HostSelfUpdatePhaseStable
	}
	if a.rotationRunning.Load() {
		capabilities["runtime_token_rotation_phase"] = "reconciling"
	}
	if policy != nil && policy.SelfUpdate != nil &&
		controlversion.Current() == policy.SelfUpdate.AgentVersion {
		capabilities["self_update_heartbeat_generation"] = policy.SelfUpdate.Generation
	}
	if binding.ExecutionHostID != "" {
		capabilities["execution_host_id"] = binding.ExecutionHostID
		capabilities["ownership_epoch"] = binding.OwnershipEpoch
	}
	if policy == nil {
		capabilities["policy_revision"] = int64(0)
		capabilities["source_policy_revision"] = int64(0)
		capabilities["local_executor_policy_revision"] = int64(0)
		capabilities["target_availability"] = map[string]string{}
		capabilities["target_availability_codes"] = map[string]string{}
		capabilities["reported_ports"] = map[string]int{}
		capabilities["port_drift"] = map[string]bool{}
		capabilities["reported_service_types"] = map[string]string{}
		capabilities["reported_deployment_modes"] = map[string]string{}
		capabilities["reported_executor_policy_revisions"] = map[string]int64{}
		capabilities["reported_executor_policy_sha256"] = map[string]string{}
		capabilities["reported_config_revisions"] = map[string]int64{}
		capabilities["reported_config_sha256"] = map[string]string{}
		capabilities["reported_docker_port_capabilities"] = map[string]string{}
		capabilities["reported_docker_published_ports"] = map[string]int{}
		capabilities["reported_docker_container_ports"] = map[string]int{}
		capabilities["reported_docker_health_ports"] = map[string]int{}
		capabilities["reported_docker_compose_sha256"] = map[string]string{}
		capabilities["reported_docker_compose_revisions"] = map[string]int64{}
		capabilities["reported_docker_version_env_sha256"] = map[string]string{}
		capabilities["reported_docker_container_ids"] = map[string]string{}
		capabilities["reported_docker_image_ids"] = map[string]string{}
		capabilities["reported_docker_repository_digests"] = map[string]string{}
		a.addRuntimeTokenRotationCapabilities(capabilities)
		return capabilities
	}
	capabilities["policy_revision"] = policy.Revision
	capabilities["source_policy_revision"] = policy.SourcePolicyRevision
	capabilities["local_executor_policy_revision"] = policy.LocalExecutorPolicyRevision
	capabilities["policy_status"] = PolicyStatusApplied
	availability := make(map[string]string, len(policy.Targets))
	availabilityCodes := make(map[string]string, len(policy.Targets))
	reportedPorts := make(map[string]int, len(policy.Targets))
	portDrift := make(map[string]bool, len(policy.Targets))
	reportedServiceTypes := make(map[string]string, len(policy.Targets))
	reportedDeploymentModes := make(map[string]string, len(policy.Targets))
	reportedPolicyRevisions := make(map[string]int64, len(policy.Targets))
	reportedPolicyDigests := make(map[string]string, len(policy.Targets))
	reportedConfigRevisions := make(map[string]int64, len(policy.Targets))
	reportedConfigDigests := make(map[string]string, len(policy.Targets))
	reportedDockerCapabilities := make(map[string]string, len(policy.Targets))
	reportedDockerPublishedPorts := make(map[string]int, len(policy.Targets))
	reportedDockerContainerPorts := make(map[string]int, len(policy.Targets))
	reportedDockerHealthPorts := make(map[string]int, len(policy.Targets))
	reportedDockerComposeDigests := make(map[string]string, len(policy.Targets))
	reportedDockerComposeRevisions := make(map[string]int64, len(policy.Targets))
	reportedDockerVersionEnvDigests := make(map[string]string, len(policy.Targets))
	reportedDockerContainerIDs := make(map[string]string, len(policy.Targets))
	reportedDockerImageIDs := make(map[string]string, len(policy.Targets))
	reportedDockerRepositoryDigests := make(map[string]string, len(policy.Targets))
	observed := make(map[string]HostTargetObservation, len(observations))
	for _, observation := range observations {
		observed[observation.ServiceID] = observation
	}
	for _, target := range policy.Targets {
		observation, exists := observed[target.ServiceID]
		if !exists {
			observation = HostTargetObservation{ServiceID: target.ServiceID, Availability: TargetAvailabilityUnknown}
		}
		if observationFailed {
			observation.Availability = TargetAvailabilityUnknown
			observation.AvailabilityCode = "observation_failed"
			observation.Docker = nil
		}
		availability[target.ServiceID] = observation.Availability
		if observation.AvailabilityCode != "" {
			availabilityCodes[target.ServiceID] = observation.AvailabilityCode
		}
		if observation.Docker != nil {
			reportedPorts[target.ServiceID] = observation.Docker.AdvertisedPort
			reportedDockerCapabilities[target.ServiceID] = observation.Docker.CapabilityVersion
			reportedDockerPublishedPorts[target.ServiceID] = observation.Docker.PublishedPort
			reportedDockerContainerPorts[target.ServiceID] = observation.Docker.ContainerPort
			reportedDockerHealthPorts[target.ServiceID] = observation.Docker.HealthPort
			reportedDockerComposeDigests[target.ServiceID] = observation.Docker.ComposePolicySHA256
			reportedDockerComposeRevisions[target.ServiceID] = observation.Docker.ComposeRevision
			reportedDockerVersionEnvDigests[target.ServiceID] = observation.Docker.VersionEnvSHA256
			reportedDockerContainerIDs[target.ServiceID] = observation.Docker.ContainerID
			reportedDockerImageIDs[target.ServiceID] = observation.Docker.ImageID
			reportedDockerRepositoryDigests[target.ServiceID] = observation.Docker.RepositoryDigest
		} else if observation.ReportedPort > 0 {
			reportedPorts[target.ServiceID] = observation.ReportedPort
		}
		if observation.ReportedServiceType != "" {
			reportedServiceTypes[target.ServiceID] = observation.ReportedServiceType
		}
		if observation.ReportedDeploymentMode != "" {
			reportedDeploymentModes[target.ServiceID] = observation.ReportedDeploymentMode
		}
		if observation.PolicyRevision > 0 {
			reportedPolicyRevisions[target.ServiceID] = observation.PolicyRevision
		}
		if observation.PolicySHA256 != "" {
			reportedPolicyDigests[target.ServiceID] = observation.PolicySHA256
		}
		if observation.ConfigRevision > 0 {
			reportedConfigRevisions[target.ServiceID] = observation.ConfigRevision
		}
		if observation.ConfigSHA256 != "" {
			reportedConfigDigests[target.ServiceID] = observation.ConfigSHA256
		}
		if observation.Docker != nil {
			portDrift[target.ServiceID] = false
		} else if target.LocalListenEndpoint != nil && observation.ReportedPort > 0 {
			portDrift[target.ServiceID] = target.LocalListenEndpoint.Port != observation.ReportedPort
		}
	}
	capabilities["target_availability"] = availability
	capabilities["target_availability_codes"] = availabilityCodes
	capabilities["reported_ports"] = reportedPorts
	capabilities["port_drift"] = portDrift
	capabilities["reported_service_types"] = reportedServiceTypes
	capabilities["reported_deployment_modes"] = reportedDeploymentModes
	capabilities["reported_executor_policy_revisions"] = reportedPolicyRevisions
	capabilities["reported_executor_policy_sha256"] = reportedPolicyDigests
	capabilities["reported_config_revisions"] = reportedConfigRevisions
	capabilities["reported_config_sha256"] = reportedConfigDigests
	capabilities["reported_docker_port_capabilities"] = reportedDockerCapabilities
	capabilities["reported_docker_published_ports"] = reportedDockerPublishedPorts
	capabilities["reported_docker_container_ports"] = reportedDockerContainerPorts
	capabilities["reported_docker_health_ports"] = reportedDockerHealthPorts
	capabilities["reported_docker_compose_sha256"] = reportedDockerComposeDigests
	capabilities["reported_docker_compose_revisions"] = reportedDockerComposeRevisions
	capabilities["reported_docker_version_env_sha256"] = reportedDockerVersionEnvDigests
	capabilities["reported_docker_container_ids"] = reportedDockerContainerIDs
	capabilities["reported_docker_image_ids"] = reportedDockerImageIDs
	capabilities["reported_docker_repository_digests"] = reportedDockerRepositoryDigests
	a.addRuntimeTokenRotationCapabilities(capabilities)
	return capabilities
}

func validHostDockerPortObservation(observation HostDockerPortObservation) bool {
	return observation.CapabilityVersion == dockerPortCapabilityVersion &&
		observation.AdvertisedPort >= 1 &&
		observation.AdvertisedPort <= 65535 &&
		validSystemdPort(observation.PublishedPort) &&
		validSystemdPort(observation.ContainerPort) &&
		observation.HealthPort == observation.PublishedPort &&
		mutationPlanHashPattern.MatchString(observation.ComposePolicySHA256) &&
		observation.ComposeRevision >= 1 &&
		digestPattern.MatchString(observation.VersionEnvSHA256) &&
		len(observation.ContainerID) == 64 &&
		dockerContainerIDPattern.MatchString(observation.ContainerID) &&
		digestPattern.MatchString(observation.ImageID) &&
		digestPattern.MatchString(observation.RepositoryDigest)
}

func (a *HostPullAgent) addRuntimeTokenRotationCapabilities(
	capabilities map[string]any,
) {
	if a == nil || capabilities == nil {
		return
	}
	status := a.runtimeCredentialStatus.Load()
	if status == nil ||
		(status.Phase != RuntimeCredentialPhaseLocalStaged &&
			status.Phase != RuntimeCredentialPhaseProofReady) {
		return
	}
	capabilities["runtime_token_rotation_id"] = status.RotationID
	capabilities["runtime_token_rotation_phase"] = status.Phase
	capabilities["execution_host_id"] = status.ExecutionHostID
	capabilities["executor_version"] = status.ExecutorVersion
	capabilities["executor_protocol_version"] =
		status.ExecutorProtocolVersion
	capabilities["mutation_protocol_version"] =
		status.MutationProtocolVersion
	capabilities["ownership_epoch"] = status.OwnershipEpoch
	capabilities["source_policy_revision"] =
		status.SourcePolicyRevision
	capabilities["projection_revision"] = status.ProjectionRevision
	capabilities["local_executor_policy_revision"] =
		status.LocalExecutorPolicyRevision
	capabilities["local_executor_policy_sha256"] =
		status.LocalExecutorPolicySHA256
	capabilities["local_stage_receipt_id"] = status.LocalStageReceiptID
	capabilities["local_phase"] = "staged_token_active"
}

func (a *HostPullAgent) recordRuntimeTokenRotationHeartbeat() {
	if a == nil {
		return
	}
	status := a.runtimeCredentialStatus.Load()
	if status == nil || status.Phase != RuntimeCredentialPhaseLocalStaged {
		a.runtimeCredentialHeartbeat.Store(nil)
		return
	}
	copy := *status
	a.runtimeCredentialHeartbeat.Store(&copy)
}

func deploymentAbsolutePath(path string) bool {
	if filepath.IsAbs(path) {
		return true
	}
	// Host artifacts are built and validated on Windows as well as Linux. A
	// slash-rooted deployment path must remain recognizable before it reaches
	// the Linux host where the service actually runs.
	return strings.HasPrefix(strings.TrimSpace(path), "/")
}

type hostAgentRetryState struct {
	base      time.Duration
	max       time.Duration
	identity  string
	operation string
	failures  uint
	next      time.Time
}

func newHostAgentRetryState(base time.Duration, identity, operation string) hostAgentRetryState {
	maximum := 5 * time.Minute
	if base <= maximum/32 {
		maximum = base * 32
	}
	if maximum < base {
		maximum = base
	}
	return hostAgentRetryState{
		base: base, max: maximum, identity: identity, operation: operation,
	}
}

func (r hostAgentRetryState) ready(now time.Time) bool {
	return r.next.IsZero() || !now.Before(r.next)
}

func (r *hostAgentRetryState) record(now time.Time, succeeded bool) {
	if succeeded {
		r.failures = 0
		r.next = time.Time{}
		return
	}
	r.failures++
	exponent := r.failures
	if exponent > 5 {
		exponent = 5
	}
	multiplier := time.Duration(uint64(1) << exponent)
	delay := r.max
	if r.base <= r.max/multiplier {
		delay = r.base * multiplier
	}
	delay = hostAgentJitteredInterval(delay, r.identity, fmt.Sprintf("%s-retry-%d", r.operation, r.failures))
	r.next = now.Add(delay)
}

func hostAgentJitteredInterval(base time.Duration, identity, operation string) time.Duration {
	if base <= 0 {
		return base
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.TrimSpace(identity)))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(operation))
	offsetPermille := int64(hasher.Sum32()%201) - 100
	jittered := base + time.Duration((int64(base)*offsetPermille)/1000)
	if jittered <= 0 {
		return base
	}
	return jittered
}
