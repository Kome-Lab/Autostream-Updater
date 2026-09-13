package hostruntime

import (
	"context"
	"errors"
	controlversion "github.com/Kome-Lab/Autostream-Updater/internal/version"
	contracts "github.com/example/autostream-contracts/pkg/contracts"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	HostPullAgentStateDir = "/var/lib/autostream-host-agent"

	TargetAvailabilityUnknown     = "unknown"
	TargetAvailabilityAvailable   = "available"
	TargetAvailabilityUnavailable = "unavailable"
)

type HostTargetObservation struct {
	PortContractVersion     int
	PolicyTransitionVersion int
	SourcePolicyRevision    int64
	ProjectionRevision      int64
	AgentUID                uint32
	AgentGID                uint32
	EndpointRevision        int64
	ObservedAt              time.Time
	DockerRoot              *contracts.UpdaterPortDockerRootBaseline
	ServiceID               string
	Availability            string
	AvailabilityCode        string
	ReportedPort            int
	ReportedServiceType     string
	ReportedDeploymentMode  string
	PolicyRevision          int64
	PolicySHA256            string
	ConfigRevision          int64
	ConfigSHA256            string
	Docker                  *HostDockerPortObservation
}

type HostDockerPortObservation struct {
	CapabilityVersion   string
	AdvertisedPort      int
	PublishedPort       int
	ContainerPort       int
	HealthPort          int
	ComposePolicySHA256 string
	ComposeConfigSHA256 string
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
