//go:build linux

package hostruntime

import (
	"context"
	"os"
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
