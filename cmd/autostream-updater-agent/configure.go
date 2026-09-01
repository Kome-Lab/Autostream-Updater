package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/hostruntime"
	"github.com/Kome-Lab/Autostream-Updater/internal/version"
)

const hostAgentInstallGroup = "autostream-host-agent"

type preparedHostAgentConfig interface {
	CommitContext(context.Context, hostruntime.UpdaterConfigureIdentity, hostruntime.ConfigurePolicyProjection) error
	Abort()
}

type hostAgentConfigureDependencies struct {
	AcquireRuntimeLocks func() (func(), error)
	AcquireTargetLocks  func() (func(), error)
	Prepare             func(string, string, hostruntime.HostAgentConfigurationOptions) (preparedHostAgentConfig, error)
	ServiceIdentity     func() (hostruntime.HostAgentConfigurePeerIdentity, error)
	ReadToken           func(context.Context) (string, error)
	Stage               func(context.Context, string, string, string, hostruntime.HostAgentConfigurePeerIdentity, time.Duration) (hostruntime.UpdaterStagedConfiguration, error)
	ValidateInstalled   func(string, string, hostruntime.UpdaterStagedConfiguration) error
	Activate            func(context.Context, string, hostruntime.UpdaterStagedConfiguration, hostruntime.UpdaterRuntimeReport, time.Duration) (hostruntime.UpdaterActivationResult, error)
	Hostname            func() (string, error)
	Output              io.Writer
}

func defaultHostAgentConfigureDependencies() hostAgentConfigureDependencies {
	return hostAgentConfigureDependencies{
		AcquireRuntimeLocks: hostruntime.AcquireHostRuntimeSetupAndLifecycleLocks,
		AcquireTargetLocks:  hostruntime.AcquireHostConfigurationTargetLocks,
		Prepare: func(identityPath, policyPath string, options hostruntime.HostAgentConfigurationOptions) (preparedHostAgentConfig, error) {
			return hostruntime.PrepareHostAgentConfigurationWithOptions(
				identityPath,
				policyPath,
				hostAgentInstallGroup,
				options,
			)
		},
		ServiceIdentity: func() (hostruntime.HostAgentConfigurePeerIdentity, error) {
			return hostruntime.LookupManagedServiceIdentity(
				hostAgentInstallGroup,
				hostAgentInstallGroup,
			)
		},
		ReadToken: defaultReadHostAgentConfigureToken,
		Stage: func(ctx context.Context, panelURL, nodeID, token string, peer hostruntime.HostAgentConfigurePeerIdentity, timeout time.Duration) (hostruntime.UpdaterStagedConfiguration, error) {
			return hostruntime.StageHostAgentConfiguration(
				ctx,
				http.DefaultClient,
				panelURL,
				nodeID,
				token,
				peer,
				timeout,
			)
		},
		ValidateInstalled: hostruntime.ValidateInstalledHostAgentConfiguration,
		Activate: func(ctx context.Context, panelURL string, staged hostruntime.UpdaterStagedConfiguration, report hostruntime.UpdaterRuntimeReport, timeout time.Duration) (hostruntime.UpdaterActivationResult, error) {
			return hostruntime.ActivateUpdaterConfiguration(ctx, http.DefaultClient, panelURL, staged, report, timeout)
		},
		Hostname: os.Hostname,
		Output:   os.Stdout,
	}
}

func runHostAgentConfigure(ctx context.Context, args []string, dependencies hostAgentConfigureDependencies) error {
	flags := flag.NewFlagSet("configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	panelURL := flags.String("panel-url", "", "Control Panel base URL")
	nodeID := flags.String("node", "", "registered Host Agent service ID")
	configPath := flags.String("config", defaultHostAgentConfigPath, "root-owned Host Agent identity configuration")
	timeout := flags.Duration("timeout", 30*time.Second, "Control Panel configure request timeout")
	adoptLiveSystemdSidecar := flags.Bool(
		"adopt-live-systemd-sidecar",
		false,
		"adopt one verified live systemd port sidecar during drift recovery",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("configure accepts only --panel-url, --node, --config, --timeout, and --adopt-live-systemd-sidecar")
	}
	if strings.TrimSpace(*panelURL) == "" {
		return errors.New("--panel-url is required")
	}
	if strings.TrimSpace(*nodeID) == "" {
		return errors.New("--node is required")
	}
	if *timeout <= 0 || *timeout > 5*time.Minute {
		return errors.New("--timeout must be greater than zero and at most 5m")
	}
	if dependencies.AcquireRuntimeLocks == nil || dependencies.AcquireTargetLocks == nil ||
		dependencies.Prepare == nil ||
		dependencies.ServiceIdentity == nil ||
		dependencies.ReadToken == nil || dependencies.Stage == nil ||
		dependencies.ValidateInstalled == nil || dependencies.Activate == nil ||
		dependencies.Hostname == nil || dependencies.Output == nil {
		return errors.New("configure dependencies are incomplete")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	runtimeUnlock, err := dependencies.AcquireRuntimeLocks()
	if err != nil {
		return errors.New("another Host runtime setup or lifecycle operation is active")
	}
	defer runtimeUnlock()
	if *adoptLiveSystemdSidecar {
		targetUnlock, err := dependencies.AcquireTargetLocks()
		if err != nil {
			return errors.New("another managed service target operation is active")
		}
		defer targetUnlock()
	}
	peer, err := dependencies.ServiceIdentity()
	if err != nil {
		return err
	}
	if peer.UID == 0 || peer.GID == 0 {
		return errors.New("Host Agent service account must be non-root")
	}
	prepared, err := dependencies.Prepare(
		*configPath,
		hostruntime.DefaultLocalExecutorPolicyPath,
		hostruntime.HostAgentConfigurationOptions{
			AdoptLiveSystemdSidecar: *adoptLiveSystemdSidecar,
		},
	)
	if err != nil {
		return err
	}
	defer prepared.Abort()
	hostname, err := dependencies.Hostname()
	if err != nil {
		return errors.New("read Host Agent hostname")
	}
	report := hostruntime.UpdaterRuntimeReport{
		Version: version.Current(), Commit: version.Commit, BuildDate: version.BuildDate,
		Hostname: hostname, OS: runtime.GOOS, Arch: runtime.GOARCH,
	}
	configureToken, err := dependencies.ReadToken(ctx)
	if err != nil {
		return err
	}
	staged, err := dependencies.Stage(
		ctx,
		strings.TrimSpace(*panelURL),
		strings.TrimSpace(*nodeID),
		configureToken,
		peer,
		*timeout,
	)
	configureToken = ""
	if err != nil {
		return fmt.Errorf("Host Agent configuration stage failed; existing identity remains active; issue a new Configure Token before retrying: %v", err)
	}
	if err := validateHostAgentStagedConfiguration(staged); err != nil {
		return fmt.Errorf("Host Agent configuration stage rejected; existing identity remains active; issue a new Configure Token before retrying: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("Host Agent configuration was staged but canceled before installation; existing identity remains active; issue a new Configure Token before retrying: %v", err)
	}
	if staged.LocalExecutorPolicy == nil {
		return errors.New("Host Agent configuration stage omitted the Local Executor policy")
	}
	if err := prepared.CommitContext(ctx, staged.Config, *staged.LocalExecutorPolicy); err != nil {
		if hostruntime.HostAgentConfigurationInstalled(err) {
			return fmt.Errorf("Host Agent identity was installed but post-install finalization failed; do not restart autostream-host-agent and issue a new Configure Token: %w", err)
		}
		return fmt.Errorf("Host Agent configuration was staged but installation failed; do not restart autostream-host-agent and issue a new Configure Token: %w", err)
	}
	postCommitError := func(operation string, err error) error {
		return fmt.Errorf("Host Agent identity was installed but %s failed; do not restart autostream-host-agent and issue a new Configure Token: %v", operation, err)
	}
	if err := dependencies.ValidateInstalled(
		*configPath,
		hostruntime.DefaultLocalExecutorPolicyPath,
		staged,
	); err != nil {
		return postCommitError("installed configuration validation", err)
	}
	result, err := dependencies.Activate(ctx, strings.TrimSpace(*panelURL), staged, report, *timeout)
	if err != nil {
		return postCommitError("activation", err)
	}
	if result.ConfigurationID != staged.ConfigurationID ||
		(result.State != "activated" && result.State != "already_activated") {
		return postCommitError("activation", errors.New("Control Panel returned an unexpected activation result"))
	}
	fmt.Fprintf(
		dependencies.Output,
		"Host Agent identity generated in %s and Local Executor policy installed in %s; both were activated. The observe-only service may now be started.\n",
		*configPath,
		hostruntime.DefaultLocalExecutorPolicyPath,
	)
	return nil
}

func validateHostAgentStagedConfiguration(staged hostruntime.UpdaterStagedConfiguration) error {
	if strings.TrimSpace(staged.Config.TransportMode) != "pull_v2" {
		return errors.New("Control Panel did not bind the staged identity to pull_v2")
	}
	if staged.Config.API != (hostruntime.UpdaterConfigureAPIAssertion{}) {
		return errors.New("portless Host Agent staged identity must not contain an API endpoint")
	}
	return nil
}
