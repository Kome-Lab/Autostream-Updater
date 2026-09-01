package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/hostruntime"
	"github.com/Kome-Lab/Autostream-Updater/internal/version"
)

const defaultHostAgentConfigPath = hostruntime.HostAgentIdentityPath
const hostAgentRecoverUpdateTimeout = 2 * time.Minute
const hostAgentUsage = "usage: autostream-host-agent run --config PATH | recover-update --config PATH | configure --panel-url URL --node ID [--config PATH] [--adopt-live-systemd-sidecar] | validate-config --config PATH | --version"

type hostAgentCLIDependencies struct {
	LoadIdentity          func(string, bool) (hostruntime.Config, error)
	LoadCanonicalIdentity func(string, bool) (hostruntime.Config, error)
	Start                 func(context.Context, hostruntime.Config) error
	Recover               func(context.Context, hostruntime.Config) error
	Configure             func(context.Context, []string) error
	EffectiveUID          func() int
	ServiceAccountUID     func() (int, error)
	Output                io.Writer
}

func main() {
	if err := run(os.Args[1:], defaultHostAgentCLIDependencies()); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("autostream-host-agent: %v", err)
		os.Exit(1)
	}
}

func defaultHostAgentCLIDependencies() hostAgentCLIDependencies {
	return hostAgentCLIDependencies{
		LoadIdentity:          hostruntime.LoadHostAgentIdentity,
		LoadCanonicalIdentity: hostruntime.LoadManagedBootstrapConfig,
		Start: func(ctx context.Context, identity hostruntime.Config) error {
			agent, err := hostruntime.NewHostPullAgent(identity, hostruntime.HostPullAgentOptions{
				ObserveTargets: hostruntime.NewLocalExecutorTargetObserver(hostruntime.LocalExecutorClient{
					SocketPath: hostruntime.LocalExecutorSocketPath,
				}),
			})
			if err != nil {
				return err
			}
			return agent.Run(ctx)
		},
		Recover: func(ctx context.Context, identity hostruntime.Config) error {
			agent, err := hostruntime.NewHostPullAgent(identity, hostruntime.HostPullAgentOptions{
				RecoveryOnly: true,
			})
			if err != nil {
				return err
			}
			return agent.Run(ctx)
		},
		Configure: func(ctx context.Context, args []string) error {
			return runHostAgentConfigure(ctx, args, defaultHostAgentConfigureDependencies())
		},
		EffectiveUID: os.Geteuid,
		ServiceAccountUID: func() (int, error) {
			account, err := user.Lookup("autostream-host-agent")
			if err != nil {
				return 0, err
			}
			uid, err := strconv.Atoi(account.Uid)
			if err != nil || uid <= 0 {
				return 0, errors.New("Host Agent service account UID is invalid")
			}
			return uid, nil
		},
		Output: os.Stdout,
	}
}

func run(args []string, dependencies hostAgentCLIDependencies) error {
	if dependencies.LoadIdentity == nil || dependencies.LoadCanonicalIdentity == nil ||
		dependencies.Start == nil || dependencies.Recover == nil ||
		dependencies.Configure == nil || dependencies.EffectiveUID == nil ||
		dependencies.ServiceAccountUID == nil || dependencies.Output == nil {
		return errors.New("host agent CLI dependencies are incomplete")
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintf(dependencies.Output, "autostream-host-agent %s\ncommit: %s\nbuild_date: %s\n", version.Current(), version.Commit, version.BuildDate)
		return nil
	}
	if len(args) == 0 {
		return errors.New(hostAgentUsage)
	}

	switch args[0] {
	case "configure":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return dependencies.Configure(ctx, args[1:])
	case "validate-config":
		configPath, err := parseHostAgentConfigFlag("validate-config", args[1:])
		if err != nil {
			return err
		}
		if _, err := dependencies.LoadIdentity(configPath, true); err != nil {
			return err
		}
		fmt.Fprintln(dependencies.Output, "host agent identity configuration valid")
		return nil
	case "recover-update":
		serviceUID, err := dependencies.ServiceAccountUID()
		if err != nil {
			return fmt.Errorf("resolve Host Agent service account: %w", err)
		}
		if dependencies.EffectiveUID() != serviceUID {
			return errors.New("recover-update must run as the non-root Host Agent service account")
		}
		configPath, err := parseHostAgentConfigFlag("recover-update", args[1:])
		if err != nil {
			return err
		}
		if configPath != defaultHostAgentConfigPath {
			return errors.New("recover-update requires the canonical Host Agent identity path")
		}
		identity, err := dependencies.LoadCanonicalIdentity(configPath, true)
		if err != nil {
			return err
		}
		signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(signalCtx, hostAgentRecoverUpdateTimeout)
		defer cancel()
		return dependencies.Recover(ctx, identity)
	case "run":
		configPath, err := parseHostAgentConfigFlag("run", args[1:])
		if err != nil {
			return err
		}
		identity, err := dependencies.LoadIdentity(configPath, true)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return dependencies.Start(ctx, identity)
	default:
		return errors.New(hostAgentUsage)
	}
}

func parseHostAgentConfigFlag(command string, args []string) (string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", defaultHostAgentConfigPath, "root-owned host agent identity configuration")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		return "", fmt.Errorf("%s accepts only --config PATH", command)
	}
	return *configPath, nil
}
