package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Kome-Lab/Autostream-Updater/internal/hostruntime"
	"github.com/Kome-Lab/Autostream-Updater/internal/version"
)

const defaultHostAgentConfigPath = hostruntime.HostAgentIdentityPath
const hostAgentRecoverUpdateTimeout = 2 * time.Minute
const hostAgentUsage = "usage: autostream-host-agent run --config PATH | recover-update --config PATH | inspect-software-claim EXACT_JOB_FLAGS | recover-software-claim EXACT_JOB_FLAGS | recover-software-plan EXACT_JOB_FLAGS | configure --panel-url URL --node ID [--config PATH] [--adopt-live-systemd-sidecar] | validate-config --config PATH | --version"

type hostAgentCLIDependencies struct {
	LoadIdentity                            func(string, bool) (hostruntime.Config, error)
	LoadCanonicalIdentity                   func(string, bool) (hostruntime.Config, error)
	Start                                   func(context.Context, hostruntime.Config) error
	Recover                                 func(context.Context, hostruntime.Config) error
	RecoverSoftwareClaim                    func(context.Context, hostruntime.Config, hostruntime.SoftwareClaimRecoveryRequest) error
	RecoverSoftwareClaimAfterGenerationRead func(context.Context, hostruntime.Config, hostruntime.SoftwareClaimRecoveryRequest) error
	RecoverSoftwarePlanAfterGenerationRead  func(context.Context, hostruntime.Config, hostruntime.SoftwareClaimRecoveryRequest) error
	InspectSoftwareClaim                    func(context.Context, hostruntime.Config, hostruntime.SoftwareClaimRecoveryRequest) (hostruntime.SoftwareClaimRecoveryProof, error)
	Configure                               func(context.Context, []string) error
	EffectiveUID                            func() int
	ServiceAccountUID                       func() (int, error)
	Output                                  io.Writer
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
		RecoverSoftwareClaim: func(ctx context.Context, identity hostruntime.Config, request hostruntime.SoftwareClaimRecoveryRequest) error {
			agent, err := hostruntime.NewHostPullAgent(identity, hostruntime.HostPullAgentOptions{})
			if err != nil {
				return err
			}
			return agent.RecoverSoftwareClaim(ctx, request)
		},
		RecoverSoftwareClaimAfterGenerationRead: func(ctx context.Context, identity hostruntime.Config, request hostruntime.SoftwareClaimRecoveryRequest) error {
			agent, err := hostruntime.NewHostPullAgent(identity, hostruntime.HostPullAgentOptions{})
			if err != nil {
				return err
			}
			return agent.RecoverSoftwareClaimAfterGenerationRead(ctx, request)
		},
		RecoverSoftwarePlanAfterGenerationRead: func(ctx context.Context, identity hostruntime.Config, request hostruntime.SoftwareClaimRecoveryRequest) error {
			agent, err := hostruntime.NewHostPullAgent(identity, hostruntime.HostPullAgentOptions{})
			if err != nil {
				return err
			}
			return agent.RecoverSoftwarePlanAfterGenerationRead(ctx, request)
		},
		InspectSoftwareClaim: func(ctx context.Context, identity hostruntime.Config, request hostruntime.SoftwareClaimRecoveryRequest) (hostruntime.SoftwareClaimRecoveryProof, error) {
			agent, err := hostruntime.NewHostPullAgent(identity, hostruntime.HostPullAgentOptions{})
			if err != nil {
				return hostruntime.SoftwareClaimRecoveryProof{}, err
			}
			return agent.InspectSoftwareClaim(ctx, request)
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
	case "inspect-software-claim", "recover-software-claim", "recover-software-plan":
		return runSoftwareClaimRecoveryCommand(args[0], args[1:], dependencies)
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

func runSoftwareClaimRecoveryCommand(command string, args []string, dependencies hostAgentCLIDependencies) error {
	serviceUID, err := dependencies.ServiceAccountUID()
	if err != nil || serviceUID <= 0 {
		return errors.New("resolve non-root Host Agent service account")
	}
	if dependencies.EffectiveUID() != serviceUID {
		return errors.New("software claim recovery must run as the non-root Host Agent service account")
	}
	configPath, request, confirmedReread, err := parseSoftwareClaimRecoveryFlags(command, args)
	if err != nil {
		return err
	}
	if configPath != defaultHostAgentConfigPath {
		return errors.New("software claim recovery requires the canonical Host Agent identity path")
	}
	identity, err := dependencies.LoadCanonicalIdentity(configPath, true)
	if err != nil {
		return err
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, hostAgentRecoverUpdateTimeout)
	defer cancel()
	if command == "recover-software-plan" {
		if dependencies.RecoverSoftwarePlanAfterGenerationRead == nil {
			return errors.New("saved software plan recovery is unavailable")
		}
		if err := dependencies.RecoverSoftwarePlanAfterGenerationRead(ctx, identity, request); err != nil {
			return err
		}
		_, err := fmt.Fprintln(dependencies.Output, "saved software plan reconciled without restaging or reapplying")
		return err
	}
	if command == "inspect-software-claim" {
		if dependencies.InspectSoftwareClaim == nil {
			return errors.New("software claim recovery inspection is unavailable")
		}
		proof, err := dependencies.InspectSoftwareClaim(ctx, identity, request)
		if err != nil {
			return err
		}
		if proof.Validate() != nil {
			return errors.New("software claim recovery inspection returned invalid metadata")
		}
		return json.NewEncoder(dependencies.Output).Encode(proof)
	}
	recover := dependencies.RecoverSoftwareClaim
	if confirmedReread {
		recover = dependencies.RecoverSoftwareClaimAfterGenerationRead
	}
	if recover == nil {
		return errors.New("software claim recovery is unavailable")
	}
	if err := recover(ctx, identity, request); err != nil {
		return err
	}
	_, err = fmt.Fprintln(dependencies.Output, "software claim recovery settled without applying software")
	return err
}

func parseSoftwareClaimRecoveryFlags(command string, args []string) (string, hostruntime.SoftwareClaimRecoveryRequest, bool, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", defaultHostAgentConfigPath, "canonical root-owned Host Agent identity")
	var request hostruntime.SoftwareClaimRecoveryRequest
	flags.StringVar(&request.JobID, "job-id", "", "exact central job ID")
	flags.Uint64Var(&request.LeaseGeneration, "lease-generation", 0, "exact current generation read from this job")
	flags.StringVar(&request.TargetID, "target-id", "", "exact software target")
	flags.StringVar(&request.CurrentVersion, "current-version", "", "original current version")
	flags.StringVar(&request.TargetVersion, "target-version", "", "original target version")
	flags.Int64Var(&request.ConfigRevision, "config-revision", 0, "original application config revision")
	flags.Int64Var(&request.OwnershipEpoch, "ownership-epoch", 0, "current original ownership epoch")
	confirmedReread := flags.Bool("confirm-current-generation", false, "operator reread this same job's current generation after an uncertain claim")
	seen := make(map[string]bool)
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		if seen[name] {
			return "", hostruntime.SoftwareClaimRecoveryRequest{}, false, errors.New("software claim recovery flags must be specified exactly once")
		}
		seen[name] = true
	}
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return "", hostruntime.SoftwareClaimRecoveryRequest{}, false, errors.New("software claim recovery accepts only bounded job metadata flags")
	}
	if err := request.Validate(); err != nil {
		return "", hostruntime.SoftwareClaimRecoveryRequest{}, false, err
	}
	if *confirmedReread && command != "recover-software-claim" {
		return "", hostruntime.SoftwareClaimRecoveryRequest{}, false, errors.New("generation reread confirmation is valid only for recover-software-claim")
	}
	return *configPath, request, *confirmedReread, nil
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
