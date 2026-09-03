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
	"path"
	"strings"
	"syscall"

	"github.com/Kome-Lab/Autostream-Updater/internal/hostruntime"
	"github.com/Kome-Lab/Autostream-Updater/internal/version"
)

const defaultLocalExecutorPolicyPath = "/etc/autostream/updater/executor-policy.json"
const localExecutorUsage = "usage: autostream-local-executor run [--policy PATH] | inspect-host-update-recovery | manual-upgrade-host-runtime --artifact-root PATH --archive-sha256 SHA256 --archive-size BYTES [--agent-stopped-for-recovery] | guard-restart-host-agent --expected-slot a|b --agent-sha256 SHA256 --executor-sha256 SHA256 | recover-self-update --recovery-slot a|b | recover-runtime-credential --rotation-id ID --confirm-emergency-revoked | validate-policy [--policy PATH] | version"

type localExecutorCLIDependencies struct {
	LoadPolicy                func(string, bool) (hostruntime.LocalExecutorPolicy, error)
	ServeExecutor             func(context.Context, string) error
	RecoverSelfUpdate         func(context.Context, string) error
	RecoverRuntimeCredential  func(string) error
	InspectHostUpdateRecovery func() (bool, error)
	UpgradeHostRuntime        func(context.Context, hostruntime.ManualHostUpgradeRequest) (hostruntime.ManualHostUpgradeResult, error)
	GuardRestartHostAgent     func(context.Context, hostruntime.HostAgentUpgradeGuardRequest) error
	RequireRoot               func() error
	Output                    io.Writer
}

func main() {
	args := os.Args[1:]
	if err := run(args, defaultLocalExecutorCLIDependencies()); err != nil &&
		!suppressLocalExecutorCancellation(args, err) {
		log.Printf("autostream-local-executor: %v", err)
		os.Exit(1)
	}
}

func suppressLocalExecutorCancellation(args []string, err error) bool {
	return errors.Is(err, context.Canceled) &&
		(len(args) == 0 ||
			(args[0] != "manual-upgrade-host-runtime" &&
				args[0] != "guard-restart-host-agent"))
}

func defaultLocalExecutorCLIDependencies() localExecutorCLIDependencies {
	return localExecutorCLIDependencies{
		LoadPolicy:                hostruntime.LoadLocalExecutorPolicy,
		ServeExecutor:             hostruntime.ServeLocalExecutor,
		RecoverSelfUpdate:         hostruntime.RecoverHostSelfUpdate,
		RecoverRuntimeCredential:  hostruntime.RecoverRuntimeCredentialAfterEmergencyManualReconfigure,
		InspectHostUpdateRecovery: hostruntime.InspectHostUpdateRecovery,
		UpgradeHostRuntime:        hostruntime.UpgradeHostRuntimeFromVerifiedBundle,
		GuardRestartHostAgent:     hostruntime.RestartHostAgentFromUpgradeGuard,
		RequireRoot:               hostruntime.RequireLocalExecutorRoot,
		Output:                    os.Stdout,
	}
}

func run(args []string, dependencies localExecutorCLIDependencies) error {
	if dependencies.LoadPolicy == nil || dependencies.ServeExecutor == nil || dependencies.Output == nil {
		return errors.New("local executor CLI dependencies are incomplete")
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintf(
			dependencies.Output,
			"autostream-local-executor %s\ncommit: %s\nbuild_date: %s\nmutation_protocol: %d\nrecovery_protocol: %d\n",
			version.Current(),
			version.Commit,
			version.BuildDate,
			hostruntime.LocalExecutorMutationProtocolVersion,
			hostruntime.HostSelfUpdateRecoveryProtocolVersion,
		)
		return nil
	}
	if len(args) == 0 {
		return errors.New(localExecutorUsage)
	}

	switch args[0] {
	case "run":
		policyPath, err := parsePolicyFlag("run", args[1:])
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return dependencies.ServeExecutor(ctx, policyPath)
	case "recover-self-update":
		if dependencies.RecoverSelfUpdate == nil {
			return errors.New("local executor recovery dependency is unavailable")
		}
		recoverySlot, err := parseRecoverySlot(args[1:])
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return dependencies.RecoverSelfUpdate(ctx, recoverySlot)
	case "manual-upgrade-host-runtime":
		if dependencies.UpgradeHostRuntime == nil ||
			dependencies.RequireRoot == nil {
			return errors.New("manual Host runtime upgrade dependency is unavailable")
		}
		request, err := parseManualHostUpgrade(args[1:])
		if err != nil {
			return err
		}
		if err := dependencies.RequireRoot(); err != nil {
			return errors.New("manual Host runtime upgrade requires root")
		}
		ctx, stop := signal.NotifyContext(
			context.Background(), os.Interrupt, syscall.SIGTERM,
		)
		defer stop()
		result, err := dependencies.UpgradeHostRuntime(ctx, request)
		if err != nil {
			return fmt.Errorf("manual Host runtime upgrade rejected: %w", err)
		}
		if result.AlreadyCurrent {
			fmt.Fprintf(
				dependencies.Output,
				"Host Agent runtime already uses %s in slots/%s.\n",
				result.Version,
				result.ActiveSlot,
			)
			return nil
		}
		fmt.Fprintf(
			dependencies.Output,
			"Host Agent runtime upgraded to %s: slots/%s -> slots/%s.\n",
			result.Version,
			result.PreviousSlot,
			result.ActiveSlot,
		)
		return nil
	case "inspect-host-update-recovery":
		if len(args) != 1 ||
			dependencies.InspectHostUpdateRecovery == nil ||
			dependencies.RequireRoot == nil {
			return errors.New(
				"Host update recovery inspection dependency is unavailable",
			)
		}
		if err := dependencies.RequireRoot(); err != nil {
			return errors.New("Host update recovery inspection requires root")
		}
		active, err := dependencies.InspectHostUpdateRecovery()
		if err != nil {
			return fmt.Errorf("inspect Host update recovery: %w", err)
		}
		if active {
			fmt.Fprintln(dependencies.Output, "active")
		} else {
			fmt.Fprintln(dependencies.Output, "inactive")
		}
		return nil
	case "guard-restart-host-agent":
		if dependencies.GuardRestartHostAgent == nil ||
			dependencies.RequireRoot == nil {
			return errors.New(
				"Host Agent installer recovery guard dependency is unavailable",
			)
		}
		request, err := parseHostAgentUpgradeGuard(args[1:])
		if err != nil {
			return err
		}
		if err := dependencies.RequireRoot(); err != nil {
			return errors.New("Host Agent installer recovery guard requires root")
		}
		ctx, stop := signal.NotifyContext(
			context.Background(), os.Interrupt, syscall.SIGTERM,
		)
		defer stop()
		if err := dependencies.GuardRestartHostAgent(ctx, request); err != nil {
			return fmt.Errorf("Host Agent installer recovery guard rejected: %w", err)
		}
		fmt.Fprintln(dependencies.Output, "exact pre-upgrade Host Agent restarted")
		return nil
	case "recover-runtime-credential":
		if dependencies.RecoverRuntimeCredential == nil ||
			dependencies.RequireRoot == nil {
			return errors.New(
				"runtime credential recovery dependency is unavailable",
			)
		}
		rotationID, err := parseRuntimeCredentialRecovery(args[1:])
		if err != nil {
			return err
		}
		if err := dependencies.RequireRoot(); err != nil {
			return errors.New(
				"recover-runtime-credential requires root",
			)
		}
		if err := dependencies.RecoverRuntimeCredential(rotationID); err != nil {
			return errors.New(
				"runtime credential emergency recovery rejected",
			)
		}
		fmt.Fprintln(
			dependencies.Output,
			"runtime credential emergency recovery prepared",
		)
		return nil
	case "validate-policy":
		policyPath, err := parsePolicyFlag("validate-policy", args[1:])
		if err != nil {
			return err
		}
		policy, err := dependencies.LoadPolicy(policyPath, true)
		if err != nil {
			return err
		}
		digest, err := policy.SHA256()
		if err != nil {
			return err
		}
		fmt.Fprintf(
			dependencies.Output,
			"local executor policy valid\nhost_id: %s\nagent_uid: %d\nagent_gid: %d\npolicy_revision: %d\npolicy_sha256: %s\n",
			policy.HostID,
			policy.AgentUID,
			policy.AgentGID,
			policy.PolicyRevision,
			digest,
		)
		return nil
	default:
		return errors.New(localExecutorUsage)
	}
}

func parseManualHostUpgrade(
	args []string,
) (hostruntime.ManualHostUpgradeRequest, error) {
	flags := flag.NewFlagSet("manual-upgrade-host-runtime", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifactRoot := flags.String("artifact-root", "", "verified Host Agent bundle root")
	archiveSHA256 := flags.String("archive-sha256", "", "verified adjacent archive digest")
	archiveSize := flags.Int64("archive-size", 0, "verified adjacent archive size")
	agentStoppedForRecovery := flags.Bool(
		"agent-stopped-for-recovery",
		false,
		"the verified installer stopped the Agent after candidate recovery",
	)
	if err := flags.Parse(args); err != nil {
		return hostruntime.ManualHostUpgradeRequest{}, errors.New(
			"manual Host runtime upgrade arguments are invalid",
		)
	}
	validSHA256 := len(*archiveSHA256) == 64
	for _, character := range *archiveSHA256 {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			validSHA256 = false
		}
	}
	if flags.NArg() != 0 || !path.IsAbs(*artifactRoot) ||
		!validSHA256 || *archiveSize < 1 || *archiveSize > 268435456 {
		return hostruntime.ManualHostUpgradeRequest{}, errors.New(
			"manual Host runtime upgrade requires exactly an absolute --artifact-root, --archive-sha256, and --archive-size",
		)
	}
	return hostruntime.ManualHostUpgradeRequest{
		ArtifactRoot:            *artifactRoot,
		ArchiveSHA256:           *archiveSHA256,
		ArchiveSize:             *archiveSize,
		AgentStoppedForRecovery: *agentStoppedForRecovery,
	}, nil
}

func parseHostAgentUpgradeGuard(
	args []string,
) (hostruntime.HostAgentUpgradeGuardRequest, error) {
	flags := flag.NewFlagSet("guard-restart-host-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	expectedSlot := flags.String("expected-slot", "", "exact pre-upgrade A/B slot")
	agentSHA256 := flags.String("agent-sha256", "", "exact pre-upgrade Agent digest")
	executorSHA256 := flags.String(
		"executor-sha256",
		"",
		"exact pre-upgrade Local Executor digest",
	)
	if err := flags.Parse(args); err != nil {
		return hostruntime.HostAgentUpgradeGuardRequest{}, errors.New(
			"Host Agent installer recovery guard arguments are invalid",
		)
	}
	if flags.NArg() != 0 ||
		(*expectedSlot != hostruntime.HostSelfUpdateSlotA &&
			*expectedSlot != hostruntime.HostSelfUpdateSlotB) ||
		!isLowerHexSHA256(*agentSHA256) ||
		!isLowerHexSHA256(*executorSHA256) {
		return hostruntime.HostAgentUpgradeGuardRequest{}, errors.New(
			"Host Agent installer recovery guard requires exactly --expected-slot a|b, --agent-sha256, and --executor-sha256",
		)
	}
	return hostruntime.HostAgentUpgradeGuardRequest{
		ExpectedSlot:   *expectedSlot,
		AgentSHA256:    *agentSHA256,
		ExecutorSHA256: *executorSHA256,
	}, nil
}

func isLowerHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func parseRuntimeCredentialRecovery(args []string) (string, error) {
	flags := flag.NewFlagSet(
		"recover-runtime-credential",
		flag.ContinueOnError,
	)
	flags.SetOutput(io.Discard)
	rotationID := flags.String(
		"rotation-id",
		"",
		"exact runtime token rotation ID from the local root ledger",
	)
	confirmed := flags.Bool(
		"confirm-emergency-revoked",
		false,
		"confirm both rotation credentials were revoked at the Control Panel",
	)
	if err := flags.Parse(args); err != nil {
		return "", errors.New(
			"recover-runtime-credential arguments are invalid",
		)
	}
	if flags.NArg() != 0 ||
		strings.TrimSpace(*rotationID) == "" ||
		*rotationID != strings.TrimSpace(*rotationID) ||
		!*confirmed {
		return "", errors.New(
			"recover-runtime-credential requires exactly --rotation-id ID --confirm-emergency-revoked",
		)
	}
	return *rotationID, nil
}

func parseRecoverySlot(args []string) (string, error) {
	flags := flag.NewFlagSet("recover-self-update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	recoverySlot := flags.String("recovery-slot", "", "fixed A/B recovery slot")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 ||
		(*recoverySlot != hostruntime.HostSelfUpdateSlotA &&
			*recoverySlot != hostruntime.HostSelfUpdateSlotB) {
		return "", errors.New("recover-self-update requires exactly --recovery-slot a|b")
	}
	return *recoverySlot, nil
}

func parsePolicyFlag(command string, args []string) (string, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", defaultLocalExecutorPolicyPath, "root-owned local executor policy")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		return "", fmt.Errorf("%s accepts only --policy PATH", command)
	}
	if !path.IsAbs(*policyPath) {
		return "", errors.New("local executor policy path must be absolute")
	}
	return *policyPath, nil
}
