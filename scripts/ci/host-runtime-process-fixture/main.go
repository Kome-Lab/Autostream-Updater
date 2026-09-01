package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	fixtureCommit    = "0123456789abcdef0123456789abcdef01234567"
	fixtureBuildDate = "2026-07-31T00:00:00Z"
	hostCommandPath  = "/opt/autostream/host-agent-smoke-fixtures/autostream-host-agent-command"
	execCommandPath  = "/opt/autostream/host-agent-smoke-fixtures/autostream-local-executor-command"
)

func isLegacyLiveRuntime() bool {
	executable, err := os.Executable()
	return err == nil && strings.Contains(filepath.ToSlash(executable), "/slots/a/")
}

func fixtureVersion(name string) string {
	if !isLegacyLiveRuntime() {
		return "v1.9.11"
	}
	version := os.Getenv("AUTOSTREAM_RUNTIME_FIXTURE_VERSION")
	if name == "autostream-host-agent" {
		if agentVersion := os.Getenv("AUTOSTREAM_RUNTIME_FIXTURE_AGENT_VERSION"); agentVersion != "" {
			version = agentVersion
		}
	}
	if name == "autostream-local-executor" {
		if executorVersion := os.Getenv("AUTOSTREAM_RUNTIME_FIXTURE_EXECUTOR_VERSION"); executorVersion != "" {
			version = executorVersion
		}
	}
	if version != "v1.9.9" && version != "v1.9.10" {
		fmt.Fprintln(os.Stderr, "legacy runtime fixture version must be v1.9.9 or v1.9.10")
		os.Exit(2)
	}
	return version
}

func dispatchFixtureCommand(name string) {
	if len(os.Args) < 2 {
		return
	}
	commandPath := ""
	switch {
	case name == "autostream-host-agent" && os.Args[1] == "recover-update":
		commandPath = hostCommandPath
	case name == "autostream-local-executor" &&
		(os.Args[1] == "inspect-host-update-recovery" ||
			os.Args[1] == "manual-upgrade-host-runtime" ||
			os.Args[1] == "guard-restart-host-agent"):
		commandPath = execCommandPath
	default:
		return
	}
	argv := append([]string{commandPath}, os.Args[1:]...)
	environment := os.Environ()
	if executable, err := os.Executable(); err == nil {
		environment = append(environment, "AUTOSTREAM_FIXTURE_EXECUTABLE="+executable)
	}
	if err := syscall.Exec(commandPath, argv, environment); err != nil {
		fmt.Fprintf(os.Stderr, "exec fixture command: %v\n", err)
		os.Exit(2)
	}
}

func fixtureRecoveryProtocol() string {
	if !isLegacyLiveRuntime() {
		return "2"
	}
	protocol := os.Getenv("AUTOSTREAM_RUNTIME_FIXTURE_RECOVERY_PROTOCOL")
	if protocol == "" {
		return "2"
	}
	return protocol
}

func main() {
	name := filepath.Base(os.Args[0])
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		version := fixtureVersion(name)
		switch name {
		case "autostream-host-agent":
			fmt.Printf(
				"autostream-host-agent %s\ncommit: %s\nbuild_date: %s\n",
				version,
				fixtureCommit,
				fixtureBuildDate,
			)
			return
		case "autostream-local-executor":
			fmt.Printf(
				"autostream-local-executor %s\ncommit: %s\nbuild_date: %s\nmutation_protocol: 2\nrecovery_protocol: %s\n",
				version,
				fixtureCommit,
				fixtureBuildDate,
				fixtureRecoveryProtocol(),
			)
			return
		}
	}
	if name != "autostream-host-agent" && name != "autostream-local-executor" {
		fmt.Fprintf(os.Stderr, "unexpected fixture executable name: %s\n", name)
		os.Exit(2)
	}
	dispatchFixtureCommand(name)
	terminated := make(chan os.Signal, 1)
	signal.Notify(terminated, syscall.SIGINT, syscall.SIGTERM)
	<-terminated
}
