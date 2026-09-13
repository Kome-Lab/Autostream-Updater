//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
)

type hostSelfUpdateExecutorTestDownloader struct {
	release HostAgentRelease
}

func (d hostSelfUpdateExecutorTestDownloader) DownloadHostAgentRelease(
	context.Context,
	string,
	string,
	string,
) (HostAgentRelease, error) {
	return d.release, nil
}

type hostSelfUpdateExecutorTestRunner struct {
	version          string
	commit           string
	binaryIdentities map[string]hostSelfUpdateExecutorTestBinaryIdentity
	restarts         int
	executorRestarts int
	restartOrder     []string
	failExecutor     bool
	serviceActive    bool
	socketActive     bool
	serviceChecks    int
	failServiceAfter int
	mainPID          string
	secondMainPID    string
	mainPIDChecks    int
	runningExe       string
	mutationProtocol int
	recoveryProtocol int
}

type hostSelfUpdateExecutorTestBinaryIdentity struct {
	version          string
	commit           string
	mutationProtocol int
	recoveryProtocol int
}

func (r *hostSelfUpdateExecutorTestRunner) Run(
	_ context.Context,
	_ string,
	_ []string,
	name string,
	args ...string,
) (string, error) {
	if name == "/usr/bin/systemctl" {
		switch {
		case len(args) == 2 &&
			args[0] == "restart" &&
			args[1] == hostSelfUpdateServiceUnit:
			r.restarts++
			r.restartOrder = append(r.restartOrder, args[1])
			return "", nil
		case len(args) == 2 &&
			args[0] == "restart" &&
			args[1] == hostSelfUpdateExecutorServiceUnit:
			r.executorRestarts++
			r.restartOrder = append(r.restartOrder, args[1])
			if r.failExecutor {
				return "", errors.New("injected Local Executor restart failure")
			}
			return "", nil
		case len(args) == 3 &&
			args[0] == "is-active" &&
			args[1] == "--quiet" &&
			(args[2] == hostSelfUpdateExecutorServiceUnit ||
				args[2] == hostSelfUpdateExecutorSocketUnit):
			if args[2] == hostSelfUpdateExecutorSocketUnit {
				if !r.socketActive {
					return "", errors.New(
						"injected inactive Local Executor socket",
					)
				}
				return "", nil
			}
			r.serviceChecks++
			if !r.serviceActive ||
				(r.failServiceAfter > 0 &&
					r.serviceChecks > r.failServiceAfter) {
				return "", errors.New("injected inactive Local Executor")
			}
			return "", nil
		case len(args) == 4 &&
			args[0] == "show" &&
			args[1] == "--property=MainPID" &&
			args[2] == "--value" &&
			args[3] == hostSelfUpdateExecutorServiceUnit:
			r.mainPIDChecks++
			if r.mainPIDChecks > 1 && r.secondMainPID != "" {
				return r.secondMainPID + "\n", nil
			}
			return r.mainPID + "\n", nil
		}
		return "", errHostSelfUpdatePrecondition
	}
	version := r.version
	commit := r.commit
	mutationProtocol := r.mutationProtocol
	recoveryProtocol := r.recoveryProtocol
	if identity, ok := r.binaryIdentities[filepath.Clean(name)]; ok {
		version = identity.version
		commit = identity.commit
		mutationProtocol = identity.mutationProtocol
		recoveryProtocol = identity.recoveryProtocol
	}
	if mutationProtocol == 0 {
		mutationProtocol = LocalExecutorMutationProtocolVersion
	}
	if recoveryProtocol == 0 {
		recoveryProtocol = HostSelfUpdateRecoveryProtocolVersion
	}
	return filepath.Base(name) + " " + version +
		"\ncommit: " + commit + "\nbuild_date: test\n" +
		"mutation_protocol: " +
		strconv.Itoa(mutationProtocol) + "\n" +
		"recovery_protocol: " +
		strconv.Itoa(recoveryProtocol) + "\n", nil
}

func (r *hostSelfUpdateExecutorTestRunner) registerBinaryIdentity(
	path string,
	identity hostSelfUpdateExecutorTestBinaryIdentity,
) {
	if r.binaryIdentities == nil {
		r.binaryIdentities =
			make(map[string]hostSelfUpdateExecutorTestBinaryIdentity)
	}
	r.binaryIdentities[filepath.Clean(path)] = identity
}
