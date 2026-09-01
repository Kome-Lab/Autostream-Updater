//go:build linux

package hostruntime

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	systemdPortSidecarMaxBytes = 64 << 10
	systemdPortGrantTimeout    = 30 * time.Second
)

type linuxSystemdPortRuntime struct {
	adapter          systemdPortAdapter
	hostID           string
	serviceID        string
	serviceType      string
	listenHost       string
	panelURL         string
	systemctlPath    string
	runner           CommandRunner
	httpClient       *http.Client
	consumeGrant     func(context.Context, string, string, string, MutationGrantBinding, *http.Client) error
	requireRootOwned bool
}

func newPlatformSystemdPortExecution(
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
	secured Target,
	remoteRuntime executorMutationRuntime,
) (systemdPortRuntime, systemdPortStateStore, error) {
	if runtime.GOOS != "linux" ||
		(remoteRuntime.platformOS != "" && remoteRuntime.platformOS != "linux") ||
		os.Geteuid() != 0 {
		return nil, nil, errors.New("systemd port reconfiguration requires a root Linux executor")
	}
	if err := policy.Validate(); err != nil ||
		policy.SchemaVersion != LocalExecutorMutationPolicySchemaVersion ||
		policy.ProtocolVersion != LocalExecutorMutationProtocolVersion ||
		policy.Mutation == nil ||
		target.validate() != nil ||
		target.DeploymentMode != ModeSystemd ||
		target.Systemd == nil {
		return nil, nil, errors.New("systemd port policy is invalid")
	}
	adapter, err := systemdPortAdapterFor(target.ServiceType, target.Systemd.Unit)
	if err != nil {
		return nil, nil, err
	}
	if secured.TargetID != target.ServiceID ||
		secured.HostID != policy.HostID ||
		secured.ServiceType != target.ServiceType ||
		secured.DeploymentMode != ModeSystemd ||
		secured.Systemd == nil ||
		secured.Systemd.Unit != adapter.Unit ||
		secured.HealthURL != target.runtimeTarget(policy.HostID).HealthURL ||
		secured.VersionURL != target.runtimeTarget(policy.HostID).VersionURL {
		return nil, nil, errors.New("secured systemd target does not match root policy")
	}
	if err := validateSecureRootPath(secured.Systemd.SystemctlPath, false); err != nil {
		return nil, nil, errors.New("secured systemctl executable is unavailable")
	}
	if err := validateRuntimeSystemdPortSidecarDirectory(filepath.Dir(adapter.SidecarPath), true); err != nil {
		return nil, nil, err
	}

	stateDir := LocalExecutorMutationStateDir
	requireRootState := true
	if remoteRuntime.localStateDir != "" {
		// localStateDir is an internal test hook. Production construction never
		// supplies it and always enforces root ownership for the durable ledger.
		stateDir = remoteRuntime.localStateDir
		requireRootState = false
	}
	state, err := newFileSystemdPortStateStore(stateDir, requireRootState)
	if err != nil {
		return nil, nil, err
	}
	runner := remoteRuntime.runner
	if runner == nil {
		runner = OSCommandRunner{NewProcessGroup: true}
	}
	consumeGrant := remoteRuntime.consumeGrant
	if consumeGrant == nil {
		consumeGrant = ConsumeMutationGrant
	}
	portRuntime := &linuxSystemdPortRuntime{
		adapter: adapter, hostID: policy.HostID,
		serviceID: target.ServiceID, serviceType: target.ServiceType,
		listenHost: target.LocalListen.Host, panelURL: policy.Mutation.PanelURL,
		systemctlPath: secured.Systemd.SystemctlPath,
		runner:        runner, httpClient: remoteRuntime.httpClient,
		consumeGrant: consumeGrant, requireRootOwned: true,
	}
	return portRuntime, state, nil
}

func (r *linuxSystemdPortRuntime) Checkpoint(
	adapter systemdPortAdapter,
) (systemdPortSidecarCheckpoint, error) {
	if !r.matchesAdapter(adapter) {
		return systemdPortSidecarCheckpoint{}, errors.New("systemd port adapter mismatch")
	}
	return checkpointSystemdPortSidecar(adapter.SidecarPath, r.requireRootOwned)
}

func (r *linuxSystemdPortRuntime) EnsurePortAvailable(endpoint LocalExecutorEndpoint) error {
	if endpoint.Host != r.listenHost ||
		!validLocalExecutorLoopback(endpoint.Host) ||
		!validSystemdPort(endpoint.Port) {
		return errors.New("systemd port availability endpoint is invalid")
	}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		inUse, err := procNetTCPListeningPort(table, endpoint.Port)
		if err != nil {
			return errors.New("requested systemd port availability could not be confirmed")
		}
		if inUse {
			return errors.New("requested systemd port is unavailable")
		}
	}
	return nil
}

func (r *linuxSystemdPortRuntime) ConsumeGrant(
	ctx context.Context,
	plan SystemdPortReconfigurePlan,
	operation string,
	currentVersion string,
	grant BoundedSecret,
) error {
	if err := plan.Validate(); err != nil ||
		plan.HostID != r.hostID ||
		plan.TargetID != r.serviceID ||
		plan.ServiceType != r.serviceType ||
		(operation != "port_reconfigure" && operation != "port_reconfigure_reconcile") ||
		!versionPattern.MatchString(currentVersion) ||
		!validBoundedSecret(grant.Reveal()) ||
		r.consumeGrant == nil {
		return errors.New("systemd port grant binding is invalid")
	}
	binding := MutationGrantBinding{
		LeaseGeneration: plan.LeaseGeneration,
		HostID:          plan.HostID,
		TransportMode:   HostTransportPullV2,
		TargetID:        plan.TargetID,
		ServiceType:     plan.ServiceType,
		TargetVersion:   currentVersion,
		DeploymentMode:  ModeSystemd,
		JobOperation:    "port_reconfigure",
		Operation:       operation,
		PlanSHA256:      plan.PortPlanSHA256,
		SessionID:       plan.SessionID,
		OwnershipEpoch:  plan.OwnershipEpoch,
		PolicyRevision:  plan.ExpectedUpdaterPolicyRevision,
		PortReconfigure: plan.mutationGrantBinding(),
	}
	consumeCtx, cancel := context.WithTimeout(ctx, systemdPortGrantTimeout)
	defer cancel()
	if err := r.consumeGrant(
		consumeCtx, r.panelURL, plan.JobID, grant.Reveal(), binding, r.httpClient,
	); err != nil {
		return errors.New("systemd port mutation grant rejected")
	}
	return nil
}

func (r *linuxSystemdPortRuntime) Write(
	adapter systemdPortAdapter,
	checkpoint systemdPortSidecarCheckpoint,
	body []byte,
) error {
	if !r.matchesAdapter(adapter) ||
		checkpoint.validate() != nil ||
		len(body) == 0 ||
		len(body) > systemdPortSidecarMaxBytes {
		return errors.New("systemd port sidecar write is invalid")
	}
	current, err := checkpointSystemdPortSidecar(adapter.SidecarPath, r.requireRootOwned)
	if err != nil || !sameSystemdPortCheckpoint(current, checkpoint) {
		return errors.New("systemd port sidecar changed before write")
	}
	if err := writeAtomicFile(adapter.SidecarPath, body, 0o600); err != nil {
		return errors.New("write systemd port sidecar")
	}
	written, err := checkpointSystemdPortSidecar(adapter.SidecarPath, r.requireRootOwned)
	if err != nil ||
		!written.Existed ||
		written.Mode != 0o600 ||
		written.SHA256 != systemdPortSidecarSHA256(body) ||
		string(written.Bytes) != string(body) {
		return errors.New("verify systemd port sidecar write")
	}
	return nil
}

func (r *linuxSystemdPortRuntime) Restore(
	adapter systemdPortAdapter,
	checkpoint systemdPortSidecarCheckpoint,
	targetBytes []byte,
) error {
	if !r.matchesAdapter(adapter) ||
		checkpoint.validate() != nil ||
		len(targetBytes) == 0 ||
		len(targetBytes) > systemdPortSidecarMaxBytes {
		return errors.New("systemd port sidecar restore is invalid")
	}
	current, err := checkpointSystemdPortSidecar(adapter.SidecarPath, r.requireRootOwned)
	if err != nil ||
		!current.Existed ||
		current.Mode != 0o600 ||
		current.SHA256 != systemdPortSidecarSHA256(targetBytes) ||
		string(current.Bytes) != string(targetBytes) {
		return errors.New("systemd port sidecar changed before restore")
	}
	if checkpoint.Existed {
		if checkpoint.Mode != 0o600 {
			return errors.New("systemd port checkpoint mode is invalid")
		}
		if err := writeAtomicFile(adapter.SidecarPath, checkpoint.Bytes, 0o600); err != nil {
			return errors.New("restore systemd port sidecar")
		}
	} else {
		if err := os.Remove(adapter.SidecarPath); err != nil {
			return errors.New("remove systemd port sidecar")
		}
		if err := syncDirectory(filepath.Dir(adapter.SidecarPath)); err != nil {
			return errors.New("sync systemd port sidecar directory")
		}
	}
	restored, err := checkpointSystemdPortSidecar(adapter.SidecarPath, r.requireRootOwned)
	if err != nil || !sameSystemdPortCheckpoint(restored, checkpoint) {
		return errors.New("verify systemd port sidecar restore")
	}
	return nil
}

func (r *linuxSystemdPortRuntime) Restart(
	ctx context.Context,
	target LocalExecutorTarget,
) error {
	if err := r.validateTarget(target); err != nil {
		return err
	}
	if _, err := r.runner.Run(
		ctx, "", nil, r.systemctlPath, "restart", r.adapter.Unit,
	); err != nil {
		return errors.New("restart systemd service")
	}
	return nil
}

func (r *linuxSystemdPortRuntime) Verify(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
) (string, error) {
	if err := r.validateTarget(target); err != nil ||
		policy.HostID != r.hostID ||
		policy.Validate() != nil {
		return "", errors.New("systemd port verification target is invalid")
	}
	observation, err := verifyStableLocalTarget(
		ctx,
		policy,
		target,
		linuxLocalTargetVerifier{runner: r.runner},
		r.httpClient,
	)
	if err != nil {
		switch {
		case errors.Is(err, errStableLocalTargetProcessVerification):
			return "", errors.New("systemd port process verification failed")
		case errors.Is(err, errStableLocalTargetEndpointVerification):
			return "", errors.New("systemd port endpoint verification failed")
		case errors.Is(err, errStableLocalTargetProcessChanged):
			return "", errors.New("systemd port process changed during verification")
		default:
			return "", err
		}
	}
	return observation.CurrentVersion, nil
}

func (*linuxSystemdPortRuntime) CrashPoint(string) error {
	return nil
}

func (r *linuxSystemdPortRuntime) matchesAdapter(adapter systemdPortAdapter) bool {
	return adapter == r.adapter
}

func (r *linuxSystemdPortRuntime) validateTarget(target LocalExecutorTarget) error {
	if err := target.validate(); err != nil ||
		target.ServiceID != r.serviceID ||
		target.ServiceType != r.serviceType ||
		target.DeploymentMode != ModeSystemd ||
		target.Systemd == nil ||
		target.Systemd.Unit != r.adapter.Unit ||
		target.LocalListen.Host != r.listenHost {
		return errors.New("systemd port runtime target does not match root authority")
	}
	return nil
}

func checkpointSystemdPortSidecar(
	path string,
	requireRootOwned bool,
) (systemdPortSidecarCheckpoint, error) {
	if err := validateRuntimeSystemdPortSidecarDirectory(filepath.Dir(path), requireRootOwned); err != nil {
		return systemdPortSidecarCheckpoint{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return newSystemdPortSidecarCheckpoint(false, 0, nil), nil
	}
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 ||
		info.Size() > systemdPortSidecarMaxBytes {
		return systemdPortSidecarCheckpoint{}, errors.New("systemd port sidecar is not a private bounded regular file")
	}
	if requireRootOwned {
		if !isRootOwner(info) ||
			validateRootOwnedFileAndParents(path, info, "systemd port sidecar") != nil {
			return systemdPortSidecarCheckpoint{}, errors.New("systemd port sidecar is not root-controlled")
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return systemdPortSidecarCheckpoint{}, errors.New("open systemd port sidecar")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil ||
		!opened.Mode().IsRegular() ||
		!os.SameFile(info, opened) ||
		opened.Mode() != info.Mode() ||
		opened.Size() != info.Size() ||
		!opened.ModTime().Equal(info.ModTime()) {
		return systemdPortSidecarCheckpoint{}, errors.New("systemd port sidecar changed during secure open")
	}
	body, err := io.ReadAll(io.LimitReader(file, systemdPortSidecarMaxBytes+1))
	if err != nil ||
		len(body) == 0 ||
		len(body) > systemdPortSidecarMaxBytes {
		return systemdPortSidecarCheckpoint{}, errors.New("read systemd port sidecar")
	}
	return newSystemdPortSidecarCheckpoint(
		true, uint32(opened.Mode().Perm()), body,
	), nil
}

func validateRuntimeSystemdPortSidecarDirectory(path string, requireRootOwned bool) error {
	info, err := os.Lstat(path)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm() != 0o700 {
		return errors.New("systemd port sidecar directory must be a private non-symlink directory")
	}
	if requireRootOwned {
		if !isRootOwner(info) || validateSecureRootPath(path, true) != nil {
			return errors.New("systemd port sidecar directory is not root-controlled")
		}
	}
	return nil
}

// procNetTCPListeningPort observes the host network namespace without opening
// a socket. The executor service intentionally has SocketBindDeny=any, so a
// bind-based availability probe would always fail under the production unit.
// A port is treated as occupied when any IPv4 or IPv6 address has a listening
// socket for it; the Control Panel reservation uses the same host-wide TCP
// namespace rather than allowing per-address port reuse.
func procNetTCPListeningPort(path string, port int) (bool, error) {
	if !validSystemdPort(port) {
		return false, errors.New("systemd TCP port is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, localExecutorMaxProcNetBytes+1))
	total := 0
	for {
		line, readErr := reader.ReadString('\n')
		total += len(line)
		if total > localExecutorMaxProcNetBytes {
			return false, errors.New("proc TCP table exceeds the size limit")
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[3] == "0A" {
			separator := strings.LastIndexByte(fields[1], ':')
			if separator < 1 || separator == len(fields[1])-1 {
				return false, errors.New("proc TCP listener entry is invalid")
			}
			listenerPort, err := strconv.ParseUint(fields[1][separator+1:], 16, 16)
			if err != nil {
				return false, errors.New("proc TCP listener port is invalid")
			}
			if int(listenerPort) == port {
				return true, nil
			}
		}
		if errors.Is(readErr, io.EOF) {
			return false, nil
		}
		if readErr != nil {
			return false, readErr
		}
	}
}
