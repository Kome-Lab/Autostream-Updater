package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	applicationprobe "github.com/Kome-Lab/Autostream-Updater/internal/probe"
)

const localExecutorHTTPMaxBytes = 64 << 10

type LocalProcessObservation struct {
	ServiceID            string
	ServiceType          string
	DeploymentMode       string
	CurrentVersion       string
	MainPID              int
	ListenerPID          int
	ControlGroup         string
	ListenerControlGroup string
}

type localTargetVerifier interface {
	Observe(context.Context, LocalExecutorPolicy, LocalExecutorTarget) (LocalProcessObservation, error)
}

type localDockerPortProbeVerifier interface {
	ObserveDockerPort(
		context.Context,
		LocalExecutorPolicy,
		LocalExecutorTarget,
		*http.Client,
	) (LocalExecutorDockerPortProbe, error)
}

type localExecutorAppliedPortState struct {
	systemd systemdPortAppliedStateReader
	docker  dockerPortAppliedStateReader
}

func (s localExecutorAppliedPortState) LoadApplied(
	targetID string,
) (*systemdPortAppliedState, error) {
	if s.systemd == nil {
		return nil, nil
	}
	return s.systemd.LoadApplied(targetID)
}

func (s localExecutorAppliedPortState) VerifyAppliedSidecar(
	target LocalExecutorTarget,
	applied systemdPortAppliedState,
) error {
	if verifier, ok := s.systemd.(systemdPortAppliedSidecarVerifier); ok {
		return verifier.VerifyAppliedSidecar(target, applied)
	}
	return errors.New("systemd applied port sidecar verifier is unavailable")
}

func (s localExecutorAppliedPortState) LoadDockerApplied(
	targetID string,
) (*dockerPortAppliedState, error) {
	if s.docker == nil {
		return nil, nil
	}
	return s.docker.LoadDockerApplied(targetID)
}

func (s localExecutorAppliedPortState) VerifyAppliedDockerSidecar(
	target LocalExecutorTarget,
	applied dockerPortAppliedState,
) error {
	if verifier, ok := s.docker.(dockerPortAppliedSidecarVerifier); ok {
		return verifier.VerifyAppliedDockerSidecar(target, applied)
	}
	return errors.New("Docker applied port sidecar verifier is unavailable")
}

func handleLocalExecutorRequest(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	verifier localTargetVerifier,
	httpClient *http.Client,
) LocalExecutorResponse {
	return handleLocalExecutorRequestWithSystemdState(
		ctx, policy, request, verifier, httpClient, nil,
	)
}

func handleLocalExecutorRequestWithSystemdState(
	ctx context.Context,
	policy LocalExecutorPolicy,
	request LocalExecutorRequest,
	verifier localTargetVerifier,
	httpClient *http.Client,
	systemdState systemdPortAppliedStateReader,
) LocalExecutorResponse {
	if err := request.Validate(); err != nil {
		return localExecutorFailure("invalid_request")
	}
	if err := policy.Validate(); err != nil {
		return localExecutorFailure("policy_invalid")
	}
	target, ok := policy.Target(request.ServiceID)
	if !ok {
		return localExecutorFailure("target_not_found")
	}
	if target.DeploymentMode == ModeSystemd && systemdState != nil {
		effectiveTarget, err := resolveSystemdPortAppliedTarget(
			policy, target, systemdState,
		)
		if err != nil {
			return localExecutorFailure("target_unavailable")
		}
		target = effectiveTarget
	}
	if target.DeploymentMode == ModeDocker && systemdState != nil {
		dockerState, ok := systemdState.(dockerPortAppliedStateReader)
		if !ok {
			return localExecutorFailure("target_unavailable")
		}
		effectiveTarget, err := resolveDockerPortAppliedTarget(
			policy, target, dockerState,
		)
		if err != nil {
			return localExecutorFailure("target_unavailable")
		}
		target = effectiveTarget
	}
	if verifier == nil {
		return localExecutorFailure("internal_error")
	}
	before, err := verifier.Observe(ctx, policy, target)
	if err != nil || validateLocalProcessObservation(target, before) != nil {
		return localExecutorFailure("target_unavailable")
	}
	if err := verifyLocalExecutorHTTP(ctx, target, before.CurrentVersion, httpClient); err != nil {
		return localExecutorFailure("target_unavailable")
	}
	var dockerProbe *LocalExecutorDockerPortProbe
	if target.DeploymentMode == ModeDocker &&
		target.Docker != nil &&
		target.Docker.PortEnvFile != "" {
		dockerVerifier, ok := verifier.(localDockerPortProbeVerifier)
		if !ok {
			return localExecutorFailure("target_unavailable")
		}
		observedDocker, err := dockerVerifier.ObserveDockerPort(
			ctx, policy, target, httpClient,
		)
		if err != nil || observedDocker.Validate() != nil {
			return localExecutorFailure("target_unavailable")
		}
		dockerProbe = &observedDocker
	}
	after, err := verifier.Observe(ctx, policy, target)
	if err != nil || validateLocalProcessObservation(target, after) != nil ||
		!sameLocalProcessObservation(before, after) {
		return localExecutorFailure("target_unavailable")
	}
	digest, err := policy.SHA256()
	if err != nil {
		return localExecutorFailure("internal_error")
	}
	probe := &LocalExecutorProbe{
		ServiceID:       target.ServiceID,
		ServiceType:     target.ServiceType,
		DeploymentMode:  target.DeploymentMode,
		PolicyRevision:  policy.PolicyRevision,
		PolicySHA256:    digest,
		ConfigRevision:  target.ConfigRevision,
		ConfigSHA256:    target.ConfigSHA256,
		CurrentVersion:  after.CurrentVersion,
		MainPID:         after.MainPID,
		ListenerPID:     after.ListenerPID,
		ControlGroup:    after.ControlGroup,
		ListenerAddress: target.LocalListen.address(),
		Docker:          dockerProbe,
	}
	response := LocalExecutorResponse{Version: LocalExecutorProtocolVersion, Probe: probe}
	if err := response.Validate(); err != nil {
		return localExecutorFailure("target_unavailable")
	}
	return response
}

var (
	errStableLocalTargetProcessVerification  = errors.New("local target process verification failed")
	errStableLocalTargetEndpointVerification = errors.New("local target endpoint verification failed")
	errStableLocalTargetProcessChanged       = errors.New("local target process changed during verification")
)

// verifyStableLocalTarget binds a direct HTTP identity probe to the exact
// managed process, listener, cgroup, and version observed on both sides of the
// request. Callers that mutate adjacent durable state can retain the returned
// observation and require it to remain byte-for-byte stable afterwards.
func verifyStableLocalTarget(
	ctx context.Context,
	policy LocalExecutorPolicy,
	target LocalExecutorTarget,
	verifier localTargetVerifier,
	httpClient *http.Client,
) (LocalProcessObservation, error) {
	if verifier == nil || policy.Validate() != nil || target.validate() != nil {
		return LocalProcessObservation{}, errors.New("local target verification authority is invalid")
	}
	before, err := verifier.Observe(ctx, policy, target)
	if err != nil || validateLocalProcessObservation(target, before) != nil {
		return LocalProcessObservation{}, errStableLocalTargetProcessVerification
	}
	if err := verifyLocalExecutorHTTP(
		ctx,
		target,
		before.CurrentVersion,
		httpClient,
	); err != nil {
		return LocalProcessObservation{}, errStableLocalTargetEndpointVerification
	}
	after, err := verifier.Observe(ctx, policy, target)
	if err != nil ||
		validateLocalProcessObservation(target, after) != nil ||
		!sameLocalProcessObservation(before, after) {
		return LocalProcessObservation{}, errStableLocalTargetProcessChanged
	}
	return after, nil
}

func validateLocalProcessObservation(target LocalExecutorTarget, observation LocalProcessObservation) error {
	if observation.ServiceID != target.ServiceID ||
		observation.ServiceType != target.ServiceType ||
		observation.DeploymentMode != target.DeploymentMode {
		return errors.New("observed service identity does not match policy")
	}
	if !versionPattern.MatchString(strings.TrimSpace(observation.CurrentVersion)) {
		return errors.New("observed version is invalid")
	}
	if observation.MainPID < 1 || observation.ListenerPID < 1 ||
		!validLocalExecutorCgroup(observation.ControlGroup) ||
		observation.ListenerControlGroup != observation.ControlGroup {
		return errors.New("observed process ownership is invalid")
	}
	return nil
}

func sameLocalProcessObservation(left, right LocalProcessObservation) bool {
	return left == right
}

func validLocalExecutorCgroup(value string) bool {
	if len(value) < 2 || len(value) > 4096 || !strings.HasPrefix(value, "/") ||
		path.Clean(value) != value || value == "/" {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func verifyLocalExecutorHTTP(ctx context.Context, target LocalExecutorTarget, baseline string, baseClient *http.Client) error {
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := http.Client{}
	if baseClient != nil {
		client.Timeout = baseClient.Timeout
	}
	if client.Timeout <= 0 || client.Timeout > 3*time.Second {
		client.Timeout = 3 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: client.Timeout}
	dialAddress := target.LocalListen.address()
	transport.DialContext = func(dialCtx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(dialCtx, "tcp", dialAddress)
	}
	client.Transport = transport
	defer transport.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	base := "http://" + target.LocalListen.address()
	if err := fetchLocalHealth(checkCtx, &client, base+"/health", target); err != nil {
		return err
	}
	version, err := fetchLocalVersion(checkCtx, &client, base+"/updater/version", target)
	if err != nil {
		return err
	}
	if !versionsEqual(version, baseline) {
		return errors.New("endpoint version does not match managed runtime")
	}
	return nil
}

func fetchLocalHealth(ctx context.Context, client *http.Client, endpoint string, target LocalExecutorTarget) error {
	var body struct {
		Status      string `json:"status"`
		Service     string `json:"service,omitempty"`
		ServiceID   string `json:"service_id,omitempty"`
		ServiceType string `json:"service_type,omitempty"`
	}
	if err := fetchStrictLocalJSON(ctx, client, endpoint, &body, "health"); err != nil {
		return err
	}
	if body.Status != "ok" {
		return errors.New("health endpoint is not healthy")
	}
	if body.ServiceID != "" && body.ServiceID != target.ServiceID {
		return errors.New("health endpoint service identity mismatch")
	}
	if body.ServiceType != "" && body.ServiceType != target.ServiceType {
		return errors.New("health endpoint service type mismatch")
	}
	return nil
}

func fetchLocalVersion(ctx context.Context, client *http.Client, endpoint string, target LocalExecutorTarget) (string, error) {
	identity, err := (applicationprobe.Client{HTTP: client}).FetchApplicationIdentity(
		ctx,
		endpoint,
		applicationprobe.ExpectedIdentity{
			ServiceID: target.ServiceID, ServiceType: target.ServiceType,
			ConfigRevision: target.ConfigRevision,
		},
	)
	if err != nil {
		return "", err
	}
	return identity.Version, nil
}

func fetchStrictLocalJSON(ctx context.Context, client *http.Client, endpoint string, out any, label string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create %s request", label)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("fetch %s endpoint", label)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, localExecutorHTTPMaxBytes))
		return fmt.Errorf("%s endpoint returned HTTP %d", label, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, localExecutorHTTPMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > localExecutorHTTPMaxBytes {
		return fmt.Errorf("%s endpoint returned an invalid bounded response", label)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("%s endpoint returned invalid JSON", label)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s endpoint returned trailing data", label)
	}
	return nil
}
