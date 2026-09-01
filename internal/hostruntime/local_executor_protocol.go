package hostruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	LocalExecutorProtocolVersion         = 1
	LocalExecutorMutationProtocolVersion = 2
	LocalExecutorProtocolMaxFrameBytes   = 64 << 10

	localExecutorHostSelfUpdateWatchdogOperation = "host_self_update_watchdog_status"
	localExecutorHostSelfUpdateWatchdogServiceID = "host-self-update-watchdog"
)

// LocalExecutorRequest intentionally has no generic arguments, paths,
// commands, units, URLs, or images. Privileged inputs are resolved exclusively
// from the root-owned local executor policy. Mutation requests carry only an
// immutable, digest-bound MutationPlan and short-lived bearer credentials.
type LocalExecutorRequest struct {
	Version                  int                               `json:"version"`
	Operation                string                            `json:"operation"`
	ServiceID                string                            `json:"service_id"`
	Plan                     *MutationPlan                     `json:"plan,omitempty"`
	PortPlan                 *SystemdPortReconfigurePlan       `json:"port_plan,omitempty"`
	HostSelfUpdate           *HostSelfUpdateRequest            `json:"host_self_update,omitempty"`
	HostSelfUpdateProof      *HostSelfUpdateAgentProof         `json:"host_self_update_proof,omitempty"`
	HostSelfUpdateGeneration string                            `json:"host_self_update_generation,omitempty"`
	HostSelfUpdateGrant      *HostSelfUpdateGrantAuthorization `json:"host_self_update_grant,omitempty"`
	RuntimeCredential        *RuntimeCredentialMutation        `json:"runtime_credential,omitempty"`
	SourcePolicyRevision     int64                             `json:"source_policy_revision,omitempty"`
	OwnershipEpoch           int64                             `json:"ownership_epoch,omitempty"`
	OwnershipPolicyRevision  int64                             `json:"ownership_policy_revision,omitempty"`
	ExecutorPolicyRevision   int64                             `json:"executor_policy_revision,omitempty"`
	MutationGrant            BoundedSecret                     `json:"mutation_grant,omitempty"`
}

func (r LocalExecutorRequest) Validate() error {
	if r.ServiceID != strings.TrimSpace(r.ServiceID) || !identifierPattern.MatchString(r.ServiceID) {
		return errors.New("local executor service_id is invalid")
	}
	if !strings.HasPrefix(r.Operation, "host_self_update_") &&
		r.HostSelfUpdateGrant != nil {
		return errors.New("local executor operation must not include a host self-update grant")
	}
	switch r.Operation {
	case "probe":
		if r.Version != LocalExecutorProtocolVersion ||
			r.Plan != nil ||
			r.PortPlan != nil ||
			r.HostSelfUpdate != nil ||
			r.HostSelfUpdateProof != nil ||
			r.HostSelfUpdateGeneration != "" ||
			r.RuntimeCredential != nil ||
			r.SourcePolicyRevision != 0 ||
			r.OwnershipEpoch != 0 ||
			r.OwnershipPolicyRevision != 0 ||
			r.ExecutorPolicyRevision != 0 ||
			!r.MutationGrant.Empty() {
			return errors.New("local executor probe request is invalid")
		}
		return nil
	case "stage", "apply", "reconcile":
		if r.Version != LocalExecutorMutationProtocolVersion ||
			r.Plan == nil ||
			r.PortPlan != nil ||
			r.HostSelfUpdate != nil ||
			r.HostSelfUpdateProof != nil ||
			r.HostSelfUpdateGeneration != "" ||
			r.RuntimeCredential != nil ||
			r.Plan.TargetID != r.ServiceID ||
			r.SourcePolicyRevision < 1 ||
			r.OwnershipEpoch < 1 ||
			r.OwnershipPolicyRevision < 1 ||
			r.ExecutorPolicyRevision < 1 {
			return errors.New("local executor mutation binding is invalid")
		}
		if err := r.Plan.Validate(); err != nil {
			return err
		}
		if r.Operation == "stage" {
			if !r.MutationGrant.Empty() {
				return errors.New("local executor stage must not include a credential")
			}
			return nil
		}
		if !validBoundedSecret(r.MutationGrant.Reveal()) {
			return errors.New("local executor mutation requires only its short-lived mutation grant")
		}
		return nil
	case "port_reconfigure", "port_reconfigure_reconcile":
		if r.Version != LocalExecutorMutationProtocolVersion ||
			r.Plan != nil ||
			r.PortPlan == nil ||
			r.HostSelfUpdate != nil ||
			r.HostSelfUpdateProof != nil ||
			r.HostSelfUpdateGeneration != "" ||
			r.RuntimeCredential != nil ||
			r.PortPlan.TargetID != r.ServiceID ||
			r.SourcePolicyRevision != r.PortPlan.ExpectedSourcePolicyRevision ||
			r.OwnershipEpoch != r.PortPlan.OwnershipEpoch ||
			r.OwnershipPolicyRevision != r.PortPlan.ExpectedUpdaterPolicyRevision ||
			r.ExecutorPolicyRevision != r.PortPlan.ExpectedExecutorPolicyRevision ||
			!validBoundedSecret(r.MutationGrant.Reveal()) {
			return errors.New("local executor port mutation binding is invalid")
		}
		return r.PortPlan.Validate()
	case localExecutorHostSelfUpdateWatchdogOperation:
		if r.Version != LocalExecutorMutationProtocolVersion ||
			r.ServiceID != localExecutorHostSelfUpdateWatchdogServiceID ||
			r.Plan != nil ||
			r.PortPlan != nil ||
			r.HostSelfUpdate != nil ||
			r.HostSelfUpdateProof != nil ||
			r.HostSelfUpdateGeneration != "" ||
			r.HostSelfUpdateGrant != nil ||
			r.RuntimeCredential != nil ||
			r.SourcePolicyRevision != 0 ||
			r.OwnershipEpoch != 0 ||
			r.OwnershipPolicyRevision != 0 ||
			r.ExecutorPolicyRevision != 0 ||
			!r.MutationGrant.Empty() {
			return errors.New(
				"local executor host self-update watchdog status request is invalid",
			)
		}
		return nil
	case "host_self_update_status", "host_self_update_stage",
		"host_self_update_activate", "host_self_update_reconcile":
		if r.Version != LocalExecutorMutationProtocolVersion ||
			r.Plan != nil ||
			r.PortPlan != nil ||
			r.RuntimeCredential != nil ||
			r.SourcePolicyRevision < 1 ||
			r.OwnershipEpoch < 1 ||
			r.OwnershipPolicyRevision < 1 ||
			r.ExecutorPolicyRevision < 1 ||
			!r.MutationGrant.Empty() {
			return errors.New("local executor host self-update binding is invalid")
		}
		switch r.Operation {
		case "host_self_update_status":
			if r.HostSelfUpdate != nil ||
				r.HostSelfUpdateProof != nil ||
				r.HostSelfUpdateGeneration != "" ||
				r.HostSelfUpdateGrant != nil {
				return errors.New("local executor host self-update status request is invalid")
			}
		case "host_self_update_stage":
			if r.HostSelfUpdate == nil ||
				r.HostSelfUpdateProof != nil ||
				r.HostSelfUpdateGeneration != "" ||
				r.HostSelfUpdateGrant == nil {
				return errors.New("local executor host self-update stage request is invalid")
			}
			if err := r.HostSelfUpdate.validate(); err != nil {
				return err
			}
			if err := r.HostSelfUpdateGrant.validate(); err != nil ||
				r.HostSelfUpdateGrant.Binding.Operation != "stage" {
				return errors.New("local executor host self-update stage grant is invalid")
			}
		case "host_self_update_activate":
			if r.HostSelfUpdate != nil ||
				r.HostSelfUpdateProof != nil ||
				r.HostSelfUpdateGrant != nil ||
				!identifierPattern.MatchString(r.HostSelfUpdateGeneration) ||
				r.HostSelfUpdateGeneration != strings.TrimSpace(r.HostSelfUpdateGeneration) {
				return errors.New("local executor host self-update activation request is invalid")
			}
		case "host_self_update_reconcile":
			if r.HostSelfUpdate != nil ||
				r.HostSelfUpdateProof == nil ||
				r.HostSelfUpdateGeneration != "" {
				return errors.New("local executor host self-update reconcile request is invalid")
			}
			if err := r.HostSelfUpdateProof.validate(); err != nil {
				return err
			}
			if r.HostSelfUpdateGrant == nil {
				if *r.HostSelfUpdateProof != (HostSelfUpdateAgentProof{}) {
					return errors.New("local executor host self-update reconcile grant is required")
				}
			} else if err := r.HostSelfUpdateGrant.validate(); err != nil ||
				r.HostSelfUpdateGrant.Binding.Operation != "reconcile" {
				return errors.New("local executor host self-update reconcile grant is invalid")
			}
		}
		return nil
	case "runtime_credential_status":
		if r.Version != LocalExecutorMutationProtocolVersion ||
			r.Plan != nil ||
			r.PortPlan != nil ||
			r.HostSelfUpdate != nil ||
			r.HostSelfUpdateProof != nil ||
			r.HostSelfUpdateGeneration != "" ||
			r.RuntimeCredential != nil ||
			r.SourcePolicyRevision != 0 ||
			r.OwnershipEpoch != 0 ||
			r.OwnershipPolicyRevision != 0 ||
			r.ExecutorPolicyRevision != 0 ||
			!r.MutationGrant.Empty() {
			return errors.New("local executor runtime credential status request is invalid")
		}
		return nil
	case "runtime_credential_prepare", "runtime_credential_stage",
		"runtime_credential_proof_ready",
		"runtime_credential_activate", "runtime_credential_cancel",
		"runtime_credential_finalize":
		if r.Version != LocalExecutorMutationProtocolVersion ||
			r.Plan != nil ||
			r.PortPlan != nil ||
			r.HostSelfUpdate != nil ||
			r.HostSelfUpdateProof != nil ||
			r.HostSelfUpdateGeneration != "" ||
			r.RuntimeCredential == nil ||
			r.SourcePolicyRevision < 1 ||
			r.OwnershipEpoch < 1 ||
			r.OwnershipPolicyRevision < 1 ||
			r.ExecutorPolicyRevision < 1 ||
			!r.MutationGrant.Empty() {
			return errors.New("local executor runtime credential binding is invalid")
		}
		return r.RuntimeCredential.validate(r.Operation)
	default:
		return errors.New("unsupported local executor operation")
	}
}

type LocalExecutorProbe struct {
	ServiceID       string                        `json:"service_id"`
	ServiceType     string                        `json:"service_type"`
	DeploymentMode  string                        `json:"deployment_mode"`
	PolicyRevision  int64                         `json:"policy_revision"`
	PolicySHA256    string                        `json:"policy_sha256"`
	ConfigRevision  int64                         `json:"config_revision"`
	ConfigSHA256    string                        `json:"config_sha256,omitempty"`
	CurrentVersion  string                        `json:"current_version"`
	MainPID         int                           `json:"main_pid"`
	ListenerPID     int                           `json:"listener_pid"`
	ControlGroup    string                        `json:"control_group"`
	ListenerAddress string                        `json:"listener_address"`
	Docker          *LocalExecutorDockerPortProbe `json:"docker,omitempty"`
}

type LocalExecutorDockerPortProbe struct {
	CapabilityVersion   string `json:"capability_version"`
	PublishedPort       int    `json:"published_port"`
	ContainerPort       int    `json:"container_port"`
	HealthPort          int    `json:"health_port"`
	ComposePolicySHA256 string `json:"compose_policy_sha256"`
	ComposeConfigSHA256 string `json:"compose_config_sha256"`
	ComposeRevision     int64  `json:"compose_revision"`
	VersionEnvSHA256    string `json:"version_env_sha256"`
	ContainerID         string `json:"container_id"`
	ImageID             string `json:"image_id"`
	RepositoryDigest    string `json:"repository_digest"`
}

func (p LocalExecutorDockerPortProbe) Validate() error {
	if p.CapabilityVersion != dockerPortCapabilityVersion ||
		!validSystemdPort(p.PublishedPort) ||
		!validSystemdPort(p.ContainerPort) ||
		p.HealthPort != p.PublishedPort ||
		!mutationPlanHashPattern.MatchString(p.ComposePolicySHA256) ||
		!mutationPlanHashPattern.MatchString(p.ComposeConfigSHA256) ||
		p.ComposeRevision < 1 ||
		!digestPattern.MatchString(p.VersionEnvSHA256) ||
		len(p.ContainerID) != 64 ||
		!dockerContainerIDPattern.MatchString(p.ContainerID) ||
		!digestPattern.MatchString(p.ImageID) ||
		!digestPattern.MatchString(p.RepositoryDigest) {
		return errors.New("local executor Docker port probe is invalid")
	}
	return nil
}

func (p LocalExecutorProbe) Validate() error {
	if !identifierPattern.MatchString(p.ServiceID) || !validLocalExecutorServiceType(p.ServiceType) {
		return errors.New("local executor probe identity is invalid")
	}
	if p.DeploymentMode != ModeSystemd && p.DeploymentMode != ModeDocker {
		return errors.New("local executor probe deployment mode is invalid")
	}
	if p.DeploymentMode == ModeSystemd && p.Docker != nil {
		return errors.New("systemd local executor probe contains Docker-only state")
	}
	if p.Docker != nil && p.Docker.Validate() != nil {
		return errors.New("local executor Docker port probe is invalid")
	}
	if p.PolicyRevision < 1 ||
		!digestPattern.MatchString(p.PolicySHA256) ||
		p.ConfigRevision < 1 ||
		(p.ConfigSHA256 != "" && !digestPattern.MatchString(p.ConfigSHA256)) {
		return errors.New("local executor probe policy binding is invalid")
	}
	if !versionPattern.MatchString(strings.TrimSpace(p.CurrentVersion)) || p.MainPID < 1 || p.ListenerPID < 1 {
		return errors.New("local executor probe runtime identity is invalid")
	}
	if !validLocalExecutorCgroup(p.ControlGroup) {
		return errors.New("local executor probe cgroup is invalid")
	}
	host, portText, err := net.SplitHostPort(p.ListenerAddress)
	if err != nil || !validLocalExecutorLoopback(host) {
		return errors.New("local executor probe listener address is invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1024 || port > 65535 {
		return errors.New("local executor probe listener address is invalid")
	}
	return nil
}

type LocalExecutorFailure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type LocalExecutorResponse struct {
	Version           int                           `json:"version"`
	Probe             *LocalExecutorProbe           `json:"probe,omitempty"`
	Stage             *MutationStageResult          `json:"stage,omitempty"`
	Result            *ApplyResult                  `json:"result,omitempty"`
	PortResult        *SystemdPortReconfigureResult `json:"port_result,omitempty"`
	HostSelfUpdate    *HostSelfUpdateRuntimeStatus  `json:"host_self_update,omitempty"`
	RuntimeCredential *RuntimeCredentialStatus      `json:"runtime_credential,omitempty"`
	SessionID         string                        `json:"session_id,omitempty"`
	PlanSHA256        string                        `json:"plan_sha256,omitempty"`
	Error             *LocalExecutorFailure         `json:"error,omitempty"`
}

func (r LocalExecutorResponse) Validate() error {
	if r.Version != LocalExecutorProtocolVersion && r.Version != LocalExecutorMutationProtocolVersion {
		return errors.New("unsupported local executor response version")
	}
	outcomes := 0
	if r.Probe != nil {
		outcomes++
	}
	if r.Stage != nil {
		outcomes++
	}
	if r.Result != nil {
		outcomes++
	}
	if r.PortResult != nil {
		outcomes++
	}
	if r.HostSelfUpdate != nil {
		outcomes++
	}
	if r.RuntimeCredential != nil {
		outcomes++
	}
	if r.Error != nil {
		outcomes++
	}
	if outcomes != 1 {
		return errors.New("local executor response must contain exactly one outcome")
	}
	if r.Probe != nil {
		if r.Version != LocalExecutorProtocolVersion || r.SessionID != "" || r.PlanSHA256 != "" {
			return errors.New("local executor probe response binding is invalid")
		}
		return r.Probe.Validate()
	}
	if r.Stage != nil {
		if r.Version != LocalExecutorMutationProtocolVersion || r.SessionID != "" || r.PlanSHA256 != "" {
			return errors.New("local executor stage response binding is invalid")
		}
		return r.Stage.Validate()
	}
	if r.Result != nil {
		if r.Version != LocalExecutorMutationProtocolVersion ||
			!mutationSessionPattern.MatchString(r.SessionID) ||
			!mutationPlanHashPattern.MatchString(r.PlanSHA256) ||
			(r.Result.Status != "succeeded" && r.Result.Status != "rolled_back") ||
			(r.Result.ArtifactDigest != "" && !digestPattern.MatchString(normalizeDigest(r.Result.ArtifactDigest))) ||
			(r.Result.PreviousDigest != "" && !digestPattern.MatchString(normalizeDigest(r.Result.PreviousDigest))) ||
			(r.Result.Message != "" && !safeExecutorMessage(r.Result.Message)) {
			return errors.New("local executor mutation result is invalid")
		}
		return nil
	}
	if r.PortResult != nil {
		if r.Version != LocalExecutorMutationProtocolVersion ||
			!mutationSessionPattern.MatchString(r.SessionID) ||
			!mutationPlanHashPattern.MatchString(r.PlanSHA256) {
			return errors.New("local executor port mutation result binding is invalid")
		}
		return r.PortResult.Validate()
	}
	if r.HostSelfUpdate != nil {
		if r.Version != LocalExecutorMutationProtocolVersion ||
			r.SessionID != "" || r.PlanSHA256 != "" {
			return errors.New("local executor host self-update response binding is invalid")
		}
		return r.HostSelfUpdate.validate()
	}
	if r.RuntimeCredential != nil {
		if r.Version != LocalExecutorMutationProtocolVersion ||
			r.SessionID != "" || r.PlanSHA256 != "" {
			return errors.New("local executor runtime credential response binding is invalid")
		}
		return r.RuntimeCredential.Validate()
	}
	if r.SessionID != "" || r.PlanSHA256 != "" {
		return errors.New("local executor failure response binding is invalid")
	}
	if !validLocalExecutorFailureCode(r.Error.Code) || !safeExecutorMessage(r.Error.Message) {
		return errors.New("local executor failure is invalid")
	}
	return nil
}

func EncodeLocalExecutorRequest(w io.Writer, request LocalExecutorRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	wire := localExecutorRequestWire{
		Version: request.Version, Operation: request.Operation, ServiceID: request.ServiceID,
		Plan: request.Plan, PortPlan: request.PortPlan,
		HostSelfUpdate:           request.HostSelfUpdate,
		HostSelfUpdateProof:      request.HostSelfUpdateProof,
		HostSelfUpdateGeneration: request.HostSelfUpdateGeneration,
		HostSelfUpdateGrant:      hostSelfUpdateGrantAuthorizationToWire(request.HostSelfUpdateGrant),
		RuntimeCredential:        runtimeCredentialMutationToWire(request.RuntimeCredential),
		SourcePolicyRevision:     request.SourcePolicyRevision,
		OwnershipEpoch:           request.OwnershipEpoch,
		OwnershipPolicyRevision:  request.OwnershipPolicyRevision,
		ExecutorPolicyRevision:   request.ExecutorPolicyRevision,
		MutationGrant:            request.MutationGrant.Reveal(),
	}
	return encodeLocalExecutorFrame(w, wire, "request")
}

func DecodeLocalExecutorRequest(r io.Reader) (LocalExecutorRequest, error) {
	var wire localExecutorRequestWire
	if err := decodeLocalExecutorFrame(r, &wire, "request"); err != nil {
		return LocalExecutorRequest{}, err
	}
	request := LocalExecutorRequest{
		Version: wire.Version, Operation: wire.Operation, ServiceID: wire.ServiceID,
		Plan: wire.Plan, PortPlan: wire.PortPlan,
		HostSelfUpdate:           wire.HostSelfUpdate,
		HostSelfUpdateProof:      wire.HostSelfUpdateProof,
		HostSelfUpdateGeneration: wire.HostSelfUpdateGeneration,
		HostSelfUpdateGrant:      hostSelfUpdateGrantAuthorizationFromWire(wire.HostSelfUpdateGrant),
		RuntimeCredential:        runtimeCredentialMutationFromWire(wire.RuntimeCredential),
		SourcePolicyRevision:     wire.SourcePolicyRevision,
		OwnershipEpoch:           wire.OwnershipEpoch,
		OwnershipPolicyRevision:  wire.OwnershipPolicyRevision,
		ExecutorPolicyRevision:   wire.ExecutorPolicyRevision,
		MutationGrant:            NewBoundedSecret(wire.MutationGrant),
	}
	if err := request.Validate(); err != nil {
		return LocalExecutorRequest{}, err
	}
	return request, nil
}

type localExecutorRequestWire struct {
	Version                  int                                   `json:"version"`
	Operation                string                                `json:"operation"`
	ServiceID                string                                `json:"service_id"`
	Plan                     *MutationPlan                         `json:"plan,omitempty"`
	PortPlan                 *SystemdPortReconfigurePlan           `json:"port_plan,omitempty"`
	HostSelfUpdate           *HostSelfUpdateRequest                `json:"host_self_update,omitempty"`
	HostSelfUpdateProof      *HostSelfUpdateAgentProof             `json:"host_self_update_proof,omitempty"`
	HostSelfUpdateGeneration string                                `json:"host_self_update_generation,omitempty"`
	HostSelfUpdateGrant      *hostSelfUpdateGrantAuthorizationWire `json:"host_self_update_grant,omitempty"`
	RuntimeCredential        *runtimeCredentialMutationWire        `json:"runtime_credential,omitempty"`
	SourcePolicyRevision     int64                                 `json:"source_policy_revision,omitempty"`
	OwnershipEpoch           int64                                 `json:"ownership_epoch,omitempty"`
	OwnershipPolicyRevision  int64                                 `json:"ownership_policy_revision,omitempty"`
	ExecutorPolicyRevision   int64                                 `json:"executor_policy_revision,omitempty"`
	MutationGrant            string                                `json:"mutation_grant,omitempty"`
}

type hostSelfUpdateGrantAuthorizationWire struct {
	Binding HostSelfUpdateGrantBinding `json:"binding"`
	Token   string                     `json:"token"`
}

func hostSelfUpdateGrantAuthorizationToWire(
	authorization *HostSelfUpdateGrantAuthorization,
) *hostSelfUpdateGrantAuthorizationWire {
	if authorization == nil {
		return nil
	}
	return &hostSelfUpdateGrantAuthorizationWire{
		Binding: authorization.Binding,
		Token:   authorization.Token.Reveal(),
	}
}

func hostSelfUpdateGrantAuthorizationFromWire(
	wire *hostSelfUpdateGrantAuthorizationWire,
) *HostSelfUpdateGrantAuthorization {
	if wire == nil {
		return nil
	}
	return &HostSelfUpdateGrantAuthorization{
		Binding: wire.Binding,
		Token:   NewBoundedSecret(wire.Token),
	}
}

type runtimeCredentialMutationWire struct {
	RotationID       string `json:"rotation_id"`
	ExecutionHostID  string `json:"execution_host_id"`
	PreviousTokenID  string `json:"previous_token_id"`
	StagedTokenID    string `json:"staged_token_id"`
	RotationRevision int64  `json:"rotation_revision"`
	RuntimeToken     string `json:"runtime_token,omitempty"`
}

func runtimeCredentialMutationToWire(
	mutation *RuntimeCredentialMutation,
) *runtimeCredentialMutationWire {
	if mutation == nil {
		return nil
	}
	return &runtimeCredentialMutationWire{
		RotationID:       mutation.RotationID,
		ExecutionHostID:  mutation.ExecutionHostID,
		PreviousTokenID:  mutation.PreviousTokenID,
		StagedTokenID:    mutation.StagedTokenID,
		RotationRevision: mutation.RotationRevision,
		RuntimeToken:     mutation.RuntimeToken.Reveal(),
	}
}

func runtimeCredentialMutationFromWire(
	wire *runtimeCredentialMutationWire,
) *RuntimeCredentialMutation {
	if wire == nil {
		return nil
	}
	return &RuntimeCredentialMutation{
		RotationID:       wire.RotationID,
		ExecutionHostID:  wire.ExecutionHostID,
		PreviousTokenID:  wire.PreviousTokenID,
		StagedTokenID:    wire.StagedTokenID,
		RotationRevision: wire.RotationRevision,
		RuntimeToken:     NewBoundedSecret(wire.RuntimeToken),
	}
}

func EncodeLocalExecutorResponse(w io.Writer, response LocalExecutorResponse) error {
	if err := response.Validate(); err != nil {
		return err
	}
	return encodeLocalExecutorFrame(w, response, "response")
}

func DecodeLocalExecutorResponse(r io.Reader) (LocalExecutorResponse, error) {
	var response LocalExecutorResponse
	if err := decodeLocalExecutorFrame(r, &response, "response"); err != nil {
		return LocalExecutorResponse{}, err
	}
	if err := response.Validate(); err != nil {
		return LocalExecutorResponse{}, err
	}
	return response, nil
}

func encodeLocalExecutorFrame(w io.Writer, value any, kind string) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode local executor %s", kind)
	}
	if len(payload)+1 > LocalExecutorProtocolMaxFrameBytes {
		return fmt.Errorf("local executor %s exceeds the size limit", kind)
	}
	payload = append(payload, '\n')
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write local executor %s: %w", kind, err)
	}
	return nil
}

func decodeLocalExecutorFrame(r io.Reader, out any, kind string) error {
	data, err := io.ReadAll(io.LimitReader(r, LocalExecutorProtocolMaxFrameBytes+1))
	if err != nil {
		return fmt.Errorf("read local executor %s: %w", kind, err)
	}
	if len(data) == 0 || len(data) > LocalExecutorProtocolMaxFrameBytes {
		return fmt.Errorf("local executor %s is empty or exceeds the size limit", kind)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode local executor %s", kind)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("local executor %s contains trailing data", kind)
	}
	return nil
}

func validLocalExecutorFailureCode(code string) bool {
	switch code {
	case "invalid_request", "target_not_found", "target_unavailable", "policy_invalid",
		"config_mismatch", "state_unavailable", "state_invalid", "target_busy",
		"stage_failed", "stage_required", "stage_invalid", "plan_conflict",
		"reconcile_required", "already_terminal", "mutation_precondition_failed",
		"authorization_failed", "authorization_uncertain", "rollback_failed",
		"internal_error":
		return true
	default:
		return false
	}
}

func localExecutorFailure(code string) LocalExecutorResponse {
	return localExecutorFailureForVersion(LocalExecutorProtocolVersion, code)
}

func localExecutorFailureForVersion(version int, code string) LocalExecutorResponse {
	if version != LocalExecutorProtocolVersion && version != LocalExecutorMutationProtocolVersion {
		version = LocalExecutorProtocolVersion
	}
	message := map[string]string{
		"invalid_request":              "request rejected",
		"target_not_found":             "target not found",
		"target_unavailable":           "target unavailable",
		"policy_invalid":               "policy rejected",
		"config_mismatch":              "request does not match the root policy",
		"state_unavailable":            "durable executor state is unavailable",
		"state_invalid":                "durable executor state requires operator review",
		"target_busy":                  "another target operation is active",
		"stage_failed":                 "release staging failed",
		"stage_required":               "the immutable release plan must be staged first",
		"stage_invalid":                "the staged release no longer matches the plan",
		"plan_conflict":                "job identity was reused with a different plan",
		"reconcile_required":           "executor state is ambiguous and requires reconcile",
		"already_terminal":             "the update plan is already terminal",
		"mutation_precondition_failed": "target precondition validation failed",
		"authorization_failed":         "self-update authorization failed",
		"authorization_uncertain":      "self-update authorization result is uncertain",
		"rollback_failed":              "local rollback could not restore the previous target state",
		"internal_error":               "internal error",
	}[code]
	if message == "" {
		code, message = "internal_error", "internal error"
	}
	return LocalExecutorResponse{
		Version: version,
		Error:   &LocalExecutorFailure{Code: code, Message: message},
	}
}
