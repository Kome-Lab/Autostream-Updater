package hostruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const runtimeTokenRotationResponseMaxBytes = 64 << 10

type RuntimeTokenRotationCredential struct {
	TokenID      string
	RuntimeToken BoundedSecret
}

type RuntimeTokenRotationClaimResult struct {
	Rotation   HostAgentRuntimeTokenRotation
	Credential RuntimeTokenRotationCredential
	Claimed    bool
}

type RuntimeTokenRotationHeartbeatProof struct {
	ExpectedRevision            int64  `json:"expected_revision"`
	AgentVersion                string `json:"agent_version"`
	AgentProtocolVersion        int    `json:"agent_protocol_version"`
	ExecutorVersion             string `json:"executor_version"`
	ExecutorProtocolVersion     int    `json:"executor_protocol_version"`
	MutationProtocolVersion     int    `json:"mutation_protocol_version"`
	OwnershipEpoch              int64  `json:"ownership_epoch"`
	SourcePolicyRevision        int64  `json:"source_policy_revision"`
	ProjectionRevision          int64  `json:"projection_revision"`
	LocalExecutorPolicyRevision int64  `json:"local_executor_policy_revision"`
	LocalExecutorPolicySHA256   string `json:"local_executor_policy_sha256"`
	LocalStageReceiptID         string `json:"local_stage_receipt_id"`
	LocalPhase                  string `json:"local_phase"`
}

func (p RuntimeTokenRotationHeartbeatProof) validate() error {
	if p.ExpectedRevision < 1 ||
		!versionPattern.MatchString(p.AgentVersion) ||
		p.AgentProtocolVersion < 1 ||
		!versionPattern.MatchString(p.ExecutorVersion) ||
		p.ExecutorProtocolVersion < 1 ||
		p.MutationProtocolVersion < 1 ||
		p.OwnershipEpoch < 1 ||
		p.SourcePolicyRevision < 1 ||
		p.ProjectionRevision < 1 ||
		p.LocalExecutorPolicyRevision < 1 ||
		!digestPattern.MatchString(p.LocalExecutorPolicySHA256) ||
		!identifierPattern.MatchString(p.LocalStageReceiptID) ||
		p.LocalPhase != "staged_token_active" {
		return errors.New("runtime token rotation heartbeat proof is invalid")
	}
	return nil
}

type runtimeTokenRotationClaimWire struct {
	Rotation   HostAgentRuntimeTokenRotation `json:"rotation"`
	Credential struct {
		TokenID      string `json:"token_id"`
		RuntimeToken string `json:"runtime_token"`
	} `json:"credential"`
	Claimed bool `json:"claimed"`
}

type runtimeTokenRotationTransitionWire struct {
	Rotation HostAgentRuntimeTokenRotation `json:"rotation"`
	Applied  bool                          `json:"applied"`
}

func ClaimRuntimeTokenRotationCredential(
	ctx context.Context,
	panelURL,
	rotationID string,
	expectedRevision int64,
	claimID string,
	previousToken string,
	client *http.Client,
) (RuntimeTokenRotationClaimResult, error) {
	if !identifierPattern.MatchString(strings.TrimSpace(claimID)) ||
		claimID != strings.TrimSpace(claimID) {
		return RuntimeTokenRotationClaimResult{}, errors.New(
			"runtime token rotation claim identity is invalid",
		)
	}
	var response runtimeTokenRotationClaimWire
	err := postRuntimeTokenRotation(
		ctx,
		panelURL,
		rotationID,
		"credential/claim",
		expectedRevision,
		claimID,
		previousToken,
		client,
		&response,
	)
	if err != nil {
		return RuntimeTokenRotationClaimResult{}, err
	}
	if err := response.Rotation.Validate(); err != nil ||
		response.Rotation.ID != rotationID ||
		!identifierPattern.MatchString(response.Credential.TokenID) ||
		response.Credential.TokenID != response.Rotation.StagedTokenID ||
		!validBoundedSecret(response.Credential.RuntimeToken) {
		return RuntimeTokenRotationClaimResult{}, errors.New(
			"runtime token rotation claim response is invalid",
		)
	}
	return RuntimeTokenRotationClaimResult{
		Rotation: response.Rotation,
		Credential: RuntimeTokenRotationCredential{
			TokenID:      response.Credential.TokenID,
			RuntimeToken: NewBoundedSecret(response.Credential.RuntimeToken),
		},
		Claimed: response.Claimed,
	}, nil
}

func ProveRuntimeTokenRotationHeartbeat(
	ctx context.Context,
	panelURL,
	rotationID string,
	proof RuntimeTokenRotationHeartbeatProof,
	stagedToken string,
	client *http.Client,
) (HostAgentRuntimeTokenRotation, error) {
	if err := proof.validate(); err != nil {
		return HostAgentRuntimeTokenRotation{}, err
	}
	var response runtimeTokenRotationTransitionWire
	if err := postRuntimeTokenRotationBody(
		ctx, panelURL, rotationID, "heartbeat-proof",
		proof, stagedToken, client, &response,
	); err != nil {
		return HostAgentRuntimeTokenRotation{}, err
	}
	if err := response.Rotation.Validate(); err != nil ||
		response.Rotation.ID != rotationID {
		return HostAgentRuntimeTokenRotation{}, errors.New(
			"runtime token rotation heartbeat response is invalid",
		)
	}
	return response.Rotation, nil
}

func AcknowledgeRuntimeTokenRotationLocalStage(
	ctx context.Context,
	panelURL,
	rotationID string,
	expectedRevision int64,
	stagedToken string,
	client *http.Client,
) (HostAgentRuntimeTokenRotation, error) {
	return transitionRuntimeTokenRotation(
		ctx, panelURL, rotationID, "local-staged",
		expectedRevision, stagedToken, client,
	)
}

func ActivateRuntimeTokenRotationAtPanel(
	ctx context.Context,
	panelURL,
	rotationID string,
	expectedRevision int64,
	stagedToken string,
	client *http.Client,
) (HostAgentRuntimeTokenRotation, error) {
	return transitionRuntimeTokenRotation(
		ctx, panelURL, rotationID, "activate",
		expectedRevision, stagedToken, client,
	)
}

func AcknowledgeRuntimeTokenRotationCancel(
	ctx context.Context,
	panelURL,
	rotationID string,
	expectedRevision int64,
	previousToken string,
	client *http.Client,
) (HostAgentRuntimeTokenRotation, error) {
	return transitionRuntimeTokenRotation(
		ctx, panelURL, rotationID, "cancel-ack",
		expectedRevision, previousToken, client,
	)
}

func transitionRuntimeTokenRotation(
	ctx context.Context,
	panelURL,
	rotationID,
	action string,
	expectedRevision int64,
	token string,
	client *http.Client,
) (HostAgentRuntimeTokenRotation, error) {
	var response runtimeTokenRotationTransitionWire
	if err := postRuntimeTokenRotation(
		ctx,
		panelURL,
		rotationID,
		action,
		expectedRevision,
		"",
		token,
		client,
		&response,
	); err != nil {
		return HostAgentRuntimeTokenRotation{}, err
	}
	if err := response.Rotation.Validate(); err != nil ||
		response.Rotation.ID != rotationID {
		return HostAgentRuntimeTokenRotation{}, errors.New(
			"runtime token rotation transition response is invalid",
		)
	}
	return response.Rotation, nil
}

func postRuntimeTokenRotation(
	ctx context.Context,
	panelURL,
	rotationID,
	action string,
	expectedRevision int64,
	claimID,
	token string,
	client *http.Client,
	out any,
) error {
	panelURL = strings.TrimRight(strings.TrimSpace(panelURL), "/")
	rotationID = strings.TrimSpace(rotationID)
	if validatePanelURL(panelURL) != nil ||
		!identifierPattern.MatchString(rotationID) ||
		expectedRevision < 1 ||
		!validBoundedSecret(token) {
		return errors.New("runtime token rotation request binding is invalid")
	}
	body := struct {
		ExpectedRevision int64  `json:"expected_revision"`
		ClaimID          string `json:"claim_id,omitempty"`
	}{
		ExpectedRevision: expectedRevision,
		ClaimID:          claimID,
	}
	return postRuntimeTokenRotationBody(
		ctx, panelURL, rotationID, action, body, token, client, out,
	)
}

func postRuntimeTokenRotationBody(
	ctx context.Context,
	panelURL,
	rotationID,
	action string,
	body any,
	token string,
	client *http.Client,
	out any,
) error {
	panelURL = strings.TrimRight(strings.TrimSpace(panelURL), "/")
	rotationID = strings.TrimSpace(rotationID)
	if validatePanelURL(panelURL) != nil ||
		!identifierPattern.MatchString(rotationID) ||
		!validBoundedSecret(token) {
		return errors.New("runtime token rotation request binding is invalid")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return errors.New("encode runtime token rotation request")
	}
	endpoint := panelURL +
		"/services/host-agent/runtime-token-rotations/" +
		url.PathEscape(rotationID) + "/" + action
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, bytes.NewReader(payload),
	)
	if err != nil {
		return errors.New("create runtime token rotation request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	configured := &http.Client{Timeout: 15 * time.Second}
	if client != nil {
		copy := *client
		configured = &copy
		if configured.Timeout <= 0 {
			configured.Timeout = 15 * time.Second
		}
	}
	configured.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := configured.Do(request)
	if err != nil {
		return errors.New("send runtime token rotation request")
	}
	defer response.Body.Close()
	if !responseNoStore(response.Header.Values("Cache-Control")) {
		return errors.New(
			"runtime token rotation response must use Cache-Control no-store",
		)
	}
	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusMultipleChoices {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		var apiError struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data, &apiError)
		return &PanelHTTPError{
			Status: response.StatusCode,
			Code:   safeRuntimeTokenRotationErrorCode(apiError.Code),
		}
	}
	limited := &io.LimitedReader{
		R: response.Body,
		N: runtimeTokenRotationResponseMaxBytes + 1,
	}
	data, err := io.ReadAll(limited)
	if err != nil ||
		len(data) == 0 ||
		len(data) > runtimeTokenRotationResponseMaxBytes {
		return errors.New("read runtime token rotation response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errors.New("decode runtime token rotation response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("runtime token rotation response contains trailing data")
	}
	return nil
}

func safeRuntimeTokenRotationErrorCode(code string) string {
	switch strings.TrimSpace(code) {
	case "runtime_token_rotation_not_found",
		"runtime_token_rotation_active",
		"runtime_token_rotation_agent_failed",
		"runtime_token_rotation_agent_inactive",
		"runtime_token_rotation_agent_mismatch",
		"runtime_token_rotation_binding_conflict",
		"runtime_token_rotation_binding_mismatch",
		"runtime_token_rotation_conflict",
		"runtime_token_rotation_credential_already_claimed",
		"runtime_token_rotation_credential_conflict",
		"runtime_token_rotation_credential_invalid",
		"runtime_token_rotation_encryption_unavailable",
		"runtime_token_rotation_failed",
		"runtime_token_rotation_heartbeat_proof_invalid",
		"runtime_token_rotation_idempotency_conflict",
		"runtime_token_rotation_proof_required",
		"runtime_token_rotation_required",
		"runtime_token_rotation_revision_conflict",
		"runtime_token_rotation_revision_stale",
		"runtime_token_rotation_shared_token",
		"runtime_token_rotation_state_invalid",
		"runtime_token_rotation_token_slot",
		"runtime_token_rotation_transition_invalid",
		"runtime_token_rotation_unavailable":
		return strings.TrimSpace(code)
	default:
		return ""
	}
}
