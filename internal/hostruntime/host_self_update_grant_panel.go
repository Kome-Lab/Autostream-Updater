package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HostSelfUpdateGrantIssueRequest struct {
	SelfUpdateID     string
	ExpectedRevision int64
	Operation        string
	PlanSHA256       string
	SessionID        string
}

type HostSelfUpdateGrantIssuer interface {
	IssueHostSelfUpdateGrant(
		context.Context,
		HostSelfUpdateGrantIssueRequest,
	) (HostSelfUpdateGrantAuthorization, error)
}

func (c PanelClient) IssueHostSelfUpdateGrant(
	ctx context.Context,
	input HostSelfUpdateGrantIssueRequest,
) (HostSelfUpdateGrantAuthorization, error) {
	input.SelfUpdateID = strings.TrimSpace(input.SelfUpdateID)
	input.Operation = strings.TrimSpace(input.Operation)
	input.PlanSHA256 = strings.TrimSpace(input.PlanSHA256)
	input.SessionID = strings.TrimSpace(input.SessionID)
	if !identifierPattern.MatchString(input.SelfUpdateID) ||
		input.ExpectedRevision < 1 ||
		(input.Operation != "stage" && input.Operation != "reconcile") ||
		!mutationPlanHashPattern.MatchString(input.PlanSHA256) ||
		!identifierPattern.MatchString(input.SessionID) {
		return HostSelfUpdateGrantAuthorization{}, errors.New("host self-update grant issue request is invalid")
	}
	body := struct {
		ExpectedRevision int64  `json:"expected_revision"`
		Operation        string `json:"operation"`
		PlanSHA256       string `json:"plan_sha256"`
		SessionID        string `json:"session_id"`
	}{
		ExpectedRevision: input.ExpectedRevision,
		Operation:        input.Operation,
		PlanSHA256:       input.PlanSHA256,
		SessionID:        input.SessionID,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return HostSelfUpdateGrantAuthorization{}, errors.New("encode host self-update grant issue request")
	}
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if err := validatePanelURL(base); err != nil {
		return HostSelfUpdateGrantAuthorization{}, errors.New("host self-update grant Panel URL is invalid")
	}
	endpoint := base + "/services/host-agent/self-updates/" +
		url.PathEscape(input.SelfUpdateID) + "/grants"
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return HostSelfUpdateGrantAuthorization{}, errors.New("create host self-update grant issue request")
	}
	request.Header.Set("Authorization", "Bearer "+c.runtimeToken())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	configuredClient := *client
	if configuredClient.Timeout <= 0 {
		configuredClient.Timeout = 15 * time.Second
	}
	configuredClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := configuredClient.Do(request)
	if err != nil {
		return HostSelfUpdateGrantAuthorization{}, errors.New("issue host self-update grant")
	}
	defer response.Body.Close()
	if !responseNoStore(response.Header.Values("Cache-Control")) {
		return HostSelfUpdateGrantAuthorization{}, errors.New("host self-update grant issue response must use Cache-Control no-store")
	}
	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusMultipleChoices {
		return HostSelfUpdateGrantAuthorization{}, errors.New("host self-update grant issue was rejected")
	}
	var wire struct {
		Grant  HostSelfUpdateGrantBinding `json:"grant"`
		Token  string                     `json:"token"`
		Issued bool                       `json:"issued"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return HostSelfUpdateGrantAuthorization{}, errors.New("decode host self-update grant issue response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return HostSelfUpdateGrantAuthorization{}, errors.New("host self-update grant issue response contains trailing data")
	}
	authorization := HostSelfUpdateGrantAuthorization{
		Binding: wire.Grant,
		Token:   NewBoundedSecret(wire.Token),
	}
	wire.Token = ""
	if err := authorization.validate(); err != nil {
		return HostSelfUpdateGrantAuthorization{}, fmt.Errorf(
			"host self-update grant issue binding is invalid: %w",
			err,
		)
	}
	if !wire.Issued ||
		authorization.Binding.SelfUpdateID != input.SelfUpdateID ||
		authorization.Binding.ExpectedSelfUpdateRevision != input.ExpectedRevision ||
		authorization.Binding.Operation != input.Operation ||
		authorization.Binding.PlanSHA256 != input.PlanSHA256 ||
		authorization.Binding.SessionID != input.SessionID {
		return HostSelfUpdateGrantAuthorization{}, errors.New("host self-update grant issue binding is invalid")
	}
	return authorization, nil
}

func hostSelfUpdateGrantPlanSHA256(
	operation string,
	policy HostAgentPolicy,
	request HostSelfUpdateRequest,
	fence LocalExecutorMutationFence,
) (string, error) {
	input := struct {
		Operation          string                     `json:"operation"`
		SelfUpdateID       string                     `json:"self_update_id"`
		SelfUpdateRevision int64                      `json:"self_update_revision"`
		Request            HostSelfUpdateRequest      `json:"request"`
		Fence              LocalExecutorMutationFence `json:"fence"`
	}{
		Operation:          operation,
		SelfUpdateID:       policy.SelfUpdateID,
		SelfUpdateRevision: policy.SelfUpdateRevision,
		Request:            request,
		Fence:              fence,
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return "", errors.New("encode host self-update grant plan")
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

// HostSelfUpdateGrantPlanSHA256 exposes the credential-free canonical plan
// binding for cross-package contract tests and Control Plane integrations.
func HostSelfUpdateGrantPlanSHA256(
	operation string,
	policy HostAgentPolicy,
	request HostSelfUpdateRequest,
	fence LocalExecutorMutationFence,
) (string, error) {
	return hostSelfUpdateGrantPlanSHA256(operation, policy, request, fence)
}
