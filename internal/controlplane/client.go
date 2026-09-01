package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

const (
	ContractMajorHeader = "X-AutoStream-Contract-Major"
	ContractMajorV2     = "2"
	maxResponseBytes    = 1 << 20
)

type Client struct {
	BaseURL       string
	HTTP          *http.Client
	TokenProvider func() string
	Now           func() time.Time
}

type HTTPError struct {
	Status int
	Code   string
}

func (e *HTTPError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("control plane returned HTTP %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("control plane returned HTTP %d", e.Status)
}

func (c Client) Claim(
	ctx context.Context,
	request contracts.UpdateAgentClaimRequest,
) (*contracts.UpdaterLeaseEnvelope, bool, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, false, errors.New("encode updater claim")
	}
	status, response, err := c.post(
		ctx,
		"/services/update-jobs/claim",
		payload,
		c.runtimeToken(),
	)
	if err != nil {
		return nil, false, err
	}
	if status == http.StatusNoContent {
		if len(bytes.TrimSpace(response)) != 0 {
			return nil, false, errors.New("updater claim no-content response contained a body")
		}
		return nil, false, nil
	}
	if status != http.StatusOK {
		return nil, false, &HTTPError{Status: status}
	}
	now := c.now()
	if contracts.ValidateUpdaterLeaseEnvelope(now, response) == nil {
		var lease contracts.UpdaterLeaseEnvelope
		if err := json.Unmarshal(response, &lease); err != nil {
			return nil, false, errors.New("decode validated updater lease")
		}
		return &lease, false, nil
	}
	if contracts.ValidateUpdateAgentClearActiveJobResponse(response) == nil {
		return nil, true, nil
	}
	return nil, false, errors.New("updater claim response is not a valid v2 lease or clear instruction")
}

func (c Client) ReportProgress(
	ctx context.Context,
	lease contracts.UpdaterLeaseEnvelope,
	progress contracts.UpdaterProgressEnvelope,
) error {
	payload, err := json.Marshal(progress)
	if err != nil || contracts.ValidateUpdaterProgressEnvelope(lease, payload) != nil {
		return errors.New("updater progress is invalid")
	}
	return c.postReport(ctx, lease.Command.MutationAuthorization.JobID, payload)
}

func (c Client) ReportResult(
	ctx context.Context,
	lease contracts.UpdaterLeaseEnvelope,
	result contracts.UpdaterResultEnvelope,
) error {
	payload, err := json.Marshal(result)
	if err != nil || contracts.ValidateUpdaterResultEnvelope(lease, payload) != nil {
		return errors.New("updater result is invalid")
	}
	return c.postReport(ctx, lease.Command.MutationAuthorization.JobID, payload)
}

func (c Client) postReport(ctx context.Context, jobID string, payload []byte) error {
	status, _, err := c.post(
		ctx,
		"/services/update-jobs/"+url.PathEscape(jobID)+"/report",
		payload,
		c.runtimeToken(),
	)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &HTTPError{Status: status}
	}
	return nil
}

func (c Client) IssueMutationGrant(
	ctx context.Context,
	jobID string,
	request contracts.UpdaterMutationGrantIssueRequest,
) (contracts.UpdaterMutationGrantIssueResponse, error) {
	now := c.now()
	payload, err := json.Marshal(request)
	if err != nil || contracts.ValidateUpdaterMutationGrantIssueRequest(now, payload) != nil {
		return contracts.UpdaterMutationGrantIssueResponse{}, errors.New("updater mutation grant request is invalid")
	}
	status, responseBody, err := c.post(
		ctx,
		"/services/update-jobs/"+url.PathEscape(jobID)+"/mutation-grants",
		payload,
		c.runtimeToken(),
	)
	if err != nil {
		return contracts.UpdaterMutationGrantIssueResponse{}, err
	}
	if status != http.StatusCreated {
		return contracts.UpdaterMutationGrantIssueResponse{}, &HTTPError{Status: status}
	}
	if contracts.ValidateUpdaterMutationGrantIssueResponse(now, responseBody) != nil {
		return contracts.UpdaterMutationGrantIssueResponse{}, errors.New("updater mutation grant response is invalid")
	}
	var response contracts.UpdaterMutationGrantIssueResponse
	if err := json.Unmarshal(responseBody, &response); err != nil ||
		contracts.ValidateUpdaterMutationGrantIssueResponseForLease(now, request.Binding.Lease, response) != nil {
		return contracts.UpdaterMutationGrantIssueResponse{}, errors.New("updater mutation grant response does not match its lease")
	}
	return response, nil
}

func ConsumeMutationGrant(
	ctx context.Context,
	baseURL, jobID string,
	grantToken string,
	request contracts.UpdaterMutationGrantConsumeRequest,
	httpClient *http.Client,
	now time.Time,
) error {
	payload, err := json.Marshal(request)
	if err != nil || contracts.ValidateUpdaterMutationGrantConsumeRequest(now, payload) != nil {
		return errors.New("updater mutation grant consumption is invalid")
	}
	client := Client{
		BaseURL: baseURL,
		HTTP:    httpClient,
		TokenProvider: func() string {
			return grantToken
		},
		Now: func() time.Time { return now },
	}
	status, response, err := client.post(
		ctx,
		"/services/update-jobs/"+url.PathEscape(jobID)+"/mutation-grants/consume",
		payload,
		grantToken,
	)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent || len(bytes.TrimSpace(response)) != 0 {
		return &HTTPError{Status: status}
	}
	return nil
}

func (c Client) post(
	ctx context.Context,
	path string,
	payload []byte,
	token string,
) (int, []byte, error) {
	if strings.TrimSpace(token) == "" {
		return 0, nil, errors.New("control plane credential is unavailable")
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(c.BaseURL, "/")+path,
		bytes.NewReader(payload),
	)
	if err != nil {
		return 0, nil, errors.New("create control plane request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set(ContractMajorHeader, ContractMajorV2)

	client := http.Client{Timeout: 15 * time.Second}
	if c.HTTP != nil {
		client = *c.HTTP
		if client.Timeout <= 0 || client.Timeout > 15*time.Second {
			client.Timeout = 15 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, errors.New("control plane request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) > maxResponseBytes {
		return 0, nil, errors.New("control plane response is not bounded")
	}
	majorValues := response.Header.Values(ContractMajorHeader)
	if len(majorValues) != 1 || strings.TrimSpace(majorValues[0]) != ContractMajorV2 {
		return 0, nil, errors.New("control plane did not confirm contract major 2")
	}
	if !hasNoStore(response.Header.Values("Cache-Control")) {
		return 0, nil, errors.New("control plane response is cacheable")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return response.StatusCode, nil, &HTTPError{
			Status: response.StatusCode,
			Code:   safeErrorCode(body),
		}
	}
	return response.StatusCode, body, nil
}

func (c Client) runtimeToken() string {
	if c.TokenProvider == nil {
		return ""
	}
	return c.TokenProvider()
}

func (c Client) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func hasNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}

func safeErrorCode(payload []byte) string {
	var response struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(payload, &response) != nil {
		return ""
	}
	code := strings.TrimSpace(response.Code)
	if len(code) == 0 || len(code) > 64 {
		return ""
	}
	for _, character := range code {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return ""
	}
	return code
}
