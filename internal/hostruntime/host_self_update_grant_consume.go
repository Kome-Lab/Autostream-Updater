package hostruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type hostSelfUpdateGrantConsumer func(
	context.Context,
	string,
	HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateGrantConsumeResult, error)

func consumeHostSelfUpdateGrant(
	ctx context.Context,
	panelURL string,
	authorization HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateGrantConsumeResult, error) {
	if err := validatePanelURL(panelURL); err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("root self-update grant panel URL is invalid")
	}
	if err := authorization.validate(); err != nil {
		return HostSelfUpdateGrantConsumeResult{}, err
	}
	wire := struct {
		Token   string                     `json:"token"`
		Binding HostSelfUpdateGrantBinding `json:"binding"`
	}{
		Token:   authorization.Token.Reveal(),
		Binding: authorization.Binding,
	}
	payload, err := json.Marshal(wire)
	wire.Token = ""
	if err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("encode host self-update grant consume request")
	}
	endpoint := strings.TrimRight(panelURL, "/") +
		"/services/host-agent/self-update-grants/consume"
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("create host self-update grant consume request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("consume host self-update grant")
	}
	defer response.Body.Close()
	if !responseNoStore(response.Header.Values("Cache-Control")) {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("host self-update grant consume response must use Cache-Control no-store")
	}
	if response.StatusCode < http.StatusOK ||
		response.StatusCode >= http.StatusMultipleChoices {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("host self-update grant was rejected")
	}
	var result HostSelfUpdateGrantConsumeResult
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("decode host self-update grant consume response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("host self-update grant consume response contains trailing data")
	}
	if err := result.Grant.validate(true); err != nil ||
		!sameHostSelfUpdateGrantBinding(result.Grant, authorization.Binding) {
		return HostSelfUpdateGrantConsumeResult{}, errors.New("host self-update grant receipt binding is invalid")
	}
	return result, nil
}

// ConsumeHostSelfUpdateGrant performs the root-side exact grant consumption
// exchange. It is exported only within this repository's internal boundary so
// the complete Host Agent -> Control Plane -> root contract can be exercised.
func ConsumeHostSelfUpdateGrant(
	ctx context.Context,
	panelURL string,
	authorization HostSelfUpdateGrantAuthorization,
) (HostSelfUpdateGrantConsumeResult, error) {
	return consumeHostSelfUpdateGrant(ctx, panelURL, authorization)
}

type hostSelfUpdateGrantState struct {
	SchemaVersion int                         `json:"schema_version"`
	Phase         string                      `json:"phase"`
	TokenSHA256   string                      `json:"token_sha256"`
	Binding       HostSelfUpdateGrantBinding  `json:"binding"`
	Receipt       *HostSelfUpdateGrantBinding `json:"receipt,omitempty"`
}

func newHostSelfUpdateGrantState(
	authorization HostSelfUpdateGrantAuthorization,
) hostSelfUpdateGrantState {
	sum := sha256.Sum256([]byte(authorization.Token.Reveal()))
	return hostSelfUpdateGrantState{
		SchemaVersion: hostSelfUpdateGrantStateSchemaVersion,
		Phase:         hostSelfUpdateGrantPhasePrepared,
		TokenSHA256:   "sha256:" + hex.EncodeToString(sum[:]),
		Binding:       authorization.Binding,
	}
}

func (s hostSelfUpdateGrantState) validate() error {
	if s.SchemaVersion != hostSelfUpdateGrantStateSchemaVersion ||
		(s.Phase != hostSelfUpdateGrantPhasePrepared &&
			s.Phase != hostSelfUpdateGrantPhaseConsumed &&
			s.Phase != hostSelfUpdateGrantPhaseApplied &&
			s.Phase != hostSelfUpdateGrantPhaseFailed) ||
		!digestPattern.MatchString(s.TokenSHA256) ||
		s.Binding.validate(false) != nil {
		return errors.New("host self-update grant state is invalid")
	}
	if s.Phase == hostSelfUpdateGrantPhasePrepared ||
		s.Phase == hostSelfUpdateGrantPhaseFailed {
		if s.Receipt != nil {
			return errors.New("receipt-free host self-update grant phase contains a receipt")
		}
		return nil
	}
	if s.Receipt == nil ||
		s.Receipt.validate(true) != nil ||
		!sameHostSelfUpdateGrantBinding(*s.Receipt, s.Binding) {
		return errors.New("consumed host self-update grant receipt is invalid")
	}
	return nil
}

func (s hostSelfUpdateGrantState) matches(
	authorization HostSelfUpdateGrantAuthorization,
) bool {
	if !sameHostSelfUpdateGrantBinding(s.Binding, authorization.Binding) {
		return false
	}
	sum := sha256.Sum256([]byte(authorization.Token.Reveal()))
	return s.TokenSHA256 == "sha256:"+hex.EncodeToString(sum[:])
}

func loadHostSelfUpdateGrantState(path string, requireRoot bool) (
	*hostSelfUpdateGrantState,
	error,
) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 ||
		info.Size() > 64<<10 ||
		(requireRoot && !isRootOwner(info)) {
		return nil, errors.New("host self-update grant state is unsafe")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read host self-update grant state")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state hostSelfUpdateGrantState
	if err := decoder.Decode(&state); err != nil {
		return nil, errors.New("decode host self-update grant state")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("host self-update grant state contains trailing data")
	}
	if err := state.validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveHostSelfUpdateGrantState(
	path string,
	state hostSelfUpdateGrantState,
	requireRoot bool,
) error {
	if err := state.validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return errors.New("encode host self-update grant state")
	}
	if err := writeAtomicFile(path, append(payload, '\n'), 0o600); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 ||
		info.Mode()&os.ModeSymlink != 0 ||
		(requireRoot && !isRootOwner(info)) {
		return errors.New("host self-update grant state security verification failed")
	}
	return nil
}
