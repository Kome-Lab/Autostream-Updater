package evidence

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

func problem(code string) error { return &Error{Code: code} }

// Decode accepts one bounded UTF-8 JSON object with exact field names. The
// token pass rejects duplicate keys, null, unknown/extraneous fields, missing
// required fields, case aliases, noncanonical integers and trailing JSON.
func Decode(data []byte) (Envelope, error) {
	var result Envelope
	if len(data) == 0 || len(data) > MaxEnvelopeBytes || !utf8.Valid(data) {
		return result, problem("encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := checkValue(decoder, reflect.TypeOf(result), 0); err != nil {
		return result, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return result, problem("trailing")
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return Envelope{}, problem("encoding")
	}
	if err := Validate(result); err != nil {
		return Envelope{}, err
	}
	return result, nil
}

// Encode provides stable transport serialization, not a selected signature
// canonicalization or authenticated representation. Profiles must bind the full
// Envelope and, where applicable, the original bytes in their verifier contract.
func Encode(value Envelope) ([]byte, error) {
	if err := Validate(value); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxEnvelopeBytes {
		return nil, problem("encoding")
	}
	return encoded, nil
}

func checkValue(decoder *json.Decoder, shape reflect.Type, depth int) error {
	if depth > 32 {
		return problem("shape")
	}
	for shape.Kind() == reflect.Pointer {
		shape = shape.Elem()
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return problem("encoding")
	}
	switch shape.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return problem("shape")
		}
		fields := make(map[string]reflect.StructField, shape.NumField())
		required := make(map[string]bool, shape.NumField())
		for index := 0; index < shape.NumField(); index++ {
			field := shape.Field(index)
			tag := strings.Split(field.Tag.Get("json"), ",")
			if len(tag) == 0 || tag[0] == "" || tag[0] == "-" {
				return problem("shape")
			}
			fields[tag[0]] = field
			required[tag[0]] = len(tag) == 1 || tag[1] != "omitempty"
		}
		seen := make(map[string]bool, len(fields))
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] {
				return problem("fields")
			}
			field, ok := fields[key]
			if !ok {
				return problem("fields")
			}
			seen[key] = true
			if err := checkValue(decoder, field.Type, depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return problem("encoding")
		}
		for name, mandatory := range required {
			if mandatory && !seen[name] {
				return problem("required")
			}
		}
	case reflect.Slice:
		if shape.Elem().Kind() != reflect.String || token != json.Delim('[') {
			return problem("shape")
		}
		count := 0
		for decoder.More() {
			count++
			if count > MaxResources {
				return problem("bounds")
			}
			if err := checkValue(decoder, shape.Elem(), depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return problem("encoding")
		}
	case reflect.String:
		value, ok := token.(string)
		if !ok || strings.ContainsRune(value, utf8.RuneError) {
			return problem("encoding")
		}
	case reflect.Uint32, reflect.Uint64:
		value, ok := token.(json.Number)
		if !ok {
			return problem("number")
		}
		number := string(value)
		if number == "" || len(number) > 1 && number[0] == '0' {
			return problem("number")
		}
		for _, digit := range number {
			if digit < '0' || digit > '9' {
				return problem("number")
			}
		}
		if _, err := strconv.ParseUint(number, 10, shape.Bits()); err != nil {
			return problem("number")
		}
	default:
		return problem("shape")
	}
	return nil
}

func identifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		alphanumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if !alphanumeric && (index == 0 || character != '.' && character != '_' && character != ':' && character != '-') {
			return false
		}
	}
	return true
}

func identifiers(values ...string) bool {
	for _, value := range values {
		if !identifier(value) {
			return false
		}
	}
	return true
}

func text(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, 0) && !strings.ContainsRune(value, utf8.RuneError)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// Validate checks structure and semantic correlation only. UNKNOWN states are
// transportable data, never authenticated current validity or actuation rights.
func Validate(value Envelope) error {
	if value.ProtocolVersion != ProtocolVersion {
		return problem("version")
	}
	if !oneOf(string(value.Kind), string(CPAuthorizationKind), string(PolicyKind), string(TrustKind),
		string(MembershipKind), string(OwnershipKind), string(FenceKind), string(GenerationKind),
		string(BootKind), string(ProcessKind), string(PAdmissionKind), string(DrainKind),
		string(CandidateKind), string(BusinessAdmissionKind)) {
		return problem("kind")
	}
	if !identifiers(value.EvidenceID, value.Issuer, value.Audience,
		value.Scope.Realm, value.Scope.Host, value.Scope.Resource, value.Scope.Backend,
		value.Execution.RequestID, value.Execution.ExecutionKey, value.Execution.OperationID,
		value.Execution.AttemptID, value.Execution.StepID, value.Frame.Issuer,
		value.Frame.ServingIncarnation, value.Frame.Generation, value.Frame.SnapshotID,
		value.Frame.ObservationProof) || !text(value.Binding, 64<<10) {
		return problem("identity")
	}
	validity := value.Validity
	switch validity.Status {
	case "SPECIFIED":
		if validity.Issued == nil || validity.Expiry == nil || !identifier(validity.QualificationProof) ||
			!identifiers(validity.Issued.TimeBase, validity.Issued.BootID, validity.Expiry.TimeBase, validity.Expiry.BootID) ||
			validity.Issued.TimeBase != validity.Expiry.TimeBase || validity.Issued.BootID != validity.Expiry.BootID ||
			validity.Expiry.Tick <= validity.Issued.Tick {
			return problem("validity")
		}
	case "UNKNOWN":
		if validity.Issued != nil || validity.Expiry != nil || validity.QualificationProof != "" {
			return problem("validity")
		}
	default:
		return problem("validity")
	}
	if !identifiers(value.Integrity.ProfileID, value.Integrity.KeyID, value.Integrity.KeyRevision) || !text(value.Integrity.Proof, 64<<10) {
		return problem("integrity")
	}
	// An interface containing a typed nil is nonnil, so count pointer values
	// explicitly through reflection rather than granting an accidental union.
	payloads := []any{value.CPAuthorization, value.Policy, value.Trust, value.Membership,
		value.Ownership, value.Fence, value.Generation, value.Boot, value.Process,
		value.PAdmission, value.Drain, value.Candidate, value.BusinessAdmission}
	count := 0
	for _, payload := range payloads {
		if !reflect.ValueOf(payload).IsNil() {
			count++
		}
	}
	if count != 1 {
		return problem("union")
	}
	valid := false
	switch value.Kind {
	case CPAuthorizationKind:
		p := value.CPAuthorization
		valid = p != nil && p.Action == AuthorizationAction &&
			oneOf(p.Decision, "AUTHORIZED", "DENIED", "UNKNOWN") &&
			identifiers(p.PolicyRevision, p.TrustRevision)
	case PolicyKind, TrustKind:
		p := value.Policy
		if value.Kind == TrustKind {
			p = value.Trust
		}
		valid = p != nil && identifiers(p.Revision, p.SubjectEvidenceID) &&
			oneOf(p.Revocation, "ACTIVE", "REVOKED", "UNKNOWN")
	case MembershipKind:
		p := value.Membership
		valid = p != nil && identifiers(p.DomainID, p.Revision) &&
			oneOf(p.State, "MEMBER", "REVOKED", "UNKNOWN")
	case OwnershipKind, FenceKind:
		p := value.Ownership
		if value.Kind == FenceKind {
			p = value.Fence
		}
		valid = p != nil && identifiers(p.OwnerID, p.OwnershipEpoch, p.FenceEpoch, p.BootID, p.ProcessIncarnation) &&
			oneOf(p.State, "CURRENT", "REVOKED", "UNKNOWN")
	case GenerationKind:
		p := value.Generation
		valid = p != nil && identifier(p.Generation) && oneOf(p.State, "ACTIVE", "REVOKED", "UNKNOWN")
	case BootKind:
		p := value.Boot
		valid = p != nil && identifiers(p.BootID, p.ActorID) && oneOf(p.ActorRole, "HOST_AGENT", "LOCAL_EXECUTOR")
	case ProcessKind:
		p := value.Process
		valid = p != nil && identifiers(p.BootID, p.Incarnation, p.ActorID) && p.ProcessID > 0 && p.StartTicks > 0 &&
			oneOf(p.ActorRole, "HOST_AGENT", "LOCAL_EXECUTOR")
	case PAdmissionKind:
		p := value.PAdmission
		valid = p != nil && identifier(p.AdmissionEpoch) &&
			oneOf(p.State, "OPEN", "CLOSED", "UNKNOWN") &&
			oneOf(p.Consumption, "UNCONSUMED", "CONSUMED", "UNKNOWN") &&
			oneOf(p.Revocation, "ACTIVE", "REVOKED", "UNKNOWN")
	case DrainKind:
		p := value.Drain
		if p != nil && identifiers(p.DomainID, p.DrainEpoch, p.MembershipRevision) &&
			oneOf(p.State, "READY", "NOT_READY", "HELD", "UNKNOWN") &&
			len(p.ResourceIDs) > 0 && len(p.ResourceIDs) <= MaxResources {
			resources := make(map[string]bool, len(p.ResourceIDs))
			valid = true
			for _, resource := range p.ResourceIDs {
				if !identifier(resource) || resources[resource] {
					valid = false
					break
				}
				resources[resource] = true
			}
			valid = valid && resources[value.Scope.Resource]
			if p.State == "READY" {
				valid = valid && identifiers(p.Seal, p.CompletionProof)
			} else {
				valid = valid && p.Seal == "" && p.CompletionProof == ""
			}
		}
	case CandidateKind:
		p := value.Candidate
		valid = p != nil && identifiers(p.CandidateID, p.Revision, p.ContentHash, p.ResourceID) &&
			p.ResourceID == value.Scope.Resource && oneOf(p.Approval, "APPROVED", "PENDING", "REJECTED", "UNKNOWN")
		if p != nil && p.Approval == "APPROVED" {
			valid = valid && identifier(p.ApproverID)
		} else if p != nil {
			valid = valid && p.ApproverID == ""
		}
	case BusinessAdmissionKind:
		p := value.BusinessAdmission
		valid = p != nil && oneOf(p.State, "OPEN", "CLOSED", "UNKNOWN") && identifier(p.AuthorityRevision)
	}
	if !valid {
		return problem("payload")
	}
	return nil
}

// Clone detaches all conditional payloads, validity points and resource arrays.
// It neither validates/authenticates evidence nor changes UNKNOWN into absence.
func Clone(value Envelope) Envelope {
	result := value
	if value.Validity.Issued != nil {
		copy := *value.Validity.Issued
		result.Validity.Issued = &copy
	}
	if value.Validity.Expiry != nil {
		copy := *value.Validity.Expiry
		result.Validity.Expiry = &copy
	}
	if value.CPAuthorization != nil {
		copy := *value.CPAuthorization
		result.CPAuthorization = &copy
	}
	if value.Policy != nil {
		copy := *value.Policy
		result.Policy = &copy
	}
	if value.Trust != nil {
		copy := *value.Trust
		result.Trust = &copy
	}
	if value.Membership != nil {
		copy := *value.Membership
		result.Membership = &copy
	}
	if value.Ownership != nil {
		copy := *value.Ownership
		result.Ownership = &copy
	}
	if value.Fence != nil {
		copy := *value.Fence
		result.Fence = &copy
	}
	if value.Generation != nil {
		copy := *value.Generation
		result.Generation = &copy
	}
	if value.Boot != nil {
		copy := *value.Boot
		result.Boot = &copy
	}
	if value.Process != nil {
		copy := *value.Process
		result.Process = &copy
	}
	if value.PAdmission != nil {
		copy := *value.PAdmission
		result.PAdmission = &copy
	}
	if value.Drain != nil {
		copy := *value.Drain
		copy.ResourceIDs = append([]string(nil), value.Drain.ResourceIDs...)
		result.Drain = &copy
	}
	if value.Candidate != nil {
		copy := *value.Candidate
		result.Candidate = &copy
	}
	if value.BusinessAdmission != nil {
		copy := *value.BusinessAdmission
		result.BusinessAdmission = &copy
	}
	return result
}
