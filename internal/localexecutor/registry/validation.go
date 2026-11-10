package registry

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strconv"
	"unicode/utf8"
)

const maxRequestBytes = 64 * 1024

// ValidateExecutionKey checks only the opaque identifier's representation.
// Global uniqueness and ownership are storage/verifier obligations, not syntax.
func ValidateExecutionKey(key ID) error {
	return validateID(key, "execution.execution_key")
}

// ValidateScope accepts canonical, opaque resource identities, never OS paths.
func ValidateScope(scope Scope) error {
	for _, item := range []struct {
		value ID
		field string
	}{
		{scope.Realm, "scope.realm"},
		{scope.Host, "scope.host"},
		{scope.Resource, "scope.resource"},
		{scope.Backend, "scope.backend"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

func ValidateExecution(execution Execution) error {
	if err := ValidateExecutionKey(execution.ExecutionKey); err != nil {
		return err
	}
	for _, item := range []struct {
		value ID
		field string
	}{
		{execution.RequestID, "execution.request_id"},
		{execution.OperationID, "execution.operation_id"},
		{execution.AttemptID, "execution.attempt_id"},
		{execution.StepID, "execution.step_id"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

// validateID deliberately rejects case folding, Unicode normalization, paths,
// whitespace, and empty values. DecodeRequest separately rejects JSON null. The value is never echoed in an error.
func validateID(value ID, field string) error {
	if len(value) == 0 || len(value) > 128 {
		return invalid(field)
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		alphanumeric := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alphanumeric && (i == 0 || c != '.' && c != '_' && c != ':' && c != '-') {
			return invalid(field)
		}
	}
	return nil
}

func validateCall(call Call) error {
	for _, item := range []struct {
		value ID
		field string
	}{
		{call.Principal, "call.principal"},
		{call.Capability, "call.capability"},
		{call.CorrelationID, "call.correlation_id"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidence(evidence Evidence) error {
	for _, item := range []struct {
		value ID
		field string
	}{
		{evidence.Issuer, "evidence.issuer"},
		{evidence.ServingIncarnation, "evidence.serving_incarnation"},
		{evidence.Generation, "evidence.generation"},
		{evidence.SnapshotID, "evidence.snapshot_id"},
		{evidence.FreshnessProof, "evidence.freshness_proof"},
		{evidence.ObservationProof, "evidence.observation_proof"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

func validateCommand(command Command) error {
	if command.Schema != CommandSchema {
		return invalid("command.schema")
	}
	if command.Operation != ReferenceOnlyOperation {
		return invalid("command.operation")
	}
	if err := ValidateScope(command.Scope); err != nil {
		return err
	}
	if err := ValidateExecution(command.Execution); err != nil {
		return err
	}
	for _, item := range []struct {
		value ID
		field string
	}{
		{command.RequestingPrincipal, "command.requesting_principal"},
		{command.AuthorizationIssuer, "command.authorization_issuer"},
		{command.CandidateRevision, "command.candidate_revision"},
		{command.CandidateContentPin, "command.candidate_content_pin"},
		{command.Expected.Revision, "command.expected.revision"},
		{command.RequiredGuard.Policy, "command.guard.policy"},
		{command.RequiredGuard.Trust, "command.guard.trust"},
		{command.RequiredGuard.Membership, "command.guard.membership"},
		{command.RequiredGuard.OwnershipEpoch, "command.guard.ownership_epoch"},
		{command.RequiredGuard.FenceEpoch, "command.guard.fence_epoch"},
		{command.RequiredGuard.Generation, "command.guard.generation"},
		{command.RequiredGuard.BootID, "command.guard.boot_id"},
		{command.RequiredGuard.ProcessIncarnation, "command.guard.process_incarnation"},
		{command.Timing.TimeBase, "command.timing.time_base"},
		{command.OriginalBudget, "command.original_budget"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	if command.Expected.StateVersion == math.MaxUint64 {
		return invalid("command.expected.state_version")
	}
	if command.Timing.DeadlineTick == 0 {
		return invalid("command.timing.deadline_tick")
	}
	return nil
}

// CanonicalBinding defines the internal v1 equality representation of Command.
// It does not select a signature, token format, wire protocol, or hash algorithm.
// Struct field order and exact validated scalar values define this local schema;
// changing them requires a new internal schema, never silent reinterpretation.
func CanonicalBinding(command Command) (Binding, error) {
	if err := validateCommand(command); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(command)
	if err != nil {
		return "", invalid("command.encoding")
	}
	return Binding(encoded), nil
}

func ValidateRequest(request Request) error {
	expected, err := CanonicalBinding(request.Command)
	if err != nil {
		return err
	}
	if len(request.Binding) == 0 || len(request.Binding) > maxRequestBytes || !utf8.ValidString(string(request.Binding)) {
		return invalid("request.binding")
	}
	if request.Binding != expected {
		return collision("request.binding")
	}
	return nil
}

// DecodeRequest decodes the bounded internal v1 representation, not a public API.
// All struct fields are mandatory. Object order/JSON string escaping can differ,
// but decoded values must produce the exact canonical immutable binding.
func DecodeRequest(data []byte) (Request, error) {
	var request Request
	if len(data) == 0 || len(data) > maxRequestBytes || !utf8.Valid(data) {
		return request, invalid("request.json")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := strictRequestValue(decoder, reflect.TypeOf(request)); err != nil {
		return request, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return request, invalid("request.json")
	}
	if err := json.Unmarshal(data, &request); err != nil {
		return Request{}, invalid("request.json")
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

func strictRequestValue(decoder *json.Decoder, target reflect.Type) error {
	token, err := decoder.Token()
	if err != nil || token == nil {
		return invalid("request.json")
	}
	switch target.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return invalid("request.json")
		}
		fields := make(map[string]reflect.Type, target.NumField())
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)
			fields[field.Name] = field.Type
		}
		seen := make(map[string]bool, len(fields))
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return invalid("request.json")
			}
			name, ok := key.(string)
			fieldType, exists := fields[name]
			if !ok || !exists || seen[name] {
				return invalid("request.json")
			}
			seen[name] = true
			if err := strictRequestValue(decoder, fieldType); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') || len(seen) != len(fields) {
			return invalid("request.json")
		}
	case reflect.String:
		if _, ok := token.(string); !ok {
			return invalid("request.json")
		}
	case reflect.Uint32, reflect.Uint64:
		number, ok := token.(json.Number)
		if !ok {
			return invalid("request.json")
		}
		value := number.String()
		if value == "" {
			return invalid("request.json")
		}
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				return invalid("request.json")
			}
		}
		if _, err := strconv.ParseUint(value, 10, target.Bits()); err != nil {
			return invalid("request.json")
		}
	default:
		return invalid("request.json")
	}
	return nil
}
