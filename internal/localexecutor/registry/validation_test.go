package registry

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func validationValidCommand() Command {
	return Command{
		Schema:    CommandSchema,
		Operation: ReferenceOnlyOperation,
		Scope:     Scope{Realm: "realm", Host: "host", Resource: "resource", Backend: "backend"},
		Execution: Execution{
			RequestID: "request", ExecutionKey: "execution", OperationID: "operation",
			AttemptID: "attempt", StepID: "step",
		},
		RequestingPrincipal: "operator",
		AuthorizationIssuer: "cp",
		CandidateRevision:   "revision-1",
		CandidateContentPin: "pin-1",
		Expected:            Reference{Revision: "revision-0", StateVersion: 0},
		RequiredGuard: Guard{
			Policy: "policy", Trust: "trust", Membership: "membership",
			OwnershipEpoch: "owner-1", FenceEpoch: "fence-1", Generation: "generation-1",
			BootID: "boot-1", ProcessIncarnation: "process-1",
		},
		Timing:         Timing{TimeBase: "clock-1", DeadlineTick: 1000},
		OriginalBudget: "budget-1",
	}
}

func validationValidRequest(t *testing.T) Request {
	t.Helper()
	command := validationValidCommand()
	binding, err := CanonicalBinding(command)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Command: command, Binding: binding}
}

func validationJSON(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(validationValidRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestValidationOpaqueIDs(t *testing.T) {
	valid := []ID{"a", "0", "a-b_c.d:e", ID(strings.Repeat("a", 128))}
	for _, value := range valid {
		if err := ValidateExecutionKey(value); err != nil {
			t.Errorf("valid identifier rejected: %q: %v", value, err)
		}
	}
	invalidValues := []ID{
		"", "A", "aA", " a", "a ", "a/b", "a\\b", "a\nb", "a\tb", "a\x00b",
		"-a", ".a", "_a", ":a", "é", "ａ", "a💬", ID(strings.Repeat("a", 129)),
	}
	for _, value := range invalidValues {
		if err := ValidateExecutionKey(value); !IsCode(err, CodeInvalid) {
			t.Errorf("invalid identifier accepted: %q", value)
		}
	}
}

func TestValidationEveryCommandIDRequired(t *testing.T) {
	commandType := reflect.TypeOf(Command{})
	var visit func(reflect.Type, []int, string)
	visit = func(typ reflect.Type, indexes []int, path string) {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			next := append(append([]int(nil), indexes...), i)
			name := path + "." + field.Name
			if field.Type == reflect.TypeOf(ID("")) {
				t.Run(name, func(t *testing.T) {
					command := validationValidCommand()
					reflect.ValueOf(&command).Elem().FieldByIndex(next).SetString("")
					if _, err := CanonicalBinding(command); !IsCode(err, CodeInvalid) {
						t.Fatalf("missing ID accepted: %s", name)
					}
				})
			} else if field.Type.Kind() == reflect.Struct {
				visit(field.Type, next, name)
			}
		}
	}
	visit(commandType, nil, "Command")
}

func TestValidationCommandScalars(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Command)
	}{
		{"schema_missing", func(c *Command) { c.Schema = 0 }},
		{"schema_unknown", func(c *Command) { c.Schema = 2 }},
		{"operation_unknown", func(c *Command) { c.Operation = "shell.run" }},
		{"operation_empty", func(c *Command) { c.Operation = "" }},
		{"state_version_overflow", func(c *Command) { c.Expected.StateVersion = math.MaxUint64 }},
		{"deadline_zero", func(c *Command) { c.Timing.DeadlineTick = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := validationValidCommand()
			test.change(&command)
			if _, err := CanonicalBinding(command); !IsCode(err, CodeInvalid) {
				t.Fatal("invalid command accepted")
			}
		})
	}
	command := validationValidCommand()
	command.Timing.DeadlineTick = 1
	if _, err := CanonicalBinding(command); err != nil {
		t.Fatal("historical command must not be rejected by present clock:", err)
	}
	command.Expected.StateVersion = math.MaxUint64 - 1
	if _, err := CanonicalBinding(command); err != nil {
		t.Fatal("last incrementable state version rejected:", err)
	}
}

func TestValidationImmutableBinding(t *testing.T) {
	request := validationValidRequest(t)
	canonical, err := json.Marshal(request.Command)
	if err != nil {
		t.Fatal(err)
	}
	if request.Binding != Binding(canonical) {
		t.Fatal("internal canonical field order changed")
	}
	changes := []struct {
		name   string
		change func(*Command)
	}{
		{"realm", func(c *Command) { c.Scope.Realm = "other" }},
		{"host", func(c *Command) { c.Scope.Host = "other" }},
		{"resource", func(c *Command) { c.Scope.Resource = "other" }},
		{"backend", func(c *Command) { c.Scope.Backend = "other" }},
		{"request_id", func(c *Command) { c.Execution.RequestID = "other" }},
		{"execution_key", func(c *Command) { c.Execution.ExecutionKey = "other" }},
		{"operation_id", func(c *Command) { c.Execution.OperationID = "other" }},
		{"attempt_id", func(c *Command) { c.Execution.AttemptID = "other" }},
		{"step_id", func(c *Command) { c.Execution.StepID = "other" }},
		{"principal", func(c *Command) { c.RequestingPrincipal = "other" }},
		{"issuer", func(c *Command) { c.AuthorizationIssuer = "other" }},
		{"candidate", func(c *Command) { c.CandidateRevision = "other" }},
		{"content_pin", func(c *Command) { c.CandidateContentPin = "other" }},
		{"expected_revision", func(c *Command) { c.Expected.Revision = "other" }},
		{"state_version", func(c *Command) { c.Expected.StateVersion++ }},
		{"policy", func(c *Command) { c.RequiredGuard.Policy = "other" }},
		{"trust", func(c *Command) { c.RequiredGuard.Trust = "other" }},
		{"membership", func(c *Command) { c.RequiredGuard.Membership = "other" }},
		{"owner", func(c *Command) { c.RequiredGuard.OwnershipEpoch = "other" }},
		{"fence", func(c *Command) { c.RequiredGuard.FenceEpoch = "other" }},
		{"generation", func(c *Command) { c.RequiredGuard.Generation = "other" }},
		{"boot", func(c *Command) { c.RequiredGuard.BootID = "other" }},
		{"process", func(c *Command) { c.RequiredGuard.ProcessIncarnation = "other" }},
		{"time_base", func(c *Command) { c.Timing.TimeBase = "other" }},
		{"deadline", func(c *Command) { c.Timing.DeadlineTick++ }},
		{"budget", func(c *Command) { c.OriginalBudget = "other" }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			changed := request
			test.change(&changed.Command)
			if err := ValidateRequest(changed); !IsCode(err, CodeBindingConflict) {
				t.Fatal("changed command reused original binding")
			}
			binding, err := CanonicalBinding(changed.Command)
			if err != nil || binding == request.Binding {
				t.Fatal("changed command did not change canonical binding", err)
			}
		})
	}
	request.Binding = Binding(string(request.Binding) + " ")
	if err := ValidateRequest(request); !IsCode(err, CodeBindingConflict) {
		t.Fatal("noncanonical binding accepted")
	}
	request.Binding = ""
	if err := ValidateRequest(request); !IsCode(err, CodeInvalid) {
		t.Fatal("empty binding accepted")
	}
}

func validationOuterValue(t *testing.T, body string, field string, replacement string) string {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &object); err != nil {
		t.Fatal(err)
	}
	object[field] = json.RawMessage(replacement)
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestValidationStrictDecodeRejectsAmbiguity(t *testing.T) {
	valid := validationJSON(t)
	tests := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"oversize", strings.Repeat(" ", maxRequestBytes+1)},
		{"invalid_utf8", string([]byte{0xff})},
		{"null_request", "null"},
		{"array_request", "[" + valid + "]"},
		{"trailing_object", valid + "{}"},
		{"trailing_null", valid + "null"},
		{"trailing_junk", valid + "x"},
		{"duplicate_command", strings.Replace(valid, "{\"Command\":", "{\"Command\":{},\"Command\":", 1)},
		{"duplicate_nested", strings.Replace(valid, "\"Schema\":1", "\"Schema\":1,\"Schema\":1", 1)},
		{"escaped_duplicate_nested", strings.Replace(valid, "\"Schema\":1", "\"Schema\":1,\"\\u0053chema\":1", 1)},
		{"unknown_outer", strings.TrimSuffix(valid, "}") + ",\"Extra\":1}"},
		{"unknown_nested", strings.Replace(valid, "\"Schema\":1", "\"Extra\":1,\"Schema\":1", 1)},
		{"case_outer", strings.Replace(valid, "\"Command\":", "\"command\":", 1)},
		{"case_nested", strings.Replace(valid, "\"Schema\":", "\"schema\":", 1)},
		{"missing_zero_field", strings.Replace(valid, ",\"StateVersion\":0", "", 1)},
		{"missing_required_id", strings.Replace(valid, "\"Realm\":\"realm\",", "", 1)},
		{"null_object", strings.Replace(valid, "\"Scope\":{\"Realm\":\"realm\",\"Host\":\"host\",\"Resource\":\"resource\",\"Backend\":\"backend\"}", "\"Scope\":null", 1)},
		{"null_scalar", strings.Replace(valid, "\"Host\":\"host\"", "\"Host\":null", 1)},
		{"string_number", strings.Replace(valid, "\"Schema\":1", "\"Schema\":\"1\"", 1)},
		{"float_number", strings.Replace(valid, "\"Schema\":1", "\"Schema\":1.0", 1)},
		{"exponent_number", strings.Replace(valid, "\"Schema\":1", "\"Schema\":1e0", 1)},
		{"negative_number", strings.Replace(valid, "\"Schema\":1", "\"Schema\":-1", 1)},
		{"overflow_uint32", strings.Replace(valid, "\"Schema\":1", "\"Schema\":4294967296", 1)},
		{"overflow_uint64", strings.Replace(valid, "\"DeadlineTick\":1000", "\"DeadlineTick\":18446744073709551616", 1)},
		{"boolean_number", strings.Replace(valid, "\"Schema\":1", "\"Schema\":true", 1)},
		{"array_number", strings.Replace(valid, "\"Schema\":1", "\"Schema\":[1]", 1)},
		{"null_binding", validationOuterValue(t, valid, "Binding", "null")},
		{"numeric_binding", validationOuterValue(t, valid, "Binding", "1")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.body == valid {
				t.Fatal("test mutation did not change input")
			}
			if _, err := DecodeRequest([]byte(test.body)); err == nil {
				t.Fatal("ambiguous input accepted")
			}
		})
	}
}

func TestValidationDecodeCanonicalizesOnlyRepresentation(t *testing.T) {
	valid := validationJSON(t)
	expected := validationValidRequest(t)
	for _, body := range []string{
		valid,
		" \n\t" + valid + "\n ",
		strings.Replace(valid, "\"Realm\":\"realm\"", "\"Realm\":\"\\u0072ealm\"", 1),
	} {
		actual, err := DecodeRequest([]byte(body))
		if err != nil || actual != expected {
			t.Fatal("equivalent JSON value rejected:", err)
		}
	}
	var reordered map[string]any
	if err := json.Unmarshal([]byte(valid), &reordered); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(reordered)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := DecodeRequest(body)
	if err != nil || actual != expected {
		t.Fatal("object field order affected immutable identity:", err)
	}
}

func TestValidationCallAndEvidence(t *testing.T) {
	call := Call{Principal: "principal", Capability: "capability", CorrelationID: "correlation"}
	if err := validateCall(call); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Principal", "Capability", "CorrelationID"} {
		changed := call
		reflect.ValueOf(&changed).Elem().FieldByName(field).SetString("")
		if err := validateCall(changed); !IsCode(err, CodeInvalid) {
			t.Fatal("missing current call field accepted:", field)
		}
	}
	evidence := Evidence{Issuer: "issuer", ServingIncarnation: "serving", Generation: "generation", SnapshotID: "snapshot", FreshnessProof: "freshness", ObservationProof: "observation"}
	if err := validateEvidence(evidence); err != nil {
		t.Fatal(err)
	}
	typ := reflect.TypeOf(evidence)
	for i := 0; i < typ.NumField(); i++ {
		changed := evidence
		reflect.ValueOf(&changed).Elem().Field(i).SetString("")
		if err := validateEvidence(changed); !IsCode(err, CodeInvalid) {
			t.Fatal("missing evidence reference accepted:", typ.Field(i).Name)
		}
	}
}
