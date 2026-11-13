package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type canonicalDiagnosticCase struct {
	Name   string
	Wire   []byte
	Code   Code
	Field  string
	Status PreflightStatus
}

// This corpus also runs unchanged against fixed old and pre-diagnostic C10
// checkouts. Expected Codes/Statuses are the old public C10 contract.
func canonicalDiagnosticCases(t *testing.T) []canonicalDiagnosticCase {
	t.Helper()
	command, err := json.Marshal(validationValidCommand())
	if err != nil {
		t.Fatal(err)
	}
	cmd := string(command)
	makeWire := func(c, b, suffix string, first bool) []byte {
		if first {
			return []byte(`{"Binding":` + b + `,"Command":` + c + suffix + `}`)
		}
		return []byte(`{"Command":` + c + `,"Binding":` + b + suffix + `}`)
	}
	var cases []canonicalDiagnosticCase
	unicode := []struct{ name, value string }{
		{"literal-replacement", string([]byte{'"', 0xef, 0xbf, 0xbd, '"'})},
		{"escaped-replacement", `"\ufffd"`},
		{"high-surrogate", `"\ud800"`},
		{"low-surrogate", `"\udfff"`},
	}
	for _, b := range unicode {
		for _, first := range []bool{false, true} {
			order := "command-first"
			if first {
				order = "binding-first"
			}
			name := b.name + "/" + order
			cases = append(cases, canonicalDiagnosticCase{name + "/only", makeWire(cmd, b.value, "", first), CodeBindingConflict, "request.binding", PreflightConflict})
			badCommands := []struct{ name, old, new string }{
				{"unknown-command", `"Schema":1`, `"private-unknown-key":"private-value","Schema":1`},
				{"unknown-scope", `"Realm":"realm"`, `"private-unknown-key":0,"Realm":"realm"`},
				{"duplicate", `"Schema":1`, `"Schema":1,"Schema":1`},
				{"escaped-duplicate", `"Schema":1`, `"Schema":1,"\u0053chema":1`},
				{"missing", `,"StateVersion":0`, ""},
				{"missing-command-field", `,"OriginalBudget":"budget-1"`, ""},
				{"identity", `"Realm":"realm"`, `"Realm":"UPPER"`},
				{"unicode-identity", `"Realm":"realm"`, `"Realm":"\ufffd"`},
				{"schema", `"Schema":1`, `"Schema":2`},
				{"operation", `"Operation":"registry.reference_only"`, `"Operation":"shell.run"`},
				{"schema-overflow", `"Schema":1`, `"Schema":4294967296`},
				{"max-state", `"StateVersion":0`, `"StateVersion":18446744073709551615`},
				{"state-overflow", `"StateVersion":0`, `"StateVersion":18446744073709551616`},
				{"deadline-zero", `"DeadlineTick":1000`, `"DeadlineTick":0`},
				{"fraction", `"DeadlineTick":1000`, `"DeadlineTick":1.0`},
				{"exponent", `"DeadlineTick":1000`, `"DeadlineTick":1e3`},
				{"signed", `"StateVersion":0`, `"StateVersion":-0`},
				{"null", `"Schema":1`, `"Schema":null`},
				{"wrong-type", `"Schema":1`, `"Schema":"1"`},
			}
			for _, change := range badCommands {
				bad := strings.Replace(cmd, change.old, change.new, 1)
				if bad == cmd {
					t.Fatal("mutation missed its field", change.name)
				}
				cases = append(cases, canonicalDiagnosticCase{name + "/" + change.name, makeWire(bad, b.value, "", first), CodeInvalid, "", PreflightRejected})
			}
			for _, suffix := range []struct{ name, value string }{
				{"unknown-root", `,"private-unknown-key":"private-value"`},
				{"duplicate-root", `,"Command":` + cmd},
				{"duplicate-binding-alias", `,"\u0042inding":"other"`},
			} {
				cases = append(cases, canonicalDiagnosticCase{name + "/" + suffix.name, makeWire(cmd, b.value, suffix.value, first), CodeInvalid, "", PreflightRejected})
			}
			for _, tail := range []string{"{}", "0"} {
				cases = append(cases, canonicalDiagnosticCase{name + "/trailing-" + tail, append(makeWire(cmd, b.value, "", first), []byte(tail)...), CodeInvalid, "", PreflightRejected})
			}
		}
	}
	for _, b := range []struct {
		name, value string
		code        Code
		field       string
		status      PreflightStatus
	}{
		{"empty", `""`, CodeInvalid, "request.binding", PreflightRejected},
		{"mismatch", `"other"`, CodeBindingConflict, "request.binding", PreflightConflict},
		{"null", `null`, CodeInvalid, "", PreflightRejected},
		{"number", `1`, CodeInvalid, "", PreflightRejected},
		{"object", `{}`, CodeInvalid, "", PreflightRejected},
		{"array", `[]`, CodeInvalid, "", PreflightRejected},
		{"boolean", `false`, CodeInvalid, "", PreflightRejected},
	} {
		cases = append(cases, canonicalDiagnosticCase{"binding-" + b.name, makeWire(cmd, b.value, "", false), b.code, b.field, b.status})
	}
	cases = append(cases,
		canonicalDiagnosticCase{"raw-invalid-utf8", makeWire(cmd, string([]byte{'"', 0xff, '"'}), "", true), CodeInvalid, "", PreflightRejected},
		canonicalDiagnosticCase{"missing-command", []byte(`{"Binding":"\ufffd"}`), CodeInvalid, "", PreflightRejected},
		canonicalDiagnosticCase{"missing-binding", []byte(`{"Command":` + cmd + `}`), CodeInvalid, "", PreflightRejected},
		canonicalDiagnosticCase{"wrong-case", []byte(`{"Binding":"\ufffd","command":` + cmd + `}`), CodeInvalid, "", PreflightRejected},
		canonicalDiagnosticCase{"over-size", bytes.Repeat([]byte(" "), maxRequestBytes+1), CodeInvalid, "", PreflightRejected},
		canonicalDiagnosticCase{"depth", []byte(`{"Binding":` + strings.Repeat("[", 40) + `"\ufffd"` + strings.Repeat("]", 40) + `,"Command":` + cmd + `}`), CodeInvalid, "", PreflightRejected},
	)
	return cases
}

func canonicalDiagnosticReject(t *testing.T, tc canonicalDiagnosticCase) (Code, string, PreflightResult) {
	t.Helper()
	request, err := DecodeRequest(tc.Wire)
	var failure *Error
	if err == nil || request != (Request{}) || !errors.As(err, &failure) {
		t.Fatal("refusal produced a Request", err)
	}
	authorizer := &readTestAuthorizer{}
	guard := &sqlitePreflightGuard{}
	verifier := &sqlitePreflightVerifier{}
	owner := &registryLifecycleOwner{}
	port := &SQLiteReadPort{owner: owner}
	preflight, err := NewConditionalCommitPreflight(port, authorizer, verifier, guard)
	if err != nil {
		t.Fatal(err)
	}
	result, checkErr := preflight.CheckEncoded(context.Background(), readTestCall(), tc.Wire)
	if checkErr == nil || !IsCode(checkErr, failure.Code) || result.Reason != "request_invalid" ||
		result.Scope != (Scope{}) || result.Execution != (Execution{}) || result.Binding != "" ||
		result.AuthorizesMutation() || result.ReusableForCommit() {
		t.Fatal("encoded refusal crossed the decode boundary", result, checkErr)
	}
	if len(authorizer.targets) != 0 || guard.calls != 0 || verifier.guardChecks != 0 || verifier.continuityChecks != 0 ||
		verifier.receiptChecks != 0 || verifier.witnessChecks != 0 || verifier.readTestVerifier.receipts != 0 ||
		verifier.snapshots != 0 || verifier.witnesses != 0 || owner.activeOperations != 0 || owner.observationVersion != 0 ||
		owner.readOperations != 0 || owner.readConnections != 0 || owner.readTransactions != 0 {
		t.Fatal("refusal reached authority, registry borrow, Guard, Continuity or verification")
	}
	// A nil receiver would make Check return invalid_context. This proves that
	// an encoded refusal returns before Check even when all downstream ports are absent.
	var absent *ConditionalCommitPreflight
	rejected, absentErr := absent.CheckEncoded(context.Background(), readTestCall(), tc.Wire)
	if absentErr == nil || !IsCode(absentErr, failure.Code) || rejected != result {
		t.Fatal("refusal entered Check", absentErr, rejected)
	}
	return failure.Code, failure.Field, result
}

func TestCanonicalAdapterDiagnosticPreflight(t *testing.T) {
	for _, tc := range canonicalDiagnosticCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			code, field, result := canonicalDiagnosticReject(t, tc)
			if code != tc.Code || result.Status != tc.Status || tc.Field != "" && field != tc.Field {
				t.Fatalf("old C10 rejection changed: code=%s field=%s status=%s; want %s/%s", code, field, result.Status, tc.Code, tc.Status)
			}
		})
	}
	t.Run("context-priority", func(t *testing.T) {
		var absent *ConditionalCommitPreflight
		wire := canonicalDiagnosticCases(t)[0].Wire
		result, err := absent.CheckEncoded(nil, readTestCall(), wire)
		if !IsCode(err, CodeInvalid) || result.Status != PreflightRejected || result.Reason != "invalid_context" {
			t.Fatal(result, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err = absent.CheckEncoded(ctx, readTestCall(), wire)
		if !errors.Is(err, context.Canceled) || result.Status != PreflightUnknown || result.Reason != "context_canceled" {
			t.Fatal(result, err)
		}
	})
}
