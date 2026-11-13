package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	evidence "github.com/Kome-Lab/Autostream-Contracts/v3evidence"
	"math"
	"reflect"
	"strings"
	"testing"
)

const legacyCanonicalGolden = `{"Schema":1,"Operation":"registry.reference_only","Scope":{"Realm":"realm","Host":"host","Resource":"resource","Backend":"backend"},"Execution":{"RequestID":"request","ExecutionKey":"execution","OperationID":"operation","AttemptID":"attempt","StepID":"step"},"RequestingPrincipal":"operator","AuthorizationIssuer":"cp","CandidateRevision":"revision-1","CandidateContentPin":"pin-1","Expected":{"Revision":"revision-0","StateVersion":0},"RequiredGuard":{"Policy":"policy","Trust":"trust","Membership":"membership","OwnershipEpoch":"owner-1","FenceEpoch":"fence-1","Generation":"generation-1","BootID":"boot-1","ProcessIncarnation":"process-1"},"Timing":{"TimeBase":"clock-1","DeadlineTick":1000},"OriginalBudget":"budget-1"}`

func TestCanonicalAdapterLegacyGolden(t *testing.T) {
	c := validationValidCommand()
	b, err := CanonicalBinding(c)
	if err != nil || string(b) != legacyCanonicalGolden {
		t.Fatal("fixed pre-adapter golden changed", err)
	}
	wire := []byte("{\"Command\":" + legacyCanonicalGolden + ",\"Binding\":" + strconvQuoteGolden(t, legacyCanonicalGolden) + "}")
	got, err := DecodeRequest(wire)
	if err != nil || got.Command != c || got.Binding != b {
		t.Fatal("legacy wire changed", err)
	}
	out, err := json.Marshal(got)
	if err != nil || !bytes.Equal(wire, out) {
		t.Fatal("legacy representation changed")
	}
}
func strconvQuoteGolden(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func TestCanonicalAdapterRoundTripAndEverySemanticField(t *testing.T) {
	base := validationValidCommand()
	original, err := CanonicalBinding(base)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	var visit func(reflect.Type, []int, string)
	visit = func(typ reflect.Type, idx []int, name string) {
		for n := 0; n < typ.NumField(); n++ {
			f := typ.Field(n)
			next := append(append([]int(nil), idx...), n)
			label := name + f.Name
			if f.Type.Kind() == reflect.Struct {
				visit(f.Type, next, label+".")
				continue
			}
			if label == "Schema" || label == "Operation" {
				continue
			}
			count++
			t.Run(label, func(t *testing.T) {
				c := base
				v := reflect.ValueOf(&c).Elem().FieldByIndex(next)
				if v.Kind() == reflect.String {
					v.SetString(v.String() + "-different")
				} else if v.Kind() == reflect.Uint64 {
					v.SetUint(v.Uint() + 1)
				} else {
					t.Fatal("unhandled scalar")
				}
				if got := registryCommand(sharedCommand(c)); got != c {
					t.Fatal("lossy typed conversion")
				}
				b, err := CanonicalBinding(c)
				if err != nil || b == original {
					t.Fatal("meaning omitted", err)
				}
				// Independent pre-adapter encoder reference: original registry types had
				// no JSON methods/tags; actual old algorithm was json.Marshal(Command).
				old, err := json.Marshal(c)
				if err != nil || string(b) != string(old) {
					t.Fatal("old baseline bytes differ", err)
				}
				if err := ValidateRequest(Request{Command: c, Binding: original}); !IsCode(err, CodeBindingConflict) {
					t.Fatal("stale binding accepted", err)
				}
				raw, _ := json.Marshal(Request{c, b})
				r, err := DecodeRequest(raw)
				if err != nil || r != (Request{c, b}) {
					t.Fatal("wire roundtrip lost field", err)
				}
			})
		}
	}
	visit(reflect.TypeOf(base), nil, "")
	if count != 26 {
		t.Fatal("field denominator changed", count)
	}
	for _, name := range []string{"schema", "operation"} {
		t.Run(name, func(t *testing.T) {
			c := base
			if name == "schema" {
				c.Schema = 2
			} else {
				c.Operation = "shell.run"
			}
			if _, err := CanonicalBinding(c); !IsCode(err, CodeInvalid) {
				t.Fatal("unsupported command accepted")
			}
		})
	}
}
func TestCanonicalAdapterNumericBoundaries(t *testing.T) {
	for _, n := range []uint64{0, 1, 1<<53 + 1, 1 << 63, math.MaxUint64 - 1} {
		c := validationValidCommand()
		c.Expected.StateVersion = n
		c.Timing.DeadlineTick = math.MaxUint64
		b, err := CanonicalBinding(c)
		if err != nil {
			t.Fatal(err)
		}
		wire, _ := json.Marshal(Request{c, b})
		r, err := DecodeRequest(wire)
		if err != nil || r.Command.Expected.StateVersion != n || r.Command.Timing.DeadlineTick != math.MaxUint64 {
			t.Fatal("uint64 narrowed", err)
		}
	}
	for _, n := range []string{"state-overflow", "zero-deadline"} {
		c := validationValidCommand()
		if n == "state-overflow" {
			c.Expected.StateVersion = math.MaxUint64
		} else {
			c.Timing.DeadlineTick = 0
		}
		if _, err := CanonicalBinding(c); !IsCode(err, CodeInvalid) {
			t.Fatal(n, err)
		}
	}
}
func TestCanonicalAdapterStrictDecode(t *testing.T) {
	raw := validationJSON(t)
	cases := map[string]string{
		"extra":         strings.Replace(raw, "\"Schema\":1", "\"Extra\":0,\"Schema\":1", 1),
		"missing":       strings.Replace(raw, ",\"StateVersion\":0", "", 1),
		"null":          strings.Replace(raw, "\"Schema\":1", "\"Schema\":null", 1),
		"case":          strings.Replace(raw, "\"Command\":", "\"command\":", 1),
		"duplicate":     strings.Replace(raw, "\"Schema\":1", "\"Schema\":1,\"Schema\":1", 1),
		"escaped-alias": strings.Replace(raw, "\"Schema\":1", "\"Schema\":1,\"\\u0053chema\":1", 1),
		"fraction":      strings.Replace(raw, "\"Schema\":1", "\"Schema\":1.0", 1),
		"exponent":      strings.Replace(raw, "\"Schema\":1", "\"Schema\":1e0", 1),
		"signed":        strings.Replace(raw, "\"Schema\":1", "\"Schema\":-1", 1),
		"uint-overflow": strings.Replace(raw, "\"DeadlineTick\":1000", "\"DeadlineTick\":18446744073709551616", 1),
		"utf8":          string([]byte{0xff}), "trailing": raw + "{}", "over-size": strings.Repeat(" ", maxRequestBytes+1),
	}
	for n, wire := range cases {
		t.Run(n, func(t *testing.T) {
			r, err := DecodeRequest([]byte(wire))
			if err == nil || r != (Request{}) {
				t.Fatal("shared refusal became Request")
			}
		})
	}
	for _, wire := range []string{
		strings.Replace(raw, "\"Scope\":", "\"Scop\\u0065\":", 1),
		strings.Replace(raw, "\"Realm\":\"realm\"", "\"Realm\":\"r\\u0065alm\"", 1),
		strings.Repeat(" ", maxRequestBytes-len(raw)) + raw,
	} {
		r, err := DecodeRequest([]byte(wire))
		if err != nil || r != validationValidRequest(t) {
			t.Fatal("legacy accepted form changed", err)
		}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &obj) != nil {
		t.Fatal("fixture")
	}
	reordered := "{\"Binding\":" + string(obj["Binding"]) + ",\"Command\":" + string(obj["Command"]) + "}"
	if r, err := DecodeRequest([]byte(reordered)); err != nil || r != validationValidRequest(t) {
		t.Fatal("field-order compatibility", err)
	}
}
func TestCanonicalAdapterBindingErrorCompatibility(t *testing.T) {
	original := validationValidRequest(t)
	for _, tc := range []struct {
		name string
		b    Binding
		code Code
	}{
		{"empty", "", CodeInvalid}, {"oversize", Binding(strings.Repeat("x", maxRequestBytes+1)), CodeInvalid},
		{"invalid-utf8", Binding(string([]byte{0xff})), CodeInvalid}, {"mismatch", "different", CodeBindingConflict},
		{"rune-error-typed", "\ufffd", CodeBindingConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := original
			r.Binding = tc.b
			var e *Error
			err := ValidateRequest(r)
			if !errors.As(err, &e) || e.Code != tc.code || e.Field != "request.binding" {
				t.Fatal("legacy typed error changed", err)
			}
		})
	}
	for _, b := range []Binding{"", "different"} {
		r := original
		r.Binding = b
		raw, _ := json.Marshal(r)
		_, err := DecodeRequest(raw)
		want := CodeInvalid
		if b != "" {
			want = CodeBindingConflict
		}
		var e *Error
		if !errors.As(err, &e) || e.Code != want || e.Field != "request.binding" {
			t.Fatal("wire binding classification changed", err)
		}
	}
	for _, b := range []string{"\\ufffd", "\\ud800"} {
		wire := validationOuterValue(t, validationJSON(t), "Binding", "\""+b+"\"")
		_, err := DecodeRequest([]byte(wire))
		if !IsCode(err, CodeInvalid) {
			t.Fatal("shared structural Unicode refusal changed", err)
		}
	}
}
func TestCanonicalAdapterDiagnosticsCannotAccept(t *testing.T) {
	for _, err := range []error{nil, errors.New("request_binding"), &evidence.Error{Code: "future_code"}, &evidence.Error{Code: "encoding"}, &evidence.Error{Code: "request_binding"}} {
		for _, raw := range [][]byte{nil, []byte("{"), []byte("{}"), []byte(validationJSON(t)), bytes.Repeat([]byte(" "), maxRequestBytes+1)} {
			if decodeContractError(err, raw) == nil {
				t.Fatal("diagnostic accepted")
			}
		}
		if commandContractError(err, validationValidCommand()) == nil {
			t.Fatal("unknown error became valid command")
		}
	}
}
