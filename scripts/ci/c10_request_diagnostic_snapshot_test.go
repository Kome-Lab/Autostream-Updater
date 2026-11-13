//go:build c10_request_diagnostic_snapshot

package registry

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type c10DiagnosticObservation struct {
	Name     string
	Code     Code
	Field    string
	Status   PreflightStatus
	Reason   string
	WireHash [32]byte
	Value    []byte
}

// Copied unchanged into fixed 6f71, pre-diagnostic a697 and final C10. Each
// refusal runs the real DecodeRequest and CheckEncoded with downstream counters.
func TestC10RequestDiagnosticSnapshot(t *testing.T) {
	target := os.Getenv("C10_DIAGNOSTIC_SNAPSHOT")
	if !filepath.IsAbs(target) {
		t.Fatal("explicit synthetic snapshot path required")
	}
	var rows []c10DiagnosticObservation
	for _, tc := range canonicalDiagnosticCases(t) {
		code, field, result := canonicalDiagnosticReject(t, tc)
		rows = append(rows, c10DiagnosticObservation{Name: tc.Name, Code: code, Field: field, Status: result.Status, Reason: result.Reason, WireHash: sha256.Sum256(tc.Wire)})
	}
	raw := []byte(validationJSON(t))
	normal, err := DecodeRequest(raw)
	if err != nil || normal != validationValidRequest(t) {
		t.Fatal("normal decoder changed", err)
	}
	value, err := json.Marshal(normal)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, c10DiagnosticObservation{Name: "normal", WireHash: sha256.Sum256(raw), Value: value})
	value, err = json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(target, value, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("C10 request/real CheckEncoded snapshot: %d observations", len(rows))
}
