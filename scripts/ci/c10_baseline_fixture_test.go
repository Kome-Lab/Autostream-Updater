//go:build c10_baseline_fixture

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type baselineManifest struct {
	Request  Request
	Snapshot ExecutionSnapshot
	Lookup   LookupResult
	Plan     ReconciliationPlan
	DBHash   [32]byte
}

func baselineDirectory(t *testing.T) string {
	t.Helper()
	d := os.Getenv("C10_BASELINE_DIR")
	if !filepath.IsAbs(d) {
		t.Fatal("explicit synthetic directory required")
	}
	return d
}
func TestC10BaselineExport(t *testing.T) {
	root := baselineDirectory(t)
	for _, kind := range []ReceiptKind{Positive, Negative} {
		f := sqliteTestNew(t, kind)
		port := sqliteTestOpen(t, f)
		snapshot, err := port.ReadExecution(context.Background(), f.request)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := NewReader(port, &readTestAuthorizer{}, &readTestVerifier{})
		if err != nil {
			t.Fatal(err)
		}
		q := LookupRequest{Call: readTestCall(), Request: f.request}
		lookup, err := reader.LookupExecution(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := reader.ReconcilePartialRestore(context.Background(), q)
		if err != nil || plan.OriginalMutationAuthorized {
			t.Fatal(err)
		}
		if snapshot.StoredRequest == nil || snapshot.Backend.Knowledge != Known || snapshot.Backend.Receipt == nil || snapshot.Backend.Receipt.Kind != kind || lookup.Backend.Knowledge != Known || plan.Knowledge != Known || len(plan.Steps) != 3 {
			t.Fatal("baseline must export known positive/negative records and a qualified read-only plan")
		}
		if err = port.Close(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, string(kind))
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, RegistryDatabaseName), raw, 0600); err != nil {
			t.Fatal(err)
		}
		manifest := baselineManifest{f.request, snapshot, lookup, plan, sha256.Sum256(raw)}
		body, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, string(kind)+".json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("fixed pre-adapter C10 exported actual SQLite records; verifier/Continuity are synthetic")
}
func TestC10BaselineImport(t *testing.T) {
	root := baselineDirectory(t)
	for _, kind := range []ReceiptKind{Positive, Negative} {
		t.Run(string(kind), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, string(kind)+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var m baselineManifest
			if json.Unmarshal(raw, &m) != nil {
				t.Fatal("manifest")
			}
			binding, err := CanonicalBinding(m.Request.Command)
			if err != nil || binding != m.Request.Binding {
				t.Fatal("old Binding needs rewriting", err)
			}
			dir := filepath.Join(root, string(kind))
			before := sqliteTestFiles(t, dir)
			dbBytes, err := os.ReadFile(filepath.Join(dir, RegistryDatabaseName))
			if err != nil || sha256.Sum256(dbBytes) != m.DBHash {
				t.Fatal("baseline artifact changed")
			}
			continuity := &sqliteTestContinuity{witness: m.Snapshot.Witness, outstanding: m.Snapshot.Outstanding}
			port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: dir, DatabaseName: RegistryDatabaseName, Continuity: continuity})
			if err != nil {
				t.Fatal(err)
			}
			got, err := port.ReadExecution(context.Background(), m.Request)
			if err != nil || !reflect.DeepEqual(got, m.Snapshot) {
				t.Fatal("stored Request/Receipt changed", err)
			}
			reader, err := NewReader(port, &readTestAuthorizer{}, &readTestVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			q := LookupRequest{Call: readTestCall(), Request: m.Request}
			lookup, err := reader.LookupExecution(context.Background(), q)
			if err != nil || !reflect.DeepEqual(lookup, m.Lookup) {
				t.Fatal("lookup changed", err)
			}
			plan, err := reader.ReconcilePartialRestore(context.Background(), q)
			if err != nil || !reflect.DeepEqual(plan, m.Plan) || plan.OriginalMutationAuthorized {
				t.Fatal("reconciliation changed", err)
			}
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err = reader.LookupExecution(cancelled, q); err == nil {
				t.Fatal("cancelled lookup succeeded")
			}
			if err = port.Close(); err != nil {
				t.Fatal(err)
			}
			afterBytes, err := os.ReadFile(filepath.Join(dir, RegistryDatabaseName))
			if err != nil || !bytes.Equal(dbBytes, afterBytes) || !reflect.DeepEqual(before, sqliteTestFiles(t, dir)) {
				t.Fatal("candidate changed old DB bytes/metadata")
			}
		})
	}
	t.Log("candidate reads old real SQLite records without migration/rewrite; synthetic verifier/Continuity only")
}
