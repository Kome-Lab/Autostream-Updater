package registry

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Frozen, unreleased draft v1 is used ONLY to prove rejection without upgrade.
// No production code embeds or applies this historical draft.
//
//go:embed sqlite_migrations/0001_initial.sql
var sqliteTestLegacyV1Migration string

func TestSQLiteLegacyV1AndDirtyBaselineArePreserved(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy-v1-%t", legacy), func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, RegistryDatabaseName)
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			if legacy {
				for _, statement := range strings.Split(sqliteTestLegacyV1Migration, ";") {
					if strings.TrimSpace(statement) != "" {
						sqliteTestExec(t, db, statement)
					}
				}
			} else {
				sqliteTestExec(t, db, registryMigrationLedgerDDL)
				sqliteTestExec(t, db, "INSERT INTO registry_migrations(version,checksum,dirty,target_schema_version) VALUES(?,?,1,?)", RegistryMigrationVersion, RegistryMigrationChecksum(), RegistrySchemaVersion)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before := sqliteTestFiles(t, directory)
			port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: directory, DatabaseName: RegistryDatabaseName})
			if port != nil {
				_ = port.Close()
			}
			if err == nil {
				t.Fatal("old or partially migrated database admitted")
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			migrationErr := MigrateRegistrySchemaV2ForAdministration(context.Background(), db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if migrationErr == nil || !reflect.DeepEqual(before, sqliteTestFiles(t, directory)) {
				t.Fatal("explicit migration upgraded, resumed or changed preserved baseline")
			}
		})
	}
}

func TestSQLiteSchemaNeverStoresContinuityFacts(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	rows, err := fixture.writer.Query("SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	tables := 0
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		tables++
		lower := strings.ToLower(name + " " + definition)
		for _, forbidden := range []string{"witness", "liabilit", "freshness"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("registry stores an independent Continuity responsibility: %s", forbidden)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if tables != 6 {
		t.Fatal("unexpected registry schema")
	}
	var frame string
	if err := fixture.writer.QueryRow("SELECT backend_frame_json FROM resources").Scan(&frame); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(frame), "freshness") {
		t.Fatal("local observation frame persisted independent freshness")
	}
	for _, statement := range []string{
		"INSERT INTO witnesses(outcome_json) VALUES('{}')",
		"INSERT INTO liabilities(liability_id) VALUES('synthetic')",
	} {
		if _, err := fixture.writer.Exec(statement); err == nil {
			t.Fatal("registry accepted a Continuity record")
		}
	}
}

func TestSQLiteUnconnectedContinuityReturnsUnknown(t *testing.T) {
	for _, typedNil := range []bool{false, true} {
		t.Run(fmt.Sprintf("typed-nil-%t", typedNil), func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			if err := fixture.writer.Close(); err != nil {
				t.Fatal(err)
			}
			config := SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName}
			if typedNil {
				var continuity *sqliteTestContinuity
				config.Continuity = continuity
			}
			port, err := OpenSQLiteReadPort(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer port.Close()
			active, _ := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope)
			if active.Knowledge != Unknown || active.Reference != nil || active.Evidence != (Evidence{}) {
				t.Fatal("unconnected Continuity became a current reference proof")
			}
			snapshot, _ := port.ReadExecution(context.Background(), fixture.request)
			if snapshot.Backend.Knowledge != Known || snapshot.Backend.Receipt == nil ||
				snapshot.Current.Knowledge != Unknown || snapshot.Current.Reference != nil ||
				snapshot.Evidence != (Evidence{}) || snapshot.Witness != nil || snapshot.Outstanding != nil {
				t.Fatal("local registry synthesized independent Continuity evidence")
			}
			reader, err := NewReader(port, &readTestAuthorizer{}, &readTestVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			query := LookupRequest{Call: readTestCall(), Request: fixture.request}
			result, _ := reader.LookupExecution(context.Background(), query)
			plan, _ := reader.ReconcilePartialRestore(context.Background(), query)
			if result.Knowledge != Unknown || plan.Knowledge != Unknown || len(plan.Steps) != 0 || plan.OriginalMutationAuthorized {
				t.Fatal("missing Continuity became successful lookup or repair permission")
			}
		})
	}
}

func TestSQLiteIndependentContinuityFailureAndPartialCoverageAreUnknown(t *testing.T) {
	for _, name := range []string{"unknown", "error", "wrong_frame", "no_freshness", "wrong_witness", "partial"} {
		t.Run(name, func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			fixture.continuity.onExecution = func(_ context.Context, request Request, frame BackendReadFrame, _ ExecutionSnapshot) (ContinuityExecutionObservation, error) {
				observation := ContinuityExecutionObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame), Witness: fixture.snapshot.Witness, Outstanding: fixture.snapshot.Outstanding}
				switch name {
				case "unknown", "partial":
					observation.Knowledge = Unknown
				case "error":
					return observation, errors.New("private path " + fixture.path + " SELECT synthetic")
				case "wrong_frame":
					observation.Frame.Generation = "other-generation"
				case "no_freshness":
					observation.Evidence.FreshnessProof = ""
				case "wrong_witness":
					witness := *fixture.snapshot.Witness
					witness.Binding = "other-binding"
					observation.Witness = &witness
				}
				return observation, nil
			}
			port := sqliteTestOpen(t, fixture)
			snapshot, err := port.ReadExecution(context.Background(), fixture.request)
			if snapshot.Backend.Knowledge != Known || snapshot.Current.Knowledge != Unknown ||
				snapshot.Evidence != (Evidence{}) || snapshot.Witness != nil || snapshot.Outstanding != nil {
				t.Fatalf("unqualified Continuity became known: %#v", snapshot)
			}
			if err != nil && (strings.Contains(err.Error(), fixture.path) || strings.Contains(err.Error(), "SELECT")) {
				t.Fatal("private Continuity error leaked")
			}
		})
	}
}

func TestSQLiteContinuityReadsDetachedFactsAfterTransactionEnds(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	projection := readTestRecord(fixture.request, *fixture.snapshot.Backend.Receipt, ExecutorLedger)
	sqliteTestProjection(t, fixture, ExecutorLedger, projection)
	port := sqliteTestOpen(t, fixture)
	var sharedWitness WitnessOutcome
	sharedOutstanding := []ID{"liability-a"}
	fixture.continuity.onReference = func(_ context.Context, scope Scope, frame BackendReadFrame, active ActiveReference) (ContinuityReferenceObservation, error) {
		if port.owner.pool.Stats().InUse != 0 || active.Scope != scope || active.Reference == nil || active.Evidence.FreshnessProof != "" {
			t.Fatal("Continuity reference read held SQL Tx or received invented freshness")
		}
		active.Reference.Revision = "mutated-by-continuity"
		return ContinuityReferenceObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame)}, nil
	}
	active, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope)
	if err != nil || active.Reference == nil || active.Reference.Revision != fixture.snapshot.Current.Reference.Revision {
		t.Fatal("Continuity mutated SQL reference input")
	}
	fixture.continuity.onExecution = func(_ context.Context, request Request, frame BackendReadFrame, snapshot ExecutionSnapshot) (ContinuityExecutionObservation, error) {
		if port.owner.pool.Stats().InUse != 0 || snapshot.StoredRequest == nil || *snapshot.StoredRequest != request ||
			snapshot.Backend.Receipt == nil || snapshot.Ledger.Record == nil ||
			snapshot.Witness != nil || snapshot.Outstanding != nil || snapshot.Evidence.FreshnessProof != "" {
			t.Fatal("Continuity did not receive detached complete SQL facts")
		}
		snapshot.StoredRequest.Binding = "mutated-request"
		snapshot.Backend.Receipt.Binding = "mutated-receipt"
		snapshot.Backend.Receipt.Positive.After.Revision = "mutated-transition"
		snapshot.Current.Reference.Revision = "mutated-current"
		snapshot.Ledger.Record.Binding = "mutated-projection"
		sharedWitness = *fixture.snapshot.Witness
		sharedWitness.Receipt = readCloneReceipt(sharedWitness.Receipt)
		return ContinuityExecutionObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame), Witness: &sharedWitness, Outstanding: sharedOutstanding}, nil
	}
	snapshot, err := port.ReadExecution(context.Background(), fixture.request)
	if err != nil || snapshot.StoredRequest == nil || *snapshot.StoredRequest != fixture.request ||
		snapshot.Backend.Receipt.Binding != fixture.request.Binding || snapshot.Ledger.Record.Binding != fixture.request.Binding ||
		snapshot.Current.Reference.Revision != fixture.snapshot.Current.Reference.Revision || snapshot.Witness == nil {
		t.Fatal("external port rewrote authoritative SQL facts")
	}
	sharedWitness.Receipt.Positive.After.Revision = "late-mutation"
	sharedOutstanding[0] = "late-liability"
	if snapshot.Witness.Receipt.Positive.After.Revision != fixture.snapshot.Witness.Receipt.Positive.After.Revision ||
		snapshot.Outstanding[0] != fixture.snapshot.Outstanding[0] {
		t.Fatal("returned Continuity pointers or slices alias external ownership")
	}
}

func TestSQLiteStoredFrameCannotMintFreshness(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	frame := sqliteTestJSON(t, sqliteTestFrame(fixture.snapshot.Evidence))
	forged := "{\"FreshnessProof\":\"forged-local-proof\"," + frame[1:]
	sqliteTestExec(t, fixture.writer, "UPDATE resources SET backend_frame_json=?", forged)
	called := false
	fixture.continuity.onReference = func(_ context.Context, _ Scope, frame BackendReadFrame, _ ActiveReference) (ContinuityReferenceObservation, error) {
		called = true
		return ContinuityReferenceObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame)}, nil
	}
	port := sqliteTestOpen(t, fixture)
	active, _ := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope)
	if called || active.Knowledge != Unknown || active.Reference != nil {
		t.Fatal("forged SQLite freshness reached qualification")
	}
}

func TestSQLiteTransitionHistoryRejectsMissingOrConflictingCorrelation(t *testing.T) {
	for _, name := range []string{"missing", "wrong_receipt", "wrong_transition", "wrong_after", "indexed_state", "current_behind_history", "negative_with_transition"} {
		t.Run(name, func(t *testing.T) {
			kind := Positive
			if name == "negative_with_transition" {
				kind = Negative
			}
			fixture := sqliteTestNew(t, kind)
			switch name {
			case "missing":
				sqliteTestExec(t, fixture.writer, "DELETE FROM reference_transitions")
			case "wrong_receipt":
				sqliteTestExec(t, fixture.writer, "UPDATE reference_transitions SET receipt_id='wrong-receipt'")
			case "wrong_transition":
				sqliteTestExec(t, fixture.writer, "UPDATE reference_transitions SET transition_id='wrong-transition'")
			case "wrong_after":
				sqliteTestExec(t, fixture.writer, "UPDATE reference_transitions SET after_state_version=?", fmt.Sprintf("%020d", 9))
			case "indexed_state":
				sqliteTestExec(t, fixture.writer, "UPDATE resources SET reference_state_version=?", fmt.Sprintf("%020d", 98))
			case "current_behind_history":
				reference := fixture.request.Command.Expected
				sqliteTestExec(t, fixture.writer, "UPDATE resources SET reference_revision=?,reference_state_version=?,reference_json=?", string(reference.Revision), fmt.Sprintf("%020d", reference.StateVersion), sqliteTestJSON(t, reference))
			case "negative_with_transition":
				args := append(sqliteTestScope(fixture.request.Command.Scope), "unexpected-transition", string(fixture.request.Command.Execution.ExecutionKey), string(fixture.snapshot.Backend.Receipt.ReceiptID), "revision-a", fmt.Sprintf("%020d", 7), "revision-b", fmt.Sprintf("%020d", 8))
				sqliteTestExec(t, fixture.writer, "INSERT INTO reference_transitions(realm,host,resource,backend,transition_id,execution_key,receipt_id,before_revision,before_state_version,after_revision,after_state_version) VALUES(?,?,?,?,?,?,?,?,?,?,?)", args...)
			}
			port := sqliteTestOpen(t, fixture)
			reader, err := NewReader(port, &readTestAuthorizer{}, &readTestVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			result, _ := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: fixture.request})
			if result.Knowledge == Known {
				t.Fatal("history or current-reference inconsistency became known")
			}
		})
	}
}

func TestSQLiteABAHistoryAndUint64StateVersions(t *testing.T) {
	t.Run("ABA-retains-distinct-historical-transition", func(t *testing.T) {
		fixture := sqliteTestNew(t, Positive)
		request := fixture.request
		request.Command.Execution = Execution{RequestID: "request-b", ExecutionKey: "execution-b", OperationID: "operation-b", AttemptID: "attempt-b", StepID: "step-b"}
		request.Command.Expected = fixture.snapshot.Backend.Receipt.Positive.After
		request.Command.CandidateRevision = fixture.snapshot.Backend.Receipt.Positive.Before.Revision
		request.Command.CandidateContentPin = "content-pin-return"
		var err error
		request.Binding, err = CanonicalBinding(request.Command)
		if err != nil {
			t.Fatal(err)
		}
		receipt := readCloneReceipt(*fixture.snapshot.Backend.Receipt)
		receipt.Execution, receipt.Binding = request.Command.Execution, request.Binding
		receipt.ReceiptID, receipt.CommitID = "receipt-b", "commit-b"
		receipt.Positive = &PositivePayload{TransitionID: "transition-b", Before: request.Command.Expected, After: Reference{Revision: request.Command.CandidateRevision, StateVersion: 9}, Semantic: ReferenceCommittedNotServiceApplied}
		sqliteTestInsertExecution(t, fixture.writer, request, &receipt)
		current := receipt.Positive.After
		sqliteTestExec(t, fixture.writer, "UPDATE resources SET reference_revision=?,reference_state_version=?,reference_json=?", string(current.Revision), fmt.Sprintf("%020d", current.StateVersion), sqliteTestJSON(t, current))
		port := sqliteTestOpen(t, fixture)
		snapshot, err := port.ReadExecution(context.Background(), fixture.request)
		if err != nil || snapshot.Backend.Knowledge != Known || snapshot.Backend.Receipt.Positive.TransitionID != "transition-a" ||
			snapshot.Backend.Receipt.Positive.Before.StateVersion != 7 || snapshot.Backend.Receipt.Positive.After.StateVersion != 8 ||
			snapshot.Current.Reference == nil || *snapshot.Current.Reference != current {
			t.Fatal("ABA confused the historical receipt with the current reference")
		}
	})
	t.Run("full-unsigned64-boundary", func(t *testing.T) {
		fixture := sqliteTestNew(t, Positive)
		sqliteTestExec(t, fixture.writer, "DELETE FROM reference_transitions")
		sqliteTestExec(t, fixture.writer, "DELETE FROM executions")
		request := fixture.request
		request.Command.Expected.StateVersion = ^uint64(0) - 1
		var err error
		request.Binding, err = CanonicalBinding(request.Command)
		if err != nil {
			t.Fatal(err)
		}
		receipt := readCloneReceipt(*fixture.snapshot.Backend.Receipt)
		receipt.Binding = request.Binding
		receipt.Positive.Before = request.Command.Expected
		receipt.Positive.After.StateVersion = ^uint64(0)
		sqliteTestInsertExecution(t, fixture.writer, request, &receipt)
		current := receipt.Positive.After
		sqliteTestExec(t, fixture.writer, "UPDATE resources SET reference_revision=?,reference_state_version=?,reference_json=?", string(current.Revision), fmt.Sprintf("%020d", current.StateVersion), sqliteTestJSON(t, current))
		fixture.request = request
		witness := *fixture.snapshot.Witness
		witness.Binding, witness.Receipt = request.Binding, readCloneReceipt(receipt)
		fixture.continuity.witness = &witness
		port := sqliteTestOpen(t, fixture)
		snapshot, err := port.ReadExecution(context.Background(), request)
		if err != nil || snapshot.Backend.Knowledge != Known || snapshot.Current.Reference == nil ||
			snapshot.Current.Reference.StateVersion != ^uint64(0) || snapshot.Backend.Receipt.Positive.After.StateVersion != ^uint64(0) {
			t.Fatal("SQLite representation narrowed uint64 state versions to signed integers")
		}
	})
}

func TestSQLiteBusyReadFailsClosedAndCanBeReadAfterUnlock(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	projection := readTestRecord(fixture.request, *fixture.snapshot.Backend.Receipt, ExecutorLedger)
	sqliteTestProjection(t, fixture, ExecutorLedger, projection)
	port := sqliteTestOpen(t, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := sqliteTestStartWriter(t, ctx, fixture.path, "lock")
	child.next(t, "ready")
	child.send(t, "begin")
	child.next(t, "locked")
	snapshot, err := port.ReadExecution(ctx, fixture.request)
	if err == nil || snapshot.Backend.Knowledge == Known ||
		strings.Contains(err.Error(), fixture.path) || strings.Contains(strings.ToLower(err.Error()), "database is locked") {
		t.Fatal("locked database became known or leaked a raw SQLite error")
	}
	child.send(t, "release")
	child.next(t, "released")
	snapshot, err = port.ReadExecution(ctx, fixture.request)
	if err != nil || snapshot.Backend.Knowledge != Known {
		t.Fatal("explicit read after lock release failed")
	}
	child.stop(t)
}

func TestSQLiteCorruptDatabaseDoesNotLeakOrRepair(t *testing.T) {
	for _, validHeader := range []bool{false, true} {
		t.Run(fmt.Sprintf("valid-header-%t", validHeader), func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			if err := fixture.writer.Close(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			if validHeader {
				// Page one's B-tree type is corrupted while the SQLite header stays valid.
				data[100] = 0
			} else {
				copy(data[:16], []byte("synthetic-bad-db!"))
			}
			if err := os.WriteFile(fixture.path, data, 0600); err != nil {
				t.Fatal(err)
			}
			before := sqliteTestFiles(t, fixture.directory)
			port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName})
			if port != nil {
				_ = port.Close()
			}
			if err == nil || strings.Contains(err.Error(), fixture.path) || !strings.HasPrefix(err.Error(), "registry_") ||
				!reflect.DeepEqual(before, sqliteTestFiles(t, fixture.directory)) {
				t.Fatal("corrupt database was admitted, exposed or changed")
			}
		})
	}
}

func TestSQLiteScopeAndIndexedPayloadMismatchCannotBecomeKnown(t *testing.T) {
	for _, name := range []string{"receipt_scope", "stored_scope", "receipt_kind", "indexed_revision"} {
		t.Run(name, func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			switch name {
			case "receipt_scope":
				receipt := readCloneReceipt(*fixture.snapshot.Backend.Receipt)
				receipt.Scope.Host = "wrong-host"
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET receipt_json=?", sqliteTestJSON(t, receipt))
			case "stored_scope":
				request := fixture.request
				request.Command.Scope.Host = "wrong-host"
				var err error
				request.Binding, err = CanonicalBinding(request.Command)
				if err != nil {
					t.Fatal(err)
				}
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET request_json=?", sqliteTestJSON(t, request))
			case "receipt_kind":
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET receipt_kind='negative'")
			case "indexed_revision":
				sqliteTestExec(t, fixture.writer, "UPDATE resources SET reference_revision='wrong-indexed-revision'")
			}
			port := sqliteTestOpen(t, fixture)
			reader, err := NewReader(port, &readTestAuthorizer{}, &readTestVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			result, _ := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: fixture.request})
			if result.Knowledge == Known {
				t.Fatal("scope or indexed payload mismatch became a qualified observation")
			}
		})
	}
}

func TestSQLiteCancellationDuringIndependentContinuityIsPreserved(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(fmt.Sprintf("execution-%t", execution), func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			port := sqliteTestOpen(t, fixture)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture.continuity.onReference = func(_ context.Context, _ Scope, frame BackendReadFrame, _ ActiveReference) (ContinuityReferenceObservation, error) {
				cancel()
				return ContinuityReferenceObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame)}, nil
			}
			fixture.continuity.onExecution = func(_ context.Context, _ Request, frame BackendReadFrame, _ ExecutionSnapshot) (ContinuityExecutionObservation, error) {
				cancel()
				return ContinuityExecutionObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame)}, nil
			}
			if execution {
				result, err := port.ReadExecution(ctx, fixture.request)
				if !errors.Is(err, context.Canceled) || result.Evidence != (Evidence{}) || result.Witness != nil {
					t.Fatal("cancellation after external execution qualification was lost")
				}
			} else {
				result, err := port.ReadActiveReference(ctx, fixture.request.Command.Scope)
				if !errors.Is(err, context.Canceled) || result.Knowledge != Unknown {
					t.Fatal("cancellation after external reference qualification was lost")
				}
			}
		})
	}
}
