package registry

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// SQL is confined to synthetic test fixtures; no real DB, credential or provider
// is used. These helpers are not part of the product read-port interface.
type sqliteTestFixture struct {
	directory  string
	path       string
	writer     *sql.DB
	request    Request
	snapshot   ExecutionSnapshot
	continuity *sqliteTestContinuity
}

func sqliteTestJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func sqliteTestExec(t *testing.T, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), statement, args...); err != nil {
		t.Fatalf("synthetic fixture statement failed: %v", err)
	}
}

func sqliteTestScope(scope Scope) []any {
	return []any{string(scope.Realm), string(scope.Host), string(scope.Resource), string(scope.Backend)}
}

func sqliteTestExecution(request Request) []any {
	return append(sqliteTestScope(request.Command.Scope), string(request.Command.Execution.ExecutionKey))
}

// sqliteTestContinuity is an independent in-memory test double. It is never
// persisted in the registry and does not implement a production Witness store.
type sqliteTestContinuity struct {
	witness     *WitnessOutcome
	outstanding []ID
	onReference func(context.Context, Scope, BackendReadFrame, ActiveReference) (ContinuityReferenceObservation, error)
	onExecution func(context.Context, Request, BackendReadFrame, ExecutionSnapshot) (ContinuityExecutionObservation, error)
}

func sqliteTestFrame(e Evidence) BackendReadFrame {
	return BackendReadFrame{Issuer: e.Issuer, ServingIncarnation: e.ServingIncarnation, Generation: e.Generation, SnapshotID: e.SnapshotID, ObservationProof: e.ObservationProof}
}

func sqliteTestEvidence(frame BackendReadFrame) Evidence {
	return Evidence{Issuer: frame.Issuer, ServingIncarnation: frame.ServingIncarnation, Generation: frame.Generation, SnapshotID: frame.SnapshotID, ObservationProof: frame.ObservationProof, FreshnessProof: "independent-freshness-proof"}
}

func (p *sqliteTestContinuity) QualifyReference(ctx context.Context, scope Scope, frame BackendReadFrame, active ActiveReference) (ContinuityReferenceObservation, error) {
	if p.onReference != nil {
		return p.onReference(ctx, scope, frame, active)
	}
	if err := ctx.Err(); err != nil {
		return ContinuityReferenceObservation{}, err
	}
	return ContinuityReferenceObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame)}, nil
}

func (p *sqliteTestContinuity) QualifyExecution(ctx context.Context, request Request, frame BackendReadFrame, snapshot ExecutionSnapshot) (ContinuityExecutionObservation, error) {
	if p.onExecution != nil {
		return p.onExecution(ctx, request, frame, snapshot)
	}
	if err := ctx.Err(); err != nil {
		return ContinuityExecutionObservation{}, err
	}
	observation := ContinuityExecutionObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame)}
	if p.witness != nil && p.witness.Scope == request.Command.Scope && p.witness.Execution == request.Command.Execution && p.witness.Binding == request.Binding {
		witness := *p.witness
		witness.Receipt = readCloneReceipt(witness.Receipt)
		observation.Witness = &witness
		observation.Outstanding = append([]ID(nil), p.outstanding...)
	} else if p.witness != nil && p.witness.Scope == (Scope{}) {
		// Deliberately malformed independent data for the fail-closed test.
		observation.Witness = p.witness
	}
	return observation, nil
}

func sqliteTestResource(t *testing.T, db *sql.DB, scope Scope, knowledge Knowledge, reference *Reference, evidence Evidence) {
	t.Helper()
	var revision, stateVersion, rawReference any
	if reference != nil {
		revision, stateVersion, rawReference = string(reference.Revision), fmt.Sprintf("%020d", reference.StateVersion), sqliteTestJSON(t, reference)
	}
	args := append(sqliteTestScope(scope), string(knowledge), revision, stateVersion, rawReference, sqliteTestJSON(t, sqliteTestFrame(evidence)))
	sqliteTestExec(t, db, "INSERT INTO resources(realm,host,resource,backend,active_knowledge,reference_revision,reference_state_version,reference_json,backend_frame_json) VALUES(?,?,?,?,?,?,?,?,?)", args...)
}

func sqliteTestInsertExecution(t *testing.T, db *sql.DB, request Request, receipt *Receipt) {
	t.Helper()
	execution := request.Command.Execution
	var kind, payload any
	knowledge := Absent
	if receipt != nil {
		knowledge, kind, payload = Known, string(receipt.Kind), sqliteTestJSON(t, receipt)
	}
	args := append(sqliteTestExecution(request), string(execution.RequestID), string(execution.OperationID), string(execution.AttemptID), string(execution.StepID), sqliteTestJSON(t, request), string(knowledge), kind, payload)
	sqliteTestExec(t, db, "INSERT INTO executions(realm,host,resource,backend,execution_key,request_id,operation_id,attempt_id,step_id,request_json,backend_knowledge,receipt_kind,receipt_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", args...)
	if receipt != nil && receipt.Kind == Positive {
		transition := receipt.Positive
		args = append(sqliteTestScope(request.Command.Scope), string(transition.TransitionID), string(execution.ExecutionKey), string(receipt.ReceiptID), string(transition.Before.Revision), fmt.Sprintf("%020d", transition.Before.StateVersion), string(transition.After.Revision), fmt.Sprintf("%020d", transition.After.StateVersion))
		sqliteTestExec(t, db, "INSERT INTO reference_transitions(realm,host,resource,backend,transition_id,execution_key,receipt_id,before_revision,before_state_version,after_revision,after_state_version) VALUES(?,?,?,?,?,?,?,?,?,?,?)", args...)
	}
}

func sqliteTestNew(t *testing.T, kind ReceiptKind) sqliteTestFixture {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, RegistryDatabaseName)
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	writer.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = writer.Close() })
	if err := MigrateRegistrySchemaV2ForAdministration(context.Background(), writer); err != nil {
		t.Fatal(err)
	}
	request, snapshot := readTestSnapshot(t, kind)
	snapshot.Current.Reference = &Reference{Revision: "revision-later", StateVersion: 99}
	sqliteTestResource(t, writer, request.Command.Scope, snapshot.Current.Knowledge, snapshot.Current.Reference, snapshot.Evidence)
	sqliteTestInsertExecution(t, writer, request, snapshot.Backend.Receipt)
	continuity := &sqliteTestContinuity{witness: snapshot.Witness, outstanding: append([]ID(nil), snapshot.Outstanding...)}
	return sqliteTestFixture{directory: directory, path: path, writer: writer, request: request, snapshot: snapshot, continuity: continuity}
}

func sqliteTestOpen(t *testing.T, fixture sqliteTestFixture) *SQLiteReadPort {
	t.Helper()
	if err := fixture.writer.Close(); err != nil {
		t.Fatal(err)
	}
	port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName, Continuity: fixture.continuity})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = port.Close() })
	return port
}

// sqliteOwnerDB unwraps the real pool only for synthetic fixture assertions.
// It is not a product API and does not add another pool or file descriptor.
func sqliteOwnerDB(port *SQLiteReadPort) *sql.DB {
	return port.owner.pool.(*sql.DB)
}

func sqliteTestProjection(t *testing.T, fixture sqliteTestFixture, boundary Boundary, projection Projection) {
	t.Helper()
	var record any
	if projection.Record != nil {
		record = sqliteTestJSON(t, projection.Record)
	}
	args := append(sqliteTestExecution(fixture.request), string(boundary), string(projection.Knowledge), record)
	sqliteTestExec(t, fixture.writer, "INSERT INTO projections(realm,host,resource,backend,execution_key,boundary,knowledge,record_json) VALUES(?,?,?,?,?,?,?,?)", args...)
}

type sqliteTestFileState struct {
	Digest   [32]byte
	Size     int64
	Modified time.Time
}

func sqliteTestFiles(t *testing.T, directory string) map[string]sqliteTestFileState {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]sqliteTestFileState)
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatal("unexpected fixture directory")
		}
		path := filepath.Join(directory, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = sqliteTestFileState{Digest: sha256.Sum256(data), Size: info.Size(), Modified: info.ModTime()}
	}
	return files
}

type sqliteTestWriterEvent struct {
	Event string
	Count int
}

type sqliteTestWriter struct {
	command *exec.Cmd
	input   io.WriteCloser
	events  chan sqliteTestWriterEvent
	context context.Context
	last    sqliteTestWriterEvent
	waited  bool
	stderr  bytes.Buffer
}

func sqliteTestStartWriter(t *testing.T, ctx context.Context, path, action string) *sqliteTestWriter {
	t.Helper()
	child := &sqliteTestWriter{
		command: exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSQLiteWriterProcess$", "-test.v"),
		events:  make(chan sqliteTestWriterEvent, 64),
		context: ctx,
	}
	// Explicit synthetic values only; do not inherit CI credentials or env.
	child.command.Env = []string{
		"AUTOSTREAM_SQLITE_TEST_HELPER=synthetic-only-v1",
		"AUTOSTREAM_SQLITE_TEST_PATH=" + path,
		"AUTOSTREAM_SQLITE_TEST_ACTION=" + action,
	}
	child.command.WaitDelay = 2 * time.Second
	child.command.Stderr = &child.stderr
	var err error
	child.input, err = child.command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(child.events)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "SQLITE_TEST_EVENT=") {
				continue
			}
			var event sqliteTestWriterEvent
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "SQLITE_TEST_EVENT=")), &event) == nil {
				child.events <- event
			}
		}
	}()
	t.Cleanup(func() {
		if !child.waited {
			_ = child.input.Close()
			if err := child.command.Wait(); err != nil && ctx.Err() == nil {
				t.Errorf("synthetic child failed: %v %s", err, child.stderr.String())
			}
			child.waited = true
		}
	})
	return child
}

func (child *sqliteTestWriter) send(t *testing.T, command string) {
	t.Helper()
	if _, err := fmt.Fprintln(child.input, command); err != nil {
		t.Fatal(err)
	}
}

func (child *sqliteTestWriter) next(t *testing.T, expected string) sqliteTestWriterEvent {
	t.Helper()
	select {
	case event, ok := <-child.events:
		if !ok || event.Event != expected {
			t.Fatalf("expected child event %q, got %#v", expected, event)
		}
		child.last = event
		return event
	case <-child.context.Done():
		t.Fatalf("synthetic child timed out waiting for %q", expected)
		return sqliteTestWriterEvent{}
	}
}

func (child *sqliteTestWriter) stop(t *testing.T) {
	t.Helper()
	child.send(t, "stop")
	_ = child.input.Close()
	if err := child.command.Wait(); err != nil {
		t.Fatalf("synthetic child failed: %v %s", err, child.stderr.String())
	}
	child.waited = true
}

func sqliteTestChildEvent(t *testing.T, event string, count int) {
	t.Helper()
	data, err := json.Marshal(sqliteTestWriterEvent{Event: event, Count: count})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("SQLITE_TEST_EVENT=" + string(data))
}

// This helper only runs in the explicitly launched synthetic child process.
// A normal go test must skip it; the skip is not counted as product coverage.
func TestSQLiteWriterProcess(t *testing.T) {
	if os.Getenv("AUTOSTREAM_SQLITE_TEST_HELPER") != "synthetic-only-v1" {
		t.Skip("synthetic subprocess helper only")
	}
	path := os.Getenv("AUTOSTREAM_SQLITE_TEST_PATH")
	action := os.Getenv("AUTOSTREAM_SQLITE_TEST_ACTION")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Base(path) != RegistryDatabaseName ||
		!strings.Contains(filepath.Dir(path), string(filepath.Separator)+"TestSQLite") ||
		action != "stress" && action != "pin" && action != "lock" {
		t.Fatal("invalid synthetic-only helper target")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	busyTimeout := 0
	if action == "stress" {
		busyTimeout = 50 // synthetic contention budget, never a production setting
	}
	if _, err := conn.ExecContext(context.Background(), fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeout)); err != nil {
		t.Fatal(err)
	}
	var rawEvidence, rawRecord string
	if err := conn.QueryRowContext(context.Background(), "SELECT backend_frame_json FROM resources").Scan(&rawEvidence); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRowContext(context.Background(), "SELECT record_json FROM projections WHERE boundary='executor_ledger'").Scan(&rawRecord); err != nil {
		t.Fatal(err)
	}
	var evidence BackendReadFrame
	var record OutcomeRecord
	if json.Unmarshal([]byte(rawEvidence), &evidence) != nil || json.Unmarshal([]byte(rawRecord), &record) != nil {
		t.Fatal("invalid synthetic fixture")
	}
	commands := bufio.NewScanner(os.Stdin)
	sqliteTestChildEvent(t, "ready", 0)
	stage := func(generation ID) {
		t.Helper()
		evidence.Generation = generation
		record.RecordedBy = generation
		if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(context.Background(), "UPDATE resources SET backend_frame_json=?", sqliteTestJSON(t, evidence)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(context.Background(), "UPDATE projections SET record_json=? WHERE boundary='executor_ledger'", sqliteTestJSON(t, record)); err != nil {
			t.Fatal(err)
		}
	}
	for commands.Scan() {
		command := commands.Text()
		if command == "stop" {
			return
		}
		if action == "lock" {
			switch command {
			case "begin":
				if _, err := conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
					t.Fatal(err)
				}
				sqliteTestChildEvent(t, "locked", 0)
			case "release":
				if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				sqliteTestChildEvent(t, "released", 0)
			default:
				t.Fatal("invalid lock command")
			}
			continue
		}
		if action == "pin" {
			switch command {
			case "begin":
				stage("generation-new")
				sqliteTestChildEvent(t, "staged", 0)
			case "try_commit":
				_, err := conn.ExecContext(context.Background(), "COMMIT")
				if err == nil {
					t.Fatal("external writer bypassed the parent's read lock")
				}
				message := strings.ToLower(err.Error())
				if !strings.Contains(message, "busy") && !strings.Contains(message, "locked") {
					t.Fatal("unexpected synthetic commit failure:", err)
				}
				sqliteTestChildEvent(t, "busy", 0)
			case "commit":
				if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
					t.Fatal(err)
				}
				sqliteTestChildEvent(t, "committed", 0)
			default:
				t.Fatal("invalid pin command")
			}
			continue
		}
		if command != "run" {
			t.Fatal("invalid stress command")
		}
		for i := 1; i <= 32; i++ {
			committed := false
			for retry := 0; retry < 1000 && !committed; retry++ {
				stage(ID(fmt.Sprintf("generation-%d", i)))
				_, err := conn.ExecContext(context.Background(), "COMMIT")
				if err == nil {
					committed = true
					continue
				}
				_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
				message := strings.ToLower(err.Error())
				if !strings.Contains(message, "busy") && !strings.Contains(message, "locked") {
					t.Fatal(err)
				}
			}
			if !committed {
				t.Fatal("synthetic writer contention budget exhausted")
			}
		}
		sqliteTestChildEvent(t, "done", 32)
	}
}

func TestSQLiteEngineAndExplicitVersionedMigration(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	before := sqliteTestFiles(t, fixture.directory)
	if err := MigrateRegistrySchemaV2ForAdministration(context.Background(), fixture.writer); err != nil {
		t.Fatalf("compatible explicit administration recheck failed: %v", err)
	}
	if !reflect.DeepEqual(before, sqliteTestFiles(t, fixture.directory)) {
		t.Fatal("compatible schema recheck rewrote the database")
	}
	port := sqliteTestOpen(t, fixture)
	var version, sourceID string
	if err := sqliteOwnerDB(port).QueryRowContext(context.Background(), "SELECT sqlite_version(),sqlite_source_id()").Scan(&version, &sourceID); err != nil {
		t.Fatal(err)
	}
	t.Log("SQLITE_ENGINE_VERSION=" + version)
	t.Log("SQLITE_SOURCE_ID=" + sourceID)
	if version != "3.54.1" || sourceID != "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76" {
		t.Fatal("unverified SQLite engine")
	}
	var schemaVersion, applicationID int
	if err := sqliteOwnerDB(port).QueryRow("PRAGMA user_version").Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	if err := sqliteOwnerDB(port).QueryRow("PRAGMA application_id").Scan(&applicationID); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != RegistrySchemaVersion || applicationID != RegistryApplicationID {
		t.Fatal("schema identity mismatch")
	}
	var migrationVersion, targetVersion, dirty int
	var checksum string
	if err := sqliteOwnerDB(port).QueryRow("SELECT version,checksum,dirty,target_schema_version FROM registry_migrations").Scan(&migrationVersion, &checksum, &dirty, &targetVersion); err != nil {
		t.Fatal(err)
	}
	if migrationVersion != RegistryMigrationVersion || targetVersion != RegistrySchemaVersion || dirty != 0 || checksum != RegistryMigrationChecksum() {
		t.Fatal("fresh migration did not record an exact clean checksum")
	}
}

func TestSQLiteSchemaRejectionDoesNotAutoMigrateOrRepair(t *testing.T) {
	for _, name := range []string{"future_version", "wrong_application", "wrong_metadata", "checksum", "dirty", "unexpected_trigger", "weakened_duplicate_table"} {
		t.Run(name, func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			switch name {
			case "future_version":
				sqliteTestExec(t, fixture.writer, "PRAGMA user_version=99")
			case "wrong_application":
				sqliteTestExec(t, fixture.writer, "PRAGMA application_id=1")
			case "wrong_metadata":
				sqliteTestExec(t, fixture.writer, "UPDATE registry_meta SET codec='unknown-codec'")
			case "checksum":
				sqliteTestExec(t, fixture.writer, "UPDATE registry_migrations SET checksum=?", strings.Repeat("0", 64))
			case "dirty":
				sqliteTestExec(t, fixture.writer, "UPDATE registry_migrations SET dirty=1")
			case "unexpected_trigger":
				sqliteTestExec(t, fixture.writer, "CREATE TRIGGER unexpected AFTER UPDATE ON resources BEGIN SELECT 1; END")
			case "weakened_duplicate_table":
				sqliteTestExec(t, fixture.writer, "PRAGMA foreign_keys=OFF")
				sqliteTestExec(t, fixture.writer, "DROP TABLE resources")
				sqliteTestExec(t, fixture.writer, "CREATE TABLE resources(realm TEXT,host TEXT,resource TEXT,backend TEXT,active_knowledge TEXT,reference_revision TEXT,reference_state_version TEXT,reference_json TEXT,backend_frame_json TEXT)")
				for i := 0; i < 2; i++ {
					sqliteTestExec(t, fixture.writer, "INSERT INTO resources VALUES('realm-a','host-a','config-a','backend-a','UNKNOWN',NULL,NULL,NULL,'{}')")
				}
			}
			if name == "checksum" || name == "dirty" {
				if err := MigrateRegistrySchemaV2ForAdministration(context.Background(), fixture.writer); err == nil {
					t.Fatal("explicit administration repaired or accepted invalid migration evidence")
				}
			}
			if err := fixture.writer.Close(); err != nil {
				t.Fatal(err)
			}
			before := sqliteTestFiles(t, fixture.directory)
			port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName})
			if port != nil {
				_ = port.Close()
			}
			if err == nil {
				t.Fatal("unsupported or weakened schema admitted")
			}
			if !reflect.DeepEqual(before, sqliteTestFiles(t, fixture.directory)) {
				t.Fatal("read open migrated, repaired or changed rejected data")
			}
		})
	}
	t.Run("unmigrated_file", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, RegistryDatabaseName)
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		before := sqliteTestFiles(t, directory)
		port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: directory, DatabaseName: RegistryDatabaseName})
		if port != nil {
			_ = port.Close()
		}
		if err == nil || !reflect.DeepEqual(before, sqliteTestFiles(t, directory)) {
			t.Fatal("unmigrated file was admitted or changed")
		}
	})
}

func TestSQLiteReadOnlyConnectionAndClose(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	header := port.owner.header
	database := sqliteOwnerDB(port)
	sqliteOwnerDB(port).SetMaxOpenConns(1)
	var queryOnly, trustedSchema int
	if err := sqliteOwnerDB(port).QueryRow("PRAGMA query_only").Scan(&queryOnly); err != nil {
		t.Fatal(err)
	}
	if err := sqliteOwnerDB(port).QueryRow("PRAGMA trusted_schema").Scan(&trustedSchema); err != nil {
		t.Fatal(err)
	}
	if queryOnly != 1 || trustedSchema != 0 {
		t.Fatal("connection hardening not effective")
	}
	if _, err := sqliteOwnerDB(port).Exec("UPDATE registry_meta SET schema_name=schema_name"); err == nil {
		t.Fatal("query-only connection accepted a write")
	}
	if _, err := sqliteOwnerDB(port).Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := sqliteOwnerDB(port).Exec("UPDATE registry_meta SET schema_name=schema_name"); err == nil {
		t.Fatal("file URI mode=ro was replaced by a togglable pragma")
	}
	if _, err := sqliteOwnerDB(port).Exec("PRAGMA user_version=2"); err == nil {
		t.Fatal("readonly file accepted persistent pragma")
	}
	if err := port.Close(); err != nil {
		t.Fatal(err)
	}
	if header == nil {
		t.Fatal("owned header descriptor missing")
	}
	if _, err := header.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("header descriptor leaked after Close: %v", err)
	}
	if err := database.PingContext(context.Background()); err == nil {
		t.Fatal("owned database pool remained open")
	}
	if err := port.Close(); err != nil {
		t.Fatal("Close was not idempotent:", err)
	}
	if _, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope); !errors.Is(err, ErrSQLiteClosed) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := port.ReadExecution(context.Background(), fixture.request); !errors.Is(err, ErrSQLiteClosed) {
		t.Fatalf("execution after close: %v", err)
	}
}

func TestSQLiteRejectsInjectedLocationsAndRecoverySidecars(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	if err := fixture.writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "../registry.sqlite3", fixture.path, "file:registry.sqlite3?mode=rw", "registry.sqlite3?mode=rw", "registry.sqlite3%3fmode=rw", "registry.sqlite3#fragment", "registry.sqlite3\x00"} {
		t.Run("filename/"+fmt.Sprintf("%x", name), func(t *testing.T) {
			port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: fixture.directory, DatabaseName: name})
			if port != nil {
				_ = port.Close()
			}
			if err == nil {
				t.Fatal("untrusted filename/URI admitted")
			}
		})
	}
	for _, directory := range []string{".", "file:" + fixture.directory, fixture.directory + "?mode=rw", fixture.directory + "%2f", fixture.directory + "\x00", filepath.Join(fixture.directory, "child") + "/.."} {
		port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: directory, DatabaseName: RegistryDatabaseName})
		if port != nil {
			_ = port.Close()
		}
		if err == nil {
			t.Fatal("noncanonical directory/URI admitted")
		}
	}
	t.Run("missing_file_not_created", func(t *testing.T) {
		directory := t.TempDir()
		port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: directory, DatabaseName: RegistryDatabaseName})
		if port != nil {
			_ = port.Close()
		}
		if err == nil {
			t.Fatal("missing database admitted")
		}
		if _, err := os.Stat(filepath.Join(directory, RegistryDatabaseName)); !os.IsNotExist(err) {
			t.Fatal("read-only open created a file")
		}
	})
	t.Run("file_symlink", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Symlink(fixture.path, filepath.Join(directory, RegistryDatabaseName)); err != nil {
			t.Fatal(err)
		}
		port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: directory, DatabaseName: RegistryDatabaseName})
		if port != nil {
			_ = port.Close()
		}
		if err == nil {
			t.Fatal("database symlink admitted")
		}
	})
	t.Run("directory_symlink", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "linked")
		if err := os.Symlink(fixture.directory, directory); err != nil {
			t.Fatal(err)
		}
		port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: directory, DatabaseName: RegistryDatabaseName})
		if port != nil {
			_ = port.Close()
		}
		if err == nil {
			t.Fatal("directory symlink admitted")
		}
	})
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		t.Run("sidecar"+suffix, func(t *testing.T) {
			f := sqliteTestNew(t, Positive)
			if err := f.writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.path+suffix, []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
			before := sqliteTestFiles(t, f.directory)
			port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: f.directory, DatabaseName: RegistryDatabaseName})
			if port != nil {
				_ = port.Close()
			}
			if err == nil || !reflect.DeepEqual(before, sqliteTestFiles(t, f.directory)) {
				t.Fatal("recovery/sidecar profile was admitted or changed")
			}
		})
	}
}

func TestSQLiteMapsPositiveNegativeAndAllProjectionBoundaries(t *testing.T) {
	for _, kind := range []ReceiptKind{Positive, Negative} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := sqliteTestNew(t, kind)
			receipt := *fixture.snapshot.Backend.Receipt
			for _, boundary := range []Boundary{ExecutorLedger, CPReport, CPAudit} {
				projection := readTestRecord(fixture.request, receipt, boundary)
				if boundary == CPReport {
					projection.Record.Ack = AckUnknown
				}
				sqliteTestProjection(t, fixture, boundary, projection)
			}
			port := sqliteTestOpen(t, fixture)
			active, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope)
			if err != nil || active.Knowledge != Known || *active.Reference != *fixture.snapshot.Current.Reference {
				t.Fatalf("current reference: %#v %v", active, err)
			}
			snapshot, err := port.ReadExecution(context.Background(), fixture.request)
			if err != nil || snapshot.StoredRequest == nil || *snapshot.StoredRequest != fixture.request ||
				snapshot.Backend.Knowledge != Known || snapshot.Backend.Receipt.Kind != kind ||
				snapshot.Ledger.Knowledge != Known || snapshot.Report.Knowledge != Known || snapshot.Audit.Knowledge != Known ||
				snapshot.Report.Record.Ack != AckUnknown || snapshot.Witness == nil ||
				!reflect.DeepEqual(snapshot.Outstanding, fixture.snapshot.Outstanding) {
				t.Fatalf("mapped snapshot: %#v %v", snapshot, err)
			}
			if kind == Positive && snapshot.Current.Reference.Revision == snapshot.Backend.Receipt.Positive.After.Revision {
				t.Fatal("fixture failed to separate past receipt and current reference")
			}
		})
	}
}

func TestSQLiteKnownAbsentUnknownConflictAndMissingRows(t *testing.T) {
	for _, state := range []Knowledge{Known, Absent, Unknown, Conflict} {
		t.Run(string(state), func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			var reference, revision, stateVersion, receipt, kind any
			if state == Known {
				reference = sqliteTestJSON(t, fixture.snapshot.Current.Reference)
				revision = string(fixture.snapshot.Current.Reference.Revision)
				stateVersion = fmt.Sprintf("%020d", fixture.snapshot.Current.Reference.StateVersion)
				receipt = sqliteTestJSON(t, fixture.snapshot.Backend.Receipt)
				kind = string(fixture.snapshot.Backend.Receipt.Kind)
			} else {
				sqliteTestExec(t, fixture.writer, "DELETE FROM reference_transitions")
			}
			sqliteTestExec(t, fixture.writer, "UPDATE resources SET active_knowledge=?,reference_revision=?,reference_state_version=?,reference_json=?", string(state), revision, stateVersion, reference)
			sqliteTestExec(t, fixture.writer, "UPDATE executions SET backend_knowledge=?,receipt_kind=?,receipt_json=?", string(state), kind, receipt)
			port := sqliteTestOpen(t, fixture)
			active, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope)
			if err != nil || active.Knowledge != state {
				t.Fatalf("active knowledge: %#v %v", active, err)
			}
			snapshot, err := port.ReadExecution(context.Background(), fixture.request)
			if err != nil || snapshot.Backend.Knowledge != state {
				t.Fatalf("backend knowledge: %#v %v", snapshot, err)
			}
		})
	}
	t.Run("missing_resource_is_unknown", func(t *testing.T) {
		fixture := sqliteTestNew(t, Positive)
		port := sqliteTestOpen(t, fixture)
		scope := fixture.request.Command.Scope
		scope.Resource = "unregistered"
		active, err := port.ReadActiveReference(context.Background(), scope)
		if err != nil || active.Knowledge != Unknown || active.Reference != nil {
			t.Fatalf("missing resource synthesized absence: %#v %v", active, err)
		}
	})
	t.Run("missing_execution_is_absence_not_authority", func(t *testing.T) {
		fixture := sqliteTestNew(t, Positive)
		port := sqliteTestOpen(t, fixture)
		request := fixture.request
		request.Command.Execution = Execution{RequestID: "other-request", ExecutionKey: "other-execution", OperationID: "other-operation", AttemptID: "other-attempt", StepID: "other-step"}
		var err error
		request.Binding, err = CanonicalBinding(request.Command)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := port.ReadExecution(context.Background(), request)
		if err != nil || snapshot.Backend.Knowledge != Absent || snapshot.StoredRequest != nil {
			t.Fatalf("missing execution: %#v %v", snapshot, err)
		}
		reader, err := NewReader(port, &readTestAuthorizer{}, &readTestVerifier{})
		if err != nil {
			t.Fatal(err)
		}
		plan, err := reader.ReconcilePartialRestore(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
		if err == nil || plan.OriginalMutationAuthorized || len(plan.Steps) != 0 {
			t.Fatal("absence became unconsumed/repair authority")
		}
	})
}

func TestSQLiteCorruptDataCannotBecomeKnownTerminalOrSelectFirst(t *testing.T) {
	for _, name := range []string{"receipt_json", "receipt_duplicate_field", "receipt_unknown_field", "receipt_wrong_binding", "request_json", "indexed_request", "projection_json", "projection_binding", "witness_independent", "orphan_projection"} {
		t.Run(name, func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			projection := readTestRecord(fixture.request, *fixture.snapshot.Backend.Receipt, ExecutorLedger)
			sqliteTestProjection(t, fixture, ExecutorLedger, projection)
			switch name {
			case "receipt_json":
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET receipt_json='{'")
			case "receipt_duplicate_field":
				original := sqliteTestJSON(t, fixture.snapshot.Backend.Receipt)
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET receipt_json=?", "{\"ReceiptID\":\"shadow\","+original[1:])
			case "receipt_unknown_field":
				original := sqliteTestJSON(t, fixture.snapshot.Backend.Receipt)
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET receipt_json=?", "{\"Unexpected\":1,"+original[1:])
			case "receipt_wrong_binding":
				receipt := readCloneReceipt(*fixture.snapshot.Backend.Receipt)
				receipt.Binding = "other-binding"
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET receipt_json=?", sqliteTestJSON(t, receipt))
			case "request_json":
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET request_json='{}'")
			case "indexed_request":
				sqliteTestExec(t, fixture.writer, "UPDATE executions SET request_id='indexed-other'")
			case "projection_json":
				sqliteTestExec(t, fixture.writer, "UPDATE projections SET record_json='{'")
			case "projection_binding":
				projection.Record.Binding = "other-binding"
				sqliteTestExec(t, fixture.writer, "UPDATE projections SET record_json=?", sqliteTestJSON(t, projection.Record))
			case "witness_independent":
				fixture.continuity.witness = &WitnessOutcome{}
			case "orphan_projection":
				sqliteTestExec(t, fixture.writer, "PRAGMA foreign_keys=OFF")
				sqliteTestExec(t, fixture.writer, "DELETE FROM executions")
			}
			port := sqliteTestOpen(t, fixture)
			snapshot, err := port.ReadExecution(context.Background(), fixture.request)
			if err != nil {
				return // fail-closed read error is permitted; never choose an unsafe row
			}
			switch name {
			case "projection_json":
				if snapshot.Backend.Knowledge != Known || snapshot.Ledger.Knowledge != Unknown {
					t.Fatal("projection corruption erased history or became known")
				}
			case "projection_binding":
				if snapshot.Backend.Knowledge != Known || snapshot.Ledger.Knowledge != Conflict {
					t.Fatal("projection identity mismatch became known")
				}
			case "witness_independent":
				if snapshot.Backend.Knowledge != Known || snapshot.Witness != nil {
					t.Fatal("malformed witness became qualified")
				}
			default:
				if snapshot.Backend.Knowledge != Unknown && snapshot.Backend.Knowledge != Conflict {
					t.Fatal("malformed/mismatched/orphan record became known or absent")
				}
			}
		})
	}
}

func TestSQLiteD02ReconciliationReadsOnlyAndPreservesFiles(t *testing.T) {
	for _, kind := range []ReceiptKind{Positive, Negative} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := sqliteTestNew(t, kind)
			before := sqliteTestFiles(t, fixture.directory)
			port := sqliteTestOpen(t, fixture)
			reader, err := NewReader(port, &readTestAuthorizer{}, &readTestVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			query := LookupRequest{Call: readTestCall(), Request: fixture.request}
			result, err := reader.LookupExecution(context.Background(), query)
			if err != nil || result.Backend.Knowledge != Known {
				t.Fatalf("lookup: %#v %v", result, err)
			}
			plan, err := reader.ReconcilePartialRestore(context.Background(), query)
			if err != nil || plan.Knowledge != Known || len(plan.Steps) != 3 || plan.OriginalMutationAuthorized {
				t.Fatalf("read-only repair plan: %#v %v", plan, err)
			}
			for _, step := range plan.Steps {
				if step.Outcome.Execution != fixture.request.Command.Execution || step.Outcome.Binding != fixture.request.Binding {
					t.Fatal("repair generated another execution")
				}
			}
			if err := port.Close(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, sqliteTestFiles(t, fixture.directory)) {
				t.Fatal("lookup/reconciliation altered bytes, mtimes or sidecar set")
			}
		})
	}
}

func TestSQLiteExecutionSnapshotDoesNotMixConcurrentWriterGenerations(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	projection := readTestRecord(fixture.request, *fixture.snapshot.Backend.Receipt, ExecutorLedger)
	projection.Record.RecordedBy = "generation-0"
	fixture.snapshot.Evidence.Generation = "generation-0"
	sqliteTestExec(t, fixture.writer, "UPDATE resources SET backend_frame_json=?", sqliteTestJSON(t, sqliteTestFrame(fixture.snapshot.Evidence)))
	sqliteTestProjection(t, fixture, ExecutorLedger, projection)
	port := sqliteTestOpen(t, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := sqliteTestStartWriter(t, ctx, fixture.path, "stress")
	child.next(t, "ready")
	child.send(t, "run")
	successful := 0
	for attempt := 0; attempt < 256; attempt++ {
		snapshot, err := port.ReadExecution(ctx, fixture.request)
		if err == nil {
			if snapshot.Ledger.Knowledge != Known || snapshot.Ledger.Record == nil ||
				snapshot.Evidence.Generation != snapshot.Ledger.Record.RecordedBy {
				t.Fatal("ReadExecution mixed separate transaction generations")
			}
			successful++
		}
		select {
		case event, ok := <-child.events:
			child.last = event
			if !ok || event.Event != "done" || event.Count != 32 {
				t.Fatalf("synthetic writer failed: %#v", event)
			}
			attempt = 256
		default:
		}
	}
	if child.last.Event != "done" {
		event := child.next(t, "done")
		if event.Count != 32 {
			t.Fatal("synthetic writer did not commit all generations")
		}
	}
	snapshot, err := port.ReadExecution(ctx, fixture.request)
	if err != nil || snapshot.Ledger.Record == nil ||
		snapshot.Evidence.Generation != snapshot.Ledger.Record.RecordedBy ||
		snapshot.Evidence.Generation != "generation-32" {
		t.Fatalf("final qualified snapshot: %#v %v", snapshot, err)
	}
	successful++
	if successful == 0 {
		t.Fatal("no qualified snapshot observed")
	}
	child.stop(t)
}

func TestSQLiteContextCancellationAndPoolWait(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	if err := fixture.writer.Close(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	port, err := OpenSQLiteReadPort(canceled, SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName})
	if port != nil {
		_ = port.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open: %v", err)
	}
	port = sqliteTestOpen(t, fixture)
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		wrapped := fmt.Errorf("synthetic private path %s SELECT: %w", fixture.path, cause)
		got := port.readError(context.Background(), wrapped, "sqlite.connection")
		if !errors.Is(got, cause) || got.Error() != cause.Error() {
			t.Fatal("wrapped context error leaked private driver details")
		}
	}
	if _, err := port.ReadActiveReference(canceled, fixture.request.Command.Scope); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read: %v", err)
	}
	if _, err := port.ReadExecution(canceled, fixture.request); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled execution read: %v", err)
	}
	sqliteOwnerDB(port).SetMaxOpenConns(1)
	held, err := sqliteOwnerDB(port).Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	timeout, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	if _, err := port.ReadExecution(timeout, fixture.request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool wait did not honor context: %v", err)
	}
}

func TestSQLiteReadTransactionPinsSnapshotUntilReaderFinishes(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	oldEvidence := fixture.snapshot.Evidence
	oldEvidence.Generation = "generation-old"
	projection := readTestRecord(fixture.request, *fixture.snapshot.Backend.Receipt, ExecutorLedger)
	projection.Record.RecordedBy = oldEvidence.Generation
	sqliteTestExec(t, fixture.writer, "UPDATE resources SET backend_frame_json=?", sqliteTestJSON(t, sqliteTestFrame(oldEvidence)))
	sqliteTestProjection(t, fixture, ExecutorLedger, projection)
	port := sqliteTestOpen(t, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	readTx, err := port.beginRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer readTx.Rollback()
	var rawEvidence string
	if err := readTx.QueryRowContext(ctx, "SELECT backend_frame_json FROM resources").Scan(&rawEvidence); err != nil {
		t.Fatal(err)
	}
	// Exercise a second successful pooled read while the first transaction is
	// pinned. Any per-read raw descriptor Close would drop its POSIX lock.
	active, err := port.ReadActiveReference(ctx, fixture.request.Command.Scope)
	if err != nil || active.Knowledge != Known {
		t.Fatalf("second pooled read failed: %#v %v", active, err)
	}
	child := sqliteTestStartWriter(t, ctx, fixture.path, "pin")
	child.next(t, "ready")
	child.send(t, "begin")
	child.next(t, "staged")
	child.send(t, "try_commit")
	child.next(t, "busy")
	var rawRecord string
	if err := readTx.QueryRowContext(ctx, "SELECT record_json FROM projections").Scan(&rawRecord); err != nil {
		t.Fatal(err)
	}
	var before BackendReadFrame
	var observed OutcomeRecord
	if err := json.Unmarshal([]byte(rawEvidence), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(rawRecord), &observed); err != nil {
		t.Fatal(err)
	}
	if before.Generation != oldEvidence.Generation || observed.RecordedBy != oldEvidence.Generation {
		t.Fatal("adapter transaction mixed the child writer's pending state")
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	child.send(t, "commit")
	child.next(t, "committed")
	snapshot, err := port.ReadExecution(ctx, fixture.request)
	if err != nil || snapshot.Evidence.Generation != "generation-new" ||
		snapshot.Ledger.Record == nil || snapshot.Ledger.Record.RecordedBy != "generation-new" {
		t.Fatalf("new snapshot not visible after external commit: %#v %v", snapshot, err)
	}
	child.stop(t)
}

func TestSQLiteDuplicateAndHardlinkOpenCannotDropAnotherReadLock(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(fmt.Sprintf("hardlink-%t", alias), func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			projection := readTestRecord(fixture.request, *fixture.snapshot.Backend.Receipt, ExecutorLedger)
			sqliteTestProjection(t, fixture, ExecutorLedger, projection)
			port := sqliteTestOpen(t, fixture)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			readTx, err := port.beginRead(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer readTx.Rollback()
			var value string
			if err := readTx.QueryRowContext(ctx, "SELECT backend_frame_json FROM resources").Scan(&value); err != nil {
				t.Fatal(err)
			}
			directory := fixture.directory
			if alias {
				directory = t.TempDir()
				if err := os.Link(fixture.path, filepath.Join(directory, RegistryDatabaseName)); err != nil {
					t.Fatal(err)
				}
			}
			other, err := OpenSQLiteReadPort(ctx, SQLiteReadConfig{Directory: directory, DatabaseName: RegistryDatabaseName})
			if other != nil {
				_ = other.Close()
			}
			if err == nil {
				t.Fatal("second owner of same database inode admitted")
			}
			// No child writer or journal exists until after this rejection, so
			// only the ownership path can reject without dropping the first lock.
			child := sqliteTestStartWriter(t, ctx, fixture.path, "pin")
			child.next(t, "ready")
			child.send(t, "begin")
			child.next(t, "staged")
			child.send(t, "try_commit")
			child.next(t, "busy")
			if err := readTx.Rollback(); err != nil {
				t.Fatal(err)
			}
			child.send(t, "commit")
			child.next(t, "committed")
			child.stop(t)
		})
	}
}
