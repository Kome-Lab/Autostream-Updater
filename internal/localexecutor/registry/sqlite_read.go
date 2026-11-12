package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"modernc.org/sqlite"
)

const RegistryDatabaseName = "registry.sqlite3"

// SQLiteReadConfig is trusted installation configuration, never a request field.
// There is no caller-supplied DSN, URI, SQL, PRAGMA, or arbitrary file basename.
type SQLiteReadConfig struct {
	Directory    string
	DatabaseName string
	// Continuity is a trusted independent read-only dependency, never request data.
	Continuity ContinuityReadPort
}

var ErrSQLiteClosed = errors.New("registry_sqlite_closed")

// SQLiteReadPort owns a bounded read-only pool. All mapping queries in one call
// share one explicit read transaction. Close never performs schema maintenance.
//
// Qualification requires exclusive process ownership of this inode: no unrelated
// SQLite or raw descriptors may be opened/closed outside this lifecycle. The
// directory, identity and DELETE profile must not be adversarially replaced.
// The package lease catches duplicate adapters/hard links only; it does not prove
// Host-wide actor exclusion or discover handles owned by other libraries.
type SQLiteReadPort struct {
	lifecycle   sync.Mutex
	activeReads sync.WaitGroup
	header      *os.File
	lease       *sqliteReadLease
	db          *sql.DB
	path        string
	identity    os.FileInfo
	closed      atomic.Bool
	closeOnce   sync.Once
	closeErr    error
	continuity  ContinuityReadPort
}

var _ ReadPort = (*SQLiteReadPort)(nil)

// sqliteReadTx owns the sql.Conn lease as well as the transaction. In particular,
// cancellation can mark Tx done before its asynchronous rollback releases the
// connection; Conn.Close waits for that release before our public call returns.
type sqliteReadTx struct {
	*sql.Tx
	conn        *sql.Conn
	releaseOnce sync.Once
	releaseErr  error
}

func (tx *sqliteReadTx) release() error {
	tx.releaseOnce.Do(func() {
		tx.releaseErr = tx.conn.Close()
	})
	return tx.releaseErr
}

func (tx *sqliteReadTx) Commit() error {
	err := tx.Tx.Commit()
	releaseErr := tx.release()
	if err != nil {
		return err
	}
	return releaseErr
}

func (tx *sqliteReadTx) Rollback() error {
	err := tx.Tx.Rollback()
	releaseErr := tx.release()
	if err != nil {
		return err
	}
	return releaseErr
}

// sqliteReadLeases prevents duplicate adapters (including hard-link aliases)
// inside this package. It cannot discover unrelated SQLite/raw file handles:
// trusted bootstrap must provide exclusive process ownership of this inode.
type sqliteReadLease struct {
	identity os.FileInfo
	// A failed cleanup retains the owner and descriptor strongly: a later file
	// finalizer must not close an unmanaged descriptor and drop surviving locks.
	owner *SQLiteReadPort
}

var sqliteReadLeases struct {
	sync.Mutex
	owners map[*sqliteReadLease]struct{}
}

func sqliteAcquireReadLease(identity os.FileInfo) (*sqliteReadLease, error) {
	sqliteReadLeases.Lock()
	defer sqliteReadLeases.Unlock()
	for owner := range sqliteReadLeases.owners {
		if os.SameFile(owner.identity, identity) {
			return nil, collision("sqlite.process_inode_owner")
		}
	}
	lease := &sqliteReadLease{identity: identity}
	if sqliteReadLeases.owners == nil {
		sqliteReadLeases.owners = make(map[*sqliteReadLease]struct{})
	}
	sqliteReadLeases.owners[lease] = struct{}{}
	return lease, nil
}

func sqliteReleaseReadLease(lease *sqliteReadLease) {
	if lease == nil {
		return
	}
	sqliteReadLeases.Lock()
	delete(sqliteReadLeases.owners, lease)
	sqliteReadLeases.Unlock()
}

func OpenSQLiteReadPort(ctx context.Context, config SQLiteReadConfig) (*SQLiteReadPort, error) {
	if ctx == nil {
		return nil, invalid("sqlite.context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, identity, err := sqliteReadLocation(config)
	if err != nil {
		return nil, err
	}
	// Lease precedes every raw open. Bootstrap must exclude all other same-process
	// SQLite/raw handles to this inode, not merely other adapters in this map.
	lease, err := sqliteAcquireReadLease(identity)
	if err != nil {
		return nil, err
	}
	header, err := os.Open(path)
	if err != nil {
		sqliteReleaseReadLease(lease)
		return nil, fault(CodeUnavailable, "sqlite.header")
	}
	port := &SQLiteReadPort{path: path, identity: identity, header: header, lease: lease, continuity: config.Continuity}
	sqliteReadLeases.Lock()
	lease.owner = port
	sqliteReadLeases.Unlock()
	// The retained descriptor is opened before our SQLite pool and is not closed
	// until all its connections are drained. Per-read raw open/close would strip
	// traditional POSIX locks held by the same process.
	if err := port.checkLocation(); err != nil {
		_ = port.Close()
		return nil, err
	}
	parameters := url.Values{
		"mode":        {"ro"},
		"_query_only": {"1"},
		"_pragma":     {"trusted_schema(0)"},
		"_defensive":  {"1"},
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String() + "?" + parameters.Encode()
	connector, err := sqlite.NewConnector(uri)
	if err != nil {
		_ = port.Close()
		return nil, fault(CodeUnavailable, "sqlite.connector")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	port.db = db
	tx, err := port.beginRead(ctx)
	if err != nil {
		_ = port.Close()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		result := port.readError(ctx, err, "sqlite.open")
		_ = port.Close()
		return nil, result
	}
	if err := port.checkLocation(); err != nil {
		_ = port.Close()
		return nil, err
	}
	return port, nil
}

func sqliteReadLocation(config SQLiteReadConfig) (string, os.FileInfo, error) {
	if config.DatabaseName != RegistryDatabaseName || config.Directory == "" ||
		!utf8.ValidString(config.Directory) || !filepath.IsAbs(config.Directory) ||
		filepath.Clean(config.Directory) != config.Directory ||
		strings.ContainsAny(config.Directory, "?#%\\:\x00") {
		return "", nil, invalid("sqlite.location")
	}
	for _, r := range config.Directory {
		if r < 32 || r == 127 {
			return "", nil, invalid("sqlite.location")
		}
	}
	// Every component is checked; no EvalSymlinks normalization silently expands
	// the trusted root into a different location.
	directory := config.Directory
	for {
		info, err := os.Lstat(directory)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", nil, invalid("sqlite.directory")
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	path := filepath.Join(config.Directory, RegistryDatabaseName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, invalid("sqlite.database_file")
	}
	if err := sqliteCheckMetadata(path, info); err != nil {
		return "", nil, err
	}
	return path, info, nil
}

// sqliteCheckMetadata never opens or closes the database inode.
func sqliteCheckMetadata(path string, identity os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		identity == nil || !os.SameFile(info, identity) {
		return invalid("sqlite.file_identity")
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil || !errors.Is(err, os.ErrNotExist) {
			return fault(CodeUnavailable, "sqlite.recovery_or_wal")
		}
	}
	return nil
}

func (p *SQLiteReadPort) checkLocation() error {
	if p == nil || p.header == nil || p.closed.Load() {
		return ErrSQLiteClosed
	}
	if err := sqliteCheckMetadata(p.path, p.identity); err != nil {
		return err
	}
	opened, err := p.header.Stat()
	if err != nil || !os.SameFile(opened, p.identity) {
		return invalid("sqlite.file_identity")
	}
	var header [100]byte
	if _, err := p.header.ReadAt(header[:], 0); err != nil ||
		string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
		return invalid("sqlite.rollback_profile")
	}
	return nil
}

func (p *SQLiteReadPort) readError(ctx context.Context, err error, field string) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// Discard driver wrapper text even when it wraps a standard context error.
	// Canceled takes deterministic precedence if an error matches both.
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if p == nil || p.db == nil || p.closed.Load() {
		return ErrSQLiteClosed
	}
	return fault(CodeUnavailable, field)
}

func (p *SQLiteReadPort) beginRead(ctx context.Context) (*sqliteReadTx, error) {
	if ctx == nil {
		return nil, invalid("sqlite.context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.checkLocation(); err != nil {
		return nil, err
	}
	conn, err := p.db.Conn(ctx)
	if err != nil {
		return nil, p.readError(ctx, err, "sqlite.connection")
	}
	transaction, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		_ = conn.Close()
		return nil, p.readError(ctx, err, "sqlite.begin")
	}
	tx := &sqliteReadTx{Tx: transaction, conn: conn}
	ok := false
	defer func() {
		if !ok {
			_ = tx.Rollback()
		}
	}()
	var queryOnly, trustedSchema int
	var journal string
	if err := tx.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil {
		return nil, p.readError(ctx, err, "sqlite.read_only")
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA trusted_schema").Scan(&trustedSchema); err != nil {
		return nil, p.readError(ctx, err, "sqlite.trusted_schema")
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return nil, p.readError(ctx, err, "sqlite.journal_profile")
	}
	if queryOnly != 1 || trustedSchema != 0 || strings.ToLower(journal) != "delete" {
		return nil, invalid("sqlite.connection_profile")
	}
	if err := validateSQLiteSchema(ctx, tx); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	ok = true
	return tx, nil
}

// admitRead shares a short gate with Close. No mutex is held while waiting
// for an existing read or SQL operation, so a newly canceled caller is not
// queued behind a long closing transaction.
func (p *SQLiteReadPort) admitRead(ctx context.Context) error {
	if ctx == nil {
		return invalid("sqlite.context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil {
		return ErrSQLiteClosed
	}
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.closed.Load() || p.db == nil || p.header == nil {
		return ErrSQLiteClosed
	}
	p.activeReads.Add(1)
	return nil
}

func (p *SQLiteReadPort) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		// Close admission before waiting. Add and Wait cannot race: additions
		// occur only under the same gate while closed is false.
		p.lifecycle.Lock()
		p.closed.Store(true)
		p.lifecycle.Unlock()
		p.activeReads.Wait()
		if p.db != nil {
			if err := p.db.Close(); err != nil {
				// Unknown connection closure must not drop their possible locks:
				// retain the header and lease rather than falsely transfer owner.
				p.closeErr = fault(CodeUnavailable, "sqlite.close")
				return
			}
			// DB.Close may return while cancellation cleanup still owns a
			// connection. Never close the raw header in that uncertain state.
			if p.db.Stats().OpenConnections != 0 {
				p.closeErr = fault(CodeUnavailable, "sqlite.close_pending")
				return
			}
		}
		if p.header != nil {
			if err := p.header.Close(); err != nil {
				p.closeErr = fault(CodeUnavailable, "sqlite.header_close")
				return
			}
		}
		sqliteReleaseReadLease(p.lease)
	})
	return p.closeErr
}

func sqliteScopeArgs(scope Scope) []any {
	return []any{string(scope.Realm), string(scope.Host), string(scope.Resource), string(scope.Backend)}
}

func sqliteExecutionArgs(request Request) []any {
	return append(sqliteScopeArgs(request.Command.Scope), string(request.Command.Execution.ExecutionKey))
}

func (p *SQLiteReadPort) ReadActiveReference(ctx context.Context, scope Scope) (ActiveReference, error) {
	result := readUnknownActive(scope)
	if err := p.admitRead(ctx); err != nil {
		return result, err
	}
	defer p.activeReads.Done()
	if err := ValidateScope(scope); err != nil {
		return result, err
	}
	tx, err := p.beginRead(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	active, _, err := p.readActive(ctx, tx, scope)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, p.readError(ctx, err, "sqlite.read_commit")
	}
	return p.qualifyReference(ctx, active)
}

func sqliteStateVersion(text string) (uint64, error) {
	if len(text) != 20 {
		return 0, invalid("sqlite.reference_state_version")
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || fmt.Sprintf("%020d", value) != text {
		return 0, invalid("sqlite.reference_state_version")
	}
	return value, nil
}

func (p *SQLiteReadPort) readActive(ctx context.Context, tx sqliteQueryer, scope Scope) (ActiveReference, bool, error) {
	result := readUnknownActive(scope)
	rows, err := tx.QueryContext(ctx, "SELECT active_knowledge, reference_json, backend_frame_json, reference_revision, reference_state_version FROM resources WHERE realm=? AND host=? AND resource=? AND backend=?", sqliteScopeArgs(scope)...)
	if err != nil {
		return result, false, p.readError(ctx, err, "sqlite.resource")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			return ActiveReference{Knowledge: Conflict, Scope: scope}, true, nil
		}
		var knowledge, frameJSON string
		var reference, revision, version sql.NullString
		if err := rows.Scan(&knowledge, &reference, &frameJSON, &revision, &version); err != nil {
			return result, true, p.readError(ctx, err, "sqlite.resource_row")
		}
		var frame BackendReadFrame
		if err := decodeSQLiteRecord(frameJSON, &frame); err != nil || sqliteValidateFrame(frame) != nil {
			continue
		}
		candidate := ActiveReference{Knowledge: Knowledge(knowledge), Scope: scope, Evidence: sqliteFrameEvidence(frame)}
		if reference.Valid {
			var value Reference
			if err := decodeSQLiteRecord(reference.String, &value); err != nil {
				continue
			}
			candidate.Reference = &value
		}
		switch candidate.Knowledge {
		case Known:
			if candidate.Reference == nil || !revision.Valid || !version.Valid ||
				validateID(candidate.Reference.Revision, "sqlite.reference_revision") != nil {
				continue
			}
			number, err := sqliteStateVersion(version.String)
			if err != nil || ID(revision.String) != candidate.Reference.Revision || number != candidate.Reference.StateVersion {
				continue
			}
		case Absent, Unknown, Conflict:
			if candidate.Reference != nil || revision.Valid || version.Valid {
				continue
			}
		default:
			continue
		}
		result = candidate
	}
	if err := rows.Err(); err != nil {
		return readUnknownActive(scope), count != 0, p.readError(ctx, err, "sqlite.resource_rows")
	}
	if err := rows.Close(); err != nil {
		return readUnknownActive(scope), count != 0, p.readError(ctx, err, "sqlite.resource_close")
	}
	if result.Knowledge == Known {
		result, err = p.checkCurrentHistory(ctx, tx, result)
	}
	return result, count != 0, err
}

func (p *SQLiteReadPort) checkCurrentHistory(ctx context.Context, tx sqliteQueryer, active ActiveReference) (ActiveReference, error) {
	var revision, version string
	err := tx.QueryRowContext(ctx, "SELECT after_revision, after_state_version FROM reference_transitions WHERE realm=? AND host=? AND resource=? AND backend=? ORDER BY after_state_version DESC LIMIT 1", sqliteScopeArgs(active.Scope)...).Scan(&revision, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return active, nil
	}
	if err != nil {
		return readUnknownActive(active.Scope), p.readError(ctx, err, "sqlite.history_current")
	}
	number, err := sqliteStateVersion(version)
	if err != nil || validateID(ID(revision), "sqlite.history_revision") != nil {
		return readUnknownActive(active.Scope), nil
	}
	if active.Reference.StateVersion < number ||
		(active.Reference.StateVersion == number && active.Reference.Revision != ID(revision)) {
		return ActiveReference{Knowledge: Conflict, Scope: active.Scope}, nil
	}
	return active, nil
}

func (p *SQLiteReadPort) ReadExecution(ctx context.Context, request Request) (ExecutionSnapshot, error) {
	result := ExecutionSnapshot{
		Backend: BackendObservation{Knowledge: Unknown},
		Current: readUnknownActive(request.Command.Scope),
		Ledger:  Projection{Knowledge: Unknown},
		Report:  Projection{Knowledge: Unknown},
		Audit:   Projection{Knowledge: Unknown},
	}
	if err := p.admitRead(ctx); err != nil {
		return result, err
	}
	defer p.activeReads.Done()
	if err := ValidateRequest(request); err != nil {
		return result, err
	}
	tx, err := p.beginRead(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	active, resourceFound, err := p.readActive(ctx, tx, request.Command.Scope)
	if err != nil {
		return result, err
	}
	result.Current = active
	result.Evidence = active.Evidence
	resourceQualified := resourceFound && sqliteValidateFrame(sqliteFrameFromEvidence(active.Evidence)) == nil
	found, err := p.readExecution(ctx, tx, request, &result)
	if err != nil {
		return result, err
	}
	if resourceQualified {
		result.Ledger = Projection{Knowledge: Absent}
		result.Report = Projection{Knowledge: Absent}
		result.Audit = Projection{Knowledge: Absent}
	}
	projectionCount, err := p.readProjections(ctx, tx, request, &result)
	if err != nil {
		return result, err
	}
	transitionCount, err := p.readTransition(ctx, tx, request, &result)
	if err != nil {
		return result, err
	}
	if found && !resourceFound {
		result.Backend = BackendObservation{Knowledge: Conflict}
	}
	if !found {
		if projectionCount+transitionCount > 0 {
			result.Backend = BackendObservation{Knowledge: Conflict}
		} else if resourceQualified {
			result.Backend = BackendObservation{Knowledge: Absent}
		}
	}
	if err := tx.Commit(); err != nil {
		return result, p.readError(ctx, err, "sqlite.read_commit")
	}
	return p.qualifyExecution(ctx, request, result)
}

func (p *SQLiteReadPort) readExecution(ctx context.Context, tx sqliteQueryer, request Request, result *ExecutionSnapshot) (bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT request_id, operation_id, attempt_id, step_id, request_json, backend_knowledge, receipt_kind, receipt_json FROM executions WHERE realm=? AND host=? AND resource=? AND backend=? AND execution_key=?", sqliteExecutionArgs(request)...)
	if err != nil {
		return false, p.readError(ctx, err, "sqlite.execution")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			result.StoredRequest = nil
			result.Backend = BackendObservation{Knowledge: Conflict}
			continue
		}
		var requestID, operationID, attemptID, stepID, rawRequest, knowledge string
		var rawKind, rawReceipt sql.NullString
		if err := rows.Scan(&requestID, &operationID, &attemptID, &stepID, &rawRequest, &knowledge, &rawKind, &rawReceipt); err != nil {
			return true, p.readError(ctx, err, "sqlite.execution_row")
		}
		stored, err := DecodeRequest([]byte(rawRequest))
		if err != nil {
			continue
		}
		result.StoredRequest = &stored
		indexed := Execution{RequestID: ID(requestID), ExecutionKey: request.Command.Execution.ExecutionKey, OperationID: ID(operationID), AttemptID: ID(attemptID), StepID: ID(stepID)}
		if ValidateExecution(indexed) != nil || stored.Command.Scope != request.Command.Scope ||
			stored.Command.Execution != indexed || stored != request {
			result.Backend = BackendObservation{Knowledge: Conflict}
			continue
		}
		candidate := BackendObservation{Knowledge: Knowledge(knowledge)}
		if rawReceipt.Valid {
			var receipt Receipt
			if err := decodeSQLiteRecord(rawReceipt.String, &receipt); err != nil {
				continue
			}
			if !rawKind.Valid || ReceiptKind(rawKind.String) != receipt.Kind {
				result.Backend = BackendObservation{Knowledge: Conflict}
				continue
			}
			candidate.Receipt = &receipt
		} else if rawKind.Valid {
			result.Backend = BackendObservation{Knowledge: Conflict}
			continue
		}
		if err := ValidateBackendObservation(request, candidate); err != nil {
			if IsCode(err, CodeBindingConflict) {
				result.Backend = BackendObservation{Knowledge: Conflict}
			}
			continue
		}
		result.Backend = candidate
	}
	if err := rows.Err(); err != nil {
		return count != 0, p.readError(ctx, err, "sqlite.execution_rows")
	}
	return count != 0, nil
}

func sqliteProjectionPointer(result *ExecutionSnapshot, boundary Boundary) *Projection {
	switch boundary {
	case ExecutorLedger:
		return &result.Ledger
	case CPReport:
		return &result.Report
	case CPAudit:
		return &result.Audit
	default:
		return nil
	}
}

func (p *SQLiteReadPort) readProjections(ctx context.Context, tx sqliteQueryer, request Request, result *ExecutionSnapshot) (int, error) {
	rows, err := tx.QueryContext(ctx, "SELECT boundary, knowledge, record_json FROM projections WHERE realm=? AND host=? AND resource=? AND backend=? AND execution_key=? ORDER BY boundary", sqliteExecutionArgs(request)...)
	if err != nil {
		return 0, p.readError(ctx, err, "sqlite.projection")
	}
	defer rows.Close()
	count := 0
	seen := make(map[Boundary]bool, 3)
	for rows.Next() {
		count++
		var boundaryText, knowledge string
		var recordJSON sql.NullString
		if err := rows.Scan(&boundaryText, &knowledge, &recordJSON); err != nil {
			return count, p.readError(ctx, err, "sqlite.projection_row")
		}
		boundary := Boundary(boundaryText)
		target := sqliteProjectionPointer(result, boundary)
		if target == nil {
			result.Ledger = Projection{Knowledge: Unknown}
			result.Report = Projection{Knowledge: Unknown}
			result.Audit = Projection{Knowledge: Unknown}
			// A row outside the closed vocabulary makes the set incomplete.
			return count, invalid("sqlite.projection_boundary")
		}
		if seen[boundary] {
			*target = Projection{Knowledge: Conflict}
			continue
		}
		seen[boundary] = true
		candidate := Projection{Knowledge: Knowledge(knowledge)}
		if recordJSON.Valid {
			var record OutcomeRecord
			if err := decodeSQLiteRecord(recordJSON.String, &record); err != nil {
				*target = Projection{Knowledge: Unknown}
				continue
			}
			candidate.Record = &record
		}
		if err := readValidateProjection(request, result.Backend.Receipt, boundary, candidate); err != nil {
			*target = Projection{Knowledge: Unknown}
			if IsCode(err, CodeBindingConflict) {
				*target = Projection{Knowledge: Conflict}
			}
			continue
		}
		*target = candidate
	}
	if err := rows.Err(); err != nil {
		return count, p.readError(ctx, err, "sqlite.projection_rows")
	}
	return count, nil
}

// readTransition cross-checks historical receipt identity, independently from
// the current reference. A later or ABA reference never rewrites a past receipt.
func (p *SQLiteReadPort) readTransition(ctx context.Context, tx sqliteQueryer, request Request, result *ExecutionSnapshot) (int, error) {
	rows, err := tx.QueryContext(ctx, "SELECT transition_id, receipt_id, before_revision, before_state_version, after_revision, after_state_version FROM reference_transitions WHERE realm=? AND host=? AND resource=? AND backend=? AND execution_key=?", sqliteExecutionArgs(request)...)
	if err != nil {
		return 0, p.readError(ctx, err, "sqlite.history")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 1 {
			result.Backend = BackendObservation{Knowledge: Conflict}
			continue
		}
		var transition, receiptID, beforeRevision, beforeVersion, afterRevision, afterVersion string
		if err := rows.Scan(&transition, &receiptID, &beforeRevision, &beforeVersion, &afterRevision, &afterVersion); err != nil {
			return count, p.readError(ctx, err, "sqlite.history_row")
		}
		before, beforeErr := sqliteStateVersion(beforeVersion)
		after, afterErr := sqliteStateVersion(afterVersion)
		if beforeErr != nil || afterErr != nil ||
			validateID(ID(transition), "sqlite.transition") != nil ||
			validateID(ID(receiptID), "sqlite.history_receipt") != nil ||
			validateID(ID(beforeRevision), "sqlite.history_before") != nil ||
			validateID(ID(afterRevision), "sqlite.history_after") != nil ||
			before == ^uint64(0) || after != before+1 || beforeRevision == afterRevision {
			result.Backend = BackendObservation{Knowledge: Unknown}
			continue
		}
		if result.Backend.Knowledge == Absent {
			result.Backend = BackendObservation{Knowledge: Conflict}
			continue
		}
		if result.Backend.Knowledge != Known || result.Backend.Receipt == nil {
			continue
		}
		receipt := result.Backend.Receipt
		if receipt.Kind != Positive || receipt.Positive == nil ||
			receipt.ReceiptID != ID(receiptID) ||
			receipt.Positive.TransitionID != ID(transition) ||
			receipt.Positive.Before != (Reference{Revision: ID(beforeRevision), StateVersion: before}) ||
			receipt.Positive.After != (Reference{Revision: ID(afterRevision), StateVersion: after}) {
			result.Backend = BackendObservation{Knowledge: Conflict}
			continue
		}
		if result.Current.Knowledge == Known && result.Current.Reference != nil &&
			(result.Current.Reference.StateVersion < after ||
				(result.Current.Reference.StateVersion == after && result.Current.Reference.Revision != ID(afterRevision))) {
			result.Backend = BackendObservation{Knowledge: Conflict}
		}
	}
	if err := rows.Err(); err != nil {
		return count, p.readError(ctx, err, "sqlite.history_rows")
	}
	if count == 0 && result.Backend.Knowledge == Known && result.Backend.Receipt != nil && result.Backend.Receipt.Kind == Positive {
		result.Backend = BackendObservation{Knowledge: Unknown}
	}
	return count, nil
}
