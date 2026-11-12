package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
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

// SQLiteReadPort maps registry facts and qualifies independent Continuity. The
// single lifecycle owner holds all file/lease/pool/transaction/Close resources.
// No Writer, writable profile, service apply or recovery authority is supplied.
type SQLiteReadPort struct {
	owner      *registryLifecycleOwner
	continuity ContinuityReadPort
}

var _ ReadPort = (*SQLiteReadPort)(nil)

func OpenSQLiteReadPort(ctx context.Context, config SQLiteReadConfig) (*SQLiteReadPort, error) {
	owner, err := openRegistryLifecycleOwner(ctx, config)
	if err != nil {
		return nil, err
	}
	return &SQLiteReadPort{owner: owner, continuity: config.Continuity}, nil
}

func (p *SQLiteReadPort) beginOperation(ctx context.Context) (*registryOperation, error) {
	if ctx == nil {
		return nil, invalid("sqlite.context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == nil || p.owner == nil {
		return nil, ErrSQLiteClosed
	}
	return p.owner.acquire(ctx)
}

// beginRead is a tracked owner borrow, including internal callers. A returned
// transaction owns its SQL connection and operation until terminal cleanup.
func (p *SQLiteReadPort) beginRead(ctx context.Context) (*sqliteReadTx, error) {
	if p == nil || p.owner == nil {
		return nil, ErrSQLiteClosed
	}
	return p.owner.beginRead(ctx)
}

func (p *SQLiteReadPort) readError(ctx context.Context, err error, field string) error {
	if p == nil {
		var owner *registryLifecycleOwner
		return owner.readError(ctx, err, field)
	}
	return p.owner.readError(ctx, err, field)
}

func (p *SQLiteReadPort) Close() error {
	if p == nil {
		return nil
	}
	return p.owner.Close()
}

func sqliteScopeArgs(scope Scope) []any {
	return []any{string(scope.Realm), string(scope.Host), string(scope.Resource), string(scope.Backend)}
}

func sqliteExecutionArgs(request Request) []any {
	return append(sqliteScopeArgs(request.Command.Scope), string(request.Command.Execution.ExecutionKey))
}

func (p *SQLiteReadPort) ReadActiveReference(ctx context.Context, scope Scope) (ActiveReference, error) {
	result := readUnknownActive(scope)
	operation, err := p.beginOperation(ctx)
	if err != nil {
		return result, err
	}
	defer operation.release()
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
	operation, err := p.beginOperation(ctx)
	if err != nil {
		return result, err
	}
	defer operation.release()
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
