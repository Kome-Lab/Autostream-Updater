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

// readPreflightSnapshot is a detached, read-only observation for Preflight.
// Every table and correlation check belongs to this same managed SQL snapshot.
// It does not qualify its own restore freshness or consume Writer admission.
func (p *SQLiteReadPort) readPreflightSnapshot(ctx context.Context, request Request) (PreflightSnapshot, error) {
    result := PreflightSnapshot{
        Snapshot: ExecutionSnapshot{
            Backend: BackendObservation{Knowledge: Unknown},
            Current: readUnknownActive(request.Command.Scope),
            Ledger: Projection{Knowledge: Unknown},
            Report: Projection{Knowledge: Unknown},
            Audit: Projection{Knowledge: Unknown},
        },
        IdentityKnowledge: Unknown,
        HistoryKnowledge: Unknown,
    }
    if err := ValidateRequest(request); err != nil { return result, err }
    tx, err := p.beginRead(ctx)
    if err != nil { return result, err }
    defer tx.Rollback()
    active, resourceFound, err := p.readActive(ctx, tx, request.Command.Scope)
    if err != nil { return result, err }
    result.Snapshot.Current, result.Snapshot.Evidence = active, active.Evidence
    resourceQualified := resourceFound && sqliteValidateFrame(sqliteFrameFromEvidence(active.Evidence)) == nil
    found, err := p.readExecution(ctx, tx, request, &result.Snapshot)
    if err != nil { return result, err }
    if resourceQualified {
        result.Snapshot.Ledger = Projection{Knowledge: Absent}
        result.Snapshot.Report = Projection{Knowledge: Absent}
        result.Snapshot.Audit = Projection{Knowledge: Absent}
    }
    projections, err := p.readProjections(ctx, tx, request, &result.Snapshot)
    if err != nil { return result, err }
    transitions, err := p.readTransition(ctx, tx, request, &result.Snapshot)
    if err != nil { return result, err }
    if found && !resourceFound { result.Snapshot.Backend = BackendObservation{Knowledge: Conflict} }
    if !found {
        if projections+transitions > 0 {
            result.Snapshot.Backend = BackendObservation{Knowledge: Conflict}
        } else if resourceQualified {
            result.Snapshot.Backend = BackendObservation{Knowledge: Absent}
        }
    }
    if err := p.readPreflightIdentities(ctx, tx, request, &result); err != nil { return result, err }
    if err := p.readPreflightScopeExecutions(ctx, tx, request.Command.Scope, &result); err != nil { return result, err }
    if err := p.readPreflightHistory(ctx, tx, request.Command.Scope, &result); err != nil { return result, err }
    if err := tx.Commit(); err != nil { return result, p.readError(ctx, err, "sqlite.preflight_snapshot") }
    return clonePreflightSnapshot(result), nil
}

// Uniqueness here covers the complete managed registry, not only the requested
// Scope. Absence is query coverage, never an unused grant or NOT_STARTED proof.
func (p *SQLiteReadPort) readPreflightIdentities(ctx context.Context, tx sqliteQueryer, request Request, result *PreflightSnapshot) error {
    execution := request.Command.Execution
    rows, err := tx.QueryContext(ctx, "SELECT realm,host,resource,backend,execution_key,request_id,operation_id,attempt_id,step_id,request_json FROM executions WHERE execution_key=? OR request_id=? OR (operation_id=? AND attempt_id=? AND step_id=?) ORDER BY realm,host,resource,backend,execution_key",
        string(execution.ExecutionKey), string(execution.RequestID), string(execution.OperationID), string(execution.AttemptID), string(execution.StepID))
    if err != nil { return p.readError(ctx, err, "sqlite.preflight_identity") }
    defer rows.Close()
    result.IdentityKnowledge = Known
    for rows.Next() {
        var realm, host, resource, backend, key, requestID, operation, attempt, step, raw string
        if err := rows.Scan(&realm, &host, &resource, &backend, &key, &requestID, &operation, &attempt, &step, &raw); err != nil {
            return p.readError(ctx, err, "sqlite.preflight_identity_row")
        }
        stored, err := DecodeRequest([]byte(raw))
        if err != nil {
            if result.IdentityKnowledge != Conflict { result.IdentityKnowledge = Unknown }
            continue
        }
        indexedScope := Scope{Realm: ID(realm), Host: ID(host), Resource: ID(resource), Backend: ID(backend)}
        indexedExecution := Execution{RequestID: ID(requestID), ExecutionKey: ID(key), OperationID: ID(operation), AttemptID: ID(attempt), StepID: ID(step)}
        if ValidateScope(indexedScope) != nil || ValidateExecution(indexedExecution) != nil ||
            stored.Command.Scope != indexedScope || stored.Command.Execution != indexedExecution {
            result.IdentityKnowledge = Conflict
        }
        result.IdentityMatches = append(result.IdentityMatches, stored)
    }
    if err := rows.Err(); err != nil { return p.readError(ctx, err, "sqlite.preflight_identity_rows") }
    if err := rows.Close(); err != nil { return p.readError(ctx, err, "sqlite.preflight_identity_close") }
    return nil
}

// Read the entire scoped transition set, with each historical immutable request
// and Receipt from the same SQL snapshot. Independent history/baseline coverage
// and authenticity remain verifier obligations, not facts synthesized by SQL.
func (p *SQLiteReadPort) readPreflightHistory(ctx context.Context, tx sqliteQueryer, scope Scope, result *PreflightSnapshot) error {
    rows, err := tx.QueryContext(ctx, "SELECT t.realm,t.host,t.resource,t.backend,t.execution_key,t.transition_id,t.receipt_id,t.before_revision,t.before_state_version,t.after_revision,t.after_state_version,e.request_id,e.operation_id,e.attempt_id,e.step_id,e.request_json,e.backend_knowledge,e.receipt_kind,e.receipt_json FROM reference_transitions t LEFT JOIN executions e ON e.realm=t.realm AND e.host=t.host AND e.resource=t.resource AND e.backend=t.backend AND e.execution_key=t.execution_key WHERE t.realm=? AND t.host=? AND t.resource=? AND t.backend=? ORDER BY t.after_state_version,t.transition_id", sqliteScopeArgs(scope)...)
    if err != nil { return p.readError(ctx, err, "sqlite.preflight_history") }
    defer rows.Close()
    result.HistoryKnowledge = Known
    for rows.Next() {
        var realm, host, resource, backend, key, transition, receiptID, beforeRevision, beforeVersion, afterRevision, afterVersion string
        var requestID, operationID, attemptID, stepID, rawRequest, backendKnowledge, rawKind, rawReceipt sql.NullString
        if err := rows.Scan(&realm, &host, &resource, &backend, &key, &transition, &receiptID, &beforeRevision, &beforeVersion, &afterRevision, &afterVersion,
            &requestID, &operationID, &attemptID, &stepID, &rawRequest, &backendKnowledge, &rawKind, &rawReceipt); err != nil {
            return p.readError(ctx, err, "sqlite.preflight_history_row")
        }
        before, beforeErr := sqliteStateVersion(beforeVersion)
        after, afterErr := sqliteStateVersion(afterVersion)
        entry := PreflightTransition{
            Scope: Scope{Realm: ID(realm), Host: ID(host), Resource: ID(resource), Backend: ID(backend)},
            ExecutionKey: ID(key), TransitionID: ID(transition), ReceiptID: ID(receiptID),
            Before: Reference{Revision: ID(beforeRevision), StateVersion: before},
            After: Reference{Revision: ID(afterRevision), StateVersion: after},
        }
        if beforeErr != nil || afterErr != nil || ValidateScope(entry.Scope) != nil ||
            validateID(entry.ExecutionKey, "preflight.history_key") != nil ||
            validateID(entry.TransitionID, "preflight.history_transition") != nil ||
            validateID(entry.ReceiptID, "preflight.history_receipt") != nil ||
            validateID(entry.Before.Revision, "preflight.history_before") != nil ||
            validateID(entry.After.Revision, "preflight.history_after") != nil {
            if result.HistoryKnowledge != Conflict { result.HistoryKnowledge = Unknown }
        }
        if !requestID.Valid || !operationID.Valid || !attemptID.Valid || !stepID.Valid || !rawRequest.Valid ||
            !backendKnowledge.Valid || !rawKind.Valid || !rawReceipt.Valid {
            if result.HistoryKnowledge != Conflict { result.HistoryKnowledge = Unknown }
            result.History = append(result.History, entry)
            continue
        }
        stored, decodeErr := DecodeRequest([]byte(rawRequest.String))
        if decodeErr != nil {
            if result.HistoryKnowledge != Conflict { result.HistoryKnowledge = Unknown }
            result.History = append(result.History, entry)
            continue
        }
        indexed := Execution{RequestID: ID(requestID.String), ExecutionKey: entry.ExecutionKey, OperationID: ID(operationID.String), AttemptID: ID(attemptID.String), StepID: ID(stepID.String)}
        if ValidateExecution(indexed) != nil || stored.Command.Scope != entry.Scope || stored.Command.Execution != indexed {
            result.HistoryKnowledge = Conflict
        }
        entry.Request = &stored
        var receipt Receipt
        if decodeSQLiteRecord(rawReceipt.String, &receipt) != nil {
            if result.HistoryKnowledge != Conflict { result.HistoryKnowledge = Unknown }
        } else {
            entry.Receipt = &receipt
            if backendKnowledge.String != string(Known) || rawKind.String != string(Positive) || receipt.Kind != Positive {
                result.HistoryKnowledge = Conflict
            }
        }
        result.History = append(result.History, entry)
    }
    if err := rows.Err(); err != nil { return p.readError(ctx, err, "sqlite.preflight_history_rows") }
    if err := rows.Close(); err != nil { return p.readError(ctx, err, "sqlite.preflight_history_close") }
    return nil
}

// Observe every execution in the affected Scope, not only aliases of this key.
// A known local UNKNOWN from an older key cannot be hidden by an empty external
// Outstanding slice. This is local content coverage, not independent freshness.
func (p *SQLiteReadPort) readPreflightScopeExecutions(ctx context.Context, tx sqliteQueryer, scope Scope, result *PreflightSnapshot) error {
    rows, err := tx.QueryContext(ctx, "SELECT execution_key,request_id,operation_id,attempt_id,step_id,request_json,backend_knowledge,receipt_kind,receipt_json FROM executions WHERE realm=? AND host=? AND resource=? AND backend=? ORDER BY execution_key", sqliteScopeArgs(scope)...)
    if err != nil { return p.readError(ctx, err, "sqlite.preflight_scope_executions") }
    defer rows.Close()
    result.ScopeExecutionKnowledge = Known
    for rows.Next() {
        var key, requestID, operation, attempt, step, raw, knowledge string
        var rawKind, rawReceipt sql.NullString
        if err := rows.Scan(&key, &requestID, &operation, &attempt, &step, &raw, &knowledge, &rawKind, &rawReceipt); err != nil {
            return p.readError(ctx, err, "sqlite.preflight_scope_row")
        }
        entry := PreflightExecutionObservation{Backend: BackendObservation{Knowledge: Unknown}}
        stored, err := DecodeRequest([]byte(raw))
        if err != nil {
            if result.ScopeExecutionKnowledge != Conflict { result.ScopeExecutionKnowledge = Unknown }
            result.ScopeExecutions = append(result.ScopeExecutions, entry)
            continue
        }
        entry.Request = &stored
        indexed := Execution{RequestID: ID(requestID), ExecutionKey: ID(key), OperationID: ID(operation), AttemptID: ID(attempt), StepID: ID(step)}
        if ValidateExecution(indexed) != nil || stored.Command.Scope != scope || stored.Command.Execution != indexed {
            result.ScopeExecutionKnowledge = Conflict
        }
        entry.Backend.Knowledge = Knowledge(knowledge)
        if rawReceipt.Valid {
            var receipt Receipt
            if decodeSQLiteRecord(rawReceipt.String, &receipt) != nil {
                if result.ScopeExecutionKnowledge != Conflict { result.ScopeExecutionKnowledge = Unknown }
            } else {
                entry.Backend.Receipt = &receipt
                if !rawKind.Valid || ReceiptKind(rawKind.String) != receipt.Kind {
                    result.ScopeExecutionKnowledge = Conflict
                }
            }
        } else if rawKind.Valid {
            result.ScopeExecutionKnowledge = Conflict
        }
        if err := ValidateBackendObservation(stored, entry.Backend); err != nil {
            if IsCode(err, CodeBindingConflict) { result.ScopeExecutionKnowledge = Conflict
            } else if result.ScopeExecutionKnowledge != Conflict { result.ScopeExecutionKnowledge = Unknown }
        }
        result.ScopeExecutions = append(result.ScopeExecutions, entry)
    }
    if err := rows.Err(); err != nil { return p.readError(ctx, err, "sqlite.preflight_scope_rows") }
    if err := rows.Close(); err != nil { return p.readError(ctx, err, "sqlite.preflight_scope_close") }
    // An orphan projection is a known local integrity/coverage gap. It cannot
    // disappear just because the new request has a different execution key.
    var orphans int64
    err = tx.QueryRowContext(ctx, "SELECT count(*) FROM projections p WHERE p.realm=? AND p.host=? AND p.resource=? AND p.backend=? AND NOT EXISTS (SELECT 1 FROM executions e WHERE e.realm=p.realm AND e.host=p.host AND e.resource=p.resource AND e.backend=p.backend AND e.execution_key=p.execution_key)", sqliteScopeArgs(scope)...).Scan(&orphans)
    if err != nil { return p.readError(ctx, err, "sqlite.preflight_scope_orphan") }
    if orphans != 0 && result.ScopeExecutionKnowledge != Conflict { result.ScopeExecutionKnowledge = Unknown }
    return nil
}
