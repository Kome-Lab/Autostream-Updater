package registry

import (
	"context"
	"reflect"
)

// Reader owns no writer or recovery handle. Ports are trusted dependencies, not
// caller-provided evidence booleans. Returned data is detached from port storage.
type Reader struct {
	port       ReadPort
	authorizer QueryAuthorizer
	verifier   Verifier
}

func readNilPort(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func NewReader(port ReadPort, authorizer QueryAuthorizer, verifier Verifier) (*Reader, error) {
	if readNilPort(port) || readNilPort(authorizer) || readNilPort(verifier) {
		return nil, invalid("reader.dependencies")
	}
	return &Reader{port: port, authorizer: authorizer, verifier: verifier}, nil
}

func readUnknownActive(scope Scope) ActiveReference {
	return ActiveReference{Knowledge: Unknown, Scope: scope}
}

func readUnknownResult(scope Scope) LookupResult {
	return LookupResult{
		Knowledge:          Unknown,
		Backend:            BackendObservation{Knowledge: Unknown},
		Current:            readUnknownActive(scope),
		Ledger:             Projection{Knowledge: Unknown},
		Report:             Projection{Knowledge: Unknown},
		Audit:              Projection{Knowledge: Unknown},
		ServiceApplication: ServiceApplicationOutsideScope,
	}
}

func (r *Reader) authorize(ctx context.Context, call Call, action QueryAction, scope Scope) error {
	if r == nil || ctx == nil || readNilPort(r.port) || readNilPort(r.authorizer) || readNilPort(r.verifier) {
		return invalid("reader.context")
	}
	if err := validateCall(call); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fault(CodeUnavailable, "context")
	}
	if err := r.authorizer.Authorize(ctx, call, action, scope); err != nil {
		return fault(CodeUnauthorized, "query_authority")
	}
	return nil
}

func readValidateActive(scope Scope, active ActiveReference) error {
	if err := ValidateScope(active.Scope); err != nil {
		return err
	}
	if active.Scope != scope {
		return collision("active.scope")
	}
	switch active.Knowledge {
	case Known:
		if active.Reference == nil {
			return invalid("active.reference")
		}
		if err := validateID(active.Reference.Revision, "active.revision"); err != nil {
			return err
		}
		return validateEvidence(active.Evidence)
	case Absent:
		if active.Reference != nil {
			return invalid("active.absent_reference")
		}
		return validateEvidence(active.Evidence)
	case Unknown, Conflict:
		if active.Reference != nil {
			return invalid("active.nonknown_reference")
		}
		if active.Evidence != (Evidence{}) {
			return validateEvidence(active.Evidence)
		}
		return nil
	default:
		return invalid("active.knowledge")
	}
}

func (r *Reader) ReadActiveReference(ctx context.Context, request ReadRequest) (ActiveReference, error) {
	result := readUnknownActive(request.Scope)
	if err := ValidateScope(request.Scope); err != nil {
		return result, err
	}
	if err := r.authorize(ctx, request.Call, ReadReferenceAction, request.Scope); err != nil {
		return result, err
	}
	active, err := r.port.ReadActiveReference(ctx, request.Scope)
	if err != nil {
		return result, fault(CodeUnavailable, "active.read")
	}
	active = readCloneActive(active)
	if err := readValidateActive(request.Scope, active); err != nil {
		return result, err
	}
	if active.Knowledge == Known || active.Knowledge == Absent {
		if err := r.verifier.VerifyActiveReference(ctx, request.Scope, readCloneActive(active)); err != nil {
			return result, fault(CodeEvidenceUnknown, "active.freshness")
		}
	}
	return active, nil
}

func (r *Reader) LookupExecution(ctx context.Context, request LookupRequest) (LookupResult, error) {
	result, _, _, err := r.lookup(ctx, request, LookupExecutionAction)
	return result, err
}

func (r *Reader) lookup(ctx context.Context, query LookupRequest, action QueryAction) (LookupResult, ExecutionSnapshot, bool, error) {
	result := readUnknownResult(query.Request.Command.Scope)
	var snapshot ExecutionSnapshot
	if err := ValidateRequest(query.Request); err != nil {
		return result, snapshot, false, err
	}
	scope := query.Request.Command.Scope
	if err := r.authorize(ctx, query.Call, action, scope); err != nil {
		return result, snapshot, false, err
	}
	observed, err := r.port.ReadExecution(ctx, query.Request)
	if err != nil {
		return result, snapshot, false, fault(CodeUnavailable, "execution.read")
	}
	snapshot = readCloneSnapshot(observed)
	result.Outstanding = append([]ID(nil), snapshot.Outstanding...)
	for _, id := range snapshot.Outstanding {
		if err := validateID(id, "outstanding.liability"); err != nil {
			return result, snapshot, false, err
		}
	}
	if err := ValidateBackendObservation(query.Request, snapshot.Backend); err != nil {
		if IsCode(err, CodeBindingConflict) {
			result.Knowledge = Conflict
		}
		return result, snapshot, false, err
	}
	if snapshot.Backend.Knowledge == Known {
		if err := r.verifier.VerifyReceipt(ctx, query.Request, readCloneReceipt(*snapshot.Backend.Receipt)); err != nil {
			return result, snapshot, false, fault(CodeEvidenceUnknown, "backend.receipt")
		}
		// Historical authenticity is independent from current restore freshness.
		result.Backend = snapshot.Backend
	} else {
		result.Backend = snapshot.Backend
	}
	if snapshot.StoredRequest != nil {
		if err := ValidateRequest(*snapshot.StoredRequest); err != nil {
			return result, snapshot, false, err
		}
		if *snapshot.StoredRequest != query.Request {
			result.Knowledge = Conflict
			return result, snapshot, false, collision("stored_request")
		}
	} else if snapshot.Backend.Knowledge == Known {
		return result, snapshot, false, fault(CodeEvidenceUnknown, "stored_request.missing")
	}
	if err := validateEvidence(snapshot.Evidence); err != nil {
		return result, snapshot, false, err
	}
	if err := readValidateActive(scope, snapshot.Current); err != nil {
		return result, snapshot, false, err
	}
	for _, item := range []struct {
		boundary   Boundary
		projection Projection
	}{
		{ExecutorLedger, snapshot.Ledger},
		{CPReport, snapshot.Report},
		{CPAudit, snapshot.Audit},
	} {
		if err := readValidateProjection(query.Request, snapshot.Backend.Receipt, item.boundary, item.projection); err != nil {
			if IsCode(err, CodeBindingConflict) {
				result.Knowledge = Conflict
			}
			return result, snapshot, false, err
		}
	}
	if err := r.verifier.VerifyExecutionSnapshot(ctx, query.Request, readCloneSnapshot(snapshot)); err != nil {
		return result, snapshot, false, fault(CodeEvidenceUnknown, "execution.freshness")
	}
	if snapshot.Current.Knowledge == Known || snapshot.Current.Knowledge == Absent {
		if err := r.verifier.VerifyActiveReference(ctx, scope, readCloneActive(snapshot.Current)); err != nil {
			return result, snapshot, false, fault(CodeEvidenceUnknown, "active.freshness")
		}
	}
	result.Current = snapshot.Current
	result.Ledger = snapshot.Ledger
	result.Report = snapshot.Report
	result.Audit = snapshot.Audit
	result.Knowledge = snapshot.Backend.Knowledge
	if snapshot.Current.Knowledge == Unknown || snapshot.Current.Knowledge == Conflict ||
		snapshot.Ledger.Knowledge == Unknown || snapshot.Report.Knowledge == Unknown ||
		snapshot.Audit.Knowledge == Unknown {
		result.Knowledge = Unknown
	}
	if snapshot.Backend.Knowledge == Conflict || snapshot.Current.Knowledge == Conflict ||
		snapshot.Ledger.Knowledge == Conflict || snapshot.Report.Knowledge == Conflict ||
		snapshot.Audit.Knowledge == Conflict {
		result.Knowledge = Conflict
	}
	return result, snapshot, true, nil
}

func readValidateProjection(request Request, receipt *Receipt, boundary Boundary, projection Projection) error {
	switch projection.Knowledge {
	case Absent, Unknown, Conflict:
		if projection.Record != nil {
			return invalid("projection.nonknown_record")
		}
		return nil
	case Known:
		if projection.Record == nil {
			return invalid("projection.known_record")
		}
	default:
		return invalid("projection.knowledge")
	}
	record := projection.Record
	if record.Scope != request.Command.Scope || record.Execution != request.Command.Execution ||
		record.Binding != request.Binding || record.Boundary != boundary {
		return collision("projection.identity")
	}
	for _, item := range []struct {
		id    ID
		field string
	}{
		{record.ReceiptID, "projection.receipt"},
		{record.RecordedBy, "projection.recorded_by"},
		{record.RecordAuthority, "projection.record_authority"},
		{record.Evidence, "projection.evidence"},
	} {
		if err := validateID(item.id, item.field); err != nil {
			return err
		}
	}
	if record.ReceiptKind != Positive && record.ReceiptKind != Negative {
		return invalid("projection.kind")
	}
	if receipt != nil && (record.ReceiptID != receipt.ReceiptID || record.ReceiptKind != receipt.Kind) {
		return collision("projection.outcome")
	}
	if record.Ack != AckConfirmed && record.Ack != AckUnknown {
		return invalid("projection.ack")
	}
	if boundary != CPAudit {
		if record.Recovered || record.OriginalAuditAvailability != "" {
			return invalid("projection.audit_scope")
		}
	} else if record.Recovered {
		if record.OriginalAuditAvailability != Unknown && record.OriginalAuditAvailability != Absent {
			return invalid("projection.recovered_audit")
		}
	} else if record.OriginalAuditAvailability != Known {
		return invalid("projection.original_audit")
	}
	return nil
}

func readCloneReceipt(receipt Receipt) Receipt {
	result := receipt
	if receipt.Positive != nil {
		payload := *receipt.Positive
		result.Positive = &payload
	}
	if receipt.Negative != nil {
		payload := *receipt.Negative
		result.Negative = &payload
	}
	return result
}

func readCloneActive(active ActiveReference) ActiveReference {
	result := active
	if active.Reference != nil {
		reference := *active.Reference
		result.Reference = &reference
	}
	return result
}

func readCloneProjection(projection Projection) Projection {
	result := projection
	if projection.Record != nil {
		record := *projection.Record
		result.Record = &record
	}
	return result
}

func readCloneSnapshot(snapshot ExecutionSnapshot) ExecutionSnapshot {
	result := snapshot
	if snapshot.StoredRequest != nil {
		request := *snapshot.StoredRequest
		result.StoredRequest = &request
	}
	if snapshot.Backend.Receipt != nil {
		receipt := readCloneReceipt(*snapshot.Backend.Receipt)
		result.Backend.Receipt = &receipt
	}
	result.Current = readCloneActive(snapshot.Current)
	result.Ledger = readCloneProjection(snapshot.Ledger)
	result.Report = readCloneProjection(snapshot.Report)
	result.Audit = readCloneProjection(snapshot.Audit)
	if snapshot.Witness != nil {
		witness := *snapshot.Witness
		witness.Receipt = readCloneReceipt(snapshot.Witness.Receipt)
		result.Witness = &witness
	}
	result.Outstanding = append([]ID(nil), snapshot.Outstanding...)
	return result
}
