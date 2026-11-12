package registry

import (
	"context"
	"reflect"
)

// BackendReadFrame identifies a SQLite observation, never its restore freshness.
// It is not an independent Witness, lease, authority or execution permission.
type BackendReadFrame struct {
	Issuer             ID
	ServingIncarnation ID
	Generation         ID
	SnapshotID         ID
	ObservationProof   ID
}

type ContinuityReferenceObservation struct {
	Knowledge Knowledge
	Frame     BackendReadFrame
	Evidence  Evidence
}

type ContinuityExecutionObservation struct {
	Knowledge   Knowledge
	Frame       BackendReadFrame
	Evidence    Evidence
	Witness     *WitnessOutcome
	Outstanding []ID
}

// ContinuityReadPort is a trusted, independent, READ-ONLY dependency. There is no
// SQLite-backed implementation here. Qualification must cover the complete
// detached observation, not only a matching generation or a nonempty proof.
// Known includes complete Witness/Outstanding coverage, including known absence.
// Partial coverage, rollback uncertainty and unavailable authority mean Unknown.
// Existing Reader/Verifier authentication remains mandatory after qualification.
type ContinuityReadPort interface {
	QualifyReference(context.Context, Scope, BackendReadFrame, ActiveReference) (ContinuityReferenceObservation, error)
	QualifyExecution(context.Context, Request, BackendReadFrame, ExecutionSnapshot) (ContinuityExecutionObservation, error)
}

func sqliteValidateFrame(frame BackendReadFrame) error {
	for _, value := range []ID{frame.Issuer, frame.ServingIncarnation, frame.Generation, frame.SnapshotID, frame.ObservationProof} {
		if err := validateID(value, "sqlite.backend_frame"); err != nil {
			return err
		}
	}
	return nil
}

func sqliteFrameEvidence(frame BackendReadFrame) Evidence {
	return Evidence{
		Issuer: frame.Issuer, ServingIncarnation: frame.ServingIncarnation,
		Generation: frame.Generation, SnapshotID: frame.SnapshotID,
		ObservationProof: frame.ObservationProof,
	}
}

func sqliteFrameFromEvidence(evidence Evidence) BackendReadFrame {
	return BackendReadFrame{
		Issuer: evidence.Issuer, ServingIncarnation: evidence.ServingIncarnation,
		Generation: evidence.Generation, SnapshotID: evidence.SnapshotID,
		ObservationProof: evidence.ObservationProof,
	}
}

func sqliteQualifiedEvidence(frame BackendReadFrame, evidence Evidence) bool {
	if sqliteValidateFrame(frame) != nil || validateEvidence(evidence) != nil {
		return false
	}
	evidence.FreshnessProof = ""
	return evidence == sqliteFrameEvidence(frame)
}

func sqliteUnknownContinuity(snapshot ExecutionSnapshot) ExecutionSnapshot {
	// Keep historical SQL receipts/projections separate from UNKNOWN freshness.
	if snapshot.Current.Knowledge != Conflict {
		snapshot.Current = readUnknownActive(snapshot.Current.Scope)
	} else {
		snapshot.Current.Evidence = Evidence{}
	}
	snapshot.Evidence = Evidence{}
	snapshot.Witness = nil
	snapshot.Outstanding = nil
	return snapshot
}

func (p *SQLiteReadPort) qualifyReference(ctx context.Context, active ActiveReference) (ActiveReference, error) {
	if err := ctx.Err(); err != nil {
		return readUnknownActive(active.Scope), err
	}
	if active.Knowledge == Conflict {
		active.Evidence = Evidence{}
		return active, nil
	}
	frame := sqliteFrameFromEvidence(active.Evidence)
	if (active.Knowledge != Known && active.Knowledge != Absent) ||
		sqliteValidateFrame(frame) != nil || readNilPort(p.continuity) {
		return readUnknownActive(active.Scope), nil
	}
	observed, err := p.continuity.QualifyReference(ctx, active.Scope, frame, readCloneActive(active))
	if err := ctx.Err(); err != nil {
		return readUnknownActive(active.Scope), err
	}
	if err != nil || observed.Knowledge != Known || observed.Frame != frame ||
		!sqliteQualifiedEvidence(frame, observed.Evidence) {
		return readUnknownActive(active.Scope), nil
	}
	active.Evidence = observed.Evidence
	return active, nil
}

func (p *SQLiteReadPort) qualifyExecution(ctx context.Context, request Request, snapshot ExecutionSnapshot) (ExecutionSnapshot, error) {
	unknown := sqliteUnknownContinuity(readCloneSnapshot(snapshot))
	if err := ctx.Err(); err != nil {
		return unknown, err
	}
	frame := sqliteFrameFromEvidence(snapshot.Evidence)
	if (snapshot.Current.Knowledge != Known && snapshot.Current.Knowledge != Absent) ||
		sqliteValidateFrame(frame) != nil || readNilPort(p.continuity) {
		return unknown, nil
	}
	// The SQL transaction and connection are released BEFORE this call. A future
	// independent owner must bind the entire payload and refuse stale/mixed frames.
	observed, err := p.continuity.QualifyExecution(ctx, request, frame, readCloneSnapshot(snapshot))
	if err := ctx.Err(); err != nil {
		return unknown, err
	}
	if err != nil || observed.Knowledge != Known || observed.Frame != frame ||
		!sqliteQualifiedEvidence(frame, observed.Evidence) {
		return unknown, nil
	}
	seen := make(map[ID]bool, len(observed.Outstanding))
	for _, id := range observed.Outstanding {
		if validateID(id, "continuity.liability") != nil || seen[id] {
			return unknown, nil
		}
		seen[id] = true
	}
	if observed.Witness != nil {
		witness := observed.Witness
		if validateID(witness.LiabilityID, "continuity.witness_liability") != nil ||
			validateID(witness.Evidence, "continuity.witness_evidence") != nil ||
			witness.Scope != request.Command.Scope || witness.Execution != request.Command.Execution ||
			witness.Binding != request.Binding || ValidateReceipt(request, witness.Receipt) != nil {
			return unknown, nil
		}
		if snapshot.Backend.Receipt != nil && !reflect.DeepEqual(witness.Receipt, *snapshot.Backend.Receipt) {
			return unknown, nil
		}
		copy := *witness
		copy.Receipt = readCloneReceipt(witness.Receipt)
		snapshot.Witness = &copy
	}
	snapshot.Outstanding = append([]ID(nil), observed.Outstanding...)
	snapshot.Evidence = observed.Evidence
	snapshot.Current.Evidence = observed.Evidence
	return snapshot, nil
}
