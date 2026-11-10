package registry

import (
	"context"
	"reflect"
)

// ReconcilePartialRestore is D-02's pure planning boundary. No repair is applied.
// A future record writer must freshly verify each RequiredCapability, source
// evidence and Expected projection; the original mutation is never authorized.
func (r *Reader) ReconcilePartialRestore(ctx context.Context, query LookupRequest) (ReconciliationPlan, error) {
	result, snapshot, fresh, err := r.lookup(ctx, query, PlanReconciliationAction)
	plan := ReconciliationPlan{
		Knowledge:                  Unknown,
		Result:                     result,
		Outstanding:                append([]ID(nil), result.Outstanding...),
		OriginalMutationAuthorized: false,
	}
	if err != nil {
		if result.Knowledge == Conflict {
			plan.Knowledge = Conflict
		}
		return plan, err
	}
	if result.Knowledge == Conflict {
		plan.Knowledge = Conflict
		return plan, collision("reconciliation.snapshot")
	}
	if !fresh || result.Backend.Knowledge != Known || result.Backend.Receipt == nil {
		return plan, fault(CodeEvidenceUnknown, "reconciliation.backend")
	}
	receipt := *result.Backend.Receipt
	witness := snapshot.Witness
	if witness == nil {
		return plan, fault(CodeEvidenceUnknown, "reconciliation.witness_missing")
	}
	if err := validateID(witness.LiabilityID, "witness.liability"); err != nil {
		return plan, err
	}
	if err := validateID(witness.Evidence, "witness.evidence"); err != nil {
		return plan, err
	}
	if witness.Scope != query.Request.Command.Scope ||
		witness.Execution != query.Request.Command.Execution ||
		witness.Binding != query.Request.Binding {
		plan.Knowledge = Conflict
		return plan, collision("witness.identity")
	}
	if err := ValidateReceipt(query.Request, witness.Receipt); err != nil {
		if IsCode(err, CodeBindingConflict) {
			plan.Knowledge = Conflict
		}
		return plan, err
	}
	if !reflect.DeepEqual(witness.Receipt, receipt) {
		plan.Knowledge = Conflict
		return plan, collision("witness.outcome")
	}
	verifiedWitness := *witness
	verifiedWitness.Receipt = readCloneReceipt(witness.Receipt)
	if err := r.verifier.VerifyWitness(ctx, query.Request, verifiedWitness); err != nil {
		return plan, fault(CodeEvidenceUnknown, "reconciliation.witness")
	}
	for _, projection := range []Projection{result.Ledger, result.Report, result.Audit} {
		if projection.Knowledge == Conflict {
			plan.Knowledge = Conflict
			return plan, collision("reconciliation.projection")
		}
		if projection.Knowledge == Unknown {
			return plan, fault(CodeEvidenceUnknown, "reconciliation.projection")
		}
		if projection.Knowledge == Known && projection.Record.Boundary != CPReport &&
			projection.Record.Ack == AckUnknown {
			return plan, fault(CodeEvidenceUnknown, "reconciliation.record_ack")
		}
	}
	records, err := DescribeTerminalRecords(query.Request, receipt)
	if err != nil {
		return plan, err
	}
	for _, record := range records {
		var projection Projection
		var action RecordAction
		var capability RequiredRecordCapability
		switch record.Boundary {
		case ExecutorLedger:
			projection = result.Ledger
			action = RecordLedgerOutcome
			capability = ExecutorRecordCapability
		case CPReport:
			projection = result.Report
			action = RecordCPOutcome
			capability = CPReportCapability
		case CPAudit:
			projection = result.Audit
			action = RecordRecoveredAudit
			capability = CPAuditCapability
		}
		if projection.Knowledge == Known {
			if record.Boundary == CPReport && projection.Record.Ack == AckUnknown {
				action = ResendCPOutcome
			} else {
				// A known ledger/audit with unknown ACK is retained, not blindly
				// rewritten; this iteration has no authority to manufacture ACKs.
				if projection.Record.Ack == AckUnknown {
					return plan, fault(CodeEvidenceUnknown, "reconciliation.record_ack")
				}
				continue
			}
		}
		step := RepairStep{
			Action:             action,
			Boundary:           record.Boundary,
			RequiredCapability: capability,
			Expected:           readCloneProjection(projection),
			Outcome:            record,
			SourceReceipt:      receipt.ReceiptID,
			SourceWitness:      witness.Evidence,
		}
		if record.Boundary == CPAudit {
			// Missing current audit does not reconstruct the historical actor,
			// approval time or even establish availability of the original audit.
			step.OriginalAuditAvailability = Unknown
		}
		plan.Steps = append(plan.Steps, step)
	}
	plan.Knowledge = Known
	return plan, nil
}
