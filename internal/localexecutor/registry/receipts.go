package registry

// DecisionProfile separates actuation eligibility from a durable refusal.
// This internal representation is not an adoption of a wire or clock product.
type DecisionProfile string

const (
	D1GuardDecision            DecisionProfile = "D1_GUARD_DECISION"
	QualifiedRejectionDecision DecisionProfile = "QUALIFIED_REJECTION"
)

// ValidateReceipt validates structure and immutable correlation, not authenticity.
// An owner-controlled Verifier must authenticate the durable receipt separately.
func ValidateReceipt(request Request, receipt Receipt) error {
	if err := ValidateRequest(request); err != nil {
		return err
	}
	for _, item := range []struct {
		value ID
		field string
	}{
		{receipt.ReceiptID, "receipt.id"},
		{receipt.CommitID, "receipt.commit"},
		{receipt.ProducerBackend, "receipt.producer"},
		{receipt.Proof, "receipt.proof"},
		{receipt.Decision.Proof, "receipt.decision.proof"},
	} {
		if err := validateID(item.value, item.field); err != nil {
			return err
		}
	}
	if err := ValidateScope(receipt.Scope); err != nil {
		return err
	}
	if err := ValidateExecution(receipt.Execution); err != nil {
		return err
	}
	command := request.Command
	if receipt.Scope != command.Scope || receipt.ProducerBackend != command.Scope.Backend {
		return collision("receipt.scope")
	}
	if receipt.Execution != command.Execution || receipt.Binding != request.Binding {
		return collision("receipt.execution_binding")
	}
	for _, value := range []ID{
		receipt.Guard.Policy, receipt.Guard.Trust, receipt.Guard.Membership,
		receipt.Guard.OwnershipEpoch, receipt.Guard.FenceEpoch, receipt.Guard.Generation,
		receipt.Guard.BootID, receipt.Guard.ProcessIncarnation, receipt.Decision.TimeBase,
	} {
		if err := validateID(value, "receipt.observed_guard"); err != nil {
			return err
		}
	}
	if receipt.Decision.BootID != receipt.Guard.BootID {
		return collision("receipt.decision_boot")
	}
	if receipt.Decision.LowerTick > receipt.Decision.UpperTick {
		return invalid("receipt.decision_interval")
	}
	switch receipt.Kind {
	case Positive:
		if receipt.Decision.Profile != D1GuardDecision {
			return invalid("receipt.decision_profile")
		}
		if receipt.Guard != command.RequiredGuard {
			return collision("receipt.guard")
		}
		if receipt.Decision.TimeBase != command.Timing.TimeBase {
			return collision("receipt.decision_timebase")
		}
		if receipt.Decision.UpperTick > command.Timing.DeadlineTick {
			return invalid("receipt.decision_deadline")
		}
		if receipt.Positive == nil || receipt.Negative != nil {
			return invalid("receipt.payload")
		}
		payload := receipt.Positive
		if err := validateID(payload.TransitionID, "receipt.transition"); err != nil {
			return err
		}
		if payload.Before != command.Expected ||
			payload.After.Revision != command.CandidateRevision {
			return collision("receipt.transition_reference")
		}
		if payload.Before.Revision == payload.After.Revision {
			return invalid("receipt.unsupported_no_change")
		}
		if payload.Before.StateVersion == ^uint64(0) ||
			payload.After.StateVersion != payload.Before.StateVersion+1 {
			return invalid("receipt.transition_version")
		}
		if payload.Semantic != ReferenceCommittedNotServiceApplied {
			return invalid("receipt.semantic")
		}
	case Negative:
		if receipt.Decision.Profile != QualifiedRejectionDecision {
			return invalid("receipt.decision_profile")
		}
		if receipt.Negative == nil || receipt.Positive != nil {
			return invalid("receipt.payload")
		}
		switch receipt.Negative.Reason {
		case GuardRejected, PreconditionMismatch, NotChangedProposed:
		default:
			return invalid("receipt.negative_reason")
		}
		if err := validateID(receipt.Negative.NoAdditionalEffectProof, "receipt.negative_proof"); err != nil {
			return err
		}
	default:
		return invalid("receipt.kind")
	}
	return nil
}

// ValidateBackendObservation never equates absence/UNKNOWN with a negative result.
func ValidateBackendObservation(request Request, observation BackendObservation) error {
	if err := ValidateRequest(request); err != nil {
		return err
	}
	switch observation.Knowledge {
	case Known:
		if observation.Receipt == nil {
			return invalid("backend.known_receipt")
		}
		return ValidateReceipt(request, *observation.Receipt)
	case Absent, Unknown, Conflict:
		if observation.Receipt != nil {
			return invalid("backend.nonknown_receipt")
		}
		return nil
	default:
		return invalid("backend.knowledge")
	}
}

// DescribeTerminalRecords implements D-01's terminal-record contract for BOTH
// signs. It is data only: no ledger, report, audit, grant, or original operation
// is written or dispatched. NOT_CHANGED remains an explicit proposed reason.
func DescribeTerminalRecords(request Request, receipt Receipt) ([]TerminalRecord, error) {
	if err := ValidateReceipt(request, receipt); err != nil {
		return nil, err
	}
	result := ReferenceCommittedNotServiceApplied
	if receipt.Kind == Negative {
		result = string(receipt.Negative.Reason)
	}
	records := make([]TerminalRecord, 0, 3)
	for _, boundary := range []Boundary{ExecutorLedger, CPReport, CPAudit} {
		records = append(records, TerminalRecord{
			Boundary:    boundary,
			Scope:       receipt.Scope,
			Execution:   receipt.Execution,
			Binding:     receipt.Binding,
			ReceiptID:   receipt.ReceiptID,
			ReceiptKind: receipt.Kind,
			Result:      result,
		})
	}
	return records, nil
}
