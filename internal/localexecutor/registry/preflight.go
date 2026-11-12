package registry

import (
	"context"
	"reflect"
)

// PreflightStatus describes a detached observation, never mutation authority.
type PreflightStatus string

const (
	PreflightEligible     PreflightStatus = "ELIGIBLE"
	PreflightRejected     PreflightStatus = "REJECTED"
	PreflightUnknown      PreflightStatus = "UNKNOWN"
	PreflightConflict     PreflightStatus = "CONFLICT"
	PreflightCommitAction QueryAction     = "registry.conditional_commit_preflight"
)

// PreflightResult intentionally contains no token, seal, lease or reservation.
// No Writer accepts this type. A future commit must repeat the checks under its
// actual Backend enforcement boundary; historical ELIGIBLE cannot authorize it.
type PreflightResult struct {
	Status    PreflightStatus
	Reason    string
	Scope     Scope
	Execution Execution
	Binding   Binding
	Observed  *Reference
	Frame     BackendReadFrame
}

func (PreflightResult) AuthorizesMutation() bool { return false }
func (PreflightResult) ReusableForCommit() bool  { return false }

type PreflightCondition string

const (
	PreflightConditionValid   PreflightCondition = "VALID"
	PreflightConditionDenied  PreflightCondition = "DENIED"
	PreflightConditionUnknown PreflightCondition = "UNKNOWN"
)

type PreflightBusinessAdmission string

const (
	PreflightBusinessOpen    PreflightBusinessAdmission = "OPEN"
	PreflightBusinessClosed  PreflightBusinessAdmission = "CLOSED"
	PreflightBusinessUnknown PreflightBusinessAdmission = "UNKNOWN"
)

type PreflightDrainState string

const (
	PreflightDrainReady    PreflightDrainState = "READY"
	PreflightDrainNotReady PreflightDrainState = "NOT_READY"
	PreflightDrainHeld     PreflightDrainState = "HELD"
	PreflightDrainUnknown  PreflightDrainState = "UNKNOWN"
)

// These are observations from trusted, read-only dependencies, not caller fields.
type PreflightGuardObservation struct {
	Knowledge         Knowledge
	Scope             Scope
	Execution         Execution
	Binding           Binding
	Frame             BackendReadFrame
	Current           Guard
	CPAuthorization   PreflightCondition
	Policy            PreflightCondition
	Trust             PreflightCondition
	Membership        PreflightCondition
	Ownership         PreflightCondition
	Fence             PreflightCondition
	Boot              PreflightCondition
	Process           PreflightCondition
	PAdmission        PreflightCondition
	Candidate         PreflightCondition
	BusinessAdmission PreflightBusinessAdmission
	Drain             PreflightDrainState
	DrainSeal         ID
	Proof             ID
}

type PreflightGuardReadPort interface {
	ObservePreflight(context.Context, Request, BackendReadFrame) (PreflightGuardObservation, error)
}

type PreflightTransition struct {
	Scope        Scope
	ExecutionKey ID
	TransitionID ID
	ReceiptID    ID
	Before       Reference
	After        Reference
	Request      *Request
	Receipt      *Receipt
}

// Every SQL field comes from the same managed Read transaction. Known identity
// means the managed registry scan completed, not global uniqueness permission.
type PreflightExecutionObservation struct {
	Request *Request
	Backend BackendObservation
}

type PreflightSnapshot struct {
	Snapshot                ExecutionSnapshot
	ScopeExecutionKnowledge Knowledge
	ScopeExecutions         []PreflightExecutionObservation
	IdentityKnowledge       Knowledge
	IdentityMatches         []Request
	HistoryKnowledge        Knowledge
	History                 []PreflightTransition
}

type PreflightContinuityObservation struct {
	Knowledge           Knowledge
	Scope               Scope
	Execution           Execution
	Binding             Binding
	Frame               BackendReadFrame
	Evidence            Evidence
	ContinuityIssuer    ID
	Proof               ID
	WitnessCoverage     Knowledge
	OutstandingCoverage Knowledge
	HistoryCoverage     Knowledge
	IdentityCoverage    Knowledge
	FreshnessCoverage   Knowledge
	HistoryBaseline     *Reference
	Witness             *WitnessOutcome
	Outstanding         []ID
}

// The added profile requires scope/resource-wide coverage, including older
// execution keys, plus an authenticated history baseline. Legacy qualification
// is insufficient for a new-start eligibility decision. No Store is implemented.
type ContinuityPreflightReadPort interface {
	ContinuityReadPort
	QualifyPreflight(context.Context, Request, BackendReadFrame, PreflightSnapshot) (PreflightContinuityObservation, error)
}

// Verifiers must authenticate the COMPLETE payload, not nonempty references.
// Guard verification includes issuer/audience/scope, immutable Request, live CP
// authority, effective Policy/Trust, membership/Drain closure, ownership/Fence,
// Boot/incarnation, expiry and Candidate existence/approval/content pin. Continuity
// verification includes complete affected-scope Witness/Outstanding/identity/
// history coverage, baseline provenance, restore freshness and the exact detached
// SQL payload/frame. No clock, token product or final D1 decision is selected here.
type PreflightVerifier interface {
	Verifier
	VerifyPreflightGuard(context.Context, Request, PreflightSnapshot, PreflightGuardObservation) error
	VerifyPreflightContinuity(context.Context, Request, PreflightSnapshot, PreflightContinuityObservation) error
}

type ConditionalCommitPreflight struct {
	port       *SQLiteReadPort
	authorizer QueryAuthorizer
	verifier   PreflightVerifier
	guard      PreflightGuardReadPort
}

func NewConditionalCommitPreflight(port *SQLiteReadPort, authorizer QueryAuthorizer, verifier PreflightVerifier, guard PreflightGuardReadPort) (*ConditionalCommitPreflight, error) {
	if port == nil || port.owner == nil || readNilPort(authorizer) || readNilPort(verifier) {
		return nil, invalid("preflight.dependencies")
	}
	return &ConditionalCommitPreflight{port: port, authorizer: authorizer, verifier: verifier, guard: guard}, nil
}

func preflightResult(request Request, status PreflightStatus, reason string) PreflightResult {
	return PreflightResult{Status: status, Reason: reason, Scope: request.Command.Scope,
		Execution: request.Command.Execution, Binding: request.Binding}
}

// CheckEncoded reuses the existing bounded, strict ImmutableRequest decoder.
// A Receipt/Witness/old PreflightResult cannot be smuggled into Command/Binding.
func (p *ConditionalCommitPreflight) CheckEncoded(ctx context.Context, call Call, encoded []byte) (PreflightResult, error) {
	if ctx == nil {
		return preflightResult(Request{}, PreflightRejected, "invalid_context"), invalid("preflight.context")
	}
	if err := ctx.Err(); err != nil {
		return preflightResult(Request{}, PreflightUnknown, "context_canceled"), err
	}
	request, err := DecodeRequest(encoded)
	if err != nil {
		status := PreflightRejected
		if IsCode(err, CodeBindingConflict) {
			status = PreflightConflict
		}
		return preflightResult(request, status, "request_invalid"), err
	}
	return p.Check(ctx, LookupRequest{Call: call, Request: request})
}

// Check borrows only the Read role. SQL connections finish before external
// validation; the outer borrow remains a Close/drain duty throughout. It never
// installs/consumes Writer admission or reserves a future commit.
func (p *ConditionalCommitPreflight) Check(ctx context.Context, query LookupRequest) (result PreflightResult, resultErr error) {
	request := query.Request
	result = preflightResult(request, PreflightUnknown, "observation_unavailable")
	if p == nil || p.port == nil || p.port.owner == nil || ctx == nil ||
		readNilPort(p.authorizer) || readNilPort(p.verifier) {
		return preflightResult(request, PreflightRejected, "invalid_context"), invalid("preflight.context")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	defer func() {
		if err := ctx.Err(); err != nil {
			result.Status, result.Reason, resultErr = PreflightUnknown, "context_canceled", err
		}
	}()
	if err := ValidateRequest(request); err != nil {
		status := PreflightRejected
		if IsCode(err, CodeBindingConflict) {
			status = PreflightConflict
		}
		return preflightResult(request, status, "request_invalid"), err
	}
	if err := validateCall(query.Call); err != nil {
		return preflightResult(request, PreflightRejected, "query_invalid"), err
	}
	execution := request.Command.Execution
	target := QueryTarget{Action: PreflightCommitAction, Scope: request.Command.Scope,
		Execution: &execution, Binding: request.Binding}
	if err := p.authorizer.Authorize(ctx, query.Call, target); err != nil {
		return preflightResult(request, PreflightRejected, "query_unauthorized"), fault(CodeUnauthorized, "preflight.query")
	}
	operation, err := p.port.beginOperation(ctx)
	if err != nil {
		if p.port.owner.uncertain.Load() {
			result.Reason = "owner_uncertain"
		} else if p.port.owner.closing.Load() {
			result.Status, result.Reason = PreflightRejected, "owner_closing"
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, fault(CodeUnavailable, "preflight.owner")
	}
	defer operation.release()
	// This override runs before releasing the outer borrow. Even an earlier
	// positive observation cannot hide cancellation or a changed owner state.
	defer func() {
		if err := ctx.Err(); err != nil {
			result.Status, result.Reason, resultErr = PreflightUnknown, "context_canceled", err
		} else if p.port.owner.uncertain.Load() || p.port.owner.closing.Load() {
			result.Status, result.Reason = PreflightUnknown, "owner_unavailable"
		}
	}()

	raw, err := p.port.readPreflightSnapshot(ctx, request)
	if err != nil {
		return result, fault(CodeUnavailable, "preflight.snapshot")
	}
	raw = clonePreflightSnapshot(raw)
	result.Frame = sqliteFrameFromEvidence(raw.Snapshot.Evidence)
	if raw.Snapshot.Current.Reference != nil {
		value := *raw.Snapshot.Current.Reference
		result.Observed = &value
	}
	status, reason := p.checkSnapshot(ctx, request, raw)
	if status != PreflightEligible {
		result.Status, result.Reason = status, reason
		return result, nil
	}

	if readNilPort(p.guard) {
		result.Reason = "guard_missing"
		return result, nil
	}
	observedGuard, err := p.guard.ObservePreflight(ctx, request, result.Frame)
	if err != nil {
		result.Reason = "guard_unavailable"
		return result, nil
	}
	status, reason = p.checkGuard(ctx, request, raw, observedGuard)
	if status != PreflightEligible {
		result.Status, result.Reason = status, reason
		return result, nil
	}

	continuity, ok := p.port.continuity.(ContinuityPreflightReadPort)
	if !ok || readNilPort(continuity) {
		result.Reason = "continuity_missing"
		return result, nil
	}
	observed, err := continuity.QualifyPreflight(ctx, request, result.Frame, clonePreflightSnapshot(raw))
	if err != nil {
		result.Reason = "continuity_unavailable"
		return result, nil
	}
	observed = clonePreflightContinuity(observed)
	status, reason = p.checkContinuity(ctx, request, raw, observed)
	if status != PreflightEligible {
		result.Status, result.Reason = status, reason
		return result, nil
	}

	// Detect changed detached payloads after Guard/Continuity callbacks. This
	// does not create distributed atomicity or promise absence of later changes.
	final, err := p.port.readPreflightSnapshot(ctx, request)
	if err != nil {
		result.Reason = "snapshot_recheck_unavailable"
		return result, fault(CodeUnavailable, "preflight.recheck")
	}
	if !reflect.DeepEqual(raw, clonePreflightSnapshot(final)) {
		result.Reason = "observation_changed"
		return result, nil
	}
	result.Status, result.Reason = PreflightEligible, "conditions_observed"
	return result, nil
}

func (p *ConditionalCommitPreflight) checkSnapshot(ctx context.Context, request Request, raw PreflightSnapshot) (PreflightStatus, string) {
	snapshot := raw.Snapshot
	if raw.IdentityKnowledge == Conflict || raw.HistoryKnowledge == Conflict ||
		raw.ScopeExecutionKnowledge == Conflict ||
		snapshot.Current.Knowledge == Conflict || snapshot.Backend.Knowledge == Conflict {
		return PreflightConflict, "snapshot_conflict"
	}
	if raw.IdentityKnowledge != Known {
		return PreflightUnknown, "identity_coverage_unknown"
	}
	for _, stored := range raw.IdentityMatches {
		if ValidateRequest(stored) != nil {
			return PreflightUnknown, "identity_malformed"
		}
		if stored != request {
			return PreflightConflict, "identity_binding_conflict"
		}
	}
	if snapshot.StoredRequest != nil {
		if ValidateRequest(*snapshot.StoredRequest) != nil {
			return PreflightUnknown, "stored_request_malformed"
		}
		if *snapshot.StoredRequest != request {
			return PreflightConflict, "stored_request_conflict"
		}
	}
	if err := ValidateBackendObservation(request, snapshot.Backend); err != nil {
		if IsCode(err, CodeBindingConflict) {
			return PreflightConflict, "receipt_conflict"
		}
		return PreflightUnknown, "receipt_malformed"
	}
	if snapshot.Backend.Knowledge == Known {
		if snapshot.StoredRequest == nil || p.verifier.VerifyReceipt(ctx, request, readCloneReceipt(*snapshot.Backend.Receipt)) != nil {
			return PreflightUnknown, "terminal_receipt_unverified"
		}
		return PreflightRejected, "execution_terminal"
	}
	if snapshot.Backend.Knowledge != Absent || snapshot.StoredRequest != nil || len(raw.IdentityMatches) != 0 {
		return PreflightUnknown, "execution_liability_unknown"
	}
	// Independent coverage cannot erase a locally observed unresolved duty.
	// Inspect every execution in the affected Scope, including wholly different
	// keys/IDs, before considering a new execution eligible.
	if raw.ScopeExecutionKnowledge != Known {
		return PreflightUnknown, "scope_execution_coverage_unknown"
	}
	seenKeys := make(map[ID]bool, len(raw.ScopeExecutions))
	seenRequests := make(map[ID]bool, len(raw.ScopeExecutions))
	seenSteps := make(map[[3]ID]bool, len(raw.ScopeExecutions))
	for _, execution := range raw.ScopeExecutions {
		if execution.Request == nil || ValidateRequest(*execution.Request) != nil {
			return PreflightUnknown, "scope_execution_malformed"
		}
		original := *execution.Request
		identity := original.Command.Execution
		step := [3]ID{identity.OperationID, identity.AttemptID, identity.StepID}
		if seenKeys[identity.ExecutionKey] || seenRequests[identity.RequestID] || seenSteps[step] {
			return PreflightConflict, "scope_execution_identity_conflict"
		}
		seenKeys[identity.ExecutionKey], seenRequests[identity.RequestID], seenSteps[step] = true, true, true
		if original.Command.Scope != request.Command.Scope {
			return PreflightConflict, "scope_execution_scope_conflict"
		}
		if err := ValidateBackendObservation(original, execution.Backend); err != nil {
			if IsCode(err, CodeBindingConflict) {
				return PreflightConflict, "scope_execution_receipt_conflict"
			}
			return PreflightUnknown, "scope_execution_receipt_malformed"
		}
		if execution.Backend.Knowledge == Conflict {
			return PreflightConflict, "scope_execution_conflict"
		}
		if execution.Backend.Knowledge != Known {
			return PreflightUnknown, "scope_execution_liability"
		}
		receipt := *execution.Backend.Receipt
		if p.verifier.VerifyReceipt(ctx, original, readCloneReceipt(receipt)) != nil {
			return PreflightUnknown, "scope_execution_receipt_unverified"
		}
		if receipt.Kind == Positive {
			matched, linked := false, false
			for _, transition := range raw.History {
                if transition.Scope == original.Command.Scope && transition.ExecutionKey == original.Command.Execution.ExecutionKey { linked = true }
				if transition.Scope == original.Command.Scope &&
					transition.ExecutionKey == original.Command.Execution.ExecutionKey &&
					transition.ReceiptID == receipt.ReceiptID &&
					transition.TransitionID == receipt.Positive.TransitionID &&
					transition.Before == receipt.Positive.Before && transition.After == receipt.Positive.After &&
					transition.Request != nil && *transition.Request == original &&
					transition.Receipt != nil && reflect.DeepEqual(*transition.Receipt, receipt) {
					matched = true
					break
				}
			}
			if !matched {
                if linked && raw.HistoryKnowledge == Known { return PreflightConflict, "scope_execution_history_conflict" }
				return PreflightUnknown, "scope_execution_history_gap"
			}
		}
	}
	current := snapshot.Current
	if current.Scope != request.Command.Scope {
		return PreflightConflict, "reference_scope_conflict"
	}
	if current.Knowledge != Known || current.Reference == nil {
		return PreflightUnknown, "reference_missing"
	}
	if validateID(current.Reference.Revision, "preflight.revision") != nil ||
		sqliteValidateFrame(sqliteFrameFromEvidence(snapshot.Evidence)) != nil ||
		sqliteFrameFromEvidence(current.Evidence) != sqliteFrameFromEvidence(snapshot.Evidence) {
		return PreflightUnknown, "reference_evidence_unknown"
	}
	if *current.Reference != request.Command.Expected {
		return PreflightRejected, "expected_reference_mismatch"
	}
	if current.Reference.Revision == request.Command.CandidateRevision {
		return PreflightRejected, "no_change_not_selected"
	}
	for _, item := range []struct {
		boundary   Boundary
		projection Projection
	}{
		{ExecutorLedger, snapshot.Ledger}, {CPReport, snapshot.Report}, {CPAudit, snapshot.Audit},
	} {
		if err := readValidateProjection(request, nil, item.boundary, item.projection); err != nil {
			if IsCode(err, CodeBindingConflict) {
				return PreflightConflict, "projection_conflict"
			}
			return PreflightUnknown, "projection_unknown"
		}
		if item.projection.Knowledge == Conflict {
			return PreflightConflict, "projection_conflict"
		}
		if item.projection.Knowledge != Absent {
			return PreflightUnknown, "projection_liability"
		}
	}
	if raw.HistoryKnowledge != Known {
		return PreflightUnknown, "history_unknown"
	}
	for _, transition := range raw.History {
		if transition.Scope != request.Command.Scope {
			return PreflightConflict, "history_scope_conflict"
		}
		if validateID(transition.ExecutionKey, "preflight.history_key") != nil ||
			validateID(transition.TransitionID, "preflight.transition") != nil ||
			validateID(transition.ReceiptID, "preflight.history_receipt") != nil ||
			validateID(transition.Before.Revision, "preflight.history_before") != nil ||
			validateID(transition.After.Revision, "preflight.history_after") != nil {
			return PreflightUnknown, "history_malformed"
		}
		if transition.Before.StateVersion == ^uint64(0) ||
			transition.After.StateVersion != transition.Before.StateVersion+1 ||
			transition.Before.Revision == transition.After.Revision {
			return PreflightConflict, "history_version_conflict"
		}
		if transition.Request == nil || transition.Receipt == nil {
			return PreflightUnknown, "history_receipt_missing"
		}
		historical := *transition.Request
		receipt := *transition.Receipt
		if ValidateRequest(historical) != nil {
			return PreflightUnknown, "history_request_malformed"
		}
		if historical.Command.Scope != transition.Scope || historical.Command.Execution.ExecutionKey != transition.ExecutionKey ||
			receipt.ReceiptID != transition.ReceiptID || receipt.Kind != Positive || receipt.Positive == nil ||
			receipt.Positive.TransitionID != transition.TransitionID || receipt.Positive.Before != transition.Before ||
			receipt.Positive.After != transition.After {
			return PreflightConflict, "history_receipt_conflict"
		}
		if err := ValidateReceipt(historical, receipt); err != nil {
			if IsCode(err, CodeBindingConflict) {
				return PreflightConflict, "history_receipt_conflict"
			}
			return PreflightUnknown, "history_receipt_malformed"
		}
		if p.verifier.VerifyReceipt(ctx, historical, readCloneReceipt(receipt)) != nil {
			return PreflightUnknown, "history_receipt_unverified"
		}
	}
	return PreflightEligible, ""
}

func (p *ConditionalCommitPreflight) checkGuard(ctx context.Context, request Request, raw PreflightSnapshot, observed PreflightGuardObservation) (PreflightStatus, string) {
	frame := sqliteFrameFromEvidence(raw.Snapshot.Evidence)
	if observed.Knowledge == Conflict {
		return PreflightConflict, "guard_conflict"
	}
	if observed.Knowledge != Known {
		return PreflightUnknown, "guard_unknown"
	}
	if observed.Scope != request.Command.Scope || observed.Execution != request.Command.Execution || observed.Binding != request.Binding {
		return PreflightConflict, "guard_identity_conflict"
	}
	if observed.Frame != frame {
		return PreflightUnknown, "guard_frame_unknown"
	}
	if validateID(observed.Proof, "preflight.guard_proof") != nil {
		return PreflightUnknown, "guard_proof_missing"
	}
	if p.verifier.VerifyPreflightGuard(ctx, request, clonePreflightSnapshot(raw), observed) != nil {
		return PreflightUnknown, "guard_unverified"
	}
	conditions := []struct {
		status PreflightCondition
		reason string
	}{
		{observed.CPAuthorization, "cp_authorization"}, {observed.Policy, "policy"},
		{observed.Trust, "trust"}, {observed.Membership, "membership"},
		{observed.Ownership, "ownership"}, {observed.Fence, "fence"},
		{observed.Boot, "boot"}, {observed.Process, "process"},
		{observed.PAdmission, "p_admission"}, {observed.Candidate, "candidate"},
	}
	for _, condition := range conditions {
		if condition.status == PreflightConditionDenied {
			return PreflightRejected, "guard_denied_" + condition.reason
		}
		if condition.status != PreflightConditionValid {
			return PreflightUnknown, "guard_unknown_" + condition.reason
		}
	}
	required := request.Command.RequiredGuard
	for _, item := range []struct {
		got, want ID
		reason    string
	}{
		{observed.Current.Policy, required.Policy, "policy"}, {observed.Current.Trust, required.Trust, "trust"},
		{observed.Current.Membership, required.Membership, "membership"},
		{observed.Current.OwnershipEpoch, required.OwnershipEpoch, "ownership"},
		{observed.Current.FenceEpoch, required.FenceEpoch, "fence"},
		{observed.Current.Generation, required.Generation, "generation"},
		{observed.Current.BootID, required.BootID, "boot"},
		{observed.Current.ProcessIncarnation, required.ProcessIncarnation, "process"},
	} {
		if validateID(item.got, "preflight.guard_current") != nil {
			return PreflightUnknown, "guard_current_missing"
		}
		if item.got != item.want {
			return PreflightRejected, "guard_mismatch_" + item.reason
		}
	}
	if observed.Current.Generation != frame.Generation {
		return PreflightUnknown, "guard_backend_generation"
	}
	if observed.BusinessAdmission != PreflightBusinessOpen && observed.BusinessAdmission != PreflightBusinessClosed {
		return PreflightUnknown, "business_admission_unknown"
	}
	switch observed.Drain {
	case PreflightDrainReady:
		if validateID(observed.DrainSeal, "preflight.drain_seal") != nil {
			return PreflightUnknown, "drain_seal_missing"
		}
	case PreflightDrainNotReady, PreflightDrainHeld:
		return PreflightRejected, "drain_not_ready"
	default:
		return PreflightUnknown, "drain_unknown"
	}
	return PreflightEligible, ""
}

func (p *ConditionalCommitPreflight) checkContinuity(ctx context.Context, request Request, raw PreflightSnapshot, observed PreflightContinuityObservation) (PreflightStatus, string) {
	frame := sqliteFrameFromEvidence(raw.Snapshot.Evidence)
	if observed.Knowledge == Conflict {
		return PreflightConflict, "continuity_conflict"
	}
	if observed.Knowledge != Known {
		return PreflightUnknown, "continuity_unknown"
	}
	if observed.Scope != request.Command.Scope || observed.Execution != request.Command.Execution || observed.Binding != request.Binding {
		return PreflightConflict, "continuity_identity_conflict"
	}
	if observed.Frame != frame || !sqliteQualifiedEvidence(frame, observed.Evidence) {
		return PreflightUnknown, "continuity_frame_unknown"
	}
	if validateID(observed.ContinuityIssuer, "preflight.continuity_issuer") != nil ||
		validateID(observed.Proof, "preflight.continuity_proof") != nil {
		return PreflightUnknown, "continuity_proof_missing"
	}
	for _, coverage := range []Knowledge{observed.WitnessCoverage, observed.OutstandingCoverage,
		observed.HistoryCoverage, observed.IdentityCoverage, observed.FreshnessCoverage} {
		if coverage != Known {
			return PreflightUnknown, "continuity_coverage_unknown"
		}
	}
	if p.verifier.VerifyPreflightContinuity(ctx, request, clonePreflightSnapshot(raw), clonePreflightContinuity(observed)) != nil {
		return PreflightUnknown, "continuity_unverified"
	}
	seen := make(map[ID]bool, len(observed.Outstanding))
	for _, id := range observed.Outstanding {
		if validateID(id, "preflight.liability") != nil || seen[id] {
			return PreflightUnknown, "outstanding_malformed"
		}
		seen[id] = true
	}
	if len(observed.Outstanding) != 0 {
		return PreflightUnknown, "outstanding_liability"
	}
	snapshot := readCloneSnapshot(raw.Snapshot)
	snapshot.Evidence = observed.Evidence
	snapshot.Current.Evidence = observed.Evidence
	snapshot.Witness = nil
	snapshot.Outstanding = append([]ID(nil), observed.Outstanding...)
	if observed.Witness != nil {
		witness := observed.Witness
		if witness.Scope != request.Command.Scope || witness.Execution != request.Command.Execution ||
			witness.Binding != request.Binding || ValidateReceipt(request, witness.Receipt) != nil {
			return PreflightConflict, "witness_identity_conflict"
		}
		if validateID(witness.LiabilityID, "preflight.witness_liability") != nil ||
			validateID(witness.Evidence, "preflight.witness_evidence") != nil ||
			p.verifier.VerifyWitness(ctx, request, *clonePreflightContinuity(observed).Witness) != nil {
			return PreflightUnknown, "witness_unverified"
		}
		return PreflightRejected, "witness_terminal"
	}
	if observed.HistoryBaseline == nil || validateID(observed.HistoryBaseline.Revision, "preflight.history_baseline") != nil {
		return PreflightUnknown, "history_baseline_unknown"
	}
	cursor := *observed.HistoryBaseline
	for _, transition := range raw.History {
		if transition.Before != cursor {
			if transition.Before.StateVersion == cursor.StateVersion {
				return PreflightConflict, "history_chain_conflict"
			}
			return PreflightUnknown, "history_chain_gap"
		}
		cursor = transition.After
	}
	if raw.Snapshot.Current.Reference == nil {
		return PreflightUnknown, "reference_missing"
	}
	if cursor != *raw.Snapshot.Current.Reference {
		if cursor.StateVersion >= raw.Snapshot.Current.Reference.StateVersion {
			return PreflightConflict, "history_current_conflict"
		}
		return PreflightUnknown, "history_current_gap"
	}
	if readValidateActive(request.Command.Scope, snapshot.Current) != nil ||
		p.verifier.VerifyActiveReference(ctx, request.Command.Scope, readCloneActive(snapshot.Current)) != nil ||
		p.verifier.VerifyExecutionSnapshot(ctx, request, readCloneSnapshot(snapshot)) != nil {
		return PreflightUnknown, "snapshot_freshness_unverified"
	}
	return PreflightEligible, ""
}

func clonePreflightSnapshot(snapshot PreflightSnapshot) PreflightSnapshot {
	result := snapshot
	result.Snapshot = readCloneSnapshot(snapshot.Snapshot)
	result.ScopeExecutions = append([]PreflightExecutionObservation(nil), snapshot.ScopeExecutions...)
	for i := range result.ScopeExecutions {
		if snapshot.ScopeExecutions[i].Request != nil {
			value := *snapshot.ScopeExecutions[i].Request
			result.ScopeExecutions[i].Request = &value
		}
		if snapshot.ScopeExecutions[i].Backend.Receipt != nil {
			value := readCloneReceipt(*snapshot.ScopeExecutions[i].Backend.Receipt)
			result.ScopeExecutions[i].Backend.Receipt = &value
		}
	}
	result.IdentityMatches = append([]Request(nil), snapshot.IdentityMatches...)
	result.History = append([]PreflightTransition(nil), snapshot.History...)
	for i := range result.History {
		if snapshot.History[i].Request != nil {
			value := *snapshot.History[i].Request
			result.History[i].Request = &value
		}
		if snapshot.History[i].Receipt != nil {
			value := readCloneReceipt(*snapshot.History[i].Receipt)
			result.History[i].Receipt = &value
		}
	}
	return result
}

func clonePreflightContinuity(observed PreflightContinuityObservation) PreflightContinuityObservation {
	result := observed
	result.Outstanding = append([]ID(nil), observed.Outstanding...)
	if observed.HistoryBaseline != nil {
		value := *observed.HistoryBaseline
		result.HistoryBaseline = &value
	}
	if observed.Witness != nil {
		value := *observed.Witness
		value.Receipt = readCloneReceipt(observed.Witness.Receipt)
		result.Witness = &value
	}
	return result
}
