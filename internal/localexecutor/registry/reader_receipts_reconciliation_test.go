package registry

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// These doubles contain no mutation/SQL/provider/restore method or credential.
type readTestPort struct {
	active ActiveReference
	snapshot ExecutionSnapshot
	err error
	reads int
}
func (p *readTestPort) ReadActiveReference(context.Context, Scope) (ActiveReference, error) {
	p.reads++
	return p.active, p.err
}
func (p *readTestPort) ReadExecution(context.Context, Request) (ExecutionSnapshot, error) {
	p.reads++
	return p.snapshot, p.err
}
type readTestAuthorizer struct {
	err error
	actions []QueryAction
}
func (a *readTestAuthorizer) Authorize(_ context.Context, _ Call, action QueryAction, _ Scope) error {
	a.actions = append(a.actions, action)
	return a.err
}
type readTestVerifier struct {
	receiptErr error
	snapshotErr error
	witnessErr error
	receipts int
	snapshots int
	witnesses int
}
func (v *readTestVerifier) VerifyReceipt(context.Context, Request, Receipt) error {
	v.receipts++
	return v.receiptErr
}
func (v *readTestVerifier) VerifyActiveReference(context.Context, Scope, ActiveReference) error {
	v.snapshots++
	return v.snapshotErr
}
func (v *readTestVerifier) VerifyExecutionSnapshot(context.Context, Request, ExecutionSnapshot) error {
	v.snapshots++
	return v.snapshotErr
}
func (v *readTestVerifier) VerifyWitness(context.Context, Request, WitnessOutcome) error {
	v.witnesses++
	return v.witnessErr
}
func receiptTestRequest(t *testing.T) Request {
	t.Helper()
	command := Command{
		Schema: CommandSchema,
		Operation: ReferenceOnlyOperation,
		Scope: Scope{Realm: "realm-a", Host: "host-a", Resource: "config-a", Backend: "backend-a"},
		Execution: Execution{RequestID: "request-a", ExecutionKey: "execution-a", OperationID: "operation-a", AttemptID: "attempt-a", StepID: "step-a"},
		RequestingPrincipal: "operator-a",
		AuthorizationIssuer: "cp-a",
		CandidateRevision: "revision-b",
		CandidateContentPin: "content-pin-b",
		Expected: Reference{Revision: "revision-a", StateVersion: 7},
		RequiredGuard: Guard{Policy: "policy-a", Trust: "trust-a", Membership: "membership-a", OwnershipEpoch: "owner-a", FenceEpoch: "fence-a", Generation: "generation-a", BootID: "boot-a", ProcessIncarnation: "process-a"},
		Timing: Timing{TimeBase: "monotonic-a", DeadlineTick: 100},
		OriginalBudget: "budget-a",
	}
	binding, err := CanonicalBinding(command)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Command: command, Binding: binding}
}
func receiptTestReceipt(t *testing.T, kind ReceiptKind) (Request, Receipt) {
	t.Helper()
	request := receiptTestRequest(t)
	receipt := Receipt{
		ReceiptID: "receipt-a", CommitID: "commit-a", ProducerBackend: request.Command.Scope.Backend,
		Scope: request.Command.Scope, Execution: request.Command.Execution,
		Binding: request.Binding, Kind: kind, Guard: request.Command.RequiredGuard,
		Decision: Decision{Profile: D1GuardDecision, TimeBase: request.Command.Timing.TimeBase, BootID: request.Command.RequiredGuard.BootID, LowerTick: 89, UpperTick: 90, Proof: "decision-proof-a"},
		Proof: "receipt-proof-a",
	}
	if kind == Positive {
		receipt.Positive = &PositivePayload{TransitionID: "transition-a", Before: request.Command.Expected, After: Reference{Revision: request.Command.CandidateRevision, StateVersion: 8}, Semantic: ReferenceCommittedNotServiceApplied}
	} else {
		receipt.Decision.Profile = QualifiedRejectionDecision
		receipt.Negative = &NegativePayload{Reason: GuardRejected, NoAdditionalEffectProof: "negative-proof-a"}
	}
	return request, receipt
}
func readTestEvidence() Evidence {
	return Evidence{Issuer: "snapshot-owner-a", ServingIncarnation: "incarnation-a", Generation: "generation-a", SnapshotID: "snapshot-a", FreshnessProof: "freshness-proof-a", ObservationProof: "observation-proof-a"}
}
func readTestCall() Call {
	return Call{Principal: "reader-a", Capability: "query-capability-a", CorrelationID: "correlation-a"}
}
func readTestSnapshot(t *testing.T, kind ReceiptKind) (Request, ExecutionSnapshot) {
	t.Helper()
	request, receipt := receiptTestReceipt(t, kind)
	current := request.Command.Expected
	return request, ExecutionSnapshot{
		StoredRequest: &request,
		Backend: BackendObservation{Knowledge: Known, Receipt: &receipt},
		Current: ActiveReference{Knowledge: Known, Scope: request.Command.Scope, Reference: &current, Evidence: readTestEvidence()},
		Ledger: Projection{Knowledge: Absent},
		Report: Projection{Knowledge: Absent},
		Audit: Projection{Knowledge: Absent},
		Witness: &WitnessOutcome{LiabilityID: "liability-a", Scope: request.Command.Scope, Execution: request.Command.Execution, Binding: request.Binding, Receipt: readCloneReceipt(receipt), Evidence: "witness-evidence-a"},
		Outstanding: []ID{"liability-a"},
		Evidence: readTestEvidence(),
	}
}
func readTestReader(t *testing.T, snapshot ExecutionSnapshot) (*Reader, *readTestPort, *readTestAuthorizer, *readTestVerifier) {
	t.Helper()
	port := &readTestPort{active: snapshot.Current, snapshot: snapshot}
	auth := &readTestAuthorizer{}
	verifier := &readTestVerifier{}
	reader, err := NewReader(port, auth, verifier)
	if err != nil {
		t.Fatal(err)
	}
	return reader, port, auth, verifier
}
func readTestRecord(request Request, receipt Receipt, boundary Boundary) Projection {
	record := &OutcomeRecord{Scope: request.Command.Scope, Execution: request.Command.Execution, Binding: request.Binding, ReceiptID: receipt.ReceiptID, ReceiptKind: receipt.Kind, Boundary: boundary, RecordedBy: "recording-actor-a", RecordAuthority: "record-capability-a", Evidence: "record-evidence-a", Ack: AckConfirmed}
	if boundary == CPAudit {
		record.OriginalAuditAvailability = Known
	}
	return Projection{Knowledge: Known, Record: record}
}

func TestReceiptValidPositiveAndQualifiedNegatives(t *testing.T) {
	for _, kind := range []ReceiptKind{Positive, Negative} {
		request, receipt := receiptTestReceipt(t, kind)
		if err := ValidateReceipt(request, receipt); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	request, receipt := receiptTestReceipt(t, Negative)
	receipt.Guard.Policy = "policy-new"
	receipt.Guard.BootID = "boot-new"
	receipt.Decision.BootID = "boot-new"
	receipt.Decision.TimeBase = "monotonic-new"
	receipt.Decision.LowerTick = 400
	receipt.Decision.UpperTick = 500
	if err := ValidateReceipt(request, receipt); err != nil {
		t.Fatalf("qualified later refusal is not new actuation: %v", err)
	}
	for _, reason := range []NegativeReason{GuardRejected, PreconditionMismatch, NotChangedProposed} {
		receipt.Negative.Reason = reason
		if err := ValidateReceipt(request, receipt); err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
	}
}

func TestReceiptRejectsMalformedAndConflictingPayloads(t *testing.T) {
	cases := []struct {
		name string
		change func(*Receipt)
		code Code
	}{
		{"binding", func(r *Receipt) { r.Binding = "other-binding" }, CodeBindingConflict},
		{"request_alias", func(r *Receipt) { r.Execution.RequestID = "request-other" }, CodeBindingConflict},
		{"execution_key", func(r *Receipt) { r.Execution.ExecutionKey = "execution-other" }, CodeBindingConflict},
		{"wrong_scope", func(r *Receipt) { r.Scope.Host = "host-other" }, CodeBindingConflict},
		{"wrong_producer", func(r *Receipt) { r.ProducerBackend = "backend-other" }, CodeBindingConflict},
		{"double_payload", func(r *Receipt) { r.Negative = &NegativePayload{Reason: GuardRejected, NoAdditionalEffectProof: "proof-b"} }, CodeInvalid},
		{"missing_payload", func(r *Receipt) { r.Positive = nil }, CodeInvalid},
		{"wrong_before", func(r *Receipt) { r.Positive.Before.StateVersion++ }, CodeBindingConflict},
		{"wrong_candidate", func(r *Receipt) { r.Positive.After.Revision = "revision-other" }, CodeBindingConflict},
		{"skipped_version", func(r *Receipt) { r.Positive.After.StateVersion++ }, CodeInvalid},
		{"service_applied", func(r *Receipt) { r.Positive.Semantic = "SERVICE_APPLIED" }, CodeInvalid},
		{"guard", func(r *Receipt) { r.Guard.Policy = "policy-other" }, CodeBindingConflict},
		{"boot", func(r *Receipt) { r.Decision.BootID = "boot-other" }, CodeBindingConflict},
		{"timebase", func(r *Receipt) { r.Decision.TimeBase = "monotonic-other" }, CodeBindingConflict},
		{"deadline", func(r *Receipt) { r.Decision.UpperTick = 101 }, CodeInvalid},
		{"interval", func(r *Receipt) { r.Decision.LowerTick = 91 }, CodeInvalid},
		{"decision_profile", func(r *Receipt) { r.Decision.Profile = QualifiedRejectionDecision }, CodeInvalid},
		{"missing_proof", func(r *Receipt) { r.Proof = "" }, CodeInvalid},
		{"unknown_kind", func(r *Receipt) { r.Kind = ReceiptKind("UNKNOWN") }, CodeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request, receipt := receiptTestReceipt(t, Positive)
			tc.change(&receipt)
			if err := ValidateReceipt(request, receipt); !IsCode(err, tc.code) {
				t.Fatalf("got %v; want %s", err, tc.code)
			}
		})
	}
	request, receipt := receiptTestReceipt(t, Positive)
	request.Command.Expected.StateVersion = ^uint64(0)
	request.Binding, _ = CanonicalBinding(request.Command)
	receipt.Binding = request.Binding
	receipt.Positive.Before = request.Command.Expected
	receipt.Positive.After.StateVersion = 0
	if err := ValidateReceipt(request, receipt); !IsCode(err, CodeInvalid) {
		t.Fatalf("version overflow: %v", err)
	}
}
func TestNegativeRequiresRefusalProfileProofAndClosedReason(t *testing.T) {
	for _, change := range []func(*Receipt){
		func(r *Receipt) { r.Decision.Profile = D1GuardDecision },
		func(r *Receipt) { r.Negative.NoAdditionalEffectProof = "" },
		func(r *Receipt) { r.Negative.Reason = "SUCCESS" },
		func(r *Receipt) { r.Positive = &PositivePayload{} },
		func(r *Receipt) { r.Guard.ProcessIncarnation = "" },
	} {
		request, receipt := receiptTestReceipt(t, Negative)
		change(&receipt)
		if err := ValidateReceipt(request, receipt); err == nil {
			t.Fatal("malformed negative accepted")
		}
	}
}
func TestBackendObservationDoesNotForgeUnknownOrAbsence(t *testing.T) {
	request, receipt := receiptTestReceipt(t, Positive)
	for _, state := range []Knowledge{Unknown, Absent, Conflict} {
		if err := ValidateBackendObservation(request, BackendObservation{Knowledge: state}); err != nil {
			t.Fatal(err)
		}
		if err := ValidateBackendObservation(request, BackendObservation{Knowledge: state, Receipt: &receipt}); err == nil {
			t.Fatalf("%s smuggles terminal payload", state)
		}
	}
	if err := ValidateBackendObservation(request, BackendObservation{Knowledge: Known}); err == nil {
		t.Fatal("known without receipt")
	}
}
func TestD01TerminalRecordDescriptorsKeepSignAndScope(t *testing.T) {
	for _, kind := range []ReceiptKind{Positive, Negative} {
		request, receipt := receiptTestReceipt(t, kind)
		records, err := DescribeTerminalRecords(request, receipt)
		if err != nil || len(records) != 3 {
			t.Fatalf("records: %#v %v", records, err)
		}
		seen := map[Boundary]bool{}
		for _, record := range records {
			if seen[record.Boundary] || record.Execution != receipt.Execution || record.Binding != receipt.Binding || record.ReceiptKind != kind || record.Scope != receipt.Scope {
				t.Fatalf("bad terminal record: %#v", record)
			}
			seen[record.Boundary] = true
			if kind == Negative && record.Result != string(GuardRejected) {
				t.Fatal("negative projected as success")
			}
		}
	}
}
func TestReaderRejectsMissingAndTypedNilDependencies(t *testing.T) {
	var missing *readTestPort
	if _, err := NewReader(missing, &readTestAuthorizer{}, &readTestVerifier{}); err == nil {
		t.Fatal("typed nil dependency accepted")
	}
	if _, err := NewReader(&readTestPort{}, nil, &readTestVerifier{}); err == nil {
		t.Fatal("nil dependency accepted")
	}
	var reader Reader
	if _, err := reader.ReadActiveReference(context.Background(), ReadRequest{Call: readTestCall(), Scope: receiptTestRequest(t).Command.Scope}); err == nil {
		t.Fatal("zero reader accepted")
	}
}
func TestReaderCurrentAuthorizationAndSafeErrors(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Positive)
	reader, port, auth, _ := readTestReader(t, snapshot)
	auth.err = errors.New("secret-provider-payload")
	_, err := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeUnauthorized) || port.reads != 0 || err.Error() == auth.err.Error() {
		t.Fatalf("authority failure not closed/sanitized: %v", err)
	}
	auth.err = nil
	port.err = errors.New("secret-store-path")
	_, err = reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeUnavailable) || err.Error() == port.err.Error() {
		t.Fatalf("storage error leaked: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := port.reads
	_, err = reader.LookupExecution(ctx, LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeUnavailable) || port.reads != before {
		t.Fatalf("canceled read did not fail closed: %v", err)
	}
}
func TestReadActiveReferenceVerifiesAndDetaches(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Positive)
	reader, port, auth, verifier := readTestReader(t, snapshot)
	before := *port.active.Reference
	active, err := reader.ReadActiveReference(context.Background(), ReadRequest{Call: readTestCall(), Scope: request.Command.Scope})
	if err != nil || active.Knowledge != Known || auth.actions[0] != ReadReferenceAction {
		t.Fatalf("read: %#v %v", active, err)
	}
	active.Reference.Revision = "caller-changed"
	if *port.active.Reference != before {
		t.Fatal("caller modified port-owned reference")
	}
	verifier.snapshotErr = errors.New("snapshot-unqualified")
	active, err = reader.ReadActiveReference(context.Background(), ReadRequest{Call: readTestCall(), Scope: request.Command.Scope})
	if !IsCode(err, CodeEvidenceUnknown) || active.Knowledge != Unknown || active.Reference != nil {
		t.Fatalf("unqualified current reference exposed: %#v %v", active, err)
	}
}
func TestLookupHistoricalReceiptDoesNotRequireCurrentGrantOrCurrentReference(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Positive)
	snapshot.Current.Reference = &Reference{Revision: "revision-later", StateVersion: 300}
	reader, port, auth, _ := readTestReader(t, snapshot)
	before := readCloneSnapshot(port.snapshot)
	result, err := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if err != nil || result.Backend.Knowledge != Known || result.Backend.Receipt.Positive.After.Revision != request.Command.CandidateRevision ||
		result.Current.Reference.Revision != "revision-later" || result.ServiceApplication != ServiceApplicationOutsideScope {
		t.Fatalf("historical lookup: %#v %v", result, err)
	}
	if len(auth.actions) != 1 || auth.actions[0] != LookupExecutionAction {
		t.Fatal("lookup authority not used")
	}
	result.Backend.Receipt.Positive.After.Revision = "caller-changed"
	result.Current.Reference.Revision = "caller-changed"
	result.Outstanding[0] = "caller-changed"
	if !reflect.DeepEqual(before, port.snapshot) {
		t.Fatal("lookup mutated source snapshot or aliased returned data")
	}
}
func TestLookupKeepsKnownBackendWhenFreshnessUnknown(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Negative)
	reader, _, _, verifier := readTestReader(t, snapshot)
	verifier.snapshotErr = errors.New("rollback-unqualified")
	result, err := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeEvidenceUnknown) || result.Knowledge != Unknown ||
		result.Backend.Knowledge != Known || result.Backend.Receipt.Kind != Negative ||
		result.Current.Knowledge != Unknown || result.Current.Reference != nil || len(result.Outstanding) != 1 {
		t.Fatalf("lost history or leaked stale state: %#v %v", result, err)
	}
}
func TestLookupRejectsUnverifiedNegativeAndStoredAlias(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Negative)
	reader, port, _, verifier := readTestReader(t, snapshot)
	verifier.receiptErr = errors.New("forged-refusal")
	result, err := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeEvidenceUnknown) || result.Backend.Knowledge != Unknown || result.Backend.Receipt != nil {
		t.Fatalf("forged negative accepted: %#v %v", result, err)
	}
	verifier.receiptErr = nil
	alias := request
	alias.Command.Execution.RequestID = "request-alias"
	alias.Binding, _ = CanonicalBinding(alias.Command)
	port.snapshot.StoredRequest = &alias
	result, err = reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeBindingConflict) || result.Knowledge != Conflict || result.Backend.Knowledge != Known || len(result.Outstanding) != 1 {
		t.Fatalf("alias/conflicting stored state: %#v %v", result, err)
	}
}
func TestLookupAbsentIsNotNotStartedAuthority(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Positive)
	snapshot.StoredRequest = nil
	snapshot.Backend = BackendObservation{Knowledge: Absent}
	snapshot.Witness = nil
	reader, _, _, _ := readTestReader(t, snapshot)
	result, err := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if err != nil || result.Backend.Knowledge != Absent || result.Backend.Receipt != nil {
		t.Fatalf("absent lookup: %#v %v", result, err)
	}
	plan, err := reader.ReconcilePartialRestore(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeEvidenceUnknown) || plan.OriginalMutationAuthorized || len(plan.Steps) != 0 {
		t.Fatalf("absence authorized mutation or repair: %#v %v", plan, err)
	}
}
func TestD02PlansPositiveAndNegativeWithoutEffects(t *testing.T) {
	for _, kind := range []ReceiptKind{Positive, Negative} {
		t.Run(string(kind), func(t *testing.T) {
			request, snapshot := readTestSnapshot(t, kind)
			reader, port, auth, verifier := readTestReader(t, snapshot)
			before := readCloneSnapshot(port.snapshot)
			query := LookupRequest{Call: readTestCall(), Request: request}
			plan, err := reader.ReconcilePartialRestore(context.Background(), query)
			if err != nil || plan.Knowledge != Known || len(plan.Steps) != 3 || plan.OriginalMutationAuthorized {
				t.Fatalf("plan: %#v %v", plan, err)
			}
			if len(auth.actions) != 1 || auth.actions[0] != PlanReconciliationAction || verifier.witnesses != 1 {
				t.Fatal("plan did not verify current Q scope and witness")
			}
			for _, step := range plan.Steps {
				if step.Outcome.ReceiptKind != kind || step.Outcome.Execution != request.Command.Execution ||
					step.SourceReceipt != snapshot.Backend.Receipt.ReceiptID || step.SourceWitness != snapshot.Witness.Evidence ||
					step.Expected.Knowledge != Absent || step.RequiredCapability == "" {
					t.Fatalf("bad step: %#v", step)
				}
				if step.Boundary == CPAudit && (step.Action != RecordRecoveredAudit || step.OriginalAuditAvailability != Unknown) {
					t.Fatal("original audit fabricated")
				}
			}
			again, err := reader.ReconcilePartialRestore(context.Background(), query)
			if err != nil || !reflect.DeepEqual(plan, again) || !reflect.DeepEqual(before, port.snapshot) {
				t.Fatal("planning writes, changes identity, or is nondeterministic")
			}
		})
	}
}
func TestD02AckLossResendsReportOnlyAndDetachesExpected(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Positive)
	receipt := *snapshot.Backend.Receipt
	snapshot.Ledger = readTestRecord(request, receipt, ExecutorLedger)
	snapshot.Report = readTestRecord(request, receipt, CPReport)
	snapshot.Audit = readTestRecord(request, receipt, CPAudit)
	snapshot.Report.Record.Ack = AckUnknown
	reader, port, _, _ := readTestReader(t, snapshot)
	plan, err := reader.ReconcilePartialRestore(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if err != nil || plan.Knowledge != Known || len(plan.Steps) != 1 || plan.Steps[0].Action != ResendCPOutcome ||
		plan.Steps[0].RequiredCapability != CPReportCapability || plan.OriginalMutationAuthorized {
		t.Fatalf("ACK loss: %#v %v", plan, err)
	}
	plan.Steps[0].Expected.Record.RecordedBy = "caller-changed"
	if port.snapshot.Report.Record.RecordedBy == "caller-changed" || plan.Result.Report.Record.RecordedBy == "caller-changed" {
		t.Fatal("repair Expected aliases source or result projection")
	}
}
func TestD02ConflictsMissingEvidenceAndUnknownBlockRepair(t *testing.T) {
	cases := []struct {
		name string
		change func(*ExecutionSnapshot)
	}{
		{"witness_missing", func(s *ExecutionSnapshot) { s.Witness = nil }},
		{"witness_receipt_diff", func(s *ExecutionSnapshot) { s.Witness.Receipt.ReceiptID = "other-receipt" }},
		{"witness_binding", func(s *ExecutionSnapshot) { s.Witness.Binding = "other-binding" }},
		{"backend_missing", func(s *ExecutionSnapshot) { s.Backend = BackendObservation{Knowledge: Absent} }},
		{"projection_unknown", func(s *ExecutionSnapshot) { s.Report = Projection{Knowledge: Unknown} }},
		{"projection_conflict", func(s *ExecutionSnapshot) { s.Ledger = Projection{Knowledge: Conflict} }},
		{"projection_binding", func(s *ExecutionSnapshot) { s.Ledger.Record.Binding = "other-binding" }},
		{"projection_receipt", func(s *ExecutionSnapshot) { s.Ledger.Record.ReceiptID = "other-receipt" }},
		{"ledger_ack_unknown", func(s *ExecutionSnapshot) { s.Ledger.Record.Ack = AckUnknown }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request, snapshot := readTestSnapshot(t, Positive)
			snapshot.Ledger = readTestRecord(request, *snapshot.Backend.Receipt, ExecutorLedger)
			tc.change(&snapshot)
			reader, port, _, _ := readTestReader(t, snapshot)
			before := readCloneSnapshot(port.snapshot)
			plan, err := reader.ReconcilePartialRestore(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
			if err == nil || plan.Knowledge == Known || len(plan.Steps) != 0 || plan.OriginalMutationAuthorized ||
				!reflect.DeepEqual(before, port.snapshot) || len(plan.Outstanding) != 1 {
				t.Fatalf("unsafe repair or lost reservation: %#v %v", plan, err)
			}
		})
	}
}
func TestD02VerifierRefusalBlocksRecordPlan(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Negative)
	reader, _, _, verifier := readTestReader(t, snapshot)
	verifier.witnessErr = errors.New("independent-witness-not-qualified")
	plan, err := reader.ReconcilePartialRestore(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeEvidenceUnknown) || len(plan.Steps) != 0 || plan.Knowledge != Unknown || plan.Result.Backend.Knowledge != Known {
		t.Fatalf("unqualified witness planned repair: %#v %v", plan, err)
	}
}

func TestLookupConflictsDominateUnknownAndMalformedIsNotTerminal(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Positive)
	snapshot.Backend = BackendObservation{Knowledge: Conflict}
	snapshot.Report = Projection{Knowledge: Unknown}
	reader, port, _, _ := readTestReader(t, snapshot)
	result, err := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if err != nil || result.Knowledge != Conflict || result.Backend.Knowledge != Conflict {
		t.Fatalf("explicit backend conflict downgraded: %#v %v", result, err)
	}
	_, snapshot = readTestSnapshot(t, Positive)
	snapshot.Backend.Receipt.Positive = nil
	port.snapshot = snapshot
	result, err = reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeInvalid) || result.Knowledge != Unknown || result.Backend.Knowledge != Unknown {
		t.Fatalf("malformed evidence declared terminal/conflict: %#v %v", result, err)
	}
}
func TestD02ExplicitCurrentConflictBlocksPlan(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Positive)
	snapshot.Current = ActiveReference{Knowledge: Conflict, Scope: request.Command.Scope}
	reader, _, _, _ := readTestReader(t, snapshot)
	plan, err := reader.ReconcilePartialRestore(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if !IsCode(err, CodeBindingConflict) || plan.Knowledge != Conflict || len(plan.Steps) != 0 || plan.Result.Backend.Knowledge != Known {
		t.Fatalf("current conflict planned repair: %#v %v", plan, err)
	}
}

func TestPositiveCannotPromoteProposedNoChangeIntoSuccess(t *testing.T) {
	request, receipt := receiptTestReceipt(t, Positive)
	request.Command.CandidateRevision = request.Command.Expected.Revision
	binding, err := CanonicalBinding(request.Command)
	if err != nil {
		t.Fatal(err)
	}
	request.Binding = binding
	receipt.Binding = binding
	receipt.Positive.After.Revision = request.Command.CandidateRevision
	if err := ValidateReceipt(request, receipt); !IsCode(err, CodeInvalid) {
		t.Fatalf("no-change accepted as reference success: %v", err)
	}
}

type readMutatingVerifier struct {
	seenExecution bool
	seenActive bool
}
func (v *readMutatingVerifier) VerifyReceipt(_ context.Context, _ Request, receipt Receipt) error {
	if receipt.Positive != nil {
		receipt.Positive.After.Revision = "verifier-changed"
	}
	return nil
}
func (v *readMutatingVerifier) VerifyWitness(_ context.Context, _ Request, witness WitnessOutcome) error {
	if witness.Receipt.Positive != nil {
		witness.Receipt.Positive.After.Revision = "verifier-changed"
	}
	return nil
}
func (v *readMutatingVerifier) VerifyActiveReference(_ context.Context, scope Scope, active ActiveReference) error {
	v.seenActive = active.Scope == scope && active.Reference != nil && active.Reference.Revision == "revision-a"
	if active.Reference != nil {
		active.Reference.Revision = "verifier-changed"
	}
	return nil
}
func (v *readMutatingVerifier) VerifyExecutionSnapshot(_ context.Context, request Request, snapshot ExecutionSnapshot) error {
	v.seenExecution = snapshot.StoredRequest != nil && *snapshot.StoredRequest == request &&
		snapshot.Backend.Receipt != nil && snapshot.Backend.Receipt.Positive.After.Revision == request.Command.CandidateRevision
	if snapshot.Backend.Receipt != nil && snapshot.Backend.Receipt.Positive != nil {
		snapshot.Backend.Receipt.Positive.After.Revision = "verifier-changed"
	}
	if snapshot.Current.Reference != nil {
		snapshot.Current.Reference.Revision = "verifier-changed"
	}
	if len(snapshot.Outstanding) > 0 {
		snapshot.Outstanding[0] = "verifier-changed"
	}
	return nil
}
func TestVerifierReceivesWholeDetachedObservedPayload(t *testing.T) {
	request, snapshot := readTestSnapshot(t, Positive)
	port := &readTestPort{active: snapshot.Current, snapshot: snapshot}
	before := readCloneSnapshot(snapshot)
	verifier := &readMutatingVerifier{}
	reader, err := NewReader(port, &readTestAuthorizer{}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.LookupExecution(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if err != nil || !verifier.seenExecution || !verifier.seenActive ||
		result.Backend.Receipt.Positive.After.Revision != request.Command.CandidateRevision ||
		!reflect.DeepEqual(before, port.snapshot) || result.Outstanding[0] != "liability-a" {
		t.Fatalf("verifier not payload-bound/detached: %#v %v", result, err)
	}
	plan, err := reader.ReconcilePartialRestore(context.Background(), LookupRequest{Call: readTestCall(), Request: request})
	if err != nil || plan.Knowledge != Known || !reflect.DeepEqual(before, port.snapshot) {
		t.Fatalf("witness callback mutated retained evidence: %#v %v", plan, err)
	}
}
