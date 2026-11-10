// Package registry defines the C10 reference-only registry read boundary.
// It does not implement a SQLite driver, mutation, GuardControl, or service apply.
package registry

import "context"

// ID is an opaque, case-sensitive v3 identifier, not an OS path or v2 token.
type ID string

// Binding is the exact internal v1 canonical command representation.
// It is an equality binding, not a signature, hash, credential, or execution grant.
type Binding string

type Scope struct {
	Realm ID
	Host ID
	Resource ID
	Backend ID
}

type Execution struct {
	RequestID ID
	ExecutionKey ID
	OperationID ID
	AttemptID ID
	StepID ID
}

type Reference struct {
	Revision ID
	StateVersion uint64
}

type Guard struct {
	Policy ID
	Trust ID
	Membership ID
	OwnershipEpoch ID
	FenceEpoch ID
	Generation ID
	BootID ID
	ProcessIncarnation ID
}

// Timing contains immutable authority-bound ticks; no wall clock or TTL is chosen.
// Receipt validation compares a historical D1 decision, not time.Now().
type Timing struct {
	TimeBase ID
	DeadlineTick uint64
}

type Command struct {
	Schema uint32
	Operation string
	Scope Scope
	Execution Execution
	RequestingPrincipal ID
	AuthorizationIssuer ID
	CandidateRevision ID
	CandidateContentPin ID
	Expected Reference
	RequiredGuard Guard
	Timing Timing
	OriginalBudget ID
}

// Evidence acquired after acceptance is deliberately absent from Command/Binding.
type Request struct {
	Command Command
	Binding Binding
}

const (
	CommandSchema uint32 = 1
	ReferenceOnlyOperation = "registry.reference_only"
	ReferenceCommittedNotServiceApplied = "REFERENCE_COMMITTED_NOT_SERVICE_APPLIED"
	ServiceApplicationOutsideScope = "OUTSIDE_P_A_SCOPE"
)

type Knowledge string

const (
	Known Knowledge = "KNOWN"
	Absent Knowledge = "ABSENT"
	Unknown Knowledge = "UNKNOWN"
	Conflict Knowledge = "CONFLICT"
)

type ReceiptKind string

const (
	Positive ReceiptKind = "positive"
	Negative ReceiptKind = "negative"
)

type NegativeReason string

const (
	GuardRejected NegativeReason = "GUARD_REJECTED"
	PreconditionMismatch NegativeReason = "PRECONDITION_MISMATCH"
	NotChangedProposed NegativeReason = "NOT_CHANGED_PROPOSED"
)

// Decision records either a historical D1 actuation decision or a qualified
// no-actuation refusal. A refusal is not permission to activate a reference.
// D1 commit visibility may occur later; there is no D2 completion deadline.
type Decision struct {
	Profile DecisionProfile
	TimeBase ID
	BootID ID
	LowerTick uint64
	UpperTick uint64
	Proof ID
}

type PositivePayload struct {
	TransitionID ID
	Before Reference
	After Reference
	Semantic string
}

type NegativePayload struct {
	Reason NegativeReason
	NoAdditionalEffectProof ID
}

// Receipt has exactly one payload matching Kind. Its proof is owner-verified.
// Structural validation alone never authenticates a backend's durable commit.
type Receipt struct {
	ReceiptID ID
	CommitID ID
	ProducerBackend ID
	Scope Scope
	Execution Execution
	Binding Binding
	Kind ReceiptKind
	Positive *PositivePayload
	Negative *NegativePayload
	Guard Guard
	Decision Decision
	Proof ID
}

type BackendObservation struct {
	Knowledge Knowledge
	Receipt *Receipt
}

// Evidence references are resolved by a trusted port, never accepted as booleans.
type Evidence struct {
	Issuer ID
	ServingIncarnation ID
	Generation ID
	SnapshotID ID
	FreshnessProof ID
	ObservationProof ID
}

type ActiveReference struct {
	Knowledge Knowledge
	Scope Scope
	Reference *Reference
	Evidence Evidence
}

type Boundary string

const (
	ExecutorLedger Boundary = "executor_ledger"
	CPReport Boundary = "cp_report"
	CPAudit Boundary = "cp_audit"
)

type AckState string

const (
	AckConfirmed AckState = "CONFIRMED"
	AckUnknown AckState = "UNKNOWN"
)

// OutcomeRecord is a projection, not authority to repeat a registry operation.
type OutcomeRecord struct {
	Scope Scope
	Execution Execution
	Binding Binding
	ReceiptID ID
	ReceiptKind ReceiptKind
	Boundary Boundary
	RecordedBy ID
	RecordAuthority ID
	Evidence ID
	Ack AckState
	Recovered bool
	OriginalAuditAvailability Knowledge
}

type Projection struct {
	Knowledge Knowledge
	Record *OutcomeRecord
}

type WitnessOutcome struct {
	LiabilityID ID
	Scope Scope
	Execution Execution
	Binding Binding
	Receipt Receipt
	Evidence ID
}

// ExecutionSnapshot must be a coherent, complete observation from a trusted port.
// ABSENT is observation absence, never a NOT_STARTED or unconsumed-grant proof.
type ExecutionSnapshot struct {
	StoredRequest *Request
	Backend BackendObservation
	Current ActiveReference
	Ledger Projection
	Report Projection
	Audit Projection
	Witness *WitnessOutcome
	Outstanding []ID
	Evidence Evidence
}

type Call struct {
	Principal ID
	Capability ID
	CorrelationID ID
}

type QueryAction string

const (
	ReadReferenceAction QueryAction = "registry.read_active_reference"
	LookupExecutionAction QueryAction = "registry.lookup_execution"
	PlanReconciliationAction QueryAction = "registry.plan_reconciliation"
)

type ReadRequest struct {
	Call Call
	Scope Scope
}

type LookupRequest struct {
	Call Call
	Request Request
}

type LookupResult struct {
	Knowledge Knowledge
	Backend BackendObservation
	Current ActiveReference
	Ledger Projection
	Report Projection
	Audit Projection
	Outstanding []ID
	ServiceApplication string
}

// ReadPort has no writer, raw SQL, path, shell, restore or startup-recovery method.
type ReadPort interface {
	ReadActiveReference(context.Context, Scope) (ActiveReference, error)
	ReadExecution(context.Context, Request) (ExecutionSnapshot, error)
}

type QueryAuthorizer interface {
	Authorize(context.Context, Call, QueryAction, Scope) error
}

// Verifier authenticates owner-issued receipts separately from current freshness.
// Observed data is passed with proof so implementations can verify payload,
// projection and snapshot-generation coherence, not only proof-reference syntax.
// Implementations must validate issuer/audience/scope/trust/restore continuity;
// merely checking that an evidence reference string is present is insufficient.
type Verifier interface {
	VerifyReceipt(context.Context, Request, Receipt) error
	VerifyActiveReference(context.Context, Scope, ActiveReference) error
	VerifyExecutionSnapshot(context.Context, Request, ExecutionSnapshot) error
	VerifyWitness(context.Context, Request, WitnessOutcome) error
}

type TerminalRecord struct {
	Boundary Boundary
	Scope Scope
	Execution Execution
	Binding Binding
	ReceiptID ID
	ReceiptKind ReceiptKind
	Result string
}

type RecordAction string

const (
	RecordLedgerOutcome RecordAction = "record_ledger_outcome"
	RecordCPOutcome RecordAction = "record_cp_outcome"
	ResendCPOutcome RecordAction = "resend_cp_outcome"
	RecordRecoveredAudit RecordAction = "record_recovered_audit"
)

type RequiredRecordCapability string

const (
	ExecutorRecordCapability RequiredRecordCapability = "executor.record_outcome"
	CPReportCapability RequiredRecordCapability = "cp.report_outcome"
	CPAuditCapability RequiredRecordCapability = "cp.record_recovered_audit"
)

type RepairStep struct {
	Action RecordAction
	Boundary Boundary
	RequiredCapability RequiredRecordCapability
	Expected Projection
	Outcome TerminalRecord
	SourceReceipt ID
	SourceWitness ID
	OriginalAuditAvailability Knowledge
}

// ReconciliationPlan is data only. It cannot apply records, consume/reissue grants,
// change a reference, reopen admission, or release an UNKNOWN reservation.
// A future writer must freshly authorize each step and revalidate expected state.
type ReconciliationPlan struct {
	Knowledge Knowledge
	Result LookupResult
	Steps []RepairStep
	Outstanding []ID
	OriginalMutationAuthorized bool
}
