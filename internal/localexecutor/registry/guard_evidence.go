package registry

import (
 "context"
 "reflect"
)

// GuardEvidenceKind names an internal, post-transport claim. These are not wire
// contracts, new CP endpoints, tokens, or replacements for Contracts-owned types.
type GuardEvidenceKind string

const (
 GuardCPAuthorization GuardEvidenceKind = "cp_authorization"
 GuardPolicy GuardEvidenceKind = "policy"
 GuardTrust GuardEvidenceKind = "trust"
 GuardMembership GuardEvidenceKind = "membership"
 GuardOwnership GuardEvidenceKind = "ownership"
 GuardFence GuardEvidenceKind = "fence"
 GuardGeneration GuardEvidenceKind = "generation"
 GuardBoot GuardEvidenceKind = "boot"
 GuardProcess GuardEvidenceKind = "process"
 GuardPAdmission GuardEvidenceKind = "p_admission"
 GuardDrain GuardEvidenceKind = "drain"
 GuardCandidate GuardEvidenceKind = "candidate"
 GuardBusiness GuardEvidenceKind = "business_admission"
)

var guardEvidenceKinds = [...]GuardEvidenceKind{
 GuardCPAuthorization, GuardPolicy, GuardTrust, GuardMembership, GuardOwnership,
 GuardFence, GuardGeneration, GuardBoot, GuardProcess, GuardPAdmission, GuardDrain,
 GuardCandidate, GuardBusiness,
}

type GuardEvidenceIssuer struct { Kind GuardEvidenceKind; Issuer ID }

// Configuration comes from trusted construction, never the requesting command.
// Every source remains pinned to this exact Scope and Audience; a claim cannot
// change its owner by naming another issuer, URL, path, policy, or request.
type GuardEvidenceConfig struct {
 Scope Scope
 Audience ID
 Issuers []GuardEvidenceIssuer
}

// Validity is issuer evidence, not a local time.Now or Go Context deadline.
// An authenticator must prove its current applicability and clock/Boot trust.
// Structural tick comparisons alone never authenticate expiry or D1.
type GuardEvidenceValidity struct {
 TimeBase ID
 BootID ID
 IssuedTick uint64
 ExpiresTick uint64
 Proof ID
}

// Only fields applicable to Kind may be populated. A Process claim associates an
// authenticated opaque v3 incarnation with actual local OS facts; this adapter
// never invents an incarnation from PID/start ticks alone.
type GuardEvidenceClaim struct {
 Kind GuardEvidenceKind
 Issuer ID
 Audience ID
 Validity GuardEvidenceValidity
 Proof ID
 Condition PreflightCondition
 Revision ID
 Drain PreflightDrainState
 DrainSeal ID
 BusinessAdmission PreflightBusinessAdmission
 CandidateRevision ID
 CandidateContentPin ID
 LocalIdentity LocalExecutorIdentity
}

type GuardEvidenceBundle struct {
 Knowledge Knowledge
 Scope Scope
 Execution Execution
 Binding Binding
 Frame BackendReadFrame
 Proof ID
 Claims []GuardEvidenceClaim
}

// Implementations must be read-only, current, bounded, and fixed-owner. This
// package supplies no v3 CP/Agent producer or legacy-v2-to-v3 authority bridge.
type GuardEvidenceReadPort interface {
 ReadGuardEvidence(context.Context, Request, BackendReadFrame) (GuardEvidenceBundle, error)
}

// Authenticators must authenticate the COMPLETE detached bundle and its exact
// Request/frame/snapshot association, each issuer/audience/scope, effective
// Policy/Trust and revocation/Barrier state, and each validity interval against
// a qualified Time Base. Merely accepting nonempty proof IDs is not sufficient.
// No default implementation, key product, signature, token or TTL is chosen.
type GuardEvidenceAuthenticator interface {
 VerifyGuardEvidence(context.Context, Request, PreflightSnapshot, GuardEvidenceBundle) error
}

// Continuity is intentionally a different source and verification responsibility.
// A Guard authenticator can never satisfy this interface implicitly.
type PreflightContinuityVerifier interface {
 VerifyPreflightContinuity(context.Context, Request, PreflightSnapshot, PreflightContinuityObservation) error
}

// GuardEvidenceAdapter is the typed fail-closed connection boundary. Its actual
// v3 evidence producer, authenticator, and independent Continuity remain
// unimplemented until explicitly supplied by trusted product composition.
type GuardEvidenceAdapter struct {
 config GuardEvidenceConfig
 source GuardEvidenceReadPort
 authenticator GuardEvidenceAuthenticator
 identity LocalExecutorIdentityReadPort
 base Verifier
 continuity PreflightContinuityVerifier
}

func NewGuardEvidenceAdapter(config GuardEvidenceConfig, source GuardEvidenceReadPort, authenticator GuardEvidenceAuthenticator, identity LocalExecutorIdentityReadPort, base Verifier, continuity PreflightContinuityVerifier) (*GuardEvidenceAdapter, error) {
 if ValidateScope(config.Scope) != nil || validateID(config.Audience, "guard.audience") != nil || len(config.Issuers) != len(guardEvidenceKinds) {
  return nil, invalid("guard.configuration")
 }
 seen := make(map[GuardEvidenceKind]bool, len(config.Issuers))
 for _, issuer := range config.Issuers {
  if !guardEvidenceKindKnown(issuer.Kind) || seen[issuer.Kind] || validateID(issuer.Issuer, "guard.issuer") != nil {
   return nil, invalid("guard.configuration")
  }
  seen[issuer.Kind] = true
 }
 config.Issuers = append([]GuardEvidenceIssuer(nil), config.Issuers...)
 if readNilPort(identity) { identity = FixedLocalExecutorIdentitySource{} }
 return &GuardEvidenceAdapter{config:config, source:source, authenticator:authenticator, identity:identity, base:base, continuity:continuity}, nil
}

func guardEvidenceKindKnown(kind GuardEvidenceKind) bool {
 for _, value := range guardEvidenceKinds { if value == kind { return true } }
 return false
}

func cloneGuardEvidenceBundle(bundle GuardEvidenceBundle) GuardEvidenceBundle {
 bundle.Claims = append([]GuardEvidenceClaim(nil), bundle.Claims...)
 return bundle
}

func (a *GuardEvidenceAdapter) issuer(kind GuardEvidenceKind) ID {
 for _, issuer := range a.config.Issuers { if issuer.Kind == kind { return issuer.Issuer } }
 return ""
}

func guardEvidenceUnknown(request Request, frame BackendReadFrame) PreflightGuardObservation {
 return PreflightGuardObservation{Knowledge:Unknown, Scope:request.Command.Scope, Execution:request.Command.Execution, Binding:request.Binding, Frame:frame}
}

func (a *GuardEvidenceAdapter) ObservePreflight(ctx context.Context, request Request, frame BackendReadFrame) (PreflightGuardObservation, error) {
 unknown := guardEvidenceUnknown(request, frame)
 if a == nil || ctx == nil { return unknown, invalid("guard.context") }
 if err := ctx.Err(); err != nil { return unknown, err }
 if ValidateRequest(request) != nil || sqliteValidateFrame(frame) != nil { return unknown, invalid("guard.request") }
 if request.Command.Scope != a.config.Scope { return unknown, collision("guard.scope") }
 if readNilPort(a.source) || readNilPort(a.authenticator) { return unknown, nil }
 bundle, err := a.source.ReadGuardEvidence(ctx, request, frame)
 if ctx.Err() != nil { return unknown, ctx.Err() }
 if err != nil { return unknown, fault(CodeUnavailable, "guard.read") }
 // Detach immediately; a source retaining its backing slice cannot alter this
 // observation after return. This read is not yet authenticity verification.
 return a.project(request, frame, cloneGuardEvidenceBundle(bundle))
}

func (a *GuardEvidenceAdapter) project(request Request, frame BackendReadFrame, bundle GuardEvidenceBundle) (PreflightGuardObservation, error) {
 observed := guardEvidenceUnknown(request, frame)
 if bundle.Knowledge == Conflict { observed.Knowledge = Conflict; return observed, nil }
 if bundle.Knowledge != Known { return observed, nil }
 if bundle.Scope != request.Command.Scope || bundle.Execution != request.Command.Execution || bundle.Binding != request.Binding { return observed, collision("guard.identity") }
 if bundle.Frame != frame { return observed, fault(CodeEvidenceUnknown, "guard.frame") }
 if validateID(bundle.Proof, "guard.proof") != nil || len(bundle.Claims) != len(guardEvidenceKinds) { return observed, fault(CodeEvidenceUnknown, "guard.coverage") }
 observed.Knowledge = Known
 observed.Proof = bundle.Proof
 seen := make(map[GuardEvidenceKind]bool, len(bundle.Claims))
 for _, claim := range bundle.Claims {
  if !guardEvidenceKindKnown(claim.Kind) || seen[claim.Kind] { return guardEvidenceUnknown(request, frame), fault(CodeEvidenceUnknown, "guard.claim_kind") }
  seen[claim.Kind] = true
  if err := a.validateClaim(request, claim); err != nil { return guardEvidenceUnknown(request, frame), err }
  switch claim.Kind {
  case GuardCPAuthorization: observed.CPAuthorization = claim.Condition
  case GuardPolicy: observed.Policy, observed.Current.Policy = claim.Condition, claim.Revision
  case GuardTrust: observed.Trust, observed.Current.Trust = claim.Condition, claim.Revision
  case GuardMembership: observed.Membership, observed.Current.Membership = claim.Condition, claim.Revision
  case GuardOwnership: observed.Ownership, observed.Current.OwnershipEpoch = claim.Condition, claim.Revision
  case GuardFence: observed.Fence, observed.Current.FenceEpoch = claim.Condition, claim.Revision
  case GuardGeneration:
   if claim.Condition != PreflightConditionValid { return guardEvidenceUnknown(request, frame), fault(CodeEvidenceUnknown, "guard.generation") }
   observed.Current.Generation = claim.Revision
  case GuardBoot: observed.Boot, observed.Current.BootID = claim.Condition, claim.Revision
  case GuardProcess: observed.Process, observed.Current.ProcessIncarnation = claim.Condition, claim.Revision
  case GuardPAdmission: observed.PAdmission = claim.Condition
  case GuardDrain: observed.Drain, observed.DrainSeal = claim.Drain, claim.DrainSeal
  case GuardCandidate: observed.Candidate = claim.Condition
  case GuardBusiness: observed.BusinessAdmission = claim.BusinessAdmission
  }
 }
 detached := cloneGuardEvidenceBundle(bundle)
 observed.SourceEvidence = &detached
 return observed, nil
}

func (a *GuardEvidenceAdapter) validateClaim(request Request, claim GuardEvidenceClaim) error {
 if claim.Issuer != a.issuer(claim.Kind) || claim.Audience != a.config.Audience ||
  validateID(claim.Proof, "guard.claim_proof") != nil {
  return fault(CodeEvidenceUnknown, "guard.claim_authority")
 }
 validity := claim.Validity
 if validateID(validity.TimeBase, "guard.time_base") != nil ||
  validateID(validity.BootID, "guard.time_boot") != nil ||
  validateID(validity.Proof, "guard.validity_proof") != nil ||
  validity.ExpiresTick <= validity.IssuedTick {
  return fault(CodeEvidenceUnknown, "guard.validity")
 }
 // Reconstruct the allowed discriminated payload. Any extra field (including
 // Continuity-like state hidden under another Kind) makes the record unknown.
 allowed := GuardEvidenceClaim{Kind:claim.Kind, Issuer:claim.Issuer, Audience:claim.Audience, Validity:claim.Validity, Proof:claim.Proof}
 switch claim.Kind {
 case GuardDrain:
  switch claim.Drain { case PreflightDrainReady, PreflightDrainNotReady, PreflightDrainHeld, PreflightDrainUnknown: default: return invalid("guard.drain") }
  allowed.Drain, allowed.DrainSeal = claim.Drain, claim.DrainSeal
  if claim.Drain == PreflightDrainReady && validateID(claim.DrainSeal, "guard.drain_seal") != nil { return fault(CodeEvidenceUnknown, "guard.drain_seal") }
  if claim.Drain != PreflightDrainReady && claim.DrainSeal != "" { return invalid("guard.drain_payload") }
 case GuardBusiness:
  switch claim.BusinessAdmission { case PreflightBusinessOpen, PreflightBusinessClosed, PreflightBusinessUnknown: default: return invalid("guard.business") }
  allowed.BusinessAdmission = claim.BusinessAdmission
 default:
  switch claim.Condition { case PreflightConditionValid, PreflightConditionDenied, PreflightConditionUnknown: default: return invalid("guard.condition") }
  allowed.Condition = claim.Condition
  switch claim.Kind {
  case GuardPolicy, GuardTrust, GuardMembership, GuardOwnership, GuardFence, GuardGeneration, GuardBoot, GuardProcess:
   if validateID(claim.Revision, "guard.revision") != nil { return invalid("guard.revision") }
   allowed.Revision = claim.Revision
  case GuardCPAuthorization:
   if claim.Issuer != request.Command.AuthorizationIssuer { return collision("guard.cp_issuer") }
  case GuardCandidate:
   allowed.CandidateRevision, allowed.CandidateContentPin = claim.CandidateRevision, claim.CandidateContentPin
   if claim.CandidateRevision != request.Command.CandidateRevision || claim.CandidateContentPin != request.Command.CandidateContentPin { return collision("guard.candidate") }
  }
  if claim.Kind == GuardProcess {
   allowed.LocalIdentity = claim.LocalIdentity
   if claim.LocalIdentity.Knowledge != Known || validateID(claim.LocalIdentity.BootID, "guard.process_boot") != nil || claim.LocalIdentity.ProcessID == 0 || claim.LocalIdentity.StartTicks == 0 { return fault(CodeEvidenceUnknown, "guard.process_identity") }
  }
 }
 if claim != allowed { return invalid("guard.claim_payload") }
 return nil
}

func (a *GuardEvidenceAdapter) VerifyPreflightGuard(ctx context.Context, request Request, snapshot PreflightSnapshot, observed PreflightGuardObservation) error {
 if a == nil || ctx == nil { return invalid("guard.context") }
 if err := ctx.Err(); err != nil { return err }
 if ValidateRequest(request) != nil || request.Command.Scope != a.config.Scope { return invalid("guard.request") }
 if readNilPort(a.source) || readNilPort(a.authenticator) || readNilPort(a.identity) || observed.SourceEvidence == nil { return fault(CodeEvidenceUnknown, "guard.connection") }
 frame := sqliteFrameFromEvidence(snapshot.Snapshot.Evidence)
 if sqliteValidateFrame(frame) != nil || observed.Frame != frame { return fault(CodeEvidenceUnknown, "guard.frame") }
 bundle := cloneGuardEvidenceBundle(*observed.SourceEvidence)
 expected, err := a.project(request, frame, cloneGuardEvidenceBundle(bundle))
 if err != nil { return err }
 if expected.Knowledge != Known || !reflect.DeepEqual(expected, observed) { return fault(CodeEvidenceUnknown, "guard.payload") }
 initial, err := a.identity.ReadLocalIdentity(ctx)
 if ctx.Err() != nil { return ctx.Err() }
 if err != nil || initial.Knowledge != Known { return fault(CodeEvidenceUnknown, "guard.local_identity") }
 for _, claim := range bundle.Claims {
  if claim.Kind == GuardBoot && claim.Revision != initial.BootID { return collision("guard.local_boot") }
  if claim.Kind == GuardProcess && claim.LocalIdentity != initial { return collision("guard.local_process") }
 }
 if err := a.authenticator.VerifyGuardEvidence(ctx, request, clonePreflightSnapshot(snapshot), cloneGuardEvidenceBundle(bundle)); err != nil {
  if ctx.Err() != nil { return ctx.Err() }
  return fault(CodeEvidenceUnknown, "guard.authentication")
 }
 // This second read is an explicit stability check, never a retry/fallback.
 // Authenticators still own current applicability; equality is not freshness.
 current, err := a.source.ReadGuardEvidence(ctx, request, frame)
 if ctx.Err() != nil { return ctx.Err() }
 if err != nil || !reflect.DeepEqual(bundle, cloneGuardEvidenceBundle(current)) { return fault(CodeEvidenceUnknown, "guard.changed") }
 final, err := a.identity.ReadLocalIdentity(ctx)
 if ctx.Err() != nil { return ctx.Err() }
 if err != nil || final != initial { return fault(CodeEvidenceUnknown, "guard.local_identity_changed") }
 return nil
}

func (a *GuardEvidenceAdapter) VerifyReceipt(ctx context.Context, request Request, receipt Receipt) error {
 if a == nil || ctx == nil { return invalid("guard.context") }
 if err := ctx.Err(); err != nil { return err }
 if readNilPort(a.base) { return fault(CodeEvidenceUnknown, "guard.receipt_verifier") }
 if err := ValidateReceipt(request, receipt); err != nil { return err }
 if a.base.VerifyReceipt(ctx, request, readCloneReceipt(receipt)) != nil { return fault(CodeEvidenceUnknown, "guard.receipt_verifier") }
 return ctx.Err()
}

func (a *GuardEvidenceAdapter) VerifyActiveReference(ctx context.Context, scope Scope, active ActiveReference) error {
 if a == nil || ctx == nil { return invalid("guard.context") }
 if err := ctx.Err(); err != nil { return err }
 if readNilPort(a.base) { return fault(CodeEvidenceUnknown, "guard.reference_verifier") }
 if readValidateActive(scope, active) != nil { return invalid("guard.active_reference") }
 if a.base.VerifyActiveReference(ctx, scope, readCloneActive(active)) != nil { return fault(CodeEvidenceUnknown, "guard.reference_verifier") }
 return ctx.Err()
}

func (a *GuardEvidenceAdapter) VerifyExecutionSnapshot(ctx context.Context, request Request, snapshot ExecutionSnapshot) error {
 if a == nil || ctx == nil { return invalid("guard.context") }
 if err := ctx.Err(); err != nil { return err }
 if readNilPort(a.base) { return fault(CodeEvidenceUnknown, "guard.snapshot_verifier") }
 if ValidateRequest(request) != nil { return invalid("guard.request") }
 if a.base.VerifyExecutionSnapshot(ctx, request, readCloneSnapshot(snapshot)) != nil { return fault(CodeEvidenceUnknown, "guard.snapshot_verifier") }
 return ctx.Err()
}

func (a *GuardEvidenceAdapter) VerifyWitness(ctx context.Context, request Request, witness WitnessOutcome) error {
 if a == nil || ctx == nil { return invalid("guard.context") }
 if err := ctx.Err(); err != nil { return err }
 if readNilPort(a.base) { return fault(CodeEvidenceUnknown, "guard.witness_verifier") }
 if witness.Scope != request.Command.Scope || witness.Execution != request.Command.Execution || witness.Binding != request.Binding || ValidateReceipt(request, witness.Receipt) != nil { return collision("guard.witness") }
 witness.Receipt = readCloneReceipt(witness.Receipt)
 if a.base.VerifyWitness(ctx, request, witness) != nil { return fault(CodeEvidenceUnknown, "guard.witness_verifier") }
 return ctx.Err()
}

func (a *GuardEvidenceAdapter) VerifyPreflightContinuity(ctx context.Context, request Request, snapshot PreflightSnapshot, observed PreflightContinuityObservation) error {
 if a == nil || ctx == nil { return invalid("guard.context") }
 if err := ctx.Err(); err != nil { return err }
 if readNilPort(a.continuity) { return fault(CodeEvidenceUnknown, "guard.continuity_verifier") }
 if ValidateRequest(request) != nil { return invalid("guard.request") }
 if a.continuity.VerifyPreflightContinuity(ctx, request, clonePreflightSnapshot(snapshot), clonePreflightContinuity(observed)) != nil { return fault(CodeEvidenceUnknown, "guard.continuity_verifier") }
 return ctx.Err()
}

var (
 _ PreflightGuardReadPort = (*GuardEvidenceAdapter)(nil)
 _ PreflightVerifier = (*GuardEvidenceAdapter)(nil)
)
