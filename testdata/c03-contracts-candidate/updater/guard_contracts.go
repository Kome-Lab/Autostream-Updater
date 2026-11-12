// UNAPPLIED C03/Contracts candidate. This file is staged under testdata only.
// It must not be installed into the product package until Contracts ownership,
// publication and dependency approval are resolved. Candidate CI may copy it
// into a disposable synthetic workspace; it is not runtime fallback code.

package registry

import (
	"context"
	"reflect"

	evidence "github.com/Kome-Lab/Autostream-Contracts/v3evidence"
)

// GuardEnvelopeReadPort is a trusted, fixed-owner, read-only delivery seam.
// The Agent may deliver detached bytes but cannot change signed/authenticated
// content. There is no URL, path, SQL, issuer selector, consume or retry method.
// No CP Producer or transport implementation is supplied by this package.
type GuardEnvelopeReadPort interface {
	ReadGuardEnvelopes(context.Context, Request, BackendReadFrame) ([][]byte, error)
}

// These separate hooks must qualify the COMPLETE canonical Envelope and original
// bytes, including profile/key/rotation/trust and target binding. CurrentValidity
// must use a trusted evidence clock, not Context.Deadline or a D1 decision.
// CurrentRevocation covers effective Policy/Trust/Domain/ownership/Fence,
// Admission, Drain and Candidate state. No default key, clock, TTL or successful
// authenticator is supplied. These hooks are not Independent Continuity.
type GuardEnvelopeVerifier interface {
	VerifyIntegrity(context.Context, evidence.Envelope, []byte) error
	VerifyCurrentValidity(context.Context, evidence.Envelope) error
	VerifyCurrentRevocation(context.Context, evidence.Envelope) error
}

type ContractsGuardEvidenceSource struct {
	config   GuardEvidenceConfig
	delivery GuardEnvelopeReadPort
}

type ContractsGuardEvidenceAuthenticator struct {
	config   GuardEvidenceConfig
	verifier GuardEnvelopeVerifier
}

func contractsGuardConfig(config GuardEvidenceConfig) (GuardEvidenceConfig, error) {
	if ValidateScope(config.Scope) != nil || validateID(config.Audience, "contracts_guard.audience") != nil || len(config.Issuers) != len(guardEvidenceKinds) {
		return GuardEvidenceConfig{}, invalid("contracts_guard.configuration")
	}
	seen := make(map[GuardEvidenceKind]bool, len(config.Issuers))
	for _, issuer := range config.Issuers {
		if !guardEvidenceKindKnown(issuer.Kind) || seen[issuer.Kind] || validateID(issuer.Issuer, "contracts_guard.issuer") != nil {
			return GuardEvidenceConfig{}, invalid("contracts_guard.configuration")
		}
		seen[issuer.Kind] = true
	}
	config.Issuers = append([]GuardEvidenceIssuer(nil), config.Issuers...)
	return config, nil
}

func NewContractsGuardEvidenceSource(config GuardEvidenceConfig, delivery GuardEnvelopeReadPort) (*ContractsGuardEvidenceSource, error) {
	pinned, err := contractsGuardConfig(config)
	if err != nil {
		return nil, err
	}
	return &ContractsGuardEvidenceSource{config: pinned, delivery: delivery}, nil
}

func NewContractsGuardEvidenceAuthenticator(config GuardEvidenceConfig, verifier GuardEnvelopeVerifier) (*ContractsGuardEvidenceAuthenticator, error) {
	pinned, err := contractsGuardConfig(config)
	if err != nil {
		return nil, err
	}
	return &ContractsGuardEvidenceAuthenticator{config: pinned, verifier: verifier}, nil
}

func contractsGuardIssuer(config GuardEvidenceConfig, kind GuardEvidenceKind) ID {
	for _, issuer := range config.Issuers {
		if issuer.Kind == kind {
			return issuer.Issuer
		}
	}
	return ""
}

func contractsGuardUnknown(request Request, frame BackendReadFrame) GuardEvidenceBundle {
	return GuardEvidenceBundle{Knowledge: Unknown, Scope: request.Command.Scope, Execution: request.Command.Execution, Binding: request.Binding, Frame: frame}
}

func contractsGuardValidateTarget(config GuardEvidenceConfig, request Request, frame BackendReadFrame) error {
	if ValidateRequest(request) != nil || sqliteValidateFrame(frame) != nil {
		return invalid("contracts_guard.request")
	}
	if request.Command.Scope != config.Scope {
		return collision("contracts_guard.scope")
	}
	if request.Command.AuthorizationIssuer != contractsGuardIssuer(config, GuardCPAuthorization) {
		return collision("contracts_guard.cp_issuer")
	}
	return nil
}

func (s *ContractsGuardEvidenceSource) ReadGuardEvidence(ctx context.Context, request Request, frame BackendReadFrame) (GuardEvidenceBundle, error) {
	unknown := contractsGuardUnknown(request, frame)
	if s == nil || ctx == nil {
		return unknown, invalid("contracts_guard.context")
	}
	if err := ctx.Err(); err != nil {
		return unknown, err
	}
	if err := contractsGuardValidateTarget(s.config, request, frame); err != nil {
		return unknown, err
	}
	if readNilPort(s.delivery) {
		return unknown, nil
	}
	encoded, err := s.delivery.ReadGuardEnvelopes(ctx, request, frame)
	if err := ctx.Err(); err != nil {
		return unknown, err
	}
	if err != nil {
		return unknown, fault(CodeUnavailable, "contracts_guard.read")
	}
	bundle, _, err := contractsGuardBundle(s.config, request, frame, encoded)
	if err != nil {
		return unknown, err
	}
	return bundle, nil
}

func contractsGuardBundle(config GuardEvidenceConfig, request Request, frame BackendReadFrame, encoded [][]byte) (GuardEvidenceBundle, []evidence.Envelope, error) {
	unknown := contractsGuardUnknown(request, frame)
	if err := contractsGuardValidateTarget(config, request, frame); err != nil {
		return unknown, nil, err
	}
	if len(encoded) != len(guardEvidenceKinds) {
		return unknown, nil, fault(CodeEvidenceUnknown, "contracts_guard.coverage")
	}
	byKind := make(map[GuardEvidenceKind]evidence.Envelope, len(encoded))
	rawByKind := make(map[GuardEvidenceKind][]byte, len(encoded))
	seenIDs := make(map[string]bool, len(encoded))
	total := 0
	for _, bytes := range encoded {
		if len(bytes) == 0 || len(bytes) > evidence.MaxEnvelopeBytes || total > evidence.MaxEnvelopeBytes*len(guardEvidenceKinds)-len(bytes) {
			return unknown, nil, fault(CodeEvidenceUnknown, "contracts_guard.size")
		}
		total += len(bytes)
		detached := append([]byte(nil), bytes...)
		envelope, err := evidence.Decode(detached)
		if err != nil {
			return unknown, nil, fault(CodeEvidenceUnknown, "contracts_guard.decode")
		}
		kind := GuardEvidenceKind(envelope.Kind)
		if !guardEvidenceKindKnown(kind) || seenIDs[envelope.EvidenceID] {
			return unknown, nil, collision("contracts_guard.identity")
		}
		if _, duplicate := byKind[kind]; duplicate {
			return unknown, nil, collision("contracts_guard.kind")
		}
		if envelope.Scope != (evidence.Scope{Realm: string(request.Command.Scope.Realm), Host: string(request.Command.Scope.Host), Resource: string(request.Command.Scope.Resource), Backend: string(request.Command.Scope.Backend)}) ||
			envelope.Execution != (evidence.Execution{RequestID: string(request.Command.Execution.RequestID), ExecutionKey: string(request.Command.Execution.ExecutionKey), OperationID: string(request.Command.Execution.OperationID), AttemptID: string(request.Command.Execution.AttemptID), StepID: string(request.Command.Execution.StepID)}) ||
			envelope.Binding != string(request.Binding) ||
			envelope.Frame != (evidence.BackendReadFrame{Issuer: string(frame.Issuer), ServingIncarnation: string(frame.ServingIncarnation), Generation: string(frame.Generation), SnapshotID: string(frame.SnapshotID), ObservationProof: string(frame.ObservationProof)}) {
			return unknown, nil, collision("contracts_guard.target")
		}
		if envelope.Issuer != string(contractsGuardIssuer(config, kind)) || envelope.Audience != string(config.Audience) {
			return unknown, nil, collision("contracts_guard.authority")
		}
		seenIDs[envelope.EvidenceID] = true
		byKind[kind], rawByKind[kind] = evidence.Clone(envelope), detached
	}
	for _, kind := range guardEvidenceKinds {
		if _, ok := byKind[kind]; !ok {
			return unknown, nil, fault(CodeEvidenceUnknown, "contracts_guard.coverage")
		}
	}
	if err := contractsGuardCorrelate(request, frame, byKind); err != nil {
		return unknown, nil, err
	}
	bundle := contractsGuardUnknown(request, frame)
	bundle.Knowledge = Known
	// Evidence IDs are lookup/correlation references ONLY. Authenticity requires
	// every original Envelope/Integrity proof to pass the separate Verifier.
	bundle.Proof = ID(byKind[GuardCPAuthorization].EvidenceID)
	envelopes := make([]evidence.Envelope, 0, len(guardEvidenceKinds))
	for _, kind := range guardEvidenceKinds {
		envelope := byKind[kind]
		bundle.EncodedEvidence = append(bundle.EncodedEvidence, append([]byte(nil), rawByKind[kind]...))
		envelopes = append(envelopes, evidence.Clone(envelope))
		if envelope.Validity.Status != "SPECIFIED" || envelope.Validity.Issued == nil || envelope.Validity.Expiry == nil {
			bundle.Knowledge = Unknown
			continue
		}
		claim := GuardEvidenceClaim{Kind: kind, Issuer: ID(envelope.Issuer), Audience: ID(envelope.Audience), Proof: ID(envelope.EvidenceID),
			Validity: GuardEvidenceValidity{TimeBase: ID(envelope.Validity.Issued.TimeBase), BootID: ID(envelope.Validity.Issued.BootID), IssuedTick: envelope.Validity.Issued.Tick, ExpiresTick: envelope.Validity.Expiry.Tick, Proof: ID(envelope.Validity.QualificationProof)}}
		switch kind {
		case GuardCPAuthorization:
			claim.Condition = contractsGuardCondition(envelope.CPAuthorization.Decision, "AUTHORIZED", "DENIED")
		case GuardPolicy:
			claim.Condition, claim.Revision = contractsGuardCondition(envelope.Policy.Revocation, "ACTIVE", "REVOKED"), ID(envelope.Policy.Revision)
		case GuardTrust:
			claim.Condition, claim.Revision = contractsGuardCondition(envelope.Trust.Revocation, "ACTIVE", "REVOKED"), ID(envelope.Trust.Revision)
		case GuardMembership:
			claim.Condition, claim.Revision = contractsGuardCondition(envelope.Membership.State, "MEMBER", "REVOKED"), ID(envelope.Membership.Revision)
		case GuardOwnership:
			claim.Condition, claim.Revision = contractsGuardCondition(envelope.Ownership.State, "CURRENT", "REVOKED"), ID(envelope.Ownership.OwnershipEpoch)
		case GuardFence:
			claim.Condition, claim.Revision = contractsGuardCondition(envelope.Fence.State, "CURRENT", "REVOKED"), ID(envelope.Fence.FenceEpoch)
		case GuardGeneration:
			claim.Condition, claim.Revision = contractsGuardCondition(envelope.Generation.State, "ACTIVE", "REVOKED"), ID(envelope.Generation.Generation)
		case GuardBoot:
			claim.Condition, claim.Revision = PreflightConditionValid, ID(envelope.Boot.BootID)
		case GuardProcess:
			process := envelope.Process
			claim.Condition, claim.Revision = PreflightConditionValid, ID(process.Incarnation)
			claim.LocalIdentity = LocalExecutorIdentity{Knowledge: Known, BootID: ID(process.BootID), ProcessID: process.ProcessID, StartTicks: process.StartTicks}
		case GuardPAdmission:
			admission := envelope.PAdmission
			switch {
			case admission.State == "UNKNOWN" || admission.Consumption == "UNKNOWN" || admission.Revocation == "UNKNOWN":
				claim.Condition = PreflightConditionUnknown
			case admission.State == "OPEN" && admission.Consumption == "UNCONSUMED" && admission.Revocation == "ACTIVE":
				claim.Condition = PreflightConditionValid
			default:
				claim.Condition = PreflightConditionDenied
			}
		case GuardDrain:
			claim.Drain, claim.DrainSeal = PreflightDrainState(envelope.Drain.State), ID(envelope.Drain.Seal)
		case GuardCandidate:
			candidate := envelope.Candidate
			switch candidate.Approval {
			case "APPROVED":
				claim.Condition = PreflightConditionValid
			case "UNKNOWN":
				claim.Condition = PreflightConditionUnknown
			default:
				claim.Condition = PreflightConditionDenied
			}
			claim.CandidateRevision, claim.CandidateContentPin = ID(candidate.Revision), ID(candidate.ContentHash)
		case GuardBusiness:
			claim.BusinessAdmission = PreflightBusinessAdmission(envelope.BusinessAdmission.State)
		}
		bundle.Claims = append(bundle.Claims, claim)
	}
	if bundle.Knowledge != Known {
		// Preserve the received bytes as diagnostic correlation only. Missing clock
		// qualification cannot produce a structurally complete Known Guard claim.
		bundle.Claims = nil
	}
	return bundle, envelopes, nil
}

func contractsGuardCondition(value, positive, negative string) PreflightCondition {
	if value == positive {
		return PreflightConditionValid
	}
	if value == negative {
		return PreflightConditionDenied
	}
	return PreflightConditionUnknown
}

func contractsGuardCorrelate(request Request, frame BackendReadFrame, byKind map[GuardEvidenceKind]evidence.Envelope) error {
	cp := byKind[GuardCPAuthorization]
	policy, trust := byKind[GuardPolicy].Policy, byKind[GuardTrust].Trust
	if cp.CPAuthorization.Action != ReferenceOnlyOperation || cp.Issuer != string(request.Command.AuthorizationIssuer) ||
		cp.CPAuthorization.PolicyRevision != policy.Revision || cp.CPAuthorization.TrustRevision != trust.Revision ||
		policy.SubjectEvidenceID != cp.EvidenceID || trust.SubjectEvidenceID != cp.EvidenceID ||
		policy.Revision != string(request.Command.RequiredGuard.Policy) || trust.Revision != string(request.Command.RequiredGuard.Trust) {
		return collision("contracts_guard.policy_trust")
	}
	membership, drain := byKind[GuardMembership].Membership, byKind[GuardDrain].Drain
	if membership.DomainID != drain.DomainID || membership.Revision != drain.MembershipRevision || membership.Revision != string(request.Command.RequiredGuard.Membership) {
		return collision("contracts_guard.membership")
	}
	owner, fence := byKind[GuardOwnership].Ownership, byKind[GuardFence].Fence
	boot, process := byKind[GuardBoot].Boot, byKind[GuardProcess].Process
	generation := byKind[GuardGeneration].Generation
	required := request.Command.RequiredGuard
	if *owner != *fence || owner.OwnershipEpoch != string(required.OwnershipEpoch) ||
		owner.FenceEpoch != string(required.FenceEpoch) || owner.BootID != boot.BootID ||
		owner.ProcessIncarnation != process.Incarnation || boot.BootID != process.BootID ||
		boot.ActorID != process.ActorID || boot.ActorRole != "LOCAL_EXECUTOR" || process.ActorRole != "LOCAL_EXECUTOR" ||
		boot.BootID != string(required.BootID) || process.Incarnation != string(required.ProcessIncarnation) ||
		generation.Generation != string(required.Generation) || generation.Generation != string(frame.Generation) {
		return collision("contracts_guard.owner_identity")
	}
	candidate := byKind[GuardCandidate].Candidate
	if candidate.ResourceID != string(request.Command.Scope.Resource) ||
		candidate.Revision != string(request.Command.CandidateRevision) || candidate.ContentHash != string(request.Command.CandidateContentPin) {
		return collision("contracts_guard.candidate")
	}
	// Drain epoch/seal/closure, Admission epoch/consumption and the actual current
	// Owner/Actor association remain authority-qualified facts, never inferred
	// from presence or a matching local string. The mandatory hooks check them.
	return nil
}

func (a *ContractsGuardEvidenceAuthenticator) VerifyGuardEvidence(ctx context.Context, request Request, snapshot PreflightSnapshot, bundle GuardEvidenceBundle) error {
	if a == nil || ctx == nil {
		return invalid("contracts_guard.context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if readNilPort(a.verifier) {
		return fault(CodeEvidenceUnknown, "contracts_guard.verifier")
	}
	frame := sqliteFrameFromEvidence(snapshot.Snapshot.Evidence)
	rebuilt, envelopes, err := contractsGuardBundle(a.config, request, frame, bundle.EncodedEvidence)
	if err != nil {
		return err
	}
	if rebuilt.Knowledge != Known || !reflect.DeepEqual(rebuilt, cloneGuardEvidenceBundle(bundle)) {
		return fault(CodeEvidenceUnknown, "contracts_guard.payload")
	}
	for _, claim := range rebuilt.Claims {
		if claim.Condition == PreflightConditionUnknown || claim.Drain == PreflightDrainUnknown || claim.BusinessAdmission == PreflightBusinessUnknown {
			return fault(CodeEvidenceUnknown, "contracts_guard.unqualified")
		}
	}
	// Never authenticate only a projection or a nonempty proof. Original bytes
	// (including profile/key metadata) and the canonical typed payload are passed
	// together. Each call receives its own detached copy.
	for index, envelope := range envelopes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if a.verifier.VerifyIntegrity(ctx, evidence.Clone(envelope), append([]byte(nil), rebuilt.EncodedEvidence[index]...)) != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fault(CodeEvidenceUnknown, "contracts_guard.integrity")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if a.verifier.VerifyCurrentValidity(ctx, evidence.Clone(envelope)) != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fault(CodeEvidenceUnknown, "contracts_guard.validity")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if a.verifier.VerifyCurrentRevocation(ctx, evidence.Clone(envelope)) != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fault(CodeEvidenceUnknown, "contracts_guard.revocation")
		}
	}
	return ctx.Err()
}

var (
	_ GuardEvidenceReadPort      = (*ContractsGuardEvidenceSource)(nil)
	_ GuardEvidenceAuthenticator = (*ContractsGuardEvidenceAuthenticator)(nil)
)
