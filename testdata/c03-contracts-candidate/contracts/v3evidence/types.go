// Package evidence owns the versioned v3 P-A Guard evidence transport contract.
// Decoding and structural validation never authenticate an issuer or authorize
// mutation. Real issuers, integrity verification, current revocation, qualified
// clocks and independent Continuity are separate product responsibilities.
package evidence

type Kind string

const (
	ProtocolVersion       uint32 = 3
	MaxEnvelopeBytes             = 256 << 10
	MaxResources                 = 1024
	CPAuthorizationKind   Kind   = "cp_authorization"
	PolicyKind            Kind   = "policy"
	TrustKind             Kind   = "trust"
	MembershipKind        Kind   = "membership"
	OwnershipKind         Kind   = "ownership"
	FenceKind             Kind   = "fence"
	GenerationKind        Kind   = "generation"
	BootKind              Kind   = "boot"
	ProcessKind           Kind   = "process"
	PAdmissionKind        Kind   = "p_admission"
	DrainKind             Kind   = "drain"
	CandidateKind         Kind   = "candidate"
	BusinessAdmissionKind Kind   = "business_admission"
	AuthorizationAction          = "registry.reference_only"
)

type Scope struct {
	Realm    string `json:"realm"`
	Host     string `json:"host"`
	Resource string `json:"resource"`
	Backend  string `json:"backend"`
}

type Execution struct {
	RequestID    string `json:"request_id"`
	ExecutionKey string `json:"execution_key"`
	OperationID  string `json:"operation_id"`
	AttemptID    string `json:"attempt_id"`
	StepID       string `json:"step_id"`
}

type BackendReadFrame struct {
	Issuer             string `json:"issuer"`
	ServingIncarnation string `json:"serving_incarnation"`
	Generation         string `json:"generation"`
	SnapshotID         string `json:"snapshot_id"`
	ObservationProof   string `json:"observation_proof"`
}

// TimePoint refers to issuer-authoritative ticks, not time.Now, a Go Context
// deadline, the D1 guarded decision, or Backend commit completion.
type TimePoint struct {
	TimeBase string `json:"time_base"`
	BootID   string `json:"boot_id"`
	Tick     uint64 `json:"tick"`
}

// SPECIFIED only describes the claimed interval. It does not establish clock
// trust or current validity. UNKNOWN transports missing qualification honestly.
type Validity struct {
	Status             string     `json:"status"`
	Issued             *TimePoint `json:"issued,omitempty"`
	Expiry             *TimePoint `json:"expiry,omitempty"`
	QualificationProof string     `json:"qualification_proof,omitempty"`
}

// Integrity carries opaque authentication material. No signature/MAC scheme,
// key product, proof encoding, rotation policy or trust default is selected.
type Integrity struct {
	ProfileID   string `json:"profile_id"`
	KeyID       string `json:"key_id"`
	KeyRevision string `json:"key_revision"`
	Proof       string `json:"proof"`
}

type CPAuthorizationPayload struct {
	Action         string `json:"action"`
	Decision       string `json:"decision"`
	PolicyRevision string `json:"policy_revision"`
	TrustRevision  string `json:"trust_revision"`
}

type RevisionPayload struct {
	Revision          string `json:"revision"`
	Revocation        string `json:"revocation"`
	SubjectEvidenceID string `json:"subject_evidence_id"`
}

type MembershipPayload struct {
	DomainID string `json:"domain_id"`
	Revision string `json:"revision"`
	State    string `json:"state"`
}

type OwnershipPayload struct {
	OwnerID            string `json:"owner_id"`
	OwnershipEpoch     string `json:"ownership_epoch"`
	FenceEpoch         string `json:"fence_epoch"`
	BootID             string `json:"boot_id"`
	ProcessIncarnation string `json:"process_incarnation"`
	State              string `json:"state"`
}

type GenerationPayload struct {
	Generation string `json:"generation"`
	State      string `json:"state"`
}

type BootPayload struct {
	BootID    string `json:"boot_id"`
	ActorID   string `json:"actor_id"`
	ActorRole string `json:"actor_role"`
}

type ProcessPayload struct {
	BootID      string `json:"boot_id"`
	ProcessID   uint64 `json:"process_id"`
	StartTicks  uint64 `json:"start_ticks"`
	Incarnation string `json:"incarnation"`
	ActorID     string `json:"actor_id"`
	ActorRole   string `json:"actor_role"`
}

type PAdmissionPayload struct {
	AdmissionEpoch string `json:"admission_epoch"`
	State          string `json:"state"`
	Consumption    string `json:"consumption"`
	Revocation     string `json:"revocation"`
}

type DrainPayload struct {
	DomainID           string   `json:"domain_id"`
	ResourceIDs        []string `json:"resource_ids"`
	DrainEpoch         string   `json:"drain_epoch"`
	MembershipRevision string   `json:"membership_revision"`
	State              string   `json:"state"`
	Seal               string   `json:"seal,omitempty"`
	CompletionProof    string   `json:"completion_proof,omitempty"`
}

type CandidatePayload struct {
	CandidateID string `json:"candidate_id"`
	Approval    string `json:"approval"`
	Revision    string `json:"revision"`
	ContentHash string `json:"content_hash"`
	ResourceID  string `json:"resource_id"`
	ApproverID  string `json:"approver_id,omitempty"`
}

type BusinessAdmissionPayload struct {
	State             string `json:"state"`
	AuthorityRevision string `json:"authority_revision"`
}

// Envelope is a request-bound P-A read attestation. Policy/Boot/etc records here
// attest a meaningful queried Scope/Execution/Binding/Frame; this is not a generic
// global policy publication, nor does a Host operation need dummy Stream/Run IDs.
// Exactly one payload matching Kind is permitted.
type Envelope struct {
	ProtocolVersion   uint32                    `json:"protocol_version"`
	EvidenceID        string                    `json:"evidence_id"`
	Kind              Kind                      `json:"kind"`
	Issuer            string                    `json:"issuer"`
	Audience          string                    `json:"audience"`
	Scope             Scope                     `json:"scope"`
	Execution         Execution                 `json:"execution"`
	Binding           string                    `json:"binding"`
	Frame             BackendReadFrame          `json:"backend_read_frame"`
	Validity          Validity                  `json:"validity"`
	Integrity         Integrity                 `json:"integrity"`
	CPAuthorization   *CPAuthorizationPayload   `json:"cp_authorization,omitempty"`
	Policy            *RevisionPayload          `json:"policy,omitempty"`
	Trust             *RevisionPayload          `json:"trust,omitempty"`
	Membership        *MembershipPayload        `json:"membership,omitempty"`
	Ownership         *OwnershipPayload         `json:"ownership,omitempty"`
	Fence             *OwnershipPayload         `json:"fence,omitempty"`
	Generation        *GenerationPayload        `json:"generation,omitempty"`
	Boot              *BootPayload              `json:"boot,omitempty"`
	Process           *ProcessPayload           `json:"process,omitempty"`
	PAdmission        *PAdmissionPayload        `json:"p_admission,omitempty"`
	Drain             *DrainPayload             `json:"drain,omitempty"`
	Candidate         *CandidatePayload         `json:"candidate,omitempty"`
	BusinessAdmission *BusinessAdmissionPayload `json:"business_admission,omitempty"`
}

// Error carries fixed classification only. It does not expose payloads, paths,
// raw codec errors, key material, or retry/actuation authority.
type Error struct{ Code string }

func (e *Error) Error() string {
	if e == nil {
		return "v3_evidence_invalid"
	}
	return "v3_evidence_" + e.Code
}
