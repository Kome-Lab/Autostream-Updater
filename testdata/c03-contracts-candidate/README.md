# UNAPPLIED C03 / Contracts evidence implementation candidate

Status: REVIEW_REQUIRED / NOT_APPLIED_TO_PRODUCT / CONTRACTS_PUBLICATION_BLOCKED.
This directory is a reviewable implementation proposal, not a product wire
authority, fallback module, deployed producer, signed credential or live data.

The canonical target owner remains Kome-Lab/Autostream-Contracts. Automatic
approval review rejected creating a persistent v3-dev branch in that separate
repository because the explicit repository scope was Autostream-Updater.
No Contracts branch/PR was created. Do not publish this proposal, require an
unreferenced Contracts commit, or install it into the product until the separate
repository write scope is explicitly authorized.

## Layout and validation boundary

- contracts/v3evidence: proposed independently versioned Go module owned by
  Contracts; Protocol3 Envelope, discriminated typed payloads, strict Codec and
  synthetic contract tests. Its module path is a PROPOSED target, not published.
- updater/guard_contracts.go: proposed C10 source/authenticator bridge.
- updater/guard_contracts_test.go: synthetic C10 interoperability tests.
- updater/guard_evidence.patch: proposed raw-envelope preservation/deep-clone
  addition to the existing GuardEvidenceBundle. It is NOT applied to product.
- scripts/ci/verify-c03-evidence-candidate.sh (repository root): builds a disposable
  git archive under RUNNER_TEMP; applies only the candidate overlay there; adds a
  local module replacement only to that copied go.mod; tests and cross-builds.
  The actual product go.mod/go.sum/internal sources must remain unchanged.

Normal Go package discovery does not include this testdata directory. The
v3-go-checks workflow explicitly runs candidate verification. A separate temporary
formatting/scoped workflow, when present during preparation, is removed before
the final required check. Candidate PASS is not product publication or an actual
CP/Agent/Executor evidence path.

## Source ownership and availability

Source investigation is fixed to Updater
5b3d18cf68e732c66453242f545e1e22be41bc0f; Contracts
2235c0da353922f322d4b02d824a51e07400027a; prior CP investigation
65a601fc9d4f15c93083e9be4ab9e71586fdba69.
The component labels below follow the supplied CP/Agent/Executor responsibility
model. No live-host observation or deployed/source identity match is implied.

| Kind | Existing owner/path | Current v3 availability |
| --- | --- | --- |
| CP Authorization | CP v2 lease/grant; internal/controlplane/client.go Claim/IssueMutationGrant/ConsumeMutationGrant | v2 only; no v3 CP producer/read endpoint |
| Policy | CP policy to Agent to Executor root projection | v2 only; no v3 effective/revocation barrier evidence |
| Trust | Current C10 Guard claim | Contract/test double only; actual manager not connected |
| Domain Membership | Current C10 Guard claim | Contract/test double only; actual Domain producer absent |
| Ownership | CP v2 Host ownership | v2 only; no v3 scoped producer |
| Fence | CP v2 epoch / Executor policy matching | v2 only; no v3 old-owner exclusion evidence |
| Boot | C10 fixed Linux OS reader | Raw facts implemented; no remote attestation or clock authority |
| Process | C10 raw PID/start ticks plus opaque incarnation claim | Raw facts implemented; authenticated v3 association absent |
| P-Admission | C10 Guard condition | Contract/test double only; producer absent |
| Drain READY | C10 Guard condition/Seal | Contract/test double only; closure/completion producer absent |
| Candidate | Request revision/content pin and C10 condition | Actual Candidate approval/store producer absent |
| Business Admission | C10 B/P/D-separated claim | Contract/test double only; CP business state is not automatically v3 evidence |

Relevant fixed source: Contracts pkg/contracts/types_updater_protocol.go:18-49
has only the v2 operation union. CP internal/httpapi/system_update_v2_adapter.go:90,
system_update_v2_grants.go:14/111 and server_routes_updater.go:3-25 own the legacy
issue/consume path. Updater docs/contracts-boundary.md:3-4 keeps wire ownership in
Contracts; local_executor_server_linux.go:240/339 authenticates UDS peers, not CP
business authorization. The earlier Registry README contains the detailed source
function/line survey. None of those v2 credentials, policies or operations are
converted/re-signed/reused by this candidate. Grant issue/consume is not read-only.

## Proposed envelope contract

Every envelope is a request-bound P-A read-attestation: ProtocolVersion,
EvidenceID/Kind, configured Issuer/Audience, exact Scope/Execution/Binding and
BackendReadFrame, issuer Validity, opaque Integrity profile/key/revision/proof,
and exactly one Kind-specific payload. No dummy Stream/Run identity is added.
Policy/Trust/epochs/Boot/process fields are required only in their applicable
payloads. This profile is not a global policy publication API.

Payloads cover CP action/decision and Policy/Trust revisions; Policy/Trust
revocation and CP evidence correlation; Domain membership; owner/fence/Boot and
incarnation; raw OS facts plus actor role; P-Admission epoch/consumption/revocation;
Drain closure/epoch/READY/Seal/completion; Candidate approval/revision/content/
resource/approver; and independent Business Admission OPEN/CLOSED/UNKNOWN.

Strict Decode rejects unknown Version/Kind, duplicate/escaped-alias/case-mismatched
keys, extra/missing/null fields, invalid UTF-8, trailing JSON, invalid integer
syntax/overflow, payload mismatch and excess size/depth. Encode validates first.
Clone detaches payloads, time points and arrays. Transport serialization is NOT
a selected signature canonicalization.

SPECIFIED validity is a claim, not clock trust. UNKNOWN validity/revocation and
Business Admission can be transported honestly but cannot qualify execution.
The proof string and EvidenceID alone never authenticate anything.

## Candidate C10 connection and verification

The bridge consumes the Contracts candidate package directly. It pins source
Scope/Audience/13 issuers in trusted construction, not Request-supplied URLs,
paths, SQL or owner selection. Exactly one envelope per Kind and unique
EvidenceIDs are required. CP/Policy/Trust anchor, Membership/Drain, owner/fence/
Boot/process, generation/frame and Candidate content are correlated.

Original bytes remain attached to the proposed bundle. Projection IDs are only
correlation references. The authenticator reconstructs the entire mapped bundle
from those bytes and requires three independent trusted hooks: complete original
payload Integrity/Issuer/Audience/key verification, current Validity/clock trust,
and current revocation/effective owner/Policy/Trust/Admission/Drain/Candidate
verification. These hooks have no successful default.

No signature/MAC algorithm, key product, Token format, TTL/skew or clock is
adopted. KeyID/revision and profile are opaque verification inputs; current key
rotation/revocation must be proven by the future verifier. Issuance/expiry are
separate from D1 guarded decision, Backend commit and Context cancellation.
Context Deadline cannot substitute for any evidence clock or D1 decision.

The Agent delivery interface transports detached bytes and cannot expand
authorization. Missing producer/delivery/verifier/clock or incomplete evidence
remains UNKNOWN. Guard is not independent Continuity; existing Witness,
Outstanding Liability and restore-freshness checks remain separate. B=CLOSED can
coexist with valid P and D; no reopen/hold/Cover operation is performed.

## Evidence and next step

All tests use temporary synthetic DBs/evidence/clock/verifier/producer/local-OS
doubles. A candidate interoperability ELIGIBLE observation is not a real CP
producer, cryptographic verifier, qualified clock or production permission.
Actual C10 runtime remains unchanged while publication is blocked.

The next required authorization is limited to Contracts repository v3-dev/work
branch and an unmerged PR for these exact canonical module changes. After that,
the canonical commit can be pinned as a separate module without upgrading the
legacy v2 replacement, and the reviewed C10 bridge can be applied normally.
That authorization would still not approve real keys, real CP business logic,
P-A mutation, GuardControl, production or merging.

Reference/Receipt/History mutation, real Continuity Store, service apply, Media/
Provider, host/DB/credential/backup/restore/deploy remain absent. Preserve media,
old history and manual auto-start hold; do not reuse old execution authority.
Product-wide acceptance NOT_RUN; Phase1 closure on hold; production migration
unauthorized; formal v2 return NOT_CERTIFIED. Power-loss durability, all-Actor
exclusion, independent Continuity, real clocks and ARM64 native remain unproven.
