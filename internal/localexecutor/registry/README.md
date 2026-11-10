# C10 registry read contracts

This package implements the first C10 Go contract boundary, not a SQLite adapter
or an activated Local Executor endpoint. It is not imported by the v2 binaries.

- Strict v3 Request / Binding / Execution identity validation.
- Positive, qualified-negative, UNKNOWN and conflicting receipt validation.
- ReadActiveReference and LookupExecution through mandatory read, current query
  authorization and owner-evidence ports. Query authorization receives the actual
  execution tuple and binding for Lookup/Plan; host-only reads have neither.
- D-01 terminal record descriptions for Executor Ledger, CP result and audit.
- D-02 pure partial-restore reconciliation and record-only repair plans.

No SQLite driver, SQL/DDL, migration, reference mutation, GuardControl, service
apply/reload/restart, filesystem/network adapter, provider or credential is
implemented. Query and reconciliation methods have no writer dependency.

## Binding and request boundary

Binding is the exact internal schema-1 encoding/json representation of the
validated Command, in its declared field order. It is not a hash, signature,
authentication token, or formally selected external wire format. Request binding
does not include itself, delivery metadata or later proof/receipt/ACK evidence.
Strict DecodeRequest rejects unknown/duplicate/missing/wrong-case fields, null,
invalid UTF-8, noninteger unsigned numbers, trailing data and oversized input.
Opaque identifiers are lower-case case-sensitive ASCII; there is no path or
legacy-token compatibility. An execution key is not auto-derived from, or
substituted for, the Operation/Attempt/Step tuple. Global uniqueness requires
the future authoritative store; this package validates correlation only.

## Trust and D1

Ports are trusted deployment boundaries, not public request fields. A nonempty
evidence reference or a fake port returning nil does not establish authenticity.
Verifier implementations must authenticate issuer, audience, scope, backend
durability evidence, current trust and restore continuity. No default allow or
self-asserted freshness/authorization boolean is supplied.

Positive receipts use a historical D1_GUARD_DECISION. Their decision interval,
time base, Boot and required Guard must match the original immutable command;
the upper bound must be within its original deadline. Current wall time is not
used to expire historical read queries. Later commit visibility does not imply D2.

Qualified negative receipts use QUALIFIED_REJECTION: evidence of a serialized
no-additional-effect refusal, never actuation authority. The observed Guard or
Boot may have changed and the refusal may be recorded after the old start
deadline. A trusted verifier must confirm that the refusal did not overwrite a
valid in-flight or committed execution. UNKNOWN cannot be fabricated as negative.
NOT_CHANGED_PROPOSED is supported as a proposal, not product adoption.

## Results and partial restore

Backend outcome, current active reference, Ledger, CP report, audit and report
ACK knowledge are independent. Current-reference equality and NOT_FOUND do not
prove the old operation succeeded, never started, or has an unused grant.
Complete observed snapshot data and active reference values are passed to trusted
verifiers, including projection evidence/coherence, separately from an authenticated
historical Backend receipt. Stale projections must not be surfaced as known.

D-01 describes terminal records for both positive and qualified negative
receipts; it does not persist them. D-02 validates the original request/key/
binding, Backend receipt, matching Witness outcome, current snapshot evidence and
existing projections. Conflicts or unknown evidence stop repair planning.
A missing fresh projection may yield a record-only step; report ACK loss yields
a same-report resend step. Recovered audit records retain UNKNOWN for unavailable
original human audit, without inventing actor or timestamp.

Plans cannot execute. A future record writer must freshly verify each required
record/report capability, expected projection and source evidence. It must not
replay a reference change, consume/reset/reissue an old grant, release unknown
liabilities, notify a provider, reopen admission or change Cover/manual holds.

The existing F5/BND issues and F6-VP-02/05/06, WP-014, related F4 authorization and
F7-OG-03/07 remain tracking references. Unit test success does not certify
SQLite durability, independent Continuity, all-Actor exclusion, production
migration, Phase 1 completion, or formal v2 return.
