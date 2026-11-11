# C10 registry read contracts

This package implements C10 registry read contracts and a SQLite ReadPort.
It is not an activated Local Executor endpoint or imported by the v2 binaries.

- Strict v3 Request / Binding / Execution identity validation.
- Positive, qualified-negative, UNKNOWN and conflicting receipt validation.
- ReadActiveReference and LookupExecution through mandatory read, current query
  authorization and owner-evidence ports. Query authorization receives the actual
  execution tuple and binding for Lookup/Plan; host-only reads have neither.
- D-01 terminal record descriptions for Executor Ledger, CP result and audit.
- D-02 pure partial-restore reconciliation and record-only repair plans.

The SQLite ReadPort uses database/sql and a versioned initial schema. The only
migration is an explicitly called administration/test operation; opening/reading
never migrates, repairs, VACUUMs, checkpoints or writes persistent state.
Reference mutation, GuardControl, service apply/reload/restart, CP/UDS, providers
and credentials remain unimplemented. Reader semantics and mandatory proof ports
are unchanged.

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


## SQLite driver selection

| Property | modernc.org/sqlite v1.62.0 | mattn/go-sqlite3 v1.14.53 |
| --- | --- | --- |
| Engine | SQLite 3.54.1 | SQLite 3.54.1 |
| Go module minimum | Go 1.26.0 | Go 1.21 |
| Linux amd64/arm64 | CGo-free generated Go core | Requires CGO and target C compiler |
| Current CGO_ENABLED=0 release | Selected; libc pinned v1.80.1 | !cgo Open is an error stub |
| Read-only | Internally constructed file: URI mode=ro | Also supports mode=ro with CGO |
| Maintenance cost | Additional exact generated/libc dependencies | C ABI/compiler/cross-toolchain dependencies |

This selection is for the Read Adapter, not a global Storage/Lock/Writer policy.
The libc version must match the selected driver's go.mod. Necessary x/sys,
x/mod and x/sync versions follow Go's selected dependency graph.
The current release script builds both existing cmds with CGO_ENABLED=0 on
linux/amd64 and linux/arm64. CI also compiles the registry test binary on both
architectures, because existing cmds do not yet import this package. ARM64
cross-compilation is not native ARM64 test execution.

Primary sources:
- https://github.com/modernc-org/sqlite/blob/v1.62.0/go.mod
- https://github.com/modernc-org/sqlite/blob/v1.62.0/CHANGELOG.md
- https://github.com/modernc-org/sqlite/blob/v1.62.0/driver.go
- https://github.com/modernc-org/sqlite/blob/v1.62.0/connector.go
- https://github.com/mattn/go-sqlite3/blob/v1.14.53/static_mock.go
- https://www.sqlite.org/isolation.html
- https://www.sqlite.org/wal.html#read_only_databases

## Schema and runtime boundary

Schema v1 uses Application ID 0x41535633, PRAGMA user_version, registry_meta and
the exact six-table manifest: resources, executions, projections, witnesses,
liabilities and registry_meta. Composite PK/UNIQUE/FK definitions are checked.
The embedded sqlite_migrations/0001_initial.sql is applied only by
MigrateRegistrySchemaV1ForAdministration to an empty database, in one transaction.
An already compatible v1 is validated; unknown/nonempty versions are rejected.
This v1 is the initial read/projection format, not a complete future Writer schema.

All ReadExecution queries share one explicit read transaction: current reference,
immutable execution/receipt, Ledger/CP/Audit projections, Witness projection and
outstanding liabilities. Missing, malformed and conflicting records are distinct;
absence is never a NOT_STARTED or unused-grant proof. JSON decoding is bounded,
exact-field and duplicate-aware. Current evidence references are copied from the
stored observation frame, never minted by the adapter. Local CP/Ledger/Witness
rows are projections; collocation does not implement independent Continuity or
authenticate an outcome. Existing Reader authorization and Verifier remain required.

Open accepts trusted installation Directory plus the fixed registry.sqlite3 name.
No request-supplied arbitrary path/URI/DSN/SQL/PRAGMA is exposed. It rejects
noncanonical paths, symlinks, changed inode identities, nonregular/missing files
and journal/WAL/SHM files. URI mode=ro is the native read-only constraint;
connection-local query_only=1, trusted_schema=0 and defensive mode add checks.
A plain filename with ?mode=ro is deliberately not used, nor immutable/nolock.

The initial adapter supports only a stable DELETE/rollback-journal profile.
This avoids WAL index/shared-memory creation and hot-journal recovery. Even an
active legitimate DELETE writer journal may conservatively block a new read;
retry is not automatic. The managed directory, path identity and profile must
not be adversarially renamed or changed while open. This is not a hostile-file
sandbox or protection against Host root.

## File-descriptor and Close qualification

On POSIX, closing any unmanaged descriptor for the database can release the
process's SQLite locks. Header inspection therefore retains its descriptor
throughout the owned SQL pool lifetime, instead of opening/closing it per read.
A process-wide inode lease rejects another Adapter (including hardlink aliases)
before opening any raw descriptor. Public reads are drained before closing SQL
connections, then the header descriptor and ownership lease. Uncertain cleanup
keeps ownership held rather than requalifying an UNKNOWN resource.

This initial Read Adapter requires exclusive process ownership of the database
inode: no separate SQLite/raw-file users may bypass the owner. External-process
SQLite writers can participate through normal SQLite locking; tests use a
separate process. A future same-process Writer must share a coordinated owner
lifecycle or introduce a separately verified design. Unknown third-party handles,
Host-root bypasses and real deployment closure are not certified by unit tests.

Context cancellation is retained during queries/pool waits and pre-open checks.
The driver's sqlite3_open_v2 call itself has no mid-open cancellation hook;
instant interruption of that native open is not promised. Close is idempotent
and prevents new reads. No migration/maintenance is hidden in Close.
