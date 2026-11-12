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

Reviewed on 2026-11-12 JST. Selection is for this C10 Read Adapter only;
it does not adopt a production Writer, storage/lock profile or PoC configuration.

| Property | modernc.org/sqlite v1.62.0 | mattn/go-sqlite3 v1.14.53 |
| --- | --- | --- |
| Fixed source commit | d04d243c4dfdb9f9fb19bd1c0c8c37d3923f0589 | 93c7e0a2ec6762a38ab371755d49a2b3f4a12e67 |
| Engine | SQLite 3.54.1 | SQLite 3.54.1 |
| Go module minimum | Go 1.26.0 | Go 1.21 |
| Linux amd64/arm64 | CGo-free generated Go core | CGO and target C toolchain required |
| Existing CGO_ENABLED=0 release | Selected; libc pinned v1.80.1 | !cgo Open is an error stub |
| Native read-only | Internally constructed file: URI mode=ro | Also supports mode=ro with CGO |
| query_only | Connector-local supplementary protection | Same SQLite connection-local constraint |
| Read transaction/snapshot | All queries on one explicit Tx/connection | Same SQLite isolation requirement |
| Busy/locked | No automatic retry; safe unavailable/context error | Same underlying SQLite locking model |
| Cancellation | v1.61.1 lock-wait Commit/Rows fix included | Binding also requires context/lock qualification |
| Maintenance | Latest release only; generated/libc version coupling | Current 1.14.x, additional C toolchain/ABI coupling |
| Driver license | BSD-3-Clause | MIT |
| Bundled engine | SQLite public domain; third-party notices also apply | SQLite public domain; third-party notices also apply |
| Reproduction inputs | Go, checksummed modules, target, flags, generated source | Also CC/CFLAGS/linker/libc/bundled-vs-system SQLite |

The selection follows the actual CGO-free release requirement, not a blanket
claim that generated Go is safer. modernc adds dependencies and generated-source
maintenance; mattn requires a C compiler for each target and fails at runtime
with CGO disabled. Existing cmds do not yet import this package; CI therefore
also compiles the registry test binary for both architectures. ARM64 compilation
is not native ARM64 execution.

Source/binary tracing uses go.mod/go.sum, fixed source commits, Go 1.26.5,
GOOS/GOARCH/CGO, build metadata, runtime sqlite_version/sqlite_source_id and test
binary hashes in CI. The exact SQLite source ID is asserted by tests:
2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76.
A C amalgamation hash, a transpiled Go module hash and a product binary digest
are different evidence. Independent clean-build byte reproducibility and
modernc signed-provenance verification are not demonstrated by these tests.

Security review coverage is PARTIAL: official SQLite CVE/release information,
driver security policies and licenses were read. modernc supports the latest
release only. The mattn repository reports no published repository advisories,
which is not an all-dependency security clearance. modernc's advisory page and
direct GoVuln module endpoints were unavailable; official vulndb import-path
search results are not a complete advisory scan. Dependency-wide reachability
analysis is NOT_RUN. No claim of "no vulnerabilities" is made.

Primary sources:
- https://github.com/modernc-org/sqlite/blob/v1.62.0/go.mod
- https://github.com/modernc-org/sqlite/blob/v1.62.0/CHANGELOG.md
- https://github.com/modernc-org/sqlite/blob/v1.62.0/driver.go
- https://github.com/modernc-org/sqlite/blob/v1.62.0/connector.go
- https://github.com/modernc-org/sqlite/blob/v1.62.0/SECURITY.md
- https://github.com/modernc-org/sqlite/blob/v1.62.0/VERIFYING.md
- https://github.com/modernc-org/sqlite/blob/v1.62.0/SBOM.md
- https://github.com/modernc-org/sqlite/blob/v1.62.0/LICENSE
- https://github.com/mattn/go-sqlite3/blob/v1.14.53/static_mock.go
- https://github.com/mattn/go-sqlite3/releases/tag/v1.14.53
- https://github.com/mattn/go-sqlite3/blob/v1.14.53/LICENSE
- https://www.sqlite.org/releaselog/3_54_1.html
- https://www.sqlite.org/cves.html
- https://www.sqlite.org/uri.html
- https://www.sqlite.org/pragma.html#pragma_query_only
- https://www.sqlite.org/isolation.html
- https://www.sqlite.org/wal.html#read_only_databases

## Schema v2 and explicit migration

Schema v2 is a fresh, unreleased read/projection baseline, with six STRICT tables:
registry_migrations, registry_meta, resources, executions, projections and
reference_transitions. Application ID, user_version, metadata, exact DDL and nine
autoindexes must match. The migration checksum binds the embedded v2 SQL bytes
and migration-ledger definition. Dirty or mismatched ledgers are rejected.

MigrateRegistrySchemaV2ForAdministration is an explicit OFFLINE administration/
test operation. It accepts only an empty DELETE-profile database or validates
an exact clean v2. It first commits a dirty ledger, then commits DDL/metadata and
clean state together. Failure preserves dirty evidence and does not authorize
automatic resume/repair. Runtime Open/Read never migrates, repairs, VACUUMs,
checkpoints, consumes authority or writes state.

The earlier unmerged 0001_initial.sql remains unchanged as historical source.
It is not embedded or applied. Existing v1 or other nonempty DBs are rejected
unmodified; no destructive v1-to-v2 transformation or data deletion is supplied.

The current reference has separately checked revision/state-version columns and
strict typed JSON. Versions use canonical 20-digit decimal uint64 TEXT, avoiding
signed SQLite integer truncation. Positive receipts require one correlated
history row; negative receipts require none. History has per-scope unique
execution/receipt/after-version identities. Receipt validation enforces +1 and
correlation; current reference checks reject rollback behind known history.
A later or ABA reference remains distinct from the historical receipt.
These read checks do not implement a future Writer's CAS/atomic-commit protocol.

## SQLite facts and independent Continuity

ReadExecution reads current reference, immutable execution/receipt, transition
and Ledger/CP/Audit projections inside one explicit SQL read transaction.
Rows absent, malformed or in conflict do not imply NOT_STARTED or unused grants.
JSON decoding is bounded, exact-field and duplicate-aware. BackendReadFrame
contains local observation correlation only; it has no FreshnessProof.

There are no Witness, Outstanding Liability or independent Freshness records
in schema v2. No SQLite-backed Continuity implementation exists here.
A trusted optional ContinuityReadPort receives a deep copy of the entire SQL
observation AFTER the SQL Tx/connection is released. Its Known answer must
qualify that exact frame/payload with complete Witness/Outstanding coverage.
It cannot replace SQL facts, promote malformed SQL, manufacture an old authority
or certify mere generation-string equality. Returned pointers/slices are copied.
The existing Reader/Verifier must still authenticate full payloads, issuer,
scope, audience, trust and restore freshness.

Without independent Continuity, with partial coverage, frame mismatch or an
unavailable/invalid answer, Current is UNKNOWN and no Witness, Outstanding set
or Freshness is asserted. A historical SQL Backend Receipt may remain known,
but aggregate lookup/reconciliation stays UNKNOWN and never yields mutation
permission. Empty Outstanding is only qualified by independent complete coverage.
Test doubles model this seam only; real independent storage and freshness are
NOT_IMPLEMENTED.

## Read-only path, locking and Close qualification

Open accepts trusted installation Directory plus the fixed registry.sqlite3 name.
No external SQL/URI/DSN/path/PRAGMA is exposed. It rejects noncanonical paths,
symlinks, changed inode identities, missing/nonregular files and journal/WAL/SHM
sidecars. Internally generated mode=ro is the native file constraint; per-
connection query_only=1, trusted_schema=0 and defensive mode add checks.
No immutable/nolock/shared-cache shortcut is used.

The initial Read Adapter supports a stable DELETE profile. Even a legitimate
active journal can conservatively block a new read. Busy/Locked/Corrupt errors
become fixed safe error codes; no SQL text, private path or driver error escapes.
There is no automatic retry. Context cancellation is preserved in queries,
pool waits and pre-open checks. sqlite3_open_v2 has no mid-open cancellation
hook; instant interruption of that native open is not promised.

## Registry lifecycle ownership

SQLiteReadPort owns fact mapping and independent Continuity qualification.
Its private registryLifecycleOwner owns the database path/identity, retained
Header FD, process inode lease, read-only connection pool and Close/drain.
A private operation token tracks each public read through Continuity completion.
The owner's beginRead also obtains its own token: an internal transaction cannot
escape drain merely because it did not enter through a public ReadPort method.

sqliteReadTx owns its sql.Conn and operation token. Commit/Rollback complete the
SQL transaction, synchronously release the connection, then release the token
exactly once. A connection-release failure marks owner uncertainty before drain
can finish. Cancellation does not turn an unfinished connection into a free lease.

Close first closes admission, then drains operations/transactions. It closes the
pool, requires zero remaining SQL connections, closes the Header FD, and only
then releases the inode lease. Failed/uncertain resource closure retains a strong
owner reference and the lease. Repeated Close does not retry or assert recovery;
there is no public force-release/resume API. Private nonempty pool/Header resource
interfaces are actual I/O seams used by the owner and synthetic failure tests,
not placeholder Writer interfaces.

On POSIX, closing an unmanaged descriptor may release process SQLite locks.
The owner retains one Header FD for the full pool lifetime. Duplicate/hardlink
owners are rejected before raw Open, including during drain or uncertain Close.
Symlinks are rejected and changed path/inode identities fail closed.
All current connections still use native mode=ro and query_only; this refactor
does not make the pool writable.

Future Writer integration must share this owner's identity, Header FD, lease,
pool ownership, operation tracking and single Close responsibility. It must not
open another Header FD, acquire another lease or independently own a pool for the
same inode. A writable connection-role/profile contract needs separate design
and authorization; it is not implemented here. P-A Mutation and GuardControl
must participate in the same enforced writer boundary, not bypass one another.
No Writer API, writable profile, Mutation or GuardControl is supplied.

Offline migration/administration must not independently open the same inode
while an owner is active or uncertain. Close must be proved complete before
switching to offline administration. These cooperative process-local invariants
do not exclude uncoordinated library handles, management CLI, another process,
Host root, Recovery, Timer or Supervisor. Host-wide Actor closure remains
unproven; the owned directory/profile must not be adversarially replaced.

Tests use only temporary synthetic DBs/processes. Existing read/receipt/schema/
Continuity/cancellation/snapshot tests remain, including separate-process Writer
lock probes. Additional owner tests exercise drain, closing admission, cancellation,
connection-release waiting, inode replacement, failure retention and concurrent
Close. Unit/race/build success does not certify power-loss durability, all-Actor
exclusion, independent Continuity, a real clock, native ARM64 execution, production
migration, Phase 1 closure or formal v2 return.

## Read-only Lifecycle Inspection

InspectLifecycle returns RegistryLifecycleDiagnostic. The private
registryLifecycleSnapshot is separate from that safe projection. Only fixed
enums, counts and qualified booleans are exposed; no path, DSN/URI, SQL, raw error,
credential, internal layout, inode number, FD number or resource pointer escapes.

OPEN means the initialized owner's tracked lifecycle and observed resources are
compatible with admission. It does not mean DB health, business admission, Drain
READY, freshness or P-A/Writer permission. CLOSING is the real Close procedure.
CLOSED requires finished successful Close, confirmed pool/header/lease release,
zero observed pool connections and absent lease. UNCERTAIN comes from a real
owner lifecycle failure and is never cleared by Inspection. Unknown or torn
observations remain UNKNOWN. Zero pool Stats or a closed FD alone is not CLOSED.

ActiveOperations counts all owner borrows, including a public read and its
internal SQL transaction separately. Drain describes these owned borrows only.
AcceptingOperations reports the managed acquire predicate; resource validation
can still fail. Confirmed-release flags describe the owner's Close procedure,
not universal proof that no external Actor holds any handle.

Inspection makes a single sampling pass: copy the owner frame under a short
gate, observe Stats/descriptor/path/lease outside that gate, then check the frame
version once. Any tracked transition yields a fully UNKNOWN result, without
retry. Consistency describes the tracked owner frame, not one globally atomic
snapshot across SQL, OS and lease state. File-system/Stats observations each keep
their own knowledge. Inspection does not acquire an operation or connection,
start a transaction, read SQL, change PRAGMAs, open/close a descriptor, acquire/
release a lease, run Close, repair state or authorize any effect.

Go1.26.5 File.Stat uses an internal descriptor reference. On blocking regular
files, a concurrent Close can return before the last Stat reference drops; that
last drop can perform the physical close after an inode-lease handoff. Inspection
therefore never calls File.Stat or File.Fd. Owner Open captures the header FD once,
before SQLite connections/publication. Linux inspection uses one direct Fstat
syscall with that private number and the cached identity. It cannot schedule a
later Go File.Close. The owner-frame check handles concurrent Close/FD reuse;
after confirmed header release the cached descriptor is never probed. Other
platforms return UNKNOWN for an unavailable live-descriptor guarantee.
Neither probe nor Stats holds the owner gate or acquires a drain borrow. A slow
probe introduces no Close-wait lock; Stats uses only its short database/sql mutex.

The descriptor number and probe seam are private, never an external request or
diagnostic field. Tests use only disposable synthetic resources to inject slow/
failed probes. The production probe is a direct read-only metadata syscall.
Bookkeeping is updated by actual acquire/release/Open/Close transitions; the
inspection path never advances it. No real clock or TTL is selected.

Fixed primary references:
- https://github.com/golang/go/blob/go1.26.5/src/database/sql/sql.go
- https://github.com/golang/go/blob/go1.26.5/src/os/stat_unix.go
- https://github.com/golang/go/blob/go1.26.5/src/internal/poll/fd_unix.go
- https://github.com/golang/go/blob/go1.26.5/src/internal/poll/fd_mutex.go
- https://github.com/golang/go/blob/go1.26.5/src/os/file_unix.go

This API is a diagnostic boundary only. It supplies no Writer, Mutation,
GuardControl, force-release, retry, repair or recovery route. Existing read,
Receipt, Continuity and lifecycle contracts remain unchanged.


## Read connection-role ownership

The current owner implements the Read role only. Each real public-read borrow
and transaction borrow has an immutable private role/kind and a concrete owner
association. A connection is attached to its transaction borrow immediately
after pool acquisition, before BeginTx; the resulting SQL transaction is attached
to that same borrow. Terminal cleanup releases that connection before ending the
borrow. Unknown connection release retains its association and marks the owner
UNCERTAIN before drain accounting can finish. It is never reported as released.

The same mode=ro pool (maximum two connections), Header FD, inode lease and
single Close procedure remain owned once. Concurrent Read transactions are
allowed and continue to validate query_only=1, trusted_schema=0, DELETE journal
mode and the versioned schema in their own snapshot. An operation waiting for a
pool connection is already counted, so Close waits for its unwind too. Close
closes admission first and drains counted work before pool/header/lease release.
No second pool, Header FD or lease is pre-created for a future Writer.

InspectLifecycle adds Roles to its safe projection. Read implementation and
managed Read admission are separate facts. Operations counts both whole-read and
inner transaction borrows; Transactions and Connections count associated handles,
including retained handles whose physical release is unknown.
UnresolvedConnections identifies those retained release obligations. These
counts are distinct from Pool Stats and do not certify live SQL work or locks.
The owner copies scalar role bookkeeping under its short gate; Inspection never
scans/mutates the ownership map or borrows any resource. A torn frame or invalid
role accounting remains UNKNOWN; Inspection never repairs it.

WriteImplementation and MutationImplementation are NOT_IMPLEMENTED;
WriterAdmission is NOT_PROVIDED. There are no fabricated Writer count=0 or
healthy/available Writer states. Rejected Write/unknown-role requests do not open
a connection or change owner state. This private role discrimination is not an
implementation of Write admission, RW exclusion, P-A or GuardControl.

A future writable role must join this same owner's identity/FD/lease/pool
lifecycle and tracked operation/transaction cleanup. Its connection profile,
conflict admission and enforced shared writer boundary must be implemented and
verified before any Write borrow becomes available. P-A and GuardControl must
participate in that same enforced boundary. A role enum/counter does not provide
that exclusion, and current concurrent-Read/external-process lock tests do not
establish shared-owner Read/Write coexistence. No unused Writer interface or
speculative RW lock is provided here. Inspection remains diagnostic only, never
a Writer/Mutation permission or Domain Drain READY proof.

Tests use only synthetic temporary databases. Host-wide Actor exclusion,
power-loss durability, independent Continuity, real clocks and native ARM64
execution remain unproven. Product-wide acceptance remains NOT_RUN, production
migration is unauthorized and formal v2 return is NOT_CERTIFIED.

Current admission matrix: Read/Read is allowed within the existing pool limit;
Read/Write and Write/Write cannot occur through this owner because every Write
request is rejected before resource acquisition, even while idle. Close blocks
all new Read borrows. No actual managed Read/Write concurrency is certified.

The conservative contract for a future initial Writer integration is owner-wide
exclusive admission against Read connection/transaction ownership and unresolved
releases, plus serialized P-A/GuardControl writes through the same enforced
boundary. Read admission must not overlap an active or uncertain write duty.
No such writable admission, reservation or OS/SQL writer mechanism exists here;
enabling it requires its own implementation and concurrent snapshot tests.
Existing snapshot transactions still span every table read by one Read API.

A connection returned after waiting in the pool is checked for actual owner
uncertainty before BeginTx. Previously admitted Reads may still race a later
uncertainty transition; they are drained rather than pretending SQL start and
Owner state are one atomic operation. The gate is never held across SQL I/O.
Drain COMPLETE means counted borrows ended and can coexist with UNCERTAIN and
unresolved connection ownership; it is not confirmed resource release.

Ownership associations are established by the private beginRead construction,
not by introspecting arbitrary sql.Conn/sql.Tx handles. Uncoordinated
package-internal/raw handles and external Actors are outside this cooperative
boundary. Inspection neither certifies those Actors nor repairs their effects.

## Opt-in Writer Connection Profile and Admission

This section refines the earlier Read-only baseline for explicitly configured
owners. Opening SQLiteReadPort still installs only the Read role; neither the
public Read APIs nor Inspection installs a Writer profile. An explicit private
prepareWriterProfile operation is required before internal Writer admission.
The earlier WriteImplementation/WriterAdmission diagnostic fields describe
participation installed on this particular Owner, not support compiled into the
binary: an unconfigured Read-only owner retains NOT_IMPLEMENTED/NOT_PROVIDED.
The new Write.ProfileImplementation field reports compiled profile support,
independently from the per-owner installation fields. Write.Profile separately
states NOT_CONFIGURED or CONFIGURED. Neither means authorization for P-A.

One lifecycle owner retains one identity, Header FD and inode lease. It owns
both fixed connection-role pool lifecycles. The existing Read connector remains
mode=ro/query_only=1/trusted_schema=0, max two connections. The Writer connector
is created lazily by the same Owner after explicit admission, with mode=rw,
query_only=0, trusted_schema=0, defensive mode and immediate transaction mode,
max one connection. It never creates the database and never turns a borrowed
Read connection writable. Separate fixed connectors are needed to preserve
SQLite's native read-only open mode; they are not independent adapter ownership
or independent Close responsibilities. No additional raw Header FD or lease is
opened. Both actual pools must be confirmed closed/empty before Header/lease
release. A profile can be configured without a physical Writer pool yet existing.

Admission is deliberately conservative and fail-fast across the entire owned
registry inode, stronger than a per-Resource conflict check. A Writer requires no
active Read or Writer borrow; while a Writer borrow exists, new Read and Writer
borrows are rejected. Multiple Reads remain allowed. The decision and counted
borrow registration occur under the existing short Owner gate. There is no
queued Writer, hidden retry, fairness guarantee or mutex held across SQL I/O.
Rejecting contention avoids an outer-public-Read/inner-transaction/queued-Writer
deadlock. Close first closes admission, then drains all accepted role borrows.

Admission, connection acquisition, SQL transaction lifetime and terminal resource
return are distinct. A pending acquisition is already an Owner drain duty.
Connection and transaction associations use the same Owner's tracked maps.
BEGIN IMMEDIATE reserves SQLite's writer position early; it does not exclude
external readers or establish Host-wide Actor closure. External readers may
still block COMMIT. Existing DELETE journal mode and role settings are validated;
no runtime migration, journal-mode conversion, checkpoint, VACUUM or repair is
performed. No caller supplies DSN, arbitrary path, PRAGMA or SQL.

The private Writer transaction does not embed sql.Tx or expose a raw SQL API.
Product code receives only the internal transaction-lifecycle foundation; tests
can access private handles solely for temporary synthetic fixtures. Commit
success concerns the SQL transaction only, never P-A reference activation,
Receipt durability, service apply or business authorization. A nonnil Commit
result remains UNKNOWN conservatively. The pinned driver may attempt rollback
on Commit error without reporting that rollback's result; returning a connection
to its pool cannot prove the ambiguous outcome. Unknown transaction/connection
duties retain their handles, mark UNCERTAIN before counted work ends, and prevent
resource release or automatic reuse/retry. Context cancellation does not promote
uncertain cleanup to known rollback. Repeated terminal calls never replay SQL.

InspectLifecycle remains one read-only sampling pass. Its short gate only copies
scalar Writer bookkeeping and pool references; Writer Stats are observed outside
the gate and the frame version is checked once. No SQL, transaction, connection
borrow, FD/lease action, Close, retry, repair or configuration change occurs.
Pool continues to describe the Read pool; Roles.Write.Pool describes the actual
Writer pool if created. PoolCreated disambiguates an absent pool from one whose
release is unconfirmed. Writer counts are asserted only on an explicitly
configured owner and include retained handles with unknown release. They do not
assert currently live SQL work or locks. UnknownOutcomes tracks unresolved
transaction outcomes separately. Drain COMPLETE can coexist with UNCERTAIN;
it means counted borrows ended, not that retained resources were released.

Roles.WriterAdmission=PROVIDED means an internal admission path is installed.
Roles.Write.Admission reports its current local conflict predicate. Neither
means CP authorization, Drain READY, final Fence or P-A permission. Mutation,
GuardControl and Independent Continuity remain NOT_IMPLEMENTED. Injecting a
ContinuityReadPort test/read dependency does not implement an independent Store.

Pinned implementation references:
- https://github.com/modernc-org/sqlite/blob/v1.62.0/connector.go
- https://github.com/modernc-org/sqlite/blob/v1.62.0/tx.go
- https://github.com/modernc-org/sqlite/blob/v1.62.0/sqlite.go
- https://github.com/golang/go/blob/go1.26.5/src/database/sql/sql.go

Only temporary synthetic databases/processes may be used by these tests.
P-A Mutation, GuardControl, independent Continuity/Witness storage, CP/UDS/real
Verifier integration, service/media/provider actions and deployment are absent.
Power-loss durability, Host-wide Actor exclusion, independent restore freshness,
real clocks and native ARM64 execution remain unproven. Product-wide acceptance
is NOT_RUN, Phase 1 closure is on hold, production migration is unauthorized and
formal v2 return is NOT_CERTIFIED. Preservation/manual-hold/old-authority-nonreuse
and UNKNOWN/HELD constraints remain unchanged.

The installed Writer profile does not adopt a storage durability target, a clock,
TTL or retry budget. Physical SQLite open may be non-cancellable once the pinned
driver enters sqlite3_open_v2; the counted borrow still prevents Close from
releasing resources while that call is unresolved. Cancellation before Begin is
separate from cancellation after an accepted transaction. The latter remains
UNKNOWN until independently reconciled; no reconciliation or force-release API
is supplied by this increment.

The transaction context controls local SQL I/O/cancellation; it is not the
adopted P-A D1 guard-decision deadline. No D1, Drain Proof, final Fence, business
authorization, execution binding or durable Backend Receipt is implemented by
beginWrite/Commit. A future typed conditional commit must keep those contracts
separate; a context deadline is not proof that the D1 decision occurred and is
not a substitute for D1's allowance for a later commit in the same transaction.
