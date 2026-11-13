# Contracts-owned Canonical Request adapter

The product Request/Command acceptance predicate, strict wire decoder and literal
Binding generation now belong to reviewed Contracts commit
790be850e98c06119330907a8fc2ae091e2bdc85, module version
v0.0.0-20261113091349-790be850e98c. Request Schema1, Binding Profile1 and Evidence
Protocol3 remain separate domains. No local replacement, hash, prefix, new wire
field, normalization or schema/record migration is introduced.

C10 public ID/Binding/Command/Request types and function signatures are unchanged.
sharedCommand and registryCommand explicitly convert all fields without narrowing
uint64. Scope/Execution scalar identities, RequestingPrincipal/AuthorizationIssuer,
Candidate revision/content pin, Expected revision/state version, all eight Guard
fields, Timing/time base/deadline and OriginalBudget are preserved.

CanonicalBinding calls shared ComputeBinding. validateCommand and ValidateRequest
call shared validation. DecodeRequest calls shared DecodeRequest and constructs a
C10 Request ONLY after shared success. C10's old strictRequestValue walker and
json.Marshal canonical encoder are removed. Generic persisted Record codecs and
standalone ValidateScope/ValidateExecution/validateID callers retain their separate
responsibilities; their existence is not an alternate Request acceptance path.

## Error compatibility

| Boundary | C10 result |
|---|---|
| Typed invalid Command | INVALID; rejection-only diagnostics retain old known field names |
| Empty/over-64KiB/invalid-UTF8 typed Binding | INVALID / request.binding |
| Valid Command plus well-formed nonempty mismatching Binding | BINDING_CONFLICT / request.binding |
| Shared wire decoder reports request_binding | Bounded Binding extraction selects only those two legacy rejection classes |
| Structural wire rejection | INVALID / request.json |
| Wire request_version / request_operation | INVALID / command.schema or command.operation |
| Unrecognized/non-contract diagnostic error | INVALID; never success |

Error matching uses errors.As and structured Code values. The diagnostic JSON
extractor is reachable only after the shared decoder has rejected request_binding.
It never returns a successful Request, repairs a Binding, re-encodes to accept,
or overrides a structural/unknown rejection. Command field diagnostics likewise
run only after shared rejection and always return an error. Error.Field is not a
production branching predicate; C10 readers/Preflight still branch on Code.

The shared strict walker refuses U+FFFD/lone-surrogate strings during structural
decoding. Such corrupt wire Bindings are therefore INVALID/request.json rather
than the old decoder's later BINDING_CONFLICT. The same typed valid-UTF8 mismatch
still retains the old conflict class. Wire semantic identity/number errors can
also report request.json rather than an old detailed field. These are rejected
inputs only: no formerly rejected input is promoted to success, and no valid
stored Request/Binding needs rewriting. The adapter deliberately does not use
forbidden diagnostic parsing on non-request_binding errors to hide this boundary.

## Evidence and limits

New tests compare fixed old bytes/golden or an actual pinned old checkout rather
than deriving both sides from the shared function. CI exports a synthetic SQLite
fixture from the pinned pre-adapter C10, then reads its actual records with the
candidate without schema migration or Binding rewrite. The candidate also exports
its own Request to a disposable fixed CP checkout at
d8ff3362ab29780a9fe605eb260b13293d09abe9, runs the PRODUCT Canonical Resolver and
Service, and imports/verifies returned original Envelope bytes with candidate C10.
Remaining issuer/Integrity/time/applicability/Continuity collaborators are explicit
test doubles; these tests do not enable real evidence issuance.

Existing SourceBoundary, Guard13 Kind/full-payload/original-bytes, Reader,
reconciliation and Preflight tests remain unchanged. CI extends its SQLite-only
CGO-free/Race selection to cover CanonicalAdapter and Validation tests. The pinned
module check retains the complete reviewed Go-file allowlist and blob checks,
including request.go/request_test.go and updated codec.go. v2 require/replace and
all unrelated dependencies/workflows are preserved.

CP management/provisioning/bootstrap, real keys/signature/clock/TTL/skew,
revocation, independent Continuity, production delivery and Mutation/Consume/
GuardControl remain separate/unconnected. The CP product implementation exists
in its owning PR but real issuance remains disabled. No production DB/Host/
Credential/Provider/media/backup/restore/service/deploy operation is performed.
Native arm64 runtime and product-wide acceptance are not certified by cross-build.

Full PRESERVE; no old execution-authority reuse; manual automatic-start hold and
UNKNOWN/HELD non-success remain. Product-wide acceptance NOT_RUN; Phase1 closure
on hold; production migration unauthorized; formal v2 return NOT_CERTIFIED.
