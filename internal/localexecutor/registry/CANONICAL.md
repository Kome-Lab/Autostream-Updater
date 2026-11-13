# Contracts-owned Canonical Request adapter

The product Request/Command acceptance predicate, strict wire decoder and literal
Binding generation now belong to reviewed Contracts commit
45aaa9932bcd92c728c86c95349853724fe1accc, module version
v0.0.0-20261113172311-45aaa9932bcd. Request Schema1, Binding Profile1 and Evidence
Protocol3 remain separate domains. No local replacement, hash, prefix, new wire
field, normalization or schema/record migration is introduced.

C10 public ID/Binding/Command/Request types and function signatures are unchanged.
sharedCommand and registryCommand explicitly convert all fields without narrowing
uint64. Scope/Execution scalar identities, RequestingPrincipal/AuthorizationIssuer,
Candidate revision/content pin, Expected revision/state version, all eight Guard
fields, Timing/time base/deadline and OriginalBudget are preserved.

CanonicalBinding calls shared ComputeBinding. validateCommand and ValidateRequest
call shared validation. DecodeRequest calls shared DecodeRequestWithDiagnostic
and constructs a
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
| Shared diagnostic confirms BindingInvalid / BindingConflict | INVALID / BINDING_CONFLICT with request.binding |
| Invalid/unknown/contradictory shared diagnostic | INVALID / request.json |
| Wire request_version / request_operation | INVALID / command.schema or command.operation |
| Unrecognized/non-contract diagnostic error | INVALID; never success |

Error matching uses errors.As and structured Code plus the new fixed
RequestDiagnostic enum. C10 performs no wire reparse. Only shared
DecodeRequestWithDiagnostic success and None can reach registryCommand.
Unknown/non-contract errors, unknown enums and contradictory diagnostics remain
INVALID; metadata cannot construct/repair a Request or authorize/retry.

Contracts completes the entire closed shape and trailing check, validates the
Command, then classifies Binding. U+FFFD and unpaired-surrogate wire Bindings
still fail the original shared DecodeRequest with its unchanged encoding error.
For a valid Command, the additional diagnostic restores C10's old
BINDING_CONFLICT/request.binding and real CheckEncoded CONFLICT. A later unknown,
duplicate, missing field, malformed number or invalid Command instead remains
INVALID/REJECTED, including Binding-first inputs. Raw invalid UTF-8 is INVALID.

Necessary Error.Field compatibility includes request.binding for empty/mismatch/
Unicode Binding and the existing typed Command and known wire version/operation
mappings. No production caller branches on Field; Error() includes it as
diagnostic text. This increment does not require every historical Field string.
In the fixed 214-observation corpus, Code/real CheckEncoded Status/normal bytes
match old 6f71 completely; 48 compound-invalid cases retain request.json rather
than old scope.realm, command.schema, command.operation,
command.expected.state_version or command.timing.deadline_tick. Those are the
four Unicode forms in both field orders combined with identity/Unicode-identity,
Schema, Operation, MaxUint64 StateVersion or zero DeadlineTick. All remain
INVALID/REJECTED. CI prints these field-only residuals explicitly.

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
