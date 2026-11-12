package registry

import (
    "bytes"
    "context"
    "crypto/sha256"
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "math"
    "os"
    "reflect"
    "strconv"
    "strings"
    "sync"
    "testing"
    "time"
)

// This per-fixture registry models trusted test-issued attestations over complete
// payloads. A nonempty string alone is never sufficient. It is not a signature
// scheme, production Verifier, independent Store or real freshness authority.
type sqlitePreflightAttestations struct {
    mu sync.Mutex
    next uint64
    payloads map[ID][]byte
}

func (a *sqlitePreflightAttestations) attest(value any) ID {
    encoded, err := json.Marshal(value)
    if err != nil { return "" }
    a.mu.Lock()
    defer a.mu.Unlock()
    a.next++
    if a.payloads == nil { a.payloads = make(map[ID][]byte) }
    id := ID("synthetic-proof-" + strconv.FormatUint(a.next, 10))
    a.payloads[id] = append([]byte(nil), encoded...)
    return id
}

func (a *sqlitePreflightAttestations) verifies(id ID, value any) bool {
    encoded, err := json.Marshal(value)
    if err != nil { return false }
    a.mu.Lock()
    defer a.mu.Unlock()
    saved, issued := a.payloads[id]
    return issued && bytes.Equal(saved, encoded)
}

func sqlitePreflightGuardPayload(request Request, frame BackendReadFrame, observed PreflightGuardObservation) any {
    observed.Proof = ""
    return struct { Request Request; Frame BackendReadFrame; Observation PreflightGuardObservation }{request, frame, observed}
}

func sqlitePreflightContinuityPayload(request Request, frame BackendReadFrame, snapshot PreflightSnapshot, observed PreflightContinuityObservation) any {
    observed.Proof = ""
    return struct { Request Request; Frame BackendReadFrame; Snapshot PreflightSnapshot; Observation PreflightContinuityObservation }{request, frame, snapshot, observed}
}

type sqlitePreflightGuard struct {
    attestations *sqlitePreflightAttestations
    change func(*PreflightGuardObservation)
    afterAttest func(*PreflightGuardObservation)
    onObserve func(context.Context) error
    err error
    calls int
}

func (g *sqlitePreflightGuard) ObservePreflight(ctx context.Context, request Request, frame BackendReadFrame) (PreflightGuardObservation, error) {
    g.calls++
    if g.onObserve != nil { if err := g.onObserve(ctx); err != nil { return PreflightGuardObservation{}, err } }
    if g.err != nil { return PreflightGuardObservation{}, g.err }
    observed := PreflightGuardObservation{
        Knowledge: Known, Scope: request.Command.Scope, Execution: request.Command.Execution,
        Binding: request.Binding, Frame: frame, Current: request.Command.RequiredGuard,
        CPAuthorization: PreflightConditionValid, Policy: PreflightConditionValid,
        Trust: PreflightConditionValid, Membership: PreflightConditionValid,
        Ownership: PreflightConditionValid, Fence: PreflightConditionValid,
        Boot: PreflightConditionValid, Process: PreflightConditionValid,
        PAdmission: PreflightConditionValid, Candidate: PreflightConditionValid,
        BusinessAdmission: PreflightBusinessClosed, Drain: PreflightDrainReady,
        DrainSeal: "drain-proof",
    }
    if g.change != nil { g.change(&observed) }
    missingProof := observed.Proof == "missing-proof"
    observed.Proof = g.attestations.attest(sqlitePreflightGuardPayload(request, frame, observed))
    if missingProof { observed.Proof = "" }
    if g.afterAttest != nil { g.afterAttest(&observed) }
    return observed, nil
}

type sqlitePreflightContinuity struct {
    *sqliteTestContinuity
    attestations *sqlitePreflightAttestations
    baseline Reference
    change func(*PreflightContinuityObservation)
    afterAttest func(*PreflightContinuityObservation)
    err error
    calls int
}

func (c *sqlitePreflightContinuity) QualifyPreflight(ctx context.Context, request Request, frame BackendReadFrame, snapshot PreflightSnapshot) (PreflightContinuityObservation, error) {
    c.calls++
    if err := ctx.Err(); err != nil { return PreflightContinuityObservation{}, err }
    if c.err != nil { return PreflightContinuityObservation{}, c.err }
    baseline := c.baseline
    observed := PreflightContinuityObservation{
        Knowledge: Known, Scope: request.Command.Scope, Execution: request.Command.Execution,
        Binding: request.Binding, Frame: frame, Evidence: sqliteTestEvidence(frame),
        ContinuityIssuer: "independent-test-authority",
        WitnessCoverage: Known, OutstandingCoverage: Known, HistoryCoverage: Known,
        IdentityCoverage: Known, FreshnessCoverage: Known, HistoryBaseline: &baseline,
    }
    if c.change != nil { c.change(&observed) }
    missingProof := observed.Proof == "missing-proof"
    observed.Proof = c.attestations.attest(sqlitePreflightContinuityPayload(request, frame, snapshot, observed))
    if missingProof { observed.Proof = "" }
    if c.afterAttest != nil { c.afterAttest(&observed) }
    return observed, nil
}

type sqlitePreflightVerifier struct {
    readTestVerifier
    attestations *sqlitePreflightAttestations
    receipts map[ID]Receipt
    guardErr error
    continuityErr error
    receiptErr error
    witnessErr error
    guardChecks int
    continuityChecks int
    receiptChecks int
    witnessChecks int
}

func (v *sqlitePreflightVerifier) VerifyPreflightGuard(_ context.Context, request Request, snapshot PreflightSnapshot, observed PreflightGuardObservation) error {
    v.guardChecks++
    if v.guardErr != nil { return v.guardErr }
    if !v.attestations.verifies(observed.Proof, sqlitePreflightGuardPayload(request, sqliteFrameFromEvidence(snapshot.Snapshot.Evidence), observed)) {
        return errors.New("synthetic Guard payload is not authenticated")
    }
    return nil
}

func (v *sqlitePreflightVerifier) VerifyPreflightContinuity(_ context.Context, request Request, snapshot PreflightSnapshot, observed PreflightContinuityObservation) error {
    v.continuityChecks++
    if v.continuityErr != nil { return v.continuityErr }
    if !v.attestations.verifies(observed.Proof, sqlitePreflightContinuityPayload(request, sqliteFrameFromEvidence(snapshot.Snapshot.Evidence), snapshot, observed)) {
        return errors.New("synthetic Continuity payload is not authenticated")
    }
    return nil
}

func (v *sqlitePreflightVerifier) VerifyReceipt(_ context.Context, request Request, receipt Receipt) error {
    v.receiptChecks++
    if v.receiptErr != nil { return v.receiptErr }
    expected, known := v.receipts[receipt.ReceiptID]
    if !known || ValidateReceipt(request, receipt) != nil || !reflect.DeepEqual(expected, receipt) {
        return errors.New("synthetic historical receipt is not authenticated")
    }
    return nil
}

func (v *sqlitePreflightVerifier) VerifyWitness(ctx context.Context, request Request, witness WitnessOutcome) error {
    v.witnessChecks++
    if v.witnessErr != nil { return v.witnessErr }
    if witness.Scope != request.Command.Scope || witness.Execution != request.Command.Execution ||
        witness.Binding != request.Binding || witness.Evidence == "" {
        return errors.New("synthetic Witness identity is not authenticated")
    }
    return v.VerifyReceipt(ctx, request, witness.Receipt)
}

type sqlitePreflightFixture struct {
    fixture sqliteTestFixture
    request Request
    baseline Reference
    attestations *sqlitePreflightAttestations
    guard *sqlitePreflightGuard
    continuity *sqlitePreflightContinuity
    verifier *sqlitePreflightVerifier
    authorizer *readTestAuthorizer
}

func sqlitePreflightRebind(t *testing.T, request *Request) {
    t.Helper()
    binding, err := CanonicalBinding(request.Command)
    if err != nil { t.Fatal("synthetic preflight request did not canonicalize") }
    request.Binding = binding
}

func sqlitePreflightSetCurrent(t *testing.T, fixture sqliteTestFixture, reference Reference) {
    t.Helper()
    args := []any{string(reference.Revision), fmt.Sprintf("%020d", reference.StateVersion), sqliteTestJSON(t, reference)}
    args = append(args, sqliteTestScope(fixture.request.Command.Scope)...)
    sqliteTestExec(t, fixture.writer, "UPDATE resources SET reference_revision=?,reference_state_version=?,reference_json=? WHERE realm=? AND host=? AND resource=? AND backend=?", args...)
}

func sqlitePreflightNew(t *testing.T) *sqlitePreflightFixture {
    t.Helper()
    fixture := sqliteTestNew(t, Positive)
    historical := readCloneReceipt(*fixture.snapshot.Backend.Receipt)
    current := historical.Positive.After
    sqlitePreflightSetCurrent(t, fixture, current)
    request := fixture.request
    request.Command.Execution = Execution{RequestID:"preflight-request",ExecutionKey:"preflight-key",OperationID:"preflight-operation",AttemptID:"preflight-attempt",StepID:"preflight-step"}
    request.Command.Expected = current
    request.Command.CandidateRevision = "revision-next"
    request.Command.CandidateContentPin = "content-next"
    request.Command.RequiredGuard.Generation = fixture.snapshot.Evidence.Generation
    sqlitePreflightRebind(t, &request)
    attestations := &sqlitePreflightAttestations{}
    continuity := &sqlitePreflightContinuity{sqliteTestContinuity:fixture.continuity, attestations:attestations, baseline:historical.Positive.Before}
    return &sqlitePreflightFixture{
        fixture:fixture, request:request, baseline:historical.Positive.Before, attestations:attestations,
        guard:&sqlitePreflightGuard{attestations:attestations}, continuity:continuity,
        verifier:&sqlitePreflightVerifier{attestations:attestations, receipts:map[ID]Receipt{historical.ReceiptID:historical}},
        authorizer:&readTestAuthorizer{},
    }
}

func (f *sqlitePreflightFixture) open(t *testing.T) (*SQLiteReadPort, *ConditionalCommitPreflight) {
    t.Helper()
    port := sqliteTestOpen(t, f.fixture)
    port.continuity = f.continuity
    checker, err := NewConditionalCommitPreflight(port, f.authorizer, f.verifier, f.guard)
    if err != nil { t.Fatal("synthetic Preflight construction failed") }
    return port, checker
}

func sqlitePreflightCheck(t *testing.T, checker *ConditionalCommitPreflight, request Request, expected PreflightStatus) PreflightResult {
    t.Helper()
    result, _ := checker.Check(context.Background(), LookupRequest{Call:readTestCall(),Request:request})
    if result.Status != expected {
        t.Fatalf("Preflight status=%s reason=%s; want %s", result.Status,result.Reason,expected)
    }
    if result.AuthorizesMutation() || result.ReusableForCommit() { t.Fatal("Preflight issued executable authority") }
    return result
}

func sqlitePreflightReceipt(t *testing.T, request Request, kind ReceiptKind) Receipt {
    t.Helper()
    receipt := Receipt{
        ReceiptID:"preflight-receipt",CommitID:"preflight-commit",ProducerBackend:request.Command.Scope.Backend,
        Scope:request.Command.Scope,Execution:request.Command.Execution,Binding:request.Binding,
        Kind:kind,Guard:request.Command.RequiredGuard,Proof:"preflight-receipt-proof",
        Decision:Decision{Profile:D1GuardDecision,TimeBase:request.Command.Timing.TimeBase,BootID:request.Command.RequiredGuard.BootID,LowerTick:89,UpperTick:90,Proof:"preflight-decision-proof"},
    }
    if kind == Positive {
        receipt.Positive=&PositivePayload{TransitionID:"preflight-transition",Before:request.Command.Expected,After:Reference{Revision:request.Command.CandidateRevision,StateVersion:request.Command.Expected.StateVersion+1},Semantic:ReferenceCommittedNotServiceApplied}
    } else {
        receipt.Decision.Profile=QualifiedRejectionDecision
        receipt.Negative=&NegativePayload{Reason:GuardRejected,NoAdditionalEffectProof:"preflight-negative-proof"}
    }
    if ValidateReceipt(request,receipt)!=nil { t.Fatal("synthetic terminal receipt is malformed") }
    return receipt
}

func TestSQLitePreflightEligibleIsObservationOnly(t *testing.T) {
    f:=sqlitePreflightNew(t)
    port,checker:=f.open(t)
    result:=sqlitePreflightCheck(t,checker,f.request,PreflightEligible)
    if result.Binding!=f.request.Binding || result.Execution!=f.request.Command.Execution ||
        result.Scope!=f.request.Command.Scope || result.Observed==nil || *result.Observed!=f.request.Command.Expected {
        t.Fatal("eligible observation lost immutable identity or expected reference")
    }
    if f.guard.calls==0 || f.continuity.calls==0 || f.verifier.guardChecks==0 || f.verifier.continuityChecks==0 || f.verifier.receiptChecks==0 {
        t.Fatal("eligibility bypassed independent full-payload verification")
    }
    if len(f.authorizer.targets)!=1 || f.authorizer.targets[0].Action!=PreflightCommitAction ||
        f.authorizer.targets[0].Execution==nil || *f.authorizer.targets[0].Execution!=f.request.Command.Execution ||
        f.authorizer.targets[0].Binding!=f.request.Binding {
        t.Fatal("query authority was not bound to the actual requested execution")
    }
    if port.owner.writerConfigured || port.owner.writePool!=nil { t.Fatal("Preflight consumed or installed Writer participation") }
    forged:=PreflightResult{Status:PreflightEligible}
    if forged.AuthorizesMutation() || forged.ReusableForCommit() { t.Fatal("forged status became authority") }
}

func TestSQLitePreflightRequestValidationAndStrictDecode(t *testing.T) {
    f:=sqlitePreflightNew(t)
    _,checker:=f.open(t)
    changed:=f.request
    changed.Binding="other-binding"
    sqlitePreflightCheck(t,checker,changed,PreflightConflict)
    for _, field:=range []string{"RequestID","ExecutionKey","OperationID","AttemptID","StepID"} {
        changed=f.request
        reflect.ValueOf(&changed.Command.Execution).Elem().FieldByName(field).SetString("")
        sqlitePreflightCheck(t,checker,changed,PreflightRejected)
    }
    encoded,err:=json.Marshal(f.request)
    if err!=nil { t.Fatal(err) }
    valid,_:=checker.CheckEncoded(context.Background(),readTestCall(),encoded)
    if valid.Status!=PreflightEligible { t.Fatal("strict decoder rejected a canonical request") }
    body:=string(encoded)
    bodies:=[]string{
        strings.TrimSuffix(body,"}")+",\"Witness\":{}}",
        strings.TrimSuffix(body,"}")+",\"Receipt\":{}}",
        strings.Replace(body,"\"Schema\":1","\"Schema\":1,\"Unknown\":true",1),
        strings.Replace(body,"\"Schema\":1","\"Schema\":1,\"Schema\":1",1),
        strings.Replace(body,"\"DeadlineTick\":100","\"DeadlineTick\":null",1),
        validationOuterValue(t,body,"Binding","null"),
        "null",body+"{}",
    }
    for _, malformed:=range bodies {
        result,err:=checker.CheckEncoded(context.Background(),readTestCall(),[]byte(malformed))
        if err==nil || result.Status==PreflightEligible { t.Fatal("unknown, duplicate, missing or invalid input became eligible") }
    }
}

func TestSQLitePreflightExpectedReferenceAndABA(t *testing.T) {
    for _, tc:=range []struct{name string; change func(*Request)}{
        {"revision",func(r *Request){r.Command.Expected.Revision="revision-other"}},
        {"state-version",func(r *Request){r.Command.Expected.StateVersion++}},
        {"same-revision-old-version-aba",func(r *Request){r.Command.Expected.StateVersion--}},
        {"same-candidate-revision",func(r *Request){r.Command.CandidateRevision=r.Command.Expected.Revision}},
    } {
        t.Run(tc.name,func(t *testing.T){
            f:=sqlitePreflightNew(t);_,checker:=f.open(t);request:=f.request;tc.change(&request);sqlitePreflightRebind(t,&request)
            sqlitePreflightCheck(t,checker,request,PreflightRejected)
        })
    }
}

func TestSQLitePreflightUint64Boundary(t *testing.T) {
    t.Run("last-incrementable",func(t *testing.T){
        f:=sqlitePreflightNew(t)
        sqliteTestExec(t,f.fixture.writer,"DELETE FROM reference_transitions")
        sqliteTestExec(t,f.fixture.writer,"DELETE FROM executions")
        current:=Reference{Revision:"revision-boundary",StateVersion:math.MaxUint64-1}
        sqlitePreflightSetCurrent(t,f.fixture,current)
        f.request.Command.Expected=current
        sqlitePreflightRebind(t,&f.request)
        f.continuity.baseline=current
        _,checker:=f.open(t)
        sqlitePreflightCheck(t,checker,f.request,PreflightEligible)
    })
    t.Run("no-overflow",func(t *testing.T){
        f:=sqlitePreflightNew(t);_,checker:=f.open(t);request:=f.request
        request.Command.Expected.StateVersion=math.MaxUint64
        request.Binding="not-a-canonical-overflow-request"
        sqlitePreflightCheck(t,checker,request,PreflightRejected)
    })
}

func TestSQLitePreflightGlobalExecutionIdentityConflicts(t *testing.T) {
    for _, name:=range []string{"execution-key","request-id","operation-attempt-step","indexed-scope-json"} {
        t.Run(name,func(t *testing.T){
            f:=sqlitePreflightNew(t)
            alias:=f.request
            if name=="indexed-scope-json" {
                sqliteTestInsertExecution(t,f.fixture.writer,f.request,nil)
                alias.Command.Scope.Host="other-host"
                sqlitePreflightRebind(t,&alias)
                args:=[]any{sqliteTestJSON(t,alias)}
                args=append(args,sqliteTestExecution(f.request)...)
                sqliteTestExec(t,f.fixture.writer,"UPDATE executions SET request_json=? WHERE realm=? AND host=? AND resource=? AND backend=? AND execution_key=?",args...)
            } else {
                alias.Command.Scope.Resource="other-resource"
                alias.Command.Execution=Execution{RequestID:"alias-request",ExecutionKey:"alias-key",OperationID:"alias-operation",AttemptID:"alias-attempt",StepID:"alias-step"}
                switch name {
                case "execution-key":alias.Command.Execution.ExecutionKey=f.request.Command.Execution.ExecutionKey
                case "request-id":alias.Command.Execution.RequestID=f.request.Command.Execution.RequestID
                case "operation-attempt-step":
                    alias.Command.Execution.OperationID=f.request.Command.Execution.OperationID
                    alias.Command.Execution.AttemptID=f.request.Command.Execution.AttemptID
                    alias.Command.Execution.StepID=f.request.Command.Execution.StepID
                }
                sqlitePreflightRebind(t,&alias)
                reference:=alias.Command.Expected
                sqliteTestResource(t,f.fixture.writer,alias.Command.Scope,Known,&reference,f.fixture.snapshot.Evidence)
                sqliteTestInsertExecution(t,f.fixture.writer,alias,nil)
            }
            _,checker:=f.open(t)
            sqlitePreflightCheck(t,checker,f.request,PreflightConflict)
        })
    }
}

func TestSQLitePreflightHistoryCoverageAndReceiptIntegrity(t *testing.T) {
    for _, tc:=range []struct{name string; setup func(*testing.T,*sqlitePreflightFixture); status PreflightStatus}{
        {"missing-history",func(t *testing.T,f *sqlitePreflightFixture){sqliteTestExec(t,f.fixture.writer,"DELETE FROM reference_transitions")},PreflightUnknown},
        {"missing-receipt",func(t *testing.T,f *sqlitePreflightFixture){sqliteTestExec(t,f.fixture.writer,"UPDATE executions SET backend_knowledge='UNKNOWN',receipt_kind=NULL,receipt_json=NULL")},PreflightUnknown},
        {"current-history-gap",func(t *testing.T,f *sqlitePreflightFixture){
            current:=Reference{Revision:"revision-gap",StateVersion:99};sqlitePreflightSetCurrent(t,f.fixture,current);f.request.Command.Expected=current;sqlitePreflightRebind(t,&f.request)
        },PreflightUnknown},
        {"nonconsecutive-version",func(t *testing.T,f *sqlitePreflightFixture){sqliteTestExec(t,f.fixture.writer,"UPDATE reference_transitions SET after_state_version='00000000000000000009'")},PreflightConflict},
        {"receipt-link",func(t *testing.T,f *sqlitePreflightFixture){sqliteTestExec(t,f.fixture.writer,"UPDATE reference_transitions SET receipt_id='receipt-wrong'")},PreflightConflict},
    } {
        t.Run(tc.name,func(t *testing.T){f:=sqlitePreflightNew(t);tc.setup(t,f);_,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,tc.status)})
    }
}

func TestSQLitePreflightGuardMissingOrUnauthenticated(t *testing.T) {
    t.Run("missing",func(t *testing.T){
        f:=sqlitePreflightNew(t);port,_:=f.open(t)
        checker,err:=NewConditionalCommitPreflight(port,f.authorizer,f.verifier,nil);if err!=nil{t.Fatal(err)}
        sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    })
    for _, tc:=range []struct{name string; change func(*PreflightGuardObservation)}{
        {"unknown",func(o *PreflightGuardObservation){o.Knowledge=Unknown}},
        {"missing-proof",func(o *PreflightGuardObservation){o.Proof="missing-proof"}},
        {"missing-current",func(o *PreflightGuardObservation){o.Current.BootID=""}},
        {"frame",func(o *PreflightGuardObservation){o.Frame.SnapshotID="old-snapshot"}},
    } {
        t.Run(tc.name,func(t *testing.T){f:=sqlitePreflightNew(t);f.guard.change=tc.change;_,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)})
    }
    t.Run("unverified",func(t *testing.T){
        f:=sqlitePreflightNew(t);f.verifier.guardErr=errors.New("private Guard authority");_,checker:=f.open(t)
        sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    })
}

func TestSQLitePreflightGuardRevisionsAndIdentity(t *testing.T) {
    for _, field:=range []string{"Policy","Trust","Membership","OwnershipEpoch","FenceEpoch","Generation","BootID","ProcessIncarnation"} {
        t.Run(field,func(t *testing.T){
            f:=sqlitePreflightNew(t)
            f.guard.change=func(o *PreflightGuardObservation){reflect.ValueOf(&o.Current).Elem().FieldByName(field).SetString("changed-revision")}
            _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightRejected)
        })
    }
    for _, name:=range []string{"scope","execution","binding"} {
        t.Run(name,func(t *testing.T){
            f:=sqlitePreflightNew(t)
            f.guard.change=func(o *PreflightGuardObservation){
                switch name {case "scope":o.Scope.Host="other-host";case "execution":o.Execution.AttemptID="other-attempt";case "binding":o.Binding="other-binding"}
            }
            _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightConflict)
        })
    }
}

func TestSQLitePreflightGuardConditionsAreIndependent(t *testing.T) {
    for _, field:=range []string{"CPAuthorization","Policy","Trust","Membership","Ownership","Fence","Boot","Process","PAdmission","Candidate"} {
        t.Run(field+"-denied",func(t *testing.T){
            f:=sqlitePreflightNew(t);f.guard.change=func(o *PreflightGuardObservation){reflect.ValueOf(o).Elem().FieldByName(field).SetString(string(PreflightConditionDenied))}
            _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightRejected)
        })
        t.Run(field+"-unknown",func(t *testing.T){
            f:=sqlitePreflightNew(t);f.guard.change=func(o *PreflightGuardObservation){reflect.ValueOf(o).Elem().FieldByName(field).SetString(string(PreflightConditionUnknown))}
            _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
        })
    }
}

func TestSQLitePreflightBusinessAdmissionAndDrainAreSeparate(t *testing.T) {
    for _, tc:=range []struct{name string; change func(*PreflightGuardObservation); status PreflightStatus}{
        {"b-closed-p-valid-d-ready",func(*PreflightGuardObservation){},PreflightEligible},
        {"b-open-independent-valid-proof",func(o *PreflightGuardObservation){o.BusinessAdmission=PreflightBusinessOpen},PreflightEligible},
        {"b-unknown",func(o *PreflightGuardObservation){o.BusinessAdmission=PreflightBusinessUnknown},PreflightUnknown},
        {"p-denied",func(o *PreflightGuardObservation){o.PAdmission=PreflightConditionDenied},PreflightRejected},
        {"d-not-ready",func(o *PreflightGuardObservation){o.Drain=PreflightDrainNotReady},PreflightRejected},
        {"d-held",func(o *PreflightGuardObservation){o.Drain=PreflightDrainHeld},PreflightRejected},
        {"d-unknown",func(o *PreflightGuardObservation){o.Drain=PreflightDrainUnknown},PreflightUnknown},
        {"d-no-seal",func(o *PreflightGuardObservation){o.DrainSeal=""},PreflightUnknown},
    } {
        t.Run(tc.name,func(t *testing.T){f:=sqlitePreflightNew(t);f.guard.change=tc.change;_,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,tc.status)})
    }
}

func TestSQLitePreflightContinuityMissingOrPartialCoverage(t *testing.T) {
    for _, name:=range []string{"disconnected","legacy-only","typed-nil"} {
        t.Run(name,func(t *testing.T){
            f:=sqlitePreflightNew(t);port,checker:=f.open(t)
            switch name {case "disconnected":port.continuity=nil;case "legacy-only":port.continuity=f.fixture.continuity;case "typed-nil":var absent *sqlitePreflightContinuity;port.continuity=absent}
            sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
        })
    }
    for _, field:=range []string{"WitnessCoverage","OutstandingCoverage","HistoryCoverage","IdentityCoverage","FreshnessCoverage"} {
        t.Run(field,func(t *testing.T){
            f:=sqlitePreflightNew(t);f.continuity.change=func(o *PreflightContinuityObservation){reflect.ValueOf(o).Elem().FieldByName(field).SetString(string(Unknown))}
            _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
        })
    }
}

func TestSQLitePreflightContinuityFrameFreshnessAndIdentity(t *testing.T) {
    for _, tc:=range []struct{name string; change func(*PreflightContinuityObservation); status PreflightStatus}{
        {"frame",func(o *PreflightContinuityObservation){o.Frame.Generation="old-generation"},PreflightUnknown},
        {"snapshot-evidence",func(o *PreflightContinuityObservation){o.Evidence.SnapshotID="old-snapshot"},PreflightUnknown},
        {"freshness-proof",func(o *PreflightContinuityObservation){o.Evidence.FreshnessProof=""},PreflightUnknown},
        {"issuer",func(o *PreflightContinuityObservation){o.ContinuityIssuer=""},PreflightUnknown},
        {"proof",func(o *PreflightContinuityObservation){o.Proof="missing-proof"},PreflightUnknown},
        {"baseline",func(o *PreflightContinuityObservation){o.HistoryBaseline=nil},PreflightUnknown},
        {"scope",func(o *PreflightContinuityObservation){o.Scope.Resource="other-resource"},PreflightConflict},
        {"execution",func(o *PreflightContinuityObservation){o.Execution.StepID="other-step"},PreflightConflict},
        {"binding",func(o *PreflightContinuityObservation){o.Binding="other-binding"},PreflightConflict},
    } {
        t.Run(tc.name,func(t *testing.T){f:=sqlitePreflightNew(t);f.continuity.change=tc.change;_,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,tc.status)})
    }
    t.Run("unverified-restore-freshness",func(t *testing.T){
        f:=sqlitePreflightNew(t);f.verifier.continuityErr=errors.New("private restore uncertainty");_,checker:=f.open(t)
        sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    })
}

func TestSQLitePreflightWitnessNeedsIdentityReceiptAndAuthentication(t *testing.T) {
    for _, name:=range []string{"scope","execution","binding","receipt","verified-terminal","unverified"} {
        t.Run(name,func(t *testing.T){
            f:=sqlitePreflightNew(t)
            receipt:=sqlitePreflightReceipt(t,f.request,Positive)
            f.verifier.receipts[receipt.ReceiptID]=receipt
            witness:=WitnessOutcome{LiabilityID:"preflight-liability",Scope:f.request.Command.Scope,Execution:f.request.Command.Execution,Binding:f.request.Binding,Receipt:receipt,Evidence:"preflight-witness-proof"}
            switch name {case "scope":witness.Scope.Host="other-host";case "execution":witness.Execution.RequestID="other-request";case "binding":witness.Binding="other-binding";case "receipt":witness.Receipt.Proof="";case "unverified":f.verifier.witnessErr=errors.New("unverified Witness")}
            f.continuity.change=func(o *PreflightContinuityObservation){o.Witness=&witness}
            _,checker:=f.open(t)
            expected:=PreflightConflict
            if name=="verified-terminal" {expected=PreflightRejected}
            if name=="unverified" {expected=PreflightUnknown}
            sqlitePreflightCheck(t,checker,f.request,expected)
        })
    }
}

func TestSQLitePreflightOutstandingCoversOldKeys(t *testing.T) {
    f:=sqlitePreflightNew(t)
    f.continuity.change=func(o *PreflightContinuityObservation){o.Outstanding=[]ID{"old-key-unknown-liability"}}
    _,checker:=f.open(t)
    sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    newRequest:=f.request
    newRequest.Command.Execution=Execution{RequestID:"new-request",ExecutionKey:"new-key",OperationID:"new-operation",AttemptID:"new-attempt",StepID:"new-step"}
    sqlitePreflightRebind(t,&newRequest)
    sqlitePreflightCheck(t,checker,newRequest,PreflightUnknown)
    f.continuity.change=func(o *PreflightContinuityObservation){o.Outstanding=[]ID{"duplicate-liability","duplicate-liability"}}
    sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
}

func TestSQLitePreflightExistingExecutionNeverBecomesNewPermission(t *testing.T) {
    t.Run("receipt-absent-not-unstarted",func(t *testing.T){
        f:=sqlitePreflightNew(t);sqliteTestInsertExecution(t,f.fixture.writer,f.request,nil)
        _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    })
    for _, unauthenticated:=range []bool{false,true} {
        t.Run(fmt.Sprintf("negative-terminal-unverified-%t",unauthenticated),func(t *testing.T){
            f:=sqlitePreflightNew(t);receipt:=sqlitePreflightReceipt(t,f.request,Negative)
            f.verifier.receipts[receipt.ReceiptID]=receipt
            sqliteTestInsertExecution(t,f.fixture.writer,f.request,&receipt)
            if unauthenticated { f.verifier.receiptErr=errors.New("unverified terminal") }
            _,checker:=f.open(t);status:=PreflightRejected;if unauthenticated{status=PreflightUnknown}
            sqlitePreflightCheck(t,checker,f.request,status)
        })
    }
}

func TestSQLitePreflightOwnerUncertainOrClosing(t *testing.T) {
    t.Run("uncertain",func(t *testing.T){
        f:=sqlitePreflightNew(t);port,checker:=f.open(t)
        sqliteLifecycleSyntheticCleanup(t,port.owner,port.owner.pool.(*sql.DB),port.owner.header)
        port.owner.markUncertain()
        sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
        if f.guard.calls!=0 || !sqliteLifecycleLeaseHeld(port.owner) {t.Fatal("uncertain owner performed external checks or dropped ownership")}
    })
    t.Run("closing",func(t *testing.T){
        f:=sqlitePreflightNew(t);port,checker:=f.open(t)
        ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
        operation,err:=port.owner.acquire(ctx);if err!=nil{t.Fatal(err)};defer operation.release()
        done:=make(chan error,1);go func(){done<-port.Close()}()
        sqliteLifecycleAwait(t,ctx,port.owner.closingStarted)
        sqlitePreflightCheck(t,checker,f.request,PreflightRejected)
        if f.guard.calls!=0 {t.Fatal("closing owner started external verification")}
        operation.release()
        if err:=sqliteLifecycleCloseResult(t,ctx,done);err!=nil{t.Fatal(err)}
    })
}

func TestSQLitePreflightContextCancellation(t *testing.T) {
    t.Run("before-admission",func(t *testing.T){
        f:=sqlitePreflightNew(t);_,checker:=f.open(t);ctx,cancel:=context.WithCancel(context.Background());cancel()
        result,err:=checker.Check(ctx,LookupRequest{Call:readTestCall(),Request:f.request})
        if result.Status!=PreflightUnknown || !errors.Is(err,context.Canceled) || f.guard.calls!=0 {t.Fatal("pre-canceled Preflight was not rejected before external work")}
    })
    t.Run("during-guard",func(t *testing.T){
        f:=sqlitePreflightNew(t);port,checker:=f.open(t)
        entered:=make(chan struct{});f.guard.onObserve=func(ctx context.Context)error{close(entered);<-ctx.Done();return ctx.Err()}
        deadline,stop:=context.WithTimeout(context.Background(),10*time.Second);defer stop()
        ctx,cancel:=context.WithCancel(deadline);defer cancel()
        done:=make(chan PreflightResult,1);go func(){result,_:=checker.Check(ctx,LookupRequest{Call:readTestCall(),Request:f.request});done<-result}()
        sqliteLifecycleAwait(t,deadline,entered);cancel()
        select {case result:=<-done:if result.Status!=PreflightUnknown{t.Fatal("canceled observation became eligible")};case <-deadline.Done():t.Fatal("canceled Preflight did not release its borrow")}
        d:=port.InspectLifecycle();sqliteInspectionCount(t,d.ActiveOperations,0)
        if d.State!=LifecycleOpen || port.owner.pool.Stats().InUse!=0 {t.Fatal("read cancellation leaked or poisoned resources")}
    })
}

func TestSQLitePreflightBorrowBlocksWriterAndDrainsClose(t *testing.T) {
    f:=sqlitePreflightNew(t);port,checker:=f.open(t)
    if err:=port.owner.prepareWriterProfile(context.Background());err!=nil{t.Fatal(err)}
    entered,resume:=make(chan struct{}),make(chan struct{})
    var once sync.Once;release:=func(){once.Do(func(){close(resume)})};defer release()
    f.guard.onObserve=func(context.Context)error{close(entered);<-resume;return nil}
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
    result:=make(chan PreflightResult,1);go func(){observed,_:=checker.Check(ctx,LookupRequest{Call:readTestCall(),Request:f.request});result<-observed}()
    sqliteLifecycleAwait(t,ctx,entered)
    d:=port.InspectLifecycle()
    sqliteInspectionCount(t,d.Roles.Read.Operations,1);sqliteInspectionCount(t,d.Roles.Read.Transactions,0)
    if port.owner.pool.Stats().InUse!=0 {t.Fatal("external verification retained a SQL transaction")}
    if tx,err:=port.owner.beginWrite(ctx);tx!=nil||err==nil{if tx!=nil{_ =tx.Rollback()};t.Fatal("Writer bypassed live Preflight observation borrow")}
    if port.owner.writePool!=nil {t.Fatal("Preflight contention opened a Writer pool")}
    closed:=make(chan error,1);go func(){closed<-port.Close()}()
    sqliteLifecycleAwait(t,ctx,port.owner.closingStarted);sqliteLifecycleCheckBlocked(t,closed)
    release()
    select {case observed:=<-result:if observed.Status!=PreflightUnknown{t.Fatal("Close race preserved obsolete eligibility")};case <-ctx.Done():t.Fatal("Preflight did not settle for Close")}
    if err:=sqliteLifecycleCloseResult(t,ctx,closed);err!=nil{t.Fatal(err)}
    sqliteInspectionClosed(t,port.InspectLifecycle())
}

func TestSQLitePreflightEligibleCannotBeReused(t *testing.T) {
    f:=sqlitePreflightNew(t);_,checker:=f.open(t)
    previous:=sqlitePreflightCheck(t,checker,f.request,PreflightEligible)
    f.guard.change=func(o *PreflightGuardObservation){o.Current.FenceEpoch="new-fence"}
    sqlitePreflightCheck(t,checker,f.request,PreflightRejected)
    if previous.Status!=PreflightEligible || previous.AuthorizesMutation() || previous.ReusableForCommit() {t.Fatal("historical result acquired reusable authority")}
    raw,err:=json.Marshal(previous);if err!=nil{t.Fatal(err)}
    observed,err:=checker.CheckEncoded(context.Background(),readTestCall(),raw)
    if err==nil || observed.Status==PreflightEligible {t.Fatal("old result was accepted as a new immutable request")}
    resultType:=reflect.TypeOf(PreflightResult{})
    for i:=0;i<reflect.TypeOf(checker).NumMethod();i++ {
        method:=reflect.TypeOf(checker).Method(i)
        for j:=1;j<method.Type.NumIn();j++ {if method.Type.In(j)==resultType {t.Fatal("Preflight API accepts an old result as authority")}}
    }
}

func TestSQLitePreflightReferenceChangeRequiresNewObservation(t *testing.T) {
    f:=sqlitePreflightNew(t);port,checker:=f.open(t)
    previous:=sqlitePreflightCheck(t,checker,f.request,PreflightEligible)
    if err:=port.Close();err!=nil{t.Fatal(err)}
    writer,err:=sql.Open("sqlite",f.fixture.path);if err!=nil{t.Fatal(err)}
    f.fixture.writer=writer
    sqlitePreflightSetCurrent(t,f.fixture,Reference{Revision:"revision-later",StateVersion:99})
    newPort,newChecker:=f.open(t)
    _=newPort
    sqlitePreflightCheck(t,newChecker,f.request,PreflightRejected)
    if previous.AuthorizesMutation() || previous.ReusableForCommit() {t.Fatal("old eligibility bypassed changed reference")}
}

func TestSQLitePreflightAuthenticatesCompletePayloads(t *testing.T) {
    t.Run("guard-tamper",func(t *testing.T){
        f:=sqlitePreflightNew(t);f.guard.afterAttest=func(o *PreflightGuardObservation){o.Current.Policy="tampered-policy"}
        _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    })
    t.Run("continuity-tamper",func(t *testing.T){
        f:=sqlitePreflightNew(t);f.continuity.afterAttest=func(o *PreflightContinuityObservation){o.HistoryBaseline.Revision="tampered-baseline"}
        _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    })
    t.Run("historical-receipt-tamper",func(t *testing.T){
        f:=sqlitePreflightNew(t);receipt:=readCloneReceipt(*f.fixture.snapshot.Backend.Receipt);receipt.Proof="unknown-receipt-proof"
        sqliteTestExec(t,f.fixture.writer,"UPDATE executions SET receipt_json=?",sqliteTestJSON(t,receipt))
        _,checker:=f.open(t);sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    })
}

func TestSQLitePreflightExternalChangeAfterSnapshotIsUnknown(t *testing.T) {
    f:=sqlitePreflightNew(t);port,checker:=f.open(t)
    changed:=false
    f.guard.onObserve=func(context.Context)error{
        // Deliberate synthetic Actor outside the Owner boundary; no raw Header
        // FD is opened/closed and no SQL read transaction is alive here.
        writer,err:=sql.Open("sqlite",f.fixture.path);if err!=nil{return err}
        defer writer.Close()
        reference:=Reference{Revision:"external-revision",StateVersion:99}
        args:=[]any{string(reference.Revision),fmt.Sprintf("%020d",reference.StateVersion),sqliteTestJSON(t,reference)}
        args=append(args,sqliteTestScope(f.request.Command.Scope)...)
        _,err=writer.ExecContext(context.Background(),"UPDATE resources SET reference_revision=?,reference_state_version=?,reference_json=? WHERE realm=? AND host=? AND resource=? AND backend=?",args...)
        changed=err==nil
        return err
    }
    observed:=sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    if !changed || observed.Reason!="observation_changed" {t.Fatal("late external data change was not detected by read-only re-observation")}
    active,err:=port.ReadActiveReference(context.Background(),f.request.Command.Scope)
    if err!=nil || active.Reference==nil || active.Reference.Revision!="external-revision" {t.Fatal("synthetic external change was not independently visible")}
}

func TestSQLitePreflightNoReferenceReceiptHistoryWritesOrPrivateErrors(t *testing.T) {
    f:=sqlitePreflightNew(t)
    if err:=f.fixture.writer.Close();err!=nil{t.Fatal(err)}
    original,err:=os.ReadFile(f.fixture.path);if err!=nil{t.Fatal(err)}
    before:=sha256.Sum256(original)
    port,checker:=f.open(t)
    sqlitePreflightCheck(t,checker,f.request,PreflightEligible)
    f.guard.err=errors.New("private-database-path SQL-UPDATE synthetic-token")
    result,err:=checker.Check(context.Background(),LookupRequest{Call:readTestCall(),Request:f.request})
    encoded,_:=json.Marshal(result)
    if result.Status!=PreflightUnknown || strings.Contains(string(encoded),"synthetic-token") ||
        strings.Contains(string(encoded),f.fixture.path) || (err!=nil&&strings.Contains(err.Error(),"SQL-UPDATE")) {
        t.Fatal("private error/path/payload leaked from Preflight")
    }
    if port.owner.writerConfigured || port.owner.writePool!=nil {t.Fatal("Preflight installed Mutation resources")}
    if err:=port.Close();err!=nil{t.Fatal(err)}
    final,err:=os.ReadFile(f.fixture.path);if err!=nil{t.Fatal(err)}
    if sha256.Sum256(final)!=before {t.Fatal("Preflight changed preserved Reference/Receipt/History/database bytes")}
}

func TestSQLitePreflightLocalUnknownOldKeyBlocksEmptyIndependentList(t *testing.T) {
    f:=sqlitePreflightNew(t)
    older:=f.request
    older.Command.Execution=Execution{RequestID:"older-request",ExecutionKey:"older-key",OperationID:"older-operation",AttemptID:"older-attempt",StepID:"older-step"}
    sqlitePreflightRebind(t,&older)
    sqliteTestInsertExecution(t,f.fixture.writer,older,nil)
    args:=sqliteTestExecution(older)
    sqliteTestExec(t,f.fixture.writer,"UPDATE executions SET backend_knowledge='UNKNOWN' WHERE realm=? AND host=? AND resource=? AND backend=? AND execution_key=?",args...)
    _,checker:=f.open(t)
    sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
    another:=f.request
    another.Command.Execution=Execution{RequestID:"later-request",ExecutionKey:"later-key",OperationID:"later-operation",AttemptID:"later-attempt",StepID:"later-step"}
    sqlitePreflightRebind(t,&another)
    sqlitePreflightCheck(t,checker,another,PreflightUnknown)
}

func TestSQLitePreflightCurrentQueryAuthorityPrecedesObservation(t *testing.T) {
    f:=sqlitePreflightNew(t);port,checker:=f.open(t)
    f.authorizer.err=errors.New("synthetic-token private-query-authority SQL-UPDATE")
    before:=sqliteInspectionStamp(port.owner)
    result,err:=checker.Check(context.Background(),LookupRequest{Call:readTestCall(),Request:f.request})
    if result.Status!=PreflightRejected || !IsCode(err,CodeUnauthorized) || f.guard.calls!=0 || f.continuity.calls!=0 ||
        !reflect.DeepEqual(before,sqliteInspectionStamp(port.owner)) || strings.Contains(err.Error(),"synthetic-token") {
        t.Fatal("query authority was bypassed, changed resources or leaked its private error")
    }
}

func TestSQLitePreflightOldKeyOrphanProjectionIsUnknown(t *testing.T) {
    f := sqlitePreflightNew(t)
    // Deliberate synthetic integrity gap, created offline. No production
    // repair, FK configuration or source Schema mutation is performed.
    sqliteTestExec(t, f.fixture.writer, "PRAGMA foreign_keys=OFF")
    args := append(sqliteTestScope(f.request.Command.Scope), "orphan-old-key", string(ExecutorLedger), string(Unknown), nil)
    sqliteTestExec(t, f.fixture.writer, "INSERT INTO projections(realm,host,resource,backend,execution_key,boundary,knowledge,record_json) VALUES(?,?,?,?,?,?,?,?)", args...)
    _, checker := f.open(t)
    result := sqlitePreflightCheck(t, checker, f.request, PreflightUnknown)
    if result.AuthorizesMutation() || f.continuity.calls != 0 {
        t.Fatal("local orphan liability was hidden by an empty independent set")
    }
}
