// UNAPPLIED candidate integration tests. The CI harness copies this file only
// into a disposable synthetic workspace. This is not a product CP Producer,
// published Contracts dependency, cryptographic implementation or clock proof.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	evidence "github.com/Kome-Lab/Autostream-Contracts/v3evidence"
)

type contractsTestDelivery struct {
	mu sync.Mutex
	encoded [][]byte
	reads int
	onRead func(context.Context, int) error
	err error
}

func contractsTestCopyBytes(values [][]byte) [][]byte {
	result:=make([][]byte,len(values))
	for index,value:=range values { result[index]=append([]byte(nil),value...) }
	return result
}

func (s *contractsTestDelivery) ReadGuardEnvelopes(ctx context.Context,_ Request,_ BackendReadFrame)([][]byte,error){
	if err:=ctx.Err();err!=nil{return nil,err}
	s.mu.Lock();s.reads++;number,hook,err:=s.reads,s.onRead,s.err;s.mu.Unlock()
	if hook!=nil {if err:=hook(ctx,number);err!=nil{return nil,err}}
	if err!=nil{return nil,err}
	s.mu.Lock();result:=contractsTestCopyBytes(s.encoded);s.mu.Unlock()
	return result,nil
}

type contractsTestIssued struct {
	typed evidence.Envelope
	raw []byte
}

// The issued/current registries and tick value are independent SYNTHETIC test
// owners. Nonempty IDs/proofs do not create an issued entry or current trust.
type contractsTestVerifier struct {
	mu sync.Mutex
	issued map[string]contractsTestIssued
	current map[string]evidence.Envelope
	clockKnown,revocationKnown bool
	tick uint64
	clockBoot string
	integrityCalls,validityCalls,revocationCalls int
	onIntegrity func(int)
}

func(v *contractsTestVerifier) VerifyIntegrity(ctx context.Context,envelope evidence.Envelope,raw []byte)error{
	if err:=ctx.Err();err!=nil{return err}
	decoded,err:=evidence.Decode(raw)
	if err!=nil||!reflect.DeepEqual(decoded,envelope){return errors.New("synthetic raw and typed payload differ")}
	v.mu.Lock()
	issued,known:=v.issued[envelope.EvidenceID]
	v.integrityCalls++;count,hook:=v.integrityCalls,v.onIntegrity
	valid:=known&&bytes.Equal(issued.raw,raw)&&reflect.DeepEqual(issued.typed,envelope)
	v.mu.Unlock()
	if !valid{return errors.New("synthetic complete payload was not issued")}
	if hook!=nil{hook(count)}
	return nil
}

func(v *contractsTestVerifier) VerifyCurrentValidity(ctx context.Context,envelope evidence.Envelope)error{
	if err:=ctx.Err();err!=nil{return err}
	v.mu.Lock();known,tick,clockBoot:=v.clockKnown,v.tick,v.clockBoot;v.validityCalls++;v.mu.Unlock()
	validity:=envelope.Validity
	if !known||validity.Status!="SPECIFIED"||validity.Issued==nil||validity.Expiry==nil||
		validity.Issued.TimeBase!="synthetic-contract-clock"||validity.Expiry.TimeBase!="synthetic-contract-clock"||
		validity.Issued.BootID!=validity.Expiry.BootID||validity.Issued.BootID!=clockBoot||validity.QualificationProof!="synthetic-clock-proof"||
		tick<validity.Issued.Tick||tick>=validity.Expiry.Tick{
		return errors.New("synthetic evidence clock is unqualified or interval expired")
	}
	return nil
}

func(v *contractsTestVerifier) VerifyCurrentRevocation(ctx context.Context,envelope evidence.Envelope)error{
	if err:=ctx.Err();err!=nil{return err}
	v.mu.Lock();known:=v.revocationKnown;current,exists:=v.current[envelope.EvidenceID];v.revocationCalls++;v.mu.Unlock()
	if !known||!exists||!reflect.DeepEqual(current,envelope){return errors.New("synthetic current applicability is unknown or changed")}
	return nil
}

type contractsTestFixture struct {
	*guardEvidenceTestFixture
	delivery *contractsTestDelivery
	verification *contractsTestVerifier
	reader *ContractsGuardEvidenceSource
	contractsAuth *ContractsGuardEvidenceAuthenticator
}

func contractsTestNew(t *testing.T)*contractsTestFixture{
	t.Helper()
	base:=guardEvidenceTestNew(t)
	request:=base.request
	command:=request.Command
	guard:=command.RequiredGuard
	frame:=sqliteTestFrame(base.fixture.snapshot.Evidence)
	f:=&contractsTestFixture{
		guardEvidenceTestFixture:base,
		delivery:&contractsTestDelivery{},
		verification:&contractsTestVerifier{
			issued:make(map[string]contractsTestIssued),current:make(map[string]evidence.Envelope),
			clockKnown:true,revocationKnown:true,tick:50,clockBoot:string(guard.BootID),
		},
	}
	for _,kind:=range guardEvidenceTestKinds(){
		issuer:=""
		for _,item:=range base.config.Issuers{if item.Kind==kind{issuer=string(item.Issuer)}}
		envelope:=evidence.Envelope{
			ProtocolVersion:evidence.ProtocolVersion,EvidenceID:"evidence-"+string(kind),Kind:evidence.Kind(kind),
			Issuer:issuer,Audience:string(base.config.Audience),
			Scope:evidence.Scope{Realm:string(command.Scope.Realm),Host:string(command.Scope.Host),Resource:string(command.Scope.Resource),Backend:string(command.Scope.Backend)},
			Execution:evidence.Execution{RequestID:string(command.Execution.RequestID),ExecutionKey:string(command.Execution.ExecutionKey),OperationID:string(command.Execution.OperationID),AttemptID:string(command.Execution.AttemptID),StepID:string(command.Execution.StepID)},
			Binding:string(request.Binding),
			Frame:evidence.BackendReadFrame{Issuer:string(frame.Issuer),ServingIncarnation:string(frame.ServingIncarnation),Generation:string(frame.Generation),SnapshotID:string(frame.SnapshotID),ObservationProof:string(frame.ObservationProof)},
			Validity:evidence.Validity{Status:"SPECIFIED",Issued:&evidence.TimePoint{TimeBase:"synthetic-contract-clock",BootID:string(guard.BootID),Tick:10},Expiry:&evidence.TimePoint{TimeBase:"synthetic-contract-clock",BootID:string(guard.BootID),Tick:100},QualificationProof:"synthetic-clock-proof"},
			Integrity:evidence.Integrity{ProfileID:"synthetic-test-only",KeyID:"synthetic-key",KeyRevision:"synthetic-key-revision",Proof:"synthetic-issued-proof"},
		}
		switch kind{
		case GuardCPAuthorization:
			envelope.CPAuthorization=&evidence.CPAuthorizationPayload{Action:ReferenceOnlyOperation,Decision:"AUTHORIZED",PolicyRevision:string(guard.Policy),TrustRevision:string(guard.Trust)}
		case GuardPolicy:
			envelope.Policy=&evidence.RevisionPayload{Revision:string(guard.Policy),Revocation:"ACTIVE",SubjectEvidenceID:"evidence-cp_authorization"}
		case GuardTrust:
			envelope.Trust=&evidence.RevisionPayload{Revision:string(guard.Trust),Revocation:"ACTIVE",SubjectEvidenceID:"evidence-cp_authorization"}
		case GuardMembership:
			envelope.Membership=&evidence.MembershipPayload{DomainID:"synthetic-domain",Revision:string(guard.Membership),State:"MEMBER"}
		case GuardOwnership,GuardFence:
			payload:=&evidence.OwnershipPayload{OwnerID:"synthetic-owner",OwnershipEpoch:string(guard.OwnershipEpoch),FenceEpoch:string(guard.FenceEpoch),BootID:string(guard.BootID),ProcessIncarnation:string(guard.ProcessIncarnation),State:"CURRENT"}
			if kind==GuardOwnership{envelope.Ownership=payload}else{envelope.Fence=payload}
		case GuardGeneration:
			envelope.Generation=&evidence.GenerationPayload{Generation:string(guard.Generation),State:"ACTIVE"}
		case GuardBoot:
			envelope.Boot=&evidence.BootPayload{BootID:string(guard.BootID),ActorID:"synthetic-executor",ActorRole:"LOCAL_EXECUTOR"}
		case GuardProcess:
			envelope.Process=&evidence.ProcessPayload{BootID:string(guard.BootID),ProcessID:base.identity.value.ProcessID,StartTicks:base.identity.value.StartTicks,Incarnation:string(guard.ProcessIncarnation),ActorID:"synthetic-executor",ActorRole:"LOCAL_EXECUTOR"}
		case GuardPAdmission:
			envelope.PAdmission=&evidence.PAdmissionPayload{AdmissionEpoch:"synthetic-admission-epoch",State:"OPEN",Consumption:"UNCONSUMED",Revocation:"ACTIVE"}
		case GuardDrain:
			envelope.Drain=&evidence.DrainPayload{DomainID:"synthetic-domain",ResourceIDs:[]string{string(command.Scope.Resource)},DrainEpoch:"synthetic-drain-epoch",MembershipRevision:string(guard.Membership),State:"READY",Seal:"synthetic-drain-seal",CompletionProof:"synthetic-completion-proof"}
		case GuardCandidate:
			envelope.Candidate=&evidence.CandidatePayload{CandidateID:"synthetic-candidate",Approval:"APPROVED",Revision:string(command.CandidateRevision),ContentHash:string(command.CandidateContentPin),ResourceID:string(command.Scope.Resource),ApproverID:"synthetic-approver"}
		case GuardBusiness:
			envelope.BusinessAdmission=&evidence.BusinessAdmissionPayload{State:"CLOSED",AuthorityRevision:"synthetic-business-revision"}
		}
		encoded,err:=evidence.Encode(envelope);if err!=nil{t.Fatal("invalid synthetic canonical fixture",kind,err)}
		f.delivery.encoded=append(f.delivery.encoded,encoded)
	}
	f.issue(t,true)
	return f
}

func(f *contractsTestFixture) issue(t *testing.T,updateCurrent bool){
	t.Helper()
	f.delivery.mu.Lock();encoded:=contractsTestCopyBytes(f.delivery.encoded);f.delivery.mu.Unlock()
	f.verification.mu.Lock();defer f.verification.mu.Unlock()
	for _,raw:=range encoded{
		envelope,err:=evidence.Decode(raw)
		if err!=nil{t.Fatal("invalid synthetic issued fixture",err)}
		f.verification.issued[envelope.EvidenceID]=contractsTestIssued{typed:evidence.Clone(envelope),raw:append([]byte(nil),raw...)}
		if updateCurrent{f.verification.current[envelope.EvidenceID]=evidence.Clone(envelope)}
	}
}

func(f *contractsTestFixture) change(t *testing.T,kind evidence.Kind,change func(*evidence.Envelope)){
	t.Helper()
	f.delivery.mu.Lock();defer f.delivery.mu.Unlock()
	for index,raw:=range f.delivery.encoded{
		envelope,err:=evidence.Decode(raw);if err!=nil{t.Fatal(err)}
		if envelope.Kind!=kind{continue}
		change(&envelope)
		// Invalid wire proposals deliberately use Marshal, so the product Decoder
		// rather than the fixture Encoder is responsible for refusing them.
		encoded,err:=json.Marshal(envelope);if err!=nil{t.Fatal(err)}
		f.delivery.encoded[index]=encoded
		return
	}
	t.Fatal("synthetic kind missing")
}

func(f *contractsTestFixture) open(t *testing.T){
	t.Helper()
	port:=sqliteTestOpen(t,f.fixture)
	port.continuity=f.continuity
	reader,err:=NewContractsGuardEvidenceSource(f.config,f.delivery);if err!=nil{t.Fatal(err)}
	auth,err:=NewContractsGuardEvidenceAuthenticator(f.config,f.verification);if err!=nil{t.Fatal(err)}
	adapter,err:=NewGuardEvidenceAdapter(f.config,reader,auth,f.identity,f.verifier,f.verifier);if err!=nil{t.Fatal(err)}
	checker,err:=NewConditionalCommitPreflight(port,f.authorizer,adapter,adapter);if err!=nil{t.Fatal(err)}
	f.port,f.adapter,f.checker=port,adapter,checker
	f.reader,f.contractsAuth=reader,auth
}

func(f *contractsTestFixture) check(t *testing.T)PreflightResult{
	t.Helper()
	result,_:=f.checker.Check(context.Background(),LookupRequest{Call:readTestCall(),Request:f.request})
	if result.AuthorizesMutation()||result.ReusableForCommit(){t.Fatal("candidate evidence granted Mutation authority")}
	return result
}

func TestSQLiteContractsSyntheticC10Interoperation(t *testing.T){
	f:=contractsTestNew(t);f.open(t)
	if result:=f.check(t);result.Status!=PreflightEligible{t.Fatalf("status=%s reason=%s",result.Status,result.Reason)}
	f.verification.mu.Lock()
	integrity,validity,revocation:=f.verification.integrityCalls,f.verification.validityCalls,f.verification.revocationCalls
	f.verification.mu.Unlock()
	if integrity!=13||validity!=13||revocation!=13{t.Fatalf("incomplete verifier calls: %d/%d/%d",integrity,validity,revocation)}
	f.delivery.mu.Lock();reads:=f.delivery.reads;f.delivery.mu.Unlock()
	if reads!=2{t.Fatalf("delivery reads=%d; expected observation and verification recheck",reads)}
	if f.port.owner.writerConfigured||f.port.owner.writePool!=nil{t.Fatal("contract read opened Writer admission")}
}

func TestSQLiteContractsHeadersPinnedToRequestAndOwners(t *testing.T){
	for _,name:=range []string{"issuer","audience","scope","execution","binding","frame"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		f.change(t,evidence.CPAuthorizationKind,func(e *evidence.Envelope){
			switch name{case "issuer":e.Issuer="another-issuer";case "audience":e.Audience="another-executor";case "scope":e.Scope.Host="another-host";case "execution":e.Execution.AttemptID="another-attempt";case "binding":e.Binding="another-binding";case "frame":e.Frame.SnapshotID="another-frame"}
		})
		f.issue(t,false);f.open(t);guardEvidenceTestIneligible(t,f.check(t))
	})}
}

func TestSQLiteContractsPolicyTrustAndEvidenceAnchor(t *testing.T){
	for _,name:=range []string{"policy","trust","policy-anchor","trust-anchor","cp-policy","cp-trust"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		kind:=evidence.PolicyKind;if strings.HasPrefix(name,"trust"){kind=evidence.TrustKind};if strings.HasPrefix(name,"cp-"){kind=evidence.CPAuthorizationKind}
		f.change(t,kind,func(e *evidence.Envelope){
			switch name{case "policy":e.Policy.Revision="another-policy";case "trust":e.Trust.Revision="another-trust";case "policy-anchor":e.Policy.SubjectEvidenceID="another-evidence";case "trust-anchor":e.Trust.SubjectEvidenceID="another-evidence";case "cp-policy":e.CPAuthorization.PolicyRevision="another-policy";case "cp-trust":e.CPAuthorization.TrustRevision="another-trust"}
		})
		f.issue(t,false);f.open(t);guardEvidenceTestIneligible(t,f.check(t))
	})}
}

func TestSQLiteContractsOwnershipFenceBootAndIncarnation(t *testing.T){
	for _,name:=range []string{"ownership","fence","boot","incarnation","owner-actor","agent-role","pid","start-ticks"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		kind:=evidence.OwnershipKind
		switch name{case "fence":kind=evidence.FenceKind;case "boot":kind=evidence.BootKind;case "incarnation","owner-actor","agent-role","pid","start-ticks":kind=evidence.ProcessKind}
		f.change(t,kind,func(e *evidence.Envelope){
			switch name{case "ownership":e.Ownership.OwnershipEpoch="another-epoch";case "fence":e.Fence.FenceEpoch="another-fence";case "boot":e.Boot.BootID="older-boot";case "incarnation":e.Process.Incarnation="older-incarnation";case "owner-actor":e.Process.ActorID="another-actor";case "agent-role":e.Process.ActorRole="HOST_AGENT";case "pid":e.Process.ProcessID++;case "start-ticks":e.Process.StartTicks++}
		})
		f.issue(t,false);f.open(t);guardEvidenceTestIneligible(t,f.check(t))
	})}
}

func TestSQLiteContractsAdmissionAndDrainAreNotBusinessAdmission(t *testing.T){
	for _,name:=range []string{"p-revoked","p-consumed","p-closed","p-unknown","drain-seal","drain-epoch","drain-membership","drain-domain","drain-held"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		kind:=evidence.PAdmissionKind;if strings.HasPrefix(name,"drain-"){kind=evidence.DrainKind}
		f.change(t,kind,func(e *evidence.Envelope){
			switch name{
			case "p-revoked":e.PAdmission.Revocation="REVOKED"
			case "p-consumed":e.PAdmission.Consumption="CONSUMED"
			case "p-closed":e.PAdmission.State="CLOSED"
			case "p-unknown":e.PAdmission.State="UNKNOWN"
			case "drain-seal":e.Drain.Seal="wrong-seal"
			case "drain-epoch":e.Drain.DrainEpoch="wrong-drain-epoch"
			case "drain-membership":e.Drain.MembershipRevision="wrong-membership"
			case "drain-domain":e.Drain.DomainID="wrong-domain"
			case "drain-held":e.Drain.State="HELD";e.Drain.Seal="";e.Drain.CompletionProof=""
			}
		})
		f.issue(t,false);f.open(t);guardEvidenceTestIneligible(t,f.check(t))
	})}
}

func TestSQLiteContractsCandidateAndBusinessUnknown(t *testing.T){
	for _,name:=range []string{"candidate-content","candidate-revision","candidate-unapproved","business-unknown"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		kind:=evidence.CandidateKind;if name=="business-unknown"{kind=evidence.BusinessAdmissionKind}
		f.change(t,kind,func(e *evidence.Envelope){
			switch name{case "candidate-content":e.Candidate.ContentHash="wrong-content";case "candidate-revision":e.Candidate.Revision="wrong-revision";case "candidate-unapproved":e.Candidate.Approval="PENDING";e.Candidate.ApproverID="";case "business-unknown":e.BusinessAdmission.State="UNKNOWN"}
		})
		f.issue(t,false);f.open(t);guardEvidenceTestIneligible(t,f.check(t))
	})}
}

func TestSQLiteContractsUnknownExpiryClockAndRevocation(t *testing.T){
	for _,name:=range []string{"expiry-unknown","expired","clock-unknown","revocation-unknown"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		switch name{
		case "expiry-unknown":f.change(t,evidence.CPAuthorizationKind,func(e *evidence.Envelope){e.Validity=evidence.Validity{Status:"UNKNOWN"}});f.issue(t,false)
		case "expired":f.verification.tick=100
		case "clock-unknown":f.verification.clockKnown=false
		case "revocation-unknown":f.verification.revocationKnown=false
		}
		f.open(t)
		ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
		result,_:=f.checker.Check(ctx,LookupRequest{Call:readTestCall(),Request:f.request})
		if result.Status!=PreflightUnknown{t.Fatalf("unqualified evidence became %s/%s",result.Status,result.Reason)}
	})}
}

func TestSQLiteContractsProofForgeryAndPayloadModification(t *testing.T){
	for _,name:=range []string{"proof","key-id","key-revision","authentication-profile","payload"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		f.change(t,evidence.CPAuthorizationKind,func(e *evidence.Envelope){
			switch name{case "proof":e.Integrity.Proof="unissued-proof";case "key-id":e.Integrity.KeyID="unissued-key";case "key-revision":e.Integrity.KeyRevision="unissued-revision";case "authentication-profile":e.Integrity.ProfileID="unselected-profile";case "payload":e.CPAuthorization.Decision="DENIED"}
		})
		// Do not register these bytes: nonempty proof metadata cannot issue them.
		f.open(t);sqlitePreflightCheck(t,f.checker,f.request,PreflightUnknown)
	})}
}

func TestSQLiteContractsGuardAndContinuityCannotSubstitute(t *testing.T){
	t.Run("missing-independent-source",func(t *testing.T){
		f:=contractsTestNew(t);f.open(t);f.port.continuity=nil;sqlitePreflightCheck(t,f.checker,f.request,PreflightUnknown)
	})
	t.Run("guard-id-as-witness-proof",func(t *testing.T){
		f:=contractsTestNew(t)
		f.continuity.afterAttest=func(o *PreflightContinuityObservation){o.Proof="evidence-cp_authorization"}
		f.open(t);sqlitePreflightCheck(t,f.checker,f.request,PreflightUnknown)
	})
	t.Run("guard-auth-has-no-continuity-role",func(t *testing.T){
		f:=contractsTestNew(t);f.open(t)
		if _,ok:=any(f.contractsAuth).(PreflightContinuityVerifier);ok{t.Fatal("Guard authenticator gained implicit Continuity authority")}
	})
}

func TestSQLiteContractsMissingProducerOrVerifierIsUnknown(t *testing.T){
	for _,name:=range []string{"delivery","integrity-verifier"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		port:=sqliteTestOpen(t,f.fixture);port.continuity=f.continuity
		var delivery GuardEnvelopeReadPort=f.delivery
		var verifier GuardEnvelopeVerifier=f.verification
		if name=="delivery"{delivery=nil}else{verifier=nil}
		reader,err:=NewContractsGuardEvidenceSource(f.config,delivery);if err!=nil{t.Fatal(err)}
		auth,err:=NewContractsGuardEvidenceAuthenticator(f.config,verifier);if err!=nil{t.Fatal(err)}
		adapter,err:=NewGuardEvidenceAdapter(f.config,reader,auth,f.identity,f.verifier,f.verifier);if err!=nil{t.Fatal(err)}
		checker,err:=NewConditionalCommitPreflight(port,f.authorizer,adapter,adapter);if err!=nil{t.Fatal(err)}
		sqlitePreflightCheck(t,checker,f.request,PreflightUnknown)
	})}
}

func TestSQLiteContractsContextCancellation(t *testing.T){
	t.Run("before-acquisition",func(t *testing.T){
		f:=contractsTestNew(t);f.open(t)
		ctx,cancel:=context.WithCancel(context.Background());cancel()
		result,err:=f.checker.Check(ctx,LookupRequest{Call:readTestCall(),Request:f.request})
		if result.Status!=PreflightUnknown||!errors.Is(err,context.Canceled){t.Fatal("canceled evidence request was not stopped")}
		if f.delivery.reads!=0{t.Fatal("canceled request fetched evidence")}
	})
	t.Run("during-acquisition",func(t *testing.T){
		f:=contractsTestNew(t);f.open(t)
		entered:=make(chan struct{})
		f.delivery.onRead=func(ctx context.Context,_ int)error{close(entered);<-ctx.Done();return ctx.Err()}
		deadline,stop:=context.WithTimeout(context.Background(),10*time.Second);defer stop()
		ctx,cancel:=context.WithCancel(deadline);defer cancel()
		done:=make(chan PreflightResult,1)
		go func(){result,_:=f.checker.Check(ctx,LookupRequest{Call:readTestCall(),Request:f.request});done<-result}()
		sqliteLifecycleAwait(t,deadline,entered);cancel()
		select{case result:=<-done:if result.Status!=PreflightUnknown{t.Fatal("canceled acquisition became eligible")};case <-deadline.Done():t.Fatal("canceled acquisition did not settle")}
		sqliteInspectionCount(t,f.port.InspectLifecycle().ActiveOperations,0)
	})
}

func TestSQLiteContractsAcquisitionAndVerificationChangesAreUnknown(t *testing.T){
	for _,name:=range []string{"during-second-read","after-integrity"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		if name=="during-second-read"{
			f.delivery.onRead=func(_ context.Context,number int)error{if number==2{f.change(t,evidence.DrainKind,func(e *evidence.Envelope){e.Drain.Seal="new-seal"})};return nil}
		}else{
			f.verification.onIntegrity=func(number int){if number==13{f.change(t,evidence.DrainKind,func(e *evidence.Envelope){e.Drain.Seal="new-seal"})}}
		}
		f.open(t);sqlitePreflightCheck(t,f.checker,f.request,PreflightUnknown)
	})}
}

func TestSQLiteContractsRetainsOriginalBytesAndRejectsProjectionTamper(t *testing.T){
	f:=contractsTestNew(t);f.open(t)
	raw,err:=f.port.readPreflightSnapshot(context.Background(),f.request);if err!=nil{t.Fatal(err)}
	frame:=sqliteFrameFromEvidence(raw.Snapshot.Evidence)
	bundle,err:=f.reader.ReadGuardEvidence(context.Background(),f.request,frame);if err!=nil{t.Fatal(err)}
	if bundle.Knowledge!=Known||len(bundle.EncodedEvidence)!=13{t.Fatal("complete original evidence was not retained")}
	if err:=f.contractsAuth.VerifyGuardEvidence(context.Background(),f.request,raw,bundle);err!=nil{t.Fatal("exact candidate bundle failed",err)}
	copy:=cloneGuardEvidenceBundle(bundle)
	copy.Claims[0].Condition=PreflightConditionDenied
	if err:=f.contractsAuth.VerifyGuardEvidence(context.Background(),f.request,raw,copy);err==nil{t.Fatal("projection changed without authenticated raw bytes")}
	copy=cloneGuardEvidenceBundle(bundle)
	original:=append([]byte(nil),bundle.EncodedEvidence[0]...)
	copy.EncodedEvidence[0][0]='['
	if !bytes.Equal(bundle.EncodedEvidence[0],original){t.Fatal("raw evidence clone shared mutable bytes")}
	if err:=f.contractsAuth.VerifyGuardEvidence(context.Background(),f.request,raw,copy);err==nil{t.Fatal("changed raw evidence was accepted")}
}

func TestSQLiteContractsDuplicateEvidenceCannotHideCoverage(t *testing.T){
	for _,name:=range []string{"duplicate-kind","duplicate-id","partial"}{t.Run(name,func(t *testing.T){
		f:=contractsTestNew(t)
		switch name{
		case "duplicate-kind":f.delivery.encoded[1]=append([]byte(nil),f.delivery.encoded[0]...)
		case "duplicate-id":f.change(t,evidence.PolicyKind,func(e *evidence.Envelope){e.EvidenceID="evidence-cp_authorization"})
		case "partial":f.delivery.encoded=f.delivery.encoded[:12]
		}
		f.open(t);guardEvidenceTestIneligible(t,f.check(t))
	})}
}

func TestSQLiteContractsReadsPreserveDatabaseAndDoNotRetry(t *testing.T){
	f:=contractsTestNew(t)
	if err:=f.fixture.writer.Close();err!=nil{t.Fatal(err)}
	before,err:=os.ReadFile(f.fixture.path);if err!=nil{t.Fatal(err)}
	beforeHash:=sha256.Sum256(before)
	f.open(t)
	if result:=f.check(t);result.Status!=PreflightEligible{t.Fatal("synthetic complete contract failed")}
	f.delivery.mu.Lock();f.delivery.err=errors.New("SECRET /private/cp.sqlite SELECT credential");beforeReads:=f.delivery.reads;f.delivery.mu.Unlock()
	result,err:=f.checker.Check(context.Background(),LookupRequest{Call:readTestCall(),Request:f.request})
	if result.Status!=PreflightUnknown{t.Fatal("delivery failure became eligible")}
	public,_:=json.Marshal(result)
	for _,private:=range []string{"SECRET","/private","SELECT","credential"}{if strings.Contains(string(public),private)||(err!=nil&&strings.Contains(err.Error(),private)){t.Fatal("private delivery data escaped")}}
	f.delivery.mu.Lock();afterReads:=f.delivery.reads;f.delivery.mu.Unlock()
	if afterReads-beforeReads!=1{t.Fatal("failed evidence fetch retried automatically")}
	if err:=f.port.Close();err!=nil{t.Fatal(err)}
	after,err:=os.ReadFile(f.fixture.path);if err!=nil{t.Fatal(err)}
	if sha256.Sum256(after)!=beforeHash{t.Fatal("evidence contract read modified Reference, Receipt, History or DB bytes")}
}
