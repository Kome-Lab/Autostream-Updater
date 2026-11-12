package registry

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// These fixtures exercise the product adapter boundary with SYNTHETIC owners,
// signatures and ticks. They do not demonstrate a deployed C03 issuer, C09 wire,
// real cryptographic Verifier, independent Continuity store or trusted clock.
type guardEvidenceTestSource struct {
	mu     sync.Mutex
	bundle GuardEvidenceBundle
	reads  int
	onRead func(context.Context, int) error
	err    error
}

func guardEvidenceTestClone(bundle GuardEvidenceBundle) GuardEvidenceBundle {
	bundle.Claims = append([]GuardEvidenceClaim(nil), bundle.Claims...)
	return bundle
}

func (s *guardEvidenceTestSource) ReadGuardEvidence(ctx context.Context, _ Request, _ BackendReadFrame) (GuardEvidenceBundle, error) {
	if err := ctx.Err(); err != nil {
		return GuardEvidenceBundle{Knowledge: Unknown}, err
	}
	s.mu.Lock()
	s.reads++
	number, hook, err := s.reads, s.onRead, s.err
	bundle := guardEvidenceTestClone(s.bundle)
	s.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, number); err != nil {
			return GuardEvidenceBundle{Knowledge: Unknown}, err
		}
	}
	if err != nil {
		return GuardEvidenceBundle{Knowledge: Unknown}, err
	}
	return bundle, nil
}

func (s *guardEvidenceTestSource) change(change func(*GuardEvidenceBundle)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	change(&s.bundle)
}

type guardEvidenceTestIdentity struct {
	mu       sync.Mutex
	value    LocalExecutorIdentity
	reads    int
	changeOn int
	err      error
}

func (s *guardEvidenceTestIdentity) ReadLocalIdentity(ctx context.Context) (LocalExecutorIdentity, error) {
	if err := ctx.Err(); err != nil {
		return LocalExecutorIdentity{Knowledge: Unknown}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.err != nil {
		return LocalExecutorIdentity{Knowledge: Unknown}, s.err
	}
	value := s.value
	if s.changeOn > 0 && s.reads >= s.changeOn {
		value.StartTicks++
	}
	return value, nil
}

type guardEvidenceTestAuth struct {
	attestations     *sqlitePreflightAttestations
	tick             uint64
	validityKnown    bool
	expectedSnapshot *PreflightSnapshot
	snapshotProof    ID
	onVerify         func()
	err              error
}

func guardEvidenceTestPayload(request Request, frame BackendReadFrame, bundle GuardEvidenceBundle) any {
	bundle.Proof = ""
	return struct {
		Request Request
		Frame   BackendReadFrame
		Bundle  GuardEvidenceBundle
	}{request, frame, bundle}
}

func (a *guardEvidenceTestAuth) VerifyGuardEvidence(ctx context.Context, request Request, raw PreflightSnapshot, bundle GuardEvidenceBundle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.err != nil {
		return a.err
	}
	frame := sqliteFrameFromEvidence(raw.Snapshot.Evidence)
	// A separate trusted test attestation binds the ENTIRE detached SQL payload,
	// not just its Frame. This is synthetic freshness, not a product authority.
	if a.expectedSnapshot == nil || !reflect.DeepEqual(clonePreflightSnapshot(*a.expectedSnapshot), clonePreflightSnapshot(raw)) ||
		!a.attestations.verifies(a.snapshotProof, clonePreflightSnapshot(raw)) {
		return errors.New("synthetic full snapshot association is unknown")
	}
	if !a.attestations.verifies(bundle.Proof, guardEvidenceTestPayload(request, frame, bundle)) {
		return errors.New("synthetic complete Guard payload was not issued")
	}
	// This is an isolated clock DOUBLE, never Context.Deadline or D1.
	if !a.validityKnown {
		return errors.New("synthetic validity is unknown")
	}
	for _, claim := range bundle.Claims {
		if claim.Validity.TimeBase != "synthetic-guard-clock" || claim.Validity.BootID != request.Command.RequiredGuard.BootID || claim.Validity.Proof != "synthetic-validity-proof" ||
			claim.Validity.IssuedTick > a.tick || a.tick >= claim.Validity.ExpiresTick {
			return errors.New("synthetic current validity rejected")
		}
	}
	if a.onVerify != nil {
		a.onVerify()
	}
	return nil
}

type guardEvidenceTestFixture struct {
	*sqlitePreflightFixture
	config   GuardEvidenceConfig
	source   *guardEvidenceTestSource
	auth     *guardEvidenceTestAuth
	identity *guardEvidenceTestIdentity
	port     *SQLiteReadPort
	adapter  *GuardEvidenceAdapter
	checker  *ConditionalCommitPreflight
}

func guardEvidenceTestKinds() []GuardEvidenceKind {
	return []GuardEvidenceKind{GuardCPAuthorization, GuardPolicy, GuardTrust, GuardMembership,
		GuardOwnership, GuardFence, GuardGeneration, GuardBoot, GuardProcess, GuardPAdmission,
		GuardDrain, GuardCandidate, GuardBusiness}
}

func guardEvidenceTestNew(t *testing.T) *guardEvidenceTestFixture {
	t.Helper()
	preflight := sqlitePreflightNew(t)
	request := preflight.request
	identity := LocalExecutorIdentity{Knowledge: Known, BootID: request.Command.RequiredGuard.BootID, ProcessID: 7001, StartTicks: 321}
	config := GuardEvidenceConfig{Scope: request.Command.Scope, Audience: "synthetic-c10-audience"}
	bundle := GuardEvidenceBundle{Knowledge: Known, Scope: request.Command.Scope, Execution: request.Command.Execution,
		Binding: request.Binding, Frame: sqliteTestFrame(preflight.fixture.snapshot.Evidence)}
	guard := request.Command.RequiredGuard
	for _, kind := range guardEvidenceTestKinds() {
		issuer := ID("synthetic-owner-" + string(kind))
		if kind == GuardCPAuthorization {
			issuer = request.Command.AuthorizationIssuer
		}
		config.Issuers = append(config.Issuers, GuardEvidenceIssuer{Kind: kind, Issuer: issuer})
		claim := GuardEvidenceClaim{Kind: kind, Issuer: issuer, Audience: config.Audience,
			Validity: GuardEvidenceValidity{TimeBase: "synthetic-guard-clock", BootID: guard.BootID, IssuedTick: 10, ExpiresTick: 100, Proof: "synthetic-validity-proof"},
			Proof:    "synthetic-claim-proof", Condition: PreflightConditionValid}
		switch kind {
		case GuardPolicy:
			claim.Revision = guard.Policy
		case GuardTrust:
			claim.Revision = guard.Trust
		case GuardMembership:
			claim.Revision = guard.Membership
		case GuardOwnership:
			claim.Revision = guard.OwnershipEpoch
		case GuardFence:
			claim.Revision = guard.FenceEpoch
		case GuardGeneration:
			claim.Revision = guard.Generation
		case GuardBoot:
			claim.Revision = guard.BootID
		case GuardProcess:
			claim.Revision, claim.LocalIdentity = guard.ProcessIncarnation, identity
		case GuardDrain:
			claim.Condition, claim.Drain, claim.DrainSeal = "", PreflightDrainReady, "synthetic-drain-seal"
		case GuardCandidate:
			claim.CandidateRevision, claim.CandidateContentPin = request.Command.CandidateRevision, request.Command.CandidateContentPin
		case GuardBusiness:
			claim.Condition, claim.BusinessAdmission = "", PreflightBusinessClosed
		}
		bundle.Claims = append(bundle.Claims, claim)
	}
	f := &guardEvidenceTestFixture{sqlitePreflightFixture: preflight, config: config,
		source:   &guardEvidenceTestSource{bundle: bundle},
		auth:     &guardEvidenceTestAuth{attestations: preflight.attestations, tick: 50, validityKnown: true},
		identity: &guardEvidenceTestIdentity{value: identity}}
	f.sign()
	return f
}

func (f *guardEvidenceTestFixture) sign() {
	f.source.mu.Lock()
	defer f.source.mu.Unlock()
	f.source.bundle.Proof = f.attestations.attest(guardEvidenceTestPayload(f.request, f.source.bundle.Frame, f.source.bundle))
}

func (f *guardEvidenceTestFixture) claim(kind GuardEvidenceKind, change func(*GuardEvidenceClaim)) {
	f.source.change(func(bundle *GuardEvidenceBundle) {
		for index := range bundle.Claims {
			if bundle.Claims[index].Kind == kind {
				change(&bundle.Claims[index])
				return
			}
		}
	})
}

func (f *guardEvidenceTestFixture) captureSnapshot(t *testing.T, port *SQLiteReadPort) {
	t.Helper()
	raw, err := port.readPreflightSnapshot(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	detached := clonePreflightSnapshot(raw)
	f.auth.expectedSnapshot = &detached
	f.auth.snapshotProof = f.attestations.attest(clonePreflightSnapshot(detached))
}

func (f *guardEvidenceTestFixture) open(t *testing.T) {
	t.Helper()
	port := sqliteTestOpen(t, f.fixture)
	port.continuity = f.continuity
	f.captureSnapshot(t, port)
	adapter, err := NewGuardEvidenceAdapter(f.config, f.source, f.auth, f.identity, f.verifier, f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := NewConditionalCommitPreflight(port, f.authorizer, adapter, adapter)
	if err != nil {
		t.Fatal(err)
	}
	f.port, f.adapter, f.checker = port, adapter, checker
}

func (f *guardEvidenceTestFixture) result(t *testing.T) PreflightResult {
	t.Helper()
	result, _ := f.checker.Check(context.Background(), LookupRequest{Call: readTestCall(), Request: f.request})
	if result.AuthorizesMutation() || result.ReusableForCommit() {
		t.Fatal("Guard read issued mutation authority")
	}
	return result
}

func guardEvidenceTestIneligible(t *testing.T, result PreflightResult) {
	t.Helper()
	if result.Status != PreflightUnknown && result.Status != PreflightConflict && result.Status != PreflightRejected {
		t.Fatalf("ineligible evidence became %s (%s)", result.Status, result.Reason)
	}
}

func TestSQLiteGuardEvidenceSyntheticHappyPath(t *testing.T) {
	f := guardEvidenceTestNew(t)
	f.open(t)
	result := f.result(t)
	if result.Status != PreflightEligible {
		t.Fatalf("synthetic boundary result=%s reason=%s", result.Status, result.Reason)
	}
	f.source.mu.Lock()
	reads := f.source.reads
	f.source.mu.Unlock()
	if reads != 2 {
		t.Fatalf("source reads=%d; want observation and one verification reread", reads)
	}
	if f.port.InspectLifecycle().State != LifecycleOpen {
		t.Fatal("Guard inspection changed Owner state")
	}
}

func TestSQLiteGuardEvidenceMissingAndForgedCPAuthorization(t *testing.T) {
	for _, mode := range []string{"missing", "forged-payload", "forged-proof", "wrong-issuer", "legacy-issuer"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			switch mode {
			case "missing":
				f.source.change(func(bundle *GuardEvidenceBundle) { bundle.Claims = bundle.Claims[1:] })
				f.sign()
			case "forged-payload":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Condition = PreflightConditionDenied })
			case "forged-proof":
				f.source.change(func(bundle *GuardEvidenceBundle) { bundle.Proof = "unissued-proof" })
			case "wrong-issuer", "legacy-issuer":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Issuer = "v2-updater-mutation-grant" })
				f.sign()
			}
			f.open(t)
			guardEvidenceTestIneligible(t, f.result(t))
		})
	}
}

func TestSQLiteGuardEvidenceAudienceAndIdentity(t *testing.T) {
	for _, mode := range []string{"audience", "scope", "execution", "binding", "frame", "request-issuer"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			switch mode {
			case "audience":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Audience = "another-executor" })
			case "scope":
				f.source.change(func(bundle *GuardEvidenceBundle) { bundle.Scope.Resource = "another-resource" })
			case "execution":
				f.source.change(func(bundle *GuardEvidenceBundle) { bundle.Execution.AttemptID = "another-attempt" })
			case "binding":
				f.source.change(func(bundle *GuardEvidenceBundle) { bundle.Binding = Binding("different-binding") })
			case "frame":
				f.source.change(func(bundle *GuardEvidenceBundle) { bundle.Frame.SnapshotID = "another-frame" })
			case "request-issuer":
				f.request.Command.AuthorizationIssuer = "unconfigured-authority"
				sqlitePreflightRebind(t, &f.request)
			}
			f.sign()
			f.open(t)
			guardEvidenceTestIneligible(t, f.result(t))
		})
	}
}

func TestSQLiteGuardEvidenceRevisionsAndCurrentIdentity(t *testing.T) {
	for _, kind := range []GuardEvidenceKind{GuardPolicy, GuardTrust, GuardMembership, GuardOwnership, GuardFence, GuardGeneration, GuardBoot, GuardProcess} {
		t.Run(string(kind), func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			f.claim(kind, func(claim *GuardEvidenceClaim) { claim.Revision = "stale-revision" })
			f.sign()
			f.open(t)
			guardEvidenceTestIneligible(t, f.result(t))
		})
	}
}

func TestSQLiteGuardEvidenceCurrentOSIdentityRequired(t *testing.T) {
	for _, mode := range []string{"boot-changed", "pid-changed", "start-changed", "read-failed", "unknown", "changed-during-verification"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			switch mode {
			case "boot-changed":
				f.identity.value.BootID = "new-boot"
			case "pid-changed":
				f.identity.value.ProcessID++
			case "start-changed":
				f.identity.value.StartTicks++
			case "read-failed":
				f.identity.err = errors.New("private OS identity failure")
			case "unknown":
				f.identity.value.Knowledge = Unknown
			case "changed-during-verification":
				f.identity.changeOn = 2
			}
			f.open(t)
			guardEvidenceTestIneligible(t, f.result(t))
		})
	}
}

func TestSQLiteGuardEvidenceMembershipAdmissionDrainAndCandidate(t *testing.T) {
	for _, mode := range []string{"membership-revoked", "p-denied", "drain-not-ready", "drain-held", "drain-seal-missing", "candidate-unapproved", "candidate-revision", "candidate-content"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			switch mode {
			case "membership-revoked":
				f.claim(GuardMembership, func(claim *GuardEvidenceClaim) { claim.Condition = PreflightConditionDenied })
			case "p-denied":
				f.claim(GuardPAdmission, func(claim *GuardEvidenceClaim) { claim.Condition = PreflightConditionDenied })
			case "drain-not-ready":
				f.claim(GuardDrain, func(claim *GuardEvidenceClaim) { claim.Drain, claim.DrainSeal = PreflightDrainNotReady, "" })
			case "drain-held":
				f.claim(GuardDrain, func(claim *GuardEvidenceClaim) { claim.Drain, claim.DrainSeal = PreflightDrainHeld, "" })
			case "drain-seal-missing":
				f.claim(GuardDrain, func(claim *GuardEvidenceClaim) { claim.DrainSeal = "" })
			case "candidate-unapproved":
				f.claim(GuardCandidate, func(claim *GuardEvidenceClaim) { claim.Condition = PreflightConditionDenied })
			case "candidate-revision":
				f.claim(GuardCandidate, func(claim *GuardEvidenceClaim) { claim.CandidateRevision = "another-candidate" })
			case "candidate-content":
				f.claim(GuardCandidate, func(claim *GuardEvidenceClaim) { claim.CandidateContentPin = "another-content" })
			}
			f.sign()
			f.open(t)
			guardEvidenceTestIneligible(t, f.result(t))
		})
	}
}

func TestSQLiteGuardEvidenceValidityIsNotContextDeadlineOrD1(t *testing.T) {
	for _, mode := range []string{"missing-time-base", "missing-validity-proof", "invalid-interval", "current-validity-unknown", "expired", "not-yet-issued", "unknown-clock", "wrong-clock-boot"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			switch mode {
			case "missing-time-base":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Validity.TimeBase = "" })
			case "missing-validity-proof":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Validity.Proof = "" })
			case "invalid-interval":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Validity.ExpiresTick = claim.Validity.IssuedTick })
			case "current-validity-unknown":
				f.auth.validityKnown = false
			case "expired":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Validity.ExpiresTick = 49 })
			case "not-yet-issued":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Validity.IssuedTick = 51 })
			case "unknown-clock":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Validity.TimeBase = "untrusted-clock" })
			case "wrong-clock-boot":
				f.claim(GuardCPAuthorization, func(claim *GuardEvidenceClaim) { claim.Validity.BootID = "another-clock-boot" })
			}
			f.sign()
			f.open(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			result, _ := f.checker.Check(ctx, LookupRequest{Call: readTestCall(), Request: f.request})
			guardEvidenceTestIneligible(t, result)
		})
	}
}

func TestSQLiteGuardEvidenceMissingDependenciesFailClosed(t *testing.T) {
	for _, mode := range []string{"source", "authenticator", "base", "continuity"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			port := sqliteTestOpen(t, f.fixture)
			port.continuity = f.continuity
			f.captureSnapshot(t, port)
			var source GuardEvidenceReadPort = f.source
			var auth GuardEvidenceAuthenticator = f.auth
			var base Verifier = f.verifier
			var continuity PreflightContinuityVerifier = f.verifier
			switch mode {
			case "source":
				source = nil
			case "authenticator":
				auth = nil
			case "base":
				base = nil
			case "continuity":
				continuity = nil
			}
			adapter, err := NewGuardEvidenceAdapter(f.config, source, auth, f.identity, base, continuity)
			if err != nil {
				t.Fatal(err)
			}
			checker, err := NewConditionalCommitPreflight(port, f.authorizer, adapter, adapter)
			if err != nil {
				t.Fatal(err)
			}
			result := sqlitePreflightCheck(t, checker, f.request, PreflightUnknown)
			if result.Status == PreflightEligible {
				t.Fatal("unconnected product evidence passed")
			}
		})
	}
}

func TestSQLiteGuardEvidenceMalformedDuplicateAndUnknownFacets(t *testing.T) {
	for _, mode := range []string{"duplicate", "unknown", "extra-payload", "empty-proof", "partial-knowledge", "too-many"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			f.source.change(func(bundle *GuardEvidenceBundle) {
				switch mode {
				case "duplicate":
					bundle.Claims[1] = bundle.Claims[0]
				case "unknown":
					bundle.Claims[1].Kind = GuardEvidenceKind("unknown-facet")
				case "extra-payload":
					bundle.Claims[0].CandidateContentPin = "not-applicable"
				case "empty-proof":
					bundle.Claims[0].Proof = ""
				case "partial-knowledge":
					bundle.Knowledge = Unknown
				case "too-many":
					bundle.Claims = append(bundle.Claims, bundle.Claims[0])
				}
			})
			f.sign()
			f.open(t)
			guardEvidenceTestIneligible(t, f.result(t))
		})
	}
}

func TestSQLiteGuardEvidenceFixedOwnersAndConfig(t *testing.T) {
	for _, mode := range []string{"scope", "audience", "missing-owner", "duplicate-owner", "unknown-owner-kind"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			switch mode {
			case "scope":
				f.config.Scope.Resource = ""
			case "audience":
				f.config.Audience = ""
			case "missing-owner":
				f.config.Issuers = f.config.Issuers[1:]
			case "duplicate-owner":
				f.config.Issuers[1] = f.config.Issuers[0]
			case "unknown-owner-kind":
				f.config.Issuers[0].Kind = GuardEvidenceKind("not-a-source")
			}
			if adapter, err := NewGuardEvidenceAdapter(f.config, f.source, f.auth, f.identity, f.verifier, f.verifier); err == nil || adapter != nil {
				t.Fatal("ambiguous or incomplete owner configuration accepted")
			}
		})
	}
}

func TestSQLiteGuardEvidenceFetchAndPostVerificationChange(t *testing.T) {
	for _, mode := range []string{"second-read", "after-auth", "fetch-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := guardEvidenceTestNew(t)
			switch mode {
			case "second-read":
				f.source.onRead = func(_ context.Context, number int) error {
					if number == 2 {
						return errors.New("synthetic source changed during acquisition")
					}
					return nil
				}
			case "after-auth":
				f.auth.onVerify = func() {
					f.source.change(func(bundle *GuardEvidenceBundle) { bundle.Claims[1].Revision = "new-effective-policy" })
					f.sign()
				}
			case "fetch-failure":
				f.source.err = errors.New("private credential or path must not leak")
			}
			f.open(t)
			guardEvidenceTestIneligible(t, f.result(t))
		})
	}
}

func TestSQLiteGuardEvidenceDetachedPayloadCannotBeForged(t *testing.T) {
	f := guardEvidenceTestNew(t)
	f.open(t)
	raw, err := f.port.readPreflightSnapshot(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	frame := sqliteFrameFromEvidence(raw.Snapshot.Evidence)
	observed, err := f.adapter.ObservePreflight(context.Background(), f.request, frame)
	if err != nil || observed.SourceEvidence == nil {
		t.Fatal("synthetic source observation failed")
	}
	observed.SourceEvidence.Claims[0].Condition = PreflightConditionDenied
	if err := f.adapter.VerifyPreflightGuard(context.Background(), f.request, raw, observed); err == nil {
		t.Fatal("changed detached evidence bypassed full-payload authentication")
	}
}

func TestSQLiteGuardEvidenceObservationIsDetachedFromSource(t *testing.T) {
	f := guardEvidenceTestNew(t)
	f.open(t)
	raw, err := f.port.readPreflightSnapshot(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	frame := sqliteFrameFromEvidence(raw.Snapshot.Evidence)
	observed, err := f.adapter.ObservePreflight(context.Background(), f.request, frame)
	if err != nil || observed.SourceEvidence == nil {
		t.Fatal("synthetic source observation failed")
	}
	saved := guardEvidenceTestClone(*observed.SourceEvidence)
	f.source.change(func(bundle *GuardEvidenceBundle) { bundle.Claims[0].Condition = PreflightConditionDenied })
	if !reflect.DeepEqual(saved, *observed.SourceEvidence) {
		t.Fatal("source changed already-detached evidence")
	}
	if err := f.adapter.VerifyPreflightGuard(context.Background(), f.request, raw, observed); err == nil {
		t.Fatal("source change after fetch was not detected")
	}
}

func TestSQLiteGuardEvidenceGuardAndContinuityAreSeparate(t *testing.T) {
	t.Run("missing-independent-port", func(t *testing.T) {
		f := guardEvidenceTestNew(t)
		f.open(t)
		f.port.continuity = nil
		sqlitePreflightCheck(t, f.checker, f.request, PreflightUnknown)
	})
	t.Run("partial-independent-coverage", func(t *testing.T) {
		f := guardEvidenceTestNew(t)
		f.continuity.change = func(value *PreflightContinuityObservation) { value.OutstandingCoverage = Unknown }
		f.open(t)
		sqlitePreflightCheck(t, f.checker, f.request, PreflightUnknown)
	})
	t.Run("guard-proof-not-continuity-proof", func(t *testing.T) {
		f := guardEvidenceTestNew(t)
		f.continuity.afterAttest = func(value *PreflightContinuityObservation) { value.Proof = f.source.bundle.Proof }
		f.open(t)
		sqlitePreflightCheck(t, f.checker, f.request, PreflightUnknown)
	})
}

func TestSQLiteGuardEvidenceContextCancellation(t *testing.T) {
	t.Run("before-fetch", func(t *testing.T) {
		f := guardEvidenceTestNew(t)
		f.open(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := f.checker.Check(ctx, LookupRequest{Call: readTestCall(), Request: f.request})
		if result.Status != PreflightUnknown || !errors.Is(err, context.Canceled) {
			t.Fatal("canceled Guard read was allowed")
		}
		f.source.mu.Lock()
		reads := f.source.reads
		f.source.mu.Unlock()
		if reads != 0 {
			t.Fatal("canceled request fetched evidence")
		}
	})
	t.Run("during-fetch", func(t *testing.T) {
		f := guardEvidenceTestNew(t)
		f.open(t)
		entered := make(chan struct{})
		f.source.onRead = func(ctx context.Context, _ int) error { close(entered); <-ctx.Done(); return ctx.Err() }
		deadline, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		ctx, cancel := context.WithCancel(deadline)
		defer cancel()
		done := make(chan PreflightResult, 1)
		go func() {
			result, _ := f.checker.Check(ctx, LookupRequest{Call: readTestCall(), Request: f.request})
			done <- result
		}()
		sqliteLifecycleAwait(t, deadline, entered)
		cancel()
		select {
		case result := <-done:
			if result.Status != PreflightUnknown {
				t.Fatal("canceled evidence fetch passed")
			}
		case <-deadline.Done():
			t.Fatal("canceled Guard fetch leaked operation")
		}
		sqliteInspectionCount(t, f.port.InspectLifecycle().ActiveOperations, 0)
	})
}

func TestSQLiteGuardEvidenceOwnerUnavailable(t *testing.T) {
	t.Run("uncertain", func(t *testing.T) {
		f := guardEvidenceTestNew(t)
		f.open(t)
		sqliteLifecycleSyntheticCleanup(t, f.port.owner, f.port.owner.pool.(*sql.DB), f.port.owner.header)
		f.port.owner.markUncertain()
		sqlitePreflightCheck(t, f.checker, f.request, PreflightUnknown)
	})
	t.Run("closing", func(t *testing.T) {
		f := guardEvidenceTestNew(t)
		f.open(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		operation, err := f.port.owner.acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer operation.release()
		closed := make(chan error, 1)
		go func() { closed <- f.port.Close() }()
		sqliteLifecycleAwait(t, ctx, f.port.owner.closingStarted)
		sqlitePreflightCheck(t, f.checker, f.request, PreflightRejected)
		operation.release()
		if err := sqliteLifecycleCloseResult(t, ctx, closed); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSQLiteGuardEvidenceReadsDoNotMutateRegistry(t *testing.T) {
	f := guardEvidenceTestNew(t)
	if err := f.fixture.writer.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(f.fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := sha256.Sum256(before)
	f.open(t)
	for range 3 {
		if result := f.result(t); result.Status != PreflightEligible {
			t.Fatal("synthetic complete Guard unexpectedly failed")
		}
	}
	if err := f.port.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(f.fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(after) != beforeHash {
		t.Fatal("Guard read changed Reference, Receipt, History or DB bytes")
	}
}

func TestSQLiteGuardEvidenceSafeErrorsAndNoRetry(t *testing.T) {
	f := guardEvidenceTestNew(t)
	f.source.err = errors.New("SECRET /private/database.sqlite SELECT * token")
	f.open(t)
	result, err := f.checker.Check(context.Background(), LookupRequest{Call: readTestCall(), Request: f.request})
	if result.Status != PreflightUnknown {
		t.Fatal("unavailable source passed")
	}
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	public := string(encoded)
	if err != nil {
		public += err.Error()
	}
	for _, private := range []string{"SECRET", "/private", "SELECT", "token"} {
		if strings.Contains(public, private) {
			t.Fatal("raw source error leaked into diagnostic")
		}
	}
	f.source.mu.Lock()
	reads := f.source.reads
	f.source.mu.Unlock()
	if reads != 1 {
		t.Fatal("source failure triggered automatic retry")
	}
}

func TestSQLiteGuardEvidenceExactSnapshotAssociation(t *testing.T) {
	f := guardEvidenceTestNew(t)
	f.open(t)
	raw, err := f.port.readPreflightSnapshot(context.Background(), f.request)
	if err != nil {
		t.Fatal(err)
	}
	frame := sqliteFrameFromEvidence(raw.Snapshot.Evidence)
	observed, err := f.adapter.ObservePreflight(context.Background(), f.request, frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.adapter.VerifyPreflightGuard(context.Background(), f.request, raw, observed); err != nil {
		t.Fatal("synthetic exact snapshot association unexpectedly failed")
	}
	changed := clonePreflightSnapshot(raw)
	changed.Snapshot.Current.Reference.Revision = "tampered-same-frame-reference"
	if sqliteFrameFromEvidence(changed.Snapshot.Evidence) != frame {
		t.Fatal("fixture changed the Frame")
	}
	if err := f.adapter.VerifyPreflightGuard(context.Background(), f.request, changed, observed); err == nil {
		t.Fatal("same Frame concealed a changed raw snapshot payload")
	}
}
