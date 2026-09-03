//go:build linux

package hostruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type hostAgentAdoptionTransactionFixture struct {
	root               string
	identityPath       string
	policyPath         string
	sidecarDir         string
	sidecarPath        string
	missingSidecarPath string
	oldSidecar         []byte
	oldSidecarInfo     os.FileInfo
	oldPolicy          ConfigurePolicyProjection
	stagedPolicy       ConfigurePolicyProjection
	identity           UpdaterConfigureIdentity
	transaction        *PreparedHostAgentConfiguration
	proofCalls         int
}

func TestHostAgentConfigurationTransactionAdoptsExactVerifiedLiveSystemdSidecar(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixture(t)
	defer fixture.transaction.Abort()

	if err := fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	); err != nil {
		t.Fatal(err)
	}
	if fixture.proofCalls != 2 {
		t.Fatalf("live proof calls = %d", fixture.proofCalls)
	}
	stagedPolicy, err := configurePolicyProjectionPolicy(fixture.stagedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	stagedPlans, err := initialSystemdPortSidecarPlans(
		stagedPolicy,
		fixture.sidecarDir,
	)
	if err != nil {
		t.Fatal(err)
	}
	body, info, existed, err := readRootSystemdPortSidecarOptional(
		fixture.sidecarPath,
	)
	if err != nil || !existed || !bytes.Equal(body, stagedPlans[0].Body) ||
		info.Mode().Perm() != 0o600 || !isRootOwner(info) ||
		os.SameFile(info, fixture.oldSidecarInfo) {
		t.Fatalf("adopted sidecar body=%q info=%#v existed=%v error=%v", body, info, existed, err)
	}
	installedPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(installedPolicy, fixture.stagedPolicy.Policy) {
		t.Fatalf("installed policy = %q, %v", installedPolicy, err)
	}
	if err := ValidateInstalledUpdaterIdentity(
		fixture.identityPath,
		fixture.identity,
	); err != nil {
		t.Fatalf("installed identity: %v", err)
	}
	if fixture.transaction.sidecars.replacementTempPath != "" ||
		!fixture.transaction.sidecars.finalized {
		t.Fatal("adopted sidecar backup was not durably finalized")
	}
}

func TestHostAgentConfigurationTransactionRestoresAdoptedSidecarWhenIdentityCommitFails(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixture(t)
	competitor := []byte("operator-created-before-identity-commit\n")
	if err := os.WriteFile(fixture.identityPath, competitor, 0o640); err != nil {
		t.Fatal(err)
	}

	err := fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	)
	if err == nil || !strings.Contains(err.Error(), "changed after preflight") {
		t.Fatalf("identity race error = %v", err)
	}
	body, info, existed, readErr := readRootSystemdPortSidecarOptional(
		fixture.sidecarPath,
	)
	if readErr != nil || !existed || !bytes.Equal(body, fixture.oldSidecar) ||
		!os.SameFile(info, fixture.oldSidecarInfo) {
		t.Fatalf("old sidecar inode was not restored: body=%q info=%#v error=%v", body, info, readErr)
	}
	installedPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(installedPolicy, fixture.oldPolicy.Policy) {
		t.Fatalf("old policy was not restored: %q, %v", installedPolicy, err)
	}
	installedIdentity, err := os.ReadFile(fixture.identityPath)
	if err != nil || !bytes.Equal(installedIdentity, competitor) {
		t.Fatalf("identity competitor was overwritten: %q, %v", installedIdentity, err)
	}
	fixture.transaction.Abort()
	entries, err := os.ReadDir(fixture.sidecarDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(fixture.sidecarPath) {
		t.Fatalf("sidecar rollback left temporary files: %#v, %v", entries, err)
	}
}

func TestHostAgentConfigurationTransactionRollsBackWhenIdentityPermissionsChangeBeforeCommit(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixture(t)
	defer fixture.transaction.Abort()
	identityBefore, err := os.ReadFile(fixture.identityPath)
	if err != nil {
		t.Fatal(err)
	}

	checks := 0
	fixture.transaction.verifyIdentityLayout = func() error {
		checks++
		if checks == 2 {
			if err := os.Chmod(fixture.identityPath, 0o660); err != nil {
				t.Fatal(err)
			}
		}
		return validateHostAgentIdentityWriteLayout(fixture.identityPath, os.Lstat)
	}
	err = fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	)
	if err == nil || !strings.Contains(err.Error(), "0600 or 0640") {
		t.Fatalf("identity permission race error = %v", err)
	}
	if checks != 2 {
		t.Fatalf("identity layout checks = %d", checks)
	}
	body, info, existed, readErr := readRootSystemdPortSidecarOptional(
		fixture.sidecarPath,
	)
	if readErr != nil || !existed || !bytes.Equal(body, fixture.oldSidecar) ||
		!os.SameFile(info, fixture.oldSidecarInfo) {
		t.Fatalf("old sidecar inode was not restored: body=%q info=%#v error=%v", body, info, readErr)
	}
	installedPolicy, readErr := os.ReadFile(fixture.policyPath)
	if readErr != nil || !bytes.Equal(installedPolicy, fixture.oldPolicy.Policy) {
		t.Fatalf("old policy was not restored: %q, %v", installedPolicy, readErr)
	}
	identityAfter, readErr := os.ReadFile(fixture.identityPath)
	if readErr != nil || !bytes.Equal(identityAfter, identityBefore) {
		t.Fatalf("identity changed after permission race: %v", readErr)
	}
}

func TestHostAgentConfigurationTransactionDoesNotOverwriteSidecarChangedAfterLiveProof(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixture(t)
	defer fixture.transaction.Abort()
	competitor := []byte("{\"schema_version\":2,\"service_type\":\"observability\",\"bind_address\":\"127.0.0.1:19999\",\"config_revision\":14}\n")
	fixture.transaction.sidecars.verifyLive = func(
		context.Context,
		LocalExecutorPolicy,
		LocalExecutorPolicy,
		LocalExecutorTarget,
		LocalExecutorTarget,
	) (hostAgentLiveSystemdSidecarProof, error) {
		fixture.proofCalls++
		if err := os.WriteFile(fixture.sidecarPath, competitor, 0o600); err != nil {
			t.Fatal(err)
		}
		return hostAgentAdoptionTestProof(), nil
	}

	err := fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	)
	if err == nil || !strings.Contains(err.Error(), "changed after preflight") {
		t.Fatalf("sidecar race error = %v", err)
	}
	body, err := os.ReadFile(fixture.sidecarPath)
	if err != nil || !bytes.Equal(body, competitor) {
		t.Fatalf("sidecar competitor was overwritten: %q, %v", body, err)
	}
	installedPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(installedPolicy, fixture.oldPolicy.Policy) {
		t.Fatalf("policy changed after rejected sidecar race: %q, %v", installedPolicy, err)
	}
}

func TestHostAgentConfigurationTransactionDefaultOptionsRejectLiveSidecarMismatchWithoutMutation(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixtureWithConfigurationOptions(
		t,
		false,
		HostAgentConfigurationOptions{},
	)
	defer fixture.transaction.Abort()
	oldIdentity, err := os.ReadFile(fixture.identityPath)
	if err != nil {
		t.Fatal(err)
	}
	verifyCalls := 0
	exchangeCalls := 0
	fixture.transaction.sidecars.verifyLive = func(
		context.Context,
		LocalExecutorPolicy,
		LocalExecutorPolicy,
		LocalExecutorTarget,
		LocalExecutorTarget,
	) (hostAgentLiveSystemdSidecarProof, error) {
		verifyCalls++
		return hostAgentAdoptionTestProof(), nil
	}
	fixture.transaction.sidecars.exchange = func(string, string) error {
		exchangeCalls++
		return errors.New("unexpected exchange")
	}

	err = fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	)
	if err == nil || !strings.Contains(err.Error(), "differs from the active policy target") {
		t.Fatalf("default mismatch error = %v", err)
	}
	if verifyCalls != 0 || exchangeCalls != 0 {
		t.Fatalf("default recovery authority calls: verify=%d exchange=%d", verifyCalls, exchangeCalls)
	}
	body, info, existed, readErr := readRootSystemdPortSidecarOptional(
		fixture.sidecarPath,
	)
	if readErr != nil || !existed || !bytes.Equal(body, fixture.oldSidecar) ||
		!os.SameFile(info, fixture.oldSidecarInfo) {
		t.Fatalf("default mismatch changed sidecar: body=%q info=%#v error=%v", body, info, readErr)
	}
	installedPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(installedPolicy, fixture.oldPolicy.Policy) {
		t.Fatalf("default mismatch changed policy: %q, %v", installedPolicy, err)
	}
	installedIdentity, err := os.ReadFile(fixture.identityPath)
	if err != nil || !bytes.Equal(installedIdentity, oldIdentity) {
		t.Fatalf("default mismatch changed identity: %q, %v", installedIdentity, err)
	}
}

func TestHostAgentConfigurationTransactionPreservesAdoptedSidecarWhenLiveProcessChanges(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixtureWithMissingTarget(t)
	defer fixture.transaction.Abort()
	fixture.transaction.sidecars.verifyLive = func(
		context.Context,
		LocalExecutorPolicy,
		LocalExecutorPolicy,
		LocalExecutorTarget,
		LocalExecutorTarget,
	) (hostAgentLiveSystemdSidecarProof, error) {
		fixture.proofCalls++
		proof := hostAgentAdoptionTestProof()
		if fixture.proofCalls == 2 {
			proof.Observation.MainPID++
			proof.Observation.ListenerPID++
			proof.MainPIDStartTime++
			proof.ListenerPIDStartTime++
		}
		return proof, nil
	}

	err := fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	)
	if err == nil || !strings.Contains(err.Error(), "preserved the adopted sidecar") {
		t.Fatalf("changed process error = %v", err)
	}
	staged, err := configurePolicyProjectionPolicy(fixture.stagedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	stagedPlans, err := initialSystemdPortSidecarPlans(staged, fixture.sidecarDir)
	if err != nil {
		t.Fatal(err)
	}
	body, info, existed, err := readRootSystemdPortSidecarOptional(
		fixture.sidecarPath,
	)
	if err != nil || !existed || !bytes.Equal(body, stagedPlans[0].Body) ||
		os.SameFile(info, fixture.oldSidecarInfo) {
		t.Fatalf("complete adopted sidecar was not preserved: body=%q info=%#v error=%v", body, info, err)
	}
	backupPath := fixture.transaction.sidecars.replacementTempPath
	backup, backupInfo, backupExists, err := readRootSystemdPortSidecarOptional(
		backupPath,
	)
	if err != nil || !backupExists || !bytes.Equal(backup, fixture.oldSidecar) ||
		!os.SameFile(backupInfo, fixture.oldSidecarInfo) {
		t.Fatalf("exact rollback inode was not preserved: body=%q info=%#v error=%v", backup, backupInfo, err)
	}
	installedPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(installedPolicy, fixture.oldPolicy.Policy) {
		t.Fatalf("policy advanced after changed process proof: %q, %v", installedPolicy, err)
	}
	if _, err := os.Lstat(fixture.missingSidecarPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new sidecar was not rolled back while recovery pair was preserved: %v", err)
	}
}

func TestHostAgentConfigurationTransactionPreservesPairWhenPostExchangeReadFails(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixture(t)
	realSyncParent := fixture.transaction.sidecars.syncParent
	syncCalls := 0
	fixture.transaction.sidecars.syncParent = func(parent string) error {
		syncCalls++
		return realSyncParent(parent)
	}
	fixture.transaction.sidecars.replacementPairVerifier = func(
		*preparedSystemdPortSidecar,
		bool,
	) bool {
		return false
	}

	err := fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	)
	if err == nil || !strings.Contains(err.Error(), "preserved the adopted sidecar") {
		t.Fatalf("post-exchange read failure = %v", err)
	}
	if syncCalls != 1 {
		t.Fatalf("post-exchange recovery directory syncs = %d", syncCalls)
	}
	if !fixture.transaction.sidecars.replaced ||
		!fixture.transaction.sidecars.replacementAmbiguous ||
		fixture.transaction.sidecars.replacementTempPath == "" {
		t.Fatalf("post-exchange state was not retained: %#v", fixture.transaction.sidecars)
	}
	staged, err := configurePolicyProjectionPolicy(fixture.stagedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	stagedPlans, err := initialSystemdPortSidecarPlans(staged, fixture.sidecarDir)
	if err != nil {
		t.Fatal(err)
	}
	canonical, canonicalInfo, existed, err := readRootSystemdPortSidecarOptional(
		fixture.sidecarPath,
	)
	if err != nil || !existed || !bytes.Equal(canonical, stagedPlans[0].Body) ||
		os.SameFile(canonicalInfo, fixture.oldSidecarInfo) {
		t.Fatalf("adopted canonical sidecar was not preserved: body=%q info=%#v error=%v", canonical, canonicalInfo, err)
	}
	backupPath := fixture.transaction.sidecars.replacementTempPath
	backup, backupInfo, existed, err := readRootSystemdPortSidecarOptional(backupPath)
	if err != nil || !existed || !bytes.Equal(backup, fixture.oldSidecar) ||
		!os.SameFile(backupInfo, fixture.oldSidecarInfo) {
		t.Fatalf("rollback inode was not preserved: body=%q info=%#v error=%v", backup, backupInfo, err)
	}

	fixture.transaction.Abort()
	if _, err := os.Lstat(fixture.sidecarPath); err != nil {
		t.Fatalf("Abort removed adopted canonical sidecar: %v", err)
	}
	if _, err := os.Lstat(backupPath); err != nil {
		t.Fatalf("Abort removed rollback inode: %v", err)
	}
}

func TestHostAgentConfigurationTransactionReprovesLiveTargetBeforeIdentityFailureRollback(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixture(t)
	defer fixture.transaction.Abort()
	oldIdentity, err := os.ReadFile(fixture.identityPath)
	if err != nil {
		t.Fatal(err)
	}
	liveChanged := false
	boundedRollbackProof := false
	fixture.transaction.sidecars.verifyLive = func(
		ctx context.Context,
		_ LocalExecutorPolicy,
		_ LocalExecutorPolicy,
		_ LocalExecutorTarget,
		_ LocalExecutorTarget,
	) (hostAgentLiveSystemdSidecarProof, error) {
		fixture.proofCalls++
		proof := hostAgentAdoptionTestProof()
		if liveChanged {
			deadline, ok := ctx.Deadline()
			remaining := time.Until(deadline)
			if !ok || remaining <= 0 || remaining > hostAgentSidecarRollbackProofTimeout {
				t.Fatalf("rollback live proof context is not bounded: ok=%v remaining=%v", ok, remaining)
			}
			boundedRollbackProof = true
			proof.Observation.MainPID++
			proof.Observation.ListenerPID++
			proof.MainPIDStartTime++
			proof.ListenerPIDStartTime++
		}
		return proof, nil
	}
	fixture.transaction.identity.renamePath = func(string, string) error {
		liveChanged = true
		return syscall.EIO
	}

	err = fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	)
	if err == nil || !strings.Contains(err.Error(), "live systemd sidecar target changed before rollback") ||
		!strings.Contains(err.Error(), "preserved the adopted sidecar") {
		t.Fatalf("identity rollback live proof error = %v", err)
	}
	if fixture.proofCalls != 3 || !boundedRollbackProof {
		t.Fatalf("rollback live proof calls=%d bounded=%v", fixture.proofCalls, boundedRollbackProof)
	}
	staged, err := configurePolicyProjectionPolicy(fixture.stagedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	stagedPlans, err := initialSystemdPortSidecarPlans(staged, fixture.sidecarDir)
	if err != nil {
		t.Fatal(err)
	}
	canonical, canonicalInfo, existed, err := readRootSystemdPortSidecarOptional(
		fixture.sidecarPath,
	)
	if err != nil || !existed || !bytes.Equal(canonical, stagedPlans[0].Body) ||
		os.SameFile(canonicalInfo, fixture.oldSidecarInfo) {
		t.Fatalf("adopted sidecar was blindly rolled back: body=%q info=%#v error=%v", canonical, canonicalInfo, err)
	}
	backup, backupInfo, existed, err := readRootSystemdPortSidecarOptional(
		fixture.transaction.sidecars.replacementTempPath,
	)
	if err != nil || !existed || !bytes.Equal(backup, fixture.oldSidecar) ||
		!os.SameFile(backupInfo, fixture.oldSidecarInfo) {
		t.Fatalf("rollback inode was not preserved: body=%q info=%#v error=%v", backup, backupInfo, err)
	}
	installedPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(installedPolicy, fixture.oldPolicy.Policy) {
		t.Fatalf("old policy was not restored: %q, %v", installedPolicy, err)
	}
	installedIdentity, err := os.ReadFile(fixture.identityPath)
	if err != nil || !bytes.Equal(installedIdentity, oldIdentity) {
		t.Fatalf("identity changed after failed commit: %q, %v", installedIdentity, err)
	}
}

func TestHostAgentConfigurationTransactionPreservesPairWhenReverseExchangeReadFails(
	t *testing.T,
) {
	fixture := newHostAgentAdoptionTransactionFixture(t)
	oldIdentity, err := os.ReadFile(fixture.identityPath)
	if err != nil {
		t.Fatal(err)
	}
	sidecars := fixture.transaction.sidecars
	realExchange := sidecars.exchange
	realPairVerifier := sidecars.replacementPairVerifier
	realSyncParent := sidecars.syncParent
	exchangeCalls := 0
	reverseExchanged := false
	reverseSyncCalls := 0
	sidecars.exchange = func(left, right string) error {
		exchangeCalls++
		err := realExchange(left, right)
		if exchangeCalls == 2 && err == nil {
			reverseExchanged = true
		}
		return err
	}
	sidecars.replacementPairVerifier = func(
		entry *preparedSystemdPortSidecar,
		swapped bool,
	) bool {
		if reverseExchanged && !swapped {
			return false
		}
		return realPairVerifier(entry, swapped)
	}
	sidecars.syncParent = func(parent string) error {
		if reverseExchanged {
			reverseSyncCalls++
		}
		return realSyncParent(parent)
	}
	fixture.transaction.identity.renamePath = func(string, string) error {
		return syscall.EIO
	}

	err = fixture.transaction.CommitContext(
		context.Background(),
		fixture.identity,
		fixture.stagedPolicy,
	)
	if err == nil || !strings.Contains(err.Error(), "preserved both systemd sidecar pathnames") {
		t.Fatalf("reverse exchange read failure = %v", err)
	}
	if exchangeCalls != 2 || !reverseExchanged || reverseSyncCalls != 1 {
		t.Fatalf("reverse exchange calls=%d exchanged=%v syncs=%d", exchangeCalls, reverseExchanged, reverseSyncCalls)
	}
	if !sidecars.replaced || !sidecars.replacementAmbiguous ||
		sidecars.replacementTempPath == "" {
		t.Fatalf("reverse exchange ambiguity was not retained: %#v", sidecars)
	}
	canonical, canonicalInfo, existed, err := readRootSystemdPortSidecarOptional(
		fixture.sidecarPath,
	)
	if err != nil || !existed || !bytes.Equal(canonical, fixture.oldSidecar) ||
		!os.SameFile(canonicalInfo, fixture.oldSidecarInfo) {
		t.Fatalf("old canonical inode was not preserved after reverse exchange: body=%q info=%#v error=%v", canonical, canonicalInfo, err)
	}
	staged, err := configurePolicyProjectionPolicy(fixture.stagedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	stagedPlans, err := initialSystemdPortSidecarPlans(staged, fixture.sidecarDir)
	if err != nil {
		t.Fatal(err)
	}
	backupPath := sidecars.replacementTempPath
	backup, backupInfo, existed, err := readRootSystemdPortSidecarOptional(backupPath)
	if err != nil || !existed || !bytes.Equal(backup, stagedPlans[0].Body) ||
		!os.SameFile(backupInfo, sidecars.replacementTempInfo) {
		t.Fatalf("staged inode was not preserved after reverse exchange: body=%q info=%#v error=%v", backup, backupInfo, err)
	}
	installedPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil || !bytes.Equal(installedPolicy, fixture.oldPolicy.Policy) {
		t.Fatalf("old policy was not restored: %q, %v", installedPolicy, err)
	}
	installedIdentity, err := os.ReadFile(fixture.identityPath)
	if err != nil || !bytes.Equal(installedIdentity, oldIdentity) {
		t.Fatalf("identity changed after failed commit: %q, %v", installedIdentity, err)
	}

	fixture.transaction.Abort()
	if _, err := os.Lstat(fixture.sidecarPath); err != nil {
		t.Fatalf("Abort removed canonical inode after reverse ambiguity: %v", err)
	}
	if _, err := os.Lstat(backupPath); err != nil {
		t.Fatalf("Abort removed backup inode after reverse ambiguity: %v", err)
	}
}

func TestSystemdLoadCredentialHasExactlyOneCanonicalNodeListener(t *testing.T) {
	canonical := "/opt/autostream/local-executor/ports/observability.json"
	if !systemdLoadCredentialHasNodeListener(
		"tls.key:/etc/autostream/tls.key "+
			"node-listener.json:/opt/autostream/local-executor/ports/observability.json\n",
		canonical,
	) {
		t.Fatal("canonical Node listener credential was rejected")
	}
	for name, value := range map[string]string{
		"missing Node listener": "tls.key:/etc/autostream/tls.key",
		"wrong credential name": "listener.json:" + canonical,
		"relative source":       "node-listener.json:ports/observability.json",
		"unclean source":        "node-listener.json:/opt/autostream/local-executor/ports/../ports/observability.json",
		"different sidecar":     "node-listener.json:/opt/autostream/local-executor/ports/worker.json",
		"duplicate Node listener": "node-listener.json:" + canonical +
			" node-listener.json:" + canonical,
	} {
		t.Run(name, func(t *testing.T) {
			if systemdLoadCredentialHasNodeListener(value, canonical) {
				t.Fatalf("unsafe LoadCredential accepted: %q", value)
			}
		})
	}
}

func newHostAgentAdoptionTransactionFixture(
	t *testing.T,
) *hostAgentAdoptionTransactionFixture {
	return newHostAgentAdoptionTransactionFixtureWithConfigurationOptions(
		t,
		false,
		HostAgentConfigurationOptions{AdoptLiveSystemdSidecar: true},
	)
}

func newHostAgentAdoptionTransactionFixtureWithMissingTarget(
	t *testing.T,
) *hostAgentAdoptionTransactionFixture {
	return newHostAgentAdoptionTransactionFixtureWithConfigurationOptions(
		t,
		true,
		HostAgentConfigurationOptions{AdoptLiveSystemdSidecar: true},
	)
}

func newHostAgentAdoptionTransactionFixtureWithConfigurationOptions(
	t *testing.T,
	includeMissingTarget bool,
	configurationOptions HostAgentConfigurationOptions,
) *hostAgentAdoptionTransactionFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-owned Host Agent sidecar adoption transaction")
	}
	root, err := os.MkdirTemp("/root", ".autostream-host-adoption-test-*")
	if err != nil {
		t.Skipf("root-controlled test directory is unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Join(root, "identity")
	policyDir := filepath.Join(root, "policy")
	sidecarDir := filepath.Join(root, "ports")
	for _, directory := range []string{identityDir, policyDir, sidecarDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	current, staged, identity, identityBytes, _, _ :=
		configureAdoptionAuthorityFixture(t)
	if includeMissingTarget {
		extra := configureTransactionPolicyFixture(t).Targets[1]
		current.Targets = append([]LocalExecutorTarget{extra}, current.Targets...)
		staged.Targets = append([]LocalExecutorTarget{extra}, staged.Targets...)
	}
	oldProjection := mustConfigureProjection(t, current)
	stagedProjection := mustConfigureProjection(t, staged)
	identityPath := filepath.Join(identityDir, "agent.yaml")
	policyPath := filepath.Join(policyDir, "policy.json")
	if err := os.WriteFile(identityPath, identityBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, oldProjection.Policy, 0o600); err != nil {
		t.Fatal(err)
	}
	oldPlans, err := initialSystemdPortSidecarPlans(current, sidecarDir)
	if err != nil {
		t.Fatal(err)
	}
	var oldSidecarPlan initialSystemdPortSidecarPlan
	missingSidecarPath := ""
	for _, plan := range oldPlans {
		switch plan.ServiceID {
		case "observability-a":
			oldSidecarPlan = plan
		case "worker-a":
			missingSidecarPath = plan.Path
		}
	}
	if oldSidecarPlan.Path == "" || (includeMissingTarget && missingSidecarPath == "") {
		t.Fatalf("adoption fixture plans are incomplete: %#v", oldPlans)
	}
	sidecarPath := oldSidecarPlan.Path
	if err := os.WriteFile(sidecarPath, oldSidecarPlan.Body, 0o600); err != nil {
		t.Fatal(err)
	}
	oldSidecarInfo, err := os.Lstat(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	preparedIdentity, err := prepareUpdaterConfig(identityPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	preparedPolicy, err := prepareLocalExecutorPolicy(policyPath)
	if err != nil {
		preparedIdentity.Abort()
		t.Fatal(err)
	}
	preparedSidecars, err := prepareSystemdPortSidecarsWithOptions(
		sidecarDir,
		configurationOptions,
	)
	if err != nil {
		preparedPolicy.Abort()
		preparedIdentity.Abort()
		t.Fatal(err)
	}
	fixture := &hostAgentAdoptionTransactionFixture{
		root:               root,
		identityPath:       identityPath,
		policyPath:         policyPath,
		sidecarDir:         sidecarDir,
		sidecarPath:        sidecarPath,
		missingSidecarPath: missingSidecarPath,
		oldSidecar:         append([]byte(nil), oldSidecarPlan.Body...),
		oldSidecarInfo:     oldSidecarInfo,
		oldPolicy:          oldProjection,
		stagedPolicy:       stagedProjection,
		identity:           identity,
	}
	preparedSidecars.verifyLive = func(
		_ context.Context,
		currentPolicy LocalExecutorPolicy,
		stagedPolicy LocalExecutorPolicy,
		currentTarget LocalExecutorTarget,
		stagedTarget LocalExecutorTarget,
	) (hostAgentLiveSystemdSidecarProof, error) {
		fixture.proofCalls++
		if currentPolicy.PolicyRevision != 4 || stagedPolicy.PolicyRevision != 6 ||
			currentTarget.ServiceID != "observability-a" ||
			currentTarget.LocalListen.Port != 18080 ||
			stagedTarget.LocalListen.Port != 18084 ||
			stagedTarget.ConfigRevision != 14 {
			t.Fatalf(
				"live proof authority current=%#v staged=%#v",
				currentTarget,
				stagedTarget,
			)
		}
		return hostAgentAdoptionTestProof(), nil
	}
	fixture.transaction = &PreparedHostAgentConfiguration{
		identity: preparedIdentity,
		policy:   preparedPolicy,
		sidecars: preparedSidecars,
		options:  configurationOptions,
		verifyIdentityLayout: func() error {
			return validateHostAgentIdentityWriteLayout(identityPath, os.Lstat)
		},
	}
	return fixture
}

func hostAgentAdoptionTestProof() hostAgentLiveSystemdSidecarProof {
	return hostAgentLiveSystemdSidecarProof{
		Observation: LocalProcessObservation{
			ServiceID:            "observability-a",
			ServiceType:          "observability",
			DeploymentMode:       ModeSystemd,
			CurrentVersion:       "v1.3.1",
			MainPID:              4242,
			ListenerPID:          4242,
			ControlGroup:         "/system.slice/autostream-observability.service",
			ListenerControlGroup: "/system.slice/autostream-observability.service",
		},
		MainPIDStartTime:     100,
		ListenerPIDStartTime: 100,
		SystemdUnitID:        "autostream-observability.service",
		LoadCredential:       "node-listener.json:/opt/autostream/local-executor/ports/observability.json",
	}
}

func TestHostAgentConfigurationTransactionRollsBackPolicyAndNewSidecars(
	t *testing.T,
) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned Host Agent configuration transaction")
	}
	root, err := os.MkdirTemp(
		"/root",
		".autostream-host-configure-test-*",
	)
	if err != nil {
		t.Skipf("root-controlled test directory is unavailable: %v", err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Join(root, "identity")
	policyDir := filepath.Join(root, "policy")
	sidecarDir := filepath.Join(root, "ports")
	for _, directory := range []string{identityDir, policyDir, sidecarDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	identityPath := filepath.Join(identityDir, "agent.yaml")
	policyPath := filepath.Join(policyDir, "policy.json")

	identity, err := prepareUpdaterConfig(identityPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := prepareLocalExecutorPolicy(policyPath)
	if err != nil {
		identity.Abort()
		t.Fatal(err)
	}
	sidecars, err := prepareSystemdPortSidecarsWithOptions(
		sidecarDir,
		HostAgentConfigurationOptions{},
	)
	if err != nil {
		policy.Abort()
		identity.Abort()
		t.Fatal(err)
	}
	transaction := &PreparedHostAgentConfiguration{
		identity: identity,
		policy:   policy,
		sidecars: sidecars,
		verifyIdentityLayout: func() error {
			return validateHostAgentIdentityWriteLayout(identityPath, os.Lstat)
		},
	}
	defer transaction.Abort()

	projection, err := BuildHostAgentConfigurePolicy(
		HostAgentConfigurePolicySource{
			PanelURL:                    "https://panel.example.com",
			ExecutionHostID:             "host-a",
			AgentUID:                    1001,
			AgentGID:                    1002,
			SourcePolicyRevision:        3,
			ProjectionRevision:          4,
			LocalExecutorPolicyRevision: 5,
			Targets: []HostAgentConfigurePolicyTarget{{
				ServiceID:             "worker-a",
				ServiceType:           "worker",
				DeploymentMode:        ModeSystemd,
				EndpointRevision:      2,
				AppliedConfigRevision: 7,
				AppliedEndpointPort:   18081,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	competitor := []byte("operator-created-before-identity-commit\n")
	if err := os.WriteFile(identityPath, competitor, 0o640); err != nil {
		t.Fatal(err)
	}
	err = transaction.Commit(
		UpdaterConfigureIdentity{
			PanelURL:      "https://panel.example.com",
			NodeID:        "host-agent-a",
			RuntimeToken:  "runtime-token",
			ServiceName:   "Host Agent A",
			ServiceType:   "update_agent",
			TransportMode: "pull_v2",
		},
		projection,
	)
	if err == nil || !strings.Contains(err.Error(), "appeared after preflight") {
		t.Fatalf("identity race commit error = %v", err)
	}
	gotCompetitor, err := os.ReadFile(identityPath)
	if err != nil || string(gotCompetitor) != string(competitor) {
		t.Fatalf("identity competitor was overwritten: %q, %v", gotCompetitor, err)
	}
	if _, err := os.Lstat(policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("policy survived failed transaction: %v", err)
	}
	workerSidecar := filepath.Join(sidecarDir, "worker.json")
	if _, err := os.Lstat(workerSidecar); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new sidecar survived failed transaction: %v", err)
	}

	transaction.Abort()
	entries, err := os.ReadDir(sidecarDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("sidecar transaction left temporary files: %#v", entries)
	}
}

func TestHostAgentConfigurationTransactionPreservesPairWhenIdentityRenameReportsFailure(
	t *testing.T,
) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned Host Agent configuration transaction")
	}
	root, err := os.MkdirTemp(
		"/root",
		".autostream-host-configure-uncertain-test-*",
	)
	if err != nil {
		t.Skipf("root-controlled test directory is unavailable: %v", err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Join(root, "identity")
	policyDir := filepath.Join(root, "policy")
	sidecarDir := filepath.Join(root, "ports")
	for _, directory := range []string{identityDir, policyDir, sidecarDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	identityPath := filepath.Join(identityDir, "agent.yaml")
	policyPath := filepath.Join(policyDir, "policy.json")
	identity, err := prepareUpdaterConfig(identityPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := prepareLocalExecutorPolicy(policyPath)
	if err != nil {
		identity.Abort()
		t.Fatal(err)
	}
	sidecars, err := prepareSystemdPortSidecarsWithOptions(
		sidecarDir,
		HostAgentConfigurationOptions{},
	)
	if err != nil {
		policy.Abort()
		identity.Abort()
		t.Fatal(err)
	}
	transaction := &PreparedHostAgentConfiguration{
		identity: identity,
		policy:   policy,
		sidecars: sidecars,
		verifyIdentityLayout: func() error {
			return validateHostAgentIdentityWriteLayout(identityPath, os.Lstat)
		},
	}
	defer transaction.Abort()

	projection, err := BuildHostAgentConfigurePolicy(
		HostAgentConfigurePolicySource{
			PanelURL:                    "https://panel.example.com",
			ExecutionHostID:             "host-a",
			AgentUID:                    1001,
			AgentGID:                    1002,
			SourcePolicyRevision:        3,
			ProjectionRevision:          4,
			LocalExecutorPolicyRevision: 5,
			Targets: []HostAgentConfigurePolicyTarget{{
				ServiceID:             "control-panel",
				ServiceType:           "control_panel",
				DeploymentMode:        ModeSystemd,
				DatabaseName:          "autostream_control_panel",
				EndpointRevision:      2,
				AppliedConfigRevision: 7,
				AppliedEndpointPort:   18080,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity.renamePath = func(tempPath, destinationPath string) error {
		if err := os.Rename(tempPath, destinationPath); err != nil {
			return err
		}
		return syscall.EIO
	}
	identityValue := UpdaterConfigureIdentity{
		PanelURL:      "https://panel.example.com",
		NodeID:        "host-agent-a",
		RuntimeToken:  "runtime-token",
		ServiceName:   "Host Agent A",
		ServiceType:   "update_agent",
		TransportMode: "pull_v2",
	}
	err = transaction.Commit(identityValue, projection)
	if err == nil || !strings.Contains(err.Error(), "was installed") {
		t.Fatalf("identity rename uncertainty = %v", err)
	}
	if !HostAgentConfigurationInstalled(err) {
		t.Fatalf("installed identity error was not classified as post-install: %v", err)
	}
	if !identity.committed {
		t.Fatal("identity rename result was not marked committed")
	}
	if err := ValidateInstalledUpdaterIdentity(identityPath, identityValue); err != nil {
		t.Fatalf("installed identity was not preserved: %v", err)
	}
	if _, err := os.Lstat(policyPath); err != nil {
		t.Fatalf("policy was rolled back after identity rename uncertainty: %v", err)
	}
	controlPanelSidecar := filepath.Join(sidecarDir, "control-panel.env")
	if _, err := os.Lstat(controlPanelSidecar); err != nil {
		t.Fatalf("sidecar was rolled back after identity rename uncertainty: %v", err)
	}
}
