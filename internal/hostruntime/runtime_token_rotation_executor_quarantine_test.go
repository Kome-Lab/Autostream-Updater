package hostruntime

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestManualRecoveryResumesQuarantinedStagedIdentityWipe(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, rt runtimeCredentialExecutorRuntime)
	}{
		{
			name: "after-quarantine-rename",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
			) {
				t.Helper()
			},
		},
		{
			name: "during-overwrite",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
			) {
				t.Helper()
				file, err := os.OpenFile(
					rt.wipingIdentity,
					os.O_RDWR,
					0,
				)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write(make([]byte, 8)); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Sync(); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "after-truncate",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
			) {
				t.Helper()
				if err := os.Truncate(rt.wipingIdentity, 0); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "after-unlink-before-directory-sync",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
			) {
				t.Helper()
				if err := os.Remove(rt.wipingIdentity); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 7, 28, 19, 15, 0, 0, time.UTC)
			policy, rt, request, _ :=
				newRuntimeCredentialExecutorFixture(t, now)
			rt.acknowledgeStage = func(
				context.Context,
				string,
				string,
				int64,
				string,
				*http.Client,
			) (HostAgentRuntimeTokenRotation, error) {
				return testRuntimeTokenRotation(
					"local_staged",
					3,
					now,
					now.Add(time.Second),
				), nil
			}
			requireRuntimeCredentialPhase(
				t,
				handleLocalExecutorRuntimeCredential(
					context.Background(),
					policy,
					request,
					rt,
				),
				RuntimeCredentialPhaseLocalStaged,
				3,
			)
			replacementToken := "wipe-crash-replacement-runtime-token"
			replacement := replaceRuntimeCredentialIdentityForTest(
				t,
				rt,
				policy,
				replacementToken,
			)
			status, exists, err := rt.loadStatus()
			if err != nil || !exists {
				t.Fatalf("load wipe-crash fixture status: %v", err)
			}
			status.Phase = RuntimeCredentialPhaseManualRecovered
			status.ActiveIdentitySHA256 =
				runtimeCredentialDigest(replacement)
			status.activeRuntimeTokenSHA256 =
				runtimeCredentialTokenDigest(replacementToken)
			if err := rt.saveStatus(status); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(
				rt.stagedIdentity,
				rt.wipingIdentity,
			); err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, rt)

			response := handleLocalExecutorRuntimeCredential(
				context.Background(),
				policy,
				LocalExecutorRequest{
					Version:   LocalExecutorMutationProtocolVersion,
					Operation: "runtime_credential_status",
					ServiceID: request.ServiceID,
				},
				rt,
			)
			requireRuntimeCredentialPhase(
				t,
				response,
				RuntimeCredentialPhaseManualRecovered,
				status.RotationRevision,
			)
			if !rt.identityCleanupComplete() {
				t.Fatal("reboot did not complete quarantined identity wipe")
			}
		})
	}
}

func TestEmergencyManualReconfigureRecoveryRejectsRevokedOrInvalidReplacement(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, rt runtimeCredentialExecutorRuntime, policy LocalExecutorPolicy)
	}{
		{
			name: "same-token-with-different-yaml-formatting",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
				policy LocalExecutorPolicy,
			) {
				t.Helper()
				active, _, _, err := rt.loadIdentity(
					rt.activeIdentity,
					policy.AgentGID,
				)
				if err != nil {
					t.Fatal(err)
				}
				reformatted, err := marshalManagedBootstrapConfig(active)
				if err != nil {
					t.Fatal(err)
				}
				reformatted = append([]byte("# Same identity, different YAML bytes.\n"), reformatted...)
				if err := rt.writeIdentityAtomic(
					rt.activeIdentity,
					reformatted,
					policy.AgentGID,
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "service-name-drift",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
				policy LocalExecutorPolicy,
			) {
				t.Helper()
				active, _, _, err := rt.loadIdentity(
					rt.activeIdentity,
					policy.AgentGID,
				)
				if err != nil {
					t.Fatal(err)
				}
				active.RuntimeToken = "replacement-runtime-token"
				active.ServiceName = "different-host-agent-service"
				replacement, err := marshalRuntimeCredentialIdentity(active)
				if err != nil {
					t.Fatal(err)
				}
				if err := rt.writeIdentityAtomic(
					rt.activeIdentity,
					replacement,
					policy.AgentGID,
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non-canonical-runtime-token",
			mutate: func(
				t *testing.T,
				rt runtimeCredentialExecutorRuntime,
				policy LocalExecutorPolicy,
			) {
				t.Helper()
				active, _, _, err := rt.loadIdentity(
					rt.activeIdentity,
					policy.AgentGID,
				)
				if err != nil {
					t.Fatal(err)
				}
				active.RuntimeToken = "replacement runtime token"
				replacement, err := marshalRuntimeCredentialIdentity(active)
				if err != nil {
					t.Fatal(err)
				}
				if err := rt.writeIdentityAtomic(
					rt.activeIdentity,
					replacement,
					policy.AgentGID,
					true,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 7, 28, 19, 30, 0, 0, time.UTC)
			policy, rt, request, _ := newRuntimeCredentialExecutorFixture(
				t,
				now,
			)
			rt.acknowledgeStage = func(
				context.Context,
				string,
				string,
				int64,
				string,
				*http.Client,
			) (HostAgentRuntimeTokenRotation, error) {
				return testRuntimeTokenRotation(
					"local_staged",
					3,
					now,
					now.Add(time.Second),
				), nil
			}
			requireRuntimeCredentialPhase(
				t,
				handleLocalExecutorRuntimeCredential(
					context.Background(),
					policy,
					request,
					rt,
				),
				RuntimeCredentialPhaseLocalStaged,
				3,
			)
			rt.now = func() time.Time {
				return now.Add(runtimeCredentialStagedMaxAge + time.Second)
			}
			tt.mutate(t, rt, policy)

			if _, err := rt.recoverAfterEmergencyManualReconfigure(
				policy,
				request.RuntimeCredential.RotationID,
			); err == nil {
				t.Fatal("unsafe replacement identity unexpectedly recovered")
			}
		})
	}
}

func replaceRuntimeCredentialIdentityForTest(
	t *testing.T,
	rt runtimeCredentialExecutorRuntime,
	policy LocalExecutorPolicy,
	token string,
) []byte {
	t.Helper()
	active, _, _, err := rt.loadIdentity(
		rt.activeIdentity,
		policy.AgentGID,
	)
	if err != nil {
		t.Fatal(err)
	}
	active.RuntimeToken = token
	replacement, err := marshalRuntimeCredentialIdentity(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.writeIdentityAtomic(
		rt.activeIdentity,
		replacement,
		policy.AgentGID,
		true,
	); err != nil {
		t.Fatal(err)
	}
	return replacement
}
