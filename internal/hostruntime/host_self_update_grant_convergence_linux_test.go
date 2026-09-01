//go:build linux

package hostruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hostSelfUpdateFailingGrantTestDownloader struct{}

func (hostSelfUpdateFailingGrantTestDownloader) DownloadHostAgentRelease(
	context.Context,
	string,
	string,
	string,
) (HostAgentRelease, error) {
	return HostAgentRelease{}, errors.New("injected host release download failure")
}

func TestHostSelfUpdateStageErrorConvergesGrantBeforeResponse(
	t *testing.T,
) {
	t.Run("stable_download_failure_becomes_exact_failed_terminal", func(t *testing.T) {
		rt, policy, request, authorization, ipcRequest :=
			newHostSelfUpdateGrantHandlerFixture(t)
		rt.downloader = hostSelfUpdateFailingGrantTestDownloader{}

		response := handleLocalExecutorHostSelfUpdate(
			context.Background(),
			policy,
			ipcRequest,
			rt,
		)
		if response.Error == nil ||
			response.Error.Code != "stage_failed" ||
			response.HostSelfUpdate != nil {
			t.Fatalf("download failure response=%#v", response)
		}
		assertFailedHostSelfUpdateGrantTerminal(
			t,
			rt,
			request,
			authorization,
		)

		response = handleLocalExecutorHostSelfUpdate(
			context.Background(),
			policy,
			ipcRequest,
			rt,
		)
		if response.Error != nil ||
			response.HostSelfUpdate == nil ||
			response.HostSelfUpdate.State.Phase != HostSelfUpdatePhaseStable ||
			response.HostSelfUpdate.State.FailedGeneration != request.Generation {
			t.Fatalf("exact failure replay response=%#v", response)
		}
	})

	t.Run("post_save_promotion_failure_converges_to_applied_stage", func(t *testing.T) {
		rt, policy, request, authorization, ipcRequest :=
			newHostSelfUpdateGrantHandlerFixture(t)
		artifactRoot := filepath.Join(t.TempDir(), "artifact")
		if err := os.MkdirAll(filepath.Join(artifactRoot, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, binary := range []string{
			"autostream-host-agent",
			"autostream-local-executor",
		} {
			if err := os.WriteFile(
				filepath.Join(artifactRoot, "bin", binary),
				[]byte(binary+"\n"),
				0o755,
			); err != nil {
				t.Fatal(err)
			}
		}
		rt.downloader = hostSelfUpdateExecutorTestDownloader{
			release: HostAgentRelease{
				Artifact: DownloadedArtifact{
					RootDir: artifactRoot,
					SHA256: strings.TrimPrefix(
						request.ArtifactSHA256,
						"sha256:",
					),
				},
				Request:             request,
				PublishedAt:         request.Release.PublishedAt,
				MinimumPanelVersion: request.Release.MinimumPanelVersion,
			},
		}
		rt.runner = hostSelfUpdateSlotIdentityRunner{request: request}
		injected := false
		rt.syncDir = func(path string) error {
			if !injected &&
				filepath.Clean(path) == filepath.Clean(rt.slotsRoot) {
				persisted, err := rt.loadPersistedState()
				if err == nil &&
					persisted.Phase == HostSelfUpdatePhaseStaged {
					injected = true
					return errors.New(
						"injected post-save promotion sync failure",
					)
				}
			}
			return syncDirectory(path)
		}

		response := handleLocalExecutorHostSelfUpdate(
			context.Background(),
			policy,
			ipcRequest,
			rt,
		)
		if !injected {
			t.Fatal("post-save promotion sync failure was not reached")
		}
		if response.Error != nil ||
			response.HostSelfUpdate == nil ||
			response.HostSelfUpdate.State.Phase != HostSelfUpdatePhaseStaged ||
			response.HostSelfUpdate.State.PendingGeneration != request.Generation {
			t.Fatalf("post-save convergence response=%#v", response)
		}
		grant, err := loadHostSelfUpdateGrantState(
			rt.grantStatePath,
			false,
		)
		if err != nil ||
			grant == nil ||
			grant.Phase != hostSelfUpdateGrantPhaseApplied ||
			!grant.matches(authorization) {
			t.Fatalf("post-save grant did not converge: %#v err=%v", grant, err)
		}
	})
}

func newHostSelfUpdateGrantHandlerFixture(
	t *testing.T,
) (
	hostSelfUpdateExecutorRuntime,
	LocalExecutorPolicy,
	HostSelfUpdateRequest,
	HostSelfUpdateGrantAuthorization,
	LocalExecutorRequest,
) {
	t.Helper()
	rt := newHostSelfUpdateGrantRecoveryRuntime(t)
	request := validHostSelfUpdateRequest()
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{
		PanelURL: "https://panel.example.com",
	}
	policy.SourcePolicyRevision = 7
	policy.ProjectionRevision = 11
	policy.PolicyRevision = 9
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: policy.ProjectionRevision,
		ExecutorPolicyRevision:  policy.PolicyRevision,
	}
	policySHA256, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		request,
		fence,
		policySHA256,
	)
	rt.consumeGrant = func(
		_ context.Context,
		_ string,
		value HostSelfUpdateGrantAuthorization,
	) (HostSelfUpdateGrantConsumeResult, error) {
		return consumedHostSelfUpdateGrant(value), nil
	}
	ipcRequest := LocalExecutorRequest{
		Version:                 LocalExecutorMutationProtocolVersion,
		Operation:               "host_self_update_stage",
		ServiceID:               policy.HostID,
		SourcePolicyRevision:    fence.SourcePolicyRevision,
		OwnershipEpoch:          fence.OwnershipEpoch,
		OwnershipPolicyRevision: fence.OwnershipPolicyRevision,
		ExecutorPolicyRevision:  fence.ExecutorPolicyRevision,
		HostSelfUpdate:          &request,
		HostSelfUpdateGrant:     &authorization,
	}
	return rt, policy, request, authorization, ipcRequest
}

func assertFailedHostSelfUpdateGrantTerminal(
	t *testing.T,
	rt hostSelfUpdateExecutorRuntime,
	request HostSelfUpdateRequest,
	authorization HostSelfUpdateGrantAuthorization,
) {
	t.Helper()
	persisted, err := rt.loadPersistedState()
	if err != nil ||
		persisted.Phase != HostSelfUpdatePhaseStable ||
		persisted.FailedGeneration != request.Generation {
		t.Fatalf("stage failure state=%#v err=%v", persisted, err)
	}
	grant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		false,
	)
	if err != nil ||
		grant == nil ||
		grant.Phase != hostSelfUpdateGrantPhaseFailed ||
		grant.Receipt != nil ||
		!grant.matches(authorization) {
		t.Fatalf("stage failure grant=%#v err=%v", grant, err)
	}
}

func TestHostSelfUpdateFailedStageGrantExactReplaySurvivesCleanup(
	t *testing.T,
) {
	rt := newHostSelfUpdateGrantRecoveryRuntime(t)
	request := validHostSelfUpdateRequest()
	state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
	if err != nil {
		t.Fatal(err)
	}
	state.FailedGeneration = request.Generation
	if err := rt.saveState(state); err != nil {
		t.Fatal(err)
	}
	policy := validLocalExecutorPolicy(t)
	policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	policy.Mutation = &LocalExecutorMutationPolicy{
		PanelURL: "https://panel.example.com",
	}
	policy.SourcePolicyRevision = 7
	policy.ProjectionRevision = 11
	policy.PolicyRevision = 9
	fence := LocalExecutorMutationFence{
		SourcePolicyRevision:    policy.SourcePolicyRevision,
		OwnershipEpoch:          3,
		OwnershipPolicyRevision: policy.ProjectionRevision,
		ExecutorPolicyRevision:  policy.PolicyRevision,
	}
	policySHA256, err := policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	authorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		request,
		fence,
		policySHA256,
	)
	if err := saveHostSelfUpdateGrantState(
		rt.grantStatePath,
		newHostSelfUpdateGrantState(authorization),
		false,
	); err != nil {
		t.Fatal(err)
	}
	if err := rt.cleanFailedHostSelfUpdateGrant(state); err != nil {
		t.Fatalf("converge failed stage grant: %v", err)
	}

	terminal, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if terminal == nil ||
		terminal.Phase != hostSelfUpdateGrantPhaseFailed ||
		!terminal.matches(authorization) {
		t.Fatalf("exact failed grant binding was not retained: %#v", terminal)
	}
	if err := os.Chmod(rt.stateRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	_, recoverErr := rt.recoverDurableHostSelfUpdateGrant(state)
	if err := os.Chmod(rt.stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if recoverErr != nil {
		t.Fatalf("exact failed grant recovery performed a write: %v", recoverErr)
	}

	consumeCalls := 0
	rt.consumeGrant = func(
		_ context.Context,
		_ string,
		value HostSelfUpdateGrantAuthorization,
	) (HostSelfUpdateGrantConsumeResult, error) {
		consumeCalls++
		return consumedHostSelfUpdateGrant(value), nil
	}
	ipcRequest := LocalExecutorRequest{
		Version:                 LocalExecutorMutationProtocolVersion,
		Operation:               "host_self_update_stage",
		ServiceID:               policy.HostID,
		SourcePolicyRevision:    fence.SourcePolicyRevision,
		OwnershipEpoch:          fence.OwnershipEpoch,
		OwnershipPolicyRevision: fence.OwnershipPolicyRevision,
		ExecutorPolicyRevision:  fence.ExecutorPolicyRevision,
		HostSelfUpdate:          &request,
		HostSelfUpdateGrant:     &authorization,
	}
	response := handleLocalExecutorHostSelfUpdate(
		context.Background(),
		policy,
		ipcRequest,
		rt,
	)
	if response.Error != nil ||
		response.HostSelfUpdate == nil ||
		response.HostSelfUpdate.State.Phase != HostSelfUpdatePhaseStable ||
		response.HostSelfUpdate.State.FailedGeneration != request.Generation ||
		consumeCalls != 0 {
		t.Fatalf(
			"exact failed stage replay was not idempotent: response=%#v calls=%d",
			response,
			consumeCalls,
		)
	}

	differentBinding := authorization
	differentBinding.Binding.ID = "different-grant-id"
	ipcRequest.HostSelfUpdateGrant = &differentBinding
	response = handleLocalExecutorHostSelfUpdate(
		context.Background(),
		policy,
		ipcRequest,
		rt,
	)
	if response.Error == nil ||
		response.Error.Code != "authorization_failed" ||
		response.HostSelfUpdate != nil ||
		consumeCalls != 0 {
		t.Fatalf(
			"different binding for failed generation was accepted: response=%#v calls=%d",
			response,
			consumeCalls,
		)
	}
	differentToken := authorization
	differentToken.Token = NewBoundedSecret(
		authorization.Token.Reveal() + "-different",
	)
	ipcRequest.HostSelfUpdateGrant = &differentToken
	response = handleLocalExecutorHostSelfUpdate(
		context.Background(),
		policy,
		ipcRequest,
		rt,
	)
	if response.Error == nil ||
		response.Error.Code != "authorization_failed" ||
		response.HostSelfUpdate != nil ||
		consumeCalls != 0 {
		t.Fatalf(
			"different token for failed grant was accepted: response=%#v calls=%d",
			response,
			consumeCalls,
		)
	}

	nextRequest := request
	nextRequest.Generation = "22222222-2222-4222-8222-222222222222"
	nextAuthorization := validHostSelfUpdateGrantAuthorization(
		"stage",
		nextRequest,
		fence,
		policySHA256,
	)
	if err := rt.authorizeHostSelfUpdate(
		context.Background(),
		policy.Mutation.PanelURL,
		nextAuthorization,
	); err != nil {
		t.Fatalf("authorize next generation: %v", err)
	}
	nextGrant, err := loadHostSelfUpdateGrantState(
		rt.grantStatePath,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if consumeCalls != 1 ||
		nextGrant == nil ||
		nextGrant.Phase != hostSelfUpdateGrantPhaseConsumed ||
		!nextGrant.matches(nextAuthorization) {
		t.Fatalf(
			"next generation did not replace terminal grant: grant=%#v calls=%d",
			nextGrant,
			consumeCalls,
		)
	}
}

func TestHostSelfUpdateFailedGenerationGrantConvergesAcrossAllPhases(
	t *testing.T,
) {
	for _, action := range []string{"cleanup", "fresh_recovery"} {
		action := action
		t.Run(action, func(t *testing.T) {
			for _, phase := range []string{
				hostSelfUpdateGrantPhasePrepared,
				hostSelfUpdateGrantPhaseConsumed,
				hostSelfUpdateGrantPhaseApplied,
			} {
				phase := phase
				t.Run(phase, func(t *testing.T) {
					stateRoot := t.TempDir()
					rt := hostSelfUpdateExecutorRuntime{
						stateRoot:      stateRoot,
						statePath:      filepath.Join(stateRoot, "state.json"),
						grantStatePath: filepath.Join(stateRoot, "grant.json"),
						allowTestPaths: true,
					}
					request := validHostSelfUpdateRequest()
					state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
					if err != nil {
						t.Fatal(err)
					}
					state.FailedGeneration = request.Generation
					authorization := validHostSelfUpdateGrantAuthorization(
						"stage",
						request,
						LocalExecutorMutationFence{
							SourcePolicyRevision:    7,
							OwnershipEpoch:          3,
							OwnershipPolicyRevision: 11,
							ExecutorPolicyRevision:  9,
						},
						"sha256:"+strings.Repeat("a", 64),
					)
					grant := newHostSelfUpdateGrantState(authorization)
					if phase != hostSelfUpdateGrantPhasePrepared {
						receipt := consumedHostSelfUpdateGrant(authorization).Grant
						grant.Phase = phase
						grant.Receipt = &receipt
					}
					if err := saveHostSelfUpdateGrantState(
						rt.grantStatePath,
						grant,
						false,
					); err != nil {
						t.Fatal(err)
					}

					switch action {
					case "cleanup":
						err = rt.cleanFailedHostSelfUpdateGrant(state)
					case "fresh_recovery":
						var recovered HostSelfUpdateState
						recovered, err = rt.recoverDurableHostSelfUpdateGrant(
							state,
						)
						if err == nil &&
							recovered.FailedGeneration !=
								state.FailedGeneration {
							t.Fatalf(
								"failed generation changed during recovery: %#v",
								recovered,
							)
						}
					default:
						t.Fatalf("unknown action %q", action)
					}
					if err != nil {
						t.Fatalf("%s %s grant: %v", action, phase, err)
					}
					remaining, err := loadHostSelfUpdateGrantState(
						rt.grantStatePath,
						false,
					)
					if err != nil {
						t.Fatal(err)
					}
					if remaining == nil ||
						remaining.Phase != hostSelfUpdateGrantPhaseFailed ||
						!remaining.matches(authorization) {
						t.Fatalf(
							"%s stage grant did not converge to exact failure: %#v",
							phase,
							remaining,
						)
					}
				})
			}
		})
	}
}

func TestHostSelfUpdateGrantRecoveryRejectsContradictoryAppliedGrantWithoutCleanup(
	t *testing.T,
) {
	for _, testCase := range []struct {
		name              string
		operation         string
		wantContradiction bool
		state             func(*testing.T, HostSelfUpdateRequest) HostSelfUpdateState
	}{
		{
			name:              "matching_staged_state_without_bound_slot",
			operation:         "stage",
			wantContradiction: true,
			state: func(
				t *testing.T,
				request HostSelfUpdateRequest,
			) HostSelfUpdateState {
				t.Helper()
				state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
				if err != nil {
					t.Fatal(err)
				}
				state, err = StageHostSelfUpdate(
					state,
					request,
					HostLifecycleBlockers{},
					validHostSelfUpdateSlotDigests(),
				)
				if err != nil {
					t.Fatal(err)
				}
				return state
			},
		},
		{
			name:              "different_failed_generation",
			operation:         "stage",
			wantContradiction: true,
			state: func(
				t *testing.T,
				_ HostSelfUpdateRequest,
			) HostSelfUpdateState {
				t.Helper()
				state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
				if err != nil {
					t.Fatal(err)
				}
				state.FailedGeneration = "different-generation"
				return state
			},
		},
		{
			name:      "matching_reconcile_grant",
			operation: "reconcile",
			state: func(
				t *testing.T,
				request HostSelfUpdateRequest,
			) HostSelfUpdateState {
				t.Helper()
				state, err := NewHostSelfUpdateState("v1.7.8", "v1.7.8")
				if err != nil {
					t.Fatal(err)
				}
				state.FailedGeneration = request.Generation
				return state
			},
		},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			stateRoot := t.TempDir()
			rt := hostSelfUpdateExecutorRuntime{
				stateRoot:      stateRoot,
				statePath:      filepath.Join(stateRoot, "state.json"),
				grantStatePath: filepath.Join(stateRoot, "grant.json"),
				allowTestPaths: true,
			}
			request := validHostSelfUpdateRequest()
			state := testCase.state(t, request)
			authorization := validHostSelfUpdateGrantAuthorization(
				testCase.operation,
				request,
				LocalExecutorMutationFence{
					SourcePolicyRevision:    7,
					OwnershipEpoch:          3,
					OwnershipPolicyRevision: 11,
					ExecutorPolicyRevision:  9,
				},
				"sha256:"+strings.Repeat("a", 64),
			)
			receipt := consumedHostSelfUpdateGrant(authorization).Grant
			grant := newHostSelfUpdateGrantState(authorization)
			grant.Phase = hostSelfUpdateGrantPhaseApplied
			grant.Receipt = &receipt
			if err := saveHostSelfUpdateGrantState(
				rt.grantStatePath,
				grant,
				false,
			); err != nil {
				t.Fatal(err)
			}

			recovered, err := rt.recoverDurableHostSelfUpdateGrant(state)
			if testCase.wantContradiction {
				if err == nil ||
					!strings.Contains(err.Error(), "contradicts runtime state") {
					t.Fatalf("contradictory applied grant was accepted: %#v err=%v", recovered, err)
				}
			} else {
				if err != nil {
					t.Fatalf("recover terminal applied grant: %v", err)
				}
				if recovered.Phase != state.Phase ||
					recovered.FailedGeneration != state.FailedGeneration {
					t.Fatalf("terminal grant changed runtime state: %#v", recovered)
				}
			}
			remaining, err := loadHostSelfUpdateGrantState(
				rt.grantStatePath,
				false,
			)
			if err != nil {
				t.Fatal(err)
			}
			if remaining == nil ||
				remaining.Phase != hostSelfUpdateGrantPhaseApplied {
				t.Fatalf("unrelated applied grant was removed: %#v", remaining)
			}
		})
	}
}
