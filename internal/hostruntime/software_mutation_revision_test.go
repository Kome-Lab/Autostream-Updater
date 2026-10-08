package hostruntime

import (
	"strings"
	"testing"
	"time"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

// Software updates preserve the application's configuration revision while the
// source, projection and executor policies fence a separate host authority.
func TestSoftwareMutationGrantSeparatesConfigurationAndPolicyRevisions(t *testing.T) {
	for _, revisions := range []struct {
		name                         string
		source, projection, executor int64
	}{
		{name: "configuration_one_policy_eight", source: 8, projection: 8, executor: 8},
		{name: "all_revision_authorities_differ", source: 11, projection: 13, executor: 17},
	} {
		for _, operation := range []string{"apply", "reconcile"} {
			for _, root := range []bool{false, true} {
				name := revisions.name + "/" + operation + "/agent_preflight"
				if root {
					name = revisions.name + "/" + operation + "/root_policy"
				}
				t.Run(name, func(t *testing.T) {
					fixture := newSoftwareMutationRevisionFixture(t, revisions.source, revisions.projection, revisions.executor)
					fixture.binding.Operation = contracts.UpdaterMutationOperation(operation)
					var policy *LocalExecutorPolicy
					var target *LocalExecutorTarget
					if root {
						policy = &fixture.policy
						target = &fixture.policy.Targets[0]
					}
					if err := validateV2SoftwareMutationGrantBinding(fixture.now, fixture.binding, operation, fixture.plan, fixture.fence, policy, target); err != nil {
						t.Fatalf("C=1 S=%d P=%d E=%d F=3 rejected: %v", revisions.source, revisions.projection, revisions.executor, err)
					}
				})
			}
		}
	}
}

func TestSoftwareMutationGrantRejectsRevisionSubstitution(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*softwareMutationRevisionFixture)
	}{
		{"desired_configuration_from_projection", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.DesiredRevision = f.fence.OwnershipPolicyRevision
		}},
		{"desired_configuration_from_source", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.DesiredRevision = f.fence.SourcePolicyRevision
		}},
		{"desired_configuration_from_executor", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.DesiredRevision = f.fence.ExecutorPolicyRevision
		}},
		{"expected_configuration_from_projection", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.Target.ExpectedConfigRevision = f.fence.OwnershipPolicyRevision
		}},
		{"root_configuration_from_projection", func(f *softwareMutationRevisionFixture) {
			f.policy.Targets[0].ConfigRevision = f.policy.ProjectionRevision
		}},
		{"source_fence_from_projection", func(f *softwareMutationRevisionFixture) {
			f.fence.SourcePolicyRevision = f.fence.OwnershipPolicyRevision
		}},
		{"projection_fence_from_configuration", func(f *softwareMutationRevisionFixture) { f.fence.OwnershipPolicyRevision = 1 }},
		{"projection_fence_from_executor", func(f *softwareMutationRevisionFixture) {
			f.fence.OwnershipPolicyRevision = f.fence.ExecutorPolicyRevision
		}},
		{"executor_fence_from_projection", func(f *softwareMutationRevisionFixture) {
			f.fence.ExecutorPolicyRevision = f.fence.OwnershipPolicyRevision
		}},
		{"ownership_epoch_from_configuration", func(f *softwareMutationRevisionFixture) { f.fence.OwnershipEpoch = 1 }},
		{"source_policy_drift", func(f *softwareMutationRevisionFixture) { f.policy.SourcePolicyRevision++ }},
		{"projection_policy_drift", func(f *softwareMutationRevisionFixture) { f.policy.ProjectionRevision++ }},
		{"executor_policy_drift", func(f *softwareMutationRevisionFixture) { f.policy.PolicyRevision++ }},
		{"plan_policy_digest_drift", func(f *softwareMutationRevisionFixture) { f.plan.ConfigSHA256 = "sha256:" + strings.Repeat("e", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSoftwareMutationRevisionFixture(t, 11, 13, 17)
			test.mutate(&fixture)
			// Keep the mutated command and local plan individually valid. A
			// rejection must come from binding their separate authorities.
			fixture.refreshCommandDigest(t)
			fixture.refreshPlanDigest(t)
			if err := contracts.ValidateUpdaterMutationGrantBinding(fixture.now, fixture.binding); err != nil {
				t.Fatalf("negative fixture is not a valid grant: %v", err)
			}
			if err := fixture.plan.Validate(); err != nil {
				t.Fatalf("negative fixture is not a valid plan: %v", err)
			}
			if err := validateV2SoftwareMutationGrantBinding(fixture.now, fixture.binding, "apply", fixture.plan, fixture.fence, &fixture.policy, &fixture.policy.Targets[0]); err == nil {
				t.Fatal("independent revision authority was substituted")
			}
		})
	}
}

func TestSoftwareMutationGrantRejectsInvalidAuthorizationAndPlan(t *testing.T) {
	for _, test := range []struct {
		name          string
		mutate        func(*softwareMutationRevisionFixture)
		refreshDigest bool
	}{
		{"expired_lease", func(f *softwareMutationRevisionFixture) { f.binding.Lease.LeaseExpiresAt = f.now.Add(-time.Second) }, false},
		{"expired_authorization", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.ExpiresAt = f.now.Add(-time.Second)
		}, false},
		{"generation_mismatch", func(f *softwareMutationRevisionFixture) { f.binding.Lease.LeaseGeneration++ }, false},
		{"ownership_epoch_mismatch", func(f *softwareMutationRevisionFixture) { f.binding.Lease.Command.MutationAuthorization.Fence++ }, true},
		{"job_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.JobID = "job-other"
		}, false},
		{"host_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.HostID = "host-other"
		}, false},
		{"target_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.Target.ServiceID = "worker-other"
		}, true},
		{"service_type_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.Target.ServiceType = contracts.SystemUpdateTargetObservability
		}, true},
		{"deployment_mode_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.Target.DeploymentMode = contracts.SystemUpdateDeploymentDocker
		}, true},
		{"current_version_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.DesiredOperation.SoftwareUpdate.ExpectedCurrentVersion = "v1.9.9"
		}, true},
		{"target_version_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.DesiredOperation.SoftwareUpdate.TargetVersion = "v2.0.2"
		}, true},
		{"mutation_operation_mismatch", func(f *softwareMutationRevisionFixture) { f.binding.Operation = contracts.UpdaterMutationReconcile }, false},
		{"session_mismatch", func(f *softwareMutationRevisionFixture) { f.binding.SessionID = "session-other-12345678" }, false},
		{"canonical_digest_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.CanonicalPayloadDigest = "sha256:" + strings.Repeat("b", 64)
		}, false},
		{"authorization_digest_mismatch", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.CanonicalArgumentDigest = "sha256:" + strings.Repeat("c", 64)
		}, false},
		{"reusable_authorization", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.OneTime = false
		}, false},
		{"unsupported_capability", func(f *softwareMutationRevisionFixture) {
			f.binding.Lease.Command.MutationAuthorization.RequiredCapability = contracts.UpdaterCapabilityBootstrap
		}, false},
		{"plan_hash_mismatch", func(f *softwareMutationRevisionFixture) { f.plan.PlanSHA256 = strings.Repeat("d", 64) }, false},
		{"invalid_root_policy", func(f *softwareMutationRevisionFixture) { f.policy.SchemaVersion = 0 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSoftwareMutationRevisionFixture(t, 11, 13, 17)
			test.mutate(&fixture)
			if test.refreshDigest {
				fixture.refreshCommandDigest(t)
			}
			if err := validateV2SoftwareMutationGrantBinding(fixture.now, fixture.binding, "apply", fixture.plan, fixture.fence, &fixture.policy, &fixture.policy.Targets[0]); err == nil {
				t.Fatal("invalid software authorization or immutable plan was accepted")
			}
		})
	}
}

func TestSoftwareMutationGrantRequiresCompleteRootPolicyBinding(t *testing.T) {
	fixture := newSoftwareMutationRevisionFixture(t, 11, 13, 17)
	for _, test := range []struct {
		name   string
		policy *LocalExecutorPolicy
		target *LocalExecutorTarget
	}{
		{"missing_root_target", &fixture.policy, nil},
		{"missing_root_policy", nil, &fixture.policy.Targets[0]},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateV2SoftwareMutationGrantBinding(fixture.now, fixture.binding, "apply", fixture.plan, fixture.fence, test.policy, test.target); err == nil {
				t.Fatal("partial root policy binding was accepted")
			}
		})
	}
}

func TestSoftwareMutationGrantRejectsNonPositiveFence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*LocalExecutorMutationFence, int64)
	}{
		{"source_policy_revision", func(f *LocalExecutorMutationFence, value int64) { f.SourcePolicyRevision = value }},
		{"projection_policy_revision", func(f *LocalExecutorMutationFence, value int64) { f.OwnershipPolicyRevision = value }},
		{"executor_policy_revision", func(f *LocalExecutorMutationFence, value int64) { f.ExecutorPolicyRevision = value }},
		{"ownership_epoch", func(f *LocalExecutorMutationFence, value int64) { f.OwnershipEpoch = value }},
	} {
		for _, value := range []int64{0, -1} {
			name := test.name + "/zero"
			if value < 0 {
				name = test.name + "/negative"
			}
			t.Run(name, func(t *testing.T) {
				fixture := newSoftwareMutationRevisionFixture(t, 11, 13, 17)
				test.mutate(&fixture.fence, value)
				if err := validateV2SoftwareMutationGrantBinding(fixture.now, fixture.binding, "apply", fixture.plan, fixture.fence, nil, nil); err == nil {
					t.Fatal("non-positive fence was accepted before root policy verification")
				}
			})
		}
	}
}

type softwareMutationRevisionFixture struct {
	now     time.Time
	policy  LocalExecutorPolicy
	plan    MutationPlan
	fence   LocalExecutorMutationFence
	binding contracts.UpdaterMutationGrantBinding
}

func newSoftwareMutationRevisionFixture(t *testing.T, source, projection, executor int64) softwareMutationRevisionFixture {
	t.Helper()
	f := softwareMutationRevisionFixture{now: time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)}
	f.policy = validLocalExecutorPolicy(t)
	f.policy.SchemaVersion = LocalExecutorMutationPolicySchemaVersion
	f.policy.ProtocolVersion = LocalExecutorMutationProtocolVersion
	f.policy.Mutation = &LocalExecutorMutationPolicy{PanelURL: "https://panel.example.com"}
	f.policy.SourcePolicyRevision = source
	f.policy.ProjectionRevision = projection
	f.policy.PolicyRevision = executor
	f.policy.Targets[0].ConfigRevision = 1
	if err := f.policy.Validate(); err != nil {
		t.Fatalf("software revision fixture root policy: %v", err)
	}
	policySHA256, err := f.policy.SHA256()
	if err != nil {
		t.Fatal(err)
	}
	f.plan = MutationPlan{
		JobID: "job-software-revision", HostID: f.policy.HostID, TargetID: f.policy.Targets[0].ServiceID,
		ServiceType: f.policy.Targets[0].ServiceType, DeploymentMode: ModeSystemd,
		CurrentVersion: "v2.0.0", TargetVersion: "v2.0.1", ExpectedVersion: "v2.0.1",
		ConfigSHA256: policySHA256, LeaseGeneration: 1,
		ArtifactDigest: strings.Repeat("a", 64), SessionID: "session-software-revision-12345678",
	}
	f.refreshPlanDigest(t)
	f.fence = LocalExecutorMutationFence{
		SourcePolicyRevision: source, OwnershipEpoch: 3,
		OwnershipPolicyRevision: projection, ExecutorPolicyRevision: executor,
	}
	f.binding = contracts.UpdaterMutationGrantBinding{
		Lease: contracts.UpdaterLeaseEnvelope{
			ProtocolVersion: 2, LeaseID: "lease-software-revision", LeaseGeneration: 1,
			LeaseExpiresAt: f.now.Add(5 * time.Minute),
			Command: contracts.UpdaterCommandEnvelope{
				ProtocolVersion: 2, CommandID: "command-software-revision", IdempotencyKey: "idempotency-software-revision",
				Issuer: contracts.UpdaterCommandIssuer{
					ServiceID: "control-panel-fixture", ServiceType: "control_panel",
					Authentication: "assignment_bound_rotating_service_identity", Permission: "updates.authorize",
				},
				MutationAuthorization: contracts.UpdaterMutationAuthorization{
					AuthorizationID: "authorization-software-revision", NonceID: "nonce-software-revision-12345678",
					JobID: f.plan.JobID, UpdaterID: "updater-fixture", HostID: f.plan.HostID,
					ActionType: contracts.UpdaterCapabilityUpdate, RequiredCapability: contracts.UpdaterCapabilityUpdate,
					Target: contracts.UpdaterTargetIdentity{
						TargetKind: contracts.UpdaterTargetApplication, ServiceID: f.plan.TargetID,
						ServiceType: contracts.SystemUpdateTargetType(f.plan.ServiceType), DeploymentMode: contracts.SystemUpdateDeploymentSystemd,
						ExpectedConfigRevision: 1,
					},
					DesiredRevision: 1, Fence: 3, ExpiresAt: f.now.Add(10 * time.Minute), OneTime: true,
				},
				DesiredOperation: contracts.UpdaterDesiredOperation{
					Operation: contracts.UpdaterDesiredSoftwareUpdate,
					SoftwareUpdate: &contracts.UpdaterSoftwareUpdateDesiredOperation{
						ExpectedCurrentVersion: f.plan.CurrentVersion, TargetVersion: f.plan.TargetVersion, Strategy: contracts.SystemUpdateWhenIdle,
					},
				},
				AuditCorrelationID: "audit-software-revision",
			},
		},
		Operation: contracts.UpdaterMutationApply, SessionID: f.plan.SessionID,
	}
	f.refreshCommandDigest(t)
	if err := f.plan.Validate(); err != nil {
		t.Fatalf("software revision fixture plan: %v", err)
	}
	if err := contracts.ValidateUpdaterMutationGrantBinding(f.now, f.binding); err != nil {
		t.Fatalf("software revision fixture grant: %v", err)
	}
	return f
}

func (f *softwareMutationRevisionFixture) refreshCommandDigest(t *testing.T) {
	t.Helper()
	command := &f.binding.Lease.Command
	authorization := &command.MutationAuthorization
	digest, err := contracts.ComputeUpdaterCommandCanonicalDigest(authorization.Target, authorization.DesiredRevision, authorization.Fence, command.DesiredOperation)
	if err != nil {
		t.Fatalf("software revision fixture command digest: %v", err)
	}
	command.CanonicalPayloadDigest = digest
	authorization.CanonicalArgumentDigest = digest
}

func (f *softwareMutationRevisionFixture) refreshPlanDigest(t *testing.T) {
	t.Helper()
	digest, err := f.plan.ComputePlanSHA256()
	if err != nil {
		t.Fatalf("software revision fixture plan digest: %v", err)
	}
	f.plan.PlanSHA256 = digest
}
