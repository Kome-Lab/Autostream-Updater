package hostruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"reflect"
	"strconv"

	contracts "github.com/example/autostream-contracts/pkg/contracts"
)

// portAgentPolicyState extends the existing active journal. Candidates are
// credential-free projections of the original job, never authority for another
// job. ActiveSnapshotID changes only after exact root and listener observation.
type portAgentPolicyState struct {
	JobID            string          `json:"job_id"`
	PortIntentSHA256 string          `json:"port_intent_sha256"`
	Before           HostAgentPolicy `json:"before"`
	Target           HostAgentPolicy `json:"target"`
	Rollback         HostAgentPolicy `json:"rollback"`
	ActiveSnapshotID string          `json:"active_snapshot_id"`
}

func (s portAgentPolicyState) validate(job *UpdateJob, plan *SystemdPortReconfigurePlan) error {
	if job == nil || plan == nil || !isPortContractV2(*job) || plan.PortContractVersion != 2 ||
		plan.Before == nil || plan.Target == nil || plan.Rollback == nil || plan.Validate() != nil ||
		job.HostID != plan.HostID || job.TargetID != plan.TargetID || job.OwnershipEpoch != plan.OwnershipEpoch ||
		job.PolicyRevision != plan.Before.ProjectionRevision || job.EffectiveType() != plan.ServiceType || job.DeploymentMode != plan.DeploymentMode ||
		s.JobID != job.ID || s.JobID != plan.JobID || s.PortIntentSHA256 != job.PortReconfigure.PortPlanSHA256 ||
		s.PortIntentSHA256 != plan.PortIntentSHA256 || !samePortSnapshot(plan.Before, job.PortReconfigure.Before) ||
		!samePortSnapshot(plan.Target, job.PortReconfigure.Target) || !samePortSnapshot(plan.Rollback, job.PortReconfigure.Rollback) {
		return errors.New("active port policy identity is invalid")
	}
	for _, candidate := range []struct {
		policy HostAgentPolicy
		ref    *contracts.SystemUpdatePortSnapshotRef
	}{
		{s.Before, plan.Before}, {s.Target, plan.Target}, {s.Rollback, plan.Rollback},
	} {
		payload, err := json.Marshal(candidate.policy)
		selected, exists := hostPullPolicyTarget(candidate.policy, job.TargetID)
		if candidate.policy.validateForService(job.AgentServiceID, 0) != nil ||
			err != nil || len(payload) > hostAgentPolicyResponseMaxBytes || !exists || selected.EndpointRevision != candidate.ref.EndpointRevision ||
			candidate.policy.RuntimeTokenRotation != nil || candidate.policy.SelfUpdate != nil ||
			candidate.policy.ExecutionHostID != job.HostID || candidate.policy.OwnershipEpoch != job.OwnershipEpoch ||
			!portAgentPolicyMatchesSnapshot(candidate.policy, job.TargetID, candidate.ref) {
			return errors.New("active port policy candidate is invalid")
		}
	}
	if s.ActiveSnapshotID != plan.Before.SnapshotID && s.ActiveSnapshotID != plan.Target.SnapshotID && s.ActiveSnapshotID != plan.Rollback.SnapshotID {
		return errors.New("active port policy snapshot is invalid")
	}
	return nil
}

func portAgentPolicyMatchesSnapshot(policy HostAgentPolicy, targetID string, ref *contracts.SystemUpdatePortSnapshotRef) bool {
	if ref == nil || policy.SourcePolicyRevision != ref.SourcePolicyRevision || policy.Revision != ref.ProjectionRevision ||
		policy.LocalExecutorPolicyRevision != ref.ExecutorPolicyRevision || policy.LocalExecutorPolicySHA256 != ref.ExecutorPolicySHA256 {
		return false
	}
	target, ok := hostPullPolicyTarget(policy, targetID)
	if !ok || target.AppliedConfigRevision != ref.ConfigRevision || target.AppliedConfigSHA256 != ref.ConfigSHA256 ||
		target.AppliedEndpointRevision != ref.AppliedEndpointRevision || target.AppliedEndpoint == nil || target.AppliedEndpoint.Port != ref.AdvertisedPort {
		return false
	}
	endpointDigest, err := contracts.ComputeSystemUpdatePortEndpointSHA256(contracts.SystemUpdatePortEndpoint{
		Host: target.AppliedEndpoint.Host, Port: target.AppliedEndpoint.Port, SSLEnabled: target.AppliedEndpoint.SSLEnabled, PublicURL: target.AppliedEndpoint.PublicURL,
	})
	if err != nil || endpointDigest != ref.AdvertisedEndpointSHA256 {
		return false
	}
	if target.DeploymentMode == ModeSystemd {
		return ref.Docker == nil && target.LocalListenEndpoint != nil && target.LocalListenEndpoint.Port == ref.LocalListenPort
	}
	return target.DeploymentMode == ModeDocker && ref.Docker != nil && target.LocalHealthEndpoint != nil &&
		target.LocalHealthEndpoint.Host == ref.Docker.PublishedHostIP && target.LocalHealthEndpoint.Port == ref.Docker.HealthPort
}

func portClaimPolicyMatches(job UpdateJob, policy HostAgentPolicy, target HostAgentPolicyTarget) bool {
	if !isPortContractV2(job) || job.PortReconfigure.validatePortJobContract(job.DeploymentMode) != nil ||
		job.PolicyRevision != job.PortReconfigure.Before.ProjectionRevision || target.ServiceID != job.TargetID {
		return false
	}
	refs := []*contracts.SystemUpdatePortSnapshotRef{job.PortReconfigure.Before}
	if !job.RecoveryRequired && (target.EndpointRevision != job.PortReconfigure.Before.EndpointRevision && target.EndpointRevision != job.PortReconfigure.Target.EndpointRevision ||
		target.DesiredEndpoint == nil || target.DesiredEndpoint.Port != job.PortReconfigure.Target.AdvertisedPort) {
		return false
	}
	if job.RecoveryRequired {
		refs = append(refs, job.PortReconfigure.Target, job.PortReconfigure.Rollback)
	}
	for _, ref := range refs {
		if portAgentPolicyMatchesSnapshot(policy, job.TargetID, ref) {
			return true
		}
	}
	return false
}

func portPolicyCandidate(before HostAgentPolicy, targetID string, ref contracts.SystemUpdatePortSnapshotRef) (HostAgentPolicy, error) {
	candidate := clonePortAgentPolicy(before)
	candidate.SourcePolicyRevision, candidate.Revision = ref.SourcePolicyRevision, ref.ProjectionRevision
	candidate.LocalExecutorPolicyRevision, candidate.LocalExecutorPolicySHA256 = ref.ExecutorPolicyRevision, ref.ExecutorPolicySHA256
	for index := range candidate.Targets {
		target := &candidate.Targets[index]
		if target.ServiceID != targetID {
			continue
		}
		if target.AppliedEndpoint == nil {
			return HostAgentPolicy{}, errors.New("port candidate lacks an applied endpoint")
		}
		target.EndpointRevision, target.AppliedEndpointRevision = ref.EndpointRevision, ref.AppliedEndpointRevision
		target.AppliedConfigRevision, target.AppliedConfigSHA256 = ref.ConfigRevision, ref.ConfigSHA256
		endpoint, err := portAdvertisedEndpoint(*target.AppliedEndpoint, ref.AdvertisedPort)
		if err != nil {
			return HostAgentPolicy{}, err
		}
		target.AppliedEndpoint = &endpoint
		desired := endpoint
		target.DesiredEndpoint = &desired
		if target.DeploymentMode == ModeSystemd {
			if target.LocalListenEndpoint == nil {
				return HostAgentPolicy{}, errors.New("port candidate lacks a local listener")
			}
			listener, err := portAdvertisedEndpoint(*target.LocalListenEndpoint, ref.LocalListenPort)
			if err != nil {
				return HostAgentPolicy{}, err
			}
			target.LocalListenEndpoint = &listener
			if target.LocalHealthEndpoint != nil {
				health, err := portAdvertisedEndpoint(*target.LocalHealthEndpoint, ref.LocalListenPort)
				if err != nil {
					return HostAgentPolicy{}, err
				}
				target.LocalHealthEndpoint = &health
			}
		} else {
			if ref.Docker == nil || target.LocalHealthEndpoint == nil {
				return HostAgentPolicy{}, errors.New("port candidate lacks a Docker health endpoint")
			}
			health, err := portAdvertisedEndpoint(*target.LocalHealthEndpoint, ref.Docker.HealthPort)
			if err != nil {
				return HostAgentPolicy{}, err
			}
			target.LocalHealthEndpoint = &health
			if target.LocalListenEndpoint != nil {
				listener, err := portAdvertisedEndpoint(*target.LocalListenEndpoint, ref.LocalListenPort)
				if err != nil {
					return HostAgentPolicy{}, err
				}
				target.LocalListenEndpoint = &listener
			}
		}
		return candidate, nil
	}
	return HostAgentPolicy{}, errors.New("port candidate target is unavailable")
}

func portAdvertisedEndpoint(before HostAgentEndpoint, port int) (HostAgentEndpoint, error) {
	after := before
	after.Port = port
	if before.PublicURL == "" || before.Port == port {
		return after, nil
	}
	parsed, err := url.Parse(before.PublicURL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return HostAgentEndpoint{}, errors.New("port advertised endpoint is invalid")
	}
	parsed.Host = net.JoinHostPort(parsed.Hostname(), strconv.Itoa(port))
	// Match the existing CP endpoint transition: changed authorities include
	// their explicit port, including 443/80. B and R return above unchanged.
	after.PublicURL = parsed.String()
	return after, nil
}

func (j *Journal) StagePortPolicy(policy HostAgentPolicy, job UpdateJob, plan SystemdPortReconfigurePlan) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if j.data.ActivePortPolicy != nil {
		return j.data.ActivePortPolicy.validate(&job, &plan)
	}
	if policy.RuntimeTokenRotation != nil || policy.SelfUpdate != nil ||
		!portAgentPolicyMatchesSnapshot(policy, job.TargetID, plan.Before) {
		return errors.New("port policy candidates require the original before snapshot")
	}
	before, err := portPolicyCandidate(policy, job.TargetID, *plan.Before)
	if err != nil {
		return err
	}
	target, err := portPolicyCandidate(before, job.TargetID, *plan.Target)
	if err != nil {
		return err
	}
	rollback, err := portPolicyCandidate(before, job.TargetID, *plan.Rollback)
	if err != nil {
		return err
	}
	state := &portAgentPolicyState{JobID: job.ID, PortIntentSHA256: plan.PortIntentSHA256,
		Before: before, Target: target, Rollback: rollback, ActiveSnapshotID: plan.Before.SnapshotID}
	if err := state.validate(&job, &plan); err != nil {
		return err
	}
	j.data.ActivePortPolicy = state
	return j.saveLocked()
}

func (j *Journal) portPolicyCandidate(snapshotID string) (*HostAgentPolicy, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.data.ActivePortPolicy == nil {
		return nil, errors.New("port policy candidates are unavailable")
	}
	state := j.data.ActivePortPolicy
	if err := state.validate(j.data.ActiveJob, j.data.ActivePortPlan); err != nil {
		return nil, err
	}
	if snapshotID == "" {
		snapshotID = state.ActiveSnapshotID
	}
	var policy HostAgentPolicy
	switch snapshotID {
	case j.data.ActivePortPlan.Before.SnapshotID:
		policy = state.Before
	case j.data.ActivePortPlan.Target.SnapshotID:
		policy = state.Target
	case j.data.ActivePortPlan.Rollback.SnapshotID:
		policy = state.Rollback
	default:
		return nil, errors.New("port policy snapshot is outside the original job")
	}
	copy := clonePortAgentPolicy(policy)
	return &copy, nil
}

func (j *Journal) adoptPortPolicy(jobID, snapshotID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.checkMutableLocked(); err != nil {
		return err
	}
	if j.data.ActivePortPolicy == nil || j.data.ActivePortPolicy.JobID != jobID ||
		j.data.ActivePortPolicy.validate(j.data.ActiveJob, j.data.ActivePortPlan) != nil {
		return errors.New("port policy adoption identity is invalid")
	}
	if j.data.ActivePortPolicy.ActiveSnapshotID == j.data.ActivePortPlan.Rollback.SnapshotID && snapshotID != j.data.ActivePortPlan.Rollback.SnapshotID {
		return errors.New("port rollback projection cannot return to target")
	}
	if snapshotID != j.data.ActivePortPlan.Before.SnapshotID && snapshotID != j.data.ActivePortPlan.Target.SnapshotID && snapshotID != j.data.ActivePortPlan.Rollback.SnapshotID {
		return errors.New("port policy adoption snapshot is invalid")
	}
	j.data.ActivePortPolicy.ActiveSnapshotID = snapshotID
	return j.saveLocked()
}

func (a *HostPullAgent) portRecoveryPolicy(current HostAgentPolicy) (HostAgentPolicy, error) {
	if a == nil || a.Journal == nil {
		return current, nil
	}
	active := a.Journal.Active()
	if active == nil || !isPortContractV2(*active) {
		return current, nil
	}
	if current.ServiceID != active.AgentServiceID || current.ExecutionHostID != active.HostID || current.OwnershipEpoch != active.OwnershipEpoch {
		return HostAgentPolicy{}, errors.New("port recovery policy ownership changed")
	}
	candidate, err := a.Journal.portPolicyCandidate("")
	if err != nil {
		if portAgentPolicyMatchesSnapshot(current, active.TargetID, active.PortReconfigure.Before) {
			return current, nil
		}
		return HostAgentPolicy{}, err
	}
	recognized := false
	for _, ref := range []*contracts.SystemUpdatePortSnapshotRef{active.PortReconfigure.Before, active.PortReconfigure.Target, active.PortReconfigure.Rollback} {
		if current.SourcePolicyRevision == ref.SourcePolicyRevision && current.Revision == ref.ProjectionRevision &&
			current.LocalExecutorPolicyRevision == ref.ExecutorPolicyRevision && current.LocalExecutorPolicySHA256 == ref.ExecutorPolicySHA256 {
			recognized = true
		}
	}
	if !recognized {
		return HostAgentPolicy{}, errors.New("port recovery received an unrelated policy generation")
	}
	// A normal CP GET may still expose T while root has restored R. A saved
	// exact same-job projection remains active until terminal acknowledgement.
	return *candidate, nil
}

func (a *HostPullAgent) verifyPortResultProjection(ctx context.Context, job UpdateJob, plan SystemdPortReconfigurePlan, result SystemdPortReconfigureResult) (SystemdPortReconfigureResult, error) {
	if result.PortResult == nil {
		return SystemdPortReconfigureResult{}, errors.New("port result observation is missing")
	}
	if !contracts.IsAcceptedSystemUpdatePortResult(*result.PortResult) {
		if !result.RecoveryRequired {
			return SystemdPortReconfigureResult{}, errors.New("failed port recovery omitted its hold")
		}
		return result, nil
	}
	if a.Journal == nil || a.ObserveTargets == nil {
		return SystemdPortReconfigureResult{}, errors.New("port projection observer is unavailable")
	}
	candidate, err := a.Journal.portPolicyCandidate(result.PortResult.ObservedSnapshotID)
	if err != nil {
		return SystemdPortReconfigureResult{}, err
	}
	observations, err := a.ObserveTargets(ctx, *candidate)
	if err != nil || portPolicyBaseline(*candidate, observations) == nil {
		return SystemdPortReconfigureResult{}, errors.New("port projection could not be verified")
	}
	seen := map[string]bool{}
	for _, observation := range observations {
		target, ok := hostPullPolicyTarget(*candidate, observation.ServiceID)
		if !ok || seen[observation.ServiceID] || observation.Availability != TargetAvailabilityAvailable ||
			observation.PolicyRevision != candidate.LocalExecutorPolicyRevision || observation.PolicySHA256 != candidate.LocalExecutorPolicySHA256 ||
			observation.ConfigRevision != target.AppliedConfigRevision || observation.ConfigSHA256 != target.AppliedConfigSHA256 {
			return SystemdPortReconfigureResult{}, errors.New("port projection differs from verified root state")
		}
		seen[observation.ServiceID] = true
	}
	typed := clonePortResult(result.PortResult)
	typed.Observation.AgentProjectionVerified = true
	if contracts.ValidateSystemUpdatePortResult(plan.SharedPortPlan(), *typed) != nil {
		return SystemdPortReconfigureResult{}, errors.New("port projection result is invalid")
	}
	if accepted := a.Journal.Active().PortResult; accepted != nil && !contracts.EqualSystemUpdatePortResults(*accepted, *typed) {
		return SystemdPortReconfigureResult{}, errors.New("port recovery cannot replace an accepted result")
	}
	if err := a.Journal.adoptPortPolicy(job.ID, typed.ObservedSnapshotID); err != nil {
		return SystemdPortReconfigureResult{}, err
	}
	active, err := a.Journal.portPolicyCandidate("")
	if err != nil || !reflect.DeepEqual(active, candidate) {
		return SystemdPortReconfigureResult{}, errors.New("port projection adoption was not durable")
	}
	result.PortResult = typed
	return result, nil
}

func isPortRecoveryObservation(report JobReport) bool {
	return report.Status == "failed" && report.PortReconfigure != nil &&
		report.PortReconfigure.Result == contracts.SystemUpdatePortReconfigurationRollbackFailed &&
		!report.PortReconfigure.Observation.ObservedAt.IsZero()
}
