package hostruntime

import (
	"fmt"
	"hash/fnv"
	"path/filepath"
	"strings"
	"time"
)

func (a *HostPullAgent) addRuntimeTokenRotationCapabilities(
	capabilities map[string]any,
) {
	if a == nil || capabilities == nil {
		return
	}
	status := a.runtimeCredentialStatus.Load()
	if status == nil ||
		(status.Phase != RuntimeCredentialPhaseLocalStaged &&
			status.Phase != RuntimeCredentialPhaseProofReady) {
		return
	}
	capabilities["runtime_token_rotation_id"] = status.RotationID
	capabilities["runtime_token_rotation_phase"] = status.Phase
	capabilities["execution_host_id"] = status.ExecutionHostID
	capabilities["executor_version"] = status.ExecutorVersion
	capabilities["executor_protocol_version"] =
		status.ExecutorProtocolVersion
	capabilities["mutation_protocol_version"] =
		status.MutationProtocolVersion
	capabilities["ownership_epoch"] = status.OwnershipEpoch
	capabilities["source_policy_revision"] =
		status.SourcePolicyRevision
	capabilities["projection_revision"] = status.ProjectionRevision
	capabilities["local_executor_policy_revision"] =
		status.LocalExecutorPolicyRevision
	capabilities["local_executor_policy_sha256"] =
		status.LocalExecutorPolicySHA256
	capabilities["local_stage_receipt_id"] = status.LocalStageReceiptID
	capabilities["local_phase"] = "staged_token_active"
}

func (a *HostPullAgent) recordRuntimeTokenRotationHeartbeat() {
	if a == nil {
		return
	}
	status := a.runtimeCredentialStatus.Load()
	if status == nil || status.Phase != RuntimeCredentialPhaseLocalStaged {
		a.runtimeCredentialHeartbeat.Store(nil)
		return
	}
	copy := *status
	a.runtimeCredentialHeartbeat.Store(&copy)
}

func deploymentAbsolutePath(path string) bool {
	if filepath.IsAbs(path) {
		return true
	}
	// Host artifacts are built and validated on Windows as well as Linux. A
	// slash-rooted deployment path must remain recognizable before it reaches
	// the Linux host where the service actually runs.
	return strings.HasPrefix(strings.TrimSpace(path), "/")
}

type hostAgentRetryState struct {
	base      time.Duration
	max       time.Duration
	identity  string
	operation string
	failures  uint
	next      time.Time
}

func newHostAgentRetryState(base time.Duration, identity, operation string) hostAgentRetryState {
	maximum := 5 * time.Minute
	if base <= maximum/32 {
		maximum = base * 32
	}
	if maximum < base {
		maximum = base
	}
	return hostAgentRetryState{
		base: base, max: maximum, identity: identity, operation: operation,
	}
}

func (r hostAgentRetryState) ready(now time.Time) bool {
	return r.next.IsZero() || !now.Before(r.next)
}

func (r *hostAgentRetryState) record(now time.Time, succeeded bool) {
	if succeeded {
		r.failures = 0
		r.next = time.Time{}
		return
	}
	r.failures++
	exponent := r.failures
	if exponent > 5 {
		exponent = 5
	}
	multiplier := time.Duration(uint64(1) << exponent)
	delay := r.max
	if r.base <= r.max/multiplier {
		delay = r.base * multiplier
	}
	delay = hostAgentJitteredInterval(delay, r.identity, fmt.Sprintf("%s-retry-%d", r.operation, r.failures))
	r.next = now.Add(delay)
}

func hostAgentJitteredInterval(base time.Duration, identity, operation string) time.Duration {
	if base <= 0 {
		return base
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.TrimSpace(identity)))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(operation))
	offsetPermille := int64(hasher.Sum32()%201) - 100
	jittered := base + time.Duration((int64(base)*offsetPermille)/1000)
	if jittered <= 0 {
		return base
	}
	return jittered
}
