package hostruntime

import (
	"context"
	"errors"
)

// The optional in-process observer carries only closed classifications. It is
// absent from production construction and never changes a wire response or
// receives the underlying error, policy, identity, or recovery payload.
type localExecutionFailureContextKey struct{}
type localExecutionFailurePhase uint8
type localExecutionFailureClass uint8

const (
	localFailurePolicySelect localExecutionFailurePhase = iota
	localFailurePolicySave
	localFailurePolicyWrite
	localFailurePolicyReload
	localFailurePolicyVerify
	localFailureForwardBudget
	localFailureForwardWrite
	localFailureForwardRestart
	localFailureForwardProbe
	localFailureProbeProjection
	localFailureProbeBefore
	localFailureProbeHTTP
	localFailureProbeDockerMapping
	localFailureProbeAfter
	localFailureProbeBaseline
	localFailureProbeResponse
	localFailureDockerContainer
	localFailureDockerPID
	localFailureDockerCgroup
	localFailureDockerVersion
	localFailureDockerListener
	localFailureSystemdRelease
	localFailureSystemdProcess
	localFailureSystemdPID
	localFailureSystemdCgroup
	localFailureSystemdListener
	localFailureHTTPHealth
	localFailureHTTPVersion
	localFailureDockerPrepareTarget
	localFailureDockerPrepareApplied
	localFailureDockerPrepareObserve
	localFailureDockerPrepareObservation
	localFailureDockerPrepareSnapshot
	localFailureDockerPrepareContainer
	localFailureDockerPrepareImage
	localFailureDockerPrepareRepository
	localFailureDockerPrepareVersionEnv
	localFailureDockerPrepareCompose
	localFailureDockerPrepareTargetPayload
	localFailureDockerPrepareRollbackPayload
	localFailureDockerPrepareTargetModel
	localFailureDockerPrepareRollbackModel
	localFailureDockerPrepareAvailability
	localFailureDockerVerifyTarget
	localFailureDockerVerifyObserve
	localFailureDockerVerifyIdentity
	localFailureDockerObserveMapping
	localFailureDockerObserveModel
	localFailureDockerObserveBaseline
	localFailureDockerObserveOwnership
	localFailureDockerObserveListener
	localFailureDockerObserveEndpoint
	localFailureDockerListenerBinding
	localFailureDockerListenerNamespace
	localFailureDockerListenerSocketTable
	localFailureDockerListenerOwnerProof
	localFailureDockerListenerRecheck
	localFailureDockerOwnerProcessDisappeared
	localFailureDockerOwnerDescriptorDisappeared
)

const (
	localFailureValidation localExecutionFailureClass = iota
	localFailureOperation
	localFailureDeadline
	localFailureCanceled
)

func observeLocalExecutionFailure(ctx context.Context, phase localExecutionFailurePhase, err error) {
	observer, _ := ctx.Value(localExecutionFailureContextKey{}).(func(localExecutionFailurePhase, localExecutionFailureClass))
	if observer == nil {
		return
	}
	class := localFailureOperation
	switch {
	case err == nil:
		class = localFailureValidation
	case errors.Is(err, context.DeadlineExceeded):
		class = localFailureDeadline
	case errors.Is(err, context.Canceled):
		class = localFailureCanceled
	}
	observer(phase, class)
}
