//go:build !linux

package hostruntime

import (
	"context"
	"errors"
)

func (LocalExecutorClient) Probe(context.Context, string) (LocalExecutorProbe, error) {
	return LocalExecutorProbe{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) Stage(context.Context, MutationPlan, LocalExecutorMutationFence) (MutationStageResult, error) {
	return MutationStageResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) Apply(context.Context, MutationPlan, LocalExecutorMutationFence, BoundedSecret) (ApplyResult, error) {
	return ApplyResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) Reconcile(context.Context, MutationPlan, LocalExecutorMutationFence, BoundedSecret) (ApplyResult, error) {
	return ApplyResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) ApplyV2(context.Context, MutationPlan, LocalExecutorMutationFence, V2MutationGrant) (ApplyResult, error) {
	return ApplyResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) ReconcileV2(context.Context, MutationPlan, LocalExecutorMutationFence, V2MutationGrant) (ApplyResult, error) {
	return ApplyResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) PortReconfigure(context.Context, SystemdPortReconfigurePlan, LocalExecutorMutationFence, BoundedSecret) (SystemdPortReconfigureResult, error) {
	return SystemdPortReconfigureResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) PortReconfigureReconcile(context.Context, SystemdPortReconfigurePlan, LocalExecutorMutationFence, BoundedSecret) (SystemdPortReconfigureResult, error) {
	return SystemdPortReconfigureResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) PortReconfigureV2(context.Context, SystemdPortReconfigurePlan, LocalExecutorMutationFence, V2MutationGrant) (SystemdPortReconfigureResult, error) {
	return SystemdPortReconfigureResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) PortReconfigureReconcileV2(context.Context, SystemdPortReconfigurePlan, LocalExecutorMutationFence, V2MutationGrant) (SystemdPortReconfigureResult, error) {
	return SystemdPortReconfigureResult{}, errors.New("local executor client requires Linux")
}
