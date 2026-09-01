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

func (LocalExecutorClient) PortReconfigure(context.Context, SystemdPortReconfigurePlan, LocalExecutorMutationFence, BoundedSecret) (SystemdPortReconfigureResult, error) {
	return SystemdPortReconfigureResult{}, errors.New("local executor client requires Linux")
}

func (LocalExecutorClient) PortReconfigureReconcile(context.Context, SystemdPortReconfigurePlan, LocalExecutorMutationFence, BoundedSecret) (SystemdPortReconfigureResult, error) {
	return SystemdPortReconfigureResult{}, errors.New("local executor client requires Linux")
}
