//go:build !linux

package registry

import "context"

func (FixedLocalExecutorIdentitySource) ReadLocalIdentity(ctx context.Context) (LocalExecutorIdentity, error) {
	if ctx == nil {
		return LocalExecutorIdentity{Knowledge: Unknown}, invalid("guard.local_identity")
	}
	if err := ctx.Err(); err != nil {
		return LocalExecutorIdentity{Knowledge: Unknown}, err
	}
	return LocalExecutorIdentity{Knowledge: Unknown}, fault(CodeEvidenceUnknown, "guard.local_identity_unsupported")
}
