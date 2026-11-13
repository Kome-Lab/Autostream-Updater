package registry

import "context"

// LocalExecutorIdentity contains raw, read-only OS facts. PID/start ticks are not
// a v3 incarnation, clock, authority, Drain proof or independent restore witness.
type LocalExecutorIdentity struct {
	Knowledge  Knowledge
	BootID     ID
	ProcessID  uint64
	StartTicks uint64
}

type LocalExecutorIdentityReadPort interface {
	ReadLocalIdentity(context.Context) (LocalExecutorIdentity, error)
}

// FixedLocalExecutorIdentitySource reads only this process's fixed OS identity.
// It accepts no caller-controlled PID, path, URL or command.
type FixedLocalExecutorIdentitySource struct{}
