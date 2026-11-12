package registry

import (
	"os"
)

// RegistryLifecycleState reports tracked owner state, never mutation authority.
type RegistryLifecycleState string

const (
	LifecycleOpen      RegistryLifecycleState = "OPEN"
	LifecycleClosing   RegistryLifecycleState = "CLOSING"
	LifecycleClosed    RegistryLifecycleState = "CLOSED"
	LifecycleUncertain RegistryLifecycleState = "UNCERTAIN"
	LifecycleUnknown   RegistryLifecycleState = "UNKNOWN"
)

// Unknown facts have no asserted value. A false confirmed-release fact means
// that the owner has not confirmed release; it is not proof of physical retention.
type LifecycleFact struct {
	Knowledge Knowledge
	Value     bool
}

type LifecycleCount struct {
	Knowledge Knowledge
	Value     int64
}

type LifecycleDrainState string

const (
	LifecycleDrainUnknown  LifecycleDrainState = "UNKNOWN"
	LifecycleDrainIdle     LifecycleDrainState = "IDLE"
	LifecycleDrainActive   LifecycleDrainState = "ACTIVE"
	LifecycleDrainWaiting  LifecycleDrainState = "WAITING"
	LifecycleDrainComplete LifecycleDrainState = "COMPLETE"
)

type LifecycleCloseResult string

const (
	LifecycleCloseNotStarted LifecycleCloseResult = "NOT_STARTED"
	LifecycleClosePending    LifecycleCloseResult = "PENDING"
	LifecycleCloseSucceeded  LifecycleCloseResult = "SUCCEEDED"
	LifecycleCloseUnknown    LifecycleCloseResult = "UNKNOWN"
)

type LifecyclePoolDiagnostic struct {
	Knowledge       Knowledge
	OpenConnections int
	InUse           int
	Idle            int
}

type LifecycleHeaderDiagnostic struct {
	// ReferenceHeld means the Go resource reference, not a live OS descriptor.
	ReferenceHeld LifecycleFact
	Valid         LifecycleFact
	Closed        LifecycleFact
	CloseStarted  LifecycleFact
	Released      LifecycleFact
}

type LifecycleLeaseDiagnostic struct {
	Held            LifecycleFact
	OwnerConsistent LifecycleFact
	Released        LifecycleFact
}

type LifecycleCloseDiagnostic struct {
	Started        LifecycleFact
	Finished       LifecycleFact
	Result         LifecycleCloseResult
	PoolReleased   LifecycleFact
	HeaderReleased LifecycleFact
	LeaseReleased  LifecycleFact
}

// RegistryLifecycleDiagnostic is an explicit safe projection. It contains no
// path, URI, SQL, raw error, credential, file identity, descriptor number or
// resource pointer. OPEN/admission/drain are diagnostics, not execution grants.
type RegistryLifecycleDiagnostic struct {
	State      RegistryLifecycleState
	// Consistency describes the tracked owner frame only. Stats and filesystem
	// facts are best-effort observations, not one globally atomic snapshot.
	Consistency        Knowledge
	ActiveOperations   LifecycleCount
	AcceptingOperations LifecycleFact
	Drain              LifecycleDrainState
	Pool               LifecyclePoolDiagnostic
	Header             LifecycleHeaderDiagnostic
	Lease              LifecycleLeaseDiagnostic
	Close              LifecycleCloseDiagnostic
}

// All fields are private, deliberately separate from the exported diagnostic.
// The frame is copied while holding gate; no resource method is called there.
type registryLifecycleFrame struct {
	version           uint64
	active            int64
	ready             bool
	closing           bool
	uncertain         bool
	drainFinished     bool
	closeFinished     bool
	closeError        bool
	poolCloseStarted  bool
	poolReleased      bool
	headerCloseStarted bool
	headerReleased    bool
	leaseReleased     bool
	pool              registryConnectionPool
	header            registryHeaderFD
	headerDescriptor  int
	headerProbe       func(int, os.FileInfo) registryHeaderProbeResult
	path              string
	identity          os.FileInfo
	lease             *registryInodeLease
}

type registryLifecycleSnapshot struct {
	frame           registryLifecycleFrame
	stable          bool
	pool            LifecyclePoolDiagnostic
	headerReference LifecycleFact
	headerValid     LifecycleFact
	headerClosed    LifecycleFact
	pathValid       LifecycleFact
	leaseHeld       LifecycleFact
	leaseLinked     LifecycleFact
}

func lifecycleKnown(value bool) LifecycleFact {
	return LifecycleFact{Knowledge: Known, Value: value}
}

func lifecycleUnknown() LifecycleFact {
	return LifecycleFact{Knowledge: Unknown}
}

func unknownRegistryLifecycleDiagnostic() RegistryLifecycleDiagnostic {
	unknown := lifecycleUnknown()
	return RegistryLifecycleDiagnostic{
		State: LifecycleUnknown, Consistency: Unknown,
		ActiveOperations: LifecycleCount{Knowledge: Unknown},
		AcceptingOperations: unknown, Drain: LifecycleDrainUnknown,
		Pool: LifecyclePoolDiagnostic{Knowledge: Unknown},
		Header: LifecycleHeaderDiagnostic{
			ReferenceHeld: unknown, Valid: unknown, Closed: unknown,
			CloseStarted: unknown, Released: unknown,
		},
		Lease: LifecycleLeaseDiagnostic{Held: unknown, OwnerConsistent: unknown, Released: unknown},
		Close: LifecycleCloseDiagnostic{
			Started: unknown, Finished: unknown, Result: LifecycleCloseUnknown,
			PoolReleased: unknown, HeaderReleased: unknown, LeaseReleased: unknown,
		},
	}
}

func (owner *registryLifecycleOwner) lifecycleFrame() registryLifecycleFrame {
	owner.gate.Lock()
	defer owner.gate.Unlock()
	return registryLifecycleFrame{
		version: owner.observationVersion, active: owner.activeOperations,
		ready: owner.ready, closing: owner.closing.Load(), uncertain: owner.uncertain.Load(),
		drainFinished: owner.drainFinished, closeFinished: owner.closeFinished,
		closeError: owner.closeErr != nil, poolCloseStarted: owner.poolCloseStarted,
		poolReleased: owner.poolReleased, headerCloseStarted: owner.headerCloseStarted,
		headerReleased: owner.headerReleased, leaseReleased: owner.leaseReleased,
		pool: owner.pool, header: owner.header, path: owner.path,
		headerDescriptor: owner.headerDescriptor, headerProbe: owner.headerProbe,
		identity: owner.identity, lease: owner.lease,
	}
}

// snapshotLifecycle is one read-only sampling pass. It neither acquires an
// operation/connection nor starts a transaction. Raw descriptor observation, pool Stats and the lease
// lookup are outside gate, so slow observation cannot hold the drain mutex.
// A changed owner frame becomes UNKNOWN; there is no implicit retry.
func (owner *registryLifecycleOwner) snapshotLifecycle() registryLifecycleSnapshot {
	snapshot := registryLifecycleSnapshot{
		pool: LifecyclePoolDiagnostic{Knowledge: Unknown},
		headerReference: lifecycleUnknown(), headerValid: lifecycleUnknown(),
		headerClosed: lifecycleUnknown(), pathValid: lifecycleUnknown(),
		leaseHeld: lifecycleUnknown(), leaseLinked: lifecycleUnknown(),
	}
	if owner == nil {
		return snapshot
	}
	frame := owner.lifecycleFrame()
	snapshot.frame = frame
	if !frame.ready && !frame.closing && !frame.uncertain {
		return snapshot
	}
	poolPresent := !readNilPort(frame.pool)
	headerPresent := !readNilPort(frame.header)
	if poolPresent {
		stats := frame.pool.Stats()
		if stats.OpenConnections >= 0 && stats.InUse >= 0 && stats.Idle >= 0 &&
			stats.OpenConnections == stats.InUse+stats.Idle {
			snapshot.pool = LifecyclePoolDiagnostic{
				Knowledge: Known, OpenConnections: stats.OpenConnections,
				InUse: stats.InUse, Idle: stats.Idle,
			}
		}
	}
	snapshot.headerReference = lifecycleKnown(headerPresent)
	if frame.headerReleased {
		// Managed Close confirmed release. Never probe a cached descriptor
		// number after release: the OS may have reused it for another file.
		snapshot.headerValid = lifecycleKnown(false)
		snapshot.headerClosed = lifecycleKnown(true)
	} else if headerPresent && frame.headerProbe != nil {
		// The platform probe observes only the cached descriptor via raw fstat.
		// Do not call File.Stat/Fd here: Go's File reference bookkeeping can
		// make a concurrent Close finish its physical close in a Stat caller.
		probe := frame.headerProbe(frame.headerDescriptor, frame.identity)
		if probe.known {
			snapshot.headerValid = lifecycleKnown(probe.valid)
			snapshot.headerClosed = lifecycleKnown(probe.closed)
		}
	}
	if frame.path != "" && frame.identity != nil {
		if info, err := os.Lstat(frame.path); err == nil && info != nil {
			snapshot.pathValid = lifecycleKnown(info.Mode().IsRegular() &&
				info.Mode()&os.ModeSymlink == 0 && os.SameFile(info, frame.identity))
		}
	}
	if frame.lease != nil {
		registryInodeLeases.Lock()
		_, held := registryInodeLeases.owners[frame.lease]
		linked := frame.lease.owner == owner && frame.lease.identity != nil &&
			frame.identity != nil && os.SameFile(frame.lease.identity, frame.identity)
		registryInodeLeases.Unlock()
		snapshot.leaseHeld = lifecycleKnown(held)
		snapshot.leaseLinked = lifecycleKnown(linked)
	}
	after := owner.lifecycleFrame()
	snapshot.stable = frame.version == after.version
	return snapshot
}

func lifecycleTrue(fact LifecycleFact) bool {
	return fact.Knowledge == Known && fact.Value
}

func lifecycleFalse(fact LifecycleFact) bool {
	return fact.Knowledge == Known && !fact.Value
}

// safeDiagnostic explicitly copies only fixed enums, counts and qualified
// booleans. Private snapshot/resource details can never leak through this API.
func (snapshot registryLifecycleSnapshot) safeDiagnostic() RegistryLifecycleDiagnostic {
	result := unknownRegistryLifecycleDiagnostic()
	if !snapshot.stable || snapshot.frame.active < 0 {
		return result
	}
	frame := snapshot.frame
	result.Consistency = Known
	result.ActiveOperations = LifecycleCount{Knowledge: Known, Value: frame.active}
	// This is the actual published owner's admission predicate, not read
	// validation, business admission, Drain READY or P-A/Writer permission.
	result.AcceptingOperations = lifecycleKnown(frame.ready && !frame.closing && !frame.uncertain &&
		!readNilPort(frame.pool) && !readNilPort(frame.header))
	switch {
	case frame.closing && frame.drainFinished:
		result.Drain = LifecycleDrainComplete
	case frame.closing:
		result.Drain = LifecycleDrainWaiting
	case frame.active > 0:
		result.Drain = LifecycleDrainActive
	default:
		result.Drain = LifecycleDrainIdle
	}
	result.Pool = snapshot.pool
	result.Header = LifecycleHeaderDiagnostic{
		ReferenceHeld: snapshot.headerReference, Valid: snapshot.headerValid,
		Closed: snapshot.headerClosed, CloseStarted: lifecycleKnown(frame.headerCloseStarted),
		Released: lifecycleKnown(frame.headerReleased),
	}
	result.Lease = LifecycleLeaseDiagnostic{
		Held: snapshot.leaseHeld, OwnerConsistent: snapshot.leaseLinked,
		Released: lifecycleKnown(frame.leaseReleased),
	}
	result.Close = LifecycleCloseDiagnostic{
		Started: lifecycleKnown(frame.closing), Finished: lifecycleKnown(frame.closeFinished),
		Result: LifecycleCloseNotStarted, PoolReleased: lifecycleKnown(frame.poolReleased),
		HeaderReleased: lifecycleKnown(frame.headerReleased), LeaseReleased: lifecycleKnown(frame.leaseReleased),
	}
	switch {
	case frame.closing && !frame.closeFinished:
		result.Close.Result = LifecycleClosePending
	case frame.closing && frame.closeFinished && (frame.uncertain || frame.closeError):
		result.Close.Result = LifecycleCloseUnknown
	case frame.closing && frame.closeFinished && frame.poolReleased && frame.headerReleased && frame.leaseReleased:
		result.Close.Result = LifecycleCloseSucceeded
	case frame.closing:
		result.Close.Result = LifecycleCloseUnknown
	}
	switch {
	case frame.uncertain:
		result.State = LifecycleUncertain
	case frame.closing && !frame.closeFinished:
		result.State = LifecycleClosing
	case frame.closing && frame.closeFinished && !frame.closeError &&
		frame.drainFinished && frame.poolReleased && frame.headerReleased && frame.leaseReleased &&
		snapshot.pool.Knowledge == Known && snapshot.pool.OpenConnections == 0 &&
		lifecycleTrue(snapshot.headerClosed) && lifecycleFalse(snapshot.leaseHeld) &&
		lifecycleTrue(snapshot.leaseLinked):
		result.State = LifecycleClosed
	case frame.ready && !frame.closing && !frame.closeFinished &&
		lifecycleTrue(snapshot.headerValid) && lifecycleFalse(snapshot.headerClosed) &&
		lifecycleTrue(snapshot.pathValid) && lifecycleTrue(snapshot.leaseHeld) &&
		lifecycleTrue(snapshot.leaseLinked) && snapshot.pool.Knowledge == Known:
		result.State = LifecycleOpen
	}
	return result
}

// InspectLifecycle is diagnostic-only and remains available while closing,
// closed or uncertain. It never admits work, repairs state or grants execution.
func (port *SQLiteReadPort) InspectLifecycle() RegistryLifecycleDiagnostic {
	if port == nil {
		return unknownRegistryLifecycleDiagnostic()
	}
	return port.owner.snapshotLifecycle().safeDiagnostic()
}
