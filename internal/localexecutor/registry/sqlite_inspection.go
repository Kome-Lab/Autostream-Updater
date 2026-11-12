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

// LifecycleRoleImplementation describes participation installed on this owner,
// not binary-wide support or execution authority.
type LifecycleRoleImplementation string

const (
	LifecycleRoleImplemented    LifecycleRoleImplementation = "IMPLEMENTED"
	LifecycleRoleNotImplemented LifecycleRoleImplementation = "NOT_IMPLEMENTED"
	LifecycleRoleUnknown        LifecycleRoleImplementation = "UNKNOWN"
)

type LifecycleAdmissionStatus string

const (
	LifecycleAdmissionNotProvided LifecycleAdmissionStatus = "NOT_PROVIDED"
	LifecycleAdmissionProvided    LifecycleAdmissionStatus = "PROVIDED"
	LifecycleAdmissionUnknown     LifecycleAdmissionStatus = "UNKNOWN"
)

// Counts describe owner-tracked borrows and associated handles. Connections and
// Transactions include retained handles whose release is unknown; they are not
// assertions that an SQL operation or OS lock is still physically active.
type LifecycleReadRoleDiagnostic struct {
	Implementation        LifecycleRoleImplementation
	Admission             LifecycleFact
	Operations            LifecycleCount
	Transactions          LifecycleCount
	Connections           LifecycleCount
	UnresolvedConnections LifecycleCount
}

// A configured profile is an internal connection capability, not P-A authority.
type LifecycleWriterProfileState string

const (
	LifecycleWriterProfileNotConfigured LifecycleWriterProfileState = "NOT_CONFIGURED"
	LifecycleWriterProfileConfigured    LifecycleWriterProfileState = "CONFIGURED"
	LifecycleWriterProfileUnknown       LifecycleWriterProfileState = "UNKNOWN"
)

type LifecycleWriteRoleDiagnostic struct {
	// Compiled profile support is distinct from participation installed on this Owner.
	ProfileImplementation LifecycleRoleImplementation
	Profile               LifecycleWriterProfileState
	Admission             LifecycleFact
	Operations            LifecycleCount
	Transactions          LifecycleCount
	Connections           LifecycleCount
	UnresolvedConnections LifecycleCount
	UnknownOutcomes       LifecycleCount
	Pool                  LifecyclePoolDiagnostic
	PoolCreated           LifecycleFact
	PoolCloseStarted      LifecycleFact
	PoolReleased          LifecycleFact
}

// Read-only owners have no installed Writer profile. Writer counts are only
// asserted after explicit internal installation; Mutation remains unavailable.
type LifecycleRolesDiagnostic struct {
	SharedOwner                LifecycleFact
	Read                       LifecycleReadRoleDiagnostic
	Write                      LifecycleWriteRoleDiagnostic
	WriteImplementation        LifecycleRoleImplementation
	WriterAdmission            LifecycleAdmissionStatus
	MutationImplementation     LifecycleRoleImplementation
	GuardControlImplementation LifecycleRoleImplementation
	ContinuityImplementation   LifecycleRoleImplementation
}

// RegistryLifecycleDiagnostic is an explicit safe projection. It contains no
// path, URI, SQL, raw error, credential, file identity, descriptor number or
// resource pointer. OPEN/admission/drain are diagnostics, not execution grants.
type RegistryLifecycleDiagnostic struct {
	State RegistryLifecycleState
	// Consistency describes the tracked owner frame only. Stats and filesystem
	// facts are best-effort observations, not one globally atomic snapshot.
	Consistency         Knowledge
	ActiveOperations    LifecycleCount
	AcceptingOperations LifecycleFact
	Drain               LifecycleDrainState
	Pool                LifecyclePoolDiagnostic
	Header              LifecycleHeaderDiagnostic
	Lease               LifecycleLeaseDiagnostic
	Close               LifecycleCloseDiagnostic
	Roles               LifecycleRolesDiagnostic
}

// All fields are private, deliberately separate from the exported diagnostic.
// The frame is copied while holding gate; no resource method is called there.
type registryLifecycleFrame struct {
	version                    uint64
	active                     int64
	readOperations             int64
	readTransactions           int64
	readConnections            int64
	unresolvedConnections      int64
	roleTrackingInvalid        bool
	writerConfigured           bool
	writeOperations            int64
	writeTransactions          int64
	writeConnections           int64
	writeUnresolvedConnections int64
	writeUnknownOutcomes       int64
	writePool                  registryConnectionPool
	writePoolCloseStarted      bool
	writePoolReleased          bool
	ready                      bool
	closing                    bool
	uncertain                  bool
	drainFinished              bool
	closeFinished              bool
	closeError                 bool
	poolCloseStarted           bool
	poolReleased               bool
	headerCloseStarted         bool
	headerReleased             bool
	leaseReleased              bool
	pool                       registryConnectionPool
	header                     registryHeaderFD
	headerDescriptor           int
	headerProbe                func(int, os.FileInfo) registryHeaderProbeResult
	path                       string
	identity                   os.FileInfo
	lease                      *registryInodeLease
}

type registryLifecycleSnapshot struct {
	frame           registryLifecycleFrame
	stable          bool
	pool            LifecyclePoolDiagnostic
	writePool       LifecyclePoolDiagnostic
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
		Roles:               unknownLifecycleRolesDiagnostic(),
		ActiveOperations:    LifecycleCount{Knowledge: Unknown},
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

func unknownLifecycleRolesDiagnostic() LifecycleRolesDiagnostic {
	return LifecycleRolesDiagnostic{
		SharedOwner: lifecycleUnknown(),
		Read: LifecycleReadRoleDiagnostic{
			Implementation: LifecycleRoleUnknown, Admission: lifecycleUnknown(),
			Operations:            LifecycleCount{Knowledge: Unknown},
			Transactions:          LifecycleCount{Knowledge: Unknown},
			Connections:           LifecycleCount{Knowledge: Unknown},
			UnresolvedConnections: LifecycleCount{Knowledge: Unknown},
		},
		Write:                      unknownLifecycleWriteRoleDiagnostic(),
		WriteImplementation:        LifecycleRoleUnknown,
		WriterAdmission:            LifecycleAdmissionUnknown,
		MutationImplementation:     LifecycleRoleUnknown,
		GuardControlImplementation: LifecycleRoleUnknown,
		ContinuityImplementation:   LifecycleRoleUnknown,
	}
}

func unknownLifecycleWriteRoleDiagnostic() LifecycleWriteRoleDiagnostic {
	return LifecycleWriteRoleDiagnostic{
		ProfileImplementation: LifecycleRoleUnknown,
		Profile:               LifecycleWriterProfileUnknown, Admission: lifecycleUnknown(),
		Operations:            LifecycleCount{Knowledge: Unknown},
		Transactions:          LifecycleCount{Knowledge: Unknown},
		Connections:           LifecycleCount{Knowledge: Unknown},
		UnresolvedConnections: LifecycleCount{Knowledge: Unknown},
		UnknownOutcomes:       LifecycleCount{Knowledge: Unknown},
		Pool:                  LifecyclePoolDiagnostic{Knowledge: Unknown},
		PoolCreated:           lifecycleUnknown(), PoolCloseStarted: lifecycleUnknown(),
		PoolReleased: lifecycleUnknown(),
	}
}

// Role bookkeeping is copied as scalars under gate, never inferred from Pool
// Stats or by scanning/altering the operation ownership map during Inspection.
func (frame registryLifecycleFrame) validRoleCounts() bool {
	return !frame.roleTrackingInvalid && frame.active >= 0 && frame.readOperations >= 0 &&
		frame.writeOperations >= 0 && frame.writeOperations <= 1 &&
		frame.readOperations+frame.writeOperations == frame.active &&
		(frame.writeOperations == 0 || frame.readOperations == 0) &&
		frame.readTransactions >= 0 && frame.readConnections >= 0 &&
		frame.unresolvedConnections >= 0 &&
		frame.readTransactions <= frame.readConnections &&
		frame.unresolvedConnections <= frame.readConnections &&
		(frame.unresolvedConnections == 0 || frame.uncertain) &&
		frame.writeTransactions >= 0 && frame.writeConnections >= 0 &&
		frame.writeUnresolvedConnections >= 0 && frame.writeUnknownOutcomes >= 0 &&
		frame.writeTransactions <= frame.writeConnections &&
		frame.writeUnresolvedConnections <= frame.writeConnections &&
		frame.writeUnknownOutcomes <= frame.writeConnections &&
		(frame.writeUnresolvedConnections == 0 || frame.uncertain) &&
		(frame.writeUnknownOutcomes == 0 || frame.uncertain) &&
		(frame.writerConfigured || (frame.writeOperations == 0 &&
			frame.writeTransactions == 0 && frame.writeConnections == 0 &&
			frame.writeUnresolvedConnections == 0 && frame.writeUnknownOutcomes == 0 &&
			readNilPort(frame.writePool)))
}

func (owner *registryLifecycleOwner) lifecycleFrame() registryLifecycleFrame {
	owner.gate.Lock()
	defer owner.gate.Unlock()
	return registryLifecycleFrame{
		version: owner.observationVersion, active: owner.activeOperations,
		readOperations: owner.readOperations, readTransactions: owner.readTransactions,
		readConnections: owner.readConnections, unresolvedConnections: owner.unresolvedConnections,
		roleTrackingInvalid: owner.roleTrackingInvalid,
		writerConfigured:    owner.writerConfigured,
		writeOperations:     owner.writeOperations, writeTransactions: owner.writeTransactions,
		writeConnections: owner.writeConnections, writeUnresolvedConnections: owner.writeUnresolvedConnections,
		writeUnknownOutcomes: owner.writeUnknownOutcomes,
		writePool:            owner.writePool, writePoolCloseStarted: owner.writePoolCloseStarted,
		writePoolReleased: owner.writePoolReleased,
		ready:             owner.ready, closing: owner.closing.Load(), uncertain: owner.uncertain.Load(),
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
		pool:            LifecyclePoolDiagnostic{Knowledge: Unknown},
		writePool:       LifecyclePoolDiagnostic{Knowledge: Unknown},
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
	if !readNilPort(frame.writePool) {
		stats := frame.writePool.Stats()
		if stats.OpenConnections >= 0 && stats.InUse >= 0 && stats.Idle >= 0 &&
			stats.OpenConnections == stats.InUse+stats.Idle {
			snapshot.writePool = LifecyclePoolDiagnostic{
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
	if !snapshot.stable {
		return result
	}
	frame := snapshot.frame
	// Static implementation availability is not a fabricated zero Writer count.
	// Only a stable, initialized/closing/uncertain owner reaches this projection.
	result.Roles.Read.Implementation = LifecycleRoleImplemented
	result.Roles.WriteImplementation = LifecycleRoleNotImplemented
	result.Roles.WriterAdmission = LifecycleAdmissionNotProvided
	result.Roles.MutationImplementation = LifecycleRoleNotImplemented
	result.Roles.GuardControlImplementation = LifecycleRoleNotImplemented
	result.Roles.ContinuityImplementation = LifecycleRoleNotImplemented
	result.Roles.Write.ProfileImplementation = LifecycleRoleImplemented
	result.Roles.Write.Profile = LifecycleWriterProfileNotConfigured
	result.Roles.Write.Admission = lifecycleKnown(false)
	if frame.writerConfigured {
		result.Roles.Write.Profile = LifecycleWriterProfileConfigured
		result.Roles.WriteImplementation = LifecycleRoleImplemented
		result.Roles.WriterAdmission = LifecycleAdmissionProvided
	}
	if !frame.validRoleCounts() {
		if frame.uncertain {
			result.State = LifecycleUncertain
		}
		result.AcceptingOperations = lifecycleKnown(false)
		result.Roles.Read.Admission = lifecycleKnown(false)
		result.Roles.Write.Admission = lifecycleKnown(false)
		return result
	}
	result.Roles.SharedOwner = lifecycleKnown(true)
	result.Roles.Read.Operations = LifecycleCount{Knowledge: Known, Value: frame.readOperations}
	result.Roles.Read.Transactions = LifecycleCount{Knowledge: Known, Value: frame.readTransactions}
	result.Roles.Read.Connections = LifecycleCount{Knowledge: Known, Value: frame.readConnections}
	result.Roles.Read.UnresolvedConnections = LifecycleCount{Knowledge: Known, Value: frame.unresolvedConnections}
	if frame.writerConfigured {
		result.Roles.Write.Operations = LifecycleCount{Knowledge: Known, Value: frame.writeOperations}
		result.Roles.Write.Transactions = LifecycleCount{Knowledge: Known, Value: frame.writeTransactions}
		result.Roles.Write.Connections = LifecycleCount{Knowledge: Known, Value: frame.writeConnections}
		result.Roles.Write.UnresolvedConnections = LifecycleCount{Knowledge: Known, Value: frame.writeUnresolvedConnections}
		result.Roles.Write.UnknownOutcomes = LifecycleCount{Knowledge: Known, Value: frame.writeUnknownOutcomes}
	}
	result.Roles.Write.Pool = snapshot.writePool
	result.Roles.Write.PoolCreated = lifecycleKnown(!readNilPort(frame.writePool))
	result.Roles.Write.PoolCloseStarted = lifecycleKnown(frame.writePoolCloseStarted)
	result.Roles.Write.PoolReleased = lifecycleKnown(frame.writePoolReleased)
	result.Consistency = Known
	result.ActiveOperations = LifecycleCount{Knowledge: Known, Value: frame.active}
	// This is the actual published owner's admission predicate, not read
	// validation, business admission, Drain READY or P-A/Writer permission.
	result.AcceptingOperations = lifecycleKnown(frame.ready && !frame.closing && !frame.uncertain &&
		!readNilPort(frame.pool) && !readNilPort(frame.header) && frame.writeOperations == 0)
	result.Roles.Read.Admission = result.AcceptingOperations
	result.Roles.Write.Admission = lifecycleKnown(frame.writerConfigured &&
		lifecycleTrue(result.AcceptingOperations) && frame.readOperations == 0 && frame.writeOperations == 0)
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
	writerReleased := readNilPort(frame.writePool) || frame.writePoolReleased
	switch {
	case frame.closing && !frame.closeFinished:
		result.Close.Result = LifecycleClosePending
	case frame.closing && frame.closeFinished && (frame.uncertain || frame.closeError):
		result.Close.Result = LifecycleCloseUnknown
	case frame.closing && frame.closeFinished && frame.poolReleased && frame.headerReleased && frame.leaseReleased && writerReleased:
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
		frame.drainFinished && frame.poolReleased && frame.headerReleased && frame.leaseReleased && writerReleased &&
		frame.readOperations == 0 && frame.readTransactions == 0 &&
		frame.readConnections == 0 && frame.unresolvedConnections == 0 &&
		frame.writeOperations == 0 && frame.writeTransactions == 0 && frame.writeConnections == 0 &&
		frame.writeUnresolvedConnections == 0 && frame.writeUnknownOutcomes == 0 &&
		(readNilPort(frame.writePool) || (snapshot.writePool.Knowledge == Known && snapshot.writePool.OpenConnections == 0)) &&
		snapshot.pool.Knowledge == Known && snapshot.pool.OpenConnections == 0 &&
		lifecycleTrue(snapshot.headerClosed) && lifecycleFalse(snapshot.leaseHeld) &&
		lifecycleTrue(snapshot.leaseLinked):
		result.State = LifecycleClosed
	case frame.ready && !frame.closing && !frame.closeFinished &&
		lifecycleTrue(snapshot.headerValid) && lifecycleFalse(snapshot.headerClosed) &&
		lifecycleTrue(snapshot.pathValid) && lifecycleTrue(snapshot.leaseHeld) &&
		lifecycleTrue(snapshot.leaseLinked) && snapshot.pool.Knowledge == Known &&
		(readNilPort(frame.writePool) || snapshot.writePool.Knowledge == Known):
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
