package registry

import "context"

// Roles classify concrete owner borrows, never business execution authority.
type registryConnectionRole uint8

const (
    registryReadRole registryConnectionRole = iota + 1
    registryWriteRole
)

type registryOperationKind uint8

const (
    registryReadOperation registryOperationKind = iota + 1
    registryReadTransaction
    registryWriteTransaction
)

// prepareWriterProfile is a trusted, package-internal installation decision.
// Ordinary ReadPort methods never call it. It creates no pool, FD or lease and
// is not a P-A/GuardControl authorization. Uncertain owners cannot opt back in.
func (owner *registryLifecycleOwner) prepareWriterProfile(ctx context.Context) error {
    if ctx == nil { return invalid("sqlite.context") }
    if err := ctx.Err(); err != nil { return err }
    if owner == nil { return ErrSQLiteClosed }
    owner.gate.Lock()
    defer owner.gate.Unlock()
    if err := ctx.Err(); err != nil { return err }
    if !owner.ready || owner.closing.Load() || owner.pool == nil || owner.header == nil { return ErrSQLiteClosed }
    if owner.uncertain.Load() { return fault(CodeUnavailable, "sqlite.lifecycle_uncertain") }
    if owner.writerConfigured { return nil }
    if owner.activeOperations != 0 { return fault(CodeUnavailable, "sqlite.role_busy") }
    owner.writerConfigured = true
    owner.observationVersion++
    return nil
}

// Admission is fail-fast, owner-wide and ordered under gate. No waiter retains
// a queued Writer reservation while a public Read needs its inner transaction:
// accepted Reads can complete, and conflicts are rejected without automatic retry.
func (owner *registryLifecycleOwner) acquireRole(ctx context.Context, role registryConnectionRole, kind registryOperationKind) (*registryOperation, error) {
    if ctx == nil { return nil, invalid("sqlite.context") }
    if err := ctx.Err(); err != nil { return nil, err }
    switch role {
    case registryReadRole:
        if kind != registryReadOperation && kind != registryReadTransaction { return nil, invalid("sqlite.operation_kind") }
    case registryWriteRole:
        if kind != registryWriteTransaction { return nil, invalid("sqlite.operation_kind") }
    default:
        return nil, fault(CodeUnavailable, "sqlite.role_not_provided")
    }
    if owner == nil { return nil, ErrSQLiteClosed }
    owner.gate.Lock()
    defer owner.gate.Unlock()
    if err := ctx.Err(); err != nil { return nil, err }
    if owner.closing.Load() || owner.pool == nil || owner.header == nil { return nil, ErrSQLiteClosed }
    if owner.uncertain.Load() { return nil, fault(CodeUnavailable, "sqlite.lifecycle_uncertain") }
    if role == registryWriteRole && !owner.writerConfigured { return nil, fault(CodeUnavailable, "sqlite.role_not_provided") }
    if owner.writeOperations != 0 || (role == registryWriteRole && owner.readOperations != 0) { return nil, fault(CodeUnavailable, "sqlite.role_busy") }
    operation := &registryOperation{owner: owner, role: role, kind: kind}
    if owner.operations == nil { owner.operations = make(map[*registryOperation]registryOperationRecord) }
    owner.operations[operation] = registryOperationRecord{role: role, kind: kind, active: true}
    owner.activeOps.Add(1)
    owner.activeOperations++
    if role == registryReadRole { owner.readOperations++ } else { owner.writeOperations++ }
    owner.observationVersion++
    return operation, nil
}

func (owner *registryLifecycleOwner) roleRecordLocked(operation *registryOperation) (registryOperationRecord, bool) {
    record, ok := owner.operations[operation]
    if !ok || operation == nil || operation.owner != owner || record.role != operation.role ||
        record.kind != operation.kind || !record.active { return record, false }
    valid := operation.role == registryReadRole && (operation.kind == registryReadOperation || operation.kind == registryReadTransaction) ||
        operation.role == registryWriteRole && operation.kind == registryWriteTransaction
    return record, valid
}

func (owner *registryLifecycleOwner) invalidateRoleTrackingLocked() {
    owner.roleTrackingInvalid = true
    owner.uncertain.Store(true)
    owner.observationVersion++
}

func (owner *registryLifecycleOwner) noteWriteOutcomeUnknown(operation *registryOperation) {
    owner.gate.Lock()
    defer owner.gate.Unlock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok || record.role != registryWriteRole {
        owner.invalidateRoleTrackingLocked()
        return
    }
    if !record.outcomeUnknown {
        record.outcomeUnknown = true
        owner.operations[operation] = record
        owner.writeUnknownOutcomes++
    }
    owner.uncertain.Store(true)
    owner.observationVersion++
}

func (owner *registryLifecycleOwner) releaseOperation(operation *registryOperation) {
    owner.gate.Lock()
    defer owner.gate.Unlock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok {
        owner.invalidateRoleTrackingLocked()
        return
    }
    if record.conn != nil && !record.unresolved {
        record.unresolved = true
        if record.role == registryReadRole { owner.unresolvedConnections++ } else { owner.writeUnresolvedConnections++ }
        owner.uncertain.Store(true)
    }
    record.active = false
    if record.unresolved || record.outcomeUnknown { owner.operations[operation] = record } else { delete(owner.operations, operation) }
    if record.role == registryReadRole { owner.readOperations-- } else { owner.writeOperations-- }
    owner.activeOperations--
    owner.observationVersion++
    owner.activeOps.Done()
}
