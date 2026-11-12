package registry

import (
    "context"
    "database/sql"
)

// Roles classify actual owner borrows; they are not authority or a writable
// connection profile. Write is deliberately recognized only to reject it.
type registryConnectionRole uint8

const (
    registryReadRole registryConnectionRole = iota + 1
    registryWriteRole
)

type registryOperationKind uint8

const (
    registryReadOperation registryOperationKind = iota + 1
    registryReadTransaction
)

// All records are private and protected by owner.gate. A connection/transaction
// is never independently owned by an adapter. Uncertain releases retain their
// association after the active borrow ends; Close must not drop the inode lease.
type registryOperationRecord struct {
    role registryConnectionRole
    kind registryOperationKind
    active bool
    conn *sql.Conn
    tx *sql.Tx
    releasing bool
    unresolved bool
}

func (owner *registryLifecycleOwner) acquireRole(ctx context.Context, role registryConnectionRole, kind registryOperationKind) (*registryOperation, error) {
    if ctx == nil { return nil, invalid("sqlite.context") }
    if err := ctx.Err(); err != nil { return nil, err }
    // No writer API/pool/FD/admission exists. Reject without touching the owner
    // or performing resource I/O, including when the owner itself is unknown.
    if role != registryReadRole { return nil, fault(CodeUnavailable, "sqlite.role_not_provided") }
    if kind != registryReadOperation && kind != registryReadTransaction { return nil, invalid("sqlite.operation_kind") }
    if owner == nil { return nil, ErrSQLiteClosed }
    owner.gate.Lock()
    defer owner.gate.Unlock()
    if err := ctx.Err(); err != nil { return nil, err }
    if owner.closing.Load() || owner.pool == nil || owner.header == nil { return nil, ErrSQLiteClosed }
    if owner.uncertain.Load() { return nil, fault(CodeUnavailable, "sqlite.lifecycle_uncertain") }
    operation := &registryOperation{owner: owner, role: role, kind: kind}
    if owner.operations == nil { owner.operations = make(map[*registryOperation]registryOperationRecord) }
    owner.operations[operation] = registryOperationRecord{role: role, kind: kind, active: true}
    // Add is under the gate that closes admission before Close calls Wait.
    owner.activeOps.Add(1)
    owner.activeOperations++
    owner.readOperations++
    owner.observationVersion++
    return operation, nil
}

func (owner *registryLifecycleOwner) roleRecordLocked(operation *registryOperation) (registryOperationRecord, bool) {
    record, ok := owner.operations[operation]
    return record, ok && operation != nil && operation.owner == owner &&
        operation.role == registryReadRole && record.role == operation.role &&
        record.kind == operation.kind && record.active
}

func (owner *registryLifecycleOwner) invalidateRoleTrackingLocked() {
    owner.roleTrackingInvalid = true
    owner.uncertain.Store(true)
    owner.observationVersion++
}

func (owner *registryLifecycleOwner) attachReadConnection(operation *registryOperation, conn *sql.Conn) error {
    owner.gate.Lock()
    defer owner.gate.Unlock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok || record.kind != registryReadTransaction || conn == nil || record.conn != nil {
        owner.invalidateRoleTrackingLocked()
        return fault(CodeUnavailable, "sqlite.connection_owner")
    }
    if _, attached := owner.connectionOwners[conn]; attached {
        owner.invalidateRoleTrackingLocked()
        return fault(CodeUnavailable, "sqlite.connection_owner")
    }
    if owner.connectionOwners == nil { owner.connectionOwners = make(map[*sql.Conn]*registryOperation) }
    owner.connectionOwners[conn] = operation
    record.conn = conn
    owner.operations[operation] = record
    owner.readConnections++
    owner.observationVersion++
    return nil
}

func (owner *registryLifecycleOwner) attachReadTransaction(operation *registryOperation, conn *sql.Conn, tx *sql.Tx) error {
    owner.gate.Lock()
    defer owner.gate.Unlock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok || record.kind != registryReadTransaction || conn == nil || record.conn != conn ||
        tx == nil || record.tx != nil || record.releasing || record.unresolved {
        owner.invalidateRoleTrackingLocked()
        return fault(CodeUnavailable, "sqlite.transaction_owner")
    }
    if _, attached := owner.transactionOwners[tx]; attached {
        owner.invalidateRoleTrackingLocked()
        return fault(CodeUnavailable, "sqlite.transaction_owner")
    }
    if owner.transactionOwners == nil { owner.transactionOwners = make(map[*sql.Tx]*registryOperation) }
    owner.transactionOwners[tx] = operation
    record.tx = tx
    owner.operations[operation] = record
    owner.readTransactions++
    owner.observationVersion++
    return nil
}

// releaseReadConnection is the sole managed connection-return boundary. Never
// hold the owner gate while Conn.Close waits for cancellation/rollback cleanup.
// A Close error preserves the unknown handle/transaction association, not a
// fictitious zero count. Terminal Tx methods serialize this through releaseOnce.
func (owner *registryLifecycleOwner) releaseReadConnection(operation *registryOperation, conn *sql.Conn) error {
    owner.gate.Lock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok || conn == nil || record.conn != conn || owner.connectionOwners[conn] != operation || record.releasing || record.unresolved {
        owner.invalidateRoleTrackingLocked()
        owner.gate.Unlock()
        return fault(CodeUnavailable, "sqlite.connection_owner")
    }
    record.releasing = true
    owner.operations[operation] = record
    owner.observationVersion++
    owner.gate.Unlock()

    err := conn.Close()

    owner.gate.Lock()
    record = owner.operations[operation]
    record.releasing = false
    if err != nil {
        record.unresolved = true
        owner.unresolvedConnections++
        owner.uncertain.Store(true) // before operation Done can unblock Close
    } else {
        delete(owner.connectionOwners, conn)
        record.conn = nil
        owner.readConnections--
        if record.tx != nil {
            delete(owner.transactionOwners, record.tx)
            record.tx = nil
            owner.readTransactions--
        }
    }
    owner.operations[operation] = record
    owner.observationVersion++
    owner.gate.Unlock()
    return err
}

func (owner *registryLifecycleOwner) releaseOperation(operation *registryOperation) {
    owner.gate.Lock()
    defer owner.gate.Unlock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok {
        owner.invalidateRoleTrackingLocked()
        return // never decrement somebody else's borrow
    }
    if record.conn != nil && !record.unresolved {
        // A consumer dropping a borrow before returning its connection is a
        // contract violation. Retain all resource ownership and fail closed.
        record.unresolved = true
        owner.unresolvedConnections++
        owner.uncertain.Store(true)
    }
    record.active = false
    if record.unresolved {
        owner.operations[operation] = record
    } else {
        delete(owner.operations, operation)
    }
    owner.readOperations--
    owner.activeOperations--
    owner.observationVersion++
    owner.activeOps.Done()
}
