package registry

import "context"

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

func (owner *registryLifecycleOwner) acquireRole(ctx context.Context, role registryConnectionRole, kind registryOperationKind) (*registryOperation, error) {
	if ctx == nil {
		return nil, invalid("sqlite.context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// No writer API/pool/FD/admission exists. Reject without touching the owner
	// or performing resource I/O, including when the owner itself is unknown.
	if role != registryReadRole {
		return nil, fault(CodeUnavailable, "sqlite.role_not_provided")
	}
	if kind != registryReadOperation && kind != registryReadTransaction {
		return nil, invalid("sqlite.operation_kind")
	}
	if owner == nil {
		return nil, ErrSQLiteClosed
	}
	owner.gate.Lock()
	defer owner.gate.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner.closing.Load() || owner.pool == nil || owner.header == nil {
		return nil, ErrSQLiteClosed
	}
	if owner.uncertain.Load() {
		return nil, fault(CodeUnavailable, "sqlite.lifecycle_uncertain")
	}
	operation := &registryOperation{owner: owner, role: role, kind: kind}
	if owner.operations == nil {
		owner.operations = make(map[*registryOperation]registryOperationRecord)
	}
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
