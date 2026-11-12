package registry

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"modernc.org/sqlite"
)

// These private resource contracts are implemented by *sql.DB and *os.File.
// They are narrow, real I/O seams for fault testing, not future Writer APIs.
type registryConnectionPool interface {
	Conn(context.Context) (*sql.Conn, error)
	Close() error
	Stats() sql.DBStats
}

type registryHeaderFD interface {
	Stat() (os.FileInfo, error)
	ReadAt([]byte, int64) (int, error)
	Close() error
}

// registryLifecycleOwner owns all SQLite handles and the retained header for
// one inode. Consumers borrow operations/transactions, never ownership of pool,
// descriptor, lease or Close. The Read pool is fixed mode=ro/query_only.
// Explicit internal Writer participation adds a lazy fixed-role pool to this
// same lifecycle; it supplies no P-A, GuardControl or service-apply authority.
//
// A future Writer must share this owner, header, lease and pool lifecycle rather
// than independently opening another header or pool. GuardControl and P-A must
// participate in the same enforced writer boundary. Current connection admission
// is owner-wide and fail-fast; P-A/GuardControl proofs and all-Actor participation
// are not implemented or certified here.
//
// The managed path/profile must not be adversarially replaced while opening or
// in use. This process-local ownership cannot exclude Host root, another process,
// a management CLI or unrelated same-process SQLite/raw-file handles.
type registryLifecycleOwner struct {
	pool             registryConnectionPool
	header           registryHeaderFD
	path             string
	identity         os.FileInfo
	lease            *registryInodeLease
	headerDescriptor int
	headerProbe      func(int, os.FileInfo) registryHeaderProbeResult
	gate             sync.Mutex
	activeOps        sync.WaitGroup
	closing          atomic.Bool
	uncertain        atomic.Bool
	closeOnce        sync.Once
	closeErr         error
	closingStarted   chan struct{}

	// Observational bookkeeping is changed only by actual lifecycle operations
	// under gate. Inspection never advances this version or acquires a borrow.
	observationVersion uint64
	activeOperations   int64
	ready              bool // constructor completion, never a Drain READY seal
	drainFinished      bool
	closeFinished      bool
	poolCloseStarted   bool
	poolReleased       bool
	headerCloseStarted bool
	headerReleased     bool
	leaseReleased      bool

	// Real Read-role ownership; all fields and records are guarded by gate.
	operations            map[*registryOperation]registryOperationRecord
	connectionOwners      map[*sql.Conn]*registryOperation
	transactionOwners     map[*sql.Tx]*registryOperation
	readOperations        int64
	readTransactions      int64
	readConnections       int64
	unresolvedConnections int64
	roleTrackingInvalid   bool

    // Both role pools belong solely to this owner. Writer is opt-in/lazy;
    // it never gets another Header FD, inode lease or independent Close.
    writerConfigured bool
    writePool registryConnectionPool
    writePoolCloseStarted bool
    writePoolReleased bool
    writeOperations int64
    writeConnections int64
    writeTransactions int64
    writeUnresolvedConnections int64
    writeUnknownOutcomes int64
}

// registryOperation is a counted, role-bound borrow. Public Read borrows cover
// independent Continuity qualification; transaction borrows cover their SQL
// connection return. Each ends once, without transferring resource ownership.
type registryOperation struct {
	owner *registryLifecycleOwner
	role  registryConnectionRole
	kind  registryOperationKind
	once  sync.Once
}

func (operation *registryOperation) release() {
	if operation == nil {
		return
	}
	operation.once.Do(func() { operation.owner.releaseOperation(operation) })
}

func (owner *registryLifecycleOwner) acquire(ctx context.Context) (*registryOperation, error) {
	return owner.acquireRole(ctx, registryReadRole, registryReadOperation)
}

// All records are private and protected by owner.gate. A connection/transaction
// is never independently owned by an adapter. Uncertain releases retain their
// association after the active borrow ends; Close must not drop the inode lease.
type registryOperationRecord struct {
	role       registryConnectionRole
	kind       registryOperationKind
	active     bool
	conn       *sql.Conn
	tx         *sql.Tx
	releasing  bool
	unresolved bool
    outcomeUnknown bool
}

// sqliteReadTx owns an independent operation borrow as well as its sql.Conn.
// Even a direct internal beginRead cannot escape drain accounting. In
// particular, cancellation may mark Tx done before asynchronous rollback has
// released the connection; Conn.Close waits for that release before the borrow
// can end. All terminal calls are serialized and cleanup happens only once.
type sqliteReadTx struct {
	*sql.Tx
	conn        *sql.Conn
	operation   *registryOperation
	finishMu    sync.Mutex
	releaseOnce sync.Once
	releaseErr  error
}

func (tx *sqliteReadTx) release() error {
	tx.releaseOnce.Do(func() {
		tx.releaseErr = tx.operation.owner.releaseReadConnection(tx.operation, tx.conn)
		tx.operation.release()
	})
	return tx.releaseErr
}

func (tx *sqliteReadTx) Commit() error {
	tx.finishMu.Lock()
	defer tx.finishMu.Unlock()
	err := tx.Tx.Commit()
	releaseErr := tx.release()
	if err != nil {
		return err
	}
	return releaseErr
}

func (tx *sqliteReadTx) Rollback() error {
	tx.finishMu.Lock()
	defer tx.finishMu.Unlock()
	err := tx.Tx.Rollback()
	releaseErr := tx.release()
	if err != nil {
		return err
	}
	return releaseErr
}

// The lease retains its owner strongly, including during failed Open/Close.
// A File finalizer must not silently close the retained descriptor and strip
// traditional process POSIX locks held through other surviving SQLite handles.
type registryInodeLease struct {
	identity os.FileInfo
	owner    *registryLifecycleOwner
}

var registryInodeLeases struct {
	sync.Mutex
	owners map[*registryInodeLease]struct{}
}

func registryAcquireInodeLease(identity os.FileInfo, owner *registryLifecycleOwner) (*registryInodeLease, error) {
	registryInodeLeases.Lock()
	defer registryInodeLeases.Unlock()
	for existing := range registryInodeLeases.owners {
		if os.SameFile(existing.identity, identity) {
			return nil, collision("sqlite.process_inode_owner")
		}
	}
	lease := &registryInodeLease{identity: identity, owner: owner}
	if registryInodeLeases.owners == nil {
		registryInodeLeases.owners = make(map[*registryInodeLease]struct{})
	}
	registryInodeLeases.owners[lease] = struct{}{}
	return lease, nil
}

func registryReleaseInodeLease(lease *registryInodeLease) {
	if lease == nil {
		return
	}
	registryInodeLeases.Lock()
	delete(registryInodeLeases.owners, lease)
	registryInodeLeases.Unlock()
}

func openRegistryLifecycleOwner(ctx context.Context, config SQLiteReadConfig) (*registryLifecycleOwner, error) {
	if ctx == nil {
		return nil, invalid("sqlite.context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, identity, err := sqliteReadLocation(config)
	if err != nil {
		return nil, err
	}
	owner := &registryLifecycleOwner{
		path: path, identity: identity, closingStarted: make(chan struct{}), headerDescriptor: -1, headerProbe: registryProbeHeader,
	}
	// Acquire and strongly attach ownership BEFORE any raw database Open.
	lease, err := registryAcquireInodeLease(identity, owner)
	if err != nil {
		return nil, err
	}
	owner.gate.Lock()
	owner.lease = lease
	owner.observationVersion++
	owner.gate.Unlock()
	header, err := os.Open(path)
	if err != nil {
		_ = owner.Close()
		return nil, fault(CodeUnavailable, "sqlite.header")
	}
	// Capture once during Open, before SQLite or publication. Inspection never
	// calls File.Fd/Stat: a Go File.Stat reference can defer physical Close
	// beyond lease handoff. Direct fstat does not own a Go FD-close reference.
	descriptor := int(header.Fd())
	owner.gate.Lock()
	owner.header = header
	owner.headerDescriptor = descriptor
	owner.observationVersion++
	owner.gate.Unlock()
	if err := owner.checkLocation(); err != nil {
		_ = owner.Close()
		return nil, err
	}
	parameters := url.Values{
		"mode":        {"ro"},
		"_query_only": {"1"},
		"_pragma":     {"trusted_schema(0)"},
		"_defensive":  {"1"},
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String() + "?" + parameters.Encode()
	connector, err := sqlite.NewConnector(uri)
	if err != nil {
		_ = owner.Close()
		return nil, fault(CodeUnavailable, "sqlite.connector")
	}
	pool := sql.OpenDB(connector)
	pool.SetMaxOpenConns(2)
	pool.SetMaxIdleConns(2)
	owner.gate.Lock()
	owner.pool = pool
	owner.observationVersion++
	owner.gate.Unlock()
	tx, err := owner.beginRead(ctx)
	if err != nil {
		// beginRead synchronously ends its counted borrow before returning an
		// error, so Close cannot wait on a borrow held by this factory itself.
		_ = owner.Close()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		result := owner.readError(ctx, err, "sqlite.open")
		_ = owner.Close()
		return nil, result
	}
	if err := owner.checkLocation(); err != nil {
		_ = owner.Close()
		return nil, err
	}
	owner.gate.Lock()
	owner.ready = true
	owner.observationVersion++
	owner.gate.Unlock()
	return owner, nil
}

func sqliteReadLocation(config SQLiteReadConfig) (string, os.FileInfo, error) {
	if config.DatabaseName != RegistryDatabaseName || config.Directory == "" ||
		!utf8.ValidString(config.Directory) || !filepath.IsAbs(config.Directory) ||
		filepath.Clean(config.Directory) != config.Directory ||
		strings.ContainsAny(config.Directory, "?#%\\:\x00") {
		return "", nil, invalid("sqlite.location")
	}
	for _, r := range config.Directory {
		if r < 32 || r == 127 {
			return "", nil, invalid("sqlite.location")
		}
	}
	// Every component is checked; no EvalSymlinks normalization silently expands
	// the trusted root into a different location.
	directory := config.Directory
	for {
		info, err := os.Lstat(directory)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", nil, invalid("sqlite.directory")
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	path := filepath.Join(config.Directory, RegistryDatabaseName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, invalid("sqlite.database_file")
	}
	if err := sqliteCheckMetadata(path, info); err != nil {
		return "", nil, err
	}
	return path, info, nil
}

// sqliteCheckMetadata never opens or closes the database inode.
func sqliteCheckMetadata(path string, identity os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		identity == nil || !os.SameFile(info, identity) {
		return invalid("sqlite.file_identity")
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil || !errors.Is(err, os.ErrNotExist) {
			return fault(CodeUnavailable, "sqlite.recovery_or_wal")
		}
	}
	return nil
}

func (owner *registryLifecycleOwner) checkLocation() error {
	if owner == nil || owner.header == nil || owner.closing.Load() {
		return ErrSQLiteClosed
	}
	if err := sqliteCheckMetadata(owner.path, owner.identity); err != nil {
		return err
	}
	opened, err := owner.header.Stat()
	if err != nil || !os.SameFile(opened, owner.identity) {
		return invalid("sqlite.file_identity")
	}
	var header [100]byte
	if _, err := owner.header.ReadAt(header[:], 0); err != nil ||
		string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
		return invalid("sqlite.rollback_profile")
	}
	return nil
}

func (owner *registryLifecycleOwner) readError(ctx context.Context, err error, field string) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// Never preserve driver wrapper text around standard context errors.
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if owner == nil || owner.pool == nil || owner.closing.Load() {
		return ErrSQLiteClosed
	}
	return fault(CodeUnavailable, field)
}

func (owner *registryLifecycleOwner) beginRead(ctx context.Context) (*sqliteReadTx, error) {
	operation, err := owner.acquireRole(ctx, registryReadRole, registryReadTransaction)
	if err != nil {
		return nil, err
	}
	keepOperation := false
	defer func() {
		if !keepOperation {
			operation.release()
		}
	}()
	if err := owner.checkLocation(); err != nil {
		return nil, err
	}
	conn, err := owner.pool.Conn(ctx)
	if err != nil {
		return nil, owner.readError(ctx, err, "sqlite.connection")
	}
	if err := owner.attachReadConnection(operation, conn); err != nil {
		// Invalid ownership never authorizes closing a possibly foreign handle.
		// Sticky uncertainty retains pool/header/lease for diagnosis.
		return nil, err
	}
	if owner.uncertain.Load() {
		_ = owner.releaseReadConnection(operation, conn)
		return nil, fault(CodeUnavailable, "sqlite.lifecycle_uncertain")
	}
	transaction, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		_ = owner.releaseReadConnection(operation, conn)
		return nil, owner.readError(ctx, err, "sqlite.begin")
	}
	if err := owner.attachReadTransaction(operation, conn, transaction); err != nil {
		_ = transaction.Rollback()
		_ = owner.releaseReadConnection(operation, conn)
		return nil, err
	}
	tx := &sqliteReadTx{Tx: transaction, conn: conn, operation: operation}
	// From this point the transaction owns the borrow. Any validation failure
	// synchronously rolls back and releases its connection before returning.
	keepOperation = true
	ok := false
	defer func() {
		if !ok {
			_ = tx.Rollback()
		}
	}()
	var queryOnly, trustedSchema int
	var journal string
	if err := tx.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil {
		return nil, owner.readError(ctx, err, "sqlite.read_only")
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA trusted_schema").Scan(&trustedSchema); err != nil {
		return nil, owner.readError(ctx, err, "sqlite.trusted_schema")
	}
	if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return nil, owner.readError(ctx, err, "sqlite.journal_profile")
	}
	if queryOnly != 1 || trustedSchema != 0 || strings.ToLower(journal) != "delete" {
		return nil, invalid("sqlite.connection_profile")
	}
	if err := validateSQLiteSchema(ctx, tx); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	ok = true
	return tx, nil
}

// markUncertain records a real lifecycle failure. It is never called by
// Inspection, even if observing a resource fails.
func (owner *registryLifecycleOwner) markUncertain() {
	owner.gate.Lock()
	if !owner.uncertain.Load() {
		owner.uncertain.Store(true)
		owner.observationVersion++
	}
	owner.gate.Unlock()
}

func (owner *registryLifecycleOwner) recordCloseError(err error) {
	owner.gate.Lock()
	owner.closeErr = err
	owner.observationVersion++
	owner.gate.Unlock()
}

func (owner *registryLifecycleOwner) Close() error {
	if owner == nil {
		return nil
	}
	owner.closeOnce.Do(func() {
		owner.gate.Lock()
		owner.closing.Store(true)
		owner.observationVersion++
		if owner.closingStarted != nil {
			close(owner.closingStarted)
		}
		owner.gate.Unlock()
		defer func() {
			owner.gate.Lock()
			owner.closeFinished = true
			owner.observationVersion++
			owner.gate.Unlock()
		}()
		owner.activeOps.Wait()
		owner.gate.Lock()
		owner.drainFinished = true
		if owner.roleTrackingInvalid || owner.readOperations != 0 || owner.readConnections != 0 ||
			owner.readTransactions != 0 || owner.unresolvedConnections != 0 ||
            owner.writeOperations != 0 || owner.writeConnections != 0 || owner.writeTransactions != 0 ||
            owner.writeUnresolvedConnections != 0 || owner.writeUnknownOutcomes != 0 || len(owner.operations) != 0 ||
			len(owner.connectionOwners) != 0 || len(owner.transactionOwners) != 0 {
			owner.uncertain.Store(true)
		}
		owner.observationVersion++
		owner.gate.Unlock()
		if owner.uncertain.Load() {
			owner.recordCloseError(fault(CodeUnavailable, "sqlite.close_uncertain"))
			return
		}
        if owner.writePool != nil {
            owner.gate.Lock()
            owner.writePoolCloseStarted = true
            owner.observationVersion++
            owner.gate.Unlock()
            if err := owner.writePool.Close(); err != nil {
                owner.markUncertain()
                owner.recordCloseError(fault(CodeUnavailable, "sqlite.writer_pool_close"))
                return
            }
            if owner.writePool.Stats().OpenConnections != 0 {
                owner.markUncertain()
                owner.recordCloseError(fault(CodeUnavailable, "sqlite.writer_pool_pending"))
                return
            }
            owner.gate.Lock()
            owner.writePoolReleased = true
            owner.observationVersion++
            owner.gate.Unlock()
        }
		if owner.pool != nil {
			owner.gate.Lock()
			owner.poolCloseStarted = true
			owner.observationVersion++
			owner.gate.Unlock()
			if err := owner.pool.Close(); err != nil {
				owner.markUncertain()
				owner.recordCloseError(fault(CodeUnavailable, "sqlite.close"))
				return
			}
			// Stats is observational and outside the lifecycle gate. A zero
			// count is used only AFTER this owner's actual pool.Close result.
			if owner.pool.Stats().OpenConnections != 0 {
				owner.markUncertain()
				owner.recordCloseError(fault(CodeUnavailable, "sqlite.close_pending"))
				return
			}
			owner.gate.Lock()
			owner.poolReleased = true
			owner.observationVersion++
			owner.gate.Unlock()
		}
		if owner.header != nil {
			owner.gate.Lock()
			owner.headerCloseStarted = true
			owner.observationVersion++
			owner.gate.Unlock()
			if err := owner.header.Close(); err != nil {
				owner.markUncertain()
				owner.recordCloseError(fault(CodeUnavailable, "sqlite.header_close"))
				return
			}
			owner.gate.Lock()
			owner.headerReleased = true
			owner.observationVersion++
			owner.gate.Unlock()
		}
		registryReleaseInodeLease(owner.lease)
		owner.gate.Lock()
		owner.leaseReleased = true
		owner.observationVersion++
		owner.gate.Unlock()
	})
	return owner.closeErr
}

func (owner *registryLifecycleOwner) attachReadConnection(operation *registryOperation, conn *sql.Conn) error {
    return owner.attachConnection(operation, conn, registryReadRole)
}

func (owner *registryLifecycleOwner) attachReadTransaction(operation *registryOperation, conn *sql.Conn, tx *sql.Tx) error {
    return owner.attachTransaction(operation, conn, tx, registryReadRole)
}

func (owner *registryLifecycleOwner) releaseReadConnection(operation *registryOperation, conn *sql.Conn) error {
    return owner.releaseConnection(operation, conn, registryReadRole)
}

func registryTransactionKind(role registryConnectionRole, kind registryOperationKind) bool {
    return role == registryReadRole && kind == registryReadTransaction ||
        role == registryWriteRole && kind == registryWriteTransaction
}

func (owner *registryLifecycleOwner) attachConnection(operation *registryOperation, conn *sql.Conn, role registryConnectionRole) error {
    owner.gate.Lock()
    defer owner.gate.Unlock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok || record.role != role || !registryTransactionKind(role, record.kind) || conn == nil || record.conn != nil {
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
    if role == registryReadRole { owner.readConnections++ } else { owner.writeConnections++ }
    owner.observationVersion++
    return nil
}

func (owner *registryLifecycleOwner) attachTransaction(operation *registryOperation, conn *sql.Conn, tx *sql.Tx, role registryConnectionRole) error {
    owner.gate.Lock()
    defer owner.gate.Unlock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok || record.role != role || !registryTransactionKind(role, record.kind) || conn == nil ||
        record.conn != conn || owner.connectionOwners[conn] != operation ||
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
    if role == registryReadRole { owner.readTransactions++ } else { owner.writeTransactions++ }
    owner.observationVersion++
    return nil
}

// A successful Conn.Close proves only managed handle return; an ambiguous
// Writer transaction is retained without calling this reusable-pool boundary.
func (owner *registryLifecycleOwner) releaseConnection(operation *registryOperation, conn *sql.Conn, role registryConnectionRole) error {
    owner.gate.Lock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok || record.role != role || conn == nil || record.conn != conn ||
        owner.connectionOwners[conn] != operation || record.releasing || record.unresolved || record.outcomeUnknown {
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
        if role == registryReadRole { owner.unresolvedConnections++ } else { owner.writeUnresolvedConnections++ }
        owner.uncertain.Store(true)
    } else {
        delete(owner.connectionOwners, conn)
        record.conn = nil
        if role == registryReadRole { owner.readConnections-- } else { owner.writeConnections-- }
        if record.tx != nil {
            delete(owner.transactionOwners, record.tx)
            record.tx = nil
            if role == registryReadRole { owner.readTransactions-- } else { owner.writeTransactions-- }
        }
    }
    owner.operations[operation] = record
    owner.observationVersion++
    owner.gate.Unlock()
    return err
}

// Writer connection profile is internal-only. Public Read construction never
// installs it, and neither this transaction handle nor its raw SQL is exported.
type sqliteWriteOutcome string

const (
    sqliteWriteActive sqliteWriteOutcome = "ACTIVE"
    sqliteWriteCommitted sqliteWriteOutcome = "COMMITTED"
    sqliteWriteRolledBack sqliteWriteOutcome = "ROLLED_BACK"
    sqliteWriteUnknown sqliteWriteOutcome = "UNKNOWN"
)

// The Tx is deliberately not embedded. Future product mutations must use closed
// typed operations; only synthetic package tests access tx directly.
type sqliteWriteTx struct {
    tx *sql.Tx
    conn *sql.Conn
    operation *registryOperation
    context context.Context
    finishMu sync.Mutex
    outcome sqliteWriteOutcome
    terminalErr error
    done chan struct{}
}

func (tx *sqliteWriteTx) State() sqliteWriteOutcome {
    if tx == nil { return sqliteWriteUnknown }
    tx.finishMu.Lock()
    defer tx.finishMu.Unlock()
    return tx.outcome
}

// Unknown is sticky. Returning a sql.Conn to its pool cannot establish the
// outcome or cleanup of an ambiguous transaction, so keep its concrete handle
// and ownership duty. No Commit retry or adapter rollback/repair is attempted.
func (tx *sqliteWriteTx) unknownLocked() error {
    tx.outcome = sqliteWriteUnknown
    tx.terminalErr = fault(CodeUnavailable, "sqlite.write_outcome_unknown")
    tx.operation.owner.noteWriteOutcomeUnknown(tx.operation)
    tx.operation.release()
    close(tx.done)
    return tx.terminalErr
}

func (tx *sqliteWriteTx) finishKnownLocked(outcome sqliteWriteOutcome) error {
    tx.outcome = outcome
    if err := tx.operation.owner.releaseConnection(tx.operation, tx.conn, registryWriteRole); err != nil {
        // SQL outcome stays known even when physical ownership return is not.
        tx.terminalErr = fault(CodeUnavailable, "sqlite.write_release_unknown")
    }
    tx.operation.release()
    close(tx.done)
    return tx.terminalErr
}

func (tx *sqliteWriteTx) Commit() error {
    if tx == nil { return fault(CodeUnavailable, "sqlite.write_transaction") }
    tx.finishMu.Lock()
    defer tx.finishMu.Unlock()
    switch tx.outcome {
    case sqliteWriteCommitted, sqliteWriteUnknown:
        return tx.terminalErr
    case sqliteWriteRolledBack:
        return fault(CodeUnavailable, "sqlite.write_already_rolled_back")
    }
    if tx.context.Err() != nil { return tx.unknownLocked() }
    if err := tx.tx.Commit(); err != nil { return tx.unknownLocked() }
    return tx.finishKnownLocked(sqliteWriteCommitted)
}

func (tx *sqliteWriteTx) Rollback() error {
    if tx == nil { return fault(CodeUnavailable, "sqlite.write_transaction") }
    tx.finishMu.Lock()
    defer tx.finishMu.Unlock()
    switch tx.outcome {
    case sqliteWriteRolledBack, sqliteWriteUnknown:
        return tx.terminalErr
    case sqliteWriteCommitted:
        return fault(CodeUnavailable, "sqlite.write_already_committed")
    }
    if tx.context.Err() != nil { return tx.unknownLocked() }
    if err := tx.tx.Rollback(); err != nil { return tx.unknownLocked() }
    return tx.finishKnownLocked(sqliteWriteRolledBack)
}

func (tx *sqliteWriteTx) watchContext() {
    select {
    case <-tx.done:
        return
    case <-tx.context.Done():
        tx.finishMu.Lock()
        if tx.outcome == sqliteWriteActive {
            // database/sql has its own asynchronous rollback path. Its return
            // and driver cleanup are not a result proof available here.
            _ = tx.unknownLocked()
        }
        tx.finishMu.Unlock()
    }
}

func (owner *registryLifecycleOwner) writerPoolFor(operation *registryOperation) (registryConnectionPool, error) {
    owner.gate.Lock()
    record, ok := owner.roleRecordLocked(operation)
    if !ok || record.role != registryWriteRole || record.kind != registryWriteTransaction ||
        !owner.writerConfigured || owner.uncertain.Load() {
        owner.gate.Unlock()
        return nil, fault(CodeUnavailable, "sqlite.write_profile")
    }
    pool := owner.writePool
    owner.gate.Unlock()
    if pool != nil { return pool, nil }

    // A fixed role connector is required: toggling a borrowed read-only
    // connection would destroy the Read profile. Both pools have ONE lifecycle
    // owner, retained Header FD and inode lease, and use the same package driver.
    // mode=rw never creates a missing DB; journal mode is validated, not changed.
    parameters := url.Values{
        "mode": {"rw"},
        "_query_only": {"0"},
        "_pragma": {"trusted_schema(0)"},
        "_defensive": {"1"},
        "_txlock": {"immediate"},
    }
    uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(owner.path)}).String() + "?" + parameters.Encode()
    connector, err := sqlite.NewConnector(uri)
    if err != nil { return nil, fault(CodeUnavailable, "sqlite.write_connector") }
    created := sql.OpenDB(connector)
    created.SetMaxOpenConns(1)
    created.SetMaxIdleConns(1)
    // Only one admitted Writer can reach this point. No Reader or other actor
    // owns this pool or its Close responsibility.
    owner.gate.Lock()
    owner.writePool = created
    owner.observationVersion++
    owner.gate.Unlock()
    return created, nil
}

func (owner *registryLifecycleOwner) beginWrite(ctx context.Context) (*sqliteWriteTx, error) {
    operation, err := owner.acquireRole(ctx, registryWriteRole, registryWriteTransaction)
    if err != nil { return nil, err }
    keepOperation := false
    defer func() { if !keepOperation { operation.release() } }()
    if err := owner.checkLocation(); err != nil { return nil, err }
    pool, err := owner.writerPoolFor(operation)
    if err != nil { return nil, err }
    conn, err := pool.Conn(ctx)
    if err != nil { return nil, owner.readError(ctx, err, "sqlite.write_connection") }
    if err := owner.attachConnection(operation, conn, registryWriteRole); err != nil {
        return nil, err // unknown/foreign ownership cannot authorize a Close
    }
    if err := ctx.Err(); err != nil {
        _ = owner.releaseConnection(operation, conn, registryWriteRole)
        return nil, err
    }
    if owner.uncertain.Load() {
        _ = owner.releaseConnection(operation, conn, registryWriteRole)
        return nil, fault(CodeUnavailable, "sqlite.lifecycle_uncertain")
    }
    transaction, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: false})
    if err != nil {
        var driverError *sqlite.Error
        if errors.As(err, &driverError) && driverError.Code()&0xff == 5 {
            // A failed BEGIN IMMEDIATE with SQLITE_BUSY is a qualified
            // no-transaction rejection. There is no automatic admission retry.
            _ = owner.releaseConnection(operation, conn, registryWriteRole)
            return nil, fault(CodeUnavailable, "sqlite.write_busy")
        }
        // Other Begin failures may lack a complete start/cleanup proof. Keep
        // the Conn even though database/sql supplied no Tx object.
        owner.noteWriteOutcomeUnknown(operation)
        return nil, owner.readError(ctx, err, "sqlite.write_begin_unknown")
    }
    if err := owner.attachTransaction(operation, conn, transaction, registryWriteRole); err != nil {
        if rollbackErr := transaction.Rollback(); rollbackErr != nil {
            owner.noteWriteOutcomeUnknown(operation)
        } else {
            _ = owner.releaseConnection(operation, conn, registryWriteRole)
        }
        return nil, err
    }
    tx := &sqliteWriteTx{
        tx: transaction, conn: conn, operation: operation, context: ctx,
        outcome: sqliteWriteActive, done: make(chan struct{}),
    }
    // From now on the concrete transaction owns the borrow even when profile
    // or schema validation fails. Its terminal path preserves ambiguity.
    keepOperation = true
    valid := false
    defer func() { if !valid { _ = tx.Rollback() } }()
    var queryOnly, trustedSchema int
    var journal string
    if err := transaction.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil {
        return nil, owner.readError(ctx, err, "sqlite.write_query_only")
    }
    if err := transaction.QueryRowContext(ctx, "PRAGMA trusted_schema").Scan(&trustedSchema); err != nil {
        return nil, owner.readError(ctx, err, "sqlite.write_trusted_schema")
    }
    if err := transaction.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
        return nil, owner.readError(ctx, err, "sqlite.write_journal")
    }
    if queryOnly != 0 || trustedSchema != 0 || strings.ToLower(journal) != "delete" {
        return nil, invalid("sqlite.write_profile")
    }
    if err := validateSQLiteSchema(ctx, transaction); err != nil {
        if ctx.Err() != nil { return nil, ctx.Err() }
        return nil, err
    }
    valid = true
    go tx.watchContext()
    return tx, nil
}
