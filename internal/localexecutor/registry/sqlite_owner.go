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
// descriptor, lease or Close. The current pool is strictly mode=ro/query_only;
// this extraction does not enable a Writer or adopt a future write profile.
//
// A future Writer must share this owner, header, lease and pool lifecycle rather
// than independently opening another header or pool. GuardControl and P-A must
// participate in the same enforced writer boundary. That boundary, its writable
// profile and all-Actor participation are not implemented or certified here.
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
			owner.readTransactions != 0 || owner.unresolvedConnections != 0 || len(owner.operations) != 0 ||
			len(owner.connectionOwners) != 0 || len(owner.transactionOwners) != 0 {
			owner.uncertain.Store(true)
		}
		owner.observationVersion++
		owner.gate.Unlock()
		if owner.uncertain.Load() {
			owner.recordCloseError(fault(CodeUnavailable, "sqlite.close_uncertain"))
			return
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
