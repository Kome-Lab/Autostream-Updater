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
	pool           registryConnectionPool
	header         registryHeaderFD
	path           string
	identity       os.FileInfo
	lease          *registryInodeLease
	gate           sync.Mutex
	activeOps      sync.WaitGroup
	closing        atomic.Bool
	uncertain      atomic.Bool
	closeOnce      sync.Once
	closeErr       error
	closingStarted chan struct{}
}

// registryOperation is a counted borrow, released once after the whole public
// read (including independent Continuity qualification) has finished.
type registryOperation struct {
	owner *registryLifecycleOwner
	once  sync.Once
}

func (operation *registryOperation) release() {
	if operation == nil {
		return
	}
	operation.once.Do(func() {
		operation.owner.activeOps.Done()
	})
}

func (owner *registryLifecycleOwner) acquire(ctx context.Context) (*registryOperation, error) {
	if ctx == nil {
		return nil, invalid("sqlite.context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
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
	// Add is under the same gate that closes admission before Close calls Wait.
	owner.activeOps.Add(1)
	return &registryOperation{owner: owner}, nil
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
		tx.releaseErr = tx.conn.Close()
		if tx.releaseErr != nil {
			// Record uncertainty BEFORE allowing Close's active-operation wait
			// to finish. An error never proves descriptor/lock release.
			tx.operation.owner.uncertain.Store(true)
		}
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
		path: path, identity: identity, closingStarted: make(chan struct{}),
	}
	// Acquire and strongly attach ownership BEFORE any raw database Open.
	lease, err := registryAcquireInodeLease(identity, owner)
	if err != nil {
		return nil, err
	}
	owner.lease = lease
	header, err := os.Open(path)
	if err != nil {
		_ = owner.Close()
		return nil, fault(CodeUnavailable, "sqlite.header")
	}
	owner.header = header
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
	owner.pool = pool
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
	operation, err := owner.acquire(ctx)
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
	transaction, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			owner.uncertain.Store(true)
		}
		return nil, owner.readError(ctx, err, "sqlite.begin")
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

func (owner *registryLifecycleOwner) Close() error {
	if owner == nil {
		return nil
	}
	owner.closeOnce.Do(func() {
		owner.gate.Lock()
		owner.closing.Store(true)
		if owner.closingStarted != nil {
			close(owner.closingStarted)
		}
		owner.gate.Unlock()
		owner.activeOps.Wait()
		if owner.uncertain.Load() {
			owner.closeErr = fault(CodeUnavailable, "sqlite.close_uncertain")
			return
		}
		if owner.pool != nil {
			if err := owner.pool.Close(); err != nil {
				owner.uncertain.Store(true)
				owner.closeErr = fault(CodeUnavailable, "sqlite.close")
				return
			}
			// An outstanding or asynchronously closing connection is not
			// released merely because DB.Close returned without an error.
			if owner.pool.Stats().OpenConnections != 0 {
				owner.uncertain.Store(true)
				owner.closeErr = fault(CodeUnavailable, "sqlite.close_pending")
				return
			}
		}
		if owner.header != nil {
			if err := owner.header.Close(); err != nil {
				owner.uncertain.Store(true)
				owner.closeErr = fault(CodeUnavailable, "sqlite.header_close")
				return
			}
		}
		registryReleaseInodeLease(owner.lease)
	})
	return owner.closeErr
}
