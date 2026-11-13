package registry

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These wrappers model resource failures only around synthetic temporary DBs.
// They are never installed by production configuration or exposed as Writer APIs.
type sqliteLifecycleTestPool struct {
	actual     *sql.DB
	closeError error
	leaveOpen  bool
	reportOpen int
	calls      atomic.Int32
}

func (p *sqliteLifecycleTestPool) Conn(ctx context.Context) (*sql.Conn, error) {
	return p.actual.Conn(ctx)
}
func (p *sqliteLifecycleTestPool) Close() error {
	p.calls.Add(1)
	if p.closeError != nil {
		return p.closeError
	}
	if p.leaveOpen {
		return nil
	}
	return p.actual.Close()
}
func (p *sqliteLifecycleTestPool) Stats() sql.DBStats {
	stats := p.actual.Stats()
	if p.reportOpen > stats.OpenConnections {
		stats.OpenConnections = p.reportOpen
	}
	return stats
}

type sqliteLifecycleTestHeader struct {
	actual     registryHeaderFD
	closeError error
	onClose    func()
	calls      atomic.Int32
}

func (h *sqliteLifecycleTestHeader) Stat() (os.FileInfo, error) { return h.actual.Stat() }
func (h *sqliteLifecycleTestHeader) ReadAt(data []byte, offset int64) (int, error) {
	return h.actual.ReadAt(data, offset)
}
func (h *sqliteLifecycleTestHeader) Close() error {
	h.calls.Add(1)
	if h.onClose != nil {
		h.onClose()
	}
	if h.closeError != nil {
		return h.closeError
	}
	return h.actual.Close()
}

func sqliteLifecycleAwait(t *testing.T, ctx context.Context, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("synthetic lifecycle operation did not reach its boundary")
	}
}

func sqliteLifecycleCloseResult(t *testing.T, ctx context.Context, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatal("synthetic lifecycle Close did not finish")
		return ctx.Err()
	}
}

func sqliteLifecycleLeaseHeld(owner *registryLifecycleOwner) bool {
	registryInodeLeases.Lock()
	defer registryInodeLeases.Unlock()
	_, present := registryInodeLeases.owners[owner.lease]
	return present && owner.lease.owner == owner
}

func sqliteLifecycleCheckBlocked(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case <-result:
		t.Fatal("Close completed before the active operation drained")
	default:
	}
}

// Only tests recover injected failures. First prove actual resource closure;
// then release the private process lease. There is no production resume/release API.
func sqliteLifecycleSyntheticCleanup(t *testing.T, owner *registryLifecycleOwner, pool *sql.DB, header registryHeaderFD) {
	t.Helper()
	t.Cleanup(func() {
		_ = owner.Close()
		if err := pool.Close(); err != nil {
			t.Errorf("synthetic pool cleanup did not establish closure: %v", err)
			return
		}
		if pool.Stats().OpenConnections != 0 {
			t.Error("synthetic cleanup still has a leased connection")
			return
		}
		if _, err := header.Stat(); err == nil {
			if err := header.Close(); err != nil {
				t.Errorf("synthetic header cleanup failed: %v", err)
				return
			}
		} else if !errors.Is(err, os.ErrClosed) {
			t.Errorf("synthetic header closure is still unknown: %v", err)
			return
		}
		registryReleaseInodeLease(owner.lease)
	})
}

func TestSQLiteLifecycleNormalAndConcurrentIdempotentClose(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	pool := owner.pool.(*sql.DB)
	header := owner.header
	trackedPool := &sqliteLifecycleTestPool{actual: pool}
	trackedHeader := &sqliteLifecycleTestHeader{actual: header}
	owner.pool, owner.header = trackedPool, trackedHeader
	if !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("open owner has no strong inode lease")
	}
	active, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope)
	if err != nil || active.Knowledge != Known {
		t.Fatal("normal owned read failed")
	}

	const callers = 12
	results := make(chan error, callers)
	var group sync.WaitGroup
	for i := 0; i < callers; i++ {
		group.Add(1)
		go func() { defer group.Done(); results <- port.Close() }()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("idempotent Close returned an error")
		}
	}
	if trackedPool.calls.Load() != 1 || trackedHeader.calls.Load() != 1 ||
		pool.Stats().OpenConnections != 0 || sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("normal Close did not release each resource exactly once")
	}
	if _, err := header.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("header descriptor remains open")
	}
	if _, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope); !errors.Is(err, ErrSQLiteClosed) {
		t.Fatal("closed owner admitted another read")
	}
	reopened, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName})
	if err != nil {
		t.Fatal("completed Close did not release ownership")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteLifecycleDrainsWholeReadIncludingIndependentContinuity(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	pool := owner.pool.(*sql.DB)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	continuityExited := make(chan struct{})
	fixture.continuity.onReference = func(ctx context.Context, _ Scope, frame BackendReadFrame, _ ActiveReference) (ContinuityReferenceObservation, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return ContinuityReferenceObservation{}, ctx.Err()
		}
		close(continuityExited)
		return ContinuityReferenceObservation{Knowledge: Known, Frame: frame, Evidence: sqliteTestEvidence(frame)}, nil
	}
	var earlyHeader atomic.Bool
	tracked := &sqliteLifecycleTestHeader{actual: owner.header, onClose: func() {
		select {
		case <-continuityExited:
		default:
			earlyHeader.Store(true)
		}
		if pool.Stats().OpenConnections != 0 {
			earlyHeader.Store(true)
		}
	}}
	owner.header = tracked
	readDone := make(chan error, 1)
	go func() { _, err := port.ReadActiveReference(ctx, fixture.request.Command.Scope); readDone <- err }()
	sqliteLifecycleAwait(t, ctx, entered)
	closeDone := make(chan error, 1)
	go func() { closeDone <- port.Close() }()
	sqliteLifecycleAwait(t, ctx, owner.closingStarted)
	sqliteLifecycleCheckBlocked(t, closeDone)
	if _, err := owner.header.Stat(); err != nil {
		t.Fatal("header closed during independent read qualification")
	}
	if _, err := port.ReadActiveReference(ctx, fixture.request.Command.Scope); !errors.Is(err, ErrSQLiteClosed) {
		t.Fatal("Close admission accepted a new read")
	}
	other, err := OpenSQLiteReadPort(ctx, SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName})
	if other != nil {
		_ = other.Close()
	}
	if err == nil {
		t.Fatal("closing owner released inode ownership before read completion")
	}
	close(release)
	if err := sqliteLifecycleCloseResult(t, ctx, readDone); err != nil {
		t.Fatal("accepted read did not finish")
	}
	if err := sqliteLifecycleCloseResult(t, ctx, closeDone); err != nil {
		t.Fatal(err)
	}
	if earlyHeader.Load() || tracked.calls.Load() != 1 || sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("Close did not drain the complete public read before releasing resources")
	}
}

func TestSQLiteLifecycleDrainsTransactionsWithoutDroppingProcessLocks(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-path", true: "hardlink"}[alias], func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			projection := readTestRecord(fixture.request, *fixture.snapshot.Backend.Receipt, ExecutorLedger)
			sqliteTestProjection(t, fixture, ExecutorLedger, projection)
			port := sqliteTestOpen(t, fixture)
			owner := port.owner
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			tx, err := owner.beginRead(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var evidence string
			if err := tx.QueryRowContext(ctx, "SELECT backend_frame_json FROM resources").Scan(&evidence); err != nil {
				t.Fatal(err)
			}
			closeDone := make(chan error, 1)
			go func() { closeDone <- port.Close() }()
			sqliteLifecycleAwait(t, ctx, owner.closingStarted)
			sqliteLifecycleCheckBlocked(t, closeDone)
			directory := fixture.directory
			if alias {
				directory = t.TempDir()
				if err := os.Link(fixture.path, filepath.Join(directory, RegistryDatabaseName)); err != nil {
					t.Fatal(err)
				}
			}
			other, err := OpenSQLiteReadPort(ctx, SQLiteReadConfig{Directory: directory, DatabaseName: RegistryDatabaseName})
			if other != nil {
				_ = other.Close()
			}
			if err == nil {
				t.Fatal("closing owner admitted a duplicate inode owner")
			}
			// Separate process/kernel locking is the oracle: closing an unmanaged
			// header descriptor would allow this COMMIT while our Tx is pinned.
			child := sqliteTestStartWriter(t, ctx, fixture.path, "pin")
			child.next(t, "ready")
			child.send(t, "begin")
			child.next(t, "staged")
			child.send(t, "try_commit")
			child.next(t, "busy")
			if !sqliteLifecycleLeaseHeld(owner) {
				t.Fatal("active transaction lost strong ownership")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			child.send(t, "commit")
			child.next(t, "committed")
			child.stop(t)
			if err := sqliteLifecycleCloseResult(t, ctx, closeDone); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSQLiteLifecycleCancellationDrainsConnectionBeforeHeader(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	pool := owner.pool.(*sql.DB)
	ctx, cancel := context.WithCancel(context.Background())
	tx, err := owner.beginRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	cancel()
	deadline, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	closeDone := make(chan error, 1)
	go func() { closeDone <- owner.Close() }()
	sqliteLifecycleAwait(t, deadline, owner.closingStarted)
	sqliteLifecycleCheckBlocked(t, closeDone)
	if _, err := owner.header.Stat(); err != nil || !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("cancellation prematurely closed the header or released ownership")
	}
	if _, err := owner.beginRead(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled acquisition lost its error")
	}
	err = tx.Rollback()
	if err != nil && !errors.Is(err, sql.ErrTxDone) && !errors.Is(err, context.Canceled) {
		t.Fatal("unexpected canceled transaction cleanup failure")
	}
	if err := sqliteLifecycleCloseResult(t, deadline, closeDone); err != nil {
		t.Fatal(err)
	}
	if pool.Stats().OpenConnections != 0 || sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("canceled connection remained live after successful Close")
	}
}

func TestSQLiteLifecycleRetainsOwnerOnResourceCloseFailure(t *testing.T) {
	for _, failure := range []string{"pool-error", "pending-connections", "header-error"} {
		t.Run(failure, func(t *testing.T) {
			fixture := sqliteTestNew(t, Positive)
			port := sqliteTestOpen(t, fixture)
			owner := port.owner
			pool := owner.pool.(*sql.DB)
			header := owner.header
			sqliteLifecycleSyntheticCleanup(t, owner, pool, header)
			poolWrapper := &sqliteLifecycleTestPool{actual: pool}
			headerWrapper := &sqliteLifecycleTestHeader{actual: header}
			switch failure {
			case "pool-error":
				poolWrapper.closeError = errors.New("SELECT synthetic private pool failure")
			case "pending-connections":
				poolWrapper.leaveOpen, poolWrapper.reportOpen = true, 1
			case "header-error":
				headerWrapper.closeError = errors.New("synthetic private header failure")
			}
			owner.pool, owner.header = poolWrapper, headerWrapper
			err := port.Close()
			if err == nil || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "SELECT") {
				t.Fatal("unknown closure became success or leaked a resource error")
			}
			if !sqliteLifecycleLeaseHeld(owner) {
				t.Fatal("failed Close released the strong inode lease")
			}
			if failure != "header-error" && headerWrapper.calls.Load() != 0 {
				t.Fatal("header closed before the pool was proven drained")
			}
			if _, err := header.Stat(); err != nil {
				t.Fatal("failure destroyed the retained header")
			}
			again := port.Close()
			if again == nil || again.Error() != err.Error() || poolWrapper.calls.Load() != 1 ||
				(failure == "header-error" && headerWrapper.calls.Load() != 1) {
				t.Fatal("repeated Close retried or hid unknown resource closure")
			}
			other, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName})
			if other != nil {
				_ = other.Close()
			}
			if err == nil {
				t.Fatal("failed owner transferred ownership to a new adapter")
			}
			if _, err := port.ReadExecution(context.Background(), fixture.request); !errors.Is(err, ErrSQLiteClosed) {
				t.Fatal("failed closing owner admitted more work")
			}
		})
	}
}

func TestSQLiteLifecycleUntrackedConnectionPreventsLeaseRelease(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	pool := owner.pool.(*sql.DB)
	header := owner.header
	sqliteLifecycleSyntheticCleanup(t, owner, pool, header)
	// Deliberate package-internal contract violation: model a handle that has not
	// returned to the pool. Future Writer code must use the owner's tracked path.
	conn, err := pool.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("outstanding SQL connection was treated as released")
	}
	if _, err := header.Stat(); err != nil {
		t.Fatal("header closed while a SQL connection remained")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("unknown closure silently retried after a later connection release")
	}
}

func TestSQLiteLifecycleConnectionReleaseErrorRetainsUncertainty(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	pool := owner.pool.(*sql.DB)
	header := owner.header
	sqliteLifecycleSyntheticCleanup(t, owner, pool, header)
	tx, err := owner.beginRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Inject a release-state mismatch without touching any descriptor while a
	// SQLite transaction holds a lock. This is synthetic package-internal misuse.
	if err := tx.Tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := tx.conn.Close(); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()
	if !owner.uncertain.Load() {
		t.Fatal("connection release failure did not poison lifecycle certainty")
	}
	if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("uncertain connection release relinquished ownership")
	}
	if _, err := header.Stat(); err != nil {
		t.Fatal("uncertain release closed the retained header")
	}
}

func TestSQLiteLifecycleDetectsSymlinksAndReplacement(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		fixture := sqliteTestNew(t, Positive)
		if err := fixture.writer.Close(); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "registry-link")
		if err := os.Symlink(fixture.directory, link); err != nil {
			t.Fatal(err)
		}
		port, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: link, DatabaseName: RegistryDatabaseName})
		if port != nil {
			_ = port.Close()
		}
		if err == nil {
			t.Fatal("symlink path admitted a lifecycle owner")
		}
	})
	t.Run("inode-replacement", func(t *testing.T) {
		fixture := sqliteTestNew(t, Positive)
		if err := fixture.writer.Close(); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(fixture.path)
		if err != nil {
			t.Fatal(err)
		}
		port := sqliteTestOpen(t, fixture)
		owner := port.owner
		oldIdentity := owner.identity
		// Both paths are inside this disposable fixture. The preserved original
		// remains intact; no real DB or recording is moved or overwritten.
		if err := os.Rename(fixture.path, fixture.path+".preserved"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.path, content, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope); err == nil {
			t.Fatal("inode replacement was accepted as the original database")
		}
		if !sqliteLifecycleLeaseHeld(owner) || !os.SameFile(owner.identity, oldIdentity) {
			t.Fatal("replacement changed or released the original inode ownership")
		}
		if err := port.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSQLiteLifecycleReadCloseRace(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	blocker, err := owner.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.release()
	start := make(chan struct{})
	failures := make(chan error, 16)
	var readers sync.WaitGroup
	for i := 0; i < 16; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for j := 0; j < 12; j++ {
				closedBefore := owner.closing.Load()
				active, err := port.ReadActiveReference(ctx, fixture.request.Command.Scope)
				if err != nil && !errors.Is(err, ErrSQLiteClosed) {
					failures <- err
					return
				}
				if closedBefore && (err == nil || active.Knowledge == Known) {
					failures <- errors.New("read admitted after Close started")
					return
				}
			}
		}()
	}
	closeDone := make(chan error, 1)
	close(start)
	go func() { closeDone <- port.Close() }()
	sqliteLifecycleAwait(t, ctx, owner.closingStarted)
	readers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("read/Close race violated admission")
		}
	}
	sqliteLifecycleCheckBlocked(t, closeDone)
	blocker.release()
	if err := sqliteLifecycleCloseResult(t, ctx, closeDone); err != nil {
		t.Fatal(err)
	}
	if sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("fully drained race retained ownership")
	}
}
