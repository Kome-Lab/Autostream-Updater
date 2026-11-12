package registry

import (
    "context"
    "database/sql"
    "errors"
    "os"
    "reflect"
    "sync"
    "testing"
    "time"
)

// All SQL below is confined to disposable synthetic databases. TEMP tables are
// connection-local probes: no product reference, receipt or schema is mutated.
func sqliteWriterOpen(t *testing.T) (*SQLiteReadPort, sqliteTestFixture) {
    t.Helper()
    fixture := sqliteTestNew(t, Positive)
    port := sqliteTestOpen(t, fixture)
    sqliteWriterSyntheticCleanup(t, port.owner)
    if err := port.owner.prepareWriterProfile(context.Background()); err != nil {
        t.Fatal("trusted synthetic Writer profile preparation failed")
    }
    return port, fixture
}

func sqliteWriterActualPool(pool registryConnectionPool) *sql.DB {
    switch value := pool.(type) {
    case *sql.DB:
        return value
    case *sqliteLifecycleTestPool:
        return value.actual
    case *sqliteInspectionPoolSpy:
        return sqliteWriterActualPool(value.actual)
    case *sqliteRolesConnectionBarrierPool:
        return sqliteWriterActualPool(value.registryConnectionPool)
    default:
        return nil
    }
}

// Only the test harness may force cleanup after an injected UNKNOWN. It first
// ends synthetic Tx/Conn handles and proves both actual pools empty, then closes
// the one header and releases the lease. This is not a product recovery route.
func sqliteWriterSyntheticCleanup(t *testing.T, owner *registryLifecycleOwner) {
    t.Helper()
    t.Cleanup(func() {
        records := sqliteRolesRecords(owner)
        for operation, record := range records {
            if record.tx != nil { _ = record.tx.Rollback() }
            if record.conn != nil { _ = record.conn.Close() }
            if record.active { operation.release() }
        }
        _ = owner.Close()
        owner.gate.Lock()
        pools := []registryConnectionPool{owner.writePool, owner.pool}
        header, lease := owner.header, owner.lease
        owner.gate.Unlock()
        for _, resource := range pools {
            if resource == nil { continue }
            pool := sqliteWriterActualPool(resource)
            if pool == nil {
                t.Error("synthetic pool cleanup has no proven actual resource")
                return
            }
            if err := pool.Close(); err != nil || pool.Stats().OpenConnections != 0 {
                t.Error("synthetic pool closure remains unproven")
                return
            }
        }
        if _, err := header.Stat(); err == nil {
            if err := header.Close(); err != nil {
                t.Error("synthetic header closure remains unproven")
                return
            }
        } else if !errors.Is(err, os.ErrClosed) {
            t.Error("synthetic header state remains unproven")
            return
        }
        registryReleaseInodeLease(lease)
    })
}

func sqliteWriterAssert(t *testing.T, d RegistryLifecycleDiagnostic, operations, transactions, connections, unresolved, unknown int64) {
    t.Helper()
    if d.Roles.Write.Profile != LifecycleWriterProfileConfigured ||
        d.Roles.WriteImplementation != LifecycleRoleImplemented ||
        d.Roles.WriterAdmission != LifecycleAdmissionProvided ||
        d.Roles.MutationImplementation != LifecycleRoleNotImplemented ||
        d.Roles.GuardControlImplementation != LifecycleRoleNotImplemented ||
        d.Roles.ContinuityImplementation != LifecycleRoleNotImplemented {
        t.Fatal("configured connection profile was confused with product Mutation authority")
    }
    sqliteInspectionCount(t, d.Roles.Write.Operations, operations)
    sqliteInspectionCount(t, d.Roles.Write.Transactions, transactions)
    sqliteInspectionCount(t, d.Roles.Write.Connections, connections)
    sqliteInspectionCount(t, d.Roles.Write.UnresolvedConnections, unresolved)
    sqliteInspectionCount(t, d.Roles.Write.UnknownOutcomes, unknown)
}

func TestSQLiteWriterProfileInstallationIsExplicit(t *testing.T) {
    fixture := sqliteTestNew(t, Positive)
    port := sqliteTestOpen(t, fixture)
    owner := port.owner
    sqliteWriterSyntheticCleanup(t, owner)
    header, lease, pool := owner.header, owner.lease, owner.pool
    before := sqliteInspectionStamp(owner)
    if tx, err := owner.beginWrite(context.Background()); tx != nil || err == nil {
        t.Fatal("Read-only construction admitted a Writer")
    }
    if !reflect.DeepEqual(before, sqliteInspectionStamp(owner)) || owner.writePool != nil || owner.writerConfigured {
        t.Fatal("rejected Writer created resources or installed a profile")
    }
    if port.InspectLifecycle().Roles.Write.Profile != LifecycleWriterProfileNotConfigured {
        t.Fatal("unconfigured owner was advertised as Writer-ready")
    }
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    if err := owner.prepareWriterProfile(ctx); !errors.Is(err, context.Canceled) {
        t.Fatal("pre-canceled profile installation was accepted")
    }
    if err := owner.prepareWriterProfile(nil); err == nil {
        t.Fatal("nil installation context was accepted")
    }
    operation, err := owner.acquire(context.Background())
    if err != nil { t.Fatal(err) }
    if err := owner.prepareWriterProfile(context.Background()); err == nil {
        operation.release()
        t.Fatal("profile installation ignored an active Read borrow")
    }
    operation.release()
    if err := owner.prepareWriterProfile(context.Background()); err != nil { t.Fatal(err) }
    if err := owner.prepareWriterProfile(context.Background()); err != nil { t.Fatal("same trusted profile was not idempotent") }
    if owner.header != header || owner.lease != lease || owner.pool != pool || owner.writePool != nil {
        t.Fatal("installing the profile duplicated owned resources or eagerly opened a Writer pool")
    }
    sqliteWriterAssert(t, port.InspectLifecycle(), 0, 0, 0, 0, 0)
    sqliteInspectionFact(t, port.InspectLifecycle().Roles.Write.Admission, true)
}

func TestSQLiteWriterFixedProfilesShareOneLifecycle(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    owner := port.owner
    header, lease, readPool := owner.header, owner.lease, owner.pool
    tx, err := owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    defer tx.Rollback()
    var queryOnly, trusted int
    var journal string
    if err := tx.tx.QueryRowContext(context.Background(), "PRAGMA query_only").Scan(&queryOnly); err != nil { t.Fatal(err) }
    if err := tx.tx.QueryRowContext(context.Background(), "PRAGMA trusted_schema").Scan(&trusted); err != nil { t.Fatal(err) }
    if err := tx.tx.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journal); err != nil { t.Fatal(err) }
    if queryOnly != 0 || trusted != 0 || journal != "delete" {
        t.Fatal("Writer connection lost its fixed writable profile")
    }
    if owner.header != header || owner.lease != lease || owner.pool != readPool ||
        owner.writePool == nil || owner.writePool == readPool {
        t.Fatal("role-specific pools did not remain under the same header and lease owner")
    }
    if owner.writePool.Stats().MaxOpenConnections != 1 || readPool.Stats().MaxOpenConnections != 2 {
        t.Fatal("Writer and Read connection limits were mixed")
    }
    record := sqliteRolesRecords(owner)[tx.operation]
    if !record.active || record.role != registryWriteRole || record.kind != registryWriteTransaction ||
        record.conn != tx.conn || record.tx != tx.tx || tx.operation.owner != owner {
        t.Fatal("Writer connection/transaction did not belong to its admitted operation")
    }
    sqliteWriterAssert(t, port.InspectLifecycle(), 1, 1, 1, 0, 0)
    if err := tx.Rollback(); err != nil { t.Fatal(err) }
    read, err := owner.beginRead(context.Background())
    if err != nil { t.Fatal(err) }
    defer read.Rollback()
    if err := read.QueryRowContext(context.Background(), "PRAGMA query_only").Scan(&queryOnly); err != nil { t.Fatal(err) }
    if err := read.QueryRowContext(context.Background(), "PRAGMA trusted_schema").Scan(&trusted); err != nil { t.Fatal(err) }
    if queryOnly != 1 || trusted != 0 { t.Fatal("using Writer promoted the Read connection profile") }
}

func TestSQLiteWriterReadRoleStillCannotWrite(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    read, err := port.owner.beginRead(context.Background())
    if err != nil { t.Fatal(err) }
    defer read.Rollback()
    if _, err := read.ExecContext(context.Background(), "CREATE TEMP TABLE forbidden_read_write(value TEXT)"); err == nil {
        t.Fatal("Read role acquired write capability after Writer profile installation")
    }
    if err := read.Rollback(); err != nil { t.Fatal(err) }
    if port.owner.uncertain.Load() { t.Fatal("a known rejected Read write poisoned ownership") }
}

func TestSQLiteWriterReadAdmissionExcludesWriter(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    read, err := port.owner.beginRead(context.Background())
    if err != nil { t.Fatal(err) }
    defer read.Rollback()
    before := sqliteInspectionStamp(port.owner)
    if tx, err := port.owner.beginWrite(context.Background()); tx != nil || err == nil {
        t.Fatal("Writer was admitted across an existing Read snapshot")
    }
    if !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) || port.owner.writePool != nil {
        t.Fatal("Read/Writer conflict changed owner state or opened a Writer pool")
    }
    sqliteInspectionFact(t, port.InspectLifecycle().Roles.Write.Admission, false)
    if err := read.Rollback(); err != nil { t.Fatal(err) }
    writer, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal("known Read completion did not permit an explicit later Writer") }
    if err := writer.Rollback(); err != nil { t.Fatal(err) }
}

func TestSQLiteWriterAdmissionExcludesReadsAndOtherWriters(t *testing.T) {
    port, fixture := sqliteWriterOpen(t)
    tx, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    defer tx.Rollback()
    before := sqliteInspectionStamp(port.owner)
    if read, err := port.owner.beginRead(context.Background()); read != nil || err == nil {
        t.Fatal("Read entered an active Writer snapshot")
    }
    if _, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope); err == nil {
        t.Fatal("public Read bypassed Writer admission")
    }
    const attempts = 8
    results := make(chan bool, attempts)
    var group sync.WaitGroup
    for i := 0; i < attempts; i++ {
        group.Add(1)
        go func() {
            defer group.Done()
            other, err := port.owner.beginWrite(context.Background())
            rejected := other == nil && err != nil
            if other != nil { _ = other.Rollback() }
            results <- rejected
        }()
    }
    group.Wait()
    close(results)
    for rejected := range results { if !rejected { t.Fatal("same-registry competing Writer was admitted") } }
    if !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) {
        t.Fatal("rejected conflicting admission changed active Writer ownership")
    }
    d := port.InspectLifecycle()
    sqliteWriterAssert(t, d, 1, 1, 1, 0, 0)
    sqliteInspectionFact(t, d.Roles.Read.Admission, false)
    sqliteInspectionFact(t, d.Roles.Write.Admission, false)
    if err := tx.Rollback(); err != nil { t.Fatal(err) }
    active, err := port.ReadActiveReference(context.Background(), fixture.request.Command.Scope)
    if err != nil || active.Knowledge != Known { t.Fatal("Read did not resume after known Writer settlement") }
}

func TestSQLiteWriterConfiguredOwnerAllowsConcurrentReads(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    results := make(chan *sqliteReadTx, 2)
    failures := make(chan error, 2)
    var group sync.WaitGroup
    for i := 0; i < 2; i++ {
        group.Add(1)
        go func() {
            defer group.Done()
            tx, err := port.owner.beginRead(ctx)
            if err != nil { failures <- err; return }
            results <- tx
        }()
    }
    group.Wait()
    close(results)
    close(failures)
    var reads []*sqliteReadTx
    for tx := range results { reads = append(reads, tx); defer tx.Rollback() }
    for range failures { t.Fatal("configured Writer profile serialized independent Reads") }
    if len(reads) != 2 || reads[0].conn == reads[1].conn { t.Fatal("Read pool lost independent snapshots") }
    sqliteInspectionCount(t, port.InspectLifecycle().Roles.Read.Transactions, 2)
    sqliteWriterAssert(t, port.InspectLifecycle(), 0, 0, 0, 0, 0)
}

func TestSQLiteWriterCommitRollbackAndRepeatedTerminalCalls(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    first, err := port.owner.beginWrite(ctx)
    if err != nil { t.Fatal(err) }
    defer first.Rollback()
    if _, err := first.tx.ExecContext(ctx, "CREATE TEMP TABLE writer_probe(value INTEGER NOT NULL)"); err != nil { t.Fatal(err) }
    if _, err := first.tx.ExecContext(ctx, "INSERT INTO writer_probe(value) VALUES(7)"); err != nil { t.Fatal(err) }
    if err := first.Commit(); err != nil || first.State() != sqliteWriteCommitted { t.Fatal("known Writer commit was not recorded") }
    if err := first.Commit(); err != nil || first.State() != sqliteWriteCommitted { t.Fatal("reporting a known commit caused another terminal action") }
    cancel()
    if first.State() != sqliteWriteCommitted || port.owner.uncertain.Load() { t.Fatal("post-completion cancellation erased known commit") }

    second, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    defer second.Rollback()
    var count int
    if err := second.tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM writer_probe WHERE value=7").Scan(&count); err != nil || count != 1 {
        t.Fatal("known committed TEMP data was missing or duplicated")
    }
    if _, err := second.tx.ExecContext(context.Background(), "INSERT INTO writer_probe(value) VALUES(9)"); err != nil { t.Fatal(err) }
    if err := second.Rollback(); err != nil || second.State() != sqliteWriteRolledBack { t.Fatal("known rollback was not recorded") }
    if err := second.Rollback(); err != nil { t.Fatal("reporting known rollback re-executed settlement") }
    third, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    defer third.Rollback()
    if err := third.tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM writer_probe WHERE value=9").Scan(&count); err != nil || count != 0 {
        t.Fatal("rolled-back TEMP data became visible")
    }
    if err := third.Rollback(); err != nil { t.Fatal(err) }
    sqliteWriterAssert(t, port.InspectLifecycle(), 0, 0, 0, 0, 0)
}

func TestSQLiteWriterPreCanceledAdmissionHasNoEffects(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    before := sqliteInspectionStamp(port.owner)
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    tx, err := port.owner.beginWrite(ctx)
    if tx != nil || !errors.Is(err, context.Canceled) { t.Fatal("canceled Writer request was accepted") }
    if !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) || port.owner.writePool != nil {
        t.Fatal("canceled admission created a Writer resource")
    }
}

func TestSQLiteWriterCancellationRetainsUnknownDuty(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    tx, err := port.owner.beginWrite(ctx)
    if err != nil { t.Fatal(err) }
    defer tx.Rollback()
    wait, stop := context.WithTimeout(context.Background(), 10*time.Second)
    defer stop()
    cancel()
    sqliteLifecycleAwait(t, wait, tx.done)
    if tx.State() != sqliteWriteUnknown || !port.owner.uncertain.Load() { t.Fatal("canceled accepted Writer was falsely settled") }
    d := port.InspectLifecycle()
    sqliteWriterAssert(t, d, 0, 1, 1, 1, 1)
    if d.State != LifecycleUncertain { t.Fatal("canceled Writer uncertainty was hidden") }
    sqliteInspectionFact(t, d.Roles.Write.Admission, false)
    record := sqliteRolesRecords(port.owner)[tx.operation]
    if record.active || !record.unresolved || record.conn != tx.conn || record.tx != tx.tx {
        t.Fatal("cancellation dropped uncertain connection/transaction ownership")
    }
    before := sqliteInspectionStamp(port.owner)
    if tx.Commit() == nil || tx.Rollback() == nil { t.Fatal("unknown cancellation was turned into execution or repair") }
    if !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) { t.Fatal("unknown terminal replay changed owner state") }
    if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(port.owner) { t.Fatal("canceled uncertainty released the inode") }
}

func TestSQLiteWriterCloseDrainsBothRolePools(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    tx, err := port.owner.beginWrite(ctx)
    if err != nil { t.Fatal(err) }
    defer tx.Rollback()
    closed := make(chan error, 1)
    go func() { closed <- port.Close() }()
    sqliteLifecycleAwait(t, ctx, port.owner.closingStarted)
    d := port.InspectLifecycle()
    if d.State != LifecycleClosing || d.Drain != LifecycleDrainWaiting { t.Fatal("Close did not drain accepted Writer") }
    sqliteWriterAssert(t, d, 1, 1, 1, 0, 0)
    sqliteInspectionFact(t, d.Header.Released, false)
    sqliteInspectionFact(t, d.Lease.Held, true)
    if other, err := port.owner.beginWrite(ctx); other != nil || err == nil { t.Fatal("closing owner admitted another Writer") }
    if other, err := port.owner.beginRead(ctx); other != nil || err == nil { t.Fatal("closing owner admitted another Read") }
    if err := port.owner.prepareWriterProfile(ctx); err == nil { t.Fatal("closing owner installed a profile") }
    sqliteLifecycleCheckBlocked(t, closed)
    if err := tx.Rollback(); err != nil { t.Fatal(err) }
    if err := sqliteLifecycleCloseResult(t, ctx, closed); err != nil { t.Fatal(err) }
    d = port.InspectLifecycle()
    sqliteInspectionClosed(t, d)
    sqliteWriterAssert(t, d, 0, 0, 0, 0, 0)
    sqliteInspectionFact(t, d.Roles.Write.PoolReleased, true)
    if d.Roles.Write.Pool.Knowledge != Known || d.Roles.Write.Pool.OpenConnections != 0 ||
        port.owner.pool.Stats().OpenConnections != 0 || port.owner.writePool.Stats().OpenConnections != 0 {
        t.Fatal("header was released before both role pools were closed")
    }
}

func TestSQLiteWriterCommitFailureNeverReplays(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    tx, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    defer tx.Rollback()
    if _, err := tx.tx.ExecContext(context.Background(), "CREATE TEMP TABLE writer_once(value INTEGER)"); err != nil { t.Fatal(err) }
    if _, err := tx.tx.ExecContext(context.Background(), "INSERT INTO writer_once(value) VALUES(1)"); err != nil { t.Fatal(err) }
    // Deliberate synthetic mismatch: the underlying driver completed, but the
    // managed Tx did not receive that result. ErrTxDone is not commit proof.
    if err := tx.tx.Commit(); err != nil { t.Fatal(err) }
    if tx.Commit() == nil || tx.State() != sqliteWriteUnknown { t.Fatal("unproven managed commit was promoted to success") }
    d := port.InspectLifecycle()
    sqliteWriterAssert(t, d, 0, 1, 1, 1, 1)
    before := sqliteInspectionStamp(port.owner)
    if tx.Commit() == nil || tx.Rollback() == nil { t.Fatal("unknown result permitted original operation replay") }
    if !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) { t.Fatal("unknown replay changed the retained duty") }
    if other, err := port.owner.beginWrite(context.Background()); other != nil || err == nil { t.Fatal("unknown owner admitted a new Writer") }
    if read, err := port.owner.beginRead(context.Background()); read != nil || err == nil { t.Fatal("unknown owner admitted a new Read") }
    if err := port.owner.prepareWriterProfile(context.Background()); err == nil { t.Fatal("profile installation cleared uncertainty") }
    var count int
    if err := tx.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM writer_once").Scan(&count); err != nil || count != 1 {
        t.Fatal("unknown reporting repeated or discarded the synthetic effect")
    }
    if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(port.owner) { t.Fatal("unknown commit released owned resources") }
}

func TestSQLiteWriterConnectionReleaseFailureRetainsOwnership(t *testing.T) {
    t.Run("ambiguous-return", func(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    tx, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    defer tx.Rollback()
    if err := tx.tx.Rollback(); err != nil { t.Fatal(err) }
    if err := tx.conn.Close(); err != nil { t.Fatal(err) }
    if err := port.owner.releaseConnection(tx.operation, tx.conn, registryWriteRole); err == nil {
        t.Fatal("unknown duplicate connection return was accepted as released")
    }
    record := sqliteRolesRecords(port.owner)[tx.operation]
    if !record.active || !record.unresolved || record.conn != tx.conn || record.tx != tx.tx || !port.owner.uncertain.Load() {
        t.Fatal("connection return failure dropped retained Writer ownership")
    }
    _ = tx.Rollback()
    if tx.State() != sqliteWriteUnknown { t.Fatal("terminal mismatch repaired unknown connection state") }
    d := port.InspectLifecycle()
    if d.State != LifecycleUncertain { t.Fatal("connection return failure became OPEN") }
    sqliteInspectionCount(t, d.Roles.Write.UnresolvedConnections, 1)
    if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(port.owner) { t.Fatal("uncertain connection allowed final Close") }

    })
    t.Run("known-commit-unknown-return", func(t *testing.T) {
        port, _ := sqliteWriterOpen(t)
        tx, err := port.owner.beginWrite(context.Background())
        if err != nil { t.Fatal(err) }
        defer tx.Rollback()
        if err := tx.tx.Commit(); err != nil { t.Fatal(err) }
        if err := tx.conn.Close(); err != nil { t.Fatal(err) }
        // Exercise the actual post-success cleanup boundary with a synthetic
        // premature connection return, without changing production callbacks.
        tx.finishMu.Lock()
        err = tx.finishKnownLocked(sqliteWriteCommitted)
        tx.finishMu.Unlock()
        if err == nil || tx.State() != sqliteWriteCommitted || !port.owner.uncertain.Load() {
            t.Fatal("known SQL commit and unknown connection return were conflated")
        }
        d := port.InspectLifecycle()
        sqliteWriterAssert(t, d, 0, 1, 1, 1, 0)
        before := sqliteInspectionStamp(port.owner)
        if tx.Commit() == nil || tx.State() != sqliteWriteCommitted ||
            !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) {
            t.Fatal("reporting known outcome repaired or repeated uncertain cleanup")
        }
        if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(port.owner) {
            t.Fatal("unknown post-commit connection ownership released the inode")
        }
    })
}

func TestSQLiteWriterPoolCloseFailureRetainsHeaderAndLease(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    tx, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    if err := tx.Rollback(); err != nil { t.Fatal(err) }
    actual := port.owner.writePool.(*sql.DB)
    port.owner.writePool = &sqliteLifecycleTestPool{actual: actual, closeError: errors.New("synthetic Writer close failure")}
    if err := port.Close(); err == nil { t.Fatal("failed Writer pool closure was accepted") }
    d := port.InspectLifecycle()
    if d.State != LifecycleUncertain || d.Close.Result != LifecycleCloseUnknown { t.Fatal("failed Writer pool closure lost uncertainty") }
    sqliteInspectionFact(t, d.Roles.Write.PoolCloseStarted, true)
    sqliteInspectionFact(t, d.Roles.Write.PoolReleased, false)
    sqliteInspectionFact(t, d.Header.Released, false)
    sqliteInspectionFact(t, d.Lease.Held, true)
    if _, err := port.owner.header.Stat(); err != nil { t.Fatal("Writer pool failure closed shared header") }
    before := sqliteInspectionStamp(port.owner)
    if err := port.Close(); err == nil || !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) {
        t.Fatal("uncertain Close retried itself or cleared retained ownership")
    }
}

func TestSQLiteWriterInspectionIsReadOnlyAndNoSQLSurface(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    tx, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    defer tx.Rollback()
    before := sqliteInspectionStamp(port.owner)
    records := sqliteRolesRecords(port.owner)
    diagnostic := port.InspectLifecycle()
    sqliteWriterAssert(t, diagnostic, 1, 1, 1, 0, 0)
    for i := 0; i < 32; i++ {
        if !reflect.DeepEqual(diagnostic, port.InspectLifecycle()) { t.Fatal("stable Writer inspection changed its output") }
    }
    if !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) || !reflect.DeepEqual(records, sqliteRolesRecords(port.owner)) {
        t.Fatal("inspection changed Writer ownership or lifecycle state")
    }
    kind := reflect.TypeOf(*tx)
    for i := 0; i < kind.NumField(); i++ { if kind.Field(i).Anonymous { t.Fatal("Writer embeds an unrestricted SQL transaction") } }
    for _, name := range []string{"Exec", "ExecContext", "Query", "QueryContext", "Raw", "BeginWrite", "PrepareWriterProfile"} {
        if _, exists := reflect.TypeOf(tx).MethodByName(name); exists { t.Fatal("private Writer exposed arbitrary SQL or admission") }
        if _, exists := reflect.TypeOf(port).MethodByName(name); exists { t.Fatal("public Read port exposed Writer admission or SQL") }
    }
    var queryOnly int
    if err := tx.tx.QueryRowContext(context.Background(), "PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly != 0 {
        t.Fatal("Inspection changed the Writer connection profile")
    }
}

func TestSQLiteWriterSameInodeCannotAcquireSecondOwner(t *testing.T) {
    port, fixture := sqliteWriterOpen(t)
    tx, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    defer tx.Rollback()
    header, lease, readPool, writePool := port.owner.header, port.owner.lease, port.owner.pool, port.owner.writePool
    other, err := OpenSQLiteReadPort(context.Background(), SQLiteReadConfig{Directory: fixture.directory, DatabaseName: RegistryDatabaseName})
    if other != nil { _ = other.Close() }
    if err == nil || other != nil { t.Fatal("second owner acquired an inode with an active Writer") }
    if port.owner.header != header || port.owner.lease != lease || port.owner.pool != readPool || port.owner.writePool != writePool {
        t.Fatal("duplicate Open changed the one owner resources")
    }
    if !sqliteLifecycleLeaseHeld(port.owner) { t.Fatal("duplicate Open dropped the active Writer lease") }
}

func TestSQLiteWriterPendingConnectionCancellationDrainsBeforeClose(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    warm, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    if err := warm.Rollback(); err != nil { t.Fatal(err) }
    actual := port.owner.writePool
    arrived, proceed := make(chan struct{}), make(chan struct{})
    var once sync.Once
    resume := func() { once.Do(func() { close(proceed) }) }
    defer resume()
    barrier := func() { close(arrived); <-proceed }
    port.owner.writePool = &sqliteRolesConnectionBarrierPool{registryConnectionPool: actual, barrier: barrier}
    deadline, stop := context.WithTimeout(context.Background(), 10*time.Second)
    defer stop()
    ctx, cancel := context.WithCancel(deadline)
    defer cancel()
    result := make(chan error, 1)
    go func() {
        tx, err := port.owner.beginWrite(ctx)
        if tx != nil { _ = tx.Rollback() }
        result <- err
    }()
    sqliteLifecycleAwait(t, deadline, arrived)
    sqliteWriterAssert(t, port.InspectLifecycle(), 1, 0, 0, 0, 0)
    closed := make(chan error, 1)
    go func() { closed <- port.Close() }()
    sqliteLifecycleAwait(t, deadline, port.owner.closingStarted)
    sqliteLifecycleCheckBlocked(t, closed)
    sqliteInspectionFact(t, port.InspectLifecycle().Header.Released, false)
    cancel()
    resume()
    if err := sqliteLifecycleCloseResult(t, deadline, result); !errors.Is(err, context.Canceled) {
        t.Fatal("pre-Begin cancellation was not a known unstarted connection return")
    }
    if err := sqliteLifecycleCloseResult(t, deadline, closed); err != nil {
        t.Fatal("Close did not wait for the pending Writer connection to return")
    }
    diagnostic := port.InspectLifecycle()
    sqliteInspectionClosed(t, diagnostic)
    sqliteWriterAssert(t, diagnostic, 0, 0, 0, 0, 0)
}

func TestSQLiteWriterUntrackedPoolConnectionCannotReleaseInode(t *testing.T) {
    port, _ := sqliteWriterOpen(t)
    warm, err := port.owner.beginWrite(context.Background())
    if err != nil { t.Fatal(err) }
    if err := warm.Rollback(); err != nil { t.Fatal(err) }
    // Deliberate package-internal bypass around the managed role seam, on a
    // synthetic DB only. A live pool handle is not absence/release proof.
    conn, err := port.owner.writePool.Conn(context.Background())
    if err != nil { t.Fatal(err) }
    defer conn.Close()
    if err := port.Close(); err == nil || !port.owner.uncertain.Load() ||
        !sqliteLifecycleLeaseHeld(port.owner) {
        t.Fatal("untracked Writer connection was treated as released")
    }
    if _, err := port.owner.header.Stat(); err != nil {
        t.Fatal("Header closed while an untracked Writer connection survived")
    }
    if err := conn.Close(); err != nil { t.Fatal(err) }
    if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(port.owner) {
        t.Fatal("later connection return silently repaired failed Close")
    }
    if port.InspectLifecycle().State != LifecycleUncertain {
        t.Fatal("unknown pool closure recovered automatically")
    }
}
