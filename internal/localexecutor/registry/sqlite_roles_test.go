package registry

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These wrappers belong only to temporary synthetic fixtures. They add neither
// a writable product profile nor an alternative owner, pool or descriptor.
type sqliteRolesPool struct {
	actual      registryConnectionPool
	connError   error
	connEntered chan struct{}
	calls       atomic.Int32
}

func (pool *sqliteRolesPool) Conn(ctx context.Context) (*sql.Conn, error) {
	pool.calls.Add(1)
	if pool.connEntered != nil {
		select {
		case pool.connEntered <- struct{}{}:
		default:
		}
	}
	if pool.connError != nil {
		return nil, pool.connError
	}
	return pool.actual.Conn(ctx)
}
func (pool *sqliteRolesPool) Close() error       { return pool.actual.Close() }
func (pool *sqliteRolesPool) Stats() sql.DBStats { return pool.actual.Stats() }

func sqliteRolesAssert(t *testing.T, diagnostic RegistryLifecycleDiagnostic, operations, transactions, connections, unresolved int64) {
	t.Helper()
	roles := diagnostic.Roles
	sqliteInspectionFact(t, roles.SharedOwner, true)
	if roles.Read.Implementation != LifecycleRoleImplemented ||
		roles.WriteImplementation != LifecycleRoleNotImplemented ||
		roles.WriterAdmission != LifecycleAdmissionNotProvided ||
		roles.MutationImplementation != LifecycleRoleNotImplemented {
		t.Fatal("diagnostics implied a Writer or hid the real Read implementation")
	}
	sqliteInspectionCount(t, roles.Read.Operations, operations)
	sqliteInspectionCount(t, roles.Read.Transactions, transactions)
	sqliteInspectionCount(t, roles.Read.Connections, connections)
	sqliteInspectionCount(t, roles.Read.UnresolvedConnections, unresolved)
}
func sqliteRolesRecords(owner *registryLifecycleOwner) map[*registryOperation]registryOperationRecord {
	owner.gate.Lock()
	defer owner.gate.Unlock()
	copy := make(map[*registryOperation]registryOperationRecord, len(owner.operations))
	for operation, record := range owner.operations {
		copy[operation] = record
	}
	return copy
}

func TestSQLiteRolesConcurrentReadTransactionsAndProfile(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
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
			if err != nil {
				failures <- err
				return
			}
			results <- tx
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	var transactions []*sqliteReadTx
	for tx := range results {
		transactions = append(transactions, tx)
		defer tx.Rollback()
	}
	for err := range failures {
		t.Fatalf("simultaneous Read borrow failed: %v", err)
	}
	if len(transactions) != 2 || transactions[0].conn == transactions[1].conn ||
		transactions[0].operation == transactions[1].operation || transactions[0].Tx == transactions[1].Tx {
		t.Fatal("independent Reads did not receive independent tracked transactions")
	}
	records := sqliteRolesRecords(port.owner)
	if len(records) != 2 {
		t.Fatal("two live Read transactions were not owned exactly once")
	}
	for _, tx := range transactions {
		record, present := records[tx.operation]
		if !present || tx.operation.owner != port.owner || tx.operation.role != registryReadRole ||
			tx.operation.kind != registryReadTransaction || !record.active ||
			record.conn != tx.conn || record.tx != tx.Tx || record.unresolved {
			t.Fatal("Read transaction, connection and operation ownership differ")
		}
		var queryOnly, trustedSchema int
		var journal string
		if err := tx.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRowContext(ctx, "PRAGMA trusted_schema").Scan(&trustedSchema); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
			t.Fatal(err)
		}
		if queryOnly != 1 || trustedSchema != 0 || journal != "delete" {
			t.Fatal("Read role lost its hardened connection profile")
		}
	}
	sqliteRolesAssert(t, port.InspectLifecycle(), 2, 2, 2, 0)
	for _, tx := range transactions {
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	sqliteRolesAssert(t, port.InspectLifecycle(), 0, 0, 0, 0)
	if len(sqliteRolesRecords(port.owner)) != 0 {
		t.Fatal("successful cleanup retained a live ownership record")
	}
}

func TestSQLiteRolesPublicOperationAndTransactionOwnership(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	operation, err := port.beginOperation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer operation.release()
	record := sqliteRolesRecords(port.owner)[operation]
	if operation.owner != port.owner || operation.role != registryReadRole || operation.kind != registryReadOperation ||
		!record.active || record.conn != nil || record.tx != nil || record.unresolved {
		t.Fatal("public Read operation owns a connection or incorrect role")
	}
	tx, err := port.owner.beginRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	sqliteRolesAssert(t, port.InspectLifecycle(), 2, 1, 1, 0)
	operation.release()
	operation.release()
	sqliteRolesAssert(t, port.InspectLifecycle(), 1, 1, 1, 0)
	if _, remains := sqliteRolesRecords(port.owner)[operation]; remains {
		t.Fatal("released public Read remained registered")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()
	sqliteRolesAssert(t, port.InspectLifecycle(), 0, 0, 0, 0)
}

func TestSQLiteRolesCloseDrainsOperationAndTransaction(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	operation, err := port.beginOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer operation.release()
	tx, err := port.owner.beginRead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	closed := make(chan error, 1)
	go func() { closed <- port.Close() }()
	sqliteLifecycleAwait(t, ctx, port.owner.closingStarted)
	diagnostic := port.InspectLifecycle()
	if diagnostic.State != LifecycleClosing || diagnostic.Drain != LifecycleDrainWaiting {
		t.Fatal("Close did not wait for Read ownership")
	}
	sqliteRolesAssert(t, diagnostic, 2, 1, 1, 0)
	sqliteInspectionFact(t, diagnostic.Roles.Read.Admission, false)
	sqliteInspectionFact(t, diagnostic.Header.Released, false)
	sqliteInspectionFact(t, diagnostic.Lease.Held, true)
	if borrow, err := port.owner.acquireRole(ctx, registryReadRole, registryReadOperation); err == nil || borrow != nil {
		t.Fatal("Close admitted another Read")
	}
	if borrow, err := port.owner.acquireRole(ctx, registryWriteRole, registryReadTransaction); err == nil || borrow != nil {
		t.Fatal("Close admitted an unimplemented Writer")
	}
	sqliteLifecycleCheckBlocked(t, closed)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	sqliteRolesAssert(t, port.InspectLifecycle(), 1, 0, 0, 0)
	sqliteLifecycleCheckBlocked(t, closed)
	operation.release()
	if err := sqliteLifecycleCloseResult(t, ctx, closed); err != nil {
		t.Fatal(err)
	}
	diagnostic = port.InspectLifecycle()
	sqliteInspectionClosed(t, diagnostic)
	sqliteRolesAssert(t, diagnostic, 0, 0, 0, 0)
	sqliteInspectionFact(t, diagnostic.Roles.Read.Admission, false)
}

func TestSQLiteRolesRejectWriteAndInvalidRolesWithoutEffects(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	pool := &sqliteInspectionPoolSpy{actual: owner.pool}
	header := &sqliteInspectionHeaderSpy{actual: owner.header}
	owner.pool, owner.header = pool, header
	before := sqliteInspectionStamp(owner)
	beforeRecords := sqliteRolesRecords(owner)
	beforeStats := pool.Stats()
	for _, input := range []struct {
		role registryConnectionRole
		kind registryOperationKind
	}{
		{registryWriteRole, registryReadOperation},
		{registryWriteRole, registryReadTransaction},
		{registryConnectionRole(0), registryReadOperation},
		{registryConnectionRole(255), registryReadTransaction},
		{registryReadRole, registryOperationKind(0)},
		{registryReadRole, registryOperationKind(255)},
	} {
		operation, err := owner.acquireRole(context.Background(), input.role, input.kind)
		if operation != nil || err == nil {
			t.Fatal("unsupported connection role or operation kind was usable")
		}
	}
	if !reflect.DeepEqual(before, sqliteInspectionStamp(owner)) || !reflect.DeepEqual(beforeRecords, sqliteRolesRecords(owner)) {
		t.Fatal("rejecting an unsupported role changed owner state")
	}
	afterStats := pool.Stats()
	if pool.connCalls.Load() != 0 || pool.closeCalls.Load() != 0 || header.statCalls.Load() != 0 ||
		header.readCalls.Load() != 0 || header.closeCalls.Load() != 0 ||
		beforeStats.OpenConnections != afterStats.OpenConnections || beforeStats.InUse != afterStats.InUse {
		t.Fatal("unsupported role touched a connection or descriptor")
	}
	sqliteRolesAssert(t, port.InspectLifecycle(), 0, 0, 0, 0)
}

func TestSQLiteRolesConnectionFailureReleasesUnboundBorrow(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	pool := &sqliteRolesPool{actual: port.owner.pool, connError: errors.New("synthetic private connection failure")}
	port.owner.pool = pool
	tx, err := port.owner.beginRead(context.Background())
	if tx != nil || err == nil {
		t.Fatal("connection failure was accepted")
	}
	if len(sqliteRolesRecords(port.owner)) != 0 || port.owner.uncertain.Load() {
		t.Fatal("known unbound acquisition failure leaked or poisoned ownership")
	}
	sqliteRolesAssert(t, port.InspectLifecycle(), 0, 0, 0, 0)
	if err := port.Close(); err != nil {
		t.Fatal("known unbound failure prevented a valid Close")
	}
}

func TestSQLiteRolesCanceledPoolWaitReleasesOnlyItsBorrow(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	deadline, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	first, err := port.owner.beginRead(deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	second, err := port.owner.beginRead(deadline)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback()
	entered := make(chan struct{}, 1)
	pool := &sqliteRolesPool{actual: port.owner.pool, connEntered: entered}
	port.owner.pool = pool
	ctx, cancel := context.WithCancel(deadline)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tx, err := port.owner.beginRead(ctx)
		if tx != nil {
			_ = tx.Rollback()
		}
		done <- err
	}()
	sqliteLifecycleAwait(t, deadline, entered)
	sqliteRolesAssert(t, port.InspectLifecycle(), 3, 2, 2, 0)
	cancel()
	if err := sqliteLifecycleCloseResult(t, deadline, done); !errors.Is(err, context.Canceled) {
		t.Fatal("waiting Read did not retain cancellation")
	}
	sqliteRolesAssert(t, port.InspectLifecycle(), 2, 2, 2, 0)
	if port.owner.uncertain.Load() {
		t.Fatal("known cancellation became unknown ownership")
	}
	for _, tx := range []*sqliteReadTx{first, second} {
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	sqliteRolesAssert(t, port.InspectLifecycle(), 0, 0, 0, 0)
}

func TestSQLiteRolesUnresolvedConnectionRetainsOwnerAndEvidence(t *testing.T) {
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
	if err := tx.Tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := tx.conn.Close(); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()
	records := sqliteRolesRecords(owner)
	record, found := records[tx.operation]
	if !found || record.active || !record.unresolved || record.conn != tx.conn || record.tx != tx.Tx {
		t.Fatal("unknown connection release lost its retained owner association")
	}
	diagnostic := port.InspectLifecycle()
	if diagnostic.State != LifecycleUncertain {
		t.Fatal("unknown connection release was promoted")
	}
	sqliteInspectionFact(t, diagnostic.Roles.Read.Admission, false)
	sqliteInspectionCount(t, diagnostic.Roles.Read.Operations, 0)
	sqliteInspectionCount(t, diagnostic.Roles.Read.Connections, 1)
	sqliteInspectionCount(t, diagnostic.Roles.Read.UnresolvedConnections, 1)
	for i := 0; i < 10; i++ {
		if !reflect.DeepEqual(diagnostic, port.InspectLifecycle()) {
			t.Fatal("Inspection changed unresolved evidence")
		}
	}
	if !reflect.DeepEqual(records, sqliteRolesRecords(owner)) {
		t.Fatal("Inspection erased an unknown connection obligation")
	}
	if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("unknown release relinquished owner resources")
	}
	if _, err := header.Stat(); err != nil {
		t.Fatal("unknown release closed the header")
	}
	if operation, err := owner.acquireRole(context.Background(), registryReadRole, registryReadOperation); operation != nil || err == nil {
		t.Fatal("uncertain owner admitted new Read")
	}
	if !owner.uncertain.Load() {
		t.Fatal("Close cleared uncertainty")
	}
}

func TestSQLiteRolesInspectionIsObservational(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	tx, err := port.owner.beginRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	before := sqliteInspectionStamp(port.owner)
	records := sqliteRolesRecords(port.owner)
	diagnostic := port.InspectLifecycle()
	sqliteRolesAssert(t, diagnostic, 1, 1, 1, 0)
	for i := 0; i < 32; i++ {
		if !reflect.DeepEqual(diagnostic, port.InspectLifecycle()) {
			t.Fatal("stable role Inspection changed its diagnostic")
		}
	}
	if !reflect.DeepEqual(before, sqliteInspectionStamp(port.owner)) ||
		!reflect.DeepEqual(records, sqliteRolesRecords(port.owner)) {
		t.Fatal("Inspection mutated role ownership or lifecycle state")
	}
	var count int
	if err := tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM resources").Scan(&count); err != nil || count != 1 {
		t.Fatal("Inspection changed the live Read transaction")
	}
}

func TestSQLiteRolesUnregisteredTokenCannotSeizeConnection(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	sqliteLifecycleSyntheticCleanup(t, owner, owner.pool.(*sql.DB), owner.header)
	tx, err := owner.beginRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	fake := &registryOperation{owner: owner, role: registryReadRole, kind: registryReadTransaction}
	before := sqliteRolesRecords(owner)
	if err := owner.attachReadConnection(fake, tx.conn); err == nil {
		t.Fatal("unregistered token seized an existing connection")
	}
	after := sqliteRolesRecords(owner)
	if len(after) != len(before) {
		t.Fatal("unregistered token created an ownership record")
	}
	if _, exists := after[fake]; exists || after[tx.operation].conn != tx.conn || after[tx.operation].tx != tx.Tx {
		t.Fatal("invalid ownership attempt reassigned the real transaction")
	}
	var count int
	if err := tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM resources").Scan(&count); err != nil || count != 1 {
		t.Fatal("rejected ownership attempt closed the real Read connection")
	}
}

type sqliteRolesConnectionBarrierPool struct {
	registryConnectionPool
	barrier func()
}

func (pool *sqliteRolesConnectionBarrierPool) Conn(ctx context.Context) (*sql.Conn, error) {
	connection, err := pool.registryConnectionPool.Conn(ctx)
	if err == nil {
		pool.barrier()
	}
	return connection, err
}

func TestSQLiteRolesWaitingConnectionRechecksUncertainty(t *testing.T) {
	fixture := sqliteTestNew(t, Positive)
	port := sqliteTestOpen(t, fixture)
	owner := port.owner
	pool := owner.pool.(*sql.DB)
	sqliteLifecycleSyntheticCleanup(t, owner, pool, owner.header)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	arrived := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	resume := func() { once.Do(func() { close(proceed) }) }
	defer resume()
	barrier := func() {
		close(arrived)
		<-proceed
	}
	owner.pool = &sqliteRolesConnectionBarrierPool{registryConnectionPool: pool, barrier: barrier}
	var returnedTransaction atomic.Bool
	done := make(chan error, 1)
	go func() {
		tx, err := owner.beginRead(ctx)
		if tx != nil {
			returnedTransaction.Store(true)
			_ = tx.Rollback()
		}
		done <- err
	}()
	sqliteLifecycleAwait(t, ctx, arrived)
	sqliteRolesAssert(t, port.InspectLifecycle(), 1, 0, 0, 0)
	owner.markUncertain()
	resume()
	if err := sqliteLifecycleCloseResult(t, ctx, done); !IsCode(err, CodeUnavailable) {
		t.Fatal("already-waiting Read ignored owner uncertainty")
	}
	if returnedTransaction.Load() || len(sqliteRolesRecords(owner)) != 0 || pool.Stats().InUse != 0 {
		t.Fatal("uncertain waiter returned a transaction or retained a known connection")
	}
	diagnostic := port.InspectLifecycle()
	if diagnostic.State != LifecycleUncertain || !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("waiter cleanup promoted uncertainty or dropped the inode lease")
	}
	sqliteRolesAssert(t, diagnostic, 0, 0, 0, 0)
	sqliteInspectionFact(t, diagnostic.Roles.Read.Admission, false)
	if err := port.Close(); err == nil || !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("uncertain waiter allowed final resource release")
	}
}
