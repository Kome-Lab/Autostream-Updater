package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These synthetic spies expose every mutating resource method. Inspection is
// permitted to use only Stats and the native probe; no Go File method may
// borrow a connection or open, retain or close a descriptor.
type sqliteInspectionPoolSpy struct {
	actual registryConnectionPool
	onStats func()
	override *sql.DBStats
	connCalls atomic.Int32
	closeCalls atomic.Int32
	statsCalls atomic.Int32
}
func (p *sqliteInspectionPoolSpy) Conn(ctx context.Context) (*sql.Conn, error) {
	p.connCalls.Add(1)
	return p.actual.Conn(ctx)
}
func (p *sqliteInspectionPoolSpy) Close() error {
	p.closeCalls.Add(1)
	return p.actual.Close()
}
func (p *sqliteInspectionPoolSpy) Stats() sql.DBStats {
	p.statsCalls.Add(1)
	if p.onStats != nil { p.onStats() }
	if p.override != nil { return *p.override }
	return p.actual.Stats()
}

type sqliteInspectionHeaderSpy struct {
	actual registryHeaderFD
	onStat func()
	statError error
	statCalls atomic.Int32
	readCalls atomic.Int32
	closeCalls atomic.Int32
}
func (h *sqliteInspectionHeaderSpy) Stat() (os.FileInfo, error) {
	h.statCalls.Add(1)
	if h.onStat != nil { h.onStat() }
	if h.statError != nil { return nil, h.statError }
	return h.actual.Stat()
}
func (h *sqliteInspectionHeaderSpy) ReadAt(data []byte, offset int64) (int, error) {
	h.readCalls.Add(1)
	return h.actual.ReadAt(data, offset)
}
func (h *sqliteInspectionHeaderSpy) Close() error {
	h.closeCalls.Add(1)
	return h.actual.Close()
}

type sqliteInspectionOwnerStamp struct {
	version uint64
	descriptor int
	probe uintptr
	active int64
	ready bool
	drainFinished bool
	closeFinished bool
	poolCloseStarted bool
	poolReleased bool
	headerCloseStarted bool
	headerReleased bool
	leaseReleased bool
	closing bool
	uncertain bool
	closeError bool
	lease *registryInodeLease
	pool registryConnectionPool
	header registryHeaderFD
}
func sqliteInspectionStamp(owner *registryLifecycleOwner) sqliteInspectionOwnerStamp {
	owner.gate.Lock()
	defer owner.gate.Unlock()
	var probe uintptr
	if owner.headerProbe != nil { probe = reflect.ValueOf(owner.headerProbe).Pointer() }
	return sqliteInspectionOwnerStamp{
		descriptor:owner.headerDescriptor,probe:probe,
		version:owner.observationVersion,active:owner.activeOperations,ready:owner.ready,
		drainFinished:owner.drainFinished,closeFinished:owner.closeFinished,
		poolCloseStarted:owner.poolCloseStarted,poolReleased:owner.poolReleased,
		headerCloseStarted:owner.headerCloseStarted,headerReleased:owner.headerReleased,
		leaseReleased:owner.leaseReleased,closing:owner.closing.Load(),
		uncertain:owner.uncertain.Load(),closeError:owner.closeErr != nil,
		lease:owner.lease,pool:owner.pool,header:owner.header,
	}
}
func sqliteInspectionFact(t *testing.T, fact LifecycleFact, value bool) {
	t.Helper()
	if fact.Knowledge != Known || fact.Value != value {
		t.Fatalf("unexpected diagnostic fact: %#v, want known %t",fact,value)
	}
}
func sqliteInspectionCount(t *testing.T, count LifecycleCount, value int64) {
	t.Helper()
	if count.Knowledge != Known || count.Value != value {
		t.Fatalf("unexpected diagnostic count: %#v, want %d",count,value)
	}
}
func sqliteInspectionClosed(t *testing.T, d RegistryLifecycleDiagnostic) {
	t.Helper()
	if d.State != LifecycleClosed || d.Consistency != Known || d.Drain != LifecycleDrainComplete ||
		d.Close.Result != LifecycleCloseSucceeded || d.Pool.Knowledge != Known ||
		d.Pool.OpenConnections != 0 || d.Pool.InUse != 0 || d.Pool.Idle != 0 {
		t.Fatalf("closed lifecycle not established: %#v",d)
	}
	sqliteInspectionCount(t,d.ActiveOperations,0)
	sqliteInspectionFact(t,d.AcceptingOperations,false)
	sqliteInspectionFact(t,d.Header.ReferenceHeld,true)
	sqliteInspectionFact(t,d.Header.Valid,false)
	sqliteInspectionFact(t,d.Header.Closed,true)
	sqliteInspectionFact(t,d.Header.CloseStarted,true)
	sqliteInspectionFact(t,d.Header.Released,true)
	sqliteInspectionFact(t,d.Lease.Held,false)
	sqliteInspectionFact(t,d.Lease.OwnerConsistent,true)
	sqliteInspectionFact(t,d.Lease.Released,true)
	sqliteInspectionFact(t,d.Close.Started,true)
	sqliteInspectionFact(t,d.Close.Finished,true)
	sqliteInspectionFact(t,d.Close.PoolReleased,true)
	sqliteInspectionFact(t,d.Close.HeaderReleased,true)
	sqliteInspectionFact(t,d.Close.LeaseReleased,true)
}

func TestSQLiteInspectionOpenActiveAndClosed(t *testing.T) {
	fixture := sqliteTestNew(t,Positive)
	port := sqliteTestOpen(t,fixture)
	owner := port.owner
	d := port.InspectLifecycle()
	if d.State != LifecycleOpen || d.Consistency != Known || d.Drain != LifecycleDrainIdle ||
		d.Close.Result != LifecycleCloseNotStarted {
		t.Fatalf("new owner was not observed OPEN: %#v",d)
	}
	sqliteInspectionCount(t,d.ActiveOperations,0)
	sqliteInspectionFact(t,d.AcceptingOperations,true)
	sqliteInspectionFact(t,d.Header.ReferenceHeld,true)
	sqliteInspectionFact(t,d.Header.Valid,true)
	sqliteInspectionFact(t,d.Header.Closed,false)
	sqliteInspectionFact(t,d.Header.CloseStarted,false)
	sqliteInspectionFact(t,d.Lease.Held,true)
	sqliteInspectionFact(t,d.Lease.OwnerConsistent,true)
	sqliteInspectionFact(t,d.Close.Started,false)
	sqliteInspectionFact(t,d.Close.Finished,false)
	stats := owner.pool.Stats()
	if d.Pool.Knowledge != Known || d.Pool.OpenConnections != stats.OpenConnections ||
		d.Pool.InUse != stats.InUse || d.Pool.Idle != stats.Idle {
		t.Fatal("diagnostic pool counts differ from the actual pool")
	}
	op,err := owner.acquire(context.Background())
	if err != nil { t.Fatal(err) }
	defer op.release()
	active := port.InspectLifecycle()
	sqliteInspectionCount(t,active.ActiveOperations,1)
	if active.State != LifecycleOpen || active.Drain != LifecycleDrainActive {
		t.Fatal("active operation was not distinguished from idle OPEN")
	}
	sqliteInspectionFact(t,active.AcceptingOperations,true)
	op.release()
	if err := port.Close();err != nil {t.Fatal(err)}
	sqliteInspectionClosed(t,port.InspectLifecycle())
}

func TestSQLiteInspectionClosingAndConnectionDrain(t *testing.T) {
	fixture := sqliteTestNew(t,Positive)
	port := sqliteTestOpen(t,fixture)
	ctx,cancel := context.WithTimeout(context.Background(),10*time.Second)
	defer cancel()
	tx,err := port.owner.beginRead(ctx)
	if err != nil {t.Fatal(err)}
	defer tx.Rollback()
	closing := make(chan error,1)
	go func(){closing<-port.Close()}()
	sqliteLifecycleAwait(t,ctx,port.owner.closingStarted)
	d := port.InspectLifecycle()
	if d.State != LifecycleClosing || d.Drain != LifecycleDrainWaiting ||
		d.Close.Result != LifecycleClosePending || d.Pool.InUse != 1 {
		t.Fatalf("connection drain was not observed: %#v",d)
	}
	sqliteInspectionCount(t,d.ActiveOperations,1)
	sqliteInspectionFact(t,d.AcceptingOperations,false)
	sqliteInspectionFact(t,d.Close.Started,true)
	sqliteInspectionFact(t,d.Close.Finished,false)
	sqliteInspectionFact(t,d.Close.PoolReleased,false)
	sqliteInspectionFact(t,d.Header.Valid,true)
	sqliteInspectionFact(t,d.Lease.Held,true)
	before := sqliteInspectionStamp(port.owner)
	for i:=0;i<20;i++ {if !reflect.DeepEqual(d,port.InspectLifecycle()){t.Fatal("stable CLOSING observation changed")}}
	if !reflect.DeepEqual(before,sqliteInspectionStamp(port.owner)){t.Fatal("Inspection changed the draining owner")}
	sqliteLifecycleCheckBlocked(t,closing)
	if err:=tx.Rollback();err!=nil{t.Fatal(err)}
	if err:=sqliteLifecycleCloseResult(t,ctx,closing);err!=nil{t.Fatal(err)}
	sqliteInspectionClosed(t,port.InspectLifecycle())
}

func TestSQLiteInspectionRepeatedCallsHaveNoMutatingEffects(t *testing.T) {
	fixture := sqliteTestNew(t,Positive)
	if err:=fixture.writer.Close();err!=nil{t.Fatal(err)}
	beforeFiles := sqliteTestFiles(t,fixture.directory)
	port := sqliteTestOpen(t,fixture)
	owner := port.owner
	actualPool := owner.pool.(*sql.DB)
	pool := &sqliteInspectionPoolSpy{actual:actualPool}
	header := &sqliteInspectionHeaderSpy{actual:owner.header}
	owner.pool,owner.header=pool,header
	actualProbe:=owner.headerProbe
	var nativeCalls atomic.Int32
	owner.headerProbe=func(fd int,identity os.FileInfo)registryHeaderProbeResult{
		nativeCalls.Add(1)
		return actualProbe(fd,identity)
	}
	beforeOwner := sqliteInspectionStamp(owner)
	beforeStats := actualPool.Stats()
	before := port.InspectLifecycle()
	for i:=0;i<100;i++ {
		if !reflect.DeepEqual(before,port.InspectLifecycle()){t.Fatal("repeated stable Inspection changed its result")}
	}
	if pool.connCalls.Load()!=0 || pool.closeCalls.Load()!=0 || header.readCalls.Load()!=0 || header.closeCalls.Load()!=0 {
		t.Fatal("Inspection borrowed a connection, read bytes or closed a resource")
	}
	if pool.statsCalls.Load()!=101 || header.statCalls.Load()!=0 || nativeCalls.Load()!=101 {
		t.Fatal("Inspection retried a resource observation or used File.Stat")
	}
	if !reflect.DeepEqual(beforeOwner,sqliteInspectionStamp(owner)) ||
		!reflect.DeepEqual(beforeStats,actualPool.Stats()) || !sqliteLifecycleLeaseHeld(owner) {
		t.Fatal("Inspection changed lifecycle state, pool metrics or inode ownership")
	}
	if err:=port.Close();err!=nil{t.Fatal(err)}
	if !reflect.DeepEqual(beforeFiles,sqliteTestFiles(t,fixture.directory)){t.Fatal("Inspection changed synthetic database bytes or metadata")}
	closed := port.InspectLifecycle()
	for i:=0;i<20;i++{if !reflect.DeepEqual(closed,port.InspectLifecycle()){t.Fatal("closed Inspection changed state")}}
	sqliteInspectionClosed(t,closed)
	if pool.closeCalls.Load()!=1 || header.closeCalls.Load()!=1 || pool.connCalls.Load()!=0 || header.readCalls.Load()!=0 || nativeCalls.Load()!=101 {
		t.Fatal("closed Inspection retried cleanup or obtained another resource")
	}
}

func TestSQLiteInspectionNilAndUnreadyRemainUnknown(t *testing.T) {
	var nilPort *SQLiteReadPort
	for _,port:=range []*SQLiteReadPort{nilPort,{}, {owner:&registryLifecycleOwner{}}} {
		d:=port.InspectLifecycle()
		if d.State!=LifecycleUnknown || d.Consistency!=Unknown ||
			d.ActiveOperations.Knowledge!=Unknown || d.Pool.Knowledge!=Unknown {
			t.Fatal("unavailable lifecycle was guessed OPEN or CLOSED")
		}
	}
}

func TestSQLiteInspectionUnknownResourceEvidenceIsNotPromoted(t *testing.T) {
	for _,failure:=range []string{"header-stat","invalid-stats","lease-link"} {
		t.Run(failure,func(t *testing.T){
			fixture:=sqliteTestNew(t,Positive)
			port:=sqliteTestOpen(t,fixture)
			owner:=port.owner
			switch failure{
			case "header-stat":
				owner.headerProbe = func(int,os.FileInfo) registryHeaderProbeResult {return registryHeaderProbeResult{}}
			case "invalid-stats":
				stats:=sql.DBStats{OpenConnections:-1}
				owner.pool=&sqliteInspectionPoolSpy{actual:owner.pool,override:&stats}
			case "lease-link":
				registryInodeLeases.Lock()
				old:=owner.lease.owner
				owner.lease.owner=nil
				registryInodeLeases.Unlock()
				defer func(){registryInodeLeases.Lock();owner.lease.owner=old;registryInodeLeases.Unlock()}()
			}
			before:=sqliteInspectionStamp(owner)
			d:=port.InspectLifecycle()
			if d.State!=LifecycleUnknown {t.Fatalf("unknown resource evidence became %s",d.State)}
			if failure=="header-stat" && (d.Header.Valid.Knowledge!=Unknown || d.Header.Closed.Knowledge!=Unknown){
				t.Fatal("Stat failure became known descriptor validity")
			}
			if failure=="invalid-stats" && d.Pool.Knowledge!=Unknown{t.Fatal("invalid pool counts were accepted")}
			if failure=="lease-link"{sqliteInspectionFact(t,d.Lease.OwnerConsistent,false)}
			if !reflect.DeepEqual(before,sqliteInspectionStamp(owner)) || owner.uncertain.Load() || owner.closing.Load(){
				t.Fatal("Inspection changed owner state while observing unknown evidence")
			}
		})
	}
}

func TestSQLiteInspectionUncertainCloseNeverRecovers(t *testing.T) {
	for _,failure:=range []string{"pool-error","header-error","pending-connection","release-error"}{
		t.Run(failure,func(t *testing.T){
			fixture:=sqliteTestNew(t,Positive)
			port:=sqliteTestOpen(t,fixture)
			owner:=port.owner
			pool:=owner.pool.(*sql.DB)
			header:=owner.header
			sqliteLifecycleSyntheticCleanup(t,owner,pool,header)
			var conn *sql.Conn
			switch failure{
			case "pool-error": owner.pool=&sqliteLifecycleTestPool{actual:pool,closeError:errors.New("synthetic secret SQL close failure")}
			case "header-error": owner.header=&sqliteLifecycleTestHeader{actual:header,closeError:errors.New("synthetic secret header failure")}
			case "pending-connection":
				var err error
				conn,err=pool.Conn(context.Background())
				if err!=nil{t.Fatal(err)}
				defer conn.Close()
			case "release-error":
				tx,err:=owner.beginRead(context.Background());if err!=nil{t.Fatal(err)}
				if err:=tx.Tx.Rollback();err!=nil{t.Fatal(err)}
				if err:=tx.conn.Close();err!=nil{t.Fatal(err)}
				_ = tx.Rollback()
				d:=port.InspectLifecycle()
				if d.State!=LifecycleUncertain || d.Close.Result!=LifecycleCloseNotStarted{t.Fatal("release uncertainty was not observed before Close")}
				sqliteInspectionFact(t,d.Close.Started,false)
			}
			if err:=port.Close();err==nil{t.Fatal("injected uncertainty became successful Close")}
			d:=port.InspectLifecycle()
			if d.State!=LifecycleUncertain || d.Close.Result!=LifecycleCloseUnknown{t.Fatal("uncertain Close was guessed CLOSED")}
			sqliteInspectionFact(t,d.Close.Started,true)
			sqliteInspectionFact(t,d.Close.Finished,true)
			sqliteInspectionFact(t,d.AcceptingOperations,false)
			sqliteInspectionFact(t,d.Lease.Held,true)
			sqliteInspectionFact(t,d.Close.LeaseReleased,false)
			if failure=="header-error"{sqliteInspectionFact(t,d.Close.PoolReleased,true)}
			if conn!=nil{if err:=conn.Close();err!=nil{t.Fatal(err)}}
			before:=sqliteInspectionStamp(owner)
			for i:=0;i<30;i++{
				next:=port.InspectLifecycle()
				if next.State!=LifecycleUncertain || next.Close.Result!=LifecycleCloseUnknown ||
					!sqliteLifecycleLeaseHeld(owner){t.Fatal("Inspection recovered an uncertain owner or lease")}
				sqliteInspectionFact(t,next.Close.LeaseReleased,false)
			}
			if !reflect.DeepEqual(before,sqliteInspectionStamp(owner)){t.Fatal("Inspection rewrote an uncertain lifecycle")}
		})
	}
}

func TestSQLiteInspectionZeroStatsAreNotReleaseProof(t *testing.T) {
	fixture:=sqliteTestNew(t,Positive)
	port:=sqliteTestOpen(t,fixture)
	owner:=port.owner
	zero:=sql.DBStats{}
	owner.pool=&sqliteInspectionPoolSpy{actual:owner.pool,override:&zero}
	d:=port.InspectLifecycle()
	if d.State==LifecycleClosed || d.Close.Result!=LifecycleCloseNotStarted{t.Fatal("zero Stats were converted to successful Close")}
	sqliteInspectionFact(t,d.Close.PoolReleased,false)
	sqliteInspectionFact(t,d.Close.HeaderReleased,false)
	sqliteInspectionFact(t,d.Close.LeaseReleased,false)
	sqliteInspectionFact(t,d.Lease.Held,true)
}

func TestSQLiteInspectionSafeProjectionDoesNotExposeInternalData(t *testing.T) {
	fixture:=sqliteTestNew(t,Positive)
	port:=sqliteTestOpen(t,fixture)
	owner:=port.owner
	actualPool:=owner.pool.(*sql.DB)
	actualHeader:=owner.header
	sqliteLifecycleSyntheticCleanup(t,owner,actualPool,actualHeader)
	canaries:=[]string{fixture.path,fixture.directory,"file:synthetic-registry?mode=rw","SELECT synthetic_private_row","synthetic-credential-canary","synthetic-token-canary"}
	raw:=errors.New(strings.Join(canaries," | "))
	// A raw internal failure is deliberately private; the public projection
	// reports fixed state/outcome vocabulary only, never Error() or file identity.
	owner.gate.Lock()
	owner.closeErr=raw
	owner.observationVersion++
	owner.gate.Unlock()
	owner.markUncertain()
	snapshot:=owner.snapshotLifecycle()
	internal,err:=json.Marshal(snapshot)
	if err!=nil || string(internal)!="{}"{t.Fatal("internal snapshot is directly serializable as public diagnostics")}
	d:=port.InspectLifecycle()
	wire,err:=json.Marshal(d);if err!=nil{t.Fatal(err)}
	printed:=fmt.Sprintf("%+v",d)
	for _,secret:=range canaries{
		if strings.Contains(string(wire),secret)||strings.Contains(printed,secret){t.Fatal("safe diagnostics exposed private observation data")}
	}
	var visit func(reflect.Type)
	visit=func(typ reflect.Type){
		if typ.Kind()==reflect.Pointer||typ.Kind()==reflect.Interface{t.Fatal("safe diagnostic shape exposes a handle or raw error")}
		if typ.Kind()!=reflect.Struct{return}
		for i:=0;i<typ.NumField();i++{
			field:=typ.Field(i)
			if !field.IsExported(){continue}
			name:=strings.ToLower(field.Name)
			for _,word:=range []string{"path","dsn","uri","sql","credential","token","secret","filename","descriptor"}{
				if strings.Contains(name,word){t.Fatal("safe projection publishes an internal-location or authority field")}
			}
			visit(field.Type)
		}
	}
	visit(reflect.TypeOf(d))
}

func TestSQLiteInspectionSlowProbesDoNotHoldOwnerGate(t *testing.T) {
	for _,probe:=range []string{"stats","native-header"}{
		t.Run(probe,func(t *testing.T){
			fixture:=sqliteTestNew(t,Positive)
			port:=sqliteTestOpen(t,fixture)
			owner:=port.owner
			ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
			defer cancel()
			entered,release:=make(chan struct{}),make(chan struct{})
			var releaseOnce sync.Once
			unblock:=func(){releaseOnce.Do(func(){close(release)})}
			defer unblock()
			var hit atomic.Bool
			pause:=func(){if hit.CompareAndSwap(false,true){close(entered);select{case<-release:case<-ctx.Done():}}}
			pool:=&sqliteInspectionPoolSpy{actual:owner.pool}
			header:=&sqliteInspectionHeaderSpy{actual:owner.header}
			var nativeCalls atomic.Int32
			actualProbe:=owner.headerProbe
			owner.headerProbe=func(fd int, identity os.FileInfo) registryHeaderProbeResult {
				nativeCalls.Add(1)
				if probe=="native-header"{pause()}
				return actualProbe(fd,identity)
			}
			if probe=="stats"{pool.onStats=pause}
			owner.pool,owner.header=pool,header
			result:=make(chan RegistryLifecycleDiagnostic,1)
			go func(){result<-port.InspectLifecycle()}()
			sqliteLifecycleAwait(t,ctx,entered)
			// Net-zero count changes still invalidate a captured frame version.
			admitted:=make(chan error,1)
			go func(){op,err:=owner.acquire(ctx);if err==nil{op.release()};admitted<-err}()
			if err:=sqliteLifecycleCloseResult(t,ctx,admitted);err!=nil{t.Fatal("probe held owner gate and blocked ordinary admission")}
			closing:=make(chan error,1)
			go func(){closing<-port.Close()}()
			sqliteLifecycleAwait(t,ctx,owner.closingStarted)
			// Observers are not operations or FD leases: Close must finish even
			// while a Stats/native fstat probe is stalled outside the owner gate.
			if err:=sqliteLifecycleCloseResult(t,ctx,closing);err!=nil{t.Fatal("slow inspection blocked Close/drain")}
			if sqliteLifecycleLeaseHeld(owner){t.Fatal("observer was treated as a lifecycle lease")}
			unblock()
			var d RegistryLifecycleDiagnostic
			select{case d=<-result:case<-ctx.Done():t.Fatal("slow inspection did not finish")}
			if d.State!=LifecycleUnknown || d.Consistency!=Unknown{t.Fatal("torn owner frame was promoted instead of UNKNOWN")}
			if pool.statsCalls.Load()!=2 || nativeCalls.Load()!=1 || header.statCalls.Load()!=0 || header.readCalls.Load()!=0 {
				t.Fatal("inspection retried or used a File method instead of one native probe")
			}
			sqliteInspectionClosed(t,port.InspectLifecycle())
		})
	}
}

func TestSQLiteInspectionLateNativeProbeCannotStripNewOwnerLocks(t *testing.T) {
	fixture:=sqliteTestNew(t,Positive)
	projection:=readTestRecord(fixture.request,*fixture.snapshot.Backend.Receipt,ExecutorLedger)
	sqliteTestProjection(t,fixture,ExecutorLedger,projection)
	old:=sqliteTestOpen(t,fixture)
	ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
	defer cancel()
	entered,release:=make(chan struct{}),make(chan struct{})
	var once sync.Once
	unblock:=func(){once.Do(func(){close(release)})}
	defer unblock()
	actualProbe:=old.owner.headerProbe
	old.owner.headerProbe=func(fd int,identity os.FileInfo)registryHeaderProbeResult{
		close(entered)
		select{case<-release:case<-ctx.Done():return registryHeaderProbeResult{}}
		return actualProbe(fd,identity)
	}
	finished:=make(chan RegistryLifecycleDiagnostic,1)
	go func(){finished<-old.InspectLifecycle()}()
	sqliteLifecycleAwait(t,ctx,entered)
	closed:=make(chan error,1)
	go func(){closed<-old.Close()}()
	if err:=sqliteLifecycleCloseResult(t,ctx,closed);err!=nil{t.Fatal("old probe blocked owner handoff")}
	next,err:=OpenSQLiteReadPort(ctx,SQLiteReadConfig{Directory:fixture.directory,DatabaseName:RegistryDatabaseName,Continuity:fixture.continuity})
	if err!=nil{t.Fatal("known old Close did not permit a new owner")}
	defer next.Close()
	tx,err:=next.owner.beginRead(ctx);if err!=nil{t.Fatal(err)}
	defer tx.Rollback()
	child:=sqliteTestStartWriter(t,ctx,fixture.path,"pin")
	child.next(t,"ready")
	child.send(t,"begin");child.next(t,"staged")
	child.send(t,"try_commit");child.next(t,"busy")
	// The old raw descriptor number can now have been reused. A pure fstat has
	// no Go File ref/decref and cannot close it or strip the new owner's locks.
	unblock()
	select{
	case d:=<-finished:
		if d.State!=LifecycleUnknown || d.Consistency!=Unknown{t.Fatal("old frame was certified after owner handoff")}
	case<-ctx.Done():t.Fatal("late native probe did not finish")
	}
	child.send(t,"try_commit");child.next(t,"busy")
	if err:=tx.Rollback();err!=nil{t.Fatal(err)}
	child.send(t,"commit");child.next(t,"committed")
	child.stop(t)
}

func TestSQLiteInspectionPreservesKernelReadLocks(t *testing.T) {
	fixture:=sqliteTestNew(t,Positive)
	projection:=readTestRecord(fixture.request,*fixture.snapshot.Backend.Receipt,ExecutorLedger)
	sqliteTestProjection(t,fixture,ExecutorLedger,projection)
	port:=sqliteTestOpen(t,fixture)
	ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
	defer cancel()
	tx,err:=port.owner.beginRead(ctx);if err!=nil{t.Fatal(err)}
	defer tx.Rollback()
	child:=sqliteTestStartWriter(t,ctx,fixture.path,"pin")
	child.next(t,"ready")
	child.send(t,"begin");child.next(t,"staged")
	child.send(t,"try_commit");child.next(t,"busy")
	for i:=0;i<30;i++{
		d:=port.InspectLifecycle()
		if d.State!=LifecycleOpen{t.Fatal("stable inspection lost the owned read state")}
		sqliteInspectionCount(t,d.ActiveOperations,1)
	}
	child.send(t,"try_commit");child.next(t,"busy")
	if err:=tx.Rollback();err!=nil{t.Fatal(err)}
	child.send(t,"commit");child.next(t,"committed")
	child.stop(t)
}

func TestSQLiteInspectionConcurrentReadAndClose(t *testing.T) {
	fixture:=sqliteTestNew(t,Positive)
	port:=sqliteTestOpen(t,fixture)
	owner:=port.owner
	ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
	defer cancel()
	blocker,err:=owner.acquire(ctx);if err!=nil{t.Fatal(err)}
	defer blocker.release()
	start:=make(chan struct{})
	errorsOut:=make(chan error,24)
	var group sync.WaitGroup
	for i:=0;i<12;i++{
		group.Add(1)
		go func(){defer group.Done();<-start;for j:=0;j<40;j++{
			d:=port.InspectLifecycle()
			switch d.State{case LifecycleOpen,LifecycleClosing,LifecycleClosed,LifecycleUncertain,LifecycleUnknown:default:errorsOut<-errors.New("invalid inspection state");return}
			if d.State==LifecycleClosed && (d.Close.Result!=LifecycleCloseSucceeded || d.Lease.Held.Knowledge!=Known || d.Lease.Held.Value){errorsOut<-errors.New("CLOSED lacks release proof");return}
			if d.Consistency==Unknown && d.State!=LifecycleUnknown{errorsOut<-errors.New("inconsistent observation was promoted");return}
		}}()
	}
	for i:=0;i<8;i++{
		group.Add(1)
		go func(){defer group.Done();<-start;for j:=0;j<12;j++{
			_,err:=port.ReadActiveReference(ctx,fixture.request.Command.Scope)
			if err!=nil&&!errors.Is(err,ErrSQLiteClosed){errorsOut<-errors.New("inspection/read race altered read behavior");return}
		}}()
	}
	closing:=make(chan error,1)
	close(start)
	go func(){closing<-port.Close()}()
	sqliteLifecycleAwait(t,ctx,owner.closingStarted)
	group.Wait();close(errorsOut)
	for err:=range errorsOut{if err!=nil{t.Fatal(err)}}
	blocker.release()
	if err:=sqliteLifecycleCloseResult(t,ctx,closing);err!=nil{t.Fatal(err)}
	sqliteInspectionClosed(t,port.InspectLifecycle())
}
