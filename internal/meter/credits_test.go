package meter

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/control"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
)

type creditController struct {
	delay  time.Duration
	expiry time.Duration
	grants atomic.Int64
	mu     sync.Mutex
	leases []wire.Lease
	budget int64
}

func (c *creditController) Lease(_ context.Context, l wire.Lease) (wire.LeaseResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leases = append(c.leases, l)
	return wire.LeaseResult{ID: l.ID, ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (c *creditController) Grant(ctx context.Context, r wire.GrantRequest) (wire.Grant, error) {
	c.grants.Add(1)
	timer := time.NewTimer(c.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return wire.Grant{}, ctx.Err()
	case <-timer.C:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := r.Bytes
	if c.budget >= 0 {
		n = min(n, c.budget)
		c.budget -= n
	}
	if n == 0 {
		return wire.Grant{}, control.Error{Status: 403}
	}
	expiry := c.expiry
	if expiry == 0 {
		expiry = 2 * time.Second
	}
	return wire.Grant{ID: r.ID, Bytes: n, ExpiresAt: time.Now().Add(expiry)}, nil
}

type noOpCloser struct{}

func (noOpCloser) Close() error { return nil }

func creditTracker(t *testing.T, c *creditController) (*Tracker, *journal.Store) {
	t.Helper()
	s, err := journal.Open(t.TempDir(), strings.Repeat("c", 256))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	tracker := New(context.Background(), c, s)
	t.Cleanup(tracker.Stop)
	tracker.Update(wire.Snapshot{ValidUntil: time.Now().Add(time.Minute), Inbounds: []wire.Inbound{{ID: 1, Users: []wire.User{{ID: 1, Epoch: 1, SpeedMbps: 100, ExpiresAt: time.Now().Add(time.Hour)}}}, {ID: 2, Users: []wire.User{{ID: 1, Epoch: 1, SpeedMbps: 100, ExpiresAt: time.Now().Add(time.Hour)}}}}})
	return tracker, s
}

func TestCreditsHideControllerLatencyAcrossSmallWrites(t *testing.T) {
	c := &creditController{delay: 80 * time.Millisecond, budget: -1}
	tracker, store := creditTracker(t, c)
	f, err := tracker.Admit(context.Background(), noOpCloser{}, "inbound-1", "1", netip.MustParseAddr("198.51.100.1"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for i := 0; i < 64; i++ {
		g, err := f.Permit(4096)
		if err != nil {
			t.Fatal(err)
		}
		if g.Bytes != 4096 {
			t.Fatal("unexpected partial credit", g)
		}
		if err = f.Settle(g, 0, 4096); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	tracker.Stop()
	if c.grants.Load() > 4 {
		t.Fatalf("%d remote calls for 64 small writes", c.grants.Load())
	}
	if elapsed > 2*time.Second {
		t.Fatalf("per-write controller latency remains: %s", elapsed)
	}
	up, down := store.Totals()
	if up != 0 || down != 262144 {
		t.Fatalf("wrong actual usage: %d/%d", up, down)
	}
	entries, err := store.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.State == "inflight" {
			t.Fatal("open credit survived shutdown")
		}
	}
	t.Logf("64 writes, %d grants, %s", c.grants.Load(), elapsed)
}

func TestCreditPartialQuotaAndDuplicateSettlement(t *testing.T) {
	c := &creditController{budget: 5000}
	tracker, store := creditTracker(t, c)
	f, err := tracker.Admit(context.Background(), noOpCloser{}, "inbound-1", "1")
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.Permit(4096)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Settle(g, 0, 4096); err != nil {
		t.Fatal(err)
	}
	if err = f.Settle(g, 0, 4096); err == nil {
		t.Fatal("duplicate ticket charged twice")
	}
	g, err = f.Permit(4096)
	if err != nil || g.Bytes != 904 {
		t.Fatal("quota overshot", g, err)
	}
	if err = f.Settle(g, 0, 904); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Permit(1); err == nil {
		t.Fatal("quota exhausted but transfer admitted")
	}
	tracker.Stop()
	_, down := store.Totals()
	if down != 5000 {
		t.Fatal("actual bytes mismatch", down)
	}
}

func TestCreditExpiryAndSnapshotRevocation(t *testing.T) {
	c := &creditController{budget: -1, expiry: 350 * time.Millisecond}
	tracker, store := creditTracker(t, c)
	f, err := tracker.Admit(context.Background(), noOpCloser{}, "inbound-1", "1")
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.Permit(100)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Settle(g, 100, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	before := c.grants.Load()
	g, err = f.Permit(100)
	if err != nil {
		t.Fatal(err)
	}
	if c.grants.Load() <= before {
		t.Fatal("expired credit reused")
	}
	if err = f.Settle(g, 0, 100); err != nil {
		t.Fatal(err)
	}
	tracker.Update(wire.Snapshot{})
	if _, err = f.Permit(1); err == nil {
		t.Fatal("cached credits bypassed revoked snapshot")
	}
	tracker.Stop()
	up, down := store.Totals()
	if up != 100 || down != 100 {
		t.Fatal("unused credit was charged", up, down)
	}
}

func TestConnectionMetricsCountUniqueSourceIPAcrossInbounds(t *testing.T) {
	c := &creditController{budget: -1}
	tracker, _ := creditTracker(t, c)
	for _, item := range []struct{ ip, inbound string }{{"192.0.2.1", "inbound-1"}, {"::ffff:192.0.2.1", "inbound-2"}, {"2001:db8::1", "inbound-1"}} {
		_, err := tracker.Admit(context.Background(), noOpCloser{}, item.inbound, "1", netip.MustParseAddr(item.ip))
		if err != nil {
			t.Fatal(err)
		}
	}
	counts := tracker.Connections()
	if len(counts) != 1 || counts[0].Count != 2 {
		t.Fatal("streams counted instead of source IPs", counts)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.leases[1].SourceIP != "192.0.2.1" {
		t.Fatal("IPv4 mapped address not normalized")
	}
}
