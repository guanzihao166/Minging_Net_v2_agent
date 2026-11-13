package meter

import (
	"context"
	"errors"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/control"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Controller interface {
	Lease(context.Context, wire.Lease) (wire.LeaseResult, error)
	Grant(context.Context, wire.GrantRequest) (wire.Grant, error)
}
type Tracker struct {
	mu       sync.RWMutex
	ctx      context.Context
	client   Controller
	store    *journal.Store
	snapshot wire.Snapshot
	flows    map[string]*flow
	failed   atomic.Bool
	stopping atomic.Bool
	workMu   sync.Mutex
	work     sync.WaitGroup
}
type flow struct {
	tracker *Tracker
	ctx     context.Context
	cancel  context.CancelFunc
	lease   wire.Lease
	until   atomic.Int64
	closer  io.Closer
	once    sync.Once
}

func New(ctx context.Context, c Controller, s *journal.Store) *Tracker {
	return &Tracker{ctx: ctx, client: c, store: s, flows: map[string]*flow{}}
}
func (t *Tracker) begin() bool {
	t.workMu.Lock()
	defer t.workMu.Unlock()
	if t.stopping.Load() {
		return false
	}
	t.work.Add(1)
	return true
}

// Stop rejects new work, interrupts blocked sockets and waits for durable settlements.
func (t *Tracker) Stop() {
	t.workMu.Lock()
	t.stopping.Store(true)
	t.workMu.Unlock()
	t.CloseInbound(0)
	t.work.Wait()
}
func (t *Tracker) Update(s wire.Snapshot) { t.mu.Lock(); t.snapshot = s; t.mu.Unlock() }
func (t *Tracker) active(iid, uid, epoch int64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.stopping.Load() || t.failed.Load() || !t.snapshot.ValidUntil.After(time.Now()) {
		return false
	}
	for _, i := range t.snapshot.Inbounds {
		if i.ID == iid {
			for _, u := range i.Users {
				if u.ID == uid && u.Epoch == epoch && u.ExpiresAt.After(time.Now()) {
					return true
				}
			}
		}
	}
	return false
}
func (t *Tracker) lookup(m adapter.InboundContext) (int64, wire.User, bool) {
	iid, e := strconv.ParseInt(strings.TrimPrefix(m.Inbound, "inbound-"), 10, 64)
	if e != nil {
		return 0, wire.User{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.stopping.Load() || t.failed.Load() || !t.snapshot.ValidUntil.After(time.Now()) {
		return 0, wire.User{}, false
	}
	for _, i := range t.snapshot.Inbounds {
		if i.ID != iid {
			continue
		}
		for _, u := range i.Users {
			match := m.User == strconv.FormatInt(u.ID, 10)
			if i.Protocol == "wireguard" {
				match = m.Source.Addr.String() == u.Credential.Address
			}
			if match && u.ExpiresAt.After(time.Now()) {
				return iid, u, true
			}
		}
	}
	return 0, wire.User{}, false
}
func (t *Tracker) admit(ctx context.Context, c io.Closer, m adapter.InboundContext) (*flow, error) {
	if !t.begin() {
		return nil, net.ErrClosed
	}
	defer t.work.Done()
	iid, u, ok := t.lookup(m)
	if !ok {
		return nil, errors.New("inactive user")
	}
	id, e := control.RandomID()
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(ctx)
	lease := wire.Lease{ID: id, UserID: u.ID, InboundID: iid, Epoch: u.Epoch}
	reply, e := t.client.Lease(ctx, lease)
	if e != nil {
		cancel()
		return nil, e
	}
	f := &flow{tracker: t, ctx: ctx, cancel: cancel, lease: lease, closer: c}
	f.until.Store(reply.ExpiresAt.Add(-time.Second).UnixNano())
	if !t.active(iid, u.ID, u.Epoch) {
		f.close()
		return nil, errors.New("configuration changed")
	}
	t.mu.Lock()
	if t.stopping.Load() {
		t.mu.Unlock()
		f.close()
		return nil, net.ErrClosed
	}
	t.flows[id] = f
	t.mu.Unlock()
	go f.keepAlive()
	return f, nil
}
func (f *flow) keepAlive() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-f.ctx.Done():
			f.close()
			return
		case <-tick.C:
			if !f.tracker.active(f.lease.InboundID, f.lease.UserID, f.lease.Epoch) || time.Now().UnixNano() >= f.until.Load() {
				f.close()
				return
			}
			ctx, cancel := context.WithTimeout(f.ctx, 4*time.Second)
			res, e := f.tracker.client.Lease(ctx, f.lease)
			cancel()
			if e == nil {
				f.until.Store(res.ExpiresAt.Add(-time.Second).UnixNano())
			} else {
				f.close()
				return
			}
		}
	}
}
func (f *flow) close() {
	f.once.Do(func() {
		f.cancel()
		f.closer.Close()
		t := f.tracker
		t.mu.Lock()
		delete(t.flows, f.lease.ID)
		t.mu.Unlock()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			l := f.lease
			l.Close = true
			t.client.Lease(ctx, l)
		}()
	})
}
func (t *Tracker) CloseInbound(id int64) {
	t.mu.RLock()
	all := []*flow{}
	for _, f := range t.flows {
		if id == 0 || f.lease.InboundID == id {
			all = append(all, f)
		}
	}
	t.mu.RUnlock()
	for _, f := range all {
		f.close()
	}
}
func (t *Tracker) Connections() []wire.UserConnections {
	t.mu.RLock()
	defer t.mu.RUnlock()
	counts := map[int64]int{}
	for _, f := range t.flows {
		counts[f.lease.UserID]++
	}
	out := []wire.UserConnections{}
	for id, n := range counts {
		out = append(out, wire.UserConnections{UserID: id, Count: n})
	}
	return out
}
func (t *Tracker) Healthy() bool { return !t.failed.Load() }
func (f *flow) permit(n int) (result wire.Grant, failure error) {
	t := f.tracker
	if n < 1 || n > 65536 || !t.active(f.lease.InboundID, f.lease.UserID, f.lease.Epoch) || time.Now().UnixNano() >= f.until.Load() {
		return wire.Grant{}, errors.New("lease inactive")
	}
	id, e := control.RandomID()
	if e != nil {
		return wire.Grant{}, e
	}
	req := wire.GrantRequest{ID: id, LeaseID: f.lease.ID, UserID: f.lease.UserID, InboundID: f.lease.InboundID, Epoch: f.lease.Epoch, Bytes: int64(n)}
	entry := journal.Entry{Request: req, State: "requested"}
	if e = t.store.Put(entry); e != nil {
		t.failed.Store(true)
		return wire.Grant{}, e
	}
	defer func() {
		if failure != nil {
			if err := t.store.Abandon(id); err != nil {
				t.failed.Store(true)
			}
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	var g wire.Grant
	for {
		g, e = t.client.Grant(f.ctx, req)
		if e == nil {
			break
		}
		var remote control.Error
		if errors.As(e, &remote) {
			if remote.Status == 429 && time.Now().Before(deadline) {
				timer := time.NewTimer(remote.Wait)
				select {
				case <-timer.C:
					continue
				case <-f.ctx.Done():
					timer.Stop()
					return g, f.ctx.Err()
				}
			}
			if remote.Status == 400 || remote.Status == 401 || remote.Status == 403 {
				t.store.Drop(id)
			}
			return g, e
		}
		if time.Now().After(deadline) || f.ctx.Err() != nil {
			return g, e
		}
		timer := time.NewTimer(150 * time.Millisecond)
		select {
		case <-timer.C:
		case <-f.ctx.Done():
			timer.Stop()
			return g, f.ctx.Err()
		}
	}
	if g.ID != id || g.Bytes < 1 || g.Bytes > int64(n) {
		return g, errors.New("invalid grant response")
	}
	entry.Grant = g
	entry.State = "inflight"
	if e = t.store.Put(entry); e != nil {
		t.failed.Store(true)
		return g, e
	}
	if !g.ExpiresAt.Add(-200 * time.Millisecond).After(time.Now()) {
		t.store.Settle(id, 0, 0)
		return g, errors.New("grant expired in transit")
	}
	return g, nil
}
func (f *flow) settle(g wire.Grant, up, down int64) error {
	e := f.tracker.store.Settle(g.ID, up, down)
	if e != nil {
		f.tracker.failed.Store(true)
		f.close()
	}
	return e
}
func (t *Tracker) RoutedConnection(ctx context.Context, c net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	// Transfer the core's handshake cache before copy/close goroutines start.
	var cached []byte
	if reader, ok := c.(N.CachedReader); ok {
		if b := reader.ReadCached(); b != nil {
			cached = append(cached, b.Bytes()...)
			b.Release()
		}
	}
	f, e := t.admit(ctx, c, m)
	if e != nil {
		c.Close()
		return c
	}
	return &meteredConn{Conn: c, f: f, cached: cached}
}
func (t *Tracker) RoutedPacketConnection(ctx context.Context, c N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	var cached []byte
	var destination M.Socksaddr
	if reader, ok := c.(N.CachedPacketReader); ok {
		if packet := reader.ReadCachedPacket(); packet != nil {
			if packet.Buffer != nil {
				cached = append(cached, packet.Buffer.Bytes()...)
				packet.Buffer.Release()
			}
			destination = packet.Destination
			N.PutPacketBuffer(packet)
		}
	}
	f, e := t.admit(ctx, c, m)
	if e != nil {
		c.Close()
		return c
	}
	return &meteredPacket{PacketConn: c, f: f, cached: cached, destination: destination}
}

// No data may take the accelerated flow path: it has no pre-send grant hook.
type rejectedFlow struct{}

func (rejectedFlow) AttachFlow(h tun.FlowHandle)   { h.CloseFlow() }
func (rejectedFlow) CountForward(int)              {}
func (rejectedFlow) CountReverse(int)              {}
func (rejectedFlow) FlowEstablished()              {}
func (rejectedFlow) CloseFlow(tun.FlowCloseReason) {}
func (t *Tracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return rejectedFlow{}
}

type meteredConn struct {
	net.Conn
	f             *flow
	writeMu       sync.Mutex
	deadlineMu    sync.Mutex
	writeDeadline time.Time
	readMu        sync.Mutex
	cached        []byte
}

func (c *meteredConn) Read(p []byte) (int, error) {
	if !c.f.tracker.begin() {
		return 0, net.ErrClosed
	}
	defer c.f.tracker.work.Done()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) > 65536 {
		p = p[:65536]
	}
	var n int
	var e error
	if len(c.cached) > 0 {
		n = copy(p, c.cached)
		c.cached = c.cached[n:]
	} else {
		n, e = c.Conn.Read(p)
	}
	if n == 0 {
		return n, e
	}
	g, err := c.f.permit(n)
	if err != nil {
		c.f.close()
		return 0, err
	}
	n = min(n, int(g.Bytes))
	if err = c.f.settle(g, int64(n), 0); err != nil {
		return 0, err
	}
	return n, e
}
func (c *meteredConn) Write(p []byte) (int, error) {
	if !c.f.tracker.begin() {
		return 0, net.ErrClosed
	}
	defer c.f.tracker.work.Done()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		g, e := c.f.permit(min(len(p), 65536))
		if e != nil {
			c.f.close()
			return total, e
		}
		deadline := g.ExpiresAt.Add(-200 * time.Millisecond)
		c.deadlineMu.Lock()
		if !c.writeDeadline.IsZero() && c.writeDeadline.Before(deadline) {
			deadline = c.writeDeadline
		}
		c.Conn.SetWriteDeadline(deadline)
		c.deadlineMu.Unlock()
		n, e := c.Conn.Write(p[:int(g.Bytes)])
		if err := c.f.settle(g, 0, int64(n)); err != nil {
			return total + n, err
		}
		total += n
		p = p[n:]
		if e != nil || n == 0 {
			if e == nil {
				e = io.ErrShortWrite
			}
			return total, e
		}
	}
	return total, nil
}
func (c *meteredConn) Close() error { c.f.close(); return nil }
func (c *meteredConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return c.Conn.SetWriteDeadline(t)
}
func (c *meteredConn) SetDeadline(t time.Time) error {
	if e := c.SetWriteDeadline(t); e != nil {
		return e
	}
	return c.Conn.SetReadDeadline(t)
}

type meteredPacket struct {
	N.PacketConn
	f           *flow
	writeMu     sync.Mutex
	readMu      sync.Mutex
	cached      []byte
	destination M.Socksaddr
}

func (c *meteredPacket) FrontHeadroom() int { return N.CalculateFrontHeadroom(c.PacketConn) }
func (c *meteredPacket) RearHeadroom() int  { return N.CalculateRearHeadroom(c.PacketConn) }

func (c *meteredPacket) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	if !c.f.tracker.begin() {
		return M.Socksaddr{}, net.ErrClosed
	}
	defer c.f.tracker.work.Done()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var d M.Socksaddr
	var e error
	if c.cached != nil {
		_, e = b.Write(c.cached)
		d = c.destination
		c.cached = nil
	} else {
		d, e = c.PacketConn.ReadPacket(b)
	}
	if e != nil {
		return d, e
	}
	n := b.Len()
	g, e := c.f.permit(n)
	if e != nil {
		c.f.close()
		return d, e
	}
	if g.Bytes < int64(n) {
		c.f.settle(g, 0, 0)
		return d, errors.New("insufficient datagram quota")
	}
	if e = c.f.settle(g, int64(n), 0); e != nil {
		return d, e
	}
	return d, nil
}
func (c *meteredPacket) WritePacket(b *buf.Buffer, d M.Socksaddr) error {
	if !c.f.tracker.begin() {
		b.Release()
		return net.ErrClosed
	}
	defer c.f.tracker.work.Done()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n := b.Len()
	g, e := c.f.permit(n)
	if e != nil {
		b.Release()
		c.f.close()
		return e
	}
	if g.Bytes < int64(n) {
		b.Release()
		c.f.settle(g, 0, 0)
		return errors.New("insufficient datagram quota")
	}
	c.PacketConn.SetWriteDeadline(g.ExpiresAt.Add(-200 * time.Millisecond))
	e = c.PacketConn.WritePacket(b, d)
	if e != nil {
		c.f.settle(g, 0, 0)
		return e
	}
	return c.f.settle(g, 0, int64(n))
}
func (c *meteredPacket) Close() error { c.f.close(); return nil }
