package xcore

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/egress"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/meter"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

const chunk = 65536

var errDatagramQuota = errors.New("insufficient datagram quota")

// meteredOutbound is the default outbound of every instance. It admits the
// connection against the controller, enforces the private-destination policy
// and wraps both directions before handing the link to Xray's freedom dialer.
type meteredOutbound struct {
	direct       outbound.Handler
	tracker      *meter.Tracker
	allowPrivate bool
}

func (h *meteredOutbound) Tag() string                          { return "metered-egress" }
func (h *meteredOutbound) Start() error                         { return h.direct.Start() }
func (h *meteredOutbound) Close() error                         { return h.direct.Close() }
func (h *meteredOutbound) SenderSettings() *serial.TypedMessage { return h.direct.SenderSettings() }
func (h *meteredOutbound) ProxySettings() *serial.TypedMessage  { return h.direct.ProxySettings() }

func abort(link *transport.Link) {
	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
}

type closer func()

func (c closer) Close() error { c(); return nil }

// address applies the egress policy and returns the resolved IP destination.
func address(ctx context.Context, a xnet.Address, allowPrivate bool) (xnet.Address, error) {
	host := a.String()
	if a.Family().IsDomain() {
		host = a.Domain()
	}
	ip, e := egress.Resolve(ctx, host, allowPrivate)
	if e != nil {
		return nil, e
	}
	return xnet.IPAddress(ip.AsSlice()), nil
}

func (h *meteredOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	in := session.InboundFromContext(ctx)
	outbounds := session.OutboundsFromContext(ctx)
	if h.tracker == nil || in == nil || in.User == nil || in.User.Email == "" || len(outbounds) == 0 {
		abort(link)
		return
	}
	// Kernel splice would move bytes past the metered link; force buffered copy.
	in.CanSpliceCopy = 3
	ob := outbounds[len(outbounds)-1]
	target := ob.Target
	if !target.IsValid() {
		abort(link)
		return
	}
	resolved, e := address(ctx, target.Address, h.allowPrivate)
	if e != nil {
		abort(link)
		return
	}
	target.Address = resolved
	ob.Target = target
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// A piped link belongs to one stream (VMess, Trojan, mux sub-streams) and is
	// interruptible; a direct VLESS link owns its connection, which must close.
	_, piped := link.Reader.(*pipe.Reader)
	stop := closer(func() {
		cancel()
		abort(link)
		if !piped && in.Conn != nil {
			in.Conn.Close()
		}
	})
	flow, e := h.tracker.Admit(ctx, stop, in.Tag, in.User.Email)
	if e != nil {
		abort(link)
		return
	}
	defer flow.Close()
	udp := target.Network == xnet.Network_UDP
	reader := &meteredReader{reader: link.Reader, flow: flow, tracker: h.tracker, udp: udp, ctx: ctx, allowPrivate: h.allowPrivate, resolved: map[string]xnet.Address{}}
	writer := &meteredWriter{writer: link.Writer, flow: flow, tracker: h.tracker, udp: udp}
	if !piped && in.Conn != nil {
		writer.deadline = in.Conn.SetWriteDeadline
	}
	h.direct.Dispatch(ctx, &transport.Link{Reader: reader, Writer: writer})
}

// meteredReader carries client-to-destination bytes. Each chunk is granted
// before it is released to the dialer and settled as upload immediately.
type meteredReader struct {
	reader       buf.Reader
	flow         *meter.Flow
	tracker      *meter.Tracker
	udp          bool
	ctx          context.Context
	allowPrivate bool
	pending      buf.MultiBuffer
	pendingErr   error
	resolved     map[string]xnet.Address
}

func (r *meteredReader) fail(e error) (buf.MultiBuffer, error) {
	r.pending = buf.ReleaseMulti(r.pending)
	r.flow.Close()
	return nil, e
}

// permitted reports whether a datagram's own destination passes the policy.
func (r *meteredReader) permitted(b *buf.Buffer) bool {
	if b.UDP == nil {
		return true
	}
	if b.UDP.Address.Family().IsDomain() {
		name := b.UDP.Address.Domain()
		a, ok := r.resolved[name]
		if !ok {
			var e error
			if a, e = address(r.ctx, b.UDP.Address, r.allowPrivate); e != nil {
				return false
			}
			if len(r.resolved) < 256 {
				r.resolved[name] = a
			}
		}
		b.UDP.Address = a
		return true
	}
	ip, ok := netip.AddrFromSlice(b.UDP.Address.IP())
	return ok && (r.allowPrivate || egress.Public(ip))
}

func (r *meteredReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if !r.tracker.Enter() {
		r.pending = buf.ReleaseMulti(r.pending)
		return nil, io.ErrClosedPipe
	}
	defer r.tracker.Leave()
	for {
		mb := r.pending
		r.pending = nil
		if mb.IsEmpty() {
			if r.pendingErr != nil {
				e := r.pendingErr
				r.pendingErr = nil
				return nil, e
			}
			var e error
			mb, e = r.reader.ReadMultiBuffer()
			if mb.IsEmpty() {
				if e == nil {
					continue
				}
				return nil, e
			}
			// Deliver what was read first; report the error on the next call.
			r.pendingErr = e
		}
		if r.udp {
			var b *buf.Buffer
			mb, b = buf.SplitFirst(mb)
			r.pending = mb
			if b == nil || b.IsEmpty() || !r.permitted(b) {
				if b != nil {
					b.Release()
				}
				continue
			}
			n := int(b.Len())
			if n > chunk {
				b.Release()
				continue
			}
			g, e := r.flow.Permit(n)
			if e != nil {
				b.Release()
				return r.fail(e)
			}
			if g.Bytes < int64(n) {
				r.flow.Settle(g, 0, 0)
				b.Release()
				return r.fail(errDatagramQuota)
			}
			if e = r.flow.Settle(g, int64(n), 0); e != nil {
				b.Release()
				return r.fail(e)
			}
			return buf.MultiBuffer{b}, nil
		}
		rest, head := buf.SplitSize(mb, chunk)
		n := head.Len()
		g, e := r.flow.Permit(int(n))
		if e != nil {
			buf.ReleaseMulti(head)
			r.pending = rest
			return r.fail(e)
		}
		if g.Bytes < int64(n) {
			// Keep ungranted bytes, in order, for a later grant.
			var tail buf.MultiBuffer
			tail, head = buf.SplitSize(head, int32(g.Bytes))
			rest = append(tail, rest...)
		}
		r.pending = rest
		if e = r.flow.Settle(g, int64(head.Len()), 0); e != nil {
			buf.ReleaseMulti(head)
			return r.fail(e)
		}
		return head, nil
	}
}

func (r *meteredReader) Interrupt() { common.Interrupt(r.reader) }
func (r *meteredReader) Close() error {
	r.pending = buf.ReleaseMulti(r.pending)
	return common.Close(r.reader)
}

// meteredWriter carries destination-to-client bytes, granted before writing
// and settled with the size actually accepted by the client side.
type meteredWriter struct {
	writer   buf.Writer
	flow     *meter.Flow
	tracker  *meter.Tracker
	udp      bool
	deadline func(time.Time) error
}

func (w *meteredWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if !w.tracker.Enter() {
		buf.ReleaseMulti(mb)
		return io.ErrClosedPipe
	}
	defer w.tracker.Leave()
	for !mb.IsEmpty() {
		var head buf.MultiBuffer
		if w.udp {
			var b *buf.Buffer
			mb, b = buf.SplitFirst(mb)
			if b == nil || b.IsEmpty() || b.Len() > chunk {
				if b != nil {
					b.Release()
				}
				continue
			}
			head = buf.MultiBuffer{b}
		} else {
			mb, head = buf.SplitSize(mb, chunk)
		}
		n := head.Len()
		g, e := w.flow.Permit(int(n))
		if e != nil {
			buf.ReleaseMulti(head)
			buf.ReleaseMulti(mb)
			w.flow.Close()
			return e
		}
		if g.Bytes < int64(n) {
			if w.udp {
				w.flow.Settle(g, 0, 0)
				buf.ReleaseMulti(head)
				buf.ReleaseMulti(mb)
				w.flow.Close()
				return errDatagramQuota
			}
			var tail buf.MultiBuffer
			tail, head = buf.SplitSize(head, int32(g.Bytes))
			mb = append(tail, mb...)
		}
		size := int64(head.Len())
		if w.deadline != nil {
			// A grant expires; a write blocked past it must not complete later.
			w.deadline(g.ExpiresAt.Add(-200 * time.Millisecond))
		}
		if e = w.writer.WriteMultiBuffer(head); e != nil {
			w.flow.Settle(g, 0, 0)
			buf.ReleaseMulti(mb)
			return e
		}
		if e = w.flow.Settle(g, 0, size); e != nil {
			buf.ReleaseMulti(mb)
			return e
		}
	}
	return nil
}

func (w *meteredWriter) Interrupt()   { common.Interrupt(w.writer) }
func (w *meteredWriter) Close() error { return common.Close(w.writer) }
