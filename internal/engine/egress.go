package engine

import (
	"context"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/egress"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"net"
)

// Only package-local tests can set this context key. There is no wire/config
// option that removes the production private-address egress restriction.
type egressTestKey struct{}
type meteredDirect struct {
	adapter.Outbound
	life         adapter.Lifecycle
	allowPrivate bool
}

func (d *meteredDirect) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return d.life.Start(stage, scope)
}
func resolveDestination(ctx context.Context, d M.Socksaddr, allowPrivate bool) (M.Socksaddr, error) {
	host := d.Fqdn
	if d.IsIP() {
		host = d.Addr.String()
	}
	ip, e := egress.Resolve(ctx, host, allowPrivate)
	if e != nil {
		return d, e
	}
	d.Addr = ip
	d.Fqdn = ""
	return d, nil
}
func (d *meteredDirect) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	target, e := resolveDestination(ctx, destination, d.allowPrivate)
	if e != nil {
		return nil, e
	}
	return d.Outbound.DialContext(ctx, network, target)
}
func (d *meteredDirect) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	target, e := resolveDestination(ctx, destination, d.allowPrivate)
	if e != nil {
		return nil, e
	}
	c, e := d.Outbound.ListenPacket(ctx, target)
	if e != nil {
		return nil, e
	}
	return &egressPacket{PacketConn: c, ctx: ctx, allowPrivate: d.allowPrivate}, nil
}

type egressPacket struct {
	net.PacketConn
	ctx          context.Context
	allowPrivate bool
}

func (c *egressPacket) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.ParseSocksaddr(addr.String())
	target, e := resolveDestination(c.ctx, destination, c.allowPrivate)
	if e != nil {
		return 0, e
	}
	return c.PacketConn.WriteTo(p, target.UDPAddr())
}
