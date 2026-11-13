package engine

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"net"
	"net/netip"
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
func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}
func resolveDestination(ctx context.Context, d M.Socksaddr, allowPrivate bool) (M.Socksaddr, error) {
	if d.IsIP() {
		if !allowPrivate && !publicAddress(d.Addr) {
			return d, errors.New("private destination denied")
		}
		return d, nil
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", d.Fqdn)
	if e != nil || len(ips) == 0 {
		return d, errors.New("destination resolution failed")
	}
	for _, ip := range ips {
		if !allowPrivate && !publicAddress(ip) {
			return d, errors.New("private DNS result denied")
		}
	}
	d.Addr = ips[0].Unmap()
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
