package engine

import (
	"context"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	bs "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
)

// The ordinary user-space connection path is mandatory: the WireGuard fast
// flow path bypasses stream backpressure and therefore cannot enforce grants.
func coreContext(ctx context.Context) context.Context {
	// VLESS and Trojan are served by the Xray core (package xcore).
	ir := inbound.NewRegistry()
	anytls.RegisterInbound(ir)
	vmess.RegisterInbound(ir)
	shadowsocks.RegisterInbound(ir)
	hysteria2.RegisterInbound(ir)
	tuic.RegisterInbound(ir)
	or := outbound.NewRegistry()
	outbound.Register[option.DirectOutboundOptions](or, "direct", func(ctx context.Context, r adapter.Router, l log.ContextLogger, tag string, o option.DirectOutboundOptions) (adapter.Outbound, error) {
		d, e := direct.NewOutbound(ctx, r, l, tag, o)
		if e != nil {
			return nil, e
		}
		allowPrivate, _ := ctx.Value(egressTestKey{}).(bool)
		return &meteredDirect{Outbound: d, life: d.(adapter.Lifecycle), allowPrivate: allowPrivate}, nil
	})
	er := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(er)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	return box.Context(ctx, ir, or, er, dr, bs.NewRegistry(), certificate.NewRegistry())
}
