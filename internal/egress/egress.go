// Package egress holds the single private-destination policy shared by every
// protocol core. Proxy users may only reach public unicast destinations.
package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// Public reports whether ip is a globally routable unicast address.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range reserved {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// Resolve returns the first address of host after every resolved address has
// passed the policy; a single private answer rejects the whole name, so DNS
// rebinding cannot select a private address later.
func Resolve(ctx context.Context, host string, allowPrivate bool) (netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		if !allowPrivate && !Public(ip) {
			return netip.Addr{}, errors.New("private destination denied")
		}
		return ip.Unmap(), nil
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil || len(ips) == 0 {
		return netip.Addr{}, errors.New("destination resolution failed")
	}
	for _, ip := range ips {
		if !allowPrivate && !Public(ip) {
			return netip.Addr{}, errors.New("private DNS result denied")
		}
	}
	return ips[0].Unmap(), nil
}
