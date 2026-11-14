package egress

import (
	"context"
	"net/netip"
	"testing"
)

func TestPublic(t *testing.T) {
	for address, public := range map[string]bool{
		"1.1.1.1": true, "2606:4700:4700::1111": true, "10.0.0.1": false, "127.0.0.1": false,
		"100.64.1.1": false, "169.254.169.254": false, "::1": false, "fe80::1": false,
		"fd00::1": false, "0.0.0.0": false, "::ffff:192.168.1.1": false, "240.0.0.1": false,
	} {
		if got := Public(netip.MustParseAddr(address)); got != public {
			t.Errorf("%s: got %v", address, got)
		}
	}
}

func TestResolveRejectsPrivateLiteral(t *testing.T) {
	if _, e := Resolve(context.Background(), "192.168.0.1", false); e == nil {
		t.Fatal("private literal accepted")
	}
	if ip, e := Resolve(context.Background(), "192.168.0.1", true); e != nil || ip.String() != "192.168.0.1" {
		t.Fatal("test allowance ignored", e)
	}
	if _, e := Resolve(context.Background(), "localhost", false); e == nil {
		t.Fatal("loopback name accepted")
	}
}
