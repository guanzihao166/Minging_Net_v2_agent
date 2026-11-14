package engine

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	xnet "github.com/xtls/xray-core/common/net"
	xray "github.com/xtls/xray-core/core"
)

// probeALPN marks the handshakes of the unauthenticated test client, so the
// target fixture can tell whether REALITY relayed one of them.
const probeALPN = "minging-unauthenticated-probe"

// observedTarget is a REALITY target that records the ALPN offers it receives.
func observedTarget(t *testing.T) (string, func() bool) {
	t.Helper()
	var mu sync.Mutex
	probed := false
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "camouflage") }))
	target.EnableHTTP2 = true
	target.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range h.SupportedProtos {
			probed = probed || p == probeALPN
		}
		return nil, nil
	}}
	target.StartTLS()
	t.Cleanup(target.Close)
	return strings.TrimPrefix(target.URL, "https://"), func() bool { mu.Lock(); defer mu.Unlock(); return probed }
}

// unauthenticatedHandshake connects like a probe that knows the SNI but not
// the REALITY key, and reports whether a TLS handshake completed.
func unauthenticatedHandshake(in wire.Inbound) error {
	conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(in.Port)), 5*time.Second)
	if e != nil {
		return e
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	client := tls.Client(conn, &tls.Config{ServerName: in.Config.ServerName, InsecureSkipVerify: true, NextProtos: []string{probeALPN, "h2"}})
	return client.Handshake()
}

func TestRealityRejectFallback(t *testing.T) {
	echo := startEcho(t, "minging-guard-roundtrip")
	for _, reject := range []bool{false, true} {
		name := "fallback-relayed"
		if reject {
			name = "fallback-refused"
		}
		t.Run(name, func(t *testing.T) {
			in := fixtureInbound(t, "vless")
			reality(t, &in)
			in.Config.Flow = "xtls-rprx-vision"
			target, probed := observedTarget(t)
			in.Config.RealityTarget = target
			in.Config.RealityRejectFallback = reject
			meteredServer(t, in, &fixtureController{})
			// Authenticated clients work either way.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			client := xrayClient(t, in)
			host, port, _ := net.SplitHostPort(echo.http)
			conn, e := xray.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(mustPort(port))))
			if e != nil {
				t.Fatal(e)
			}
			httpThrough(t, conn, "minging-guard-roundtrip")
			e = unauthenticatedHandshake(in)
			time.Sleep(200 * time.Millisecond)
			if reject {
				if e == nil || probed() {
					t.Fatalf("unauthenticated connection reached the target (handshake error %v, target saw probe %v)", e, probed())
				}
				return
			}
			// Without the guard REALITY relays the probe to the real target.
			if e != nil || !probed() {
				t.Fatalf("control case: probe was not relayed (handshake error %v)", e)
			}
		})
	}
}
