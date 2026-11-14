package engine

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/meter"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/xcore"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	bs "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	sbtrojan "github.com/sagernet/sing-box/protocol/trojan"
	sbvless "github.com/sagernet/sing-box/protocol/vless"
	sbvmess "github.com/sagernet/sing-box/protocol/vmess"
	sj "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	xnet "github.com/xtls/xray-core/common/net"
	xray "github.com/xtls/xray-core/core"

	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
)

func rawKey(t *testing.T) (private, public string) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

// vlessEncryption returns a server decryption / client encryption pair in the
// same format as `xray vlessenc`, with X25519 or ML-KEM-768 authentication.
func vlessEncryption(t *testing.T, appearance string, pq bool) (string, string) {
	t.Helper()
	server, client := rawKey(t)
	if pq {
		k, e := mlkem.GenerateKey768()
		if e != nil {
			t.Fatal(e)
		}
		server = base64.RawURLEncoding.EncodeToString(k.Bytes())
		client = base64.RawURLEncoding.EncodeToString(k.EncapsulationKey().Bytes())
	}
	return "mlkem768x25519plus." + appearance + ".600s." + server, "mlkem768x25519plus." + appearance + ".0rtt." + client
}

func certificatePin(t *testing.T, in wire.Inbound) string {
	t.Helper()
	block, _ := pem.Decode([]byte(in.Secrets.Certificate))
	if block == nil {
		t.Fatal("fixture certificate")
	}
	if _, e := x509.ParseCertificate(block.Bytes); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// xrayClientStream renders the client half of an inbound the way exported
// subscriptions describe it.
func xrayClientStream(t *testing.T, in wire.Inbound) map[string]any {
	c := in.Config
	transport := xcore.Transport(c.Transport)
	stream := map[string]any{"network": transport, "security": c.EffectiveSecurity()}
	switch transport {
	case "ws":
		stream["wsSettings"] = map[string]any{"path": c.Path, "host": c.Host}
	case "httpupgrade":
		stream["httpupgradeSettings"] = map[string]any{"path": c.Path, "host": c.Host}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": c.ServiceName, "multiMode": c.GRPCMultiMode}
	case "xhttp":
		x := map[string]any{"path": c.Path, "host": c.Host, "mode": c.XHTTPMode}
		if len(c.XHTTPExtra) > 0 {
			x["extra"] = c.XHTTPExtra
		}
		stream["xhttpSettings"] = x
	}
	switch c.EffectiveSecurity() {
	case "tls":
		t := map[string]any{"serverName": c.ServerName, "fingerprint": "chrome", "pinnedPeerCertSha256": certificatePin(t, in)}
		if len(c.ALPN) > 0 {
			t["alpn"] = c.ALPN
		}
		stream["tlsSettings"] = t
	case "reality":
		r := map[string]any{"serverName": c.ServerName, "fingerprint": "chrome", "password": c.RealityPublicKey, "shortId": c.RealityShortID, "spiderX": "/"}
		if c.RealityMldsa65Verify != "" {
			r["mldsa65Verify"] = c.RealityMldsa65Verify
		}
		stream["realitySettings"] = r
	}
	return stream
}

func xrayClient(t *testing.T, in wire.Inbound) *xray.Instance {
	t.Helper()
	u := in.Users[0].Credential
	settings := map[string]any{"address": "127.0.0.1", "port": in.Port}
	switch in.Protocol {
	case "vless":
		settings["id"] = u.UUID
		settings["encryption"] = "none"
		if in.Config.Encryption != "" {
			settings["encryption"] = in.Config.Encryption
		}
		settings["flow"] = in.Config.Flow
	case "vmess":
		settings["id"] = u.UUID
		settings["security"] = "auto"
	case "trojan":
		settings["password"] = u.Password
	}
	document := map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{map[string]any{"protocol": in.Protocol, "settings": settings, "streamSettings": xrayClientStream(t, in)}}}
	raw, _ := json.Marshal(document)
	config, e := xcore.Load(raw)
	if e != nil {
		t.Fatal(e)
	}
	client, e := xray.New(config)
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func singBoxClient(t *testing.T, ob map[string]any) *box.Box {
	t.Helper()
	or := outbound.NewRegistry()
	direct.RegisterOutbound(or)
	sbvless.RegisterOutbound(or)
	sbvmess.RegisterOutbound(or)
	sbtrojan.RegisterOutbound(or)
	anytls.RegisterOutbound(or)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	ctx := box.Context(context.Background(), inbound.NewRegistry(), or, endpoint.NewRegistry(), dr, bs.NewRegistry(), certificate.NewRegistry())
	ob["tag"] = "proxy"
	raw, _ := json.Marshal(map[string]any{"log": map[string]any{"level": "error"}, "outbounds": []any{ob}, "route": map[string]any{"final": "proxy"}})
	options, e := sj.UnmarshalExtendedContext[option.Options](ctx, raw)
	if e != nil {
		t.Fatal(e)
	}
	b, e := box.New(box.Options{Options: options, Context: ctx})
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Start(); e != nil {
		b.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

type echoFixtures struct {
	http string
	udp  *net.UDPAddr
}

func startEcho(t *testing.T, body string) echoFixtures {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
	t.Cleanup(server.Close)
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		b := make([]byte, 65536)
		for {
			n, addr, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], addr)
		}
	}()
	return echoFixtures{strings.TrimPrefix(server.URL, "http://"), udp.LocalAddr().(*net.UDPAddr)}
}

func httpThrough(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
	response, e := http.ReadResponse(bufio.NewReader(conn), nil)
	if e != nil {
		t.Fatal("TCP through proxy:", e)
	}
	reply, e := io.ReadAll(response.Body)
	response.Body.Close()
	if e != nil || !strings.Contains(string(reply), want) {
		t.Fatalf("TCP roundtrip: %v %q", e, reply)
	}
}

// meteredServer starts the inbound on the production engine path, with only
// the loopback egress allowance that package tests may set.
func meteredServer(t *testing.T, in wire.Inbound, controller meter.Controller) (*journal.Store, *meter.Tracker) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), egressTestKey{}, true))
	t.Cleanup(cancel)
	store, e := journal.Open(t.TempDir(), strings.Repeat("a", 256))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	tracker := meter.New(ctx, controller, store)
	tracker.Update(wire.Snapshot{ProtocolVersion: 1, ServerID: 1, Revision: strings.Repeat("a", 64), IssuedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute), Inbounds: []wire.Inbound{in}})
	t.Cleanup(func() { tracker.CloseInbound(0) })
	engine := New(ctx, t.TempDir(), tracker, nil, tracker.Update, tracker.CloseInbound)
	core, raw, e := Plan(in, "")
	if e != nil {
		t.Fatal(e)
	}
	if core == coreSingBox {
		// The sing-box route keeps its private-IP rules; lift them for loopback.
		var config map[string]any
		json.Unmarshal(raw, &config)
		config["route"].(map[string]any)["rules"] = []any{}
		raw, _ = json.Marshal(config)
	}
	runtime, e := engine.start(core, raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = runtime.Start(); e != nil {
		runtime.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { runtime.Close() })
	return store, tracker
}

func realityTarget(t *testing.T) string {
	t.Helper()
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "camouflage") }))
	target.EnableHTTP2 = true
	target.StartTLS()
	t.Cleanup(target.Close)
	return strings.TrimPrefix(target.URL, "https://")
}

func reality(t *testing.T, in *wire.Inbound) {
	private, public := rawKey(t)
	in.Config.TLS = false
	in.Config.Security = "reality"
	in.Config.ServerName = "example.com"
	in.Config.RealityTarget = realityTarget(t)
	in.Config.RealityServerNames = []string{"example.com"}
	in.Config.RealityPublicKey = public
	in.Config.RealityShortID = "6ba85179e30d4fc2"
	in.Secrets.RealityPrivateKey = private
}

type modernCase struct {
	name, protocol string
	setup          func(*testing.T, *wire.Inbound)
	singBox        func(wire.Inbound) map[string]any
}

func singTLS(in wire.Inbound) map[string]any {
	return map[string]any{"enabled": true, "server_name": in.Config.ServerName, "insecure": true}
}
func singReality(in wire.Inbound) map[string]any {
	return map[string]any{"enabled": true, "server_name": in.Config.ServerName, "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": in.Config.RealityPublicKey, "short_id": in.Config.RealityShortID}}
}

func TestModernInboundMatrix(t *testing.T) {
	echo := startEcho(t, "minging-modern-roundtrip")
	cases := []modernCase{
		{"vless-reality-vision-raw", "vless", func(t *testing.T, in *wire.Inbound) { reality(t, in); in.Config.Flow = "xtls-rprx-vision" }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "vless", "server": "127.0.0.1", "server_port": in.Port, "uuid": in.Users[0].Credential.UUID, "flow": "xtls-rprx-vision", "tls": singReality(in)}
		}},
		{"vless-reality-grpc", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Transport = "grpc"
			in.Config.ServiceName = "mnet"
		}, nil},
		{"vless-reality-xhttp", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Transport = "xhttp"
			in.Config.Path = "/mnet-xhttp"
			in.Config.XHTTPMode = "auto"
		}, nil},
		{"vless-tls-xhttp-packet-up-extra", "vless", func(t *testing.T, in *wire.Inbound) {
			in.Config.Security = "tls"
			in.Config.Transport = "xhttp"
			in.Config.Path = "/mnet"
			in.Config.XHTTPMode = "packet-up"
			in.Config.XHTTPExtra = json.RawMessage(`{"xPaddingBytes":"100-1000","noGRPCHeader":true,"scMaxEachPostBytes":"500000-1000000"}`)
		}, nil},
		{"vless-encryption-native-x25519-vision", "vless", func(t *testing.T, in *wire.Inbound) {
			in.Config.TLS = false
			in.Config.Security = "none"
			in.Config.Flow = "xtls-rprx-vision"
			in.Secrets.Decryption, in.Config.Encryption = vlessEncryption(t, "native", false)
		}, nil},
		{"vless-encryption-random-mlkem-ws-tls", "vless", func(t *testing.T, in *wire.Inbound) {
			in.Config.Security = "tls"
			in.Config.Transport = "ws"
			in.Config.Path = "/ws"
			in.Secrets.Decryption, in.Config.Encryption = vlessEncryption(t, "random", true)
		}, nil},
		{"vless-encryption-xorpub-xhttp-reality", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Transport = "xhttp"
			in.Config.Path = "/x"
			in.Config.XHTTPMode = "stream-one"
			in.Secrets.Decryption, in.Config.Encryption = vlessEncryption(t, "xorpub", false)
		}, nil},
		// sing-box clients send "zero" for auto over TLS; the VMess server must accept it.
		{"vmess-ws-tls-auto", "vmess", func(t *testing.T, in *wire.Inbound) { in.Config.Transport = "ws"; in.Config.Path = "/vm" }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": in.Port, "uuid": in.Users[0].Credential.UUID, "security": "auto", "tls": singTLS(in), "transport": map[string]any{"type": "ws", "path": "/vm"}}
		}},
		{"vmess-grpc-tls", "vmess", func(t *testing.T, in *wire.Inbound) { in.Config.Transport = "grpc"; in.Config.ServiceName = "vm" }, nil},
		{"trojan-httpupgrade-tls", "trojan", func(t *testing.T, in *wire.Inbound) { in.Config.Transport = "httpupgrade"; in.Config.Path = "/up" }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "trojan", "server": "127.0.0.1", "server_port": in.Port, "password": in.Users[0].Credential.Password, "tls": singTLS(in), "transport": map[string]any{"type": "httpupgrade", "path": "/up"}}
		}},
		{"vless-httpupgrade-tls", "vless", func(t *testing.T, in *wire.Inbound) {
			in.Config.Transport = "httpupgrade"
			in.Config.Path = "/vu"
			in.Config.Host = "cdn.example"
		}, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "vless", "server": "127.0.0.1", "server_port": in.Port, "uuid": in.Users[0].Credential.UUID, "tls": singTLS(in), "transport": map[string]any{"type": "httpupgrade", "path": "/vu", "host": "cdn.example"}}
		}},
		{"vmess-raw-none", "vmess", func(t *testing.T, in *wire.Inbound) { in.Config.TLS = false; in.Config.Security = "none" }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "vmess", "server": "127.0.0.1", "server_port": in.Port, "uuid": in.Users[0].Credential.UUID, "security": "chacha20-poly1305"}
		}},
		{"trojan-grpc-tls", "trojan", func(t *testing.T, in *wire.Inbound) { in.Config.Transport = "grpc"; in.Config.ServiceName = "tj" }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "trojan", "server": "127.0.0.1", "server_port": in.Port, "password": in.Users[0].Credential.Password, "tls": singTLS(in), "transport": map[string]any{"type": "grpc", "service_name": "tj"}}
		}},
		{"trojan-reality-raw", "trojan", func(t *testing.T, in *wire.Inbound) { reality(t, in) }, nil},
		{"anytls", "anytls", nil, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "anytls", "server": "127.0.0.1", "server_port": in.Port, "password": in.Users[0].Credential.Password, "tls": singTLS(in)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := fixtureInbound(t, tc.protocol)
			in.Config.TLS = true
			if tc.setup != nil {
				tc.setup(t, &in)
			}
			store, tracker := meteredServer(t, in, &fixtureController{})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			udpMessage := []byte("minging-modern-udp")
			if tc.protocol == "vless" || tc.protocol == "vmess" || tc.protocol == "trojan" {
				client := xrayClient(t, in)
				host, port, _ := net.SplitHostPort(echo.http)
				conn, e := xray.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(mustPort(port))))
				if e != nil {
					t.Fatal(e)
				}
				httpThrough(t, conn, "minging-modern-roundtrip")
				packet, e := xray.DialUDP(ctx, client)
				if e != nil {
					t.Fatal(e)
				}
				udpRoundTrip(t, packet, echo.udp, udpMessage)
			}
			if tc.singBox != nil && (in.Config.Security != "reality" || singBoxUTLS) {
				client := singBoxClient(t, tc.singBox(in))
				ob := client.Outbound().Default()
				conn, e := ob.DialContext(ctx, "tcp", M.ParseSocksaddr(echo.http))
				if e != nil {
					t.Fatal("sing-box client:", e)
				}
				httpThrough(t, conn, "minging-modern-roundtrip")
				packet, e := ob.ListenPacket(ctx, M.SocksaddrFromNet(echo.udp))
				if e != nil {
					t.Fatal(e)
				}
				udpRoundTrip(t, packet, echo.udp, udpMessage)
			}
			tracker.CloseInbound(0)
			time.Sleep(50 * time.Millisecond)
			up, down := store.Totals()
			if up < int64(len(udpMessage)) || down < int64(len("minging-modern-roundtrip")) {
				t.Fatalf("payload bypassed metering: upload=%d download=%d", up, down)
			}
			t.Logf("metered upload=%d download=%d", up, down)
		})
	}
}

func mustPort(s string) uint16 {
	var p uint16
	fmt.Sscan(s, &p)
	return p
}

func udpRoundTrip(t *testing.T, packet net.PacketConn, target *net.UDPAddr, message []byte) {
	t.Helper()
	defer packet.Close()
	result := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, _, e := packet.ReadFrom(buffer)
		if e == nil && string(buffer[:n]) != string(message) {
			e = fmt.Errorf("unexpected UDP reply %q", buffer[:n])
		}
		result <- e
	}()
	if _, e := packet.WriteTo(message, target); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-result:
		if e != nil {
			t.Fatal("UDP:", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("UDP reply timed out")
	}
}

// quotaController grants bytes until a fixed budget is spent, then refuses.
type quotaController struct {
	mu     sync.Mutex
	budget int64
}

func (c *quotaController) Lease(ctx context.Context, x wire.Lease) (wire.LeaseResult, error) {
	return wire.LeaseResult{ID: x.ID, ExpiresAt: time.Now().Add(25 * time.Second)}, nil
}
func (c *quotaController) Grant(ctx context.Context, x wire.GrantRequest) (wire.Grant, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.budget <= 0 {
		return wire.Grant{}, fmt.Errorf("quota exhausted")
	}
	n := min(x.Bytes, c.budget)
	c.budget -= n
	return wire.Grant{ID: x.ID, Bytes: n, ExpiresAt: time.Now().Add(5 * time.Second)}, nil
}

// TestXrayQuotaStopsTransfer proves Xray-served traffic cannot exceed grants
// even with Vision over REALITY, where Xray would otherwise splice sockets.
func TestXrayQuotaStopsTransfer(t *testing.T) {
	large := strings.Repeat("q", 4<<20)
	echo := startEcho(t, large)
	in := fixtureInbound(t, "vless")
	reality(t, &in)
	in.Config.Flow = "xtls-rprx-vision"
	const budget = 256 << 10
	store, _ := meteredServer(t, in, &quotaController{budget: budget})
	client := xrayClient(t, in)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	host, port, _ := net.SplitHostPort(echo.http)
	conn, e := xray.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(mustPort(port))))
	if e != nil {
		t.Fatal(e)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
	received, _ := io.Copy(io.Discard, conn)
	conn.Close()
	if received >= int64(len(large)) || received > budget {
		t.Fatalf("transfer exceeded quota: received %d with budget %d", received, budget)
	}
	time.Sleep(50 * time.Millisecond)
	up, down := store.Totals()
	if up+down > budget {
		t.Fatalf("settled %d bytes beyond budget %d", up+down, budget)
	}
	t.Logf("quota held: client received %d bytes, settled upload=%d download=%d", received, up, down)
}

// TestXrayDeniesPrivateDestinations runs the production policy (no test
// allowance): loopback destinations must be refused before any dial.
func TestXrayDeniesPrivateDestinations(t *testing.T) {
	echo := startEcho(t, "must-not-be-reached")
	in := fixtureInbound(t, "vless")
	reality(t, &in)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, e := journal.Open(t.TempDir(), strings.Repeat("a", 256))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	tracker := meter.New(ctx, &fixtureController{}, store)
	tracker.Update(wire.Snapshot{ProtocolVersion: 1, ServerID: 1, Revision: strings.Repeat("a", 64), IssuedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute), Inbounds: []wire.Inbound{in}})
	defer tracker.CloseInbound(0)
	raw, e := xcore.Build(in, "")
	if e != nil {
		t.Fatal(e)
	}
	server, e := xcore.New(ctx, raw, tracker, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = server.Start(); e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	client := xrayClient(t, in)
	host, port, _ := net.SplitHostPort(echo.http)
	conn, e := xray.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(mustPort(port))))
	if e != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
	reply, _ := io.ReadAll(conn)
	conn.Close()
	if strings.Contains(string(reply), "must-not-be-reached") {
		t.Fatal("private destination reached through Xray inbound")
	}
	if up, down := store.Totals(); up+down != 0 {
		t.Fatalf("denied connection was metered: %d/%d", up, down)
	}
}

// TestXrayRejectsUnsafeCombinations keeps invalid security pairings out of
// the core even if a controller sent them.
func TestXrayRejectsUnsafeCombinations(t *testing.T) {
	for name, mutate := range map[string]func(*wire.Inbound){
		"plain-vless":   func(in *wire.Inbound) { in.Config.TLS = false; in.Config.Security = "none" },
		"reality-ws":    func(in *wire.Inbound) { reality(t, in); in.Config.Transport = "ws"; in.Config.Path = "/" },
		"vmess-reality": func(in *wire.Inbound) { in.Protocol = "vmess"; reality(t, in) },
		"vision-over-ws": func(in *wire.Inbound) {
			in.Config.Transport = "ws"
			in.Config.Path = "/"
			in.Config.Flow = "xtls-rprx-vision"
		},
		"xhttp-on-trojan":  func(in *wire.Inbound) { in.Protocol = "trojan"; in.Config.Transport = "xhttp"; in.Config.Path = "/" },
		"bad-short-id":     func(in *wire.Inbound) { reality(t, in); in.Config.RealityShortID = "xyz" },
		"unknown-security": func(in *wire.Inbound) { in.Config.Security = "xtls" },
	} {
		t.Run(name, func(t *testing.T) {
			in := fixtureInbound(t, "vless")
			in.Config.TLS = true
			mutate(&in)
			if _, e := xcore.Build(in, ""); e == nil {
				t.Fatal("unsafe combination accepted")
			}
		})
	}
}
