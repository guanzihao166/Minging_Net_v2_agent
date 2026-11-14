package engine

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/meter"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	bs "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
	sj "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureController struct {
	mu             sync.Mutex
	leases, grants int
}

func (c *fixtureController) Lease(ctx context.Context, x wire.Lease) (wire.LeaseResult, error) {
	c.mu.Lock()
	if !x.Close {
		c.leases++
	}
	c.mu.Unlock()
	return wire.LeaseResult{ID: x.ID, ExpiresAt: time.Now().Add(25 * time.Second)}, nil
}
func (c *fixtureController) Grant(ctx context.Context, x wire.GrantRequest) (wire.Grant, error) {
	c.mu.Lock()
	c.grants++
	c.mu.Unlock()
	return wire.Grant{ID: x.ID, Bytes: x.Bytes, ExpiresAt: time.Now().Add(2 * time.Second)}, nil
}
func keyPair(t *testing.T) (string, string) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
func certificatePair(t *testing.T) (string, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	k, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
}
func fixtureInbound(t *testing.T, protocol string) wire.Inbound {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cert, key := certificatePair(t)
	priv, pub := keyPair(t)
	cpriv, cpub := keyPair(t)
	credential := wire.Credential{UUID: "00c3cf1b-80f0-477c-bb0d-a051ee220191", Password: "fixture-password-long-enough-1234567890", SSKey: base64.StdEncoding.EncodeToString([]byte("1234567890abcdef")), PrivateKey: cpriv, PublicKey: cpub, Address: "10.0.0.2"}
	return wire.Inbound{ID: 1, Protocol: protocol, ListenHost: "127.0.0.1", Port: port, Config: wire.ClientConfig{TLS: protocol != "ss2022" && protocol != "wireguard", ServerName: "localhost", Method: "2022-blake3-aes-128-gcm", ServerKey: base64.StdEncoding.EncodeToString([]byte("fedcba0987654321")), WGPublicKey: pub, MTU: 1408}, Secrets: wire.Secrets{Certificate: cert, PrivateKey: key, WGPrivateKey: priv}, Users: []wire.User{{ID: 1, Epoch: 1, ExpiresAt: time.Now().Add(time.Hour), SpeedMbps: 100, MaxConnections: 10, Credential: credential}}}
}
func clientBox(t *testing.T, in wire.Inbound, publicHost ...string) *box.Box {
	t.Helper()
	ir := inbound.NewRegistry()
	or := outbound.NewRegistry()
	direct.RegisterOutbound(or)
	vless.RegisterOutbound(or)
	vmess.RegisterOutbound(or)
	shadowsocks.RegisterOutbound(or)
	trojan.RegisterOutbound(or)
	hysteria2.RegisterOutbound(or)
	tuic.RegisterOutbound(or)
	er := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(er)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	ctx := box.Context(context.Background(), ir, or, er, dr, bs.NewRegistry(), certificate.NewRegistry())
	c := in.Users[0].Credential
	server := "127.0.0.1"
	insecure := true
	if len(publicHost) > 0 {
		server = publicHost[0]
		insecure = false
	}
	ob := map[string]any{"tag": "proxy", "server": server, "server_port": in.Port}
	switch in.Protocol {
	case "vless", "vmess":
		ob["type"] = in.Protocol
		ob["uuid"] = c.UUID
		if in.Protocol == "vmess" {
			ob["security"] = "auto"
		}
	case "trojan":
		ob["type"] = "trojan"
		ob["password"] = c.Password
	case "ss2022":
		ob["type"] = "shadowsocks"
		ob["method"] = in.Config.Method
		ob["password"] = in.Config.ServerKey + ":" + c.SSKey
	case "hy2":
		ob["type"] = "hysteria2"
		ob["password"] = c.Password
	case "tuic5":
		ob["type"] = "tuic"
		ob["uuid"] = c.UUID
		ob["password"] = c.Password
		ob["congestion_control"] = "bbr"
	case "wireguard":
	}
	if in.Config.TLS {
		ob["tls"] = map[string]any{"enabled": true, "server_name": in.Config.ServerName, "insecure": insecure}
		if len(in.Config.ALPN) > 0 {
			ob["tls"].(map[string]any)["alpn"] = in.Config.ALPN
		} else if in.Protocol == "tuic5" {
			ob["tls"].(map[string]any)["alpn"] = []string{"h3"}
		}
	}
	config := map[string]any{"log": map[string]any{"level": "error"}, "outbounds": []any{ob}, "route": map[string]any{"final": "proxy"}}
	if in.Protocol == "wireguard" {
		delete(config, "outbounds")
		config["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": "proxy", "system": false, "address": []string{c.Address + "/32"}, "private_key": c.PrivateKey, "peers": []any{map[string]any{"address": server, "port": in.Port, "public_key": in.Config.WGPublicKey, "allowed_ips": []string{"0.0.0.0/0"}}}, "mtu": 1408, "workers": 2}}
	}
	raw, _ := json.Marshal(config)
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
func TestSevenProtocolTCPUDP(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "minging-real-protocol-roundtrip") }))
	defer destination.Close()
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
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
	for _, protocol := range []string{"vless", "vmess", "ss2022", "trojan", "wireguard", "hy2", "tuic5"} {
		t.Run(protocol, func(t *testing.T) {
			if protocol == "wireguard" && runtime.GOOS == "windows" {
				t.Skip("WireGuard uses the Linux acceptance run; Windows UDP sendmsg is not a supported deployment target")
			}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), egressTestKey{}, true))
			defer cancel()
			in := fixtureInbound(t, protocol)
			s := wire.Snapshot{ProtocolVersion: 1, ServerID: 1, Revision: strings.Repeat("a", 64), IssuedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute), Inbounds: []wire.Inbound{in}}
			store, e := journal.Open(t.TempDir(), strings.Repeat("a", 256))
			if e != nil {
				t.Fatal(e)
			}
			defer store.Close()
			controller := &fixtureController{}
			tracker := meter.New(ctx, controller, store)
			tracker.Update(s)
			defer tracker.CloseInbound(0)
			engine := New(ctx, t.TempDir(), tracker, nil, tracker.Update, tracker.CloseInbound)
			kind, raw, e := Plan(in, "")
			if e != nil {
				t.Fatal(e)
			}
			if kind == coreSingBox {
				// Only this local protocol test removes egress rejection to reach its two
				// loopback echo fixtures. Production Build always retains private-IP blocks.
				var config map[string]any
				json.Unmarshal(raw, &config)
				config["route"].(map[string]any)["rules"] = []any{}
				if protocol == "wireguard" {
					config["route"].(map[string]any)["rules"] = []any{map[string]any{"ip_cidr": []string{"198.18.0.1/32"}, "action": "route", "outbound": "egress", "override_address": "127.0.0.1"}}
				}
				raw, _ = json.Marshal(config)
			}
			core, e := engine.start(kind, raw)
			if e != nil {
				t.Fatal(e)
			}
			if e = core.Start(); e != nil {
				core.Close()
				t.Fatal(e)
			}
			defer core.Close()
			client := clientBox(t, in)
			outbound := client.Outbound().Default()
			if protocol == "wireguard" {
				var found bool
				outbound, found = client.Outbound().Outbound("proxy")
				if !found {
					t.Fatal("wireguard endpoint absent")
				}
			}
			dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			defer stop()
			tcpTarget := M.ParseSocksaddr(strings.TrimPrefix(destination.URL, "http://"))
			if protocol == "wireguard" {
				tcpTarget.Addr = netip.MustParseAddr("198.18.0.1")
			}
			conn, e := outbound.DialContext(dialCtx, "tcp", tcpTarget)
			if e != nil {
				t.Fatal(e)
			}
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n")
			response, e := http.ReadResponse(bufio.NewReader(conn), nil)
			if e != nil {
				conn.Close()
				t.Fatal(e)
			}
			reply, e := io.ReadAll(response.Body)
			response.Body.Close()
			conn.Close()
			if e != nil || !strings.Contains(string(reply), "minging-real-protocol-roundtrip") {
				t.Fatalf("TCP roundtrip: %v %s", e, reply)
			}
			target := M.SocksaddrFromNetIP(netip.MustParseAddrPort(udp.LocalAddr().String()))
			if protocol == "wireguard" {
				target.Addr = netip.MustParseAddr("198.18.0.1")
			}
			packet, e := outbound.ListenPacket(dialCtx, target)
			if e != nil {
				t.Fatal(e)
			}
			packet.SetDeadline(time.Now().Add(10 * time.Second))
			message := []byte("minging-udp-roundtrip")
			if _, e = packet.WriteTo(message, target.UDPAddr()); e != nil {
				t.Fatal(e)
			}
			buffer := make([]byte, 1024)
			n, _, e := packet.ReadFrom(buffer)
			packet.Close()
			if e != nil || string(buffer[:n]) != string(message) {
				t.Fatalf("UDP roundtrip: %v %q", e, buffer[:n])
			}
			tracker.CloseInbound(0)
			time.Sleep(20 * time.Millisecond)
			up, down := store.Totals()
			if up < int64(len(message)) || down < int64(len(message)) {
				t.Fatalf("real payload bypassed metering: %d/%d", up, down)
			}
			t.Logf("TCP+UDP handshake and metered payload: upload=%d download=%d", up, down)
		})
	}
}
