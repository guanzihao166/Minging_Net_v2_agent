package engine

// Explicit opt-in: a private controller export and an independently reachable
// probe host are required. Ordinary unit/CI runs never touch production.
import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPublicProtocols(t *testing.T) {
	path := os.Getenv("MNET_PUBLIC_SNAPSHOT")
	if path == "" {
		t.Skip("public node acceptance is explicitly enabled")
	}
	host := os.Getenv("MNET_NODE_IP")
	probe := os.Getenv("MNET_PROBE_IP")
	if _, err := netip.ParseAddr(host); err != nil {
		t.Fatal("node IP required")
	}
	if _, err := netip.ParseAddr(probe); err != nil {
		t.Fatal("probe IP required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot wire.Snapshot
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 24)
	rand.Read(nonce)
	token := hex.EncodeToString(nonce)
	content := strings.Repeat("minging-public-protocol-payload\n", 8192)
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip != host || r.URL.Path != "/"+token {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, content)
	})}
	go httpServer.Serve(listener)
	defer httpServer.Close()
	udp, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 128)
		for {
			n, peer, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			ip, _, _ := net.SplitHostPort(peer.String())
			if ip == host && string(b[:n]) == token {
				udp.WriteTo(b[:n], peer)
			}
		}
	}()
	tcpPort := listener.Addr().(*net.TCPAddr).Port
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	if len(snapshot.Inbounds) != 7 {
		t.Fatalf("expected seven deployed inbounds, got %d", len(snapshot.Inbounds))
	}
	for _, in := range snapshot.Inbounds {
		t.Run(in.Protocol, func(t *testing.T) {
			if len(in.Users) != 1 {
				t.Fatal("private export must contain only the acceptance user")
			}
			client := clientBox(t, in, host)
			outbound, ok := client.Outbound().Outbound("proxy")
			if !ok {
				t.Fatal("client outbound missing")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			target := M.ParseSocksaddr(net.JoinHostPort(probe, fmt.Sprint(tcpPort)))
			started := time.Now()
			conn, e := outbound.DialContext(ctx, "tcp", target)
			if e != nil {
				t.Fatal("public TCP dial", e)
			}
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			fmt.Fprintf(conn, "GET /%s HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n", token)
			response, e := http.ReadResponse(bufio.NewReader(conn), nil)
			if e != nil {
				conn.Close()
				t.Fatal("public TCP response", e)
			}
			body, e := io.ReadAll(io.LimitReader(response.Body, int64(len(content)+1)))
			response.Body.Close()
			conn.Close()
			if e != nil || string(body) != content {
				t.Fatalf("public TCP payload mismatch: %d bytes, error %v", len(body), e)
			}
			tcpElapsed := time.Since(started)
			target = M.ParseSocksaddr(net.JoinHostPort(probe, fmt.Sprint(udpPort)))
			packet, e := outbound.ListenPacket(ctx, target)
			if e != nil {
				t.Fatal("public UDP dial", e)
			}
			packet.SetDeadline(time.Now().Add(15 * time.Second))
			if _, e = packet.WriteTo([]byte(token), target.UDPAddr()); e != nil {
				packet.Close()
				t.Fatal(e)
			}
			buf := make([]byte, 128)
			n, _, e := packet.ReadFrom(buf)
			packet.Close()
			if e != nil || string(buf[:n]) != token {
				t.Fatalf("public UDP response mismatch (%d bytes): %v", n, e)
			}
			t.Logf("public TCP=%d bytes in %s; UDP=%d bytes; TLS verification=%v", len(body), tcpElapsed, n, in.Config.TLS)
		})
	}
}
