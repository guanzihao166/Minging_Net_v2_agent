package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPublicGuards(t *testing.T) {
	path := os.Getenv("MNET_PUBLIC_SNAPSHOT")
	mode := os.Getenv("MNET_GUARD_CASE")
	if path == "" || mode == "" {
		t.Skip("explicit public guard acceptance only")
	}
	var snapshot wire.Snapshot
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &snapshot); e != nil {
		t.Fatal(e)
	}
	var in wire.Inbound
	for _, candidate := range snapshot.Inbounds {
		if candidate.Protocol == "vless" {
			in = candidate
			break
		}
	}
	if len(in.Users) != 1 {
		t.Fatal("one acceptance user is required")
	}
	if mode == "wrongcredential" {
		in.Users[0].Credential.UUID = "00000000-0000-4000-8000-000000000000"
	}
	host := os.Getenv("MNET_NODE_IP")
	probe := os.Getenv("MNET_PROBE_IP")
	client := clientBox(t, in, host)
	outbound, ok := client.Outbound().Outbound("proxy")
	if !ok {
		t.Fatal("client outbound missing")
	}
	listener, e := net.Listen("tcp", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	body := strings.Repeat("g", 256<<10)
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip != host {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		if mode == "connections" {
			io.WriteString(w, "g")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		io.WriteString(w, body)
	})}
	go server.Serve(listener)
	defer server.Close()
	target := M.ParseSocksaddr(net.JoinHostPort(probe, fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)))
	if mode == "private" {
		target = M.ParseSocksaddr("127.0.0.1:10000")
	}
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, e := outbound.DialContext(ctx, "tcp", target)
		if e == nil {
			c.SetDeadline(time.Now().Add(15 * time.Second))
			_, e = fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: acceptance\r\nConnection: close\r\n\r\n")
		}
		return c, e
	}
	started := time.Now()
	conn, e := dial()
	if mode == "denied" || mode == "private" || mode == "wrongcredential" {
		if e == nil {
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(4 * time.Second))
			data, _ := io.ReadAll(io.LimitReader(conn, 8193))
			if len(data) != 0 {
				t.Fatalf("denied flow delivered %d payload bytes", len(data))
			}
		}
		t.Log(mode + ": no application payload delivered")
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if mode == "quota" {
		data, err := io.ReadAll(io.LimitReader(conn, int64(len(body)+4096)))
		if len(data) == 0 || len(data) > 8192 || err == nil && len(data) >= len(body) {
			t.Fatalf("quota did not stop transfer: bytes=%d error=%v", len(data), err)
		}
		t.Logf("quota stopped TCP at %d response bytes (8192 total byte allowance)", len(data))
		return
	}
	response, e := http.ReadResponse(bufio.NewReader(conn), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if mode == "connections" {
		first := make([]byte, 1)
		if _, e = io.ReadFull(response.Body, first); e != nil {
			t.Fatal(e)
		}
		second, err := dial()
		if err == nil {
			defer second.Close()
			second.SetReadDeadline(time.Now().Add(4 * time.Second))
			data, _ := io.ReadAll(io.LimitReader(second, 1))
			if len(data) != 0 {
				t.Fatal("second simultaneous connection bypassed cap")
			}
		}
		t.Log("one active connection accepted; second connection rejected")
		return
	}
	if mode != "rate" {
		t.Fatal("unknown guard case")
	}
	data, e := io.ReadAll(response.Body)
	elapsed := time.Since(started)
	if e != nil || string(data) != body {
		t.Fatal("rate-limited response incomplete", len(data), e)
	}
	// 1 Mbps, explicit 64 KiB initial burst; 256 KiB needs at least 1.5 s.
	if elapsed < 1400*time.Millisecond {
		t.Fatalf("rate cap bypassed: %s", elapsed)
	}
	t.Logf("1 Mbps cap: %d bytes in %s", len(data), elapsed)
}
