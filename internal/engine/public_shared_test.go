package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// Opt-in acceptance against two independently enrolled public agents. No mocked
// control plane: both obtain leases/grants from the deployed PostgreSQL service.
func TestPublicSharedLimits(t *testing.T) {
	path, mode := os.Getenv("MNET_SHARED_SNAPSHOT"), os.Getenv("MNET_SHARED_CASE")
	if path == "" || mode == "" {
		t.Skip("explicit two-agent acceptance only")
	}
	var nodes []struct {
		Host    string       `json:"host"`
		Inbound wire.Inbound `json:"inbound"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &nodes); err != nil || len(nodes) != 2 {
		t.Fatal("two client fixtures required", err)
	}
	outbounds := make([]adapter.Outbound, 2)
	for i, n := range nodes {
		if len(n.Inbound.Users) != 1 {
			t.Fatal("acceptance user only")
		}
		b := clientBox(t, n.Inbound, n.Host)
		outbounds[i], _ = b.Outbound().Outbound("proxy")
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("s", 256<<10)
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 30 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip != nodes[0].Host && ip != nodes[1].Host && ip != os.Getenv("MNET_SHARED_CONTAINER_IP") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		if mode == "connections" {
			io.WriteString(w, "s")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		io.WriteString(w, body)
	})}
	go server.Serve(listener)
	defer server.Close()
	destination := M.ParseSocksaddr(net.JoinHostPort(os.Getenv("MNET_PROBE_IP"), fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)))
	dial := func(i int) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, e := outbounds[i].DialContext(ctx, "tcp", destination)
		if e == nil {
			conn.SetDeadline(time.Now().Add(25 * time.Second))
			_, e = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: shared-acceptance\r\nConnection: close\r\n\r\n")
		}
		return conn, e
	}
	if mode == "connections" {
		first, e := dial(0)
		if e != nil {
			t.Fatal(e)
		}
		defer first.Close()
		response, e := http.ReadResponse(bufio.NewReader(first), nil)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if _, e = io.ReadFull(response.Body, make([]byte, 1)); e != nil {
			t.Fatal(e)
		}
		second, e := dial(1)
		if e != nil {
			t.Fatal(e)
		}
		defer second.Close()
		secondResponse, e := http.ReadResponse(bufio.NewReader(second), nil)
		if e != nil {
			t.Fatal("independent server IP allowance", e)
		}
		defer secondResponse.Body.Close()
		if _, e = io.ReadFull(secondResponse.Body, make([]byte, 1)); e != nil {
			t.Fatal(e)
		}
		t.Log("both servers admitted the source IP using their independent IP allowances")
		return
	}
	if mode != "rate" && mode != "quota" && mode != "baseline" {
		t.Fatal("unknown shared case")
	}
	started := time.Now()
	counts := make([]int, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range outbounds {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, e := dial(i)
			if e != nil {
				errs[i] = e
				return
			}
			defer conn.Close()
			if mode == "quota" {
				b, _ := io.ReadAll(io.LimitReader(conn, 8193))
				counts[i] = len(b)
				return
			}
			response, e := http.ReadResponse(bufio.NewReader(conn), nil)
			if e != nil {
				errs[i] = e
				return
			}
			defer response.Body.Close()
			b, e := io.ReadAll(response.Body)
			counts[i] = len(b)
			errs[i] = e
			if string(b) != body {
				errs[i] = fmt.Errorf("response mismatch: %d bytes", len(b))
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(started)
	if mode == "quota" {
		total := counts[0] + counts[1]
		if total <= 0 || total > 8192 {
			t.Fatalf("shared quota bypass: %v", counts)
		}
		t.Logf("8192 total-byte quota across agents: response bytes %v", counts)
		return
	}
	for i, e := range errs {
		if e != nil {
			t.Fatalf("agent %d: %v", i, e)
		}
	}
	if mode == "rate" && elapsed < 3500*time.Millisecond {
		t.Fatalf("aggregate 1 Mbps bypass: %s", elapsed)
	}
	t.Logf("two independent agents: payload=%v elapsed=%s mode=%s", counts, elapsed, mode)
}
