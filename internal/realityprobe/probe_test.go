package realityprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixture serves TLS with httptest's certificate, which covers example.com and
// 127.0.0.1, and returns its address with a pool trusting that certificate.
func fixture(t *testing.T, h2 bool, maxVersion uint16) (string, *x509.CertPool) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	server.EnableHTTP2 = h2
	server.TLS = &tls.Config{MaxVersion: maxVersion}
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return strings.TrimPrefix(server.URL, "https://"), pool
}

func TestProbeReportsFeasibleTarget(t *testing.T) {
	address, pool := fixture(t, true, 0)
	r := probe(context.Background(), Target{Target: address, ServerNames: []string{"Example.com", "example.com", "unrelated.test"}}, true, pool)
	if !r.Feasible || r.Reason != "" || r.TLSVersion != "1.3" || r.ALPN != "h2" || r.Curve != "X25519MLKEM768" || !r.CertValid {
		t.Fatalf("feasible target misreported: %+v", r)
	}
	if r.ServerName != "example.com" || len(r.VerifiedNames) != 1 || r.VerifiedNames[0] != "example.com" || r.LatencyMS < 1 || r.CertChainBytes == 0 || r.Address != "127.0.0.1" {
		t.Fatalf("details misreported: %+v", r)
	}
}

func TestProbeExplainsUnusableTargets(t *testing.T) {
	h1, pool1 := fixture(t, false, 0)
	tls12, pool12 := fixture(t, true, tls.VersionTLS12)
	good, pool := fixture(t, true, 0)
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := closed.Addr().String()
	closed.Close()
	cases := []struct {
		target Target
		pool   *x509.CertPool
		allow  bool
		reason string
	}{
		{Target{Target: h1, ServerNames: []string{"example.com"}}, pool1, true, "alpn"},
		{Target{Target: tls12, ServerNames: []string{"example.com"}}, pool12, true, "tls_version"},
		{Target{Target: good, ServerNames: []string{"other.test"}}, pool, true, "certificate"},
		{Target{Target: good, ServerNames: []string{"example.com"}}, nil, true, "certificate"},
		{Target{Target: good, ServerNames: []string{"example.com"}}, pool, false, "private"},
		{Target{Target: refused, ServerNames: []string{"example.com"}}, pool, true, "connect"},
		{Target{Target: "example.com"}, pool, true, "invalid"},
		{Target{Target: "127.0.0.1:443"}, pool, true, "invalid"},
		{Target{Target: "bad host:443"}, pool, true, "invalid"},
	}
	for _, c := range cases {
		r := probe(context.Background(), c.target, c.allow, c.pool)
		if r.Feasible || r.Reason != c.reason {
			t.Errorf("%+v: got feasible=%v reason=%q detail=%q, want %q", c.target, r.Feasible, r.Reason, r.Detail, c.reason)
		}
	}
}

func TestProbeRunsTargetsConcurrently(t *testing.T) {
	address, _ := fixture(t, true, 0)
	targets := make([]Target, MaxTargets)
	for i := range targets {
		targets[i] = Target{Target: address, ServerNames: []string{"example.com"}}
	}
	start := time.Now()
	results := Probe(context.Background(), targets, true)
	if len(results) != MaxTargets || time.Since(start) > 3*time.Second {
		t.Fatalf("%d results in %v", len(results), time.Since(start))
	}
	for _, r := range results {
		// The system pool does not trust the fixture, so only the handshake
		// properties can be asserted here.
		if r.TLSVersion != "1.3" || r.ALPN != "h2" {
			t.Fatalf("concurrent probe failed: %+v", r)
		}
	}
}
