// Package realityprobe measures REALITY target candidates from this node: the
// TLS handshake REALITY borrows, how long it takes from here, and whether the
// certificate covers the server names clients will send.
package realityprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/egress"
)

const (
	// MaxTargets bounds one request; MaxNames bounds names checked per target.
	MaxTargets     = 16
	MaxNames       = 8
	attempts       = 2
	attemptTimeout = 4 * time.Second
	maxCertNames   = 20
)

// Target is one candidate: host:port and the server names clients would send.
// The first name is the SNI used for the measurement (the host when empty).
type Target struct {
	Target      string   `json:"target"`
	ServerNames []string `json:"server_names"`
}

// Result reports one candidate. Reason is a stable code: invalid, private,
// dns, connect, handshake, tls_version, alpn, curve or certificate.
type Result struct {
	Target         string   `json:"target"`
	ServerName     string   `json:"server_name"`
	Address        string   `json:"address,omitempty"`
	Feasible       bool     `json:"feasible"`
	Reason         string   `json:"reason,omitempty"`
	Detail         string   `json:"detail,omitempty"`
	LatencyMS      int64    `json:"latency_ms"` // best TCP connect + TLS handshake
	ConnectMS      int64    `json:"connect_ms"`
	DNSMS          int64    `json:"dns_ms"`
	TLSVersion     string   `json:"tls_version,omitempty"`
	ALPN           string   `json:"alpn,omitempty"`
	Curve          string   `json:"curve,omitempty"`
	CertValid      bool     `json:"cert_valid"`
	CertChainBytes int      `json:"cert_chain_bytes"`
	CertSubject    string   `json:"cert_subject,omitempty"`
	CertIssuer     string   `json:"cert_issuer,omitempty"`
	NotAfter       string   `json:"not_after,omitempty"`
	VerifiedNames  []string `json:"verified_names"`
	CertNames      []string `json:"certificate_names"`
}

// Probe measures every target concurrently. allowPrivate exists for package
// tests that reach loopback fixtures; the agent never sets it.
func Probe(ctx context.Context, targets []Target, allowPrivate bool) []Result {
	results := make([]Result, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = probe(ctx, t, allowPrivate, nil)
		}()
	}
	wg.Wait()
	return results
}

func names(t Target, host string) []string {
	out := []string{}
	for _, n := range t.ServerNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && len(out) < MaxNames && !contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) == 0 && net.ParseIP(host) == nil {
		out = append(out, strings.ToLower(host))
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func validHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func elapsed(start time.Time) int64 {
	ms := time.Since(start).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return ms
}

// probe measures one target. roots replaces the system pool in tests.
func probe(ctx context.Context, t Target, allowPrivate bool, roots *x509.CertPool) Result {
	r := Result{Target: strings.TrimSpace(t.Target), VerifiedNames: []string{}, CertNames: []string{}}
	host, port, e := net.SplitHostPort(r.Target)
	number, _ := strconv.Atoi(port)
	if e != nil || !validHost(host) || number < 1 || number > 65535 {
		r.Reason = "invalid"
		return r
	}
	sni := names(t, host)
	if len(sni) == 0 {
		r.Reason = "invalid"
		r.Detail = "server name required for an IP target"
		return r
	}
	for _, n := range sni {
		if !validHost(n) || net.ParseIP(n) != nil {
			r.Reason = "invalid"
			return r
		}
	}
	r.ServerName = sni[0]
	resolveCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	start := time.Now()
	ip, e := egress.Resolve(resolveCtx, host, allowPrivate)
	cancel()
	r.DNSMS = elapsed(start)
	if e != nil {
		r.Reason = "dns"
		if strings.Contains(e.Error(), "private") {
			r.Reason = "private"
		}
		return r
	}
	r.Address = ip.String()
	address := net.JoinHostPort(ip.String(), port)
	var state *tls.ConnectionState
	for range attempts {
		s, connect, total, reason, detail := handshake(ctx, address, sni[0])
		if reason != "" {
			if state == nil {
				r.Reason, r.Detail = reason, detail
			}
			continue
		}
		if state == nil {
			state = s
		}
		if r.LatencyMS == 0 || total < r.LatencyMS {
			r.LatencyMS, r.ConnectMS = total, connect
		}
	}
	if state == nil {
		return r
	}
	r.Reason, r.Detail = "", ""
	r.TLSVersion = versionName(state.Version)
	r.ALPN = state.NegotiatedProtocol
	r.Curve = curveName(state.CurveID)
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		for _, c := range state.PeerCertificates {
			r.CertChainBytes += len(c.Raw)
		}
		r.CertSubject = leaf.Subject.CommonName
		if r.CertSubject == "" && len(leaf.DNSNames) > 0 {
			r.CertSubject = leaf.DNSNames[0]
		}
		if len(leaf.Issuer.Organization) > 0 {
			r.CertIssuer = leaf.Issuer.Organization[0]
		} else {
			r.CertIssuer = leaf.Issuer.CommonName
		}
		r.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		for _, n := range leaf.DNSNames {
			if len(r.CertNames) < maxCertNames && !strings.HasPrefix(n, "*.") && !contains(r.CertNames, strings.ToLower(n)) {
				r.CertNames = append(r.CertNames, strings.ToLower(n))
			}
		}
		opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()}
		for _, c := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		if _, e := leaf.Verify(opts); e == nil {
			for _, n := range sni {
				if leaf.VerifyHostname(n) == nil {
					r.VerifiedNames = append(r.VerifiedNames, n)
				}
			}
		} else {
			r.Detail = "certificate chain not trusted"
		}
		r.CertValid = contains(r.VerifiedNames, sni[0])
	}
	switch {
	case state.Version != tls.VersionTLS13:
		r.Reason = "tls_version"
	case state.NegotiatedProtocol != "h2":
		r.Reason = "alpn"
	case state.CurveID != tls.X25519 && state.CurveID != tls.X25519MLKEM768:
		r.Reason = "curve"
	case !r.CertValid:
		r.Reason = "certificate"
	default:
		r.Feasible = true
	}
	return r
}

// handshake dials the resolved address with REALITY's key exchange offers and
// returns the connection state and timings in milliseconds.
func handshake(ctx context.Context, address, sni string) (*tls.ConnectionState, int64, int64, string, string) {
	attempt, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	start := time.Now()
	conn, e := (&net.Dialer{}).DialContext(attempt, "tcp", address)
	if e != nil {
		return nil, 0, 0, "connect", shortError(e)
	}
	defer conn.Close()
	connect := elapsed(start)
	client := tls.Client(conn, &tls.Config{
		ServerName: sni,
		// The chain and names are verified afterwards so failures can be
		// reported in detail instead of as a bare handshake error.
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	if e = client.HandshakeContext(attempt); e != nil {
		return nil, connect, 0, "handshake", shortError(e)
	}
	total := elapsed(start)
	state := client.ConnectionState()
	return &state, connect, total, "", ""
}

func shortError(e error) string {
	var dns *net.DNSError
	switch {
	case errors.Is(e, context.DeadlineExceeded):
		return "timeout"
	case errors.As(e, &dns):
		return "dns error"
	}
	s := e.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	}
	return "other"
}

func curveName(id tls.CurveID) string {
	switch id {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case 0:
		return ""
	}
	return "0x" + strconv.FormatUint(uint64(id), 16)
}
