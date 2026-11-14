package xcore

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

const guardShortID = "6ba85179e30d4fc2"

func testKeyPair(t *testing.T) (private, public string) {
	t.Helper()
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}

func guardKeys(t *testing.T) (private string, public []byte) {
	t.Helper()
	private, publicText := testKeyPair(t)
	public, e := base64.RawURLEncoding.DecodeString(publicText)
	if e != nil {
		t.Fatal(e)
	}
	return private, public
}

func testGuard(t *testing.T, private string) *realityGuard {
	t.Helper()
	g, e := newGuard(GuardSpec{Listen: "@minging-agent-test", Target: "example.com:443", ServerNames: []string{"example.com"}, PrivateKey: private, ShortIDs: []string{guardShortID}})
	if e != nil {
		t.Fatal(e)
	}
	return g
}

// helloFrom captures the ClientHello records a client writes before it waits
// for the server's reply.
func helloFrom(t *testing.T, dial func(net.Conn)) (records, message []byte) {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		dial(client)
		client.Close()
	}()
	server.SetDeadline(time.Now().Add(10 * time.Second))
	records, message, e := readClientHello(server)
	server.Close()
	if e != nil {
		t.Fatal("reading ClientHello:", e)
	}
	return records, message
}

// xrayHello is the ClientHello Xray's own REALITY client sends.
func xrayHello(t *testing.T, serverName string, public []byte, shortID string) []byte {
	t.Helper()
	id, _ := hex.DecodeString(shortID)
	_, message := helloFrom(t, func(c net.Conn) {
		config := &xreality.Config{ServerName: serverName, Fingerprint: "chrome", PublicKey: public, ShortId: id, SpiderX: "/"}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		xreality.UClient(c, config, ctx, xnet.TCPDestination(xnet.DomainAddress(serverName), 443))
	})
	return message
}

func TestGuardAuthenticatesLikeREALITY(t *testing.T) {
	private, public := guardKeys(t)
	guard := testGuard(t, private)
	if !guard.authenticate(xrayHello(t, "example.com", public, guardShortID)) {
		t.Fatal("authenticated Xray REALITY ClientHello refused")
	}
	if guard.authenticate(xrayHello(t, "example.com", public, "0011223344556677")) {
		t.Fatal("unknown short ID accepted")
	}
	if guard.authenticate(xrayHello(t, "other.example", public, guardShortID)) {
		t.Fatal("server name outside serverNames accepted")
	}
	_, otherPublic := guardKeys(t)
	if guard.authenticate(xrayHello(t, "example.com", otherPublic, guardShortID)) {
		t.Fatal("ClientHello for another key accepted")
	}
	// Ordinary TLS clients, with or without the hybrid key share REALITY
	// requires, are what probes look like: they must never pass.
	for _, curves := range [][]tls.CurveID{nil, {tls.X25519}} {
		_, plain := helloFrom(t, func(c net.Conn) {
			tls.Client(c, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true, CurvePreferences: curves}).Handshake()
		})
		if guard.authenticate(plain) {
			t.Fatalf("plain TLS ClientHello accepted (curves %v)", curves)
		}
	}
	// A clock outside maxTimeDiff is refused.
	guard.maxDiff = time.Millisecond
	hello := xrayHello(t, "example.com", public, guardShortID)
	time.Sleep(1100 * time.Millisecond)
	if guard.authenticate(hello) {
		t.Fatal("ClientHello outside maxTimeDiff accepted")
	}
}

func TestReadClientHelloReassemblesRecords(t *testing.T) {
	private, public := guardKeys(t)
	message := xrayHello(t, "example.com", public, guardShortID)
	// Split the message across three handshake records, as TLS-fragmenting
	// clients do; the guard must reassemble it exactly like REALITY.
	var records []byte
	for _, part := range [][]byte{message[:3], message[3:200], message[200:]} {
		records = append(records, 22, 3, 1, byte(len(part)>>8), byte(len(part)))
		records = append(records, part...)
	}
	gotRecords, gotMessage, e := readClientHello(bytes.NewReader(records))
	if e != nil || !bytes.Equal(gotMessage, message) || !bytes.Equal(gotRecords, records) {
		t.Fatalf("reassembly failed: %v", e)
	}
	if !testGuard(t, private).authenticate(gotMessage) {
		t.Fatal("reassembled ClientHello refused")
	}
	for _, bad := range [][]byte{{23, 3, 3, 0, 1, 0}, {22, 3, 1, 0, 4, 2, 0, 0, 0}, []byte("GET / HTTP/1.1\r\n\r\n")} {
		if _, _, e := readClientHello(bytes.NewReader(bad)); e == nil {
			t.Fatalf("non-ClientHello %q accepted", bad)
		}
	}
}

func TestBuildRejectFallbackRoutesTargetThroughGuard(t *testing.T) {
	in := inbound()
	private, _ := testKeyPair(t)
	in.Secrets.RealityPrivateKey = private
	in.Config.RealityRejectFallback = true
	in.Config.RealityMaxTimeDiff = 90000
	raw, e := Build(in, "")
	if e != nil {
		t.Fatal(e)
	}
	var document struct {
		Guard    GuardSpec `json:"mingingRealityGuard"`
		Inbounds []struct {
			StreamSettings struct {
				RealitySettings struct {
					Target string `json:"target"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if e = json.Unmarshal(raw, &document); e != nil {
		t.Fatal(e)
	}
	g := document.Guard
	if !strings.HasPrefix(g.Listen, "@minging-agent/reality/7/") || document.Inbounds[0].StreamSettings.RealitySettings.Target != g.Listen ||
		g.Target != "www.example.com:443" || g.ShortIDs[0] != "0123abcd" || g.ServerNames[0] != "www.example.com" || g.MaxTimeDiff != 90000 || g.PrivateKey != private {
		t.Fatalf("guard not wired: %s", raw)
	}
	if _, e = Load(raw); e != nil {
		t.Fatal("Xray rejected the guarded configuration:", e)
	}
	instance, e := New(context.Background(), raw, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	if instance.guard == nil {
		t.Fatal("guard not created")
	}
	instance.Close()
	// Unchanged inbounds keep their address; a new target gets a new one.
	again, _ := Build(in, "")
	in.Config.RealityTarget = "www.example.org:443"
	moved, _ := Build(in, "")
	if !bytes.Equal(raw, again) || bytes.Contains(moved, []byte(g.Listen)) {
		t.Fatal("guard address must be stable per inbound and target")
	}
	in.Config.RealityRejectFallback = false
	plain, _ := Build(in, "")
	if bytes.Contains(plain, []byte(guardDocumentKey)) || !bytes.Contains(plain, []byte(`"target":"www.example.org:443"`)) {
		t.Fatalf("guard present without reject fallback: %s", plain)
	}
}

func TestGuardRefusesWithoutContactingTarget(t *testing.T) {
	private, public := guardKeys(t)
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	// The guard's start-up measurement of the target also connects here, so
	// arrivals are matched by content.
	accepted := make(chan []byte, 64)
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				records, _, _ := readClientHello(c)
				accepted <- records
			}()
		}
	}()
	spec := GuardSpec{Listen: "@minging-agent-test-" + strconv.FormatInt(time.Now().UnixNano(), 36), Target: target.Addr().String(), ServerNames: []string{"example.com"}, PrivateKey: private, ShortIDs: []string{guardShortID}}
	guard, e := newGuard(spec)
	if e != nil {
		t.Fatal(e)
	}
	if e = guard.Start(); e != nil {
		t.Skip("abstract sockets unavailable:", e)
	}
	defer guard.Close()
	send := func(records []byte) []byte {
		c, e := net.Dial("unix", spec.Listen)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write(records)
		reply := make([]byte, 64)
		n, _ := c.Read(reply)
		return reply[:n]
	}
	plainRecords, _ := helloFrom(t, func(c net.Conn) {
		tls.Client(c, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}).Handshake()
	})
	arrived := func(want []byte, wait time.Duration) bool {
		deadline := time.After(wait)
		for {
			select {
			case got := <-accepted:
				if bytes.Equal(got, want) {
					return true
				}
			case <-deadline:
				return false
			}
		}
	}
	if reply := send(plainRecords); len(reply) != 0 {
		t.Fatalf("refused connection received %d bytes", len(reply))
	}
	if arrived(plainRecords, 500*time.Millisecond) {
		t.Fatal("unauthenticated ClientHello reached the target")
	}
	id, _ := hex.DecodeString(guardShortID)
	authenticated, _ := helloFrom(t, func(c net.Conn) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		xreality.UClient(c, &xreality.Config{ServerName: "example.com", Fingerprint: "chrome", PublicKey: public, ShortId: id, SpiderX: "/"}, ctx, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	})
	c, e := net.Dial("unix", spec.Listen)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.Write(authenticated)
	if !arrived(authenticated, 5*time.Second) {
		t.Fatal("authenticated ClientHello did not reach the target unchanged")
	}
}
