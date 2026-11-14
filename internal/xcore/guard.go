package xcore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/reality"
	"golang.org/x/crypto/cryptobyte"
)

// A REALITY server relays every connection that fails authentication to its
// target, so probes see the real site. With RealityRejectFallback the inbound's
// target is this guard instead: it repeats REALITY's own authentication on the
// ClientHello that REALITY mirrors to the target, closes refused connections
// without ever contacting the real target, and lets authenticated handshakes
// borrow the real target's handshake exactly as before.

// guardDocumentKey carries the guard next to the Xray document; Xray ignores
// unknown top-level keys and New reads it back.
const guardDocumentKey = "mingingRealityGuard"

const (
	recordHeaderLen = 5
	maxRecordLen    = 16384 + 2048
	maxHelloLen     = 65536
	mlkemShareLen   = 1184 + 32 // ML-KEM-768 encapsulation key followed by X25519
	groupX25519     = 29
	groupHybrid     = 4588 // X25519MLKEM768
	helloTimeout    = 10 * time.Second
	dialTimeout     = 10 * time.Second
	// REALITY closes its target connection once the authenticated handshake is
	// done; this only bounds connections it abandons.
	relayLifetime = time.Minute
	// detectionDeadline bounds how long authenticated handshakes wait for the
	// copied target measurements before REALITY proceeds without them.
	detectionDeadline = 20 * time.Second
)

// GuardSpec is what the guard needs to authenticate like the REALITY server it
// fronts. The agent pins minClientVer 0.0.0 and sets no maximum, so client
// versions are never refused and are not part of the check.
type GuardSpec struct {
	X25519Only  bool     `json:"x25519Only,omitempty"`
	Listen      string   `json:"listen"`
	Target      string   `json:"target"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
	MaxTimeDiff int64    `json:"maxTimeDiff"` // milliseconds, 0 = unlimited
}

// guardAddress names an inbound's abstract socket. It stays the same while the
// inbound and its target are unchanged, so unchanged configurations are not
// restarted, and changes with the target, because REALITY caches target
// measurements under the address it dials.
func guardAddress(listenHost string, port int, id int64, target string) string {
	sum := sha256.Sum256([]byte(listenHost + "\x00" + strconv.Itoa(port) + "\x00" + strconv.FormatInt(id, 10) + "\x00" + target))
	return "@minging-agent/reality/" + strconv.FormatInt(id, 10) + "/" + hex.EncodeToString(sum[:8])
}

type realityGuard struct {
	spec     GuardSpec
	key      *ecdh.PrivateKey
	names    map[string]bool
	shortIDs map[[8]byte]bool
	maxDiff  time.Duration
	dialer   net.Dialer

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	closed   bool
}

func newGuard(spec GuardSpec) (*realityGuard, error) {
	if !strings.HasPrefix(spec.Listen, "@") || len(spec.Listen) > 100 {
		return nil, errors.New("guard must listen on an abstract socket")
	}
	if host, port, e := net.SplitHostPort(spec.Target); e != nil || host == "" || port == "" {
		return nil, errors.New("guard target must be host:port")
	}
	raw, e := base64.RawURLEncoding.DecodeString(spec.PrivateKey)
	if e != nil || len(raw) != 32 {
		return nil, errors.New("invalid REALITY private key")
	}
	key, e := ecdh.X25519().NewPrivateKey(raw)
	if e != nil {
		return nil, errors.New("invalid REALITY private key")
	}
	if len(spec.ServerNames) == 0 || len(spec.ShortIDs) == 0 || spec.MaxTimeDiff < 0 {
		return nil, errors.New("guard needs server names and short IDs")
	}
	g := &realityGuard{spec: spec, key: key, names: map[string]bool{}, shortIDs: map[[8]byte]bool{}, maxDiff: time.Duration(spec.MaxTimeDiff) * time.Millisecond, dialer: net.Dialer{Timeout: dialTimeout}, conns: map[net.Conn]struct{}{}}
	for _, name := range spec.ServerNames {
		g.names[name] = true
	}
	for _, s := range spec.ShortIDs {
		// Xray decodes short IDs into eight bytes, zero-padded on the right.
		var id [8]byte
		if len(s) > 16 || len(s)%2 != 0 {
			return nil, errors.New("invalid REALITY short ID")
		}
		if _, e := hex.Decode(id[:], []byte(s)); e != nil {
			return nil, errors.New("invalid REALITY short ID")
		}
		g.shortIDs[id] = true
	}
	return g, nil
}

// Start listens before Xray starts, so Xray's own target measurement finds the
// copied results instead of probing through the guard, which would refuse it.
func (g *realityGuard) Start() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errors.New("REALITY guard closed")
	}
	if g.listener != nil {
		return nil
	}
	l, e := net.Listen("unix", g.spec.Listen)
	if e != nil {
		return fmt.Errorf("REALITY guard listen failed: %w", e)
	}
	g.listener = l
	primeDetection(g.spec.Listen, g.spec.Target, g.spec.ServerNames)
	go g.serve(l)
	return nil
}

func (g *realityGuard) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	l, conns := g.listener, g.conns
	g.conns = nil
	g.mu.Unlock()
	if l != nil {
		l.Close()
	}
	for c := range conns {
		c.Close()
	}
	return nil
}

func (g *realityGuard) track(c net.Conn) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.conns[c] = struct{}{}
	return true
}

func (g *realityGuard) untrack(c net.Conn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.conns != nil {
		delete(g.conns, c)
	}
}

func (g *realityGuard) serve(l net.Listener) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go g.handle(c)
	}
}

// handle receives REALITY's side of one client connection. REALITY mirrors the
// client's ClientHello here before it decides; the guard decides the same way.
func (g *realityGuard) handle(inner net.Conn) {
	defer inner.Close()
	if !g.track(inner) {
		return
	}
	defer g.untrack(inner)
	inner.SetDeadline(time.Now().Add(helloTimeout))
	records, hello, e := readClientHello(inner)
	if e != nil || !g.authenticate(hello) {
		// Refused before the target is contacted: nothing is relayed, and
		// REALITY closes the client connection when this side ends.
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	upstream, e := g.dialer.DialContext(ctx, "tcp", g.spec.Target)
	cancel()
	if e != nil {
		return
	}
	defer upstream.Close()
	if !g.track(upstream) {
		return
	}
	defer g.untrack(upstream)
	deadline := time.Now().Add(relayLifetime)
	inner.SetDeadline(deadline)
	upstream.SetDeadline(deadline)
	if _, e = upstream.Write(records); e != nil {
		return
	}
	go func() {
		// After an authenticated ClientHello REALITY only reads the target's
		// handshake. Any further byte means REALITY is relaying a connection
		// it refused, so the relay ends here.
		var b [1]byte
		inner.Read(b[:])
		upstream.Close()
		inner.Close()
	}()
	io.Copy(inner, upstream)
}

// readClientHello reads whole TLS records until they hold one ClientHello and
// returns the records as received together with the reassembled message.
func readClientHello(r io.Reader) (records, message []byte, err error) {
	header := make([]byte, recordHeaderLen)
	for {
		if _, err = io.ReadFull(r, header); err != nil {
			return nil, nil, err
		}
		n := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || n == 0 || n > maxRecordLen {
			return nil, nil, errors.New("not a TLS handshake record")
		}
		start := len(records)
		records = append(records, header...)
		records = append(records, make([]byte, n)...)
		if _, err = io.ReadFull(r, records[start+recordHeaderLen:]); err != nil {
			return nil, nil, err
		}
		message = append(message, records[start+recordHeaderLen:]...)
		if len(message) >= 4 {
			total := 4 + (int(message[1])<<16 | int(message[2])<<8 | int(message[3]))
			if message[0] != 1 || total > maxHelloLen {
				return nil, nil, errors.New("not a ClientHello")
			}
			if len(message) >= total {
				return records, message[:total], nil
			}
		}
		if len(records) > maxHelloLen+64*recordHeaderLen {
			return nil, nil, errors.New("ClientHello too long")
		}
	}
}

type keyShare struct {
	group uint16
	data  []byte
}

type clientHello struct {
	random     []byte
	sessionID  []byte
	serverName string
	tls13      bool
	keyShares  []keyShare
}

// parseClientHello reads the fields REALITY authenticates from a ClientHello
// handshake message (type, uint24 length, body), with the same structural
// rules as REALITY's parser for them.
func parseClientHello(message []byte) (clientHello, bool) {
	var h clientHello
	s := cryptobyte.String(message)
	var kind uint8
	var body cryptobyte.String
	if !s.ReadUint8(&kind) || kind != 1 || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() {
		return h, false
	}
	var legacy uint16
	var session, suites, compression, extensions cryptobyte.String
	if !body.ReadUint16(&legacy) || !body.ReadBytes(&h.random, 32) || !body.ReadUint8LengthPrefixed(&session) ||
		!body.ReadUint16LengthPrefixed(&suites) || !body.ReadUint8LengthPrefixed(&compression) {
		return h, false
	}
	h.sessionID = session
	if body.Empty() {
		return h, true
	}
	if !body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return h, false
	}
	seen := map[uint16]bool{}
	for !extensions.Empty() {
		var kind uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&kind) || !extensions.ReadUint16LengthPrefixed(&data) || seen[kind] {
			return h, false
		}
		seen[kind] = true
		switch kind {
		case 0: // server_name
			var names cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&names) || names.Empty() {
				return h, false
			}
			for !names.Empty() {
				var nameType uint8
				var name cryptobyte.String
				if !names.ReadUint8(&nameType) || !names.ReadUint16LengthPrefixed(&name) || name.Empty() {
					return h, false
				}
				if nameType != 0 {
					continue
				}
				if h.serverName != "" || strings.HasSuffix(string(name), ".") {
					return h, false
				}
				h.serverName = string(name)
			}
		case 43: // supported_versions
			var versions cryptobyte.String
			if !data.ReadUint8LengthPrefixed(&versions) || versions.Empty() {
				return h, false
			}
			for !versions.Empty() {
				var v uint16
				if !versions.ReadUint16(&v) {
					return h, false
				}
				// REALITY serves TLS 1.3 and 1.2 and prefers 1.3 whenever offered.
				h.tls13 = h.tls13 || v == 0x0304
			}
		case 51: // key_share
			var shares cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&shares) {
				return h, false
			}
			for !shares.Empty() {
				var ks keyShare
				var key cryptobyte.String
				if !shares.ReadUint16(&ks.group) || !shares.ReadUint16LengthPrefixed(&key) || len(key) == 0 {
					return h, false
				}
				ks.data = key
				h.keyShares = append(h.keyShares, ks)
			}
		}
	}
	return h, true
}

// authenticate repeats REALITY's server-side check: TLS 1.3, a configured SNI,
// the selected hybrid or classic X25519 key-share policy, and a session ID
// that opens under the shared key with an accepted short ID and time.
func (g *realityGuard) authenticate(message []byte) bool {
	h, ok := parseClientHello(message)
	if !ok || !h.tls13 || !g.names[h.serverName] || len(h.sessionID) != 32 {
		return false
	}
	var peer, hybrid []byte
	for _, ks := range h.keyShares {
		if ks.group == groupHybrid && len(ks.data) == mlkemShareLen {
			if hybrid != nil {
				peer = nil
				hybrid = nil
				break
			}
			hybrid = ks.data[mlkemShareLen-32:]
			continue
		}
		if ks.group == groupX25519 && len(ks.data) == 32 {
			if peer != nil {
				peer = nil
				hybrid = nil
				break
			}
			peer = ks.data
			break
		}
	}
	if hybrid == nil && !g.spec.X25519Only {
		return false
	}
	if g.spec.X25519Only && peer == nil {
		return false
	}
	if peer == nil {
		peer = hybrid
	}
	public, e := ecdh.X25519().NewPublicKey(peer)
	if e != nil {
		return false
	}
	shared, e := g.key.ECDH(public)
	if e != nil {
		return false
	}
	authKey, e := hkdf.Key(sha256.New, shared, h.random[:20], "REALITY", 32)
	if e != nil {
		return false
	}
	block, e := aes.NewCipher(authKey)
	if e != nil {
		return false
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return false
	}
	// The session ID sits at a fixed offset and is authenticated as zeros.
	const sessionAt = 4 + 2 + 32 + 1
	aad := slices.Clone(message)
	clear(aad[sessionAt : sessionAt+32])
	plain, e := aead.Open(nil, h.random[20:], h.sessionID, aad)
	if e != nil || len(plain) != 16 {
		return false
	}
	if g.maxDiff > 0 {
		sent := time.Unix(int64(binary.BigEndian.Uint32(plain[4:8])), 0)
		if time.Since(sent).Abs() > g.maxDiff {
			return false
		}
	}
	var id [8]byte
	copy(id[:], plain[8:16])
	return g.shortIDs[id]
}

// primeDetection publishes REALITY's measurements of the real target (post-
// handshake record sizes and change_cipher_spec tolerance) under the guard
// address, the target Xray's REALITY dials and looks them up by. Reserving the
// keys first keeps Xray from measuring through the guard.
func primeDetection(listen, target string, names []string) {
	key := func(dest, sni string, alpn int) string { return dest + " " + sni + " " + strconv.Itoa(alpn) }
	type pending struct {
		guard, real string
		lens, css   bool
	}
	var waiting []*pending
	for _, sni := range names {
		for alpn := range 3 {
			guard := key(listen, sni, alpn)
			if _, loaded := reality.GlobalPostHandshakeRecordsLens.LoadOrStore(guard, false); !loaded {
				waiting = append(waiting, &pending{guard: guard, real: key(target, sni, alpn)})
			}
		}
	}
	if len(waiting) == 0 {
		return
	}
	config := &reality.Config{Type: "tcp", Dest: target, ServerNames: map[string]bool{}}
	for _, sni := range names {
		config.ServerNames[sni] = true
	}
	reality.DetectPostHandshakeRecordsLens(config)
	go func() {
		deadline := time.Now().Add(detectionDeadline)
		for {
			done := true
			for _, p := range waiting {
				if !p.lens {
					if v, ok := reality.GlobalPostHandshakeRecordsLens.Load(p.real); ok {
						if lens, ok := v.([]int); ok {
							reality.GlobalPostHandshakeRecordsLens.Store(p.guard, lens)
							p.lens = true
						}
					}
				}
				if !p.css {
					if v, ok := reality.GlobalMaxCSSMsgCount.Load(p.real); ok {
						reality.GlobalMaxCSSMsgCount.Store(p.guard, v)
						p.css = true
					}
				}
				done = done && p.lens && p.css
			}
			if done {
				return
			}
			if time.Now().After(deadline) {
				for _, p := range waiting {
					if !p.lens {
						// Like REALITY after a failed measurement: proceed without
						// post-handshake records rather than wait forever.
						reality.GlobalPostHandshakeRecordsLens.CompareAndSwap(p.guard, false, []int{})
					}
				}
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
}
