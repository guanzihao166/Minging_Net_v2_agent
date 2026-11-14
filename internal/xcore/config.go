// Package xcore runs VLESS and Trojan inbounds on an embedded Xray-core.
// Xray is the reference implementation of REALITY, XHTTP and VLESS Encryption;
// every proxied byte still passes the shared lease/grant tracker before it moves.
package xcore

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
)

// Supports reports whether protocol runs on this core. VMess stays on sing-box:
// Xray 26 accepts only AES-128-GCM/ChaCha20 VMess, while sing-box clients turn
// "auto" over TLS into "zero" and would be refused.
func Supports(protocol string) bool {
	return protocol == "vless" || protocol == "trojan"
}

var (
	shortIDPattern = regexp.MustCompile(`^[0-9a-f]{0,16}$`)
	keyPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	ticketPattern  = regexp.MustCompile(`^[0-9]{1,6}(-[0-9]{1,6})?s$`)
	paddingPattern = regexp.MustCompile(`^[0-9]{1,3}-[0-9]{1,6}-[0-9]{1,6}$`)
	seedPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
)

// ValidDecryption checks a VLESS Encryption server string before Xray parses
// it (Xray's parser panics on some malformed inputs):
// mlkem768x25519plus.<native|xorpub|random>.<ticket>[.padding...].<key>
// where key is an X25519 private key (32 bytes) or ML-KEM-768 seed (64 bytes).
func ValidDecryption(s string) bool {
	b := strings.Split(s, ".")
	if len(b) < 4 || len(b) > 40 || b[0] != "mlkem768x25519plus" || !ticketPattern.MatchString(b[2]) {
		return false
	}
	switch b[1] {
	case "native", "xorpub", "random":
	default:
		return false
	}
	for _, p := range b[3 : len(b)-1] {
		if !paddingPattern.MatchString(p) {
			return false
		}
	}
	key := b[len(b)-1]
	return keyPattern.MatchString(key) || seedPattern.MatchString(key)
}

// xhttpServerKeys are the XHTTP "extra" members that affect the server or must
// match on both ends. Client-only members (xmux, downloadSettings) are dropped.
var xhttpServerKeys = map[string]bool{
	"headers": true, "xPaddingBytes": true, "xPaddingObfsMode": true, "xPaddingKey": true, "xPaddingHeader": true,
	"xPaddingPlacement": true, "xPaddingMethod": true, "uplinkHTTPMethod": true, "sessionIDPlacement": true,
	"sessionIDKey": true, "sessionIDTable": true, "sessionIDLength": true, "seqPlacement": true, "seqKey": true,
	"uplinkDataPlacement": true, "uplinkDataKey": true, "uplinkChunkSize": true, "noGRPCHeader": true,
	"noSSEHeader": true, "scMaxEachPostBytes": true, "scMinPostsIntervalMs": true, "scMaxBufferedPosts": true,
	"scStreamUpServerSecs": true, "serverMaxHeaderBytes": true,
}

// Transport normalizes the stored transport name to Xray's method name.
func Transport(name string) string {
	switch name {
	case "", "tcp", "raw":
		return "raw"
	}
	return name
}

func pemLines(s string) []string {
	return strings.Split(strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")), "\n")
}

// Build renders one inbound as a complete Xray JSON configuration without
// outbounds; the runtime attaches the metered egress handler itself.
func Build(in wire.Inbound, tlsDirectory string) ([]byte, error) {
	if !Supports(in.Protocol) {
		return nil, fmt.Errorf("unsupported protocol")
	}
	if in.ID < 1 || in.Port < 1024 || in.Port > 65535 || net.ParseIP(in.ListenHost) == nil || len(in.Users) > 100000 {
		return nil, fmt.Errorf("invalid inbound")
	}
	c := in.Config
	security := c.EffectiveSecurity()
	transport := Transport(c.Transport)
	switch transport {
	case "raw", "ws", "grpc", "httpupgrade":
	case "xhttp":
		if in.Protocol != "vless" {
			return nil, fmt.Errorf("XHTTP is offered for VLESS only")
		}
	default:
		return nil, fmt.Errorf("unsupported transport")
	}
	decryption := "none"
	if in.Protocol == "vless" && in.Secrets.Decryption != "" && in.Secrets.Decryption != "none" {
		if !ValidDecryption(in.Secrets.Decryption) {
			return nil, fmt.Errorf("invalid VLESS decryption")
		}
		decryption = in.Secrets.Decryption
	}
	switch security {
	case "tls":
	case "reality":
		if transport != "raw" && transport != "xhttp" && transport != "grpc" {
			return nil, fmt.Errorf("REALITY supports VLESS/Trojan over RAW, XHTTP or gRPC")
		}
	case "none":
		// Plain VLESS is accepted only when VLESS Encryption protects it.
		if in.Protocol != "vless" || decryption == "none" {
			return nil, fmt.Errorf("security none requires VLESS Encryption")
		}
	default:
		return nil, fmt.Errorf("unsupported security")
	}
	if c.Flow != "" {
		if in.Protocol != "vless" || c.Flow != "xtls-rprx-vision" {
			return nil, fmt.Errorf("unsupported flow")
		}
		if decryption == "none" && (transport != "raw" || security == "none") {
			return nil, fmt.Errorf("Vision needs RAW with TLS/REALITY, or VLESS Encryption")
		}
	}
	tag := "inbound-" + strconv.FormatInt(in.ID, 10)
	clients := make([]map[string]any, 0, len(in.Users))
	seen := map[int64]bool{}
	for _, u := range in.Users {
		if u.ID < 1 || u.Epoch < 1 || u.SpeedMbps < 1 || u.MaxConnections < 1 || seen[u.ID] {
			return nil, fmt.Errorf("invalid user rights")
		}
		seen[u.ID] = true
		email := strconv.FormatInt(u.ID, 10)
		switch in.Protocol {
		case "vless":
			if u.Credential.UUID == "" {
				return nil, fmt.Errorf("missing UUID")
			}
			entry := map[string]any{"id": u.Credential.UUID, "email": email}
			if c.Flow != "" {
				entry["flow"] = c.Flow
			}
			clients = append(clients, entry)
		case "trojan":
			if u.Credential.Password == "" {
				return nil, fmt.Errorf("missing password")
			}
			clients = append(clients, map[string]any{"password": u.Credential.Password, "email": email})
		}
	}
	settings := map[string]any{"clients": clients}
	if in.Protocol == "vless" {
		settings["decryption"] = decryption
	}
	stream := map[string]any{"network": transport, "security": security}
	var guard *GuardSpec
	switch transport {
	case "raw":
		stream["rawSettings"] = map[string]any{}
	case "ws":
		if !strings.HasPrefix(c.Path, "/") {
			return nil, fmt.Errorf("WebSocket path must start with /")
		}
		stream["wsSettings"] = map[string]any{"path": c.Path, "host": c.Host}
	case "httpupgrade":
		if !strings.HasPrefix(c.Path, "/") {
			return nil, fmt.Errorf("HTTPUpgrade path must start with /")
		}
		stream["httpupgradeSettings"] = map[string]any{"path": c.Path, "host": c.Host}
	case "grpc":
		if c.ServiceName == "" {
			return nil, fmt.Errorf("gRPC service name required")
		}
		stream["grpcSettings"] = map[string]any{"serviceName": c.ServiceName}
	case "xhttp":
		if !strings.HasPrefix(c.Path, "/") {
			return nil, fmt.Errorf("XHTTP path must start with /")
		}
		mode := c.XHTTPMode
		switch mode {
		case "":
			mode = "auto"
		case "auto", "packet-up", "stream-up", "stream-one":
		default:
			return nil, fmt.Errorf("unsupported XHTTP mode")
		}
		x := map[string]any{"path": c.Path, "host": c.Host, "mode": mode}
		if len(c.XHTTPExtra) > 0 && string(c.XHTTPExtra) != "null" {
			var extra map[string]json.RawMessage
			if e := json.Unmarshal(c.XHTTPExtra, &extra); e != nil || len(c.XHTTPExtra) > 8192 {
				return nil, fmt.Errorf("invalid XHTTP extra")
			}
			server := map[string]json.RawMessage{}
			for k, v := range extra {
				if xhttpServerKeys[k] {
					server[k] = v
				}
			}
			if len(server) > 0 {
				x["extra"] = server
			}
		}
		stream["xhttpSettings"] = x
	}
	switch security {
	case "tls":
		cert, key := in.Secrets.Certificate, in.Secrets.PrivateKey
		if in.Secrets.LocalTLS {
			b, e := os.ReadFile(filepath.Join(tlsDirectory, "default.crt"))
			if e != nil {
				return nil, fmt.Errorf("local TLS certificate is missing")
			}
			k, e := os.ReadFile(filepath.Join(tlsDirectory, "default.key"))
			if e != nil {
				return nil, fmt.Errorf("local TLS key is missing")
			}
			cert, key = string(b), string(k)
		}
		if cert == "" || key == "" {
			return nil, fmt.Errorf("TLS certificate required")
		}
		minVersion := c.TLSMinVersion
		switch minVersion {
		case "":
			minVersion = "1.2"
		case "1.2", "1.3":
		default:
			return nil, fmt.Errorf("unsupported TLS minimum version")
		}
		t := map[string]any{"serverName": c.ServerName, "minVersion": minVersion, "rejectUnknownSni": c.RejectUnknownSNI, "certificates": []any{map[string]any{"certificate": pemLines(cert), "key": pemLines(key)}}}
		if len(c.ALPN) > 0 {
			t["alpn"] = c.ALPN
		}
		stream["tlsSettings"] = t
	case "reality":
		names := c.RealityServerNames
		if len(names) == 0 && c.ServerName != "" {
			names = []string{c.ServerName}
		}
		host, port, e := net.SplitHostPort(c.RealityTarget)
		if e != nil || host == "" || port == "" || len(names) == 0 {
			return nil, fmt.Errorf("REALITY target host:port and server names required")
		}
		if !keyPattern.MatchString(in.Secrets.RealityPrivateKey) || !shortIDPattern.MatchString(c.RealityShortID) || len(c.RealityShortID)%2 != 0 {
			return nil, fmt.Errorf("invalid REALITY key or short ID")
		}
		target := c.RealityTarget
		if c.RealityRejectFallback {
			// REALITY dials the guard, which authenticates the mirrored
			// ClientHello and only then reaches the real target.
			guard = &GuardSpec{Listen: guardAddress(in.ListenHost, in.Port, in.ID, c.RealityTarget), Target: c.RealityTarget, ServerNames: names, PrivateKey: in.Secrets.RealityPrivateKey, ShortIDs: []string{c.RealityShortID}, MaxTimeDiff: c.RealityMaxTimeDiff}
			target = guard.Listen
		}
		r := map[string]any{"target": target, "serverNames": names, "privateKey": in.Secrets.RealityPrivateKey, "shortIds": []string{c.RealityShortID},
			// Pinning 0.0.0 keeps non-Xray clients (mihomo, sing-box) admissible
			// even if a future core default raises the minimum client version.
			"minClientVer": "0.0.0"}
		if c.RealityMaxTimeDiff > 0 {
			r["maxTimeDiff"] = c.RealityMaxTimeDiff
		}
		if in.Secrets.RealityMldsa65Seed != "" {
			if !keyPattern.MatchString(in.Secrets.RealityMldsa65Seed) {
				return nil, fmt.Errorf("invalid REALITY ML-DSA-65 seed")
			}
			r["mldsa65Seed"] = in.Secrets.RealityMldsa65Seed
		}
		stream["realitySettings"] = r
	}
	inbound := map[string]any{"tag": tag, "listen": in.ListenHost, "port": in.Port, "protocol": in.Protocol, "settings": settings, "streamSettings": stream}
	level := map[string]any{"handshake": 4, "connIdle": 300, "uplinkOnly": 1, "downlinkOnly": 1, "bufferSize": 64}
	document := map[string]any{"policy": map[string]any{"levels": map[string]any{"0": level}}, "inbounds": []any{inbound}, "outbounds": []any{}}
	if guard != nil {
		document[guardDocumentKey] = guard
	}
	return json.Marshal(document)
}
