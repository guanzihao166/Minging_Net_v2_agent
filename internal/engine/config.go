package engine

import (
	"encoding/json"
	"fmt"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/xcore"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Core names select the protocol implementation serving an inbound.
const (
	coreSingBox = "sing-box"
	coreXray    = "xray"
)

// Plan selects the core for an inbound and renders its configuration.
// VLESS and Trojan run on Xray-core, which implements REALITY, XHTTP, VLESS
// Encryption and Vision upstream; the remaining protocols use sing-box.
func Plan(in wire.Inbound, tlsDirectory string) (string, []byte, error) {
	if xcore.Supports(in.Protocol) {
		raw, e := xcore.Build(in, tlsDirectory)
		return coreXray, raw, e
	}
	raw, e := Build(in, tlsDirectory)
	return coreSingBox, raw, e
}

func Build(in wire.Inbound, tlsDirectory string) ([]byte, error) {
	if in.ID < 1 || in.Port < 1024 || in.Port > 65535 || net.ParseIP(in.ListenHost) == nil || len(in.Users) > 100000 {
		return nil, fmt.Errorf("invalid inbound")
	}
	tag := "inbound-" + strconv.FormatInt(in.ID, 10)
	users := []map[string]any{}
	seen := map[int64]bool{}
	for _, u := range in.Users {
		if u.ID < 1 || u.Epoch < 1 || u.SpeedMbps < 1 || u.MaxConnections < 1 || seen[u.ID] {
			return nil, fmt.Errorf("invalid user rights")
		}
		seen[u.ID] = true
		v := map[string]any{"name": strconv.FormatInt(u.ID, 10)}
		c := u.Credential
		switch in.Protocol {
		case "vmess":
			if c.UUID == "" {
				return nil, fmt.Errorf("missing UUID")
			}
			v["uuid"] = c.UUID
		case "ss2022":
			v["password"] = c.SSKey
		case "hy2", "anytls":
			if c.Password == "" {
				return nil, fmt.Errorf("missing password")
			}
			v["password"] = c.Password
		case "tuic5":
			v["uuid"] = c.UUID
			v["password"] = c.Password
		case "wireguard":
			v = map[string]any{"public_key": c.PublicKey, "allowed_ips": []string{c.Address + "/32"}}
		default:
			return nil, fmt.Errorf("unsupported protocol")
		}
		users = append(users, v)
	}
	inbound := map[string]any{"tag": tag, "listen": in.ListenHost, "listen_port": in.Port, "users": users, "udp_timeout": "30s"}
	switch in.Protocol {
	case "vmess":
		inbound["type"] = "vmess"
	case "anytls":
		inbound["type"] = "anytls"
		if len(in.Config.PaddingScheme) > 0 {
			inbound["padding_scheme"] = in.Config.PaddingScheme
		}
	case "ss2022":
		inbound["type"] = "shadowsocks"
		inbound["method"] = in.Config.Method
		inbound["password"] = in.Config.ServerKey
	case "hy2":
		inbound["type"] = "hysteria2"
		inbound["ignore_client_bandwidth"] = true
		if in.Config.ObfsPassword != "" {
			inbound["obfs"] = map[string]any{"type": "salamander", "password": in.Config.ObfsPassword}
		}
		if m := in.Config.Masquerade; m != "" {
			// Unauthenticated probes see this HTTPS site instead of an error.
			u, e := url.Parse(m)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
				return nil, fmt.Errorf("masquerade must be an https URL")
			}
			inbound["masquerade"] = map[string]any{"type": "proxy", "url": m, "rewrite_host": true}
		}
	case "tuic5":
		inbound["type"] = "tuic"
		inbound["congestion_control"] = "bbr"
		if in.Config.Congestion != "" {
			inbound["congestion_control"] = in.Config.Congestion
		}
	case "wireguard":
	default:
		return nil, fmt.Errorf("unsupported protocol")
	}
	if in.Config.TLS || in.Config.Security == "tls" || in.Protocol == "anytls" {
		cert, key := in.Secrets.Certificate, in.Secrets.PrivateKey
		if in.Secrets.LocalTLS {
			c, e := os.ReadFile(filepath.Join(tlsDirectory, "default.crt"))
			if e != nil {
				return nil, fmt.Errorf("local TLS certificate is missing")
			}
			k, e := os.ReadFile(filepath.Join(tlsDirectory, "default.key"))
			if e != nil {
				return nil, fmt.Errorf("local TLS key is missing")
			}
			cert, key = string(c), string(k)
		}
		inbound["tls"] = map[string]any{"enabled": true, "server_name": in.Config.ServerName, "certificate": []string{cert}, "key": []string{key}}
		switch in.Config.TLSMinVersion {
		case "", "1.2":
		case "1.3":
			inbound["tls"].(map[string]any)["min_version"] = "1.3"
		default:
			return nil, fmt.Errorf("unsupported TLS minimum version")
		}
		if len(in.Config.ALPN) > 0 {
			inbound["tls"].(map[string]any)["alpn"] = in.Config.ALPN
		} else if in.Protocol == "tuic5" {
			inbound["tls"].(map[string]any)["alpn"] = []string{"h3"}
		}
	}
	switch t := in.Config.Transport; t {
	case "", "tcp", "raw":
	case "ws", "grpc":
		// HTTPUpgrade is served by Xray only: Xray 26 clients send WebSocket key
		// headers that sing-box's HTTPUpgrade server rejects.
		if in.Protocol != "vmess" {
			return nil, fmt.Errorf("transport is not available for this protocol")
		}
		transport := map[string]any{"type": "grpc", "service_name": in.Config.ServiceName}
		if t == "ws" {
			transport = map[string]any{"type": "ws", "path": in.Config.Path}
			if in.Config.Host != "" {
				transport["headers"] = map[string]string{"Host": in.Config.Host}
			}
		}
		inbound["transport"] = transport
	default:
		return nil, fmt.Errorf("transport is not available for this protocol")
	}
	if s := in.Config.Security; s == "reality" || (s == "none" && in.Config.TLS) {
		return nil, fmt.Errorf("security layer is not available for this protocol")
	}
	result := map[string]any{"log": map[string]any{"level": "error", "timestamp": true}, "dns": map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "system"}}}, "outbounds": []any{map[string]any{"type": "direct", "tag": "egress"}}, "route": map[string]any{"default_domain_resolver": "system", "final": "egress", "rules": []any{map[string]any{"network": "icmp", "action": "reject"}, map[string]any{"action": "resolve"}, map[string]any{"ip_is_private": true, "action": "reject"}, map[string]any{"ip_cidr": []string{"0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}, "action": "reject"}}}}
	if in.Protocol == "wireguard" {
		result["endpoints"] = []any{map[string]any{"type": "wireguard", "tag": tag, "system": false, "address": []string{"10.0.0.1/32"}, "private_key": in.Secrets.WGPrivateKey, "listen_port": in.Port, "mtu": in.Config.MTU, "peers": users, "workers": 2, "udp_timeout": "30s"}}
	} else {
		result["inbounds"] = []any{inbound}
	}
	return json.Marshal(result)
}
func ValidateSnapshot(s wire.Snapshot, id int64) error {
	if s.ProtocolVersion != wire.ProtocolVersion || s.ServerID != id || len(s.Revision) != 64 || len(s.Inbounds) > 1000 || s.IssuedAt.After(time.Now().Add(30*time.Second)) || !s.ValidUntil.After(time.Now()) || s.ValidUntil.Sub(s.IssuedAt) > 2*time.Minute {
		return fmt.Errorf("invalid or expired configuration")
	}
	ports := map[int]bool{}
	ids := map[int64]bool{}
	for _, i := range s.Inbounds {
		if ports[i.Port] || ids[i.ID] {
			return fmt.Errorf("duplicate inbound or port")
		}
		ports[i.Port] = true
		ids[i.ID] = true
	}
	return nil
}
