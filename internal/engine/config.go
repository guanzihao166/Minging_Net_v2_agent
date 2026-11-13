package engine

import (
	"encoding/json"
	"fmt"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

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
		case "vless", "vmess":
			if c.UUID == "" {
				return nil, fmt.Errorf("missing UUID")
			}
			v["uuid"] = c.UUID
		case "ss2022":
			v["password"] = c.SSKey
		case "trojan", "hy2":
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
	case "vless", "vmess", "trojan":
		inbound["type"] = in.Protocol
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
	if in.Config.TLS {
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
		if len(in.Config.ALPN) > 0 {
			inbound["tls"].(map[string]any)["alpn"] = in.Config.ALPN
		}
	}
	if in.Config.Transport == "ws" {
		t := map[string]any{"type": "ws", "path": in.Config.Path}
		if in.Config.Host != "" {
			t["headers"] = map[string]string{"Host": in.Config.Host}
		}
		inbound["transport"] = t
	} else if in.Config.Transport == "grpc" {
		inbound["transport"] = map[string]any{"type": "grpc", "service_name": in.Config.ServiceName}
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
