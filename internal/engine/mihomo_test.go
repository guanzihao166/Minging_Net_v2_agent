package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"golang.org/x/net/proxy"
)

// TestMihomoInterop drives the real mihomo client (MNET_MIHOMO=path) through
// every modern inbound shape the controller can export, over the production
// engine and metering path. It documents which REALITY clients Xray accepts.
func TestMihomoInterop(t *testing.T) {
	exe := os.Getenv("MNET_MIHOMO")
	if exe == "" {
		t.Skip("set MNET_MIHOMO to a mihomo binary to run real-client interop")
	}
	echo := startEcho(t, "minging-mihomo-roundtrip")
	type interop struct {
		name, protocol string
		setup          func(*testing.T, *wire.Inbound)
		proxy          func(wire.Inbound) map[string]any
		mustFail       bool
	}
	realityOpts := func(in wire.Inbound, pq bool) map[string]any {
		o := map[string]any{"public-key": in.Config.RealityPublicKey, "short-id": in.Config.RealityShortID}
		if pq {
			o["support-x25519mlkem768"] = true
		}
		return o
	}
	vlessBase := func(in wire.Inbound) map[string]any {
		return map[string]any{"type": "vless", "server": "127.0.0.1", "port": in.Port, "uuid": in.Users[0].Credential.UUID, "udp": true, "packet-encoding": "xudp", "client-fingerprint": "chrome"}
	}
	cases := []interop{
		{"vless-reality-vision-pq", "vless", func(t *testing.T, in *wire.Inbound) { reality(t, in); in.Config.Flow = "xtls-rprx-vision" }, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["tls"], p["servername"], p["reality-opts"] = "xtls-rprx-vision", true, "example.com", realityOpts(in, true)
			return p
		}, false},
		{"vless-reality-vision-classic-hello", "vless", func(t *testing.T, in *wire.Inbound) { reality(t, in); in.Config.Flow = "xtls-rprx-vision" }, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["tls"], p["servername"], p["reality-opts"] = "xtls-rprx-vision", true, "example.com", realityOpts(in, false)
			return p
		}, true},
		{"vless-reality-x25519-only", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Flow = "xtls-rprx-vision"
			in.Config.RealityX25519Only = true
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["tls"], p["servername"], p["reality-opts"] = "xtls-rprx-vision", true, "example.com", realityOpts(in, false)
			return p
		}, false},
		{"vless-reality-x25519-only-guard", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Flow = "xtls-rprx-vision"
			in.Config.RealityX25519Only = true
			in.Config.RealityRejectFallback = true
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["tls"], p["servername"], p["reality-opts"] = "xtls-rprx-vision", true, "example.com", realityOpts(in, false)
			return p
		}, false},
		{"vless-reality-x25519-only-hybrid-client", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Flow = "xtls-rprx-vision"
			in.Config.RealityX25519Only = true
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["tls"], p["servername"], p["reality-opts"] = "xtls-rprx-vision", true, "example.com", realityOpts(in, true)
			return p
		}, false},
		{"vless-reality-x25519-only-bad-short-id", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Flow = "xtls-rprx-vision"
			in.Config.RealityX25519Only = true
			in.Config.RealityRejectFallback = true
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["tls"], p["servername"], p["reality-opts"] = "xtls-rprx-vision", true, "example.com", realityOpts(in, false)
			p["reality-opts"].(map[string]any)["short-id"] = "ffffffffffffffff"
			return p
		}, true},
		{"vless-reality-x25519-only-bad-uuid", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Flow = "xtls-rprx-vision"
			in.Config.RealityX25519Only = true
			in.Config.RealityRejectFallback = true
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["tls"], p["servername"], p["reality-opts"] = "xtls-rprx-vision", true, "example.com", realityOpts(in, false)
			p["uuid"] = "ffffffff-ffff-4fff-bfff-ffffffffffff"
			return p
		}, true},
		// The fallback guard must admit mihomo exactly as REALITY does.
		{"vless-reality-vision-pq-reject-fallback", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Flow = "xtls-rprx-vision"
			in.Config.RealityRejectFallback = true
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["tls"], p["servername"], p["reality-opts"] = "xtls-rprx-vision", true, "example.com", realityOpts(in, true)
			return p
		}, false},
		{"trojan-reality-reject-fallback", "trojan", func(t *testing.T, in *wire.Inbound) { reality(t, in); in.Config.RealityRejectFallback = true }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "trojan", "server": "127.0.0.1", "port": in.Port, "password": in.Users[0].Credential.Password, "udp": true, "sni": "example.com", "client-fingerprint": "chrome", "reality-opts": realityOpts(in, true)}
		}, false},
		{"vless-reality-grpc", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Transport = "grpc"
			in.Config.ServiceName = "mnet"
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["tls"], p["servername"], p["reality-opts"], p["network"], p["grpc-opts"] = true, "example.com", realityOpts(in, true), "grpc", map[string]any{"grpc-service-name": "mnet"}
			return p
		}, false},
		{"vless-reality-xhttp", "vless", func(t *testing.T, in *wire.Inbound) {
			reality(t, in)
			in.Config.Transport, in.Config.Path, in.Config.XHTTPMode = "xhttp", "/mx", "auto"
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["tls"], p["servername"], p["reality-opts"], p["network"], p["xhttp-opts"] = true, "example.com", realityOpts(in, true), "xhttp", map[string]any{"path": "/mx", "mode": "stream-one"}
			return p
		}, false},
		{"vless-tls-xhttp-packet-up", "vless", func(t *testing.T, in *wire.Inbound) {
			in.Config.Security, in.Config.Transport, in.Config.Path, in.Config.XHTTPMode = "tls", "xhttp", "/px", "packet-up"
			in.Config.XHTTPExtra = json.RawMessage(`{"xPaddingBytes":"100-1000"}`)
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["tls"], p["servername"], p["skip-cert-verify"], p["alpn"], p["network"] = true, "localhost", true, []string{"h2"}, "xhttp"
			p["xhttp-opts"] = map[string]any{"path": "/px", "mode": "packet-up", "x-padding-bytes": "100-1000"}
			return p
		}, false},
		{"vless-encryption-native-x25519-vision", "vless", func(t *testing.T, in *wire.Inbound) {
			in.Config.TLS, in.Config.Security, in.Config.Flow = false, "none", "xtls-rprx-vision"
			in.Secrets.Decryption, in.Config.Encryption = vlessEncryption(t, "native", false)
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["flow"], p["encryption"] = "xtls-rprx-vision", in.Config.Encryption
			return p
		}, false},
		{"vless-encryption-random-mlkem-ws-tls", "vless", func(t *testing.T, in *wire.Inbound) {
			in.Config.Security, in.Config.Transport, in.Config.Path = "tls", "ws", "/ews"
			in.Secrets.Decryption, in.Config.Encryption = vlessEncryption(t, "random", true)
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["tls"], p["servername"], p["skip-cert-verify"], p["network"], p["ws-opts"], p["encryption"] = true, "localhost", true, "ws", map[string]any{"path": "/ews"}, in.Config.Encryption
			return p
		}, false},
		{"vless-httpupgrade-tls", "vless", func(t *testing.T, in *wire.Inbound) {
			in.Config.Security, in.Config.Transport, in.Config.Path, in.Config.Host = "tls", "httpupgrade", "/hu", "cdn.example"
		}, func(in wire.Inbound) map[string]any {
			p := vlessBase(in)
			p["tls"], p["servername"], p["skip-cert-verify"], p["network"] = true, "localhost", true, "ws"
			p["ws-opts"] = map[string]any{"path": "/hu", "v2ray-http-upgrade": true, "headers": map[string]string{"Host": "cdn.example"}}
			return p
		}, false},
		{"trojan-reality", "trojan", func(t *testing.T, in *wire.Inbound) { reality(t, in) }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "trojan", "server": "127.0.0.1", "port": in.Port, "password": in.Users[0].Credential.Password, "udp": true, "sni": "example.com", "client-fingerprint": "chrome", "reality-opts": realityOpts(in, true)}
		}, false},
		{"trojan-grpc-tls", "trojan", func(t *testing.T, in *wire.Inbound) { in.Config.Transport, in.Config.ServiceName = "grpc", "tg" }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "trojan", "server": "127.0.0.1", "port": in.Port, "password": in.Users[0].Credential.Password, "udp": true, "sni": "localhost", "skip-cert-verify": true, "network": "grpc", "grpc-opts": map[string]any{"grpc-service-name": "tg"}}
		}, false},
		{"vmess-ws-tls-auto", "vmess", func(t *testing.T, in *wire.Inbound) { in.Config.Transport, in.Config.Path = "ws", "/vw" }, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "vmess", "server": "127.0.0.1", "port": in.Port, "uuid": in.Users[0].Credential.UUID, "alterId": 0, "cipher": "auto", "udp": true, "tls": true, "servername": "localhost", "skip-cert-verify": true, "network": "ws", "ws-opts": map[string]any{"path": "/vw"}}
		}, false},
		{"anytls", "anytls", nil, func(in wire.Inbound) map[string]any {
			return map[string]any{"type": "anytls", "server": "127.0.0.1", "port": in.Port, "password": in.Users[0].Credential.Password, "udp": true, "sni": "localhost", "skip-cert-verify": true, "client-fingerprint": "chrome"}
		}, false},
	}
	proxies, listeners := []any{}, []any{}
	ports := map[string]int{}
	for _, c := range cases {
		in := fixtureInbound(t, c.protocol)
		in.Config.TLS = true
		if c.setup != nil {
			c.setup(t, &in)
		}
		meteredServer(t, in, &fixtureController{})
		p := c.proxy(in)
		p["name"] = c.name
		proxies = append(proxies, p)
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		ports[c.name] = l.Addr().(*net.TCPAddr).Port
		l.Close()
		listeners = append(listeners, map[string]any{"name": "in-" + c.name, "type": "mixed", "listen": "127.0.0.1", "port": ports[c.name], "proxy": c.name})
	}
	dir := t.TempDir()
	config, _ := json.Marshal(map[string]any{"mode": "rule", "log-level": "warning", "ipv6": false, "proxies": proxies, "listeners": listeners, "rules": []string{"MATCH,DIRECT"}})
	if e := os.WriteFile(filepath.Join(dir, "config.yaml"), config, 0600); e != nil {
		t.Fatal(e)
	}
	logFile, _ := os.Create(filepath.Join(dir, "mihomo.log"))
	cmd := exec.Command(exe, "-d", dir, "-f", filepath.Join(dir, "config.yaml"))
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		logFile.Close()
		if t.Failed() {
			raw, _ := os.ReadFile(filepath.Join(dir, "mihomo.log"))
			t.Log("mihomo log:\n" + string(raw))
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for _, port := range ports {
		for {
			if c, e := net.DialTimeout("tcp", fmt.Sprint("127.0.0.1:", port), time.Second); e == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("mihomo listeners did not start")
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dialer, err := proxy.SOCKS5("tcp", fmt.Sprint("127.0.0.1:", ports[c.name]), nil, &net.Dialer{Timeout: 12 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{Dial: dialer.Dial, DisableKeepAlives: true}}
			response, e := client.Get("http://" + echo.http + "/")
			ok := false
			if e == nil {
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				ok = strings.Contains(string(body), "minging-mihomo-roundtrip")
			}
			switch {
			case c.mustFail && ok:
				t.Fatal("expected Xray to refuse this ClientHello")
			case c.mustFail:
				t.Logf("refused as expected: %v", e)
			case !ok:
				t.Fatalf("mihomo could not reach the fixture: %v", e)
			}
		})
	}
}
