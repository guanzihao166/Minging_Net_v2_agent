package xcore

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
)

func inbound() wire.Inbound {
	return wire.Inbound{ID: 7, Protocol: "vless", ListenHost: "0.0.0.0", Port: 24443,
		Config:  wire.ClientConfig{Security: "reality", Transport: "xhttp", Path: "/x", ServerName: "www.example.com", RealityTarget: "www.example.com:443", RealityShortID: "0123abcd", XHTTPExtra: json.RawMessage(`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"},"downloadSettings":{"address":"evil"}}`)},
		Secrets: wire.Secrets{RealityPrivateKey: strings.Repeat("A", 43)},
		Users:   []wire.User{{ID: 3, Epoch: 1, ExpiresAt: time.Now().Add(time.Hour), SpeedMbps: 10, MaxConnections: 2, Credential: wire.Credential{UUID: "00c3cf1b-80f0-477c-bb0d-a051ee220191"}}}}
}

func TestBuildRealityXHTTP(t *testing.T) {
	raw, e := Build(inbound(), "")
	if e != nil {
		t.Fatal(e)
	}
	text := string(raw)
	for _, want := range []string{`"minClientVer":"0.0.0"`, `"email":"3"`, `"tag":"inbound-7"`, `"decryption":"none"`, `"xPaddingBytes":"100-1000"`, `"serverNames":["www.example.com"]`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in %s", want, text)
		}
	}
	for _, unwanted := range []string{"xmux", "downloadSettings", "evil", `"outbounds":[{`} {
		if strings.Contains(text, unwanted) {
			t.Errorf("client-only or unsafe member %q reached the server config", unwanted)
		}
	}
	if _, e = Load(raw); e != nil {
		t.Fatal("Xray rejected generated configuration:", e)
	}
}

func TestBuildRejectsMalformedSecrets(t *testing.T) {
	for _, bad := range []string{"mlkem768x25519plus.native.600s.short", "mlkem768x25519plus.native.600s", "mlkem768x25519plus.other.600s." + strings.Repeat("A", 43), "mlkem768x25519plus.native.600." + strings.Repeat("A", 43), "mlkem768x25519plus.native.600s.1-2." + strings.Repeat("A", 43)} {
		in := inbound()
		in.Secrets.Decryption = bad
		in.Config.Security = "none"
		if _, e := Build(in, ""); e == nil {
			t.Fatalf("malformed decryption %q accepted", bad)
		}
	}
	for _, good := range []string{"mlkem768x25519plus.native.600s." + strings.Repeat("A", 43), "mlkem768x25519plus.random.100-500s.100-111-1111.75-0-111.50-0-3333." + strings.Repeat("B", 86)} {
		if !ValidDecryption(good) {
			t.Fatalf("valid decryption %q rejected", good)
		}
	}
	// Even input that slips past validation must not crash the process.
	if _, e := Load([]byte(`{"inbounds":[{"protocol":"vless","port":24443,"settings":{"clients":[],"decryption":"mlkem768x25519plus.native.600s.short"}}]}`)); e == nil {
		t.Fatal("core accepted malformed decryption")
	}
	in := inbound()
	in.Secrets.RealityPrivateKey = "not-a-key"
	if _, e := Build(in, ""); e == nil {
		t.Fatal("malformed REALITY key accepted")
	}
}
