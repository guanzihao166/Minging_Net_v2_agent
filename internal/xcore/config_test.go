package xcore

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"github.com/xtls/xray-core/app/proxyman"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

func inbound() wire.Inbound {
	return wire.Inbound{ID: 7, Protocol: "vless", ListenHost: "0.0.0.0", Port: 24443,
		Config:  wire.ClientConfig{Security: "reality", Transport: "xhttp", Path: "/x", ServerName: "www.example.com", RealityTarget: "www.example.com:443", RealityShortID: "0123abcd", XHTTPExtra: json.RawMessage(`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"},"downloadSettings":{"address":"evil"}}`)},
		Secrets: wire.Secrets{RealityPrivateKey: strings.Repeat("A", 43)},
		Users:   []wire.User{{ID: 3, Epoch: 1, ExpiresAt: time.Now().Add(time.Hour), SpeedMbps: 10, MaxConnections: 2, Credential: wire.Credential{UUID: "00c3cf1b-80f0-477c-bb0d-a051ee220191"}}}}
}

// Inspect the configuration actually passed to the core, not just JSON text.
// Saved configurations carrying old bounds must follow the same policy.
func TestRealityClientVersionBoundsDisabled(t *testing.T) {
	for _, transport := range []string{"raw", "xhttp", "grpc"} {
		for _, guarded := range []bool{false, true} {
			for _, saved := range []bool{false, true} {
				in := inbound()
				in.Config.Transport = transport
				in.Config.ServiceName = "version-policy"
				in.Config.RealityRejectFallback = guarded
				raw, err := Build(in, "")
				if err != nil {
					t.Fatal(err)
				}
				if saved {
					var doc map[string]any
					if err := json.Unmarshal(raw, &doc); err != nil {
						t.Fatal(err)
					}
					settings := doc["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
					settings["minClientVer"], settings["maxClientVer"] = "26.3.27", "26.11.9"
					raw, err = json.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
				}
				built, err := Load(raw)
				if err != nil {
					t.Fatal(err)
				}
				receiver, err := built.Inbound[0].ReceiverSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				stream := receiver.(*proxyman.ReceiverConfig).StreamSettings
				security, err := stream.SecuritySettings[0].GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				settings := security.(*xreality.Config)
				if !bytes.Equal(settings.MinClientVer, []byte{0, 0, 0}) || len(settings.MaxClientVer) != 0 {
					t.Fatalf("client version bounds active: %v / %v", settings.MinClientVer, settings.MaxClientVer)
				}
			}
		}
	}
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

func TestRealityX25519OnlySurvivesCoreSerialization(t *testing.T) {
	for _, only := range []bool{false, true} {
		in := inbound()
		in.Config.RealityX25519Only = only
		raw, err := Build(in, "")
		if err != nil {
			t.Fatal(err)
		}
		core, err := Load(raw)
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := core.Inbound[0].ReceiverSettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		security, err := receiver.(*proxyman.ReceiverConfig).StreamSettings.SecuritySettings[0].GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		cfg := security.(*xreality.Config).GetREALITYConfig()
		if cfg.X25519Only != only || cfg.Clone().X25519Only != only {
			t.Fatal("per-inbound policy lost")
		}
	}
	in := inbound()
	in.Config.RealityX25519Only = true
	in.Secrets.RealityMldsa65Seed = strings.Repeat("A", 43)
	if _, err := Build(in, ""); err == nil {
		t.Fatal("post-quantum signature accepted in classic mode")
	}
}
