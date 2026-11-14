package xcore

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/meter"
	applog "github.com/xtls/xray-core/app/log"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/infra/conf"

	// Only the components these inbounds use are linked and registered.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// Xray routes log records to one process-wide handler. Each instance's log app
// would replace it and silence everything once that instance closes, so the
// agent strips the log app and keeps this error-only handler instead.
type errorLog struct{}

func (errorLog) Handle(m xlog.Message) {
	if g, ok := m.(*xlog.GeneralMessage); ok && g.Severity <= xlog.Severity_Error {
		slog.Error("xray", "message", g.String())
	}
}

var logConfigType = serial.GetMessageType(&applog.Config{})

func init() { xlog.RegisterHandler(errorLog{}) }

// Instance is one inbound served by its own Xray core, with the fallback guard
// in front of its REALITY target when unauthenticated fallback is refused.
type Instance struct {
	server *core.Instance
	guard  *realityGuard
}

// Load parses and validates a configuration produced by Build. Xray's parsers
// may panic on malformed input; that must reject the inbound, not the agent.
func Load(raw []byte) (config *core.Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			config, err = nil, fmt.Errorf("protocol configuration rejected")
		}
	}()
	var document conf.Config
	if e := json.Unmarshal(raw, &document); e != nil {
		return nil, fmt.Errorf("protocol configuration rejected: %w", e)
	}
	built, e := document.Build()
	if e != nil {
		return nil, fmt.Errorf("protocol configuration rejected: %w", e)
	}
	apps := built.App[:0]
	for _, app := range built.App {
		if app.Type != logConfigType {
			apps = append(apps, app)
		}
	}
	built.App = apps
	return built, nil
}

// New builds a stopped instance whose only outbound is the metered egress.
// allowPrivate exists for package tests reaching loopback fixtures.
func New(ctx context.Context, raw []byte, tracker *meter.Tracker, allowPrivate bool) (*Instance, error) {
	config, e := Load(raw)
	if e != nil {
		return nil, e
	}
	var side struct {
		Guard *GuardSpec `json:"mingingRealityGuard"`
	}
	if e = json.Unmarshal(raw, &side); e != nil {
		return nil, fmt.Errorf("protocol configuration rejected: %w", e)
	}
	var guard *realityGuard
	if side.Guard != nil {
		if guard, e = newGuard(*side.Guard); e != nil {
			return nil, fmt.Errorf("protocol configuration rejected: %w", e)
		}
	}
	server, e := newCore(config)
	if e != nil {
		return nil, fmt.Errorf("protocol core rejected configuration: %w", e)
	}
	// Freedom's built-in final rule independently blackholes private targets for
	// these inbounds; only package tests reaching loopback fixtures lift it.
	settings := json.RawMessage(`{"domainStrategy":"AsIs"}`)
	if allowPrivate {
		settings = json.RawMessage(`{"domainStrategy":"AsIs","finalRules":[{"action":"allow"}]}`)
	}
	detour := conf.OutboundDetourConfig{Protocol: "freedom", Tag: "direct", Settings: &settings}
	directConfig, e := detour.Build()
	if e == nil {
		var direct any
		direct, e = core.CreateObject(server, directConfig)
		if e == nil {
			handler := &meteredOutbound{direct: direct.(outbound.Handler), tracker: tracker, allowPrivate: allowPrivate}
			e = server.GetFeature(outbound.ManagerType()).(outbound.Manager).AddHandler(ctx, handler)
		}
	}
	if e != nil {
		server.Close()
		return nil, fmt.Errorf("egress setup failed: %w", e)
	}
	return &Instance{server: server, guard: guard}, nil
}

func newCore(config *core.Config) (server *core.Instance, err error) {
	defer func() {
		if r := recover(); r != nil {
			server, err = nil, fmt.Errorf("core initialization failed")
		}
	}()
	return core.New(config)
}

// Start brings the guard up first: REALITY dials it for every connection and
// Xray looks up the target measurements the guard publishes when it starts.
func (i *Instance) Start() error {
	if i.guard != nil {
		if e := i.guard.Start(); e != nil {
			return e
		}
	}
	if e := i.server.Start(); e != nil {
		if i.guard != nil {
			i.guard.Close()
		}
		return e
	}
	return nil
}

func (i *Instance) Close() error {
	e := i.server.Close()
	if i.guard != nil {
		i.guard.Close()
	}
	return e
}
