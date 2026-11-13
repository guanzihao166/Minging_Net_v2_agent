package engine

import (
	"context"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFailedStartRestoresPreviousInbound(t *testing.T) {
	in := fixtureInbound(t, "vless")
	s := wire.Snapshot{ProtocolVersion: 1, ServerID: 1, Revision: strings.Repeat("a", 64), IssuedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute), Inbounds: []wire.Inbound{in}}
	engine := New(context.Background(), t.TempDir(), nil, nil, func(wire.Snapshot) {}, func(int64) {})
	defer engine.Close()
	if e := engine.Apply(s); e != nil {
		t.Fatal(e)
	}
	occupied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	next := s
	next.Inbounds = append([]wire.Inbound(nil), s.Inbounds...)
	next.Inbounds[0].Port = occupied.Addr().(*net.TCPAddr).Port
	next.Revision = strings.Repeat("b", 64)
	next.IssuedAt = time.Now()
	if e = engine.Apply(next); e == nil {
		t.Fatal("occupied port accepted")
	}
	if engine.Snapshot().Revision != s.Revision {
		t.Fatal("failed configuration committed")
	}
	conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(in.Port)), time.Second)
	if e != nil {
		t.Fatal("previous listener not restored", e)
	}
	conn.Close()
}
