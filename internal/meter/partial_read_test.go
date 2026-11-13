package meter

import (
	"context"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"github.com/sagernet/sing-box/adapter"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type partialController struct{}

func (*partialController) Lease(context.Context, wire.Lease) (wire.LeaseResult, error) {
	return wire.LeaseResult{ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (*partialController) Grant(_ context.Context, r wire.GrantRequest) (wire.Grant, error) {
	return wire.Grant{ID: r.ID, Bytes: min(r.Bytes, 3), ExpiresAt: time.Now().Add(2 * time.Second)}, nil
}

type eofPayloadConn struct {
	net.Conn
	read bool
}

func (c *eofPayloadConn) Read(p []byte) (int, error) {
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	return copy(p, "stream-preserved"), io.EOF
}

func TestPartialGrantPreservesReadBytesAndEOF(t *testing.T) {
	store, e := journal.Open(t.TempDir(), strings.Repeat("p", 256))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	tracker := New(context.Background(), &partialController{}, store)
	defer tracker.Stop()
	tracker.Update(wire.Snapshot{ValidUntil: time.Now().Add(time.Minute), Inbounds: []wire.Inbound{{ID: 1, Users: []wire.User{{ID: 1, Epoch: 1, ExpiresAt: time.Now().Add(time.Hour)}}}}})
	left, right := net.Pipe()
	defer right.Close()
	conn := tracker.RoutedConnection(context.Background(), &eofPayloadConn{Conn: left}, adapter.InboundContext{Inbound: "inbound-1", User: "1"}, nil, nil)
	result, e := io.ReadAll(conn)
	if e != nil || string(result) != "stream-preserved" {
		t.Fatalf("TCP stream lost bytes: %q, %v", result, e)
	}
	entries, e := store.Entries()
	if e != nil {
		t.Fatal(e)
	}
	var charged int64
	for _, entry := range entries {
		charged += entry.Report.Upload
		if entry.State != "settled" {
			t.Fatal("unsettled partial grant")
		}
	}
	if charged != int64(len(result)) {
		t.Fatalf("charged %d for %d bytes", charged, len(result))
	}
}
