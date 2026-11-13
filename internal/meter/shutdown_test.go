package meter

import (
	"context"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"github.com/sagernet/sing-box/adapter"
	"net"
	"strings"
	"testing"
	"time"
)

type shutdownController struct{ granted chan struct{} }

func (c *shutdownController) Lease(context.Context, wire.Lease) (wire.LeaseResult, error) {
	return wire.LeaseResult{ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (c *shutdownController) Grant(_ context.Context, r wire.GrantRequest) (wire.Grant, error) {
	close(c.granted)
	return wire.Grant{ID: r.ID, Bytes: r.Bytes, ExpiresAt: time.Now().Add(2 * time.Second)}, nil
}
func TestStopWaitsForDurableSettlement(t *testing.T) {
	store, err := journal.Open(t.TempDir(), strings.Repeat("a", 256))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	controller := &shutdownController{granted: make(chan struct{})}
	tracker := New(context.Background(), controller, store)
	tracker.Update(wire.Snapshot{ValidUntil: time.Now().Add(time.Minute), Inbounds: []wire.Inbound{{ID: 1, Users: []wire.User{{ID: 1, Epoch: 1, ExpiresAt: time.Now().Add(time.Hour)}}}}})
	left, right := net.Pipe()
	defer right.Close()
	c := tracker.RoutedConnection(context.Background(), left, adapter.InboundContext{Inbound: "inbound-1", User: "1"}, nil, nil)
	finished := make(chan struct{})
	go func() { defer close(finished); c.Write([]byte("pending payload")) }()
	<-controller.granted
	tracker.Stop()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("socket write survived stop")
	}
	entries, err := store.Entries()
	if err != nil || len(entries) != 1 || entries[0].State != "settled" {
		t.Fatal("missing durable settlement", entries, err)
	}
	if entries[0].Report.Upload != 0 || entries[0].Report.Download != 0 {
		t.Fatal("unsent bytes were charged")
	}
	if _, err = c.Write([]byte("after stop")); err == nil {
		t.Fatal("shutdown admitted new payload")
	}
}
