package journal

import (
	"bytes"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDurableUsageAndEncryptedConfig(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir, strings.Repeat("s", 256))
	if e != nil {
		t.Fatal(e)
	}
	snapshot := wire.Snapshot{Revision: strings.Repeat("b", 64), Inbounds: []wire.Inbound{{Secrets: wire.Secrets{PrivateKey: "private-fixture-not-in-plaintext"}}}}
	if e = s.SaveSnapshot(snapshot); e != nil {
		t.Fatal(e)
	}
	entry := Entry{Request: wire.GrantRequest{ID: strings.Repeat("a", 32)}, Grant: wire.Grant{ID: strings.Repeat("a", 32), Bytes: 100, ExpiresAt: time.Now().Add(time.Second)}, State: "inflight"}
	if e = s.Put(entry); e != nil {
		t.Fatal(e)
	}
	if e = s.Settle(entry.Request.ID, 20, 30); e != nil {
		t.Fatal(e)
	}
	raw, e := s.QueueReport(wire.Report{ID: strings.Repeat("c", 32)})
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(dir, strings.Repeat("s", 256))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	up, down := s.Totals()
	if up != 20 || down != 30 {
		t.Fatal("counters lost")
	}
	same, e := s.QueueReport(wire.Report{ID: strings.Repeat("d", 32)})
	if e != nil || !bytes.Equal(raw, same) {
		t.Fatal("lost response changed retry payload")
	}
	if e = s.AckReport(raw); e != nil {
		t.Fatal(e)
	}
	entries, _ := s.Entries()
	if len(entries) != 0 {
		t.Fatal("ack left duplicate usage")
	}
	restored, e := s.LoadSnapshot()
	if e != nil || restored.Inbounds[0].Secrets.PrivateKey != snapshot.Inbounds[0].Secrets.PrivateKey {
		t.Fatal("configuration recovery")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "usage.db"))
	if bytes.Contains(data, []byte("private-fixture-not-in-plaintext")) {
		t.Fatal("plaintext private key in journal")
	}
}
