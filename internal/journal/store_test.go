package journal

import (
	"bytes"
	"encoding/json"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreditWindowOutboxWaitsForFinalSettlement(t *testing.T) {
	dir := t.TempDir()
	secret := strings.Repeat("w", 256)
	s, err := Open(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	if err = s.Put(Entry{Request: wire.GrantRequest{ID: id}, Grant: wire.Grant{ID: id, Bytes: 1000}, State: "inflight"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Accumulate(id, 100, 200, false); err != nil {
		t.Fatal(err)
	}
	raw, err := s.QueueReport(wire.Report{ID: strings.Repeat("b", 32)})
	if err != nil {
		t.Fatal(err)
	}
	var first wire.Report
	json.Unmarshal(raw, &first)
	if len(first.Grants) != 0 {
		t.Fatal("open window entered outbox")
	}
	if err = s.AckReport(raw); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entries, err := s.Entries()
	if err != nil || len(entries) != 1 || entries[0].State != "inflight" || entries[0].Report.Download != 200 {
		t.Fatal("partial durable settlement lost", entries, err)
	}
	if err = s.Accumulate(id, 0, 50, true); err != nil {
		t.Fatal(err)
	}
	raw, err = s.QueueReport(wire.Report{ID: strings.Repeat("c", 32)})
	if err != nil {
		t.Fatal(err)
	}
	var final wire.Report
	json.Unmarshal(raw, &final)
	if len(final.Grants) != 1 || final.Grants[0].Upload != 100 || final.Grants[0].Download != 250 || !final.Grants[0].Closed {
		t.Fatal("wrong cumulative usage", final)
	}
	if err = s.AckReport(raw); err != nil {
		t.Fatal(err)
	}
	entries, err = s.Entries()
	if err != nil || len(entries) != 0 {
		t.Fatal("closed grant not acknowledged")
	}
	up, down := s.Totals()
	if up != 100 || down != 250 {
		t.Fatal("reserved or duplicate bytes charged", up, down)
	}
}

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
