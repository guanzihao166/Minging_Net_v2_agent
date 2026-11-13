package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/control"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/engine"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/meter"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
)

// Exercise the actual report sender over TLS and the actual disk journal. The
// receiver commits once, loses its response, and sees the identical report after
// the sender is restarted. Transport authentication must use a fresh nonce.
func TestReportLostAckSurvivesRestart(t *testing.T) {
	token, dir := strings.Repeat("x", 256), t.TempDir()
	var mu sync.Mutex
	requests, applied, bytesApplied := 0, 0, int64(0)
	var first []byte
	nonce := ""
	seen := map[string]bool{}
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil || !wire.ValidSignature(r, token, raw, time.Now()) {
			t.Error("invalid signed report")
			w.WriteHeader(401)
			return
		}
		var report wire.Report
		if err = json.Unmarshal(raw, &report); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		requests++
		if requests == 1 {
			first = append([]byte(nil), raw...)
			nonce = r.Header.Get("X-Mnet-Nonce")
		} else if !bytes.Equal(raw, first) || nonce == r.Header.Get("X-Mnet-Nonce") {
			t.Error("retry changed durable payload or reused authentication nonce")
		}
		if !seen[report.ID] {
			seen[report.ID] = true
			applied++
			for _, g := range report.Grants {
				bytesApplied += g.Upload + g.Download
			}
		}
		if requests == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer receiver.Close()
	makeDaemon := func() *Daemon {
		store, err := journal.Open(dir, token)
		if err != nil {
			t.Fatal(err)
		}
		client := &control.Client{Config: control.Config{ServerID: 1, Controller: receiver.URL, Token: token}, HTTP: receiver.Client()}
		tracker := meter.New(context.Background(), client, store)
		runtime := engine.New(context.Background(), t.TempDir(), tracker, nil, tracker.Update, tracker.CloseInbound)
		return &Daemon{config: control.Config{StateDirectory: dir}, client: client, store: store, tracker: tracker, engine: runtime, version: "acceptance"}
	}
	closeDaemon := func(d *Daemon) {
		d.tracker.Stop()
		d.engine.Close()
		if err := d.store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	d := makeDaemon()
	id := strings.Repeat("1", 32)
	if err := d.store.Put(journal.Entry{Request: wire.GrantRequest{ID: id}, Grant: wire.Grant{ID: id, Bytes: 4096}, State: "inflight"}); err != nil {
		t.Fatal(err)
	}
	if err := d.store.Settle(id, 123, 2048); err != nil {
		t.Fatal(err)
	}
	d.report(context.Background())
	entries, err := d.store.Entries()
	if err != nil || len(entries) != 1 || entries[0].State != "settled" {
		t.Fatal("lost acknowledgement discarded durable traffic", err)
	}
	closeDaemon(d)
	d = makeDaemon()
	defer closeDaemon(d)
	if err = d.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.report(context.Background())
	entries, err = d.store.Entries()
	if err != nil || len(entries) != 0 {
		t.Fatal("successful acknowledgement did not clear pending traffic", err)
	}
	up, down := d.store.Totals()
	if up != 123 || down != 2048 {
		t.Fatal("restart changed actual traffic totals", up, down)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 2 || applied != 1 || bytesApplied != 2171 {
		t.Fatal("duplicated settlement", requests, applied, bytesApplied)
	}
	t.Log("TLS response loss, journal reopen, unchanged report retry, fresh signature nonce and exactly-once settlement passed")
}
