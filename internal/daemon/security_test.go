package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/control"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManagementSourceAndPersistentReplay(t *testing.T) {
	dir := t.TempDir()
	token := strings.Repeat("a", 256)
	store, e := journal.Open(dir, token)
	if e != nil {
		t.Fatal(e)
	}
	d := &Daemon{config: control.Config{Token: token, ControllerIPs: []string{"203.0.113.1/32"}}, store: store}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	request := func(ip string) int {
		body := []byte(`{"revision":"fixture"}`)
		r := httptest.NewRequest("PUT", "/v1/config", bytes.NewReader(body))
		r.RemoteAddr = ip + ":1234"
		stamp := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := strings.Repeat("b", 32)
		r.Header.Set("X-Mnet-Time", stamp)
		r.Header.Set("X-Mnet-Nonce", nonce)
		r.Header.Set("X-Mnet-Signature", wire.Signature(token, "PUT", "/v1/config", stamp, nonce, body))
		w := httptest.NewRecorder()
		d.authenticate(handler).ServeHTTP(w, r)
		return w.Code
	}
	if request("198.51.100.1") != 403 || request("203.0.113.1") != 200 || request("203.0.113.1") != 409 {
		t.Fatal("source/replay protection failed")
	}
	store.Close()
	store, e = journal.Open(dir, token)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	d.store = store
	if request("203.0.113.1") != 409 {
		t.Fatal("replay accepted after restart")
	}
}
func TestCrashRecoveryDoesNotInventUsage(t *testing.T) {
	token := strings.Repeat("a", 256)
	store, e := journal.Open(t.TempDir(), token)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		json.NewEncoder(w).Encode(wire.Grant{ID: id, Bytes: 100, ExpiresAt: time.Now().Add(-time.Second)})
	}))
	defer server.Close()
	d := &Daemon{store: store, client: &control.Client{Config: control.Config{Controller: server.URL, Token: token, ServerID: 1}, HTTP: server.Client()}}
	for index, state := range []string{"requested", "inflight"} {
		id := strings.Repeat(strconv.Itoa(index+1), 32)
		if e = store.Put(journal.Entry{Request: wire.GrantRequest{ID: id}, State: state}); e != nil {
			t.Fatal(e)
		}
	}
	if e = d.recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	entries, e := store.Entries()
	if e != nil {
		t.Fatal(e)
	}
	states := map[string]bool{}
	for _, entry := range entries {
		states[entry.State] = true
	}
	if !states["settled"] || !states["uncertain"] {
		t.Fatal("recovery states", states)
	}
	up, down := store.Totals()
	if up != 0 || down != 0 {
		t.Fatal("allocated bytes misrepresented as actual traffic")
	}
}

func TestLiveRecoveryLeavesActiveGrantsAlone(t *testing.T) {
	token := strings.Repeat("a", 256)
	store, e := journal.Open(t.TempDir(), token)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	queried := map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		queried[id] = true
		json.NewEncoder(w).Encode(wire.Grant{ID: id, Bytes: 100, Closed: id == strings.Repeat("4", 32), ExpiresAt: time.Now().Add(-time.Minute)})
	}))
	defer server.Close()
	d := &Daemon{store: store, client: &control.Client{Config: control.Config{Controller: server.URL, Token: token, ServerID: 1}, HTTP: server.Client()}}
	for i, state := range []string{"requested", "inflight", "abandoned", "uncertain"} {
		id := strings.Repeat(strconv.Itoa(i+1), 32)
		if e = store.Put(journal.Entry{Request: wire.GrantRequest{ID: id}, State: state}); e != nil {
			t.Fatal(e)
		}
	}
	// Recent abandoned work is held for the preceding HTTP request to finish.
	if e = d.recoverPending(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	if len(queried) != 0 {
		t.Fatal("live recovery raced with a recent request")
	}
}
