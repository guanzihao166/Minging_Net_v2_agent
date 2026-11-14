package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/control"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/engine"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/journal"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/meter"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/realityprobe"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Daemon struct {
	config    control.Config
	client    *control.Client
	store     *journal.Store
	tracker   *meter.Tracker
	engine    *engine.Engine
	version   string
	mu        sync.Mutex
	lastError string
	metrics   metricsState
	probing   atomic.Bool
}

func Load(path string) (control.Config, error) {
	var c control.Config
	info, e := os.Stat(path)
	if e != nil {
		return c, e
	}
	if info.Mode().Perm()&0077 != 0 {
		return c, errors.New("agent configuration must have mode 0600")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	if e = json.Unmarshal(raw, &c); e != nil {
		return c, e
	}
	e = c.Validate()
	return c, e
}
func Run(ctx context.Context, c control.Config, version string) error {
	client, e := control.New(c)
	if e != nil {
		return e
	}
	store, e := journal.Open(c.StateDirectory, c.Token)
	if e != nil {
		return e
	}
	defer store.Close()
	certificate, pin, e := managementCertificate(c.StateDirectory)
	if e != nil {
		return e
	}
	d := &Daemon{config: c, client: client, store: store, version: version}
	d.tracker = meter.New(ctx, client, store)
	d.engine = engine.New(ctx, c.TLSDirectory, d.tracker, store.SaveSnapshot, d.tracker.Update, d.tracker.CloseInbound)
	defer d.tracker.Stop()
	defer d.engine.Close()
	// No listener accepts proxy traffic before previous usage intents are recovered.
	if e = d.recover(ctx); e != nil {
		return e
	}
	if previous, err := store.LoadSnapshot(); err == nil && engine.ValidateSnapshot(previous, c.ServerID) == nil {
		if err = d.engine.Apply(previous); err != nil {
			d.error("上次配置恢复失败，等待主控配置")
		}
	}
	handler := http.NewServeMux()
	handler.HandleFunc("PUT /v1/config", d.apply)
	handler.HandleFunc("POST /v1/reality/probe", d.realityProbe)
	handler.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"version": version, "healthy": d.tracker.Healthy()})
	})
	server := &http.Server{Addr: c.Listen, Handler: d.authenticate(handler), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return e
	}
	defer listener.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	enrolled := false
	configTick := time.NewTicker(15 * time.Second)
	defer configTick.Stop()
	reportTick := time.NewTicker(3 * time.Second)
	defer reportTick.Stop()
	watchTick := time.NewTicker(time.Second)
	defer watchTick.Stop()
	syncConfig := func() {
		job, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		if !enrolled {
			e := client.Do(job, "POST", "/api/agent/enroll", map[string]string{"certificate_pin": pin, "version": version}, nil)
			if e != nil {
				d.error("控制器登记失败")
				return
			}
			enrolled = true
		}
		var snapshot wire.Snapshot
		if e := client.Do(job, "GET", "/api/agent/config", nil, &snapshot); e != nil {
			d.error("控制器配置拉取失败")
			return
		}
		if e = engine.ValidateSnapshot(snapshot, c.ServerID); e != nil {
			d.error("控制器配置已过期或版本不符")
			return
		}
		if e = d.engine.Apply(snapshot); e != nil {
			d.error("协议配置应用失败，已尝试恢复上一版本")
			return
		}
		d.error("")
	}
	syncConfig()
	for {
		select {
		case <-ctx.Done():
			d.tracker.Stop()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(shutdown)
			d.report(shutdown)
			return nil
		case err := <-serveErr:
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		case <-configTick.C:
			syncConfig()
			if err := d.recoverPending(ctx, false); err != nil {
				d.error("中断计量核对暂未完成")
			}
		case <-reportTick.C:
			d.report(ctx)
		case <-watchTick.C:
			s := d.engine.Snapshot()
			if !s.ValidUntil.IsZero() && !s.ValidUntil.After(time.Now()) {
				d.tracker.CloseInbound(0)
			}
		}
	}
}
func (d *Daemon) error(message string) {
	d.mu.Lock()
	changed := d.lastError != message
	d.lastError = message
	d.mu.Unlock()
	if changed && message != "" {
		slog.Warn(message)
	}
}
func (d *Daemon) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil {
			http.Error(w, "forbidden", 403)
			return
		}
		ip, e := netip.ParseAddr(host)
		if e != nil {
			http.Error(w, "forbidden", 403)
			return
		}
		allowed := false
		for _, s := range d.config.ControllerIPs {
			p, _ := netip.ParsePrefix(s)
			if p.Contains(ip.Unmap()) {
				allowed = true
			}
		}
		if !allowed {
			http.Error(w, "forbidden", 403)
			return
		}
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		if e != nil || !wire.ValidSignature(r, d.config.Token, body, time.Now()) {
			http.Error(w, "authentication failed", 401)
			return
		}
		nonce := r.Header.Get("X-Mnet-Nonce")
		fresh, err := d.store.UseNonce(nonce)
		if err != nil {
			http.Error(w, "replay protection unavailable", 503)
			return
		}
		if !fresh {
			http.Error(w, "replayed", 409)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func (d *Daemon) apply(w http.ResponseWriter, r *http.Request) {
	var s wire.Snapshot
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s) != nil || decoder.Decode(new(any)) != io.EOF || engine.ValidateSnapshot(s, d.config.ServerID) != nil {
		http.Error(w, "invalid configuration", 400)
		return
	}
	if e := d.engine.Apply(s); e != nil {
		d.error("协议配置应用失败，已尝试恢复上一版本")
		http.Error(w, "configuration application failed", 422)
		return
	}
	d.error("")
	json.NewEncoder(w).Encode(map[string]string{"revision": s.Revision})
}

// realityProbe measures REALITY target candidates from this node for the
// controller's target picker. One measurement runs at a time.
func (d *Daemon) realityProbe(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Targets []realityprobe.Target `json:"targets"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.Targets) == 0 || len(input.Targets) > realityprobe.MaxTargets {
		http.Error(w, "invalid probe request", 400)
		return
	}
	if !d.probing.CompareAndSwap(false, true) {
		http.Error(w, "probe already running", 429)
		return
	}
	defer d.probing.Store(false)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	json.NewEncoder(w).Encode(map[string]any{"results": realityprobe.Probe(ctx, input.Targets, false)})
}
func (d *Daemon) recover(ctx context.Context) error { return d.recoverPending(ctx, true) }
func (d *Daemon) recoverPending(ctx context.Context, startup bool) error {
	entries, e := d.store.Entries()
	if e != nil {
		return e
	}
	processed := 0
	for _, entry := range entries {
		if !startup && (processed >= 100 || entry.UpdatedAt.After(time.Now().Add(-30*time.Second)) || (entry.State != "abandoned" && entry.State != "uncertain")) {
			continue
		}
		if entry.State == "settled" {
			continue
		}
		processed++
		job, cancel := context.WithTimeout(ctx, 10*time.Second)
		grant, err := d.client.GrantStatus(job, entry.Request.ID)
		cancel()
		if err != nil {
			var remote control.Error
			if errors.As(err, &remote) && remote.Status == 404 {
				if e = d.store.Drop(entry.Request.ID); e != nil {
					return e
				}
				continue
			}
			return errors.New("usage recovery requires the controller")
		}
		if grant.Closed {
			if e = d.store.Drop(entry.Request.ID); e != nil {
				return e
			}
			continue
		}
		entry.Grant = grant
		if entry.State == "requested" || entry.State == "abandoned" {
			entry.State = "inflight"
			if e = d.store.Put(entry); e != nil {
				return e
			}
			if e = d.store.Settle(entry.Request.ID, 0, 0); e != nil {
				return e
			}
		} else {
			// A crash between socket I/O and durable settlement leaves an ambiguous
			// bounded grant. Hold that reservation for explicit reconciliation;
			// allocated bytes are not evidence of actual network traffic.
			entry.State = "uncertain"
			if e = d.store.Put(entry); e != nil {
				return e
			}
		}
	}
	return nil
}
func (d *Daemon) report(ctx context.Context) {
	id, e := control.RandomID()
	if e != nil {
		return
	}
	s := d.engine.Snapshot()
	connections := d.tracker.Connections()
	count := 0
	for _, v := range connections {
		count += v.Count
	}
	up, down := d.store.Totals()
	d.mu.Lock()
	message := d.lastError
	d.mu.Unlock()
	if entries, err := d.store.Entries(); err == nil {
		for _, entry := range entries {
			if entry.State == "uncertain" {
				message = "存在待人工核对的中断流量预留"
				break
			}
		}
	}
	report := wire.Report{ID: id, At: time.Now().UTC(), Revision: s.Revision, Healthy: d.tracker.Healthy() && message == "" && s.ValidUntil.After(time.Now()), Error: message, Version: d.version, Connections: connections, Metrics: d.metrics.sample(up, down, count)}
	raw, e := d.store.QueueReport(report)
	if e != nil {
		d.error("计量日志写入失败")
		return
	}
	job, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if e = d.client.DoRaw(job, "POST", "/api/agent/report", raw, nil); e == nil {
		if e = d.store.AckReport(raw); e != nil {
			d.error("计量确认写入失败")
		} else if e = d.writeStatus(report.Healthy); e != nil {
			d.error("健康状态写入失败")
		}
	}
}
