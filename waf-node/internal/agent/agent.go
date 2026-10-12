// Package agent validates complete site revisions before atomically publishing
// them to request handlers. Retired engines stay alive until their last request.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MonthyG/WAF/waf-node/internal/engine"
	"github.com/MonthyG/WAF/waf-node/internal/proxy"
	"github.com/nats-io/nats.go"
)

type Origin struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}
type Bundle struct {
	SiteID        string   `json:"site_id"`
	Revision      int64    `json:"revision"`
	Hostname      string   `json:"hostname"`
	EngineMode    string   `json:"engine_mode"`
	ParanoiaLevel int      `json:"paranoia_level"`
	Origins       []Origin `json:"origins"`
	HTTPRedirect  bool     `json:"http_redirect"`
	Limits        struct {
		RequestBodyKB int64 `json:"request_body_kb"`
	} `json:"limits"`
	InspectResponse bool   `json:"inspect_response_body"`
	SecLang         string `json:"seclang"`
}
type Message struct {
	Op     string `json:"op"`
	Bundle Bundle `json:"bundle"`
}
type entry struct {
	bundle  Bundle
	handler *proxy.Proxy
	refs    atomic.Int64
}

const retired = int64(1 << 62)

func (e *entry) acquire() bool {
	for {
		n := e.refs.Load()
		if n >= retired {
			return false
		}
		if e.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}
func (e *entry) release() {
	if e.refs.Add(-1) == retired {
		e.handler.Close()
	}
}
func (e *entry) retire() {
	if e.refs.Add(retired) == retired {
		e.handler.Close()
	}
}

type table struct{ hosts map[string]*entry }
type Agent struct {
	NodeID   string
	log      *slog.Logger
	table    atomic.Pointer[table]
	mu       sync.Mutex
	applied  map[string]int64
	failures atomic.Uint64
	nc       atomic.Pointer[nats.Conn]
}

func New(nodeID string, log *slog.Logger) *Agent {
	if log == nil {
		log = slog.Default()
	}
	a := &Agent{NodeID: nodeID, log: log, applied: map[string]int64{}}
	a.table.Store(&table{hosts: map[string]*entry{}})
	return a
}

func (a *Agent) Apply(m Message) (applyErr error) {
	defer func() {
		if applyErr != nil {
			a.failures.Add(1)
		}
	}()
	a.mu.Lock()
	defer a.mu.Unlock()
	b := m.Bundle
	if b.SiteID == "" || b.Revision < 1 {
		return errors.New("invalid site identity or revision")
	}
	if b.Revision <= a.applied[b.SiteID] {
		return nil
	}
	current := a.table.Load()
	next := &table{hosts: make(map[string]*entry, len(current.hosts)+1)}
	for host, e := range current.hosts {
		next.hosts[host] = e
	}
	var old *entry
	for host, e := range next.hosts {
		if e.bundle.SiteID == b.SiteID {
			old = e
			delete(next.hosts, host)
		}
	}
	if m.Op == "upsert" {
		if len(b.Origins) == 0 || len(b.Origins) > 20 {
			return errors.New("invalid origins")
		}
		if b.HTTPRedirect {
			return errors.New("TLS is not implemented")
		}
		if len(b.SecLang) > 1<<20 {
			return errors.New("SecLang exceeds size limit")
		}
		if e := next.hosts[b.Hostname]; e != nil {
			return errors.New("hostname already assigned to another site")
		}
		cfg := proxy.Config{SiteID: b.SiteID, Hostname: b.Hostname, Origin: b.Origins[0].URL, Mode: b.EngineMode, ParanoiaLevel: b.ParanoiaLevel, RequestBodyLimit: b.Limits.RequestBodyKB * 1024, InspectResponse: b.InspectResponse, Listen: "127.0.0.1:8080", ManagementListen: "127.0.0.1:9090"}
		if err := cfg.Validate(); err != nil {
			return err
		}
		for _, o := range b.Origins {
			cfg.Origins = append(cfg.Origins, proxy.Origin{URL: o.URL, Weight: o.Weight})
		}
		waf, err := engine.Compile(b.SecLang)
		if err != nil {
			return fmt.Errorf("compile failed: %w", err)
		}
		p, err := proxy.NewWithWAF(cfg, waf, a.log)
		if err != nil {
			return err
		}
		next.hosts[b.Hostname] = &entry{bundle: b, handler: p}
	} else if m.Op != "delete" {
		return errors.New("invalid config operation")
	}
	a.table.Store(next)
	a.applied[b.SiteID] = b.Revision
	if old != nil {
		old.retire()
	}
	return nil
}

func (a *Agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for {
		e := a.table.Load().hosts[host]
		if e == nil {
			http.Error(w, "Unknown protected site", 404)
			return
		}
		if !e.acquire() {
			continue
		}
		defer e.release()
		e.handler.ServeHTTP(w, r)
		return
	}
}
func (a *Agent) Applied() map[string]int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := map[string]int64{}
	for k, v := range a.applied {
		m[k] = v
	}
	return m
}
func (a *Agent) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.table.Swap(&table{hosts: map[string]*entry{}})
	for _, e := range old.hosts {
		e.retire()
	}
}
func (a *Agent) ManagementHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"node_id": a.NodeID, "applied": a.Applied()})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		nc := a.nc.Load()
		if nc == nil || !nc.IsConnected() {
			http.Error(w, "NATS unavailable", 503)
			return
		}
		w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# TYPE waf_agent_apply_failures_total counter\nwaf_agent_apply_failures_total %d\n# TYPE waf_config_revision gauge\n", a.failures.Load())
		for id, rev := range a.Applied() {
			fmt.Fprintf(w, "waf_config_revision{site=%q} %d\n", id, rev)
		}
		for _, e := range a.table.Load().hosts {
			if e.acquire() {
				e.handler.ManagementHandler().ServeHTTP(w, r)
				e.release()
			}
		}
	})
	return mux
}

// Run restores the authoritative snapshot before consuming durable updates.
// Both successful and rejected deliveries are acknowledged to JetStream; a
// rejected revision is reported to control and does not replace the old engine.
func (a *Agent) Run(ctx context.Context, nc *nats.Conn) error {
	a.nc.Store(nc)
	snapshotCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := nc.RequestWithContext(snapshotCtx, "waf.config.snapshot."+a.NodeID, []byte(`{}`))
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	var snapshot struct {
		Bundles  []Bundle `json:"bundles"`
		Sequence uint64   `json:"sequence"`
	}
	if err := json.Unmarshal(reply.Data, &snapshot); err != nil {
		return err
	}
	for _, b := range snapshot.Bundles {
		if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
			return err
		}
	}
	js, err := nc.JetStream()
	if err != nil {
		return err
	}
	sub, err := js.PullSubscribe("waf.config."+a.NodeID, "node-"+a.NodeID, nats.BindStream("WAF_CONFIG"))
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()
	heartbeat := func() {
		data, _ := json.Marshal(map[string]any{"node_id": a.NodeID, "version": "0.1.0", "load": 0, "applied": a.Applied()})
		nc.Publish("waf.node.heartbeat."+a.NodeID, data)
	}
	heartbeat()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			heartbeat()
		default:
		}
		msgs, err := sub.Fetch(16, nats.MaxWait(time.Second))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for _, msg := range msgs {
			if meta, err := msg.Metadata(); err == nil && meta.Sequence.Stream <= snapshot.Sequence {
				msg.Ack()
				continue
			}
			var m Message
			err := json.Unmarshal(msg.Data, &m)
			if err == nil {
				err = a.Apply(m)
			}
			ack := map[string]any{"node_id": a.NodeID, "site_id": m.Bundle.SiteID, "revision": m.Bundle.Revision, "ok": err == nil}
			if err != nil {
				ack["error"] = "Node rejected the configuration; previous revision retained"
				a.log.Error("configuration rejected", "site_id", m.Bundle.SiteID, "revision", m.Bundle.Revision)
			}
			data, _ := json.Marshal(ack)
			if err := nc.Publish("waf.node.ack."+a.NodeID, data); err != nil {
				return err
			}
			if err := nc.Flush(); err != nil {
				return err
			}
			msg.Ack()
		}
	}
}
