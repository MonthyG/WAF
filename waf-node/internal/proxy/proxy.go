package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MonthyG/WAF/waf-node/internal/engine"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

type requestState struct {
	tx      types.Transaction
	blocked bool
	failed  bool
}
type stateKey struct{}

var errResponseBlocked = errors.New("response blocked by WAF")

type Proxy struct {
	Observe   func(Observation) // Configure before serving requests.
	cfg       Config
	waf       coraza.WAF
	upstream  *httputil.ReverseProxy
	transport *http.Transport
	log       *slog.Logger
	metrics   metrics
}

func New(c Config, log *slog.Logger) (*Proxy, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	waf, err := engine.New(engine.Options{Mode: c.Mode, ParanoiaLevel: c.ParanoiaLevel, RequestBodyLimit: c.RequestBodyLimit, InspectResponse: c.InspectResponse})
	if err != nil {
		return nil, fmt.Errorf("compile WAF: %w", err)
	}
	return NewWithWAF(c, waf, log)
}

// NewWithWAF allows the CRS regression harness to exercise this exact connector
// with the upstream suite's prescribed engine configuration.
func NewWithWAF(c Config, waf coraza.WAF, log *slog.Logger) (*Proxy, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if waf == nil {
		return nil, fmt.Errorf("WAF is required")
	}
	if log == nil {
		log = slog.Default()
	}
	u, _ := url.Parse(c.Origin)
	targets := []*url.URL{u}
	weights := []uint64{1}
	totalWeight := uint64(1)
	if len(c.Origins) > 0 {
		targets = nil
		weights = nil
		totalWeight = 0
		for _, o := range c.Origins {
			check := c
			check.Origin = o.URL
			check.Origins = nil
			if err := check.Validate(); err != nil {
				return nil, err
			}
			if o.Weight < 1 || o.Weight > 100 {
				return nil, fmt.Errorf("origin weight must be 1–100")
			}
			target, _ := url.Parse(o.URL)
			targets = append(targets, target)
			weights = append(weights, uint64(o.Weight))
			totalWeight += uint64(o.Weight)
		}
	}
	var sequence atomic.Uint64
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Customer origins are reached directly, not through the controller's egress proxy.
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = 128
	p := &Proxy{cfg: c, waf: waf, transport: transport, log: log}
	p.metrics.hits = make(map[int]uint64)
	p.upstream = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			position := (sequence.Add(1) - 1) % totalWeight
			for i, weight := range weights {
				if position < weight {
					r.SetURL(targets[i])
					break
				}
				position -= weight
			}
			r.Out.Host = c.Hostname
			// Rewrite strips inbound Forwarded and X-Forwarded-* before this call.
			r.SetXForwarded()
			r.Out.Header.Del("X-CloudInside-WAF-Event")
			st := r.In.Context().Value(stateKey{}).(*requestState)
			if len(alertMatches(st.tx)) > 0 {
				r.Out.Header.Set("X-CloudInside-WAF-Event", st.tx.ID())
			}
			if c.InspectResponse {
				r.Out.Header.Del("Accept-Encoding")
			}
		},
		ModifyResponse: func(r *http.Response) error {
			st := r.Request.Context().Value(stateKey{}).(*requestState)
			if st.tx.IsRuleEngineOff() {
				return nil
			}
			for k, values := range r.Header {
				for _, v := range values {
					st.tx.AddResponseHeader(k, v)
				}
			}
			if r.ContentLength >= 0 {
				st.tx.AddResponseHeader("Content-Length", strconv.FormatInt(r.ContentLength, 10))
			}
			if it := st.tx.ProcessResponseHeaders(r.StatusCode, r.Proto); it != nil {
				st.blocked = true
				return errResponseBlocked
			}
			if st.tx.IsResponseBodyAccessible() && st.tx.IsResponseBodyProcessable() {
				// Buffer at most the configured 1 MiB inspection prefix. Stream the rest.
				original := r.Body
				it, _, err := st.tx.ReadResponseBodyFrom(original)
				if err != nil {
					return err
				}
				if it != nil {
					st.blocked = true
					return errResponseBlocked
				}
				body, err := st.tx.ResponseBodyReader()
				if err != nil {
					return err
				}
				r.Body = &joinedBody{Reader: io.MultiReader(body, original), Closer: original}
			}
			it, err := st.tx.ProcessResponseBody()
			if err != nil {
				return err
			}
			if it != nil {
				st.blocked = true
				return errResponseBlocked
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			st := r.Context().Value(stateKey{}).(*requestState)
			if errors.Is(err, errResponseBlocked) {
				block(w, st.tx.ID())
				return
			}
			st.failed = true
			p.log.Error("origin request failed", "site_id", c.SiteID, "event_id", st.tx.ID())
			http.Error(w, "Origin unavailable", http.StatusBadGateway)
		},
	}
	return p, nil
}

type joinedBody struct {
	io.Reader
	io.Closer
}

// Close must be called only after the HTTP server has drained active requests.
func (p *Proxy) Close() error {
	p.transport.CloseIdleConnections()
	if closer, ok := p.waf.(experimental.WAFCloser); ok {
		return closer.Close()
	}
	return nil
}

// Coraza includes nolog setup/control matches in MatchedRules. They are not
// security detections and must not inflate attack counters or event headers.
func alertMatches(tx types.Transaction) []types.MatchedRule {
	var alerts []types.MatchedRule
	for _, match := range tx.MatchedRules() {
		if logging, ok := match.(interface{ Log() bool }); ok && !logging.Log() {
			continue
		}
		alerts = append(alerts, match)
	}
	return alerts
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.TrimSuffix(strings.ToLower(host), ".") != p.cfg.Hostname {
		http.Error(w, "Unknown protected site", http.StatusNotFound)
		return
	}
	started := time.Now()
	captured := &responseCapture{ResponseWriter: w}
	w = captured
	tx := p.waf.NewTransaction()
	st := &requestState{tx: tx}
	action := "allowed"
	defer func() {
		tx.ProcessLogging()
		if st.blocked {
			action = "blocked"
		} else if st.failed {
			action = "error"
		} else if action != "rejected" && len(alertMatches(tx)) > 0 {
			action = "detected"
		}
		p.metrics.record(action)
		var eventRuleIDs []int
		if matches := alertMatches(tx); len(matches) > 0 {
			ids := make([]int, 0, len(matches))
			seen := map[int]bool{}
			for _, m := range matches {
				id := m.Rule().ID()
				if !seen[id] {
					ids = append(ids, id)
					seen[id] = true
					p.metrics.hit(id)
				}
			}
			eventRuleIDs = ids
			// Do not record query strings, bodies, cookies, tokens, or matched data.
			p.log.Info("waf_event", "event_id", tx.ID(), "site_id", p.cfg.SiteID, "action", action, "rule_ids", ids, "method", r.Method, "client_ip", clientIP(r.RemoteAddr))
		}
		if p.Observe != nil {
			status := captured.status
			if status == 0 {
				status = http.StatusOK
			}
			observation := Observation{EventID: tx.ID(), SiteID: p.cfg.SiteID, Timestamp: started.UTC(), Action: action, Method: r.Method, RuleIDs: eventRuleIDs, Status: status, BytesOut: captured.bytes, DurationMS: float64(time.Since(started)) / float64(time.Millisecond)}
			if len(eventRuleIDs) > 0 {
				observation.Path = r.URL.EscapedPath()
				if len(observation.Path) > 2048 {
					observation.Path = observation.Path[:2048]
				}
				observation.ClientIP = clientIP(r.RemoteAddr)
			}
			p.Observe(observation)
		}
		if err := tx.Close(); err != nil {
			p.log.Error("transaction cleanup failed", "event_id", tx.ID())
		}
	}()
	if r.ContentLength > p.cfg.RequestBodyLimit {
		action = "rejected"
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !tx.IsRuleEngineOff() {
		if it, err := inspectRequest(tx, r, p.cfg.RequestBodyLimit); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				action = "rejected"
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			} else {
				st.failed = true
				http.Error(w, "Unable to inspect request", http.StatusBadRequest)
			}
			return
		} else if it != nil {
			st.blocked = true
			block(w, tx.ID())
			return
		}
	} else if r.Body != nil {
		// Enforce the same resource ceiling in off mode, including chunked uploads.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.cfg.RequestBodyLimit))
		if err != nil {
			action = "rejected"
			http.Error(w, "Request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	if len(alertMatches(tx)) > 0 {
		w.Header().Set("X-CloudInside-WAF-Event", tx.ID())
	}
	upstreamStarted := time.Now()
	p.upstream.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
	p.metrics.observe(time.Since(upstreamStarted).Seconds())
}

func inspectRequest(tx types.Transaction, r *http.Request, limit int64) (*types.Interruption, error) {
	client, port, _ := net.SplitHostPort(r.RemoteAddr)
	clientPort, _ := strconv.Atoi(port)
	tx.ProcessConnection(client, clientPort, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	tx.SetServerName(r.Host)
	tx.AddRequestHeader("Host", r.Host)
	for k, values := range r.Header {
		for _, v := range values {
			tx.AddRequestHeader(k, v)
		}
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	if r.Body != nil && r.Body != http.NoBody {
		// A hard cap applies even in DetectionOnly, where Coraza otherwise permits
		// uninspected bytes beyond its limit. Never forward a truncated request.
		original := r.Body
		defer original.Close()
		body, err := io.ReadAll(http.MaxBytesReader(nil, original, limit))
		if err != nil {
			return nil, err
		}
		if tx.IsRequestBodyAccessible() {
			it, _, err := tx.WriteRequestBody(body)
			if err != nil || it != nil {
				return it, err
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return tx.ProcessRequestBody()
}

func clientIP(remote string) string { host, _, _ := net.SplitHostPort(remote); return host }

func block(w http.ResponseWriter, id string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-CloudInside-WAF-Event", id)
	w.WriteHeader(http.StatusForbidden)
	// Coraza generates the event ID; no request-derived content is interpolated.
	fmt.Fprintf(w, "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>CloudInside WAF</title><style>body{font:18px system-ui;background:#101827;color:#e5eaf3;max-width:640px;margin:15vh auto;padding:24px}small{color:#9fb0cb}code{overflow-wrap:anywhere}</style><small>CLOUDINSIDE · WAF</small><h1>Request blocked</h1><p>This request was blocked by this site’s security policy. Contact the site owner if you believe this was a mistake.</p><p>Event ID: <code>%s</code></p></html>", id)
}

type metrics struct {
	allowed, blocked, detected, rejected, failed atomic.Uint64
	mu                                           sync.Mutex
	hits                                         map[int]uint64
	latencyCount                                 uint64
	latencySum                                   float64
	buckets                                      [7]uint64
}

var bounds = [...]float64{.001, .005, .01, .05, .1, .5, 1}

func (m *metrics) record(action string) {
	switch action {
	case "blocked":
		m.blocked.Add(1)
	case "detected":
		m.detected.Add(1)
	case "rejected":
		m.rejected.Add(1)
	case "error":
		m.failed.Add(1)
	default:
		m.allowed.Add(1)
	}
}
func (m *metrics) hit(id int) { m.mu.Lock(); defer m.mu.Unlock(); m.hits[id]++ }
func (m *metrics) observe(seconds float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencyCount++
	m.latencySum += seconds
	for i, upper := range bounds {
		if seconds <= upper {
			m.buckets[i]++
		}
	}
}

func (p *Proxy) ManagementHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, "{\"status\":\"ok\"}\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.Origin, nil)
		req.Host = p.cfg.Hostname
		res, err := p.transport.RoundTrip(req)
		if err != nil {
			http.Error(w, "origin unavailable", http.StatusServiceUnavailable)
			return
		}
		defer res.Body.Close()
		if res.StatusCode >= 500 {
			http.Error(w, "origin unhealthy", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		m := &p.metrics
		fmt.Fprintln(w, "# HELP waf_requests_total Completed requests for the configured site.\n# TYPE waf_requests_total counter")
		for _, v := range []struct {
			action string
			count  uint64
		}{{"allowed", m.allowed.Load()}, {"blocked", m.blocked.Load()}, {"detected", m.detected.Load()}, {"rejected", m.rejected.Load()}, {"error", m.failed.Load()}} {
			fmt.Fprintf(w, "waf_requests_total{site=%q,action=%q} %d\n", p.cfg.SiteID, v.action, v.count)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		fmt.Fprintln(w, "# HELP waf_rule_hits_total Requests matching each rule.\n# TYPE waf_rule_hits_total counter")
		for id, count := range m.hits {
			fmt.Fprintf(w, "waf_rule_hits_total{site=%q,rule_id=\"%d\"} %d\n", p.cfg.SiteID, id, count)
		}
		fmt.Fprintln(w, "# HELP waf_upstream_latency_seconds Upstream round trip including response transfer and inspection.\n# TYPE waf_upstream_latency_seconds histogram")
		for i, upper := range bounds {
			fmt.Fprintf(w, "waf_upstream_latency_seconds_bucket{site=%q,le=\"%g\"} %d\n", p.cfg.SiteID, upper, m.buckets[i])
		}
		fmt.Fprintf(w, "waf_upstream_latency_seconds_bucket{site=%q,le=\"+Inf\"} %d\nwaf_upstream_latency_seconds_sum{site=%q} %g\nwaf_upstream_latency_seconds_count{site=%q} %d\n", p.cfg.SiteID, m.latencyCount, p.cfg.SiteID, m.latencySum, p.cfg.SiteID, m.latencyCount)
	})
	return mux
}
