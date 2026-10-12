package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func testConfig(origin, mode string) Config {
	return Config{SiteID: "test", Hostname: "shop.localhost", Origin: origin, Listen: "127.0.0.1:8080", ManagementListen: "127.0.0.1:9090", Mode: mode, ParanoiaLevel: 1, RequestBodyLimit: 1 << 20}
}

func fixture(t testing.TB, c Config, handler http.Handler, log *slog.Logger) (*Proxy, *httptest.Server) {
	t.Helper()
	origin := httptest.NewServer(handler)
	t.Cleanup(origin.Close)
	c.Origin = origin.URL
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	p, err := New(c, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	s := httptest.NewServer(p)
	t.Cleanup(s.Close)
	return p, s
}

func request(t testing.TB, s *httptest.Server, method, path, body, contentType string) (*http.Response, string) {
	t.Helper()
	r, err := http.NewRequest(method, s.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "shop.localhost"
	r.Header.Set("User-Agent", "CloudInside integration test")
	r.Header.Set("Accept", "application/json")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	res, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(data)
}

func TestAttackModes(t *testing.T) {
	for _, mode := range []string{"block", "detect", "off"} {
		t.Run(mode, func(t *testing.T) {
			var reached atomic.Int64
			var logs bytes.Buffer
			p, s := fixture(t, testConfig("", mode), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"ok":true}`)
			}), slog.New(slog.NewJSONHandler(&logs, nil)))
			cases := []struct{ name, method, path, body, ctype string }{
				{"SQLi-query", "GET", "/?q=" + url.QueryEscape("' OR 1=1 UNION SELECT username,password FROM users--"), "", ""},
				{"XSS-query", "GET", "/?q=" + url.QueryEscape("<script>alert(document.cookie)</script>"), "", ""},
				{"SQLi-form", "POST", "/login", "username=" + url.QueryEscape("' OR 1=1--"), "application/x-www-form-urlencoded"},
				{"XSS-json", "POST", "/comment", `{"comment":"<script>alert(1)</script>"}`, "application/json"},
				{"traversal", "GET", "/?file=..%2F..%2Fetc%2Fpasswd", "", ""},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					res, body := request(t, s, tc.method, tc.path, tc.body, tc.ctype)
					want := 200
					if mode == "block" {
						want = 403
					}
					if res.StatusCode != want {
						t.Fatalf("status %d, want %d: %s", res.StatusCode, want, body)
					}
					if mode != "off" && res.Header.Get("X-CloudInside-WAF-Event") == "" {
						t.Fatal("missing event correlation header")
					}
					if mode == "block" && !strings.Contains(body, res.Header.Get("X-CloudInside-WAF-Event")) {
						t.Fatal("blocked page lacks event ID")
					}
				})
			}
			if mode == "block" && reached.Load() != 0 {
				t.Fatal("attack reached origin")
			}
			if mode != "block" && reached.Load() != int64(len(cases)) {
				t.Fatal("detect/off did not forward")
			}
			if mode == "detect" && !strings.Contains(logs.String(), `"action":"detected"`) {
				t.Fatal("detect mode did not log")
			}
			if mode == "off" && logs.Len() != 0 {
				t.Fatal("off mode unexpectedly logged matches")
			}
			if strings.Contains(logs.String(), "document.cookie") || strings.Contains(logs.String(), "username,password") {
				t.Fatal("sensitive matched data leaked into audit log")
			}
			r := httptest.NewRecorder()
			p.ManagementHandler().ServeHTTP(r, httptest.NewRequest("GET", "/metrics", nil))
			if !strings.Contains(r.Body.String(), `waf_requests_total{site="test",action=`) {
				t.Fatal("missing metrics")
			}
		})
	}
}

func TestBenignForwarding(t *testing.T) {
	_, s := fixture(t, testConfig("", "block"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"body": string(body), "host": r.Host, "xff": r.Header.Get("X-Forwarded-For"), "proto": r.Header.Get("X-Forwarded-Proto"), "event": r.Header.Get("X-CloudInside-WAF-Event"), "forwarded": r.Header.Get("Forwarded")})
	}), nil)
	for _, tc := range []struct{ body, ctype string }{{"name=Alice&city=Taipei", "application/x-www-form-urlencoded"}, {`{"name":"Alice","quantity":2}`, "application/json"}} {
		res, data := request(t, s, "POST", "/orders?sort=date", tc.body, tc.ctype)
		if res.StatusCode != 200 {
			t.Fatalf("benign blocked: %d %s", res.StatusCode, data)
		}
		var got map[string]string
		if err := json.Unmarshal([]byte(data), &got); err != nil {
			t.Fatal(err)
		}
		if got["body"] != tc.body || got["host"] != "shop.localhost" || got["proto"] != "http" {
			t.Fatalf("forwarding corrupted: %v", got)
		}
	}
	r, _ := http.NewRequest("GET", s.URL+"/", nil)
	r.Host = "SHOP.LOCALHOST:8080"
	r.Header.Set("X-Forwarded-For", "198.51.100.99")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Forwarded", "for=198.51.100.99")
	r.Header.Set("X-CloudInside-WAF-Event", "spoofed")
	res, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var got map[string]string
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["xff"] != "127.0.0.1" || got["proto"] != "http" || got["event"] == "spoofed" || got["forwarded"] != "" {
		t.Fatalf("spoofed forwarding headers: %v", got)
	}
}

func TestUnknownHostAndManagementIsolation(t *testing.T) {
	var reached atomic.Int64
	p, s := fixture(t, testConfig("", "block"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); io.WriteString(w, "customer origin") }), nil)
	r, _ := http.NewRequest("GET", s.URL+"/", nil)
	r.Host = "other.example"
	res, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 404 || reached.Load() != 0 {
		t.Fatal("unknown host forwarded")
	}
	_, body := request(t, s, "GET", "/metrics", "", "")
	if body != "customer origin" {
		t.Fatal("management endpoint exposed on traffic listener")
	}
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		r := httptest.NewRecorder()
		p.ManagementHandler().ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 200 {
			t.Fatalf("%s: %d", path, r.Code)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	for _, mode := range []string{"block", "detect", "off"} {
		t.Run(mode, func(t *testing.T) {
			var reached atomic.Int64
			c := testConfig("", mode)
			c.RequestBodyLimit = 64
			_, s := fixture(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }), nil)
			for _, chunked := range []bool{false, true} {
				r, _ := http.NewRequest("POST", s.URL+"/", strings.NewReader(strings.Repeat("x", 65)))
				r.Host = c.Hostname
				r.Header.Set("Content-Type", "text/plain")
				if chunked {
					r.ContentLength = -1
				}
				res, err := s.Client().Do(r)
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if res.StatusCode != 413 {
					t.Fatalf("chunked=%t status=%d", chunked, res.StatusCode)
				}
			}
			if reached.Load() != 0 {
				t.Fatal("oversized body reached origin")
			}
		})
	}
}

func TestOriginFailureAndTLSVerification(t *testing.T) {
	for _, tlsOrigin := range []bool{false, true} {
		t.Run(fmt.Sprint(tlsOrigin), func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "should not be reached") }))
			defer origin.Close()
			c := testConfig(origin.URL, "block")
			if !tlsOrigin {
				origin.Close()
			}
			p, err := New(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			s := httptest.NewServer(p)
			defer s.Close()
			res, _ := request(t, s, "GET", "/", "", "")
			if res.StatusCode != 502 {
				t.Fatalf("expected 502, got %d", res.StatusCode)
			}
			r := httptest.NewRecorder()
			p.ManagementHandler().ServeHTTP(r, httptest.NewRequest("GET", "/readyz", nil))
			if r.Code != 503 {
				t.Fatal("unavailable origin reported ready")
			}
		})
	}
}

func TestResponseInspection(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		t.Run(fmt.Sprint(inspect), func(t *testing.T) {
			c := testConfig("", "block")
			c.InspectResponse = inspect
			_, s := fixture(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				io.WriteString(w, "<html>ViewStateException: Invalid viewstate detected.</html>")
			}), nil)
			res, body := request(t, s, "GET", "/", "", "")
			want := 200
			if inspect {
				want = 403
			}
			if res.StatusCode != want {
				t.Fatalf("status=%d body=%s", res.StatusCode, body)
			}
			if inspect && strings.Contains(body, "ViewStateException") {
				t.Fatal("blocked response leaked")
			}
		})
	}
}

func TestParallelRequests(t *testing.T) {
	_, s := fixture(t, testConfig("", "block"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}), nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				res, _ := request(t, s, "GET", "/?name=alice", "", "")
				if res.StatusCode != 200 {
					t.Errorf("status=%d", res.StatusCode)
				}
			}
		}()
	}
	wg.Wait()
}

func TestConfigValidation(t *testing.T) {
	base := testConfig("http://127.0.0.1:9080", "detect")
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []func(*Config){func(c *Config) { c.Hostname = "*.example.com" }, func(c *Config) { c.Hostname = "bad\nexample" }, func(c *Config) { c.Hostname = "-bad.example" }, func(c *Config) { c.Origin = "file:///etc/passwd" }, func(c *Config) { c.Origin = "https://user:pass@example.com" }, func(c *Config) { c.Origin = "https://example.com/path" }, func(c *Config) { c.Mode = "oops" }, func(c *Config) { c.ParanoiaLevel = 5 }, func(c *Config) { c.RequestBodyLimit = 0 }, func(c *Config) { c.ManagementListen = "0.0.0.0:9090" }}
	for i, change := range cases {
		c := base
		change(&c)
		if c.Validate() == nil {
			t.Errorf("case %d accepted invalid config", i)
		}
	}
}

func TestLargeResponsePreserved(t *testing.T) {
	for _, inspect := range []bool{false, true} {
		t.Run(fmt.Sprint(inspect), func(t *testing.T) {
			body := strings.Repeat("hello ", 200000)
			c := testConfig("", "block")
			c.InspectResponse = inspect
			_, s := fixture(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				io.WriteString(w, body)
			}), nil)
			res, got := request(t, s, "GET", "/", "", "")
			if res.StatusCode != 200 || got != body {
				t.Fatalf("response truncated/corrupted: status=%d got=%d want=%d", res.StatusCode, len(got), len(body))
			}
		})
	}
}

func TestChunkedBodyPreserved(t *testing.T) {
	want := `{"name":"Alice","quantity":2}`
	_, s := fixture(t, testConfig("", "block"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, r.Body)
	}), nil)
	r, _ := http.NewRequest("POST", s.URL+"/", strings.NewReader(want))
	r.Host = "shop.localhost"
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/json")
	res, err := s.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || string(got) != want {
		t.Fatalf("chunked body corrupted: %d %q", res.StatusCode, got)
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("broken connection") }
func (brokenBody) Close() error             { return nil }

func TestInspectionReadFailureDoesNotForward(t *testing.T) {
	var reached atomic.Int64
	p, _ := fixture(t, testConfig("", "block"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }), nil)
	r := httptest.NewRequest("POST", "http://shop.localhost/", brokenBody{})
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 400 || reached.Load() != 0 {
		t.Fatalf("inspection error forwarded or accepted: %d %d", w.Code, reached.Load())
	}
}

func TestBenignCRSSetupMatchesAreNotAttacks(t *testing.T) {
	var logs bytes.Buffer
	p, s := fixture(t, testConfig("", "detect"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}), slog.New(slog.NewJSONHandler(&logs, nil)))
	response, _ := request(t, s, "GET", "/products?category=books", "", "")
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	if response.Header.Get("X-WAF-Event-ID") != "" {
		t.Fatal("benign request received attack event header")
	}
	if strings.Contains(logs.String(), "waf_event") {
		t.Fatal("CRS setup rules were reported as security events")
	}
	metrics := httptest.NewRecorder()
	p.ManagementHandler().ServeHTTP(metrics, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `waf_requests_total{site="test",action="allowed"} 1`) {
		t.Fatal("benign request counted as detection")
	}
	response, _ = request(t, s, "GET", "/?q="+url.QueryEscape("<script>alert(1)</script>"), "", "")
	if response.StatusCode != 200 || !strings.Contains(logs.String(), `"action":"detected"`) {
		t.Fatal("detect-mode attack event was lost")
	}
}

func TestObservationIsBoundedAndOmitsRequestSecrets(t *testing.T) {
	p, s := fixture(t, testConfig("", "block"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello") }), nil)
	observations := make(chan Observation, 2)
	p.Observe = func(o Observation) { observations <- o }
	response, _ := request(t, s, "GET", "/private?access_token=secret", "", "")
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	observation := <-observations
	if observation.Action != "allowed" || observation.BytesOut != 5 || observation.Status != 200 || observation.Path != "" || observation.ClientIP != "" {
		t.Fatalf("incorrect benign observation: %+v", observation)
	}
	response, _ = request(t, s, "GET", "/private?q="+url.QueryEscape("<script>alert(1)</script>")+"&access_token=secret", "", "")
	if response.StatusCode != 403 {
		t.Fatal(response.StatusCode)
	}
	observation = <-observations
	data, _ := json.Marshal(observation)
	if strings.Contains(string(data), "secret") || strings.Contains(string(data), "<script>") {
		t.Fatal("observation leaked query data")
	}
	if observation.Action != "blocked" || observation.Status != 403 || observation.Path != "/private" || len(observation.RuleIDs) == 0 {
		t.Fatalf("incorrect blocked observation: %+v", observation)
	}
}

func TestLongMethodDoesNotPoisonTelemetryBatch(t *testing.T) {
	p, server := fixture(t, testConfig("", "detect"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }), nil)
	observations := make(chan Observation, 1)
	p.Observe = func(o Observation) { observations <- o }
	request(t, server, strings.Repeat("A", 100), "/", "", "")
	if got := <-observations; len(got.Method) != 32 {
		t.Fatalf("unbounded method: %d", len(got.Method))
	}
}
