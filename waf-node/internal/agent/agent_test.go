package agent

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func testBundle(origin string, revision int64) Bundle {
	b := Bundle{SiteID: "11111111-1111-4111-8111-111111111111", Revision: revision, Hostname: "shop.localhost", EngineMode: "block", ParanoiaLevel: 1, Origins: []Origin{{URL: origin, Weight: 1}}, SecLang: `SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS:attack "@streq true" "id:9000100,phase:2,deny,status:403,log"`}
	b.Limits.RequestBodyKB = 1024
	return b
}

func TestInvalidRevisionRetainsLastGood(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "origin") }))
	defer origin.Close()
	a := New("node", slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer a.Close()
	b := testBundle(origin.URL, 2)
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	bad := b
	bad.Revision = 3
	bad.SecLang = `SecRule ARGS "@rx [" "id:9000100,phase:2,deny"`
	if a.Apply(Message{Op: "upsert", Bundle: bad}) == nil {
		t.Fatal("invalid rule accepted")
	}
	if a.Applied()[b.SiteID] != 2 {
		t.Fatal("failed revision replaced the good revision")
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/?attack=true", nil))
	if w.Code != 403 {
		t.Fatalf("old protection lost: %d", w.Code)
	}
	b.Revision = 1
	b.SecLang = "SecRuleEngine Off"
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	if a.Applied()[b.SiteID] != 2 {
		t.Fatal("older revision accepted")
	}
}

func TestReloadPreservesInflightRequest(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; io.WriteString(w, "finished") }))
	defer origin.Close()
	a := New("node", slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer a.Close()
	b := testBundle(origin.URL, 1)
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/", nil))
		done <- w
	}()
	<-entered
	b.Revision = 2
	if err := a.Apply(Message{Op: "delete", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/", nil))
	if w.Code != 404 {
		t.Fatal("deleted site still routes")
	}
	close(release)
	result := <-done
	if result.Code != 200 || result.Body.String() != "finished" {
		t.Fatal("in-flight request dropped")
	}
	b.Revision = 1
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/", nil))
	if w.Code != 404 {
		t.Fatal("stale config resurrected deleted site")
	}
}

func TestConcurrentReloads(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	a := New("node", slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer a.Close()
	b := testBundle(origin.URL, 1)
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				w := httptest.NewRecorder()
				a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/", nil))
				if w.Code != 200 || w.Body.String() != "ok" {
					failures.Add(1)
				}
			}
		}()
	}
	for revision := int64(2); revision < 22; revision++ {
		b.Revision = revision
		if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d requests dropped", failures.Load())
	}
	t.Log("800 requests completed across 20 reloads without a dropped request")
}

func TestWeightedOrigins(t *testing.T) {
	var hits [2]atomic.Int64
	servers := make([]*httptest.Server, 2)
	for i := range servers {
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits[i].Add(1); fmt.Fprint(w, "ok") }))
		defer servers[i].Close()
	}
	a := New("node", slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer a.Close()
	b := testBundle(servers[0].URL, 1)
	b.Origins = append(b.Origins, Origin{URL: servers[1].URL, Weight: 2})
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/", nil))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	if hits[0].Load() != 10 || hits[1].Load() != 20 {
		t.Fatal("origin weights were not applied")
	}
}

func TestMetricsAcrossSitesDeclareFamiliesOnce(t *testing.T) {
	a := New("node", nil)
	defer a.Close()
	b := testBundle("http://127.0.0.1:1", 1)
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	b.SiteID = "22222222-2222-4222-8222-222222222222"
	b.Hostname = "other.localhost"
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.ManagementHandler().ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/metrics", nil))
	for _, name := range []string{"waf_requests_total", "waf_rule_hits_total", "waf_upstream_latency_seconds"} {
		if strings.Count(w.Body.String(), "# TYPE "+name+" ") != 1 {
			t.Fatalf("duplicate or missing metric declaration: %s", name)
		}
	}
	if !strings.Contains(w.Body.String(), `site="11111111-1111-4111-8111-111111111111"`) || !strings.Contains(w.Body.String(), `site="22222222-2222-4222-8222-222222222222"`) {
		t.Fatal("missing site metrics")
	}
}
