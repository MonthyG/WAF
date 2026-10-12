package engine

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
)

func TestXMLAttributeInspection(t *testing.T) {
	cfg, err := Config(Options{Mode: "block", ParanoiaLevel: 1, RequestBodyLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	waf, err := coraza.NewWAF(cfg.WithErrorCallback(func(m types.MatchedRule) { t.Log(m.ErrorLog()) }))
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := waf.(experimental.WAFCloser); ok {
		defer c.Close()
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("127.0.0.1", 1234, "127.0.0.1", 8080)
	tx.ProcessURI("/post", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "shop.localhost")
	tx.AddRequestHeader("User-Agent", "CloudInside regression test")
	tx.AddRequestHeader("Content-Type", "application/xml")
	tx.ProcessRequestHeaders()
	_, _, err = tx.WriteRequestBody([]byte(`<?xml version="1.0"?><root><a probe="1234 OR 1=1"></a></root>`))
	if err != nil {
		t.Fatal(err)
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatal(err)
	}
	tx.ProcessLogging()
	if it == nil {
		t.Fatal("SQL injection in XML attribute was not blocked")
	}
}

func BenchmarkPL1(b *testing.B) {
	benchmarkPL1(b, false)
}

func BenchmarkPL1ExperimentalPrefilter(b *testing.B) {
	benchmarkPL1(b, true)
}

func benchmarkPL1(b *testing.B, prefilter bool) {
	waf, err := New(Options{Mode: "block", ParanoiaLevel: 1, RequestBodyLimit: 1 << 20, ExperimentalRXPrefilter: prefilter})
	if err != nil {
		b.Fatal(err)
	}
	if c, ok := waf.(experimental.WAFCloser); ok {
		defer c.Close()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		tx.ProcessConnection("127.0.0.1", 1234, "127.0.0.1", 8080)
		tx.ProcessURI("/products?category=books&page=1", "GET", "HTTP/1.1")
		tx.AddRequestHeader("Host", "shop.localhost")
		tx.AddRequestHeader("User-Agent", "CloudInside-benchmark")
		tx.AddRequestHeader("Accept", "application/json")
		if tx.ProcessRequestHeaders() != nil {
			b.Fatal("benign headers blocked")
		}
		if it, err := tx.ProcessRequestBody(); err != nil || it != nil {
			b.Fatalf("benign request rejected: %v %v", it, err)
		}
		tx.AddResponseHeader("Content-Type", "application/json")
		tx.ProcessResponseHeaders(200, "HTTP/1.1")
		if _, err := tx.ProcessResponseBody(); err != nil {
			b.Fatal(err)
		}
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
