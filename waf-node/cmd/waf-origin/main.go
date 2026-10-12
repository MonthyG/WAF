// waf-origin is a loopback-only development fixture, not a customer application.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9080", "loopback listen address")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("development origin must use a literal loopback IP")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
		if err != nil {
			http.Error(w, "body too large", 413)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"service": "CloudInside test origin", "method": r.Method, "path": r.URL.Path, "body_bytes": len(body)})
	})
	s := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("development origin listening on %s", *addr)
	log.Fatal(s.ListenAndServe())
}
