package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/MonthyG/WAF/waf-node/internal/agent"
	"github.com/MonthyG/WAF/waf-node/internal/telemetry"
	"github.com/nats-io/nats.go"
)

func main() {
	if err := run(); err != nil {
		slog.Error("waf-agent stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	id := flag.String("node-id", "", "registered node UUID")
	server := flag.String("nats", "nats://127.0.0.1:14222", "NATS URL")
	credentials := flag.String("credentials", "", "NATS user credentials file")
	listen := flag.String("listen", "127.0.0.1:8080", "traffic address")
	management := flag.String("management", "127.0.0.1:9090", "loopback management address")
	tlsListen := flag.String("tls-listen", "", "HTTPS address (requires node-key)")
	nodeKey := flag.String("node-key", "", "RSA private key file for certificate delivery")
	stateDir := flag.String("state-dir", "", "enable telemetry with a private durable spool directory")
	flag.Parse()
	if len(*id) != 36 || strings.ContainsAny(*id, " .>*\r\n") {
		return fmt.Errorf("node-id must be a UUID")
	}
	host, _, err := net.SplitHostPort(*management)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("management must bind loopback")
	}
	u, err := url.Parse(*server)
	if err != nil {
		return err
	}
	if *credentials == "" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("non-loopback NATS requires a credentials file")
		}
	}
	opts := []nats.Option{nats.Name("waf-agent-" + *id), nats.MaxReconnects(-1), nats.ReconnectWait(time.Second), nats.Timeout(5 * time.Second)}
	if *credentials != "" {
		opts = append(opts, nats.UserCredentials(*credentials))
	}
	nc, err := nats.Connect(*server, opts...)
	if err != nil {
		return fmt.Errorf("NATS connection failed")
	}
	defer nc.Close()
	a := agent.New(*id, slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	defer a.Close()
	var reporter *telemetry.Reporter
	if *stateDir != "" {
		reporter, err = telemetry.New(*id, filepath.Join(*stateDir, "telemetry"), nc)
		if err != nil {
			return err
		}
		defer reporter.Close()
		a.Observer = reporter.Observe
	}
	if *nodeKey != "" {
		data, err := os.ReadFile(*nodeKey)
		if err != nil {
			return err
		}
		a.PrivateKey, err = agent.ParseNodeKey(data)
		clear(data)
		if err != nil {
			return err
		}
	}
	if *tlsListen != "" && a.PrivateKey == nil {
		return fmt.Errorf("tls-listen requires node-key")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errs := make(chan error, 4)
	traffic, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer traffic.Close()
	admin, err := net.Listen("tcp", *management)
	if err != nil {
		return err
	}
	defer admin.Close()
	s := &http.Server{Handler: a, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	managementHandler := a.ManagementHandler()
	if reporter != nil {
		original := managementHandler
		managementHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			original.ServeHTTP(w, r)
			if r.URL.Path == "/metrics" {
				fmt.Fprint(w, reporter.Metrics())
			}
		})
	}
	m := &http.Server{Handler: managementHandler, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	var https *http.Server
	if *tlsListen != "" {
		listener, e := net.Listen("tcp", *tlsListen)
		if e != nil {
			return e
		}
		defer listener.Close()
		https = &http.Server{Handler: a, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: a.GetCertificate}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
		go func() { errs <- https.ServeTLS(listener, "", "") }()
	}
	go func() { errs <- a.Run(ctx, nc) }()
	go func() { errs <- s.Serve(traffic) }()
	go func() { errs <- m.Serve(admin) }()
	slog.Info("waf-agent started", "node_id", *id, "listen", *listen)
	select {
	case <-ctx.Done():
	case err = <-errs:
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e := s.Shutdown(shutdown); e != nil {
		s.Close()
	}
	if https != nil {
		if e := https.Shutdown(shutdown); e != nil {
			https.Close()
		}
	}
	if e := m.Shutdown(shutdown); e != nil {
		m.Close()
	}
	return err
}
