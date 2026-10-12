package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MonthyG/WAF/waf-node/internal/agent"
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errs := make(chan error, 3)
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
	m := &http.Server{Handler: a.ManagementHandler(), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
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
	if e := m.Shutdown(shutdown); e != nil {
		m.Close()
	}
	return err
}
