package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MonthyG/WAF/waf-node/internal/engine"
	"github.com/MonthyG/WAF/waf-node/internal/proxy"
)

func main() {
	path := flag.String("config", "configs/local.json", "single-site JSON configuration")
	check := flag.Bool("check", false, "validate config and compile CRS, then exit")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(*path, *check, log); err != nil {
		log.Error("waf-proxy stopped", "error", err)
		os.Exit(1)
	}
}

func run(path string, check bool, log *slog.Logger) error {
	cfg, err := proxy.LoadConfig(path)
	if err != nil {
		return err
	}
	p, err := proxy.New(cfg, log)
	if err != nil {
		return err
	}
	defer p.Close()
	if check {
		log.Info("configuration valid", "crs", engine.CRSVersion, "mode", cfg.Mode)
		return nil
	}
	traffic, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer traffic.Close()
	management, err := net.Listen("tcp", cfg.ManagementListen)
	if err != nil {
		return err
	}
	defer management.Close()
	server := &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	admin := &http.Server{Handler: p.ManagementHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	errCh := make(chan error, 2)
	go func() { errCh <- server.Serve(traffic) }()
	go func() { errCh <- admin.Serve(management) }()
	log.Info("waf-proxy started", "listen", cfg.Listen, "management", cfg.ManagementListen, "site", cfg.Hostname, "mode", cfg.Mode, "crs", engine.CRSVersion)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errCh:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Drain traffic before releasing the Coraza instance.
	if err := server.Shutdown(shutdown); err != nil {
		server.Close()
		return fmt.Errorf("traffic shutdown: %w", err)
	}
	if err := admin.Shutdown(shutdown); err != nil {
		admin.Close()
		return fmt.Errorf("management shutdown: %w", err)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	log.Info("waf-proxy stopped cleanly")
	return nil
}
