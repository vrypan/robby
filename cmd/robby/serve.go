package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/vrypan/robby/internal/config"
	"github.com/vrypan/robby/internal/relay"
	"github.com/vrypan/robby/internal/store"
	"github.com/vrypan/robby/internal/xrpc"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the robby server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe()
		},
	}
}

func runServe() error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	st, err := store.Open(filepath.Join(cfg.DataDir, "accounts.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	xrpc.Version = Version()
	srv, err := xrpc.NewServer(cfg, st, log)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		// No WriteTimeout: firehose websockets and streamed proxy responses
		// are intentionally long-lived.
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "hostname", cfg.Hostname)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// Declare ourselves to the configured relays so they (re)subscribe to
	// our firehose and backfill repos. Per PLAN.md's watchdog note, this
	// runs on every startup. Best-effort: failures are logged, not fatal.
	if len(cfg.Relays) > 0 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			for _, r := range cfg.Relays {
				if err := relay.RequestCrawl(ctx, r, cfg.Hostname); err != nil {
					log.Warn("requestCrawl failed", "relay", r, "err", err)
				} else {
					log.Info("requestCrawl ok", "relay", r)
				}
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-sigCh:
		log.Info("shutting down")
		return httpSrv.Close()
	}
}
