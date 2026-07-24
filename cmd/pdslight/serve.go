package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/vrypan/pds-light/internal/config"
	"github.com/vrypan/pds-light/internal/store"
	"github.com/vrypan/pds-light/internal/xrpc"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the pds-light server",
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
	srv := xrpc.NewServer(cfg, st, log)

	httpSrv := &http.Server{
		Addr:    cfg.Listen,
		Handler: srv.Handler(),
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "hostname", cfg.Hostname)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

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
