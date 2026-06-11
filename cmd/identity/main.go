// Command identity is the identity service container entry point.
//
// It is a thin shim over the identityserver library: it loads Options
// from the environment, constructs the server, and serves its HTTP
// handler plus a Prometheus metrics listener. All wiring — config,
// persistence, JWT signer, OAuth, IDV, OpenTelemetry, background workers
// — lives in github.com/elloloop/identity/identityserver so a deployer
// who embeds identity into an existing Go server runs the exact same code
// path this binary does.
//
// The identity service hosts authentication and user management RPCs:
// OAuth, password login, passkeys, TOTP, QR cross-device login, sessions,
// admin user management, groups, audit logging, and admin help requests.
//
// See docs/embedding.md for the library API and docs/IDENTITY.md for the
// service charter and decision log.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/elloloop/identity/identityserver"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	opts := identityserver.OptionsFromEnv()
	opts.Logger = logger

	// `identity migrate` runs pending Postgres migrations and exits,
	// without starting the server (the deploy-step path). It flushes the
	// logger explicitly because os.Exit skips deferred calls.
	if migrateRequested(os.Args) {
		code := runMigrate(opts, logger)
		syncLogger(logger)
		os.Exit(code)
	}

	defer syncLogger(logger)

	cfg := opts.Config

	logger.Info(
		"identity_service_starting",
		zap.Int("connect_port", cfg.ConnectPort),
		zap.Int("metrics_port", cfg.MetricsPort),
		zap.String("entdb_address", cfg.EntDBAddress),
		zap.String("tenant", cfg.DefaultTenantID),
	)

	srv, err := identityserver.New(context.Background(), opts)
	if err != nil {
		logger.Fatal("identity_server_init_failed", zap.Error(err))
	}
	if err := srv.Start(context.Background()); err != nil {
		logger.Fatal("identity_server_start_failed", zap.Error(err))
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("identity_server_shutdown_error", zap.Error(err))
		}
	}()

	// ── Prometheus metrics server ────────────────────────────────────
	metricsAddr := fmt.Sprintf(":%d", cfg.MetricsPort)
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsServer := &http.Server{
		Addr:              metricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KiB
	}

	// ── Connect server ───────────────────────────────────────────────
	addr := fmt.Sprintf(":%d", cfg.ConnectPort)
	server := &http.Server{
		Addr:              addr,
		Handler:           http.MaxBytesHandler(srv.Handler(), cfg.HTTPMaxBodyBytes),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KiB
	}

	serverErr := make(chan error, 2)
	go func() {
		logger.Info("metrics_server_starting", zap.String("addr", metricsAddr))
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("metrics: %w", err)
		}
	}()
	go func() {
		logger.Info("identity_service_started", zap.String("addr", addr))
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("connect: %w", err)
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	select {
	case sig := <-sigCh:
		logger.Info("identity_service_shutting_down", zap.String("signal", sig.String()))
	case err := <-serverErr:
		logger.Error("server_failed_early", zap.Error(err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Stop accepting first, drain in-flight; the deferred srv.Shutdown
	// then drains background workers and releases the EntDB client,
	// signer watcher, and OTel exporter.
	if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
		logger.Error("server_shutdown_error", zap.Error(shutdownErr))
	}
	if shutdownErr := metricsServer.Shutdown(ctx); shutdownErr != nil {
		logger.Error("metrics_shutdown_error", zap.Error(shutdownErr))
	}
	logger.Info("shutdown_complete")
}

// syncLogger flushes the zap logger and intentionally swallows the sync error,
// since stdout sync on some platforms returns ENOTTY and the process is about
// to exit anyway.
func syncLogger(logger *zap.Logger) {
	if err := logger.Sync(); err != nil {
		// best-effort -- stderr may not be syncable (e.g. terminal)
		_ = err
	}
}
