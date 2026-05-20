// Command embedded shows how a host program mounts identity into its own
// Go server instead of running the dedicated container. It builds one
// identityserver.Server and exposes it on both surfaces:
//
//   - a native *grpc.Server, alongside the host's own gRPC services, and
//   - an http.ServeMux, alongside the host's own HTTP routes.
//
// Run it with:
//
//	go run ./examples/embedded
//
// It uses the in-memory repository so it boots with no external
// dependencies. A real deployment sets GATEWAY_REPO_DRIVER=entdb (and the
// rest of the GATEWAY_* config) and uses identityserver.OptionsFromEnv.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"

	"github.com/elloloop/identity/identityserver"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return err
	}
	defer func() { _ = logger.Sync() }()

	ctx := context.Background()

	// Programmatic Options. A host that is already env-driven can call
	// identityserver.OptionsFromEnv() instead and tweak individual fields.
	opts := identityserver.Options{
		Logger: logger,
		Config: identityserver.Config{ // #nosec G101 -- passkey relying-party settings are public WebAuthn metadata.
			RepoDriver:                    "memory",
			IdentityMode:                  "single",
			DefaultTenantID:               "demo",
			AuthAllowLocal:                true,
			PasswordSignupEnabled:         true,
			AllowedOrigins:                "http://localhost:8080",
			JWTExpirySeconds:              900,
			RefreshExpirySeconds:          604800,
			LoginMaxFailedAttempts:        5,
			LoginLockoutSeconds:           900,
			LoginChallengeExpirySeconds:   300,
			PasskeyRPID:                   "localhost",
			PasskeyRPName:                 "Embedded Demo",
			PasskeyOrigin:                 "http://localhost:8080",
			PasskeyChallengeExpirySeconds: 300,
			QRLoginBaseURL:                "http://localhost:8080",
			QRLoginExpirySeconds:          300,
			TOTPIssuer:                    "Embedded Demo",
			PasswordResetExpirySeconds:    3600,
			// The sweeper and audit flusher start in srv.Start below.
			SweeperIntervalSeconds: 0,
		},
	}

	srv, err := identityserver.New(ctx, opts)
	if err != nil {
		return fmt.Errorf("identityserver.New: %w", err)
	}
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("identityserver.Start: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("identity_shutdown_error", zap.Error(err))
		}
	}()

	// ── Surface 1: native gRPC, on the host's own *grpc.Server ──────────
	grpcSrv := grpc.NewServer()
	srv.RegisterGRPC(grpcSrv)
	// The host registers its own services here too:
	//   myservicepb.RegisterMyServiceServer(grpcSrv, myImpl)

	grpcLis, err := net.Listen("tcp", "127.0.0.1:8090")
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	grpcErr := make(chan error, 1)
	go func() {
		logger.Info("grpc_listening", zap.String("addr", grpcLis.Addr().String()))
		grpcErr <- grpcSrv.Serve(grpcLis)
	}()

	// ── Surface 2: HTTP (Connect / gRPC-Web / gRPC), on the host's mux ──
	mux := http.NewServeMux()
	mux.Handle("/", srv.Handler())
	// The host adds its own routes alongside identity's:
	//   mux.HandleFunc("/healthz", myHealth)

	// h2c lets the demo serve gRPC over plaintext HTTP/2; a production host
	// terminates TLS (or sits behind a proxy that does) and can drop h2c.
	httpSrv := &http.Server{
		Addr:              "127.0.0.1:8080",
		Handler:           h2c.NewHandler(mux, &http2.Server{}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	httpErr := make(chan error, 1)
	go func() {
		logger.Info("http_listening", zap.String("addr", httpSrv.Addr))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
		}
	}()

	// ── Graceful shutdown ───────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logger.Info("shutting_down", zap.String("signal", sig.String()))
	case err := <-grpcErr:
		return fmt.Errorf("grpc serve: %w", err)
	case err := <-httpErr:
		return fmt.Errorf("http serve: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	grpcSrv.GracefulStop()
	return httpSrv.Shutdown(shutdownCtx)
}
