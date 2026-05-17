// Command identity is the identity service entry point.
//
// The identity service hosts authentication and user management RPCs:
// OAuth, password login, passkeys, TOTP, QR cross-device login, sessions,
// admin user management, groups, audit logging, and admin help requests.
//
// All persistent state lives in EntDB (tenant-sharded graph database).
// See docs/design/identity/ for high-level design and ADRs.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/observability"
	"github.com/elloloop/identity/internal/repo"
	entdbrepo "github.com/elloloop/identity/internal/repo/entdb"
	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
	"github.com/elloloop/identity/internal/service"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
	jwtfile "github.com/elloloop/identity/pkg/jwt/file"
	jwtkmsaws "github.com/elloloop/identity/pkg/jwt/kmsaws"
	"github.com/elloloop/identity/pkg/passkeys"
	"github.com/elloloop/identity/pkg/totp"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer syncLogger(logger)

	cfg := config.Load()

	logger.Info(
		"identity_service_starting",
		zap.Int("connect_port", cfg.ConnectPort),
		zap.Int("metrics_port", cfg.MetricsPort),
		zap.String("entdb_address", cfg.EntDBAddress),
		zap.String("tenant", cfg.DefaultTenantID),
	)

	// ── OpenTelemetry traces (off by default) ────────────────────────
	otelShutdown, err := observability.Setup(context.Background(), observability.FromAppConfig(cfg))
	if err != nil {
		logger.Fatal("otel_setup_failed", zap.Error(err))
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := otelShutdown(shutdownCtx); err != nil {
			logger.Error("otel_shutdown_failed", zap.Error(err))
		}
	}()
	if cfg.OTelEnabled {
		logger.Info(
			"otel_enabled",
			zap.String("endpoint", cfg.OTelExporterEndpoint),
			zap.String("protocol", cfg.OTelExporterProtocol),
			zap.Float64("sample_ratio", cfg.OTelSampleRatio),
			zap.String("deployment_env", cfg.OTelDeploymentEnv),
		)
	}

	// ── EntDB client ─────────────────────────────────────────────────
	db, err := entdb.NewClient(cfg.EntDBAddress)
	if err != nil {
		logger.Fatal("entdb_client_create_failed", zap.Error(err))
	}
	if err := db.Connect(context.Background()); err != nil {
		logger.Fatal("entdb_connect_failed", zap.Error(err))
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("entdb_close_failed", zap.Error(err))
		}
	}()

	// ── JWT signer ───────────────────────────────────────────────────
	// GATEWAY_JWT_SIGNER selects the backend; file is the default.
	signer, stopSigner, err := buildSigner(context.Background(), cfg, logger)
	if err != nil {
		logger.Fatal("jwt_signer_init_failed", zap.Error(err))
	}
	defer stopSigner()

	// Startup assertion: the JWKS document the verifier publishes
	// MUST include every active kid the signer reports. Drift means
	// downstream services cached a JWKS that cannot validate the next
	// token we mint — that's a panic-at-startup condition, not a
	// runtime warning.
	if err := jwtpkg.AssertJWKSIncludesActiveKIDs(signer, time.Now().UTC()); err != nil {
		logger.Fatal("jwks_active_kid_drift", zap.Error(err))
	}

	// ── WebAuthn / Passkeys ──────────────────────────────────────────
	webauthnSvc, err := passkeys.NewWebAuthnService(passkeys.Config{
		RPID:   cfg.PasskeyRPID,
		RPName: cfg.PasskeyRPName,
		Origin: cfg.PasskeyOrigin,
	})
	if err != nil {
		logger.Fatal("webauthn_init_failed", zap.Error(err))
	}

	// ── TOTP encryption key ──────────────────────────────────────────
	var totpKey []byte
	if cfg.TOTPEncryptionKey != "" {
		totpKey, err = base64.StdEncoding.DecodeString(cfg.TOTPEncryptionKey)
		if err != nil {
			logger.Fatal("totp_key_decode_failed", zap.Error(err))
		}
		if len(totpKey) != 32 {
			logger.Fatal("totp_key_wrong_size", zap.Int("got", len(totpKey)), zap.Int("want", 32))
		}
	} else {
		// Dev fallback: deterministic throwaway key (exactly 32 bytes).
		totpKey = []byte("glassa-dev-totp-encryption-key!!")
		logger.Warn("using_dev_totp_encryption_key")
	}

	// ── TOTP recovery-code pepper ────────────────────────────────────
	// The pepper is the HMAC-SHA-256 key under which every recovery
	// code hash is stored. It gates offline brute force of a stolen
	// recovery-code table. Required whenever TOTPEncryptionKey is
	// configured (i.e. any non-dev deployment); a deterministic dev
	// fallback is only allowed when the encryption key is also dev.
	var totpRecoveryPepper []byte
	switch {
	case cfg.TOTPRecoveryPepper != "":
		totpRecoveryPepper, err = base64.StdEncoding.DecodeString(cfg.TOTPRecoveryPepper)
		if err != nil {
			logger.Fatal("totp_recovery_pepper_decode_failed", zap.Error(err))
		}
		if len(totpRecoveryPepper) < totp.MinRecoveryPepperBytes {
			logger.Fatal(
				"totp_recovery_pepper_too_short",
				zap.Int("got", len(totpRecoveryPepper)),
				zap.Int("min", totp.MinRecoveryPepperBytes),
			)
		}
	case cfg.TOTPEncryptionKey != "":
		logger.Fatal(
			"totp_recovery_pepper_required",
			zap.String("env", "GATEWAY_TOTP_RECOVERY_PEPPER"),
		)
	default:
		totpRecoveryPepper = []byte("glassa-dev-totp-recovery-pepper-do-not-use-in-prod")
		logger.Warn("using_dev_totp_recovery_pepper")
	}

	// ── Repository / DB adapters ─────────────────────────────────────
	// repo.Build dispatches on cfg.RepoDriver and returns matching
	// service.Repository + service.DB implementations. Both share a
	// single *entdb.DbClient when the entdb driver is selected, so
	// writes and reads in one process see each other.
	built, err := repo.Build(context.Background(), repo.Config{
		Driver:      repo.Driver(cfg.RepoDriver),
		EntDBClient: db,
		TenantID:    cfg.DefaultTenantID,
		PostgresDSN: cfg.PostgresDSN,
	}, logger)
	if err != nil {
		logger.Fatal("repo_build_failed", zap.Error(err))
	}
	authRepo := built.Repository
	dbAdapter := built.DB

	// ── Identity-verification provider (optional) ────────────────────
	idvProvider, err := buildIDVProvider(cfg, logger)
	if err != nil {
		logger.Fatal("idv_provider_init_failed", zap.Error(err))
	}

	// ── Multi-mode tenant admin + per-tenant repo factory ────────────
	tenantAdmin, repoForTenant := buildMultiModeWiring(cfg, db, logger)

	// ── Build HTTP handler via shared wiring ─────────────────────────
	chain, stopApp, err := app.New(app.Deps{
		Config:              cfg,
		Logger:              logger,
		Signer:              signer,
		Repo:                authRepo,
		DB:                  dbAdapter,
		Passkeys:            webauthnSvc,
		TOTPKey:             totpKey,
		TOTPRecoveryPepper:  totpRecoveryPepper,
		IDVProvider:         idvProvider,
		MetricsRegistry:     prometheus.DefaultRegisterer,
		TenantAdmin:         tenantAdmin,
		RepositoryForTenant: repoForTenant,
	})
	if err != nil {
		logger.Fatal("app_init_failed", zap.Error(err))
	}
	defer stopApp()

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
		Handler:           http.MaxBytesHandler(chain, cfg.HTTPMaxBodyBytes),
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
	// Stop accepting first, drain in-flight, then close DB.
	if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
		logger.Error("server_shutdown_error", zap.Error(shutdownErr))
	}
	if shutdownErr := metricsServer.Shutdown(ctx); shutdownErr != nil {
		logger.Error("metrics_shutdown_error", zap.Error(shutdownErr))
	}
	logger.Info("shutdown_complete")
}

// buildSigner constructs the configured jwt.Signer and returns a stop
// func that detaches signal handlers etc. on shutdown.
func buildSigner(ctx context.Context, cfg *config.Config, logger *zap.Logger) (jwtpkg.Signer, func(), error) {
	switch cfg.JWTSigner {
	case "", "file":
		return buildFileSigner(cfg, logger)
	case "kms_aws":
		return buildKMSAWSSigner(ctx, cfg, logger)
	default:
		return nil, func() {}, fmt.Errorf("unknown GATEWAY_JWT_SIGNER %q (want file or kms_aws)", cfg.JWTSigner)
	}
}

func buildFileSigner(cfg *config.Config, logger *zap.Logger) (jwtpkg.Signer, func(), error) {
	logOpt := jwtfile.Options{
		Logf: func(format string, args ...any) {
			logger.Info(fmt.Sprintf(format, args...))
		},
	}

	path := cfg.JWTKeysFile
	if path == "" {
		// Dev fallback: generate a throwaway key in-memory so the
		// service still starts without external setup. The scratch
		// container image has no writable temp dir, so we deliberately
		// avoid touching the filesystem here. NEVER use this in
		// production — the warning log is loud on purpose.
		s, err := jwtfile.GenerateInMemory("dev", 365*24*time.Hour, logOpt)
		if err != nil {
			return nil, func() {}, fmt.Errorf("generating dev signing key: %w", err)
		}
		logger.Warn(
			"jwt_signer_dev_key_generated",
			zap.String("kid", s.ActiveKID()),
			zap.String("hint", "set GATEWAY_JWT_KEYS_FILE for any non-dev deployment"),
		)
		return s, func() {}, nil
	}

	s, err := jwtfile.New(path, logOpt)
	if err != nil {
		return nil, func() {}, err
	}
	logger.Info("jwt_signer_file", zap.String("path", path), zap.String("active_kid", s.ActiveKID()))

	stopWatch := jwtfile.WatchSIGHUP(s, func(err error) {
		logger.Error("jwt_signer_reload_failed", zap.Error(err))
	})

	return s, stopWatch, nil
}

func buildKMSAWSSigner(ctx context.Context, cfg *config.Config, logger *zap.Logger) (jwtpkg.Signer, func(), error) {
	if cfg.JWTKMSKeys == "" {
		return nil, func() {}, errors.New("GATEWAY_JWT_KMS_KEYS is required when GATEWAY_JWT_SIGNER=kms_aws")
	}
	refs, err := jwtkmsaws.ARNFromConfig(cfg.JWTKMSKeys)
	if err != nil {
		return nil, func() {}, fmt.Errorf("parsing GATEWAY_JWT_KMS_KEYS: %w", err)
	}

	var opts []func(*awsconfig.LoadOptions) error
	if cfg.JWTKMSAWSRegion != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.JWTKMSAWSRegion))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, func() {}, fmt.Errorf("loading AWS config: %w", err)
	}
	client := awskms.NewFromConfig(awsCfg)

	s, err := jwtkmsaws.New(ctx, jwtkmsaws.Config{
		API:  client,
		Keys: refs,
	})
	if err != nil {
		return nil, func() {}, err
	}
	kids := make([]string, 0, len(refs))
	for _, r := range refs {
		kids = append(kids, r.KID)
	}
	logger.Info("jwt_signer_kms_aws", zap.Strings("kids", kids), zap.String("active_kid", s.ActiveKID()))
	return s, func() {}, nil
}

// buildMultiModeWiring returns the TenantAdmin + per-tenant repo
// factory for OrganizationSignup. Returns (nil, nil) in single mode.
//
// In multi mode it dispatches on the persistence driver:
//   - entdb: full TenantAdmin against tenant-shard-db's Admin handle.
//   - postgres: degenerate PostgresTenantAdmin (slug uniqueness is
//     enforced via the per-tenant Repository's CreateOrganization
//     unique index — postgres has no cross-tenant registry concept).
//   - memory: not supported; the bootstrap function fatals.
//
// app.New rejects mode=multi at boot if both returned values are nil.
func buildMultiModeWiring(cfg *config.Config, db *entdb.DbClient, logger *zap.Logger) (service.TenantAdmin, service.RepositoryForTenant) {
	if !cfg.IsMultiMode() {
		return nil, nil
	}
	switch repo.Driver(cfg.RepoDriver) {
	case repo.DriverEntDB:
		return repo.NewTenantAdmin(db), func(tenantID string) service.Repository {
			return entdbrepo.NewRepository(db, tenantID)
		}
	case repo.DriverPostgres:
		return repo.NewPostgresTenantAdmin(), func(tenantID string) service.Repository {
			pg, pgErr := pgrepo.New(context.Background(), pgrepo.Config{
				DSN:         cfg.PostgresDSN,
				MaxConns:    int32(cfg.PostgresMaxConns), // #nosec G115 -- config-bounded.
				AutoMigrate: false,
				TenantID:    tenantID,
			})
			if pgErr != nil {
				logger.Error("postgres_per_tenant_repo_failed",
					zap.String("tenant_id", tenantID), zap.Error(pgErr))
				return nil
			}
			return pg
		}
	default:
		logger.Fatal("identity_mode_multi_unsupported_driver",
			zap.String("driver", cfg.RepoDriver))
		return nil, nil
	}
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
