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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb"

	"github.com/elloloop/identity/internal/app"
	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo"
	"github.com/elloloop/identity/pkg/jwt"
	"github.com/elloloop/identity/pkg/passkeys"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer syncLogger(logger)

	cfg := config.Load()

	logger.Info("identity_service_starting",
		zap.Int("connect_port", cfg.ConnectPort),
		zap.Int("metrics_port", cfg.MetricsPort),
		zap.String("entdb_address", cfg.EntDBAddress),
		zap.String("tenant", cfg.DefaultTenantID),
	)

	// ── EntDB client ─────────────────────────────────────────────────
	db, err := entdb.NewClient(cfg.EntDBAddress)
	if err != nil {
		logger.Fatal("entdb_client_create_failed", zap.Error(err))
	}
	if err := db.Connect(context.Background()); err != nil {
		logger.Fatal("entdb_connect_failed", zap.Error(err))
	}
	defer db.Close()

	// ── JWT Key Ring ─────────────────────────────────────────────────
	var keyRing *jwt.KeyRing
	if cfg.JWTKeys != "" {
		keyRing, err = parseKeyRingFromEnv(cfg.JWTKeys)
		if err != nil {
			logger.Fatal("jwt_key_ring_parse_failed", zap.Error(err))
		}
		logger.Info("jwt_key_ring_loaded",
			zap.Int("key_count", len(keyRing.AllKIDs())),
			zap.String("active_kid", keyRing.Active().KID),
		)
	} else {
		key, genErr := jwt.GenerateKey("dev")
		if genErr != nil {
			logger.Fatal("jwt_key_generate_failed", zap.Error(genErr))
		}
		keyRing, err = jwt.NewKeyRing([]jwt.SigningKey{key})
		if err != nil {
			logger.Fatal("jwt_key_ring_create_failed", zap.Error(err))
		}
		logger.Warn("auto_generating_dev_rsa_key",
			zap.String("kid", key.KID),
		)
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

	// ── Repository / DB adapters ─────────────────────────────────────
	// Both wrap the same *entdb.DbClient: NewEntDBRepository provides
	// the typed CRUD surface used by AuthService, NewDBAdapter provides
	// the raw-node surface used by admin/groups/help/profile services
	// and by the audit logger.
	authRepo := repo.NewEntDBRepository(db, cfg.DefaultTenantID)
	dbAdapter := repo.NewDBAdapter(db)

	// ── Build HTTP handler via shared wiring ─────────────────────────
	chain := app.New(app.Deps{
		Config:   cfg,
		Logger:   logger,
		KeyRing:  keyRing,
		Repo:     authRepo,
		DB:       dbAdapter,
		Passkeys: webauthnSvc,
		TOTPKey:  totpKey,
	})

	// ── Prometheus metrics server ────────────────────────────────────
	go func() {
		metricsAddr := fmt.Sprintf(":%d", cfg.MetricsPort)
		logger.Info("metrics_server_starting", zap.String("addr", metricsAddr))
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		if listenErr := http.ListenAndServe(metricsAddr, metricsMux); listenErr != nil {
			logger.Error("metrics_server_failed", zap.Error(listenErr))
		}
	}()

	// ── Start Connect server ─────────────────────────────────────────
	addr := fmt.Sprintf(":%d", cfg.ConnectPort)
	server := &http.Server{
		Addr:              addr,
		Handler:           chain,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("identity_service_started", zap.String("addr", addr))
		if listenErr := server.ListenAndServe(); listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			logger.Fatal("server_failed", zap.Error(listenErr))
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh

	logger.Info("identity_service_shutting_down", zap.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if shutdownErr := server.Shutdown(ctx); shutdownErr != nil {
		logger.Error("server_shutdown_error", zap.Error(shutdownErr))
	}

	// db.Close() is handled by defer above — no duplicate call needed.
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

// jwtKeyJSON is the JSON schema for a single key in the GATEWAY_JWT_KEYS
// environment variable.
type jwtKeyJSON struct {
	KID           string `json:"kid"`
	PrivateKeyPEM string `json:"private_key_pem"`
	PublicKeyPEM  string `json:"public_key_pem"`
	Active        bool   `json:"active"`
}

// parseKeyRingFromEnv parses the GATEWAY_JWT_KEYS JSON array into a KeyRing.
//
// Expected format:
//
//	[{"kid":"k1","private_key_pem":"-----BEGIN RSA PRIVATE KEY-----\n...","active":true}]
func parseKeyRingFromEnv(jsonStr string) (*jwt.KeyRing, error) {
	var raw []jwtKeyJSON
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("parsing JWT keys JSON: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("JWT keys JSON is empty")
	}

	keys := make([]jwt.SigningKey, 0, len(raw))
	for _, k := range raw {
		if k.KID == "" {
			return nil, fmt.Errorf("JWT key missing kid")
		}

		// Parse private key PEM.
		privBlock, _ := pem.Decode([]byte(k.PrivateKeyPEM))
		if privBlock == nil {
			return nil, fmt.Errorf("kid=%s: invalid private key PEM", k.KID)
		}
		privKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			// Try PKCS8 as fallback.
			pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
			if pkcs8Err != nil {
				return nil, fmt.Errorf("kid=%s: parsing private key: %w", k.KID, err)
			}
			var ok bool
			privKey, ok = pkcs8Key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("kid=%s: private key is not RSA", k.KID)
			}
		}

		keys = append(keys, jwt.SigningKey{
			KID:        k.KID,
			PrivateKey: privKey,
			PublicKey:  &privKey.PublicKey,
			Active:     k.Active,
		})
	}

	return jwt.NewKeyRing(keys)
}
