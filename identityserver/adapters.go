package identityserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"go.uber.org/zap"

	"github.com/elloloop/tenant-shard-db/sdk/go/entdb/v2"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/internal/repo"
	entdbrepo "github.com/elloloop/identity/internal/repo/entdb"
	pgrepo "github.com/elloloop/identity/internal/repo/postgres"
	"github.com/elloloop/identity/internal/service"
	"github.com/elloloop/identity/pkg/idv"
	jwtpkg "github.com/elloloop/identity/pkg/jwt"
	jwtfile "github.com/elloloop/identity/pkg/jwt/file"
	jwtkmsaws "github.com/elloloop/identity/pkg/jwt/kmsaws"
	"github.com/elloloop/identity/pkg/totp"
)

// buildSigner constructs the configured jwt.Signer and returns a stop
// func that detaches the file watcher (file backend) on shutdown.
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

// decodeTOTPKey returns the 32-byte TOTP encryption key from config,
// falling back to a deterministic dev key (loud warning) when unset.
func decodeTOTPKey(cfg *config.Config, logger *zap.Logger) ([]byte, error) {
	if cfg.TOTPEncryptionKey == "" {
		logger.Warn("using_dev_totp_encryption_key")
		return []byte("glassa-dev-totp-encryption-key!!"), nil
	}
	key, err := base64.StdEncoding.DecodeString(cfg.TOTPEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("totp key decode: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("totp key wrong size: got %d, want 32", len(key))
	}
	return key, nil
}

// decodeTOTPRecoveryPepper returns the HMAC pepper for recovery-code
// hashing. It is required whenever a real TOTP encryption key is set;
// the dev fallback is only allowed when the encryption key is also dev.
func decodeTOTPRecoveryPepper(cfg *config.Config, logger *zap.Logger) ([]byte, error) {
	switch {
	case cfg.TOTPRecoveryPepper != "":
		pepper, err := base64.StdEncoding.DecodeString(cfg.TOTPRecoveryPepper)
		if err != nil {
			return nil, fmt.Errorf("totp recovery pepper decode: %w", err)
		}
		if len(pepper) < totp.MinRecoveryPepperBytes {
			return nil, fmt.Errorf("totp recovery pepper too short: got %d, min %d",
				len(pepper), totp.MinRecoveryPepperBytes)
		}
		return pepper, nil
	case cfg.TOTPEncryptionKey != "":
		return nil, errors.New("GATEWAY_TOTP_RECOVERY_PEPPER is required when GATEWAY_TOTP_ENCRYPTION_KEY is set")
	default:
		logger.Warn("using_dev_totp_recovery_pepper")
		return []byte("glassa-dev-totp-recovery-pepper-do-not-use-in-prod"), nil
	}
}

// buildIDVProvider returns the configured identity-verification provider.
// Returns nil with no error when IDVProvider is unset, in which case the
// IDV RPCs respond with CodeUnimplemented.
func buildIDVProvider(cfg *config.Config, logger *zap.Logger) (idv.Provider, error) {
	switch cfg.IDVProvider {
	case "":
		logger.Info("idv_provider_disabled")
		return nil, nil
	case "stub":
		logger.Warn(
			"idv_provider_stub_in_use",
			zap.String("note", "stub auto-approves every session — never use in production"),
		)
		return idv.NewStubProvider(), nil
	case "azure":
		ttl := time.Duration(cfg.IDVAzureSessionTTLSec) * time.Second
		p, err := idv.NewAzureProvider(idv.AzureConfig{
			Endpoint:   cfg.IDVAzureEndpoint,
			Key:        cfg.IDVAzureKey,
			SessionTTL: ttl,
		})
		if err != nil {
			return nil, fmt.Errorf("azure: %w", err)
		}
		logger.Info(
			"idv_provider_loaded",
			zap.String("provider", "azure"),
			zap.String("endpoint", cfg.IDVAzureEndpoint),
		)
		return p, nil
	default:
		return nil, fmt.Errorf("unknown idv provider %q", cfg.IDVProvider)
	}
}

// buildMultiModeWiring returns the TenantAdmin + per-tenant repo factory
// for OrganizationSignup. It dispatches on the persistence driver:
//
//   - entdb: full TenantAdmin against tenant-shard-db's Admin handle.
//   - postgres: degenerate PostgresTenantAdmin (slug uniqueness is
//     enforced via the per-tenant Repository's CreateOrganization unique
//     index — postgres has no cross-tenant registry concept).
//   - memory: not supported.
func buildMultiModeWiring(ctx context.Context, cfg *config.Config, db *entdb.DbClient, logger *zap.Logger) (service.TenantAdmin, service.RepositoryForTenant, error) {
	switch repo.Driver(cfg.RepoDriver) {
	case repo.DriverEntDB:
		admin, err := repo.NewTenantAdmin(db)
		if err != nil {
			return nil, nil, fmt.Errorf("tenant admin: %w", err)
		}
		return admin, func(tenantID string) service.Repository {
			return entdbrepo.NewRepository(db, tenantID)
		}, nil
	case repo.DriverPostgres:
		if cfg.PostgresMaxConns > math.MaxInt32 {
			return nil, nil, fmt.Errorf("postgres max conns exceeds int32: %d", cfg.PostgresMaxConns)
		}
		maxConns := int32(cfg.PostgresMaxConns) // #nosec G115 -- bounds checked above.
		dsn := cfg.PostgresDSN
		return repo.NewPostgresTenantAdmin(), func(tenantID string) service.Repository {
			pg, pgErr := pgrepo.New(ctx, pgrepo.Config{
				DSN:         dsn,
				MaxConns:    maxConns,
				AutoMigrate: false,
				TenantID:    tenantID,
			})
			if pgErr != nil {
				logger.Error("postgres_per_tenant_repo_failed",
					zap.String("tenant_id", tenantID), zap.Error(pgErr))
				return nil
			}
			return pg
		}, nil
	default:
		return nil, nil, fmt.Errorf("identity mode=multi unsupported driver %q", cfg.RepoDriver)
	}
}
