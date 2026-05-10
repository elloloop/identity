package main

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/idv"
)

// buildIDVProvider returns the configured identity-verification
// provider. Returns nil with no error when IDVProvider is unset, in
// which case the IDV RPCs respond with CodeUnimplemented.
func buildIDVProvider(cfg *config.Config, logger *zap.Logger) (idv.Provider, error) {
	switch cfg.IDVProvider {
	case "":
		logger.Info("idv_provider_disabled")
		return nil, nil
	case "stub":
		logger.Warn("idv_provider_stub_in_use",
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
		logger.Info("idv_provider_loaded",
			zap.String("provider", "azure"),
			zap.String("endpoint", cfg.IDVAzureEndpoint),
		)
		return p, nil
	default:
		return nil, fmt.Errorf("unknown idv provider %q", cfg.IDVProvider)
	}
}
