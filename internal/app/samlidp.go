package app

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/samlidp"
)

// buildSAMLIssuer constructs the samlidp.Issuer selected by config. When the
// SAML IdP is disabled (the default) it returns the no-op issuer so the
// server always holds a non-nil Issuer; the HTTP surface mounts nothing
// while Issuer.Enabled() reports false. Config.Validate has already
// guaranteed the required fields are present when enabled, so the only error
// here is the signing material failing to parse or the cert/key not
// matching — a fail-closed boot error rather than minting unverifiable
// assertions later.
func buildSAMLIssuer(cfg *config.Config, logger *zap.Logger) (samlidp.Issuer, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	if !cfg.SAMLIDPEnabled {
		logger.Info("saml_idp_disabled")
		return samlidp.NewNoopIssuer(), nil
	}

	iss, err := samlidp.NewRSAIssuer(samlidp.Options{
		EntityID: cfg.SAMLEntityID,
		SSOURL:   cfg.SAMLSSOURL,
		SLOURL:   cfg.SAMLSLOURL,
		KeyPEM:   []byte(cfg.SAMLSigningKey),
		CertPEM:  []byte(cfg.SAMLSigningCert),
	})
	if err != nil {
		return nil, fmt.Errorf("saml idp: %w", err)
	}
	logger.Info("saml_idp_enabled", zap.String("entity_id", cfg.SAMLEntityID))
	return iss, nil
}
