package app

import (
	"encoding/json"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/email"
)

// buildEmailTransport constructs an email.Transport from the gateway
// configuration and reports whether it delivers. The chosen transport is:
//
//  1. If cfg.SMTPProviders is non-empty, parse it as JSON
//     ([]email.SMTPConfig) and chain the valid providers in order.
//  2. Else if cfg.SMTPHost is set, a chain of that single SMTP provider.
//  3. Else if either is set but names no valid provider, an empty chain,
//     whose every Send fails, logged at ERROR.
//  4. Otherwise a LogOnly transport, with a warning that email is
//     effectively disabled.
//
// The transport is never nil. A chain holds only real providers, so its
// Send fails unless a provider accepted the message; delivers is true for
// every chain, and false only for the LogOnly fallback, whose nil from Send
// means nothing was sent. Configuration errors (bad JSON, bad SMTP fields)
// are logged and the failing provider is skipped; this avoids hard-failing
// the whole binary because of a misconfigured secondary provider.
func buildEmailTransport(cfg *config.Config, logger *zap.Logger) (transport email.Transport, delivers bool) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// (1) JSON multi-provider config.
	if cfg.SMTPProviders != "" {
		var providers []email.SMTPConfig
		if err := json.Unmarshal([]byte(cfg.SMTPProviders), &providers); err != nil {
			logger.Error(
				"smtp_providers_parse_failed",
				zap.Error(err),
				zap.String("hint", "GATEWAY_SMTP_PROVIDERS must be a JSON array of email.SMTPConfig"),
			)
		} else {
			transports := make([]email.Transport, 0, len(providers))
			for i, p := range providers {
				t, err := email.NewSMTP(p)
				if err != nil {
					logger.Warn(
						"smtp_provider_invalid",
						zap.Int("idx", i), zap.String("host", p.Host), zap.Error(err),
					)
					continue
				}
				transports = append(transports, t)
			}
			if len(transports) > 0 {
				logger.Info(
					"email_transport_chain_configured",
					zap.Int("provider_count", len(transports)),
				)
				return email.NewChain(logger, transports...), true
			}
			logger.Error(
				"smtp_providers_empty_after_validation",
				zap.String("note", "no usable SMTP providers parsed"),
			)
		}
	}

	// (2) Single-provider env vars.
	if cfg.SMTPHost != "" {
		smtpCfg := email.SMTPConfig{
			Host:     cfg.SMTPHost,
			Port:     cfg.SMTPPort,
			User:     cfg.SMTPUser,
			Pass:     cfg.SMTPPass,
			From:     cfg.SMTPFrom,
			StartTLS: cfg.SMTPTLS && cfg.SMTPPort != 465,
			TLS:      cfg.SMTPTLS && cfg.SMTPPort == 465,
		}
		t, err := email.NewSMTP(smtpCfg)
		if err != nil {
			logger.Error("smtp_single_provider_invalid", zap.Error(err))
		} else {
			logger.Info(
				"email_smtp_configured",
				zap.String("host", smtpCfg.Host),
				zap.Int("port", smtpCfg.Port),
				zap.Bool("tls", smtpCfg.TLS),
				zap.Bool("starttls", smtpCfg.StartTLS),
			)
			return email.NewChain(logger, t), true
		}
	}

	// (3) Configured, but no valid provider.
	if cfg.SMTPProviders != "" || cfg.SMTPHost != "" {
		logger.Error(
			"email_smtp_no_valid_provider",
			zap.String("hint",
				"every email send fails until GATEWAY_SMTP_HOST or GATEWAY_SMTP_PROVIDERS names a valid provider"),
		)
		return email.NewChain(logger), true
	}

	// (4) Nothing configured — log-only.
	logger.Warn(
		"email_disabled_no_transport_configured",
		zap.String("hint",
			"set GATEWAY_SMTP_HOST/PORT/USER/PASS/FROM or GATEWAY_SMTP_PROVIDERS to enable email delivery"),
	)
	return email.NewLogOnly(logger), false
}
