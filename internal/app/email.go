package app

import (
	"encoding/json"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/email"
)

// buildEmailTransport constructs an email.Transport from the gateway
// configuration. The chosen transport order is:
//
//  1. If cfg.SMTPProviders is non-empty, parse it as JSON
//     ([]email.SMTPConfig) and chain those providers in order, with a
//     LogOnly tail so the chain is never empty.
//  2. Else if cfg.SMTPHost is set, use a single SMTP transport
//     followed by a LogOnly tail.
//  3. Otherwise return a LogOnly transport and warn that email is
//     effectively disabled.
//
// The function never returns nil — calls to Send always succeed
// (possibly only as a log line), so service code can rely on the
// transport always being usable. Configuration errors (bad JSON, bad
// SMTP fields) are logged and the failing provider is skipped; this
// avoids hard-failing the whole binary because of a misconfigured
// secondary provider.
func buildEmailTransport(cfg *config.Config, logger *zap.Logger) email.Transport {
	if logger == nil {
		logger = zap.NewNop()
	}
	tail := email.NewLogOnly(logger)

	// (1) JSON multi-provider config.
	if cfg.SMTPProviders != "" {
		var providers []email.SMTPConfig
		if err := json.Unmarshal([]byte(cfg.SMTPProviders), &providers); err != nil {
			logger.Warn("smtp_providers_parse_failed",
				zap.Error(err),
				zap.String("hint", "GATEWAY_SMTP_PROVIDERS must be a JSON array of email.SMTPConfig"),
			)
		} else {
			transports := make([]email.Transport, 0, len(providers)+1)
			for i, p := range providers {
				t, err := email.NewSMTP(p)
				if err != nil {
					logger.Warn("smtp_provider_invalid",
						zap.Int("idx", i), zap.String("host", p.Host), zap.Error(err),
					)
					continue
				}
				transports = append(transports, t)
			}
			if len(transports) > 0 {
				transports = append(transports, tail)
				logger.Info("email_transport_chain_configured",
					zap.Int("provider_count", len(transports)-1),
				)
				return email.NewChain(logger, transports...)
			}
			logger.Warn("smtp_providers_empty_after_validation",
				zap.String("note", "no usable SMTP providers parsed; falling back to log-only"),
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
			logger.Warn("smtp_single_provider_invalid", zap.Error(err))
		} else {
			logger.Info("email_smtp_configured",
				zap.String("host", smtpCfg.Host),
				zap.Int("port", smtpCfg.Port),
				zap.Bool("tls", smtpCfg.TLS),
				zap.Bool("starttls", smtpCfg.StartTLS),
			)
			return email.NewChain(logger, t, tail)
		}
	}

	// (3) Nothing configured — log-only.
	logger.Warn("email_disabled_no_transport_configured",
		zap.String("hint",
			"set GATEWAY_SMTP_HOST/PORT/USER/PASS/FROM or GATEWAY_SMTP_PROVIDERS to enable email delivery"),
	)
	return tail
}
