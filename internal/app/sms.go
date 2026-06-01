package app

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/sms"
)

// buildSMSSender constructs an sms.Sender from the gateway
// configuration. When GATEWAY_SMS_ENABLED is false it returns the
// log-only sender (so service code can always call Send without a nil
// check). When enabled, it builds the configured provider — Twilio, AWS
// SNS, or Azure Communication Services.
//
// Config.Validate has already enforced that an enabled deployment names
// a supported provider with its required credentials set, so a build
// error here is unexpected; it is still surfaced so a malformed
// credential (e.g. a non-base64 Azure key) fails the boot rather than
// silently degrading to log-only.
func buildSMSSender(cfg *config.Config, logger *zap.Logger) (sms.Sender, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if !cfg.SMSEnabled {
		logger.Warn(
			"sms_disabled_no_provider_configured",
			zap.String("hint",
				"set GATEWAY_SMS_ENABLED=true and GATEWAY_SMS_PROVIDER (twilio|sns|azure) plus its credentials to enable phone verification"),
		)
		return sms.NewLogOnly(logger), nil
	}

	switch cfg.SMSProvider {
	case config.SMSProviderTwilio:
		sender, err := sms.NewTwilio(sms.TwilioConfig{
			AccountSID: cfg.SMSTwilioAccountSID,
			AuthToken:  cfg.SMSTwilioAuthToken,
			From:       cfg.SMSTwilioFrom,
		})
		if err != nil {
			return nil, fmt.Errorf("twilio: %w", err)
		}
		logger.Info("sms_provider_configured", zap.String("provider", config.SMSProviderTwilio))
		return sender, nil

	case config.SMSProviderSNS:
		sender, err := sms.NewSNS(sms.SNSConfig{
			Region:          cfg.SMSAWSRegion,
			AccessKeyID:     cfg.SMSAWSAccessKeyID,
			SecretAccessKey: cfg.SMSAWSSecretAccessKey,
			SenderID:        cfg.SMSAWSSenderID,
		})
		if err != nil {
			return nil, fmt.Errorf("sns: %w", err)
		}
		logger.Info("sms_provider_configured", zap.String("provider", config.SMSProviderSNS))
		return sender, nil

	case config.SMSProviderAzure:
		endpoint, accessKey, err := sms.ParseAzureConnectionString(cfg.SMSAzureConnectionString)
		if err != nil {
			return nil, fmt.Errorf("azure: %w", err)
		}
		sender, err := sms.NewAzure(sms.AzureConfig{
			Endpoint:  endpoint,
			AccessKey: accessKey,
			From:      cfg.SMSAzureFrom,
		})
		if err != nil {
			return nil, fmt.Errorf("azure: %w", err)
		}
		logger.Info("sms_provider_configured", zap.String("provider", config.SMSProviderAzure))
		return sender, nil

	default:
		// Validate should have rejected this; fail closed rather than
		// silently delivering nowhere.
		return nil, fmt.Errorf("unsupported GATEWAY_SMS_PROVIDER %q", cfg.SMSProvider)
	}
}
