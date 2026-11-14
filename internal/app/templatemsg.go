package app

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
	"github.com/elloloop/identity/pkg/templatemsg"
)

// buildWhatsAppCloudSender constructs the message channel's sender for
// GATEWAY_TEMPLATEMSG_PROVIDER=whatsapp_cloud. Config.Validate has already
// held its values to what a send needs, so a build error here is unexpected;
// it is still surfaced so the boot fails rather than the channel going quiet.
func buildWhatsAppCloudSender(cfg *config.Config, logger *zap.Logger) (templatemsg.Sender, error) {
	sender, err := templatemsg.NewWhatsAppCloud(cfg.WhatsAppCloud())
	if err != nil {
		return nil, fmt.Errorf("whatsapp cloud: %w", err)
	}
	logger.Info("template_message_provider_configured",
		zap.String("provider", config.TemplateMessageProviderWhatsAppCloud),
		zap.String("api_version", cfg.TemplateMessageWhatsAppAPIVersion),
		zap.Bool("code_button", cfg.TemplateMessageWhatsAppCodeButton))
	return sender, nil
}
