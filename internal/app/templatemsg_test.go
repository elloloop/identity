package app

import (
	"testing"

	"go.uber.org/zap"

	"github.com/elloloop/identity/internal/config"
)

func TestBuildWhatsAppCloudSender(t *testing.T) {
	whatsApp := func(mutate func(*config.Config)) *config.Config {
		c := &config.Config{
			TemplateMessageProvider:              config.TemplateMessageProviderWhatsAppCloud,
			TemplateMessageWhatsAppAccessToken:   "EAAG-test-token",
			TemplateMessageWhatsAppPhoneNumberID: "106540352242922",
			TemplateMessageWhatsAppAPIVersion:    config.DefaultWhatsAppCloudAPIVersion,
			TemplateMessageWhatsAppCodeButton:    true,
		}
		if mutate != nil {
			mutate(c)
		}
		return c
	}
	cases := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{name: "a complete config builds", cfg: whatsApp(nil)},
		{
			name:    "no phone number id errors",
			cfg:     whatsApp(func(c *config.Config) { c.TemplateMessageWhatsAppPhoneNumberID = "" }),
			wantErr: true,
		},
		{
			name:    "no api version errors",
			cfg:     whatsApp(func(c *config.Config) { c.TemplateMessageWhatsAppAPIVersion = "" }),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := buildWhatsAppCloudSender(tc.cfg, zap.NewNop())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got sender %#v", s)
				}
				return
			}
			if err != nil || s == nil {
				t.Fatalf("err = %v, sender = %#v", err, s)
			}
		})
	}
}
