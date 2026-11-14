package config

import (
	"strings"
	"testing"
)

func whatsAppConfig() *Config {
	c := baseSMSConfig()
	c.TemplateMessageProvider = TemplateMessageProviderWhatsAppCloud
	c.TemplateMessageWhatsAppAccessToken = "EAAG-test-token"
	c.TemplateMessageWhatsAppPhoneNumberID = "106540352242922"
	return c
}

func TestLoad_TemplateMessageDefaults(t *testing.T) {
	t.Setenv("GATEWAY_TEMPLATEMSG_PROVIDER", "WhatsApp_Cloud")
	c := Load()
	if c.TemplateMessageProvider != TemplateMessageProviderWhatsAppCloud {
		t.Errorf("provider = %q, want it lower-cased", c.TemplateMessageProvider)
	}
	if c.TemplateMessageWhatsAppAPIVersion != DefaultWhatsAppCloudAPIVersion {
		t.Errorf("api version = %q, want the pinned default", c.TemplateMessageWhatsAppAPIVersion)
	}
	if !c.TemplateMessageWhatsAppCodeButton {
		t.Error("code button: want on by default, as authentication templates have one")
	}
}

func TestValidateTemplateMessages(t *testing.T) {
	if err := baseSMSConfig().Validate(); err != nil {
		t.Fatalf("no provider must validate: %v", err)
	}
	if err := whatsAppConfig().Validate(); err != nil {
		t.Fatalf("a complete whatsapp_cloud config must validate: %v", err)
	}
	cases := []struct {
		name     string
		mutate   func(*Config)
		wantText string
	}{
		{"an unknown provider", func(c *Config) { c.TemplateMessageProvider = "carrier_pigeon" }, "GATEWAY_TEMPLATEMSG_PROVIDER"},
		{"no access token", func(c *Config) { c.TemplateMessageWhatsAppAccessToken = "" }, "GATEWAY_TEMPLATEMSG_WHATSAPP_ACCESS_TOKEN"},
		{"no phone number id", func(c *Config) { c.TemplateMessageWhatsAppPhoneNumberID = "" }, "GATEWAY_TEMPLATEMSG_WHATSAPP_PHONE_NUMBER_ID"},
		{"a token with a line break", func(c *Config) { c.TemplateMessageWhatsAppAccessToken = "EAAG\nX-Injected: 1" }, "access token"},
		{"a phone number for an id", func(c *Config) { c.TemplateMessageWhatsAppPhoneNumberID = "+14155550123" }, "phone number id"},
		{"an id with a path", func(c *Config) { c.TemplateMessageWhatsAppPhoneNumberID = "1/../2" }, "phone number id"},
		{"an empty api version", func(c *Config) { c.TemplateMessageWhatsAppAPIVersion = "" }, "api version"},
		{"a floating api version", func(c *Config) { c.TemplateMessageWhatsAppAPIVersion = "latest" }, "api version"},
		{"a language with a space", func(c *Config) { c.TemplateMessageWhatsAppLanguage = "en US" }, "default language"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := whatsAppConfig()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatal("want a refusal")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("refusal %q does not name %s", err, tc.wantText)
			}
			if strings.Contains(err.Error(), "EAAG") {
				t.Errorf("refusal %q carries the token", err)
			}
		})
	}
}
