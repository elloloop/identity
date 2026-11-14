package config

import (
	"strings"
	"testing"
)

// localCaptureConfig is a deployment that captures both channels' codes and
// names only loopback addresses, so a test can move one of them off the
// machine.
func localCaptureConfig() *Config {
	c := baseSMSConfig()
	c.SMSEnabled = true
	c.SMSProvider = SMSProviderLocalCapture
	c.TemplateMessageProvider = TemplateMessageProviderLocalCapture
	c.JWTIssuer = "http://localhost:8080"
	c.AppBaseURL = "http://localhost"
	c.EmailLinkBaseURL = "http://127.0.0.1:3010"
	c.TenantInvitationPageURL = "http://localhost:3010/invite"
	c.QRLoginBaseURL = "http://[::1]:9002"
	c.PasskeyRPID = "localhost"
	c.PasskeyOrigin = "http://localhost:3000"
	c.PasskeyRelyingPartiesJSON = `[{"host":"localhost","rp_id":"localhost","origins":["http://localhost:3000"]}]`
	c.DefaultProjectAuthDomains = "localhost,auth.localhost"
	c.CookieDomain = ".localhost"
	c.AllowedOrigins = "http://localhost:3000, http://127.0.0.1:3001"
	c.OAuthAllowedReturnURLs = "http://localhost:3000/,http://localhost:3001/"
	return c
}

func TestValidatePhoneCodeCapture_ALocalDeploymentStarts(t *testing.T) {
	for name, c := range map[string]*Config{
		"both channels": localCaptureConfig(),
		"the defaults, by SMS": func() *Config {
			c := baseSMSConfig()
			c.SMSEnabled, c.SMSProvider = true, SMSProviderLocalCapture
			return c
		}(),
		"the defaults, by template message": func() *Config {
			c := baseSMSConfig()
			c.TemplateMessageProvider = TemplateMessageProviderLocalCapture
			return c
		}(),
	} {
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidatePhoneCodeCapture_RefusesADeploymentThatIsNotLocal(t *testing.T) {
	cases := []struct {
		env    string
		mutate func(*Config)
	}{
		{"GATEWAY_JWT_ISSUER", func(c *Config) { c.JWTIssuer = "https://auth.example.com" }},
		{"GATEWAY_JWT_ISSUER", func(c *Config) { c.JWTIssuer = "identity" }},
		{"GATEWAY_JWT_ISSUER", func(c *Config) { c.JWTIssuer = "http://localhost.example.com" }},
		{"GATEWAY_JWT_ISSUER", func(c *Config) { c.JWTIssuer = "http://localhost@example.com" }},
		{"GATEWAY_APP_BASE_URL", func(c *Config) { c.AppBaseURL = "https://app.example.com" }},
		{"GATEWAY_EMAIL_LINK_BASE_URL", func(c *Config) { c.EmailLinkBaseURL = "https://hub.example.com" }},
		{"GATEWAY_TENANT_INVITATION_PAGE_URL", func(c *Config) { c.TenantInvitationPageURL = "https://app.example.com/join" }},
		{"GATEWAY_QR_LOGIN_BASE_URL", func(c *Config) { c.QRLoginBaseURL = "https://qr.example.com" }},
		{"GATEWAY_PASSKEY_RP_ID", func(c *Config) { c.PasskeyRPID = "example.com" }},
		{"GATEWAY_PASSKEY_ORIGIN", func(c *Config) { c.PasskeyOrigin = "https://example.com" }},
		{"GATEWAY_PASSKEY_RELYING_PARTIES", func(c *Config) {
			c.PasskeyRelyingPartiesJSON = `[{"host":"auth.example.com","rp_id":"example.com","origins":["https://example.com"]}]`
		}},
		{"GATEWAY_DEFAULT_PROJECT_AUTH_DOMAINS", func(c *Config) { c.DefaultProjectAuthDomains = "localhost,auth.example.com" }},
		{"GATEWAY_COOKIE_DOMAIN", func(c *Config) { c.CookieDomain = ".example.com" }},
		{"GATEWAY_ALLOWED_ORIGINS", func(c *Config) { c.AllowedOrigins = "http://localhost:3000,https://app.example.com" }},
		{"GATEWAY_ALLOWED_ORIGINS", func(c *Config) { c.AllowedOrigins = "https://*.previews.example.app" }},
		{"GATEWAY_ALLOWED_ORIGINS", func(c *Config) { c.AllowedOrigins = "http://0.0.0.0:3000" }},
		{"GATEWAY_OAUTH_ALLOWED_RETURN_URLS", func(c *Config) { c.OAuthAllowedReturnURLs = "https://app.example.com/" }},
		{"GATEWAY_SAML_ENTITY_ID", func(c *Config) { c.SAMLEntityID = "https://idp.example.com/metadata" }},
		{"GATEWAY_SAML_SSO_URL", func(c *Config) { c.SAMLSSOURL = "https://idp.example.com/sso" }},
		{"GATEWAY_SAML_SLO_URL", func(c *Config) { c.SAMLSLOURL = "https://idp.example.com/slo" }},
	}
	for _, channel := range []struct {
		name   string
		only   func(*Config)
		chosen string
	}{
		{
			name:   "SMS",
			only:   func(c *Config) { c.TemplateMessageProvider = "" },
			chosen: "GATEWAY_SMS_PROVIDER=local_capture",
		},
		{
			name: "template message",
			only: func(c *Config) {
				c.SMSProvider = SMSProviderTwilio
				c.SMSTwilioAccountSID, c.SMSTwilioAuthToken, c.SMSTwilioFrom = "AC", "tok", "+15005550006"
			},
			chosen: "GATEWAY_TEMPLATEMSG_PROVIDER=local_capture",
		},
	} {
		for _, tc := range cases {
			c := localCaptureConfig()
			channel.only(c)
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Errorf("%s capture with a non-loopback %s: want a refusal", channel.name, tc.env)
				continue
			}
			if msg := err.Error(); !strings.Contains(msg, tc.env) || !strings.Contains(msg, channel.chosen) {
				t.Errorf("%s capture, %s: the refusal %q names neither the variable nor the capture", channel.name, tc.env, msg)
			}
		}
	}
}

// A real provider is not held to loopback: the guard is for capture only.
func TestValidatePhoneCodeCapture_ARealProviderIsNotHeldToLoopback(t *testing.T) {
	c := localCaptureConfig()
	c.SMSProvider = SMSProviderTwilio
	c.SMSTwilioAccountSID, c.SMSTwilioAuthToken, c.SMSTwilioFrom = "AC", "tok", "+15005550006"
	c.TemplateMessageProvider = ""
	c.JWTIssuer = "https://auth.example.com"
	c.AppBaseURL = "https://app.example.com"
	if err := c.Validate(); err != nil {
		t.Fatalf("twilio on a public deployment: %v", err)
	}
	// A capture name left on a switched-off SMS channel captures nothing.
	c.SMSEnabled = false
	c.SMSProvider = SMSProviderLocalCapture
	if err := c.Validate(); err != nil {
		t.Fatalf("local_capture with SMS off: %v", err)
	}
}

func TestValidatePhoneCodeCapture_TheRefusalHidesCredentialsInAURL(t *testing.T) {
	c := localCaptureConfig()
	c.AppBaseURL = "https://user:hunter2@app.example.com"
	err := c.Validate()
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("want a refusal that hides the password, got %v", err)
	}
}

func TestNamesLoopbackHost(t *testing.T) {
	for value, want := range map[string]bool{
		"localhost":                  true,
		"LOCALHOST":                  true,
		"localhost:8080":             true,
		"auth.localhost":             true,
		".localhost":                 true,
		"127.0.0.1":                  true,
		"127.10.0.1:80":              true,
		"::1":                        true,
		"[::1]":                      true,
		"[::1]:9002":                 true,
		"http://localhost":           true,
		"https://app.localhost:3000": true,
		"http://127.0.0.1:3000/path": true,
		"http://[::1]:9002":          true,
		"https://*.localhost":        true,
		"example.com":                false,
		"localhost.example.com":      false,
		"http://localhost.example":   false,
		"http://localhost@evil.test": false,
		"http://evil.test#localhost": false,
		"http://0.0.0.0":             false,
		"10.0.0.1":                   false,
		"app://desktop":              false,
		"identity":                   false,
		"":                           false,
		"http://%zz":                 false,
	} {
		if got := namesLoopbackHost(value); got != want {
			t.Errorf("namesLoopbackHost(%q) = %v, want %v", value, got, want)
		}
	}
}
