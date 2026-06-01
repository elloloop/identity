package config

import "testing"

// baseSMSConfig returns a Config that passes Validate when SMS is
// disabled, so SMS-specific tests can toggle one thing at a time.
func baseSMSConfig() *Config {
	c := Load()
	c.RevocationMode = RevocationModeTTL
	return c
}

func TestValidateSMS_DisabledIsAlwaysValid(t *testing.T) {
	c := baseSMSConfig()
	c.SMSEnabled = false
	c.SMSProvider = "" // no provider needed when disabled
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled SMS must validate: %v", err)
	}
}

func TestValidateSMS_EnabledRequiresProvider(t *testing.T) {
	c := baseSMSConfig()
	c.SMSEnabled = true
	c.SMSProvider = ""
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SMS with no provider must fail")
	}
	c.SMSProvider = "firebase" // intentionally out of scope
	if err := c.Validate(); err == nil {
		t.Fatal("enabled SMS with an unsupported provider must fail")
	}
}

func TestValidateSMS_TwilioCreds(t *testing.T) {
	c := baseSMSConfig()
	c.SMSEnabled = true
	c.SMSProvider = SMSProviderTwilio
	if err := c.Validate(); err == nil {
		t.Fatal("twilio with no creds must fail")
	}
	c.SMSTwilioAccountSID = "AC"
	c.SMSTwilioAuthToken = "tok"
	if err := c.Validate(); err == nil {
		t.Fatal("twilio missing From must fail")
	}
	c.SMSTwilioFrom = "+15005550006"
	if err := c.Validate(); err != nil {
		t.Fatalf("twilio with full creds must validate: %v", err)
	}
}

func TestValidateSMS_SNSCreds(t *testing.T) {
	c := baseSMSConfig()
	c.SMSEnabled = true
	c.SMSProvider = SMSProviderSNS
	if err := c.Validate(); err == nil {
		t.Fatal("sns with no creds must fail")
	}
	c.SMSAWSRegion = "us-east-1"
	c.SMSAWSAccessKeyID = "AKID"
	if err := c.Validate(); err == nil {
		t.Fatal("sns missing secret must fail")
	}
	c.SMSAWSSecretAccessKey = "secret"
	if err := c.Validate(); err != nil {
		t.Fatalf("sns with full creds must validate: %v", err)
	}
}

func TestValidateSMS_AzureCreds(t *testing.T) {
	c := baseSMSConfig()
	c.SMSEnabled = true
	c.SMSProvider = SMSProviderAzure
	if err := c.Validate(); err == nil {
		t.Fatal("azure with no creds must fail")
	}
	c.SMSAzureConnectionString = "endpoint=https://x.communication.azure.com/;accesskey=YWJj"
	if err := c.Validate(); err == nil {
		t.Fatal("azure missing From must fail")
	}
	c.SMSAzureFrom = "+15005550006"
	if err := c.Validate(); err != nil {
		t.Fatalf("azure with full creds must validate: %v", err)
	}
}

func TestLoadSMSDefaults(t *testing.T) {
	cfg := Load()
	if cfg.SMSEnabled {
		t.Fatal("SMS must default to disabled")
	}
	if cfg.PhoneCodeTTLSeconds != 300 {
		t.Fatalf("PhoneCodeTTLSeconds default = %d, want 300", cfg.PhoneCodeTTLSeconds)
	}
	if cfg.PhoneCodeMaxAttempts != 5 {
		t.Fatalf("PhoneCodeMaxAttempts default = %d, want 5", cfg.PhoneCodeMaxAttempts)
	}
	if cfg.PhoneCodeCooldownSeconds != 60 {
		t.Fatalf("PhoneCodeCooldownSeconds default = %d, want 60", cfg.PhoneCodeCooldownSeconds)
	}
	if cfg.RateLimitPhonePerIP != 5 {
		t.Fatalf("RateLimitPhonePerIP default = %d, want 5", cfg.RateLimitPhonePerIP)
	}
}

func TestSMSProviderCaseInsensitive(t *testing.T) {
	t.Setenv("GATEWAY_SMS_PROVIDER", "Twilio")
	cfg := Load()
	if cfg.SMSProvider != SMSProviderTwilio {
		t.Fatalf("provider = %q, want %q", cfg.SMSProvider, SMSProviderTwilio)
	}
}
