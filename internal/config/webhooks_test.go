package config

import "testing"

func baseValidConfig() *Config {
	// A directly-constructed Config; Validate fills RevocationMode and
	// leaves webhooks disabled (the default), so it validates cleanly.
	return &Config{}
}

func TestValidateWebhooks_DisabledSkipsChecks(t *testing.T) {
	c := baseValidConfig()
	// Nonsense knobs are tolerated while disabled — the worker never runs.
	c.WebhooksEnabled = false
	c.WebhooksMaxAttempts = 0
	c.WebhooksBackoffMaxSeconds = -5
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled webhooks should validate: %v", err)
	}
}

func TestValidateWebhooks_EnabledRejectsBadKnobs(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*Config)
		valid bool
	}{
		{"good", func(c *Config) {
			c.WebhooksMaxAttempts = 6
			c.WebhooksBackoffBaseSeconds = 2
			c.WebhooksBackoffMaxSeconds = 300
			c.WebhooksWorkerIntervalSeconds = 1
			c.WebhooksBatchSize = 50
		}, true},
		{"zero attempts", func(c *Config) {
			c.WebhooksMaxAttempts = 0
			c.WebhooksBackoffBaseSeconds = 2
			c.WebhooksBackoffMaxSeconds = 300
			c.WebhooksWorkerIntervalSeconds = 1
			c.WebhooksBatchSize = 50
		}, false},
		{"max < base", func(c *Config) {
			c.WebhooksMaxAttempts = 6
			c.WebhooksBackoffBaseSeconds = 10
			c.WebhooksBackoffMaxSeconds = 5
			c.WebhooksWorkerIntervalSeconds = 1
			c.WebhooksBatchSize = 50
		}, false},
		{"zero batch", func(c *Config) {
			c.WebhooksMaxAttempts = 6
			c.WebhooksBackoffBaseSeconds = 2
			c.WebhooksBackoffMaxSeconds = 300
			c.WebhooksWorkerIntervalSeconds = 1
			c.WebhooksBatchSize = 0
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := baseValidConfig()
			c.WebhooksEnabled = true
			tc.mut(c)
			err := c.Validate()
			if tc.valid && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestLoad_WebhookDefaults(t *testing.T) {
	c := Load()
	if c.WebhooksEnabled {
		t.Fatal("webhooks should default disabled")
	}
	if c.WebhooksMaxAttempts != 6 || c.WebhooksBackoffBaseSeconds != 2 ||
		c.WebhooksBackoffMaxSeconds != 300 || c.WebhooksWorkerIntervalSeconds != 1 ||
		c.WebhooksBatchSize != 50 {
		t.Fatalf("unexpected webhook defaults: %+v", c)
	}
}
