package config

import (
	"strings"
	"testing"

	"github.com/elloloop/identity/pkg/events"
)

// enabledWebhookConfig returns a Config with valid webhook knobs and eventing
// on, so only the subscription field under test drives the outcome.
func enabledWebhookConfig(subscriptions string) *Config {
	return &Config{
		WebhooksEnabled:               true,
		WebhooksMaxAttempts:           6,
		WebhooksBackoffBaseSeconds:    2,
		WebhooksBackoffMaxSeconds:     300,
		WebhooksWorkerIntervalSeconds: 1,
		WebhooksBatchSize:             50,
		WebhookSubscriptions:          subscriptions,
	}
}

func TestWebhookSubscriptionList_ParsesValidJSON(t *testing.T) {
	c := enabledWebhookConfig(`[
		{"url":"https://relay.example.com/webhooks/identity","secret":"s3cr3t","event_types":["user.deleted"]},
		{"url":"https://other.example.com/hook","secret":"k2","event_types":["user.created","user.updated"],"project_id":"proj-2"}
	]`)

	subs, err := c.WebhookSubscriptionList()
	if err != nil {
		t.Fatalf("WebhookSubscriptionList: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("want 2 subscriptions, got %d", len(subs))
	}
	if subs[0].URL != "https://relay.example.com/webhooks/identity" || subs[0].Secret != "s3cr3t" {
		t.Errorf("subs[0] = %+v", subs[0])
	}
	if len(subs[0].EventTypes) != 1 || subs[0].EventTypes[0] != events.EventUserDeleted {
		t.Errorf("subs[0].EventTypes = %v", subs[0].EventTypes)
	}
	if subs[0].ProjectID != "" {
		t.Errorf("subs[0].ProjectID = %q, want empty (default project)", subs[0].ProjectID)
	}
	if subs[1].ProjectID != "proj-2" || len(subs[1].EventTypes) != 2 {
		t.Errorf("subs[1] = %+v", subs[1])
	}
}

func TestWebhookSubscriptionList_EmptyIsNoError(t *testing.T) {
	for _, raw := range []string{"", "   ", "[]"} {
		c := enabledWebhookConfig(raw)
		subs, err := c.WebhookSubscriptionList()
		if err != nil {
			t.Fatalf("raw %q: unexpected error: %v", raw, err)
		}
		if len(subs) != 0 {
			t.Fatalf("raw %q: want 0 subscriptions, got %d", raw, len(subs))
		}
	}
}

func TestWebhookSubscriptionList_Rejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"invalid json", `[{"url":`, "must be a JSON array"},
		{"unknown field", `[{"url":"https://a.example.com","secret":"k","endpoint":"x"}]`, "must be a JSON array"},
		{"unknown event type", `[{"url":"https://a.example.com","secret":"k","event_types":["user.frobnicated"]}]`, "unknown event type"},
		{"empty url", `[{"url":"","secret":"k","event_types":["user.deleted"]}]`, "url must not be empty"},
		{"empty secret", `[{"url":"https://a.example.com","secret":"","event_types":["user.deleted"]}]`, "secret must not be empty"},
		{"http non-loopback", `[{"url":"http://a.example.com","secret":"k","event_types":["user.deleted"]}]`, "must use https"},
		{"relative url", `[{"url":"/webhooks","secret":"k","event_types":["user.deleted"]}]`, "must be absolute"},
		{"non-http scheme", `[{"url":"ftp://a.example.com","secret":"k"}]`, "must use https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := enabledWebhookConfig(tc.raw)
			_, err := c.WebhookSubscriptionList()
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestWebhookSubscriptionList_AllowsLoopbackHTTP(t *testing.T) {
	for _, host := range []string{"http://localhost:8080/hook", "http://127.0.0.1:9000/x", "http://[::1]:9000/x"} {
		c := enabledWebhookConfig(`[{"url":"` + host + `","secret":"k","event_types":["user.deleted"]}]`)
		if _, err := c.WebhookSubscriptionList(); err != nil {
			t.Fatalf("loopback %q should be allowed: %v", host, err)
		}
	}
}

func TestWebhookSubscriptionList_EmptyEventTypesMeansAll(t *testing.T) {
	c := enabledWebhookConfig(`[{"url":"https://a.example.com","secret":"k"}]`)
	subs, err := c.WebhookSubscriptionList()
	if err != nil {
		t.Fatalf("WebhookSubscriptionList: %v", err)
	}
	if len(subs) != 1 || len(subs[0].EventTypes) != 0 {
		t.Fatalf("want one subscription with no event filter, got %+v", subs)
	}
}

func TestValidateWebhooks_EnabledValidatesSubscriptions(t *testing.T) {
	good := enabledWebhookConfig(`[{"url":"https://a.example.com","secret":"k","event_types":["user.deleted"]}]`)
	if err := good.Validate(); err != nil {
		t.Fatalf("valid subscription config should pass Validate: %v", err)
	}

	bad := enabledWebhookConfig(`[{"url":"http://public.example.com","secret":"k"}]`)
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate should reject a non-HTTPS subscription URL")
	}
}

func TestValidateWebhooks_ConfiguredButDisabledFailsFast(t *testing.T) {
	c := &Config{
		WebhooksEnabled:      false,
		WebhookSubscriptions: `[{"url":"https://a.example.com","secret":"k","event_types":["user.deleted"]}]`,
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("subscriptions configured with webhooks disabled must fail fast")
	}
	if !strings.Contains(err.Error(), "GATEWAY_WEBHOOKS_ENABLED=false") {
		t.Fatalf("error %q does not explain the disabled master switch", err.Error())
	}
}

func TestValidateWebhooks_DisabledWithoutSubscriptionsPasses(t *testing.T) {
	c := &Config{WebhooksEnabled: false}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled webhooks without subscriptions should validate: %v", err)
	}
}
