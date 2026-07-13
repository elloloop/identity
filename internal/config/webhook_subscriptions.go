package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/elloloop/identity/pkg/events"
)

// WebhookSubscription is one declared outbound-webhook endpoint, parsed from
// the GATEWAY_WEBHOOK_SUBSCRIPTIONS JSON array. Each entry seeds one
// events.Subscription into the outbox at boot so emitted user-lifecycle
// events are delivered to the endpoint. Secret is the HMAC-SHA256 signing
// key the endpoint verifies against; it is sensitive and never logged.
type WebhookSubscription struct {
	// URL is the HTTPS endpoint the signed webhook is POSTed to. Plain HTTP is
	// accepted only for a loopback host (local development).
	URL string `json:"url"`
	// Secret is the HMAC-SHA256 signing key. Required; never logged.
	Secret string `json:"secret"`
	// EventTypes filters which events reach this endpoint; empty ⇒ all types.
	// Every entry must be a known events.EventType.
	EventTypes []events.EventType `json:"event_types"`
	// ProjectID scopes the subscription. Empty ⇒ the service default project,
	// resolved at seed time — the project single-project deployments emit
	// user-lifecycle events under.
	ProjectID string `json:"project_id,omitempty"`
}

// WebhookSubscriptionList parses and validates GATEWAY_WEBHOOK_SUBSCRIPTIONS.
// It returns the declared subscriptions, or an error when the JSON is
// malformed or any entry is invalid (empty/non-HTTPS URL, empty secret, or an
// unknown event type). An empty env var yields no subscriptions and no error:
// enabling webhooks without any subscription is a supported (if inert)
// configuration.
func (c *Config) WebhookSubscriptionList() ([]WebhookSubscription, error) {
	raw := strings.TrimSpace(c.WebhookSubscriptions)
	if raw == "" {
		return nil, nil
	}
	var subs []WebhookSubscription
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&subs); err != nil {
		return nil, fmt.Errorf(
			"config: GATEWAY_WEBHOOK_SUBSCRIPTIONS must be a JSON array of "+
				"{url,secret,event_types,project_id}: %w", err,
		)
	}
	for i := range subs {
		if err := subs[i].validate(); err != nil {
			return nil, fmt.Errorf("config: GATEWAY_WEBHOOK_SUBSCRIPTIONS[%d]: %w", i, err)
		}
	}
	return subs, nil
}

// validate enforces one subscription's invariants: an HTTPS URL (HTTP only
// for a loopback host), a non-empty secret, and only known event types.
func (s WebhookSubscription) validate() error {
	if err := validateWebhookURL(s.URL); err != nil {
		return err
	}
	if s.Secret == "" {
		return errors.New("secret must not be empty")
	}
	for _, t := range s.EventTypes {
		if !t.Valid() {
			return fmt.Errorf("unknown event type %q", t)
		}
	}
	return nil
}

// validateWebhookURL requires an absolute HTTPS URL. Plain HTTP is accepted
// only when the host is loopback, matching the repo's localhost-dev
// convention for base URLs (GATEWAY_APP_BASE_URL etc.).
func validateWebhookURL(raw string) error {
	if raw == "" {
		return errors.New("url must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("url %q is not a valid URL: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("url %q must be absolute (scheme and host)", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("url %q must use https (http is accepted only for a loopback host)", raw)
	default:
		return fmt.Errorf("url %q must use https", raw)
	}
}

// isLoopbackHost reports whether host is a loopback name or address
// (localhost, 127.0.0.0/8, or ::1) — the only case a plaintext webhook URL is
// accepted.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
